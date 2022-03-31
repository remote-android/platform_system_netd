/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <map>
#include <string>

#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_TAG "ClatdController"
#include <log/log.h>

#include "ClatdController.h"
#include "InterfaceController.h"

#include <android/net/InterfaceConfigurationParcel.h>
#include <netdutils/Status.h>

#include "android-base/properties.h"
#include "android-base/scopeguard.h"
#include "android-base/stringprintf.h"
#include "android-base/unique_fd.h"
#include "bpf/BpfMap.h"
#include "bpf_shared.h"
#include "netdutils/DumpWriter.h"

extern "C" {
#include "checksum.h"
}

#include "Fwmark.h"
#include "NetdConstants.h"
#include "NetworkController.h"
#include "TcUtils.h"
#include "netid_client.h"

// Sync from external/android-clat/clatd.{c, h}
#define MAXMTU 65536
#define PACKETLEN (MAXMTU + sizeof(struct tun_pi))
/* 40 bytes IPv6 header - 20 bytes IPv4 header + 8 bytes fragment header */
#define MTU_DELTA 28

static const char* kClatdPath = "/apex/com.android.tethering/bin/for-system/clatd";

// For historical reasons, start with 192.0.0.4, and after that, use all subsequent addresses in
// 192.0.0.0/29 (RFC 7335).
static const char* kV4AddrString = "192.0.0.4";
static const in_addr kV4Addr = {inet_addr(kV4AddrString)};
static const int kV4AddrLen = 29;

using android::base::Result;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::bpf::BpfMap;
using android::netdutils::DumpWriter;
using android::netdutils::ScopedIndent;

namespace android {
namespace net {

void ClatdController::init(void) {
    std::lock_guard guard(mutex);

    int rv = getClatEgress4MapFd();
    if (rv < 0) {
        ALOGE("getClatEgress4MapFd() failure: %s", strerror(-rv));
        return;
    }
    mClatEgress4Map.reset(rv);

    rv = getClatIngress6MapFd();
    if (rv < 0) {
        ALOGE("getClatIngress6MapFd() failure: %s", strerror(-rv));
        mClatEgress4Map.reset(-1);
        return;
    }
    mClatIngress6Map.reset(rv);

    mClatEgress4Map.clear();
    mClatIngress6Map.clear();
}

bool ClatdController::isIpv4AddressFree(in_addr_t addr) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s == -1) {
        return 0;
    }

    // Attempt to connect to the address. If the connection succeeds and getsockname returns the
    // same then the address is already assigned to the system and we can't use it.
    struct sockaddr_in sin = {
            .sin_family = AF_INET,
            .sin_port = htons(53),
            .sin_addr = {addr},
    };
    socklen_t len = sizeof(sin);
    bool inuse = connect(s, (struct sockaddr*)&sin, sizeof(sin)) == 0 &&
                 getsockname(s, (struct sockaddr*)&sin, &len) == 0 && (size_t)len >= sizeof(sin) &&
                 sin.sin_addr.s_addr == addr;

    close(s);
    return !inuse;
}

// Picks a free IPv4 address, starting from ip and trying all addresses in the prefix in order.
//   ip        - the IP address from the configuration file
//   prefixlen - the length of the prefix from which addresses may be selected.
//   returns: the IPv4 address, or INADDR_NONE if no addresses were available
in_addr_t ClatdController::selectIpv4Address(const in_addr ip, int16_t prefixlen) {
    // Don't accept prefixes that are too large because we scan addresses one by one.
    if (prefixlen < 16 || prefixlen > 32) {
        return INADDR_NONE;
    }

    // All these are in host byte order.
    in_addr_t mask = 0xffffffff >> (32 - prefixlen) << (32 - prefixlen);
    in_addr_t ipv4 = ntohl(ip.s_addr);
    in_addr_t first_ipv4 = ipv4;
    in_addr_t prefix = ipv4 & mask;

    // Pick the first IPv4 address in the pool, wrapping around if necessary.
    // So, for example, 192.0.0.4 -> 192.0.0.5 -> 192.0.0.6 -> 192.0.0.7 -> 192.0.0.0.
    do {
        if (isIpv4AddressFreeFunc(htonl(ipv4))) {
            return htonl(ipv4);
        }
        ipv4 = prefix | ((ipv4 + 1) & ~mask);
    } while (ipv4 != first_ipv4);

    return INADDR_NONE;
}

// Alters the bits in the IPv6 address to make them checksum neutral with v4 and nat64Prefix.
void ClatdController::makeChecksumNeutral(in6_addr* v6, const in_addr v4,
                                          const in6_addr& nat64Prefix) {
    // Fill last 8 bytes of IPv6 address with random bits.
    arc4random_buf(&v6->s6_addr[8], 8);

    // Make the IID checksum-neutral. That is, make it so that:
    //   checksum(Local IPv4 | Remote IPv4) = checksum(Local IPv6 | Remote IPv6)
    // in other words (because remote IPv6 = NAT64 prefix | Remote IPv4):
    //   checksum(Local IPv4) = checksum(Local IPv6 | NAT64 prefix)
    // Do this by adjusting the two bytes in the middle of the IID.

    uint16_t middlebytes = (v6->s6_addr[11] << 8) + v6->s6_addr[12];

    uint32_t c1 = ip_checksum_add(0, &v4, sizeof(v4));
    uint32_t c2 = ip_checksum_add(0, &nat64Prefix, sizeof(nat64Prefix)) +
                  ip_checksum_add(0, v6, sizeof(*v6));

    uint16_t delta = ip_checksum_adjust(middlebytes, c1, c2);
    v6->s6_addr[11] = delta >> 8;
    v6->s6_addr[12] = delta & 0xff;
}

// Picks a random interface ID that is checksum neutral with the IPv4 address and the NAT64 prefix.
int ClatdController::generateIpv6Address(const char* iface, const in_addr v4,
                                         const in6_addr& nat64Prefix, in6_addr* v6) {
    unique_fd s(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (s == -1) return -errno;

    if (setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface) + 1) == -1) {
        return -errno;
    }

    sockaddr_in6 sin6 = {.sin6_family = AF_INET6, .sin6_addr = nat64Prefix};
    if (connect(s, reinterpret_cast<struct sockaddr*>(&sin6), sizeof(sin6)) == -1) {
        return -errno;
    }

    socklen_t len = sizeof(sin6);
    if (getsockname(s, reinterpret_cast<struct sockaddr*>(&sin6), &len) == -1) {
        return -errno;
    }

    *v6 = sin6.sin6_addr;

    if (IN6_IS_ADDR_UNSPECIFIED(v6) || IN6_IS_ADDR_LOOPBACK(v6) || IN6_IS_ADDR_LINKLOCAL(v6) ||
        IN6_IS_ADDR_SITELOCAL(v6) || IN6_IS_ADDR_ULA(v6)) {
        return -ENETUNREACH;
    }

    makeChecksumNeutral(v6, v4, nat64Prefix);

    return 0;
}

void ClatdController::maybeStartBpf(const ClatdTracker& tracker) {
    auto isEthernet = android::net::isEthernet(tracker.iface);
    if (!isEthernet.ok()) {
        ALOGE("isEthernet(%s[%d]) failure: %s", tracker.iface, tracker.ifIndex,
              isEthernet.error().message().c_str());
        return;
    }

    ClatEgress4Key txKey = {
            .iif = tracker.v4ifIndex,
            .local4 = tracker.v4,
    };
    ClatEgress4Value txValue = {
            .oif = tracker.ifIndex,
            .local6 = tracker.v6,
            .pfx96 = tracker.pfx96,
            .oifIsEthernet = isEthernet.value(),
    };

    auto ret = mClatEgress4Map.writeValue(txKey, txValue, BPF_ANY);
    if (!ret.ok()) {
        ALOGE("mClatEgress4Map.writeValue failure: %s", strerror(ret.error().code()));
        return;
    }

    ClatIngress6Key rxKey = {
            .iif = tracker.ifIndex,
            .pfx96 = tracker.pfx96,
            .local6 = tracker.v6,
    };
    ClatIngress6Value rxValue = {
            // TODO: move all the clat code to eBPF and remove the tun interface entirely.
            .oif = tracker.v4ifIndex,
            .local4 = tracker.v4,
    };

    ret = mClatIngress6Map.writeValue(rxKey, rxValue, BPF_ANY);
    if (!ret.ok()) {
        ALOGE("mClatIngress6Map.writeValue failure: %s", strerror(ret.error().code()));
        ret = mClatEgress4Map.deleteValue(txKey);
        if (!ret.ok())
            ALOGE("mClatEgress4Map.deleteValue failure: %s", strerror(ret.error().code()));
        return;
    }

    // We do tc setup *after* populating the maps, so scanning through them
    // can always be used to tell us what needs cleanup.

    // Usually the clsact will be added in RouteController::addInterfaceToPhysicalNetwork.
    // But clat is started before the v4- interface is added to the network. The clat startup have
    // to add clsact of v4- tun interface first for adding bpf filter in maybeStartBpf.
    // TODO: move "qdisc add clsact" of v4- tun interface out from ClatdController.
    int rv = tcQdiscAddDevClsact(tracker.v4ifIndex);
    if (rv) {
        ALOGE("tcQdiscAddDevClsact(%d[%s]) failure: %s", tracker.v4ifIndex, tracker.v4iface,
              strerror(-rv));
        ret = mClatEgress4Map.deleteValue(txKey);
        if (!ret.ok())
            ALOGE("mClatEgress4Map.deleteValue failure: %s", strerror(ret.error().code()));
        ret = mClatIngress6Map.deleteValue(rxKey);
        if (!ret.ok())
            ALOGE("mClatIngress6Map.deleteValue failure: %s", strerror(ret.error().code()));
        return;
    }

    // This program will be attached to the v4-* interface which is a TUN and thus always rawip.
    rv = tcFilterAddDevEgressClatIpv4(tracker.v4ifIndex, CLAT_EGRESS4_PROG_RAWIP_PATH);
    if (rv) {
        ALOGE("tcFilterAddDevEgressClatIpv4(%d[%s], RAWIP) failure: %s", tracker.v4ifIndex,
              tracker.v4iface, strerror(-rv));

        // The v4- interface clsact is not deleted for unwinding error because once it is created
        // with interface addition, the lifetime is till interface deletion. Moreover, the clsact
        // has no clat filter now. It should not break anything.

        ret = mClatEgress4Map.deleteValue(txKey);
        if (!ret.ok())
            ALOGE("mClatEgress4Map.deleteValue failure: %s", strerror(ret.error().code()));
        ret = mClatIngress6Map.deleteValue(rxKey);
        if (!ret.ok())
            ALOGE("mClatIngress6Map.deleteValue failure: %s", strerror(ret.error().code()));
        return;
    }

    std::string rxProgPath =
            isEthernet.value() ? CLAT_INGRESS6_PROG_ETHER_PATH : CLAT_INGRESS6_PROG_RAWIP_PATH;
    rv = tcFilterAddDevIngressClatIpv6(tracker.ifIndex, rxProgPath);
    if (rv) {
        ALOGE("tcFilterAddDevIngressClatIpv6(%d[%s], %d) failure: %s", tracker.ifIndex,
              tracker.iface, isEthernet.value(), strerror(-rv));
        rv = tcFilterDelDevEgressClatIpv4(tracker.v4ifIndex);
        if (rv) {
            ALOGE("tcFilterDelDevEgressClatIpv4(%d[%s]) failure: %s", tracker.v4ifIndex,
                  tracker.v4iface, strerror(-rv));
        }

        // The v4- interface clsact is not deleted. See the reason in the error unwinding code of
        // the egress filter attaching of v4- tun interface.

        ret = mClatEgress4Map.deleteValue(txKey);
        if (!ret.ok())
            ALOGE("mClatEgress4Map.deleteValue failure: %s", strerror(ret.error().code()));
        ret = mClatIngress6Map.deleteValue(rxKey);
        if (!ret.ok())
            ALOGE("mClatIngress6Map.deleteValue failure: %s", strerror(ret.error().code()));
        return;
    }

    // success
}

void ClatdController::setIptablesDropRule(bool add, const char* iface, const char* pfx96Str,
                                          const char* v6Str) {
    std::string cmd = StringPrintf(
            "*raw\n"
            "%s %s -i %s -s %s/96 -d %s -j DROP\n"
            "COMMIT\n",
            (add ? "-A" : "-D"), LOCAL_RAW_PREROUTING, iface, pfx96Str, v6Str);

    iptablesRestoreFunction(V6, cmd);
}

void ClatdController::maybeStopBpf(const ClatdTracker& tracker) {
    int rv = tcFilterDelDevIngressClatIpv6(tracker.ifIndex);
    if (rv < 0) {
        ALOGE("tcFilterDelDevIngressClatIpv6(%d[%s]) failure: %s", tracker.ifIndex, tracker.iface,
              strerror(-rv));
    }

    rv = tcFilterDelDevEgressClatIpv4(tracker.v4ifIndex);
    if (rv < 0) {
        ALOGE("tcFilterDelDevEgressClatIpv4(%d[%s]) failure: %s", tracker.v4ifIndex,
              tracker.v4iface, strerror(-rv));
    }

    // We cleanup the maps last, so scanning through them can be used to
    // determine what still needs cleanup.

    ClatEgress4Key txKey = {
            .iif = tracker.v4ifIndex,
            .local4 = tracker.v4,
    };

    auto ret = mClatEgress4Map.deleteValue(txKey);
    if (!ret.ok()) ALOGE("mClatEgress4Map.deleteValue failure: %s", strerror(ret.error().code()));

    ClatIngress6Key rxKey = {
            .iif = tracker.ifIndex,
            .pfx96 = tracker.pfx96,
            .local6 = tracker.v6,
    };

    ret = mClatIngress6Map.deleteValue(rxKey);
    if (!ret.ok()) ALOGE("mClatIngress6Map.deleteValue failure: %s", strerror(ret.error().code()));
}

// Finds the tracker of the clatd running on interface |interface|, or nullptr if clatd has not been
// started  on |interface|.
ClatdController::ClatdTracker* ClatdController::getClatdTracker(const std::string& interface) {
    auto it = mClatdTrackers.find(interface);
    return (it == mClatdTrackers.end() ? nullptr : &it->second);
}

// Initializes a ClatdTracker for the specified interface.
int ClatdController::ClatdTracker::init(unsigned networkId, const std::string& interface,
                                        const std::string& v4interface,
                                        const std::string& nat64Prefix) {
    fwmark.netId = networkId;
    fwmark.explicitlySelected = true;
    fwmark.protectedFromVpn = true;
    fwmark.permission = PERMISSION_SYSTEM;

    snprintf(fwmarkString, sizeof(fwmarkString), "0x%x", fwmark.intValue);
    strlcpy(iface, interface.c_str(), sizeof(iface));
    ifIndex = if_nametoindex(iface);
    strlcpy(v4iface, v4interface.c_str(), sizeof(v4iface));
    v4ifIndex = if_nametoindex(v4iface);

    // Pass in everything that clatd needs: interface, a fwmark for outgoing packets, the NAT64
    // prefix, and the IPv4 and IPv6 addresses.
    // Validate the prefix and strip off the prefix length.
    uint8_t family;
    uint8_t prefixLen;
    int res = parsePrefix(nat64Prefix.c_str(), &family, &pfx96, sizeof(pfx96), &prefixLen);
    // clatd only supports /96 prefixes.
    if (res != sizeof(pfx96)) return res;
    if (family != AF_INET6) return -EAFNOSUPPORT;
    if (prefixLen != 96) return -EINVAL;
    if (!inet_ntop(AF_INET6, &pfx96, pfx96String, sizeof(pfx96String))) return -errno;

    // Pick an IPv4 address.
    // TODO: this picks the address based on other addresses that are assigned to interfaces, but
    // the address is only actually assigned to an interface once clatd starts up. So we could end
    // up with two clatd instances with the same IPv4 address.
    // Stop doing this and instead pick a free one from the kV4Addr pool.
    v4 = {selectIpv4Address(kV4Addr, kV4AddrLen)};
    if (v4.s_addr == INADDR_NONE) {
        ALOGE("No free IPv4 address in %s/%d", kV4AddrString, kV4AddrLen);
        return -EADDRNOTAVAIL;
    }
    if (!inet_ntop(AF_INET, &v4, v4Str, sizeof(v4Str))) return -errno;

    // Generate a checksum-neutral IID.
    if (generateIpv6Address(iface, v4, pfx96, &v6)) {
        ALOGE("Unable to find global source address on %s for %s", iface, pfx96String);
        return -EADDRNOTAVAIL;
    }
    if (!inet_ntop(AF_INET6, &v6, v6Str, sizeof(v6Str))) return -errno;

    ALOGD("starting clatd on %s v4=%s v6=%s pfx96=%s", iface, v4Str, v6Str, pfx96String);
    return 0;
}

/* function: configure_tun_ip
 * configures the ipv4 address on the tunnel interface
 *   v4iface - tunnel interface name
 *   v4Str   - tunnel ipv4 address
 *   mtu     - mtu of tun device
 * returns: 0 on success, -errno on failure
 */
int ClatdController::configure_tun_ip(const char* v4iface, const char* v4Str, int mtu) {
    ALOGI("Using IPv4 address %s on %s", v4Str, v4iface);

    // Configure the interface before bringing it up. As soon as we bring the interface up, the
    // framework will be notified and will assume the interface's configuration has been finalized.
    std::string mtuStr = std::to_string(mtu);
    if (int res = InterfaceController::setMtu(v4iface, mtuStr.c_str())) {
        ALOGE("setMtu %s failed (%s)", v4iface, strerror(-res));
        return res;
    }

    InterfaceConfigurationParcel ifConfig;
    ifConfig.ifName = std::string(v4iface);
    ifConfig.ipv4Addr = std::string(v4Str);
    ifConfig.prefixLength = 32;
    ifConfig.hwAddr = std::string("");
    ifConfig.flags = std::vector<std::string>{std::string(String8(INetd::IF_STATE_UP().string()))};
    const auto& status = InterfaceController::setCfg(ifConfig);
    if (!status.ok()) {
        ALOGE("configure_tun_ip/setCfg failed: %s", strerror(status.code()));
        return -status.code();
    }

    return 0;
}

/* function: add_anycast_address
 * adds an anycast IPv6 address to an interface, returns 0 on success and <0 on failure
 *   sock      - the socket to add the address to
 *   addr      - the IP address to add
 *   ifindex   - index of interface to add the address to
 * returns: 0 on success, -errno on failure
 */
int ClatdController::add_anycast_address(int sock, struct in6_addr* addr, int ifindex) {
    struct ipv6_mreq mreq = {*addr, ifindex};
    int ret = setsockopt(sock, SOL_IPV6, IPV6_JOIN_ANYCAST, &mreq, sizeof(mreq));
    if (ret) {
        ret = errno;
        ALOGE("setsockopt(IPV6_JOIN_ANYCAST): %s", strerror(errno));
        return -ret;
    }

    return 0;
}

/* function: configure_packet_socket
 * Binds the packet socket and attaches the receive filter to it.
 *   sock    - the socket to configure
 *   addr    - the IP address to filter
 *   ifindex - index of interface to add the filter to
 * returns: 0 on success, -errno on failure
 */
int ClatdController::configure_packet_socket(int sock, in6_addr* addr, int ifindex) {
    uint32_t* ipv6 = addr->s6_addr32;

    // clang-format off
    struct sock_filter filter_code[] = {
    // Load the first four bytes of the IPv6 destination address (starts 24 bytes in).
    // Compare it against the first four bytes of our IPv6 address, in host byte order (BPF loads
    // are always in host byte order). If it matches, continue with next instruction (JMP 0). If it
    // doesn't match, jump ahead to statement that returns 0 (ignore packet). Repeat for the other
    // three words of the IPv6 address, and if they all match, return PACKETLEN (accept packet).
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,  24),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,    htonl(ipv6[0]), 0, 7),
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,  28),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,    htonl(ipv6[1]), 0, 5),
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,  32),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,    htonl(ipv6[2]), 0, 3),
        BPF_STMT(BPF_LD  | BPF_W   | BPF_ABS,  36),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K,    htonl(ipv6[3]), 0, 1),
        BPF_STMT(BPF_RET | BPF_K,              PACKETLEN),
        BPF_STMT(BPF_RET | BPF_K,              0),
    };
    // clang-format on
    struct sock_fprog filter = {sizeof(filter_code) / sizeof(filter_code[0]), filter_code};

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter))) {
        int res = errno;
        ALOGE("attach packet filter failed: %s", strerror(errno));
        return -res;
    }

    struct sockaddr_ll sll = {
            .sll_family = AF_PACKET,
            .sll_protocol = htons(ETH_P_IPV6),
            .sll_ifindex = ifindex,
            .sll_pkttype =
                    PACKET_OTHERHOST,  // The 464xlat IPv6 address is not assigned to the kernel.
    };
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll))) {
        int res = errno;
        ALOGE("binding packet socket: %s", strerror(errno));
        return -res;
    }

    return 0;
}

/* function: configure_clat_ipv6_address
 * picks the clat IPv6 address and configures packet translation to use it.
 *   tunnel - tun device data
 *   interface - uplink interface name
 * returns: 0 on success, -errno on failure
 */
int ClatdController::configure_clat_ipv6_address(struct ClatdTracker* tracker,
                                                 struct tun_data* tunnel) {
    ALOGI("Using IPv6 address %s on %s", tracker->v6Str, tracker->iface);

    // Start translating packets to the new prefix.
    // TODO: return if error. b/212679140 needs to be fixed first.
    add_anycast_address(tunnel->write_fd6, &tracker->v6, tracker->ifIndex);

    // Update our packet socket filter to reflect the new 464xlat IP address.
    if (int res = configure_packet_socket(tunnel->read_fd6, &tracker->v6, tracker->ifIndex)) {
        // Things aren't going to work. Bail out and hope we have better luck next time.
        // We don't log an error here because configure_packet_socket has already done so.
        return res;
    }

    return 0;
}

/* function: detect mtu
 * returns: mtu on success, -errno on failure
 */
int ClatdController::detect_mtu(const struct in6_addr* plat_subnet, uint32_t plat_suffix,
                                uint32_t mark) {
    // Create an IPv6 UDP socket.
    unique_fd s(socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (s < 0) {
        int ret = errno;
        ALOGE("socket(AF_INET6, SOCK_DGRAM, 0) failed: %s", strerror(errno));
        return -ret;
    }

    // Socket's mark affects routing decisions (network selection)
    if ((mark != MARK_UNSET) && setsockopt(s, SOL_SOCKET, SO_MARK, &mark, sizeof(mark))) {
        int ret = errno;
        ALOGE("setsockopt(SOL_SOCKET, SO_MARK) failed: %s", strerror(errno));
        return -ret;
    }

    // Try to connect udp socket to plat_subnet(96 bits):plat_suffix(32 bits)
    struct sockaddr_in6 dst = {
            .sin6_family = AF_INET6,
            .sin6_addr = *plat_subnet,
    };
    dst.sin6_addr.s6_addr32[3] = plat_suffix;
    if (connect(s, (struct sockaddr*)&dst, sizeof(dst))) {
        int ret = errno;
        ALOGE("connect() failed: %s", strerror(errno));
        return -ret;
    }

    // Fetch the socket's IPv6 mtu - this is effectively fetching mtu from routing table
    int mtu;
    socklen_t sz_mtu = sizeof(mtu);
    if (getsockopt(s, SOL_IPV6, IPV6_MTU, &mtu, &sz_mtu)) {
        int ret = errno;
        ALOGE("getsockopt(SOL_IPV6, IPV6_MTU) failed: %s", strerror(errno));
        return -ret;
    }
    if (sz_mtu != sizeof(mtu)) {
        ALOGE("getsockopt(SOL_IPV6, IPV6_MTU) returned unexpected size: %d", sz_mtu);
        return -EFAULT;
    }

    return mtu;
}

/* function: configure_interface
 * reads the configuration and applies it to the interface
 *   tracker - clat tracker
 *   tunnel - tun device data
 * returns: 0 on success, -errno on failure
 */
int ClatdController::configure_interface(struct ClatdTracker* tracker, struct tun_data* tunnel) {
    int res = detect_mtu(&tracker->pfx96, htonl(0x08080808), tracker->fwmark.intValue);
    if (res < 0) return -res;

    int mtu = res;
    // clamp to minimum ipv6 mtu - this probably cannot ever trigger
    if (mtu < 1280) mtu = 1280;
    // clamp to buffer size
    if (mtu > MAXMTU) mtu = MAXMTU;
    // decrease by ipv6(40) + ipv6 fragmentation header(8) vs ipv4(20) overhead of 28 bytes
    mtu -= MTU_DELTA;
    ALOGI("ipv4 mtu is %d", mtu);

    if (int ret = configure_tun_ip(tracker->v4iface, tracker->v4Str, mtu)) return ret;
    if (int ret = configure_clat_ipv6_address(tracker, tunnel)) return ret;

    return 0;
}

int ClatdController::startClatd(const std::string& interface, const std::string& nat64Prefix,
                                std::string* v6Str) {
    std::lock_guard guard(mutex);

    // 1. fail if pre-existing tracker already exists
    ClatdTracker* existing = getClatdTracker(interface);
    if (existing != nullptr) {
        ALOGE("clatd pid=%d already started on %s", existing->pid, interface.c_str());
        return -EBUSY;
    }

    // 2. get network id associated with this external interface
    unsigned networkId = mNetCtrl->getNetworkForInterface(interface.c_str());
    if (networkId == NETID_UNSET) {
        ALOGE("Interface %s not assigned to any netId", interface.c_str());
        return -ENODEV;
    }

    // 3. open the tun device in non blocking mode as required by clatd
    int res = open("/dev/net/tun", O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (res == -1) {
        res = errno;
        ALOGE("open of tun device failed (%s)", strerror(res));
        return -res;
    }
    unique_fd tmpTunFd(res);

    // 4. create the v4-... tun interface
    std::string v4interface("v4-");
    v4interface += interface;

    struct ifreq ifr = {
            .ifr_flags = IFF_TUN,
    };
    strlcpy(ifr.ifr_name, v4interface.c_str(), sizeof(ifr.ifr_name));

    res = ioctl(tmpTunFd, TUNSETIFF, &ifr, sizeof(ifr));
    if (res == -1) {
        res = errno;
        ALOGE("ioctl(TUNSETIFF) failed (%s)", strerror(res));
        return -res;
    }

    // disable IPv6 on it - failing to do so is not a critical error
    res = InterfaceController::setEnableIPv6(v4interface.c_str(), 0);
    if (res) ALOGE("setEnableIPv6 %s failed (%s)", v4interface.c_str(), strerror(res));

    // 5. initialize tracker object
    ClatdTracker tracker;
    int ret = tracker.init(networkId, interface, v4interface, nat64Prefix);
    if (ret) return ret;

    // 6. create a throwaway socket to reserve a file descriptor number
    res = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (res == -1) {
        res = errno;
        ALOGE("socket(ipv6/udp) failed (%s)", strerror(res));
        return -res;
    }
    unique_fd passedTunFd(res);

    // 7. this is the FD we'll pass to clatd on the cli, so need it as a string
    char passedTunFdStr[INT32_STRLEN];
    snprintf(passedTunFdStr, sizeof(passedTunFdStr), "%d", passedTunFd.get());

    // 8. create a raw socket for clatd sending packets to the tunnel
    res = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW);
    if (res < 0) {
        res = errno;
        ALOGE("raw socket failed: %s", strerror(errno));
        return -res;
    }
    unique_fd tmpRawSock(res);

    const int mark = tracker.fwmark.intValue;
    if (mark != MARK_UNSET &&
        setsockopt(tmpRawSock, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) < 0) {
        res = errno;
        ALOGE("could not set mark on raw socket: %s", strerror(errno));
        return -res;
    }

    // create a throwaway socket to reserve a file descriptor number
    res = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (res == -1) {
        res = errno;
        ALOGE("socket(ipv6/udp) failed (%s) for raw socket", strerror(res));
        return -res;
    }
    unique_fd passedRawSock(res);

    // this is the raw socket FD we'll pass to clatd on the cli, so need it as a string
    char passedRawSockStr[INT32_STRLEN];
    snprintf(passedRawSockStr, sizeof(passedRawSockStr), "%d", passedRawSock.get());

    // 9. create a packet socket for clatd sending packets to the tunnel
    // Will eventually be bound to htons(ETH_P_IPV6) protocol,
    // but only after appropriate bpf filter is attached.
    res = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (res < 0) {
        res = errno;
        ALOGE("packet socket failed: %s", strerror(errno));
        return -res;
    }
    unique_fd tmpPacketSock(res);

    // create a throwaway socket to reserve a file descriptor number
    res = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (res == -1) {
        res = errno;
        ALOGE("socket(ipv6/udp) failed (%s) for packet socket", strerror(res));
        return -res;
    }
    unique_fd passedPacketSock(res);

    // this is the packet socket FD we'll pass to clatd on the cli, so need it as a string
    char passedPacketSockStr[INT32_STRLEN];
    snprintf(passedPacketSockStr, sizeof(passedPacketSock), "%d", passedPacketSock.get());

    // 10. configure tun and clat interface
    struct tun_data tunnel = {.fd4 = tmpTunFd, .read_fd6 = tmpPacketSock, .write_fd6 = tmpRawSock};
    res = configure_interface(&tracker, &tunnel);
    if (res) {
        ALOGE("configure interface failed: %s", strerror(res));
        return -res;
    }

    // 11. we're going to use this as argv[0] to clatd to make ps output more useful
    std::string progname("clatd-");
    progname += tracker.iface;

    // clang-format off
    const char* args[] = {progname.c_str(),
                          "-i", tracker.iface,
                          "-p", tracker.pfx96String,
                          "-4", tracker.v4Str,
                          "-6", tracker.v6Str,
                          "-t", passedTunFdStr,
                          "-r", passedPacketSockStr,
                          "-w", passedRawSockStr,
                          nullptr};
    // clang-format on

    // 12. register vfork requirement
    posix_spawnattr_t attr;
    res = posix_spawnattr_init(&attr);
    if (res) {
        ALOGE("posix_spawnattr_init failed (%s)", strerror(res));
        return -res;
    }
    const android::base::ScopeGuard attrGuard = [&] { posix_spawnattr_destroy(&attr); };
    res = posix_spawnattr_setflags(&attr, POSIX_SPAWN_USEVFORK);
    if (res) {
        ALOGE("posix_spawnattr_setflags failed (%s)", strerror(res));
        return -res;
    }

    // 13. register dup2() action: this is what 'clears' the CLOEXEC flag
    // on the tun fd that we want the child clatd process to inherit
    // (this will happen after the vfork, and before the execve)
    posix_spawn_file_actions_t fa;
    res = posix_spawn_file_actions_init(&fa);
    if (res) {
        ALOGE("posix_spawn_file_actions_init failed (%s)", strerror(res));
        return -res;
    }
    const android::base::ScopeGuard faGuard = [&] { posix_spawn_file_actions_destroy(&fa); };
    res = posix_spawn_file_actions_adddup2(&fa, tmpTunFd, passedTunFd);
    if (res) {
        ALOGE("posix_spawn_file_actions_adddup2 tun fd failed (%s)", strerror(res));
        return -res;
    }
    res = posix_spawn_file_actions_adddup2(&fa, tmpPacketSock, passedPacketSock);
    if (res) {
        ALOGE("posix_spawn_file_actions_adddup2 packet socket failed (%s)", strerror(res));
        return -res;
    }
    res = posix_spawn_file_actions_adddup2(&fa, tmpRawSock, passedRawSock);
    if (res) {
        ALOGE("posix_spawn_file_actions_adddup2 raw socket failed (%s)", strerror(res));
        return -res;
    }

    // 14. add the drop rule for iptables.
    setIptablesDropRule(true, tracker.iface, tracker.pfx96String, tracker.v6Str);

    // 15. actually perform vfork/dup2/execve
    res = posix_spawn(&tracker.pid, kClatdPath, &fa, &attr, (char* const*)args, nullptr);
    if (res) {
        ALOGE("posix_spawn failed (%s)", strerror(res));
        return -res;
    }

    // 16. configure eBPF offload - if possible
    maybeStartBpf(tracker);

    mClatdTrackers[interface] = tracker;
    ALOGD("clatd started on %s", interface.c_str());

    *v6Str = tracker.v6Str;
    return 0;
}

int ClatdController::stopClatd(const std::string& interface) {
    std::lock_guard guard(mutex);
    ClatdTracker* tracker = getClatdTracker(interface);

    if (tracker == nullptr) {
        ALOGE("clatd already stopped");
        return -ENODEV;
    }

    ALOGD("Stopping clatd pid=%d on %s", tracker->pid, interface.c_str());

    maybeStopBpf(*tracker);

    ::stopProcess(tracker->pid, "clatd");

    setIptablesDropRule(false, tracker->iface, tracker->pfx96String, tracker->v6Str);
    mClatdTrackers.erase(interface);

    ALOGD("clatd on %s stopped", interface.c_str());

    return 0;
}

void ClatdController::dumpEgress(DumpWriter& dw) {
    if (!mClatEgress4Map.isValid()) return;  // if unsupported just don't dump anything

    ScopedIndent bpfIndent(dw);
    dw.println("BPF egress map: iif(iface) v4Addr -> v6Addr nat64Prefix oif(iface)");

    ScopedIndent bpfDetailIndent(dw);
    const auto printClatMap = [&dw](const ClatEgress4Key& key, const ClatEgress4Value& value,
                                    const BpfMap<ClatEgress4Key, ClatEgress4Value>&) {
        char iifStr[IFNAMSIZ] = "?";
        char local4Str[INET_ADDRSTRLEN] = "?";
        char local6Str[INET6_ADDRSTRLEN] = "?";
        char pfx96Str[INET6_ADDRSTRLEN] = "?";
        char oifStr[IFNAMSIZ] = "?";

        if_indextoname(key.iif, iifStr);
        inet_ntop(AF_INET, &key.local4, local4Str, sizeof(local4Str));
        inet_ntop(AF_INET6, &value.local6, local6Str, sizeof(local6Str));
        inet_ntop(AF_INET6, &value.pfx96, pfx96Str, sizeof(pfx96Str));
        if_indextoname(value.oif, oifStr);

        dw.println("%u(%s) %s -> %s %s/96 %u(%s) %s", key.iif, iifStr, local4Str, local6Str,
                   pfx96Str, value.oif, oifStr, value.oifIsEthernet ? "ether" : "rawip");
        return Result<void>();
    };
    auto res = mClatEgress4Map.iterateWithValue(printClatMap);
    if (!res.ok()) {
        dw.println("Error printing BPF map: %s", res.error().message().c_str());
    }
}

void ClatdController::dumpIngress(DumpWriter& dw) {
    if (!mClatIngress6Map.isValid()) return;  // if unsupported just don't dump anything

    ScopedIndent bpfIndent(dw);
    dw.println("BPF ingress map: iif(iface) nat64Prefix v6Addr -> v4Addr oif(iface)");

    ScopedIndent bpfDetailIndent(dw);
    const auto printClatMap = [&dw](const ClatIngress6Key& key, const ClatIngress6Value& value,
                                    const BpfMap<ClatIngress6Key, ClatIngress6Value>&) {
        char iifStr[IFNAMSIZ] = "?";
        char pfx96Str[INET6_ADDRSTRLEN] = "?";
        char local6Str[INET6_ADDRSTRLEN] = "?";
        char local4Str[INET_ADDRSTRLEN] = "?";
        char oifStr[IFNAMSIZ] = "?";

        if_indextoname(key.iif, iifStr);
        inet_ntop(AF_INET6, &key.pfx96, pfx96Str, sizeof(pfx96Str));
        inet_ntop(AF_INET6, &key.local6, local6Str, sizeof(local6Str));
        inet_ntop(AF_INET, &value.local4, local4Str, sizeof(local4Str));
        if_indextoname(value.oif, oifStr);

        dw.println("%u(%s) %s/96 %s -> %s %u(%s)", key.iif, iifStr, pfx96Str, local6Str, local4Str,
                   value.oif, oifStr);
        return Result<void>();
    };
    auto res = mClatIngress6Map.iterateWithValue(printClatMap);
    if (!res.ok()) {
        dw.println("Error printing BPF map: %s", res.error().message().c_str());
    }
}

void ClatdController::dumpTrackers(DumpWriter& dw) {
    ScopedIndent trackerIndent(dw);
    dw.println("Trackers: iif[iface] nat64Prefix v6Addr -> v4Addr v4iif[v4iface] [fwmark]");

    ScopedIndent trackerDetailIndent(dw);
    for (const auto& pair : mClatdTrackers) {
        const ClatdTracker& tracker = pair.second;
        dw.println("%u[%s] %s/96 %s -> %s %u[%s] [%s]", tracker.ifIndex, tracker.iface,
                   tracker.pfx96String, tracker.v6Str, tracker.v4Str, tracker.v4ifIndex,
                   tracker.v4iface, tracker.fwmarkString);
    }
}

void ClatdController::dump(DumpWriter& dw) {
    std::lock_guard guard(mutex);

    ScopedIndent clatdIndent(dw);
    dw.println("ClatdController");

    dumpTrackers(dw);
    dumpIngress(dw);
    dumpEgress(dw);
}

auto ClatdController::isIpv4AddressFreeFunc = isIpv4AddressFree;
auto ClatdController::iptablesRestoreFunction = execIptablesRestore;

}  // namespace net
}  // namespace android
