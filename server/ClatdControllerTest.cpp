/*
 * Copyright 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * ClatdControllerTest.cpp - unit tests for ClatdController.cpp
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <linux/if_packet.h>
#include <netutils/ifc.h>

extern "C" {
#include <checksum.h>
}

#include "ClatdController.h"
#include "IptablesBaseTest.h"
#include "NetworkController.h"
#include "tun_interface.h"

static const char kIPv4LocalAddr[] = "192.0.0.4";

namespace android {
namespace net {

using android::base::StringPrintf;
using android::net::TunInterface;

// Mock functions for isIpv4AddressFree.
bool neverFree(in_addr_t /* addr */) {
    return 0;
}
bool alwaysFree(in_addr_t /* addr */) {
    return 1;
}
bool only2Free(in_addr_t addr) {
    return (ntohl(addr) & 0xff) == 2;
}
bool over6Free(in_addr_t addr) {
    return (ntohl(addr) & 0xff) >= 6;
}
bool only10Free(in_addr_t addr) {
    return (ntohl(addr) & 0xff) == 10;
}

class ClatdControllerTest : public IptablesBaseTest {
  public:
    ClatdControllerTest() : mClatdCtrl(nullptr) {
        ClatdController::iptablesRestoreFunction = fakeExecIptablesRestore;
    }

    void SetUp() { resetIpv4AddressFreeFunc(); }

  protected:
    ClatdController mClatdCtrl;
    void setIpv4AddressFreeFunc(bool (*func)(in_addr_t)) {
        ClatdController::isIpv4AddressFreeFunc = func;
    }
    void resetIpv4AddressFreeFunc() {
        ClatdController::isIpv4AddressFreeFunc = ClatdController::isIpv4AddressFree;
    }
    in_addr_t selectIpv4Address(const in_addr a, int16_t b) {
        return ClatdController::selectIpv4Address(a, b);
    }
    void makeChecksumNeutral(in6_addr* a, const in_addr b, const in6_addr& c) {
        ClatdController::makeChecksumNeutral(a, b, c);
    }
    int detect_mtu(const struct in6_addr* a, uint32_t b, uint32_t c) {
        return mClatdCtrl.detect_mtu(a, b, c);
    }
    int configure_tun_ip(const char* a, const char* b, int c) {
        std::lock_guard guard(mClatdCtrl.mutex);
        return mClatdCtrl.configure_tun_ip(a, b, c);
    }
    int configure_clat_ipv6_address(ClatdController::ClatdTracker* a,
                                    ClatdController::tun_data* b) {
        std::lock_guard guard(mClatdCtrl.mutex);
        return mClatdCtrl.configure_clat_ipv6_address(a, b);
    }
};

TEST_F(ClatdControllerTest, SelectIpv4Address) {
    struct in_addr addr;

    inet_pton(AF_INET, kIPv4LocalAddr, &addr);

    // If no addresses are free, return INADDR_NONE.
    setIpv4AddressFreeFunc(neverFree);
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 29));
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 16));

    // If the configured address is free, pick that. But a prefix that's too big is invalid.
    setIpv4AddressFreeFunc(alwaysFree);
    EXPECT_EQ(inet_addr(kIPv4LocalAddr), selectIpv4Address(addr, 29));
    EXPECT_EQ(inet_addr(kIPv4LocalAddr), selectIpv4Address(addr, 20));
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 15));

    // A prefix length of 32 works, but anything above it is invalid.
    EXPECT_EQ(inet_addr(kIPv4LocalAddr), selectIpv4Address(addr, 32));
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 33));

    // If another address is free, pick it.
    setIpv4AddressFreeFunc(over6Free);
    EXPECT_EQ(inet_addr("192.0.0.6"), selectIpv4Address(addr, 29));

    // Check that we wrap around to addresses that are lower than the first address.
    setIpv4AddressFreeFunc(only2Free);
    EXPECT_EQ(inet_addr("192.0.0.2"), selectIpv4Address(addr, 29));
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 30));

    // If a free address exists outside the prefix, we don't pick it.
    setIpv4AddressFreeFunc(only10Free);
    EXPECT_EQ(INADDR_NONE, selectIpv4Address(addr, 29));
    EXPECT_EQ(inet_addr("192.0.0.10"), selectIpv4Address(addr, 24));

    // Now try using the real function which sees if IP addresses are free using bind().
    // Assume that the machine running the test has the address 127.0.0.1, but not 8.8.8.8.
    resetIpv4AddressFreeFunc();
    addr.s_addr = inet_addr("8.8.8.8");
    EXPECT_EQ(inet_addr("8.8.8.8"), selectIpv4Address(addr, 29));

    addr.s_addr = inet_addr("127.0.0.1");
    EXPECT_EQ(inet_addr("127.0.0.2"), selectIpv4Address(addr, 29));
}

TEST_F(ClatdControllerTest, MakeChecksumNeutral) {
    // We can't test generateIPv6Address here since it requires manipulating routing, which we can't
    // do without talking to the real netd on the system.
    uint32_t rand = arc4random_uniform(0xffffffff);
    uint16_t rand1 = rand & 0xffff;
    uint16_t rand2 = (rand >> 16) & 0xffff;
    std::string v6PrefixStr = StringPrintf("2001:db8:%x:%x", rand1, rand2);
    std::string v6InterfaceAddrStr = StringPrintf("%s::%x:%x", v6PrefixStr.c_str(), rand2, rand1);
    std::string nat64PrefixStr = StringPrintf("2001:db8:%x:%x::", rand2, rand1);

    in_addr v4 = {inet_addr(kIPv4LocalAddr)};
    in6_addr v6InterfaceAddr;
    ASSERT_TRUE(inet_pton(AF_INET6, v6InterfaceAddrStr.c_str(), &v6InterfaceAddr));
    in6_addr nat64Prefix;
    ASSERT_TRUE(inet_pton(AF_INET6, nat64PrefixStr.c_str(), &nat64Prefix));

    // Generate a boatload of random IIDs.
    int onebits = 0;
    uint64_t prev_iid = 0;
    for (int i = 0; i < 100000; i++) {
        in6_addr v6 = v6InterfaceAddr;
        makeChecksumNeutral(&v6, v4, nat64Prefix);

        // Check the generated IP address is in the same prefix as the interface IPv6 address.
        EXPECT_EQ(0, memcmp(&v6, &v6InterfaceAddr, 8));

        // Check that consecutive IIDs are not the same.
        uint64_t iid = *(uint64_t*)(&v6.s6_addr[8]);
        ASSERT_TRUE(iid != prev_iid)
                << "Two consecutive random IIDs are the same: " << std::showbase << std::hex << iid
                << "\n";
        prev_iid = iid;

        // Check that the IID is checksum-neutral with the NAT64 prefix and the
        // local prefix.
        uint16_t c1 = ip_checksum_finish(ip_checksum_add(0, &v4, sizeof(v4)));
        uint16_t c2 = ip_checksum_finish(ip_checksum_add(0, &nat64Prefix, sizeof(nat64Prefix)) +
                                         ip_checksum_add(0, &v6, sizeof(v6)));

        if (c1 != c2) {
            char v6Str[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &v6, v6Str, sizeof(v6Str));
            FAIL() << "Bad IID: " << v6Str << " not checksum-neutral with " << kIPv4LocalAddr
                   << " and " << nat64PrefixStr.c_str() << std::showbase << std::hex
                   << "\n  IPv4 checksum: " << c1 << "\n  IPv6 checksum: " << c2 << "\n";
        }

        // Check that IIDs are roughly random and use all the bits by counting the
        // total number of bits set to 1 in a random sample of 100000 generated IIDs.
        onebits += __builtin_popcountll(*(uint64_t*)&iid);
    }
    EXPECT_LE(3190000, onebits);
    EXPECT_GE(3210000, onebits);
}

TEST_F(ClatdControllerTest, DetectMtu) {
    // ::1 with bottom 32 bits set to 1 is still ::1 which routes via lo with mtu of 64KiB
    ASSERT_EQ(detect_mtu(&in6addr_loopback, htonl(1), 0 /*MARK_UNSET*/), 65536);
}

// Get the first IPv4 address for a given interface name
in_addr* getinterface_ip(const char* interface) {
    ifaddrs *ifaddr, *ifa;
    in_addr* retval = nullptr;

    if (getifaddrs(&ifaddr) == -1) return nullptr;

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        if ((strcmp(ifa->ifa_name, interface) == 0) && (ifa->ifa_addr->sa_family == AF_INET)) {
            retval = (in_addr*)malloc(sizeof(in_addr));
            if (retval) {
                const sockaddr_in* sin = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
                *retval = sin->sin_addr;
            }
            break;
        }
    }

    freeifaddrs(ifaddr);
    return retval;
}

TEST_F(ClatdControllerTest, ConfigureTunIpManual) {
    // Create an interface for configure_tun_ip to configure and bring up.
    TunInterface v4Iface;
    ASSERT_EQ(0, v4Iface.init());

    configure_tun_ip(v4Iface.name().c_str(), "192.0.2.1" /* v4Str */, 1472 /* mtu */);
    in_addr* ip = getinterface_ip(v4Iface.name().c_str());
    ASSERT_NE(nullptr, ip);
    EXPECT_EQ(inet_addr("192.0.2.1"), ip->s_addr);
    free(ip);

    v4Iface.destroy();
}

ClatdController::tun_data makeTunData() {
    // Create some fake but realistic-looking sockets so configure_clat_ipv6_address doesn't balk.
    return {
            .read_fd6 = socket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, htons(ETH_P_IPV6)),
            .write_fd6 = socket(AF_INET6, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_RAW),
            .fd4 = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0),
    };
}

void cleanupTunData(ClatdController::tun_data* tunnel) {
    close(tunnel->write_fd6);
    close(tunnel->read_fd6);
    close(tunnel->fd4);
}

TEST_F(ClatdControllerTest, ConfigureIpv6Address) {
    // Create an interface for configure_clat_ipv6_address to attach socket filter to.
    TunInterface v6Iface;
    ASSERT_EQ(0, v6Iface.init());
    ClatdController::tun_data tunnel = makeTunData();

    // Only initialize valid value to configure_clat_ipv6_address() required fields
    // {ifIndex, v6, v6Str}. The uninitialized fields have initialized with invalid
    // value just in case.
    ClatdController::ClatdTracker tracker = {
            .pid = -1,              // unused
            .ifIndex = 0,           // initialize later
            .iface = "",            // unused
            .v4ifIndex = 0,         // unused
            .v4iface = "",          // unused
            .fwmark.intValue = 0,   // unused
            .fwmarkString = "0x0",  // unused
            .v4 = {},               // unused
            .v4Str = "",            // unused
            .v6 = {},               // initialize later
            .v6Str = "",            // initialize later
            .pfx96 = {},            // unused
            .pfx96String = "",      // unused
    };
    tracker.ifIndex = static_cast<unsigned int>(v6Iface.ifindex());
    const char* addrStr = "2001:db8::f00";
    ASSERT_EQ(1, inet_pton(AF_INET6, addrStr, &tracker.v6));
    strlcpy(tracker.v6Str, addrStr, sizeof(tracker.v6Str));

    ASSERT_EQ(0, configure_clat_ipv6_address(&tracker, &tunnel));

    // Check that the packet socket is bound to the interface. We can't check the socket filter
    // because there is no way to fetch it from the kernel.
    sockaddr_ll sll;
    socklen_t len = sizeof(sll);
    ASSERT_EQ(0, getsockname(tunnel.read_fd6, reinterpret_cast<sockaddr*>(&sll), &len));
    EXPECT_EQ(htons(ETH_P_IPV6), sll.sll_protocol);
    EXPECT_EQ(sll.sll_ifindex, v6Iface.ifindex());

    v6Iface.destroy();
    cleanupTunData(&tunnel);
}

}  // namespace net
}  // namespace android
