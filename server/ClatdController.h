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

#ifndef _CLATD_CONTROLLER_H
#define _CLATD_CONTROLLER_H

#include <map>
#include <mutex>
#include <string>

#include <linux/if.h>
#include <netinet/in.h>

#include <android-base/thread_annotations.h>

#include "Fwmark.h"
#include "NetdConstants.h"
#include "bpf/BpfMap.h"
#include "bpf_shared.h"
#include "netdutils/DumpWriter.h"

namespace android {
namespace net {

class NetworkController;

class ClatdController {
  public:
    explicit ClatdController(NetworkController* controller) EXCLUDES(mutex)
        : mNetCtrl(controller){};
    virtual ~ClatdController() EXCLUDES(mutex){};

    /* First thing init/startClatd/stopClatd/dump do is grab the mutex. */
    void init(void) EXCLUDES(mutex);

    int startClatd(const std::string& interface, const std::string& nat64Prefix,
                   std::string* v6Addr) EXCLUDES(mutex);
    int stopClatd(const std::string& interface) EXCLUDES(mutex);

    void dump(netdutils::DumpWriter& dw) EXCLUDES(mutex);

    // Public struct ClatdTracker and tun_data for testing. gtest/TEST_F macro changes the class
    // name. In TEST_F(ClatdControllerTest..), can't access struct ClatdTracker and tun_data.
    // TODO: probably use gtest/FRIEND_TEST macro.
    struct ClatdTracker {
        pid_t pid = -1;
        unsigned ifIndex;
        char iface[IFNAMSIZ];
        unsigned v4ifIndex;
        char v4iface[IFNAMSIZ];
        Fwmark fwmark;
        char fwmarkString[UINT32_STRLEN];
        in_addr v4;
        char v4Str[INET_ADDRSTRLEN];
        in6_addr v6;
        char v6Str[INET6_ADDRSTRLEN];
        in6_addr pfx96;
        char pfx96String[INET6_ADDRSTRLEN];

        int init(unsigned networkId, const std::string& interface, const std::string& v4interface,
                 const std::string& nat64Prefix);
    };

    // Public for testing. See above reason in struct ClatdTracker.
    struct tun_data {
        int read_fd6, write_fd6, fd4;
    };

  private:
    std::mutex mutex;

    const NetworkController* mNetCtrl GUARDED_BY(mutex);
    std::map<std::string, ClatdTracker> mClatdTrackers GUARDED_BY(mutex);
    ClatdTracker* getClatdTracker(const std::string& interface) REQUIRES(mutex);

    void dumpEgress(netdutils::DumpWriter& dw) REQUIRES(mutex);
    void dumpIngress(netdutils::DumpWriter& dw) REQUIRES(mutex);
    void dumpTrackers(netdutils::DumpWriter& dw) REQUIRES(mutex);

    static in_addr_t selectIpv4Address(const in_addr ip, int16_t prefixlen);
    static int generateIpv6Address(const char* iface, const in_addr v4, const in6_addr& nat64Prefix,
                                   in6_addr* v6);
    static void makeChecksumNeutral(in6_addr* v6, const in_addr v4, const in6_addr& nat64Prefix);

    bpf::BpfMap<ClatEgress4Key, ClatEgress4Value> mClatEgress4Map GUARDED_BY(mutex);
    bpf::BpfMap<ClatIngress6Key, ClatIngress6Value> mClatIngress6Map GUARDED_BY(mutex);

    void maybeStartBpf(const ClatdTracker& tracker) REQUIRES(mutex);
    void maybeStopBpf(const ClatdTracker& tracker) REQUIRES(mutex);

    int detect_mtu(const struct in6_addr* plat_subnet, uint32_t plat_suffix, uint32_t mark);
    int configure_interface(struct ClatdTracker* tracker, struct tun_data* tunnel) REQUIRES(mutex);
    int configure_tun_ip(const char* v4iface, const char* v4Str, int mtu) REQUIRES(mutex);
    int configure_clat_ipv6_address(struct ClatdTracker* tracker, struct tun_data* tunnel)
            REQUIRES(mutex);
    int add_anycast_address(int sock, struct in6_addr* addr, int ifindex) REQUIRES(mutex);
    int configure_packet_socket(int sock, in6_addr* addr, int ifindex) REQUIRES(mutex);

    // For testing.
    friend class ClatdControllerTest;

    static bool (*isIpv4AddressFreeFunc)(in_addr_t);
    static bool isIpv4AddressFree(in_addr_t addr);
    static int (*iptablesRestoreFunction)(IptablesTarget target, const std::string& commands);
};

}  // namespace net
}  // namespace android

#endif
