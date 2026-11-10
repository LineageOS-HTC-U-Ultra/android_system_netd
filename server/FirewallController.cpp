/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <set>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <limits>

#define LOG_TAG "FirewallController"
#define LOG_NDEBUG 0

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log.h>

#include "Controllers.h"
#include "FirewallController.h"
#include "NetdConstants.h"

using android::base::Join;
using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace net {

auto FirewallController::execIptablesRestore = ::execIptablesRestore;

const char* FirewallController::TABLE = "filter";

const char* FirewallController::LOCAL_INPUT = "fw_INPUT";
const char* FirewallController::LOCAL_OUTPUT = "fw_OUTPUT";
const char* FirewallController::LOCAL_FORWARD = "fw_FORWARD";

namespace {

constexpr ChildChain kUidFirewallChains[] = {
        DOZABLE, STANDBY, POWERSAVE, RESTRICTED, LOW_POWER_STANDBY,
        BACKGROUND, OEM_DENY_1, OEM_DENY_2, OEM_DENY_3,
};

}  // namespace

// ICMPv6 types that are required for any form of IPv6 connectivity to work. Note that because the
// fw_dozable chain is called from both INPUT and OUTPUT, this includes both packets that we need
// to be able to send (e.g., RS, NS), and packets that we need to receive (e.g., RA, NA).
const char* FirewallController::ICMPV6_TYPES[] = {
    "packet-too-big",
    "router-solicitation",
    "router-advertisement",
    "neighbour-solicitation",
    "neighbour-advertisement",
    "redirect",
};

FirewallController::FirewallController(void) {
    // If no rules are set, it's in DENYLIST mode
    mFirewallType = DENYLIST;
    mIfaceRules = {};
}

int FirewallController::setupIptablesHooks(void) {
    int result = flushRules();
    if (android::base::GetBoolProperty("ro.kernel.ebpf.supported", true)) return result;
    for (const auto chain : kUidFirewallChains) {
        const auto name = getChainName(chain);
        const bool allowlist = getFirewallType(chain) == ALLOWLIST;
        const std::vector<int32_t> noUids;
        result |= replaceUidChain(name, allowlist, noUids);
    }
    return result;
}

int FirewallController::setFirewallType(FirewallType ftype) {
    int res = 0;
    if (mFirewallType != ftype) {
        // flush any existing rules
        resetFirewall();

        if (ftype == ALLOWLIST) {
            // create default rule to drop all traffic
            std::string command =
                "*filter\n"
                "-A fw_INPUT -j DROP\n"
                "-A fw_OUTPUT -j REJECT\n"
                "-A fw_FORWARD -j REJECT\n"
                "COMMIT\n";
            res = execIptablesRestore(V4V6, command.c_str());
        }

        // Set this after calling disableFirewall(), since it defaults to ALLOWLIST there
        mFirewallType = ftype;
    }
    return res ? -EREMOTEIO : 0;
}

int FirewallController::flushRules() {
    std::string command =
            "*filter\n"
            ":fw_INPUT -\n"
            ":fw_OUTPUT -\n"
            ":fw_FORWARD -\n"
            "-6 -A fw_OUTPUT ! -o lo -s ::1 -j DROP\n"
            "COMMIT\n";

    return (execIptablesRestore(V4V6, command.c_str()) == 0) ? 0 : -EREMOTEIO;
}

int FirewallController::resetFirewall(void) {
    mFirewallType = ALLOWLIST;
    mIfaceRules.clear();
    return flushRules();
}

int FirewallController::isFirewallEnabled(void) {
    // TODO: verify that rules are still in place near top
    return -1;
}

int FirewallController::setInterfaceRule(const char* iface, FirewallRule rule) {
    if (mFirewallType == DENYLIST) {
        // Unsupported in DENYLIST mode
        return -EINVAL;
    }

    if (!isIfaceName(iface)) {
        errno = ENOENT;
        return -ENOENT;
    }

    // Only delete rules if we actually added them, because otherwise our iptables-restore
    // processes will terminate with "no such rule" errors and cause latency penalties while we
    // spin up new ones.
    const char* op;
    if (rule == ALLOW && mIfaceRules.find(iface) == mIfaceRules.end()) {
        op = "-I";
        mIfaceRules.insert(iface);
    } else if (rule == DENY && mIfaceRules.find(iface) != mIfaceRules.end()) {
        op = "-D";
        mIfaceRules.erase(iface);
    } else {
        return 0;
    }

    std::string command = Join(std::vector<std::string> {
        "*filter",
        StringPrintf("%s fw_INPUT -i %s -j RETURN", op, iface),
        StringPrintf("%s fw_OUTPUT -o %s -j RETURN", op, iface),
        "COMMIT\n"
    }, "\n");
    return (execIptablesRestore(V4V6, command) == 0) ? 0 : -EREMOTEIO;
}

const char* FirewallController::getChainName(ChildChain chain) {
    switch (chain) {
        case DOZABLE: return "fw_dozable";
        case STANDBY: return "fw_standby";
        case POWERSAVE: return "fw_powersave";
        case RESTRICTED: return "fw_restricted";
        case LOW_POWER_STANDBY: return "fw_low_power_standby";
        case BACKGROUND: return "fw_background";
        case OEM_DENY_1: return "fw_oem_deny_1";
        case OEM_DENY_2: return "fw_oem_deny_2";
        case OEM_DENY_3: return "fw_oem_deny_3";
        default: return nullptr;
    }
}

bool FirewallController::isSupportedChainName(const std::string& name, ChildChain* chain) {
    for (const auto candidate : kUidFirewallChains) {
        if (name == getChainName(candidate)) {
            *chain = candidate;
            return true;
        }
    }
    return false;
}

FirewallType FirewallController::getFirewallType(ChildChain chain) const {
    switch (chain) {
        case DOZABLE:
        case POWERSAVE:
        case RESTRICTED:
        case LOW_POWER_STANDBY:
        case BACKGROUND:
            return ALLOWLIST;
        case STANDBY:
        case OEM_DENY_1:
        case OEM_DENY_2:
        case OEM_DENY_3:
            return DENYLIST;
        default:
            return DENYLIST;
    }
}

std::string FirewallController::makeUidRules(IptablesTarget target, const char* name,
                                              bool allowlist,
                                              const std::vector<int32_t>& uids) const {
    std::string commands = StringPrintf("*filter\n:%s -\n", name);
    if (allowlist) {
        StringAppendF(&commands, "-A %s -m owner --uid-owner 0-%u -j RETURN\n", name,
                      static_cast<unsigned int>(AID_APP - 1));
        for (const auto uid : uids) {
            StringAppendF(&commands, "-A %s -m owner --uid-owner %d -j RETURN\n", name, uid);
        }
        const auto maxUid = static_cast<unsigned int>(std::numeric_limits<uid_t>::max() - 1);
        StringAppendF(&commands, "-A %s -m owner ! --uid-owner 0-%u -j RETURN\n", name, maxUid);
        StringAppendF(&commands, "-A %s -p esp -j RETURN\n", name);
        StringAppendF(&commands, "-A %s -i lo -j RETURN\n-A %s -o lo -j RETURN\n", name, name);
        StringAppendF(&commands, "-A %s -p tcp --tcp-flags RST RST -j RETURN\n", name);
        commands.append(makeCriticalCommands(target, name));
        StringAppendF(&commands, "-A %s -j DROP\n", name);
    } else {
        StringAppendF(&commands, "-A %s -i lo -j RETURN\n-A %s -o lo -j RETURN\n", name, name);
        StringAppendF(&commands, "-A %s -p tcp --tcp-flags RST RST -j RETURN\n", name);
        for (const auto uid : uids) {
            StringAppendF(&commands, "-A %s -m owner --uid-owner %d -j DROP\n", name, uid);
        }
    }
    commands.append("COMMIT\n");
    return commands;
}

int FirewallController::replaceUidChain(const std::string& name, bool allowlist,
                                        const std::vector<int32_t>& uids) {
    ChildChain chain = INVALID_CHAIN;
    if (!isSupportedChainName(name, &chain) || (getFirewallType(chain) == ALLOWLIST) != allowlist) {
        return -EINVAL;
    }
    // INVALID_UID can be present in framework-generated UID lists. It is a
    // sentinel, not a packet owner UID, and iptables rejects it as a match.
    std::vector<int32_t> validUids;
    validUids.reserve(uids.size());
    for (const auto uid : uids) {
        if (uid >= 0) validUids.push_back(uid);
    }

    const auto v4 = makeUidRules(V4, name.c_str(), allowlist, validUids);
    const auto v6 = makeUidRules(V6, name.c_str(), allowlist, validUids);
    const int result = execIptablesRestore(V4, v4) | execIptablesRestore(V6, v6);
    if (result == 0) {
        mUidRules[chain] = std::set<int32_t>(validUids.begin(), validUids.end());
    }
    return result == 0 ? 0 : -EREMOTEIO;
}

int FirewallController::setUidRule(ChildChain chain, int uid, FirewallRule rule) {
    const char* name = getChainName(chain);
    if (name == nullptr || uid < 0 || (rule != ALLOW && rule != DENY)) return -EINVAL;
    const bool allowlist = getFirewallType(chain) == ALLOWLIST;
    const bool add = allowlist ? rule == ALLOW : rule == DENY;
    auto& rules = mUidRules[chain];
    if ((rules.count(uid) != 0) == add) return 0;

    const char* operation = add ? (allowlist ? "-I" : "-A") : "-D";
    const char* target = allowlist ? "RETURN" : "DROP";
    const std::string command = StringPrintf(
            "*filter\n%s %s -m owner --uid-owner %d -j %s\nCOMMIT\n",
            operation, name, uid, target);
    const int result = execIptablesRestore(V4V6, command);
    if (result == 0) {
        if (add) rules.insert(uid);
        else rules.erase(uid);
    }
    return result == 0 ? 0 : -EREMOTEIO;
}

int FirewallController::enableChildChains(ChildChain chain, bool enable) {
    const char* name = getChainName(chain);
    if (name == nullptr) return -EINVAL;
    const bool enabled = mEnabledChains.count(chain) != 0;
    if (enabled == enable) return 0;
    const char* operation = enable ? "-A" : "-D";
    const std::string command = StringPrintf(
            "*filter\n%s fw_INPUT -j %s\n%s fw_OUTPUT -j %s\nCOMMIT\n",
            operation, name, operation, name);
    const int result = execIptablesRestore(V4V6, command);
    if (result == 0) {
        if (enable) mEnabledChains.insert(chain);
        else mEnabledChains.erase(chain);
    }
    return result == 0 ? 0 : -EREMOTEIO;
}

/* static */
std::string FirewallController::makeCriticalCommands(IptablesTarget target, const char* chainName) {
    // Allow ICMPv6 packets necessary to make IPv6 connectivity work. http://b/23158230 .
    std::string commands;
    if (target == V6) {
        for (size_t i = 0; i < ARRAY_SIZE(ICMPV6_TYPES); i++) {
            StringAppendF(&commands, "-A %s -p icmpv6 --icmpv6-type %s -j RETURN\n",
                   chainName, ICMPV6_TYPES[i]);
        }
    }
    return commands;
}

}  // namespace net
}  // namespace android
