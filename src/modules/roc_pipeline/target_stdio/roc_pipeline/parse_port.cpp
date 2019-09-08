/*
 * Copyright (c) 2015 Roc authors
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "roc_pipeline/parse_port.h"
#include "roc_core/log.h"

namespace roc {
namespace pipeline {

namespace {

bool match_proto(PortType type, const char* str, PortProtocol& proto) {
    switch (type) {
    case Port_AudioSource:
        if (strcmp(str, "rtp") == 0) {
            proto = Proto_RTP;
        } else if (strcmp(str, "rtp+rs8m") == 0) {
            proto = Proto_RTP_RSm8_Source;
        } else if (strcmp(str, "rtp+ldpc") == 0) {
            proto = Proto_RTP_LDPC_Source;
        } else {
            roc_log(LogError, "parse port: '%s' is not a valid source port protocol",
                    str);
            return false;
        }
        return true;

    case Port_AudioRepair:
        if (strcmp(str, "rs8m") == 0) {
            proto = Proto_RSm8_Repair;
        } else if (strcmp(str, "ldpc") == 0) {
            proto = Proto_LDPC_Repair;
        } else {
            roc_log(LogError, "parse port: '%s' is not a valid repair port protocol",
                    str);
            return false;
        }
        return true;
    }

    roc_log(LogError, "parse port: unsupported port type");
    return false;
}

PortProtocol parse_proto(const char* begin, const char* end, PortType type) {
    char proto_buf[16] = {};

    if (size_t(end - begin) > sizeof(proto_buf) - 1) {
        roc_log(LogError, "parse port: bad protocol: too long");
        return Proto_None;
    }

    memcpy(proto_buf, begin, size_t(end - begin));
    proto_buf[end - begin] = '\0';

    PortProtocol protocol = Proto_None;
    if (!match_proto(type, proto_buf, protocol)) {
        return Proto_None;
    }

    return protocol;
}

long parse_port_num(const char* port) {
    if (!isdigit(*port)) {
        roc_log(LogError, "parse port: bad port: not a number");
        return -1;
    }

    char* port_end = NULL;
    const long port_num = strtol(port, &port_end, 10);

    if (port_num == LONG_MAX || port_num == LONG_MIN || !port_end || *port_end) {
        roc_log(LogError, "parse port: bad port: not a positive integer");
        return -1;
    }

    if (port_num < 0 || port_num > 65535) {
        roc_log(LogError, "parse port: bad port: not in range [1; 65535]");
        return -1;
    }

    return port_num;
}

bool parse_ipv4_addr(const char* addr, long port_num, PortConfig& result) {
    if (!result.address.set_ipv4(addr, (int)port_num)) {
        roc_log(LogError, "parse port: bad IPv4 address: %s", addr);
        return false;
    }

    return true;
}

bool parse_ipv6_addr(const char* addr, long port_num, PortConfig& result) {
    const size_t addrlen = strlen(addr);

    if (addr[addrlen - 1] != ']') {
        roc_log(LogError, "parse port: bad IPv6 address: expected closing ']'");
        return false;
    }

    char addr6[128] = {};
    if (addrlen - 2 > sizeof(addr6) - 1) {
        roc_log(LogError, "parse port: bad IPv6 address: address too long");
        return false;
    }

    memcpy(addr6, addr + 1, addrlen - 2);

    if (!result.address.set_ipv6(addr6, (int)port_num)) {
        roc_log(LogError, "parse port: bad IPv6 address: %s", addr6);
        return false;
    }

    return true;
}

void parse_miface(const char* miface, PortConfig& result) {
    if (strlen(miface) != 1) {
        result.address.set_miface(miface + 1);
    }
}

bool parse_addr(const char* begin, const char* end, long port_num, PortConfig& result) {
    if (begin + 1 == end) {
        return parse_ipv4_addr("0.0.0.0", port_num, result);
    }

    char addr_buf[256] = {};
    if (size_t(end - begin) > sizeof(addr_buf) - 1) {
        roc_log(LogError, "parse port: bad address: too long");
        return false;
    }

    memcpy(addr_buf, begin + 1, size_t(end - begin) - 1);
    addr_buf[end - begin - 1] = '\0';

    const char* miface = strchr(addr_buf, '@');
    if (miface) {
        parse_miface(miface, result);
        addr_buf[miface - addr_buf] = '\0';
    }

    return addr_buf[0] == '[' ? parse_ipv6_addr(addr_buf, port_num, result)
                              : parse_ipv4_addr(addr_buf, port_num, result);
}

} // namespace

bool parse_port(PortType type, const char* input, PortConfig& result) {
    if (input == NULL) {
        roc_log(LogError, "parse port: string is null");
        return false;
    }

    const char* lcolon = strchr(input, ':');
    const char* rcolon = strrchr(input, ':');

    if (!lcolon || !rcolon || lcolon == rcolon || lcolon == input || !rcolon[1]) {
        roc_log(LogError,
                "parse port: bad format: expected"
                " PROTO:ADDR:PORT or PROTO::PORT, or PROTO:ADDR@MIFACE:PORT");
        return false;
    }

    const PortProtocol protocol = parse_proto(input, lcolon, type);
    if (protocol == Proto_None) {
        return false;
    }

    const long port_num = parse_port_num(rcolon + 1);
    if (port_num == -1) {
        return false;
    }

    if (!parse_addr(lcolon, rcolon, port_num, result)) {
        return false;
    }

    result.protocol = protocol;

    return true;
}

} // namespace pipeline
} // namespace roc
