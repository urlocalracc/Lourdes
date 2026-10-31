#pragma once
#include "net.hpp"
#include <string>
#include <vector>
#include <fstream>
#include <cstdlib>
#include "tpl.hpp"

struct Cidr {
    uint32_t net, mask;
    int bits;
};

static bool parse_ip(const std::string& s, uint32_t& v) {
    in_addr a;
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return false;
    v = ntohl(a.s_addr);
    return true;
}

static bool parse_cidr(const std::string& s, Cidr& c) {
    size_t sl = s.find('/');
    std::string ip = s.substr(0, sl);
    int bits = 32;
    if (sl != std::string::npos) bits = std::atoi(s.substr(sl + 1).c_str());
    uint32_t v;
    if (bits < 0 || bits > 32 || !parse_ip(ip, v)) return false;
    c.bits = bits;
    c.mask = bits ? 0xffffffffu << (32 - bits) : 0;
    c.net = v & c.mask;
    return true;
}

static std::string ip_str(uint32_t v) {
    in_addr a;
    a.s_addr = htonl(v);
    char b[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, b, sizeof b);
    return b;
}

static bool expand_target(const std::string& spec, std::vector<uint32_t>& out) {
    Cidr c;
    if (parse_cidr(spec, c)) {
        if (c.bits >= 31) {
            uint32_t n = c.bits == 32 ? 1 : 2;
            for (uint32_t i = 0; i < n; i++) out.push_back(c.net + i);
            return true;
        }
        if (c.bits < 20) return false;
        uint32_t last = c.net | ~c.mask;
        for (uint32_t v = c.net + 1; v < last; v++) out.push_back(v);
        return true;
    }
    addrinfo hints;
    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(spec.c_str(), nullptr, &hints, &res) != 0) return false;
    for (addrinfo* p = res; p; p = p->ai_next)
        out.push_back(ntohl(((sockaddr_in*)p->ai_addr)->sin_addr.s_addr));
    freeaddrinfo(res);
    return true;
}

struct Scope {
    std::vector<Cidr> allow;
    bool strict = false;

    void add_defaults() {
        const char* d[] = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"};
        for (const char* s : d) {
            Cidr c;
            if (parse_cidr(s, c)) allow.push_back(c);
        }
    }

    bool load(const std::string& path) {
        std::ifstream f(path);
        if (!f) return false;
        std::string line;
        allow.clear();
        while (std::getline(f, line)) {
            line = trim(line);
            if (line.empty() || line[0] == '#') continue;
            Cidr c;
            if (parse_cidr(line, c)) allow.push_back(c);
        }
        strict = true;
        return !allow.empty();
    }

    bool permits(uint32_t v) const {
        for (const auto& c : allow)
            if ((v & c.mask) == c.net) return true;
        return false;
    }
};
