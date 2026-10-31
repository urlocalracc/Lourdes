#pragma once
#include "net.hpp"
#include <map>
#include <random>
#include <cstdio>

typedef std::map<std::string, std::string> Facts;

static inline void put16(std::vector<uint8_t>& b, uint16_t v) {
    b.push_back(v & 0xff);
    b.push_back(v >> 8);
}

static inline void put32(std::vector<uint8_t>& b, uint32_t v) {
    for (int i = 0; i < 4; i++) b.push_back((v >> (8 * i)) & 0xff);
}

static inline void put64(std::vector<uint8_t>& b, uint64_t v) {
    for (int i = 0; i < 8; i++) b.push_back((v >> (8 * i)) & 0xff);
}

static inline uint16_t get16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}

static inline uint32_t get32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void rnd(std::vector<uint8_t>& b, size_t n) {
    thread_local std::mt19937 g{std::random_device{}()};
    for (size_t i = 0; i < n; i++) b.push_back(g() & 0xff);
}

static inline void frame(std::vector<uint8_t>& p) {
    size_t n = p.size() - 4;
    p[0] = 0;
    p[1] = (n >> 16) & 0xff;
    p[2] = (n >> 8) & 0xff;
    p[3] = n & 0xff;
}

static inline void align8(std::vector<uint8_t>& p) {
    while ((p.size() - 4) % 8) p.push_back(0);
}

static std::vector<uint8_t> build_smb1_negotiate() {
    std::vector<uint8_t> p(4, 0);
    p.insert(p.end(), {0xff, 'S', 'M', 'B', 0x72, 0, 0, 0, 0, 0x18, 0x43, 0xc8, 0, 0});
    p.insert(p.end(), 8, 0);
    put16(p, 0);
    put16(p, 0xffff);
    put16(p, 0x1234);
    put16(p, 0);
    put16(p, 1);
    p.push_back(0);
    const char* d = "NT LM 0.12";
    put16(p, (uint16_t)(2 + std::strlen(d)));
    p.push_back(0x02);
    p.insert(p.end(), d, d + std::strlen(d) + 1);
    frame(p);
    return p;
}

static std::vector<uint8_t> build_smb2_negotiate() {
    std::vector<uint8_t> p(4, 0);
    p.insert(p.end(), {0xfe, 'S', 'M', 'B'});
    put16(p, 64);
    put16(p, 0);
    put32(p, 0);
    put16(p, 0);
    put16(p, 31);
    put32(p, 0);
    put32(p, 0);
    put64(p, 0);
    put32(p, 0);
    put32(p, 0);
    put64(p, 0);
    p.insert(p.end(), 16, 0);
    put16(p, 36);
    put16(p, 5);
    put16(p, 1);
    put16(p, 0);
    put32(p, 0x7f);
    rnd(p, 16);
    put32(p, 112);
    put16(p, 2);
    put16(p, 0);
    const uint16_t dialects[5] = {0x0202, 0x0210, 0x0300, 0x0302, 0x0311};
    for (int i = 0; i < 5; i++) put16(p, dialects[i]);
    align8(p);
    put16(p, 1);
    put16(p, 38);
    put32(p, 0);
    put16(p, 1);
    put16(p, 32);
    put16(p, 1);
    rnd(p, 32);
    align8(p);
    put16(p, 3);
    put16(p, 12);
    put32(p, 0);
    put16(p, 2);
    put16(p, 0);
    put32(p, 0);
    put16(p, 1);
    put16(p, 2);
    frame(p);
    return p;
}

static void probe_smb1(const std::string& ip, int port, int ms, Facts& f) {
    f["smb1.enabled"] = "false";
    Conn c;
    std::vector<uint8_t> r;
    if (!c.open(ip, port, ms)) return;
    if (!c.send_all(build_smb1_negotiate()) || !c.recv_smb(r, ms)) return;
    if (r.size() < 71 || std::memcmp(&r[4], "\xff" "SMB", 4) != 0) return;
    if (get32(&r[9]) != 0 || r[36] < 17) return;
    if (get16(&r[37]) == 0xffff) return;
    uint8_t sm = r[39];
    f["smb1.enabled"] = "true";
    f["smb1.signing"] = (sm & 8) ? "required" : (sm & 4) ? "enabled" : "disabled";
}

static void probe_smb2(const std::string& ip, int port, int ms, Facts& f) {
    f["smb2.enabled"] = "false";
    Conn c;
    std::vector<uint8_t> r;
    if (!c.open(ip, port, ms)) return;
    if (!c.send_all(build_smb2_negotiate()) || !c.recv_smb(r, ms)) return;
    if (r.size() < 132 || std::memcmp(&r[4], "\xfe" "SMB", 4) != 0) return;
    if (get32(&r[12]) != 0) return;
    uint16_t sm = get16(&r[70]);
    uint16_t di = get16(&r[72]);
    uint16_t nc = get16(&r[74]);
    uint32_t cap = get32(&r[92]);
    uint32_t no = get32(&r[128]);
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%04x", di);
    f["smb2.enabled"] = "true";
    f["smb2.dialect"] = buf;
    f["smb2.signing"] = (sm & 2) ? "required" : (sm & 1) ? "enabled" : "disabled";
    f["smb2.encryption"] = (cap & 0x40) ? "true" : "false";
    f["smb2.compression"] = "false";
    if (di != 0x0311) return;
    size_t rel = no;
    for (uint16_t i = 0; i < nc; i++) {
        size_t pos = 4 + rel;
        if (pos + 8 > r.size()) break;
        uint16_t type = get16(&r[pos]);
        uint16_t dl = get16(&r[pos + 2]);
        if (type == 3 && pos + 10 <= r.size() && get16(&r[pos + 8]) > 0) f["smb2.compression"] = "true";
        if (type == 2) f["smb2.encryption"] = "true";
        rel += 8 + (size_t)dl;
        rel = (rel + 7) & ~(size_t)7;
    }
}

static Facts gather(const std::string& ip, int port, int ms, bool n1, bool n2) {
    Facts f;
    {
        Conn c;
        if (!c.open(ip, port, ms)) {
            f["tcp.open"] = "false";
            return f;
        }
    }
    f["tcp.open"] = "true";
    if (n1) probe_smb1(ip, port, ms, f);
    if (n2) probe_smb2(ip, port, ms, f);
    return f;
}
