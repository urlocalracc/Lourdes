#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET sock_t;
#define CLOSESOCK closesocket
#else
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
typedef int sock_t;
#define CLOSESOCK close
#endif

inline void net_init() {
#ifdef _WIN32
    WSADATA d;
    WSAStartup(MAKEWORD(2, 2), &d);
#endif
}

inline void set_nonblocking(sock_t s, bool on) {
#ifdef _WIN32
    u_long m = on ? 1 : 0;
    ioctlsocket(s, FIONBIO, &m);
#else
    int fl = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, on ? (fl | O_NONBLOCK) : (fl & ~O_NONBLOCK));
#endif
}

class Conn {
    sock_t s;
    bool ok;

    bool wait_read(int ms) {
        fd_set r;
        FD_ZERO(&r);
        FD_SET(s, &r);
        timeval tv;
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        return select((int)s + 1, &r, nullptr, nullptr, &tv) > 0;
    }

    bool recv_n(uint8_t* p, size_t n, int ms) {
        while (n) {
            if (!wait_read(ms)) return false;
            int k = recv(s, (char*)p, (int)n, 0);
            if (k <= 0) return false;
            p += k;
            n -= (size_t)k;
        }
        return true;
    }

public:
    Conn() : s((sock_t)-1), ok(false) {}
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
    ~Conn() { if (ok) CLOSESOCK(s); }

    bool open(const std::string& ip, int port, int ms) {
        sockaddr_in a;
        std::memset(&a, 0, sizeof a);
        a.sin_family = AF_INET;
        a.sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, ip.c_str(), &a.sin_addr) != 1) return false;
        s = socket(AF_INET, SOCK_STREAM, 0);
        if (s == (sock_t)-1) return false;
        ok = true;
        set_nonblocking(s, true);
        connect(s, (sockaddr*)&a, sizeof a);
        fd_set w, e;
        FD_ZERO(&w);
        FD_ZERO(&e);
        FD_SET(s, &w);
        FD_SET(s, &e);
        timeval tv;
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        if (select((int)s + 1, nullptr, &w, &e, &tv) <= 0 || !FD_ISSET(s, &w)) return false;
        int err = 0;
        socklen_t l = sizeof err;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&err, &l);
        if (err) return false;
        set_nonblocking(s, false);
        return true;
    }

    bool send_all(const std::vector<uint8_t>& d) {
        size_t off = 0;
#ifdef MSG_NOSIGNAL
        int flags = MSG_NOSIGNAL;
#else
        int flags = 0;
#endif
        while (off < d.size()) {
            int k = send(s, (const char*)d.data() + off, (int)(d.size() - off), flags);
            if (k <= 0) return false;
            off += (size_t)k;
        }
        return true;
    }

    bool recv_smb(std::vector<uint8_t>& out, int ms) {
        uint8_t h[4];
        if (!recv_n(h, 4, ms)) return false;
        size_t len = ((size_t)h[1] << 16) | ((size_t)h[2] << 8) | h[3];
        if (len < 32 || len > 65536) return false;
        out.assign(4 + len, 0);
        std::memcpy(out.data(), h, 4);
        return recv_n(out.data() + 4, len, ms);
    }
};
