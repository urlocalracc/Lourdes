#include <iostream>
#include <thread>
#include <mutex>
#include <atomic>
#include <algorithm>
#include <set>
#include "smb.hpp"
#include "tpl.hpp"
#include "scope.hpp"

struct Finding {
    std::string host, id, name, severity, cve;
};

static std::string jesc(const std::string& s) {
    std::string o;
    for (char ch : s) {
        if (ch == '"' || ch == '\\') {
            o += '\\';
            o += ch;
        } else if (ch == '\n') o += "\\n";
        else if ((unsigned char)ch < 0x20) o += ' ';
        else o += ch;
    }
    return o;
}

static void usage() {
    std::puts(
        "usage: smbscan --authorized -t <ip|cidr|host,...> [options]\n"
        "  -t  targets, comma separated\n"
        "  -T  file with one target per line\n"
        "  -p  port (default 445)\n"
        "  -w  templates directory (default templates)\n"
        "  -c  threads (default 16)\n"
        "  -o  timeout in ms (default 3000)\n"
        "  -s  scope file, one cidr per line (default: private lab ranges only)\n"
        "  -j  json output file\n"
        "  -v  print collected facts per host\n"
        "  --authorized  confirm you are allowed to test the targets");
}

static std::vector<std::string> split(const std::string& s, char d) {
    std::vector<std::string> o;
    std::stringstream ss(s);
    std::string t;
    while (std::getline(ss, t, d)) {
        t = trim(t);
        if (!t.empty()) o.push_back(t);
    }
    return o;
}

int main(int argc, char** argv) {
    std::string tdir = "templates", scopefile, jsonout;
    std::vector<std::string> specs;
    int port = 445, threads = 16, timeout = 3000;
    bool authorized = false, verbose = false;

    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto val = [&]() -> std::string {
            if (i + 1 >= argc) {
                usage();
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "-t") {
            for (auto& s : split(val(), ',')) specs.push_back(s);
        } else if (a == "-T") {
            std::ifstream f(val());
            std::string l;
            while (std::getline(f, l)) {
                l = trim(l);
                if (!l.empty() && l[0] != '#') specs.push_back(l);
            }
        } else if (a == "-p") port = std::atoi(val().c_str());
        else if (a == "-w") tdir = val();
        else if (a == "-c") threads = std::max(1, std::atoi(val().c_str()));
        else if (a == "-o") timeout = std::max(200, std::atoi(val().c_str()));
        else if (a == "-s") scopefile = val();
        else if (a == "-j") jsonout = val();
        else if (a == "-v") verbose = true;
        else if (a == "--authorized") authorized = true;
        else {
            usage();
            return 2;
        }
    }

    if (!authorized || specs.empty()) {
        usage();
        return 2;
    }

    net_init();

    std::vector<Tpl> tpls = load_templates(tdir);
    if (tpls.empty()) {
        std::fprintf(stderr, "no templates loaded from %s\n", tdir.c_str());
        return 1;
    }

    Scope sc;
    if (!scopefile.empty()) {
        if (!sc.load(scopefile)) {
            std::fprintf(stderr, "invalid scope file\n");
            return 1;
        }
    } else {
        sc.add_defaults();
    }

    std::set<uint32_t> uniq;
    for (const auto& s : specs) {
        std::vector<uint32_t> ips;
        if (!expand_target(s, ips)) {
            std::fprintf(stderr, "cannot resolve or expand target: %s\n", s.c_str());
            continue;
        }
        for (uint32_t v : ips) {
            if (!sc.permits(v)) {
                std::fprintf(stderr, "out of scope, skipped: %s\n", ip_str(v).c_str());
                continue;
            }
            uniq.insert(v);
        }
    }
    std::vector<uint32_t> hosts(uniq.begin(), uniq.end());
    if (hosts.empty()) {
        std::fprintf(stderr, "no in-scope targets\n");
        return 1;
    }

    bool n1 = false, n2 = false;
    for (const auto& t : tpls) {
        if (t.probe == "smb1") n1 = true;
        if (t.probe == "smb2") n2 = true;
    }

    std::vector<Finding> findings;
    std::mutex mu;
    std::atomic<size_t> idx{0};

    auto work = [&]() {
        for (;;) {
            size_t i = idx++;
            if (i >= hosts.size()) break;
            std::string ip = ip_str(hosts[i]);
            Facts f = gather(ip, port, timeout, n1, n2);
            if (f["tcp.open"] != "true") continue;
            std::lock_guard<std::mutex> lk(mu);
            if (verbose) {
                std::printf("%s:%d\n", ip.c_str(), port);
                for (const auto& kv : f) std::printf("  %s = %s\n", kv.first.c_str(), kv.second.c_str());
            }
            for (const auto& t : tpls) {
                if (!eval_template(t, f)) continue;
                Finding fd{ip + ":" + std::to_string(port), t.id, t.name, t.severity, t.cve};
                findings.push_back(fd);
                std::printf("[%s] %s %s %s%s%s\n", t.severity.c_str(), t.id.c_str(), fd.host.c_str(),
                            t.name.c_str(), t.cve.empty() ? "" : " ", t.cve.c_str());
                std::fflush(stdout);
            }
        }
    };

    std::vector<std::thread> pool;
    int n = std::min<int>(threads, (int)hosts.size());
    for (int i = 0; i < n; i++) pool.emplace_back(work);
    for (auto& t : pool) t.join();

    if (!jsonout.empty()) {
        std::ofstream o(jsonout);
        o << "[\n";
        for (size_t i = 0; i < findings.size(); i++) {
            const Finding& f = findings[i];
            o << "  {\"host\":\"" << jesc(f.host) << "\",\"id\":\"" << jesc(f.id) << "\",\"name\":\""
              << jesc(f.name) << "\",\"severity\":\"" << jesc(f.severity) << "\",\"cve\":\"" << jesc(f.cve)
              << "\"}" << (i + 1 < findings.size() ? "," : "") << "\n";
        }
        o << "]\n";
    }

    std::fprintf(stderr, "scanned %zu host(s), %zu finding(s)\n", hosts.size(), findings.size());
    return 0;
}
