#pragma once
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstdlib>

struct Matcher {
    std::string field, op, value;
};

struct Tpl {
    std::string id, name, severity, cve, desc, probe;
    std::vector<Matcher> matchers;
};

static inline std::string trim(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

static std::vector<Tpl> parse_templates(const std::string& text) {
    std::vector<Tpl> out;
    Tpl cur;
    bool has = false;
    auto flush = [&]() {
        if (has && !cur.id.empty() && !cur.probe.empty() && !cur.matchers.empty()) out.push_back(cur);
        cur = Tpl();
        has = false;
    };
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;
        if (line == "---") {
            flush();
            continue;
        }
        size_t c = line.find(':');
        if (c == std::string::npos) continue;
        std::string k = trim(line.substr(0, c));
        std::string v = trim(line.substr(c + 1));
        has = true;
        if (k == "id") cur.id = v;
        else if (k == "name") cur.name = v;
        else if (k == "severity") cur.severity = v;
        else if (k == "cve") cur.cve = v;
        else if (k == "desc") cur.desc = v;
        else if (k == "probe") {
            std::transform(v.begin(), v.end(), v.begin(), [](unsigned char ch) { return (char)std::tolower(ch); });
            cur.probe = v;
        } else if (k == "match") {
            std::istringstream ms(v);
            Matcher m;
            ms >> m.field >> m.op;
            std::getline(ms, m.value);
            m.value = trim(m.value);
            if (!m.field.empty() && !m.op.empty()) cur.matchers.push_back(m);
        }
    }
    flush();
    return out;
}

static std::vector<Tpl> load_templates(const std::string& dir) {
    std::vector<Tpl> all;
    try {
        for (const auto& e : std::filesystem::directory_iterator(dir)) {
            if (!e.is_regular_file() || e.path().extension() != ".tpl") continue;
            std::ifstream f(e.path());
            std::stringstream ss;
            ss << f.rdbuf();
            std::vector<Tpl> t = parse_templates(ss.str());
            all.insert(all.end(), t.begin(), t.end());
        }
    } catch (...) {
    }
    std::sort(all.begin(), all.end(), [](const Tpl& a, const Tpl& b) { return a.id < b.id; });
    return all;
}

static bool to_num(const std::string& s, long long& v) {
    char* e = nullptr;
    v = std::strtoll(s.c_str(), &e, 0);
    return e != s.c_str() && *e == 0;
}

static bool eval_matcher(const Matcher& m, const std::map<std::string, std::string>& f) {
    auto it = f.find(m.field);
    if (it == f.end()) return false;
    const std::string& a = it->second;
    if (m.op == "eq") return a == m.value;
    if (m.op == "ne") return a != m.value;
    if (m.op == "has") return a.find(m.value) != std::string::npos;
    long long x, y;
    if (!to_num(a, x) || !to_num(m.value, y)) return false;
    if (m.op == "gt") return x > y;
    if (m.op == "ge") return x >= y;
    if (m.op == "lt") return x < y;
    if (m.op == "le") return x <= y;
    return false;
}

static bool eval_template(const Tpl& t, const std::map<std::string, std::string>& f) {
    for (const auto& m : t.matchers)
        if (!eval_matcher(m, f)) return false;
    return !t.matchers.empty();
}
