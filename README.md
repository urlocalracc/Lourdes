<div align="center">

# Lourdes

**Windows SMB Vulnerability Scanner**

A lightweight, template-based scanner for SMB security checks.

![C++](https://img.shields.io/badge/C%2B%2B-00599C?style=flat-square&logo=cplusplus&logoColor=white)
![SMB](https://img.shields.io/badge/Protocol-SMB-orange?style=flat-square)
![Status](https://img.shields.io/badge/Status-Development-yellow?style=flat-square)

</div>

---

## ⚡ Features

- SMB1 and SMB2/3 detection
- SMB signing and encryption checks
- Template-based detection rules
- CIDR and hostname support
- Multithreaded scanning
- JSON output
- Configurable timeouts and scan scope

## 🛠️ Installation

```bash
sudo apt update
sudo apt install -y g++ cmake

cmake -B build
cmake --build build
```

## 🚀 Usage

```bash
./build/smbscan --authorized -t 10.10.10.40 -v
```

### Examples

```bash
# Scan a subnet
./build/smbscan --authorized -t 10.10.10.0/24

# Scan multiple targets
./build/smbscan --authorized -t 10.10.10.40,10.10.10.41

# Load targets from a file
./build/smbscan --authorized -T targets.txt

# Export findings to JSON
./build/smbscan --authorized -t 10.10.10.40 -j findings.json

# Increase timeout
./build/smbscan --authorized -t 10.10.10.40 -o 6000 -v
```

## ⚙️ Options

| Flag | Description | Default |
|:---|:---|:---|
| `--authorized` | Confirm authorization | Required |
| `-t` | IP, CIDR, or hostname | — |
| `-T` | Target list file | — |
| `-p` | Target port | `445` |
| `-w` | Templates directory | `templates/` |
| `-c` | Worker threads | `16` |
| `-o` | Timeout (ms) | `3000` |
| `-s` | Allowed CIDR ranges file | Private ranges |
| `-j` | JSON output file | — |
| `-v` | Show collected facts | Disabled |

## 🧩 Templates

Detection rules are stored in `templates/*.tpl`.

Example:

```yaml
id: smb3-no-encryption
name: SMB 3.x without encryption capability
severity: low
probe: smb2
match: smb2.dialect ge 0x0300
match: smb2.encryption eq false
```

Add a new `.tpl` file to create a rule. **No recompilation needed.**

## 🔍 Collected Facts

| Fact | Description |
|:---|:---|
| `tcp.open` | TCP port status |
| `smb1.enabled` | SMB1 support |
| `smb1.signing` | SMB1 signing mode |
| `smb2.enabled` | SMB2/3 support |
| `smb2.dialect` | Negotiated SMB dialect |
| `smb2.signing` | SMB2/3 signing mode |
| `smb2.encryption` | Encryption capability |
| `smb2.compression` | Compression capability |

## ⚠️ Notes

> Findings are indicators, not confirmed vulnerabilities. Verify patch levels and vulnerability status independently.

> [!WARNING]
> Only scan systems you own or have explicit permission to test.

---

<div align="center">

**Lourdes** · SMB Security Research

</div>
