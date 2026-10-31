id: smb1-enabled
name: SMBv1 enabled, MS17-010 exposure candidate (verify patch level)
severity: high
cve: CVE-2017-0144
desc: Host accepts an SMBv1 negotiate. Unpatched SMBv1 servers are affected by MS17-010.
probe: smb1
match: smb1.enabled eq true
