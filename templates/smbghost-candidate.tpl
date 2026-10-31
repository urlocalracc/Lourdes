id: smbghost-candidate
name: SMBv3.1.1 compression negotiated, SMBGhost candidate (verify patch level)
severity: high
cve: CVE-2020-0796
desc: Server selects dialect 3.1.1 and returns a compression context. Patched hosts may still report this.
probe: smb2
match: smb2.enabled eq true
match: smb2.dialect eq 0x0311
match: smb2.compression eq true
