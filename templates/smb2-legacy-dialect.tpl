id: smb2-legacy-dialect
name: Highest negotiated dialect is below SMB 3.0
severity: info
desc: Server does not support SMB 3.x, which usually indicates an older Windows release.
probe: smb2
match: smb2.enabled eq true
match: smb2.dialect lt 0x0300
