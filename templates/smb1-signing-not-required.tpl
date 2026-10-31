id: smb1-signing-not-required
name: SMBv1 signing not required
severity: medium
desc: SMBv1 is enabled and message signing is not enforced.
probe: smb1
match: smb1.enabled eq true
match: smb1.signing ne required
