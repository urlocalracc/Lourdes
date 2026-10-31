id: smb2-signing-not-required
name: SMB2/3 signing not required
severity: medium
desc: Message signing is not enforced, which allows relay attacks in a lab network.
probe: smb2
match: smb2.enabled eq true
match: smb2.signing ne required
