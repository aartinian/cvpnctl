# Security

cvpnctl handles your CA's private key and every user's key, so if you find a security problem, I'd really like to hear about it.

## Reporting

Please report it privately rather than in a public issue: on GitHub, use [Report a vulnerability](https://github.com/aartinian/cvpnctl/security/advisories/new). A short description and the steps to reproduce it are plenty; just leave out real account or endpoint IDs.

This is a one-person project, so give me a few days to reply. Fixes go into the next release, and I'm happy to credit you in the advisory. Only the latest release is supported, so please check that the problem is still there with it.

## Good to know

cvpnctl tries hard to keep keys safe: they're written with private file permissions, in S3 mode they only live in a temporary folder that's deleted afterwards, and an older copy of the shared PKI can never overwrite a newer one. A few things are outside its control, though:

- **The CA key** is what everything depends on: whoever has it can issue certificates your VPN accepts. Keep it on an encrypted disk, or in S3 behind tight IAM and KMS permissions ([docs/iam.md](docs/iam.md)).
- **Your machine and AWS credentials:** anyone who controls them can do whatever cvpnctl can.
- **Download links** give access to a user's private key until they expire, so send them straight to that user. `cvpnctl link` or `revoke` makes an old link stop working.
- **EasyRSA, OpenSSL, OpenVPN and AWS** have their own security processes; please report issues in those upstream.
