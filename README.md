<p align="center"><img src="docs/logo.svg" alt="cvpnctl" width="236"></p>

<p align="center"><b>User certificates for AWS Client VPN, one command at a time.</b><br>Issue, renew and revoke with EasyRSA; cvpnctl handles ACM, the CRL and the <code>.ovpn</code> files, and lets a whole team share one PKI in S3.</p>

<p align="center">
<a href="https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml"><img src="https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml/badge.svg" alt="CI"></a>
<a href="https://github.com/aartinian/cvpnctl/actions/workflows/github-code-scanning/codeql"><img src="https://github.com/aartinian/cvpnctl/actions/workflows/github-code-scanning/codeql/badge.svg" alt="CodeQL"></a>
<a href="https://github.com/aartinian/cvpnctl/releases"><img src="https://img.shields.io/github/v/release/aartinian/cvpnctl" alt="Release"></a>
<a href="go.mod"><img src="https://img.shields.io/github/go-mod/go-version/aartinian/cvpnctl" alt="Go"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/aartinian/cvpnctl" alt="License"></a>
</p>

<p align="center"><img src="docs/demo.svg" alt="cvpnctl create issues a certificate, imports it to ACM, saves the PKI to S3 and prints a download link; cvpnctl status then shows that everything is in order" width="823"></p>

## Why

An [AWS Client VPN](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html) endpoint with certificate authentication means running your own PKI. Each user change touches EasyRSA, ACM, the endpoint's CRL and a hand-made `.ovpn` file. Miss a step and a revoked user can still connect.

cvpnctl does each of those in one command, with [EasyRSA](https://github.com/OpenVPN/easy-rsa) and your own AWS credentials.

## Features

- **One command per change:** `create`, `renew` and `revoke` do every step, from EasyRSA to the endpoint.
- **Revocation that sticks:** access ends within about a minute, open sessions included.
- **Safe to re-run:** checks come before the first change, and a command that fails halfway can simply be run again.
- **Expiry and drift at a glance:** `status` shows what expires when and whether the endpoint's CRL matches your PKI.
- **Shared by a team:** keep the PKI in S3 instead of on one laptop: locked, versioned, KMS-encrypted, with expiring download links for users ([details](#shared-pki-in-s3)).
- **Nothing to host:** one binary for Linux and macOS; works with any OpenVPN client, including the [AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/).

## Quick start

You need:

- Linux or macOS
- [EasyRSA](https://github.com/OpenVPN/easy-rsa/releases) 3.2.7 or later (a release or Homebrew; most distro packages are too old)
- an EasyRSA PKI whose CA your Client VPN endpoint trusts, with certificate authentication on the endpoint
- AWS credentials for ACM and the endpoint's CRL: see [docs/iam.md](docs/iam.md)

**1. Install** (checks the download's SHA-256; asks for sudo to write to `/usr/local/bin`):

```
curl -fsSL https://github.com/aartinian/cvpnctl/releases/latest/download/install.sh | bash
```

<details>
<summary>Other ways to install</summary>

Without sudo, into a directory of your own (created if missing):

```
curl -fsSL https://github.com/aartinian/cvpnctl/releases/latest/download/install.sh | INSTALL_DIR="$HOME/.local/bin" bash
```

A specific version: take the script from that release.

```
curl -fsSL https://github.com/aartinian/cvpnctl/releases/download/v0.3.1/install.sh | bash
```

With Go 1.26 or later:

```
go install github.com/aartinian/cvpnctl/cmd/cvpnctl@latest
```

Or download the archive for your platform from the [releases](https://github.com/aartinian/cvpnctl/releases) page.
</details>

**2. Write the config:**

```
mkdir -p ~/.config/cvpnctl
curl -fsSL -o ~/.config/cvpnctl/cvpnctl.yaml https://github.com/aartinian/cvpnctl/releases/latest/download/cvpnctl.yaml.example
```

Edit it to match your setup:

```yaml
easyrsa:
  path: ~/easy-rsa              # directory containing the easyrsa script
  pki_dir: ~/vpn-pki            # your PKI
certs:
  output_dir: ~/vpn/certs       # per-user folders and cvpnctl's state file
aws:
  region: eu-central-1          # region of the endpoint
  profile: default              # optional AWS profile
  vpn_endpoint_id: cvpn-endpoint-0123456789abcdef0
ovpn:
  template: ~/.config/cvpnctl/base.ovpn
  output_dir: ~/vpn/clients     # where <user>.ovpn files are written
```

**3. Make the `.ovpn` template** from the client configuration AWS generates for your endpoint ([result](base.ovpn.example)):

```
aws ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id <endpoint-id> --output text |
  sed '/<ca>/,/<\/ca>/d' > ~/.config/cvpnctl/base.ovpn
printf '\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n' >> ~/.config/cvpnctl/base.ovpn
```

**4. Check everything** (reads only, changes nothing):

```
cvpnctl status
```

**5. Add your first user:**

```
$ cvpnctl create -u max.mustermann
Creating max.mustermann
  ✓ certificate issued         expires 2029-01-15
  ✓ imported to ACM            …/287fe781
  ✓ files saved                ~/vpn/certs/max.mustermann/
  ✓ .ovpn written              ~/vpn/clients/max.mustermann.ovpn
Done. Send ~/vpn/clients/max.mustermann.ovpn to max.mustermann securely.
```

## Commands

| Command | What it does | Mode |
|---|---|---|
| `create -u <user>` | Issues a certificate, imports it to ACM, writes the `.ovpn` (S3: prints a download link) | both |
| `renew -u <user>` | Issues a new certificate, then revokes the old one and uploads the CRL | both |
| `revoke -u <user>` | Revokes the certificate, uploads the CRL, deletes it from ACM and removes the user's files or link | both |
| `list` | Lists users with certificate expiry and ACM ARN | both |
| `status` | Shows what expires when, and whether the endpoint's CRL matches your PKI | both |
| `push-crl` | Regenerates the CRL and uploads it | both |
| `link -u <user>` | A new download link for an existing certificate | S3 |
| `template show` / `template set <file>` | Prints or replaces the stored `.ovpn` template | S3 |
| `store migrate --from <config>` | Moves a local PKI into the bucket | S3 |
| `store versions` | Lists every saved version of the PKI | S3 |
| `store restore <version>` | Makes an earlier version current again | S3 |
| `unlock` | Removes a lock left behind by a crashed command | S3 |

Options:

- `-c <file>` selects the config. Without it: `./cvpnctl.yaml`, then `~/.config/cvpnctl/cvpnctl.yaml`, then `/etc/cvpnctl/cvpnctl.yaml`.
- `-v` shows EasyRSA's output.
- `--yes` skips the confirmation of `revoke`, `restore` and `unlock`, for scripts.

`status` exits with `0` when all is well, `2` when something needs attention, `1` when the check itself fails. A monthly reminder through cron (with the full path, as cron's `PATH` is minimal):

```
0 9 1 * * out=$(/usr/local/bin/cvpnctl status 2>&1) || echo "$out"
```

## Shared PKI in S3

For several admins, keep the PKI, cvpnctl's state and the template in an S3 bucket instead of on one machine.

**1. Create the bucket, KMS key and admin permissions** with [examples/terraform](examples/terraform), or by hand: the bucket needs versioning, KMS encryption and all public access blocked, and the admins the permissions in [docs/iam.md](docs/iam.md#additional-policy-for-the-shared-pki-in-s3).

**2. Switch the config to S3.** Keep the local one as the source for the move:

```
mv ~/.config/cvpnctl/cvpnctl.yaml ~/.config/cvpnctl/cvpnctl.local.yaml
```

Then write a new `~/.config/cvpnctl/cvpnctl.yaml` with a `store` section instead of the local paths:

```yaml
easyrsa:
  path: ~/easy-rsa
store:
  bucket: acme-vpn-pki
  prefix: cvpnctl/              # optional
  kms_key_id: alias/cvpnctl
  link_hours: 24                # how long download links stay valid, 1–168
aws:
  region: eu-central-1          # the bucket must be in this region too
  profile: default
  vpn_endpoint_id: cvpn-endpoint-0123456789abcdef0
```

**3. Move the PKI over and check:**

```
cvpnctl store migrate --from ~/.config/cvpnctl/cvpnctl.local.yaml
cvpnctl status
```

`migrate` checks the bucket and the PKI first, never overwrites an existing PKI, verifies the upload file by file, and deletes nothing locally. Once `status` is all ✓, delete the local copies yourself.

**How it works:**

- Each command downloads the PKI into a private temp folder, works there, uploads it again and deletes the folder: no keys stay on disk.
- A command that changes something takes a lock; a second admin gets `locked by <user> on <host> since <time>` and nothing changes.
- Every change is a new S3 version that `store restore` can bring back.
- Users get a link to download their `.ovpn` (no AWS access needed). It contains their private key: send it to them directly.
- Links are signed with the admin's credentials, last at most 7 days, and end early when temporary credentials (SSO, an assumed role) expire; cvpnctl warns when that happens.

**When something goes wrong:**

| Situation | What to do |
|---|---|
| `locked by …` | Someone else is working; `status` shows the lock. After a crash: `cvpnctl unlock`. |
| A change needs undoing | `cvpnctl store versions`, then `cvpnctl store restore <version>`. It warns, and wants you to type `restore`, if that would let a revoked certificate back in or lose track of a valid one. |
| A link expired or got lost | `cvpnctl link -u <user>` (same certificate). |

## Certificates and expiry

| Certificate | Default lifetime | When it expires |
|---|---|---|
| CA | 10 years | Nothing works. A new CA needs a new endpoint and new `.ovpn` files for everyone. |
| Server certificate (endpoint) | 825 days | Nobody can connect. Renew it and re-import it into the same ACM ARN. |
| Client root (endpoint) | its certificate's lifetime | Re-import a renewed certificate into the same ACM ARN. |
| User certificate | 825 days | That user can't connect: `cvpnctl renew`. |
| CRL | 180 days | Nobody can connect. Every `renew`, `revoke` and `push-crl` refreshes it. |

`cvpnctl status` shows all of them. Client VPN needs a domain name in the server certificate:

```
easyrsa --san=DNS:server build-server-full server nopass
```

## CA key

Anyone with the CA's private key (`pki/private/ca.key`) can issue certificates your VPN accepts. Keep it on an encrypted disk and encrypt its backups, or keep the PKI in S3 with KMS.

You can also give it a passphrase. EasyRSA then asks for it on every `create`, `renew`, `revoke` and `push-crl`, so these need a terminal; `list` and `status` don't.

```
easyrsa set-pass ca
```

## Security

Found a security problem? Please report it privately rather than in an issue; [SECURITY.md](SECURITY.md) says how, and what cvpnctl can and can't protect.

## Development

```
go test ./...      # lifecycle tests run if EasyRSA is installed
go vet ./...
go build ./cmd/cvpnctl
```

## License

MIT, see [LICENSE](LICENSE).
