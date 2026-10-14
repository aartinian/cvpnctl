# cvpnctl

[![CI](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml/badge.svg)](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml)
[![Release](https://img.shields.io/github/v/release/aartinian/cvpnctl)](https://github.com/aartinian/cvpnctl/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/aartinian/cvpnctl)](go.mod)
[![License](https://img.shields.io/github/license/aartinian/cvpnctl)](LICENSE)

A command-line tool that manages user certificates for an
[AWS Client VPN](https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/what-is.html)
endpoint, using [EasyRSA](https://github.com/OpenVPN/easy-rsa).

For each user, it issues a certificate, imports it to AWS Certificate Manager
(ACM), and writes a `.ovpn` file. Users import that file into the
[AWS VPN Client](https://aws.amazon.com/vpn/client-vpn-download/),
[OpenVPN Connect](https://openvpn.net/client/), or any other OpenVPN client.
To remove a user, it revokes the certificate and uploads the updated
certificate revocation list (CRL) to the endpoint.

```
$ cvpnctl create -u max.mustermann
Creating max.mustermann
  ✓ certificate issued         expires 2029-01-15
  ✓ files saved                ~/vpn/certs/max.mustermann/
  ✓ imported to ACM            …/287fe781
  ✓ .ovpn written              ~/vpn/clients/max.mustermann.ovpn
Done. Send ~/vpn/clients/max.mustermann.ovpn to max.mustermann securely.
```

## Requirements

- Linux or macOS
- [EasyRSA](https://github.com/OpenVPN/easy-rsa/releases) 3.2.7 or later, from
  a release or Homebrew. Most distro packages are older; cvpnctl refuses them.
- An EasyRSA PKI whose CA your Client VPN endpoint trusts
- A Client VPN endpoint that uses certificate (mutual) authentication
- AWS credentials with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["acm:ImportCertificate", "acm:DeleteCertificate", "acm:DescribeCertificate"],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:ImportClientVpnClientCertificateRevocationList",
        "ec2:ExportClientVpnClientCertificateRevocationList"
      ],
      "Resource": "arn:aws:ec2:<region>:<account-id>:client-vpn-endpoint/<endpoint-id>"
    },
    {
      "Effect": "Allow",
      "Action": "ec2:DescribeClientVpnEndpoints",
      "Resource": "*"
    }
  ]
}
```

The three `Describe`/`Export` actions are read-only and only used by `status`.

## Install

```
curl -fsSL https://raw.githubusercontent.com/aartinian/cvpnctl/master/scripts/install.sh | bash
```

or with Go 1.26+:

```
go install github.com/aartinian/cvpnctl/cmd/cvpnctl@latest
```

## Configure

cvpnctl needs two files: its config, and a template for the `.ovpn` files.

**1. The config.** Download the example and edit it:

```
mkdir -p ~/.config/cvpnctl
curl -fsSL -o ~/.config/cvpnctl/cvpnctl.yaml \
  https://raw.githubusercontent.com/aartinian/cvpnctl/master/cvpnctl.yaml.example
```

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

**2. The template.** Start from the client configuration AWS generates for your
endpoint, remove its `<ca>` block, and add placeholders for the CA, certificate,
and key:

```
aws ec2 export-client-vpn-client-configuration \
  --client-vpn-endpoint-id <endpoint-id> --output text |
  sed '/<ca>/,/<\/ca>/d' > ~/.config/cvpnctl/base.ovpn
printf '\n{{.CA}}\n{{.Cert}}\n{{.Key}}\n' >> ~/.config/cvpnctl/base.ovpn
```

[`base.ovpn.example`](base.ovpn.example) shows the result.

**3. Check it:** `cvpnctl status` loads everything, contacts AWS, and changes
nothing.

cvpnctl uses `--config <file>` if given. Otherwise it uses the first of these
that exists: `./cvpnctl.yaml` in the current directory,
`~/.config/cvpnctl/cvpnctl.yaml`, `/etc/cvpnctl/cvpnctl.yaml`. It warns if a
later one is being ignored.

## Commands

| Command | What it does |
|---|---|
| `create -u <user>` | Issues a certificate, imports it to ACM, writes `<user>.ovpn` |
| `renew -u <user>` | Issues a new certificate, then revokes the old one and uploads the CRL |
| `revoke -u <user>` | Revokes the certificate, uploads the CRL, deletes it from ACM, removes the user's files |
| `list` | Lists users with certificate expiry and ACM ARN |
| `push-crl` | Regenerates the CRL and uploads it |
| `status` | Shows what expires when, and whether the endpoint's CRL matches your PKI. Changes nothing. |

- Access ends within about a minute of a revocation, including open sessions.
- A command that fails halfway can be run again.
- `revoke` asks for confirmation; `--yes` skips it, for scripts.
- `-v` shows EasyRSA's output; `-c <file>` selects a config file.

`status` exits with `0` when all is well, `2` when something expires within 30
days, has expired, or the endpoint's CRL is out of date, and `1` when the
check itself fails. To get a monthly reminder through cron:

```
0 9 1 * * out=$(/usr/local/bin/cvpnctl status 2>&1) || echo "$out"
```

## Certificates and expiry

| Certificate | Default lifetime | When it expires |
|---|---|---|
| CA | 10 years | Nothing works. A new CA needs a new endpoint and new `.ovpn` files for everyone. |
| Server certificate (endpoint) | 825 days | Nobody can connect. Renew it and re-import it into the same ACM ARN. |
| Client root (endpoint) | its certificate's lifetime | Re-import a renewed certificate into the same ACM ARN. |
| User certificate | 825 days | That user can't connect: `cvpnctl renew`. |
| CRL | 180 days | Nobody can connect. Every `renew`, `revoke`, and `push-crl` refreshes it. |

`cvpnctl status` shows all of them. For Client VPN, the server certificate
needs a domain name: create it with
`easyrsa --san=DNS:server build-server-full server nopass`.

## CA key

Anyone with the CA's private key (`pki/private/ca.key`) can issue certificates
your VPN accepts. Keep it on an encrypted disk, and encrypt its backups.

You can also protect it with a passphrase (`easyrsa set-pass ca`). EasyRSA then
asks for it on every `create`, `renew`, `revoke`, and `push-crl`, so these need
a terminal and can't run unattended. `list` and `status` don't need it.

## Development

```
go test ./...      # lifecycle tests run if EasyRSA is installed
go vet ./...
go build ./cmd/cvpnctl
```

## License

MIT, see [LICENSE](LICENSE).
