# cvpnctl

[![CI](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml/badge.svg)](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml)

`cvpnctl` manages OpenVPN client certificates for **AWS Client VPN** with
**EasyRSA**. One command issues a certificate, imports it to AWS Certificate
Manager, and writes a ready-to-send `.ovpn` file. Another revokes it and pushes
the updated CRL to the VPN endpoint, so access is cut off immediately.

```
$ cvpnctl create --user max.mustermann
$ cvpnctl renew  --user max.mustermann
$ cvpnctl revoke --user max.mustermann
$ cvpnctl list
```

## Why

Adding or removing a VPN user by hand is a dozen steps: run EasyRSA, copy files
around, import to ACM, stitch a `.ovpn` together, and on removal remember to
regenerate *and upload* the CRL. Skipping the last step leaves a revoked user
connected. `cvpnctl` does all of it, in an order that is safe to re-run if
anything fails halfway.

## Requirements

- [EasyRSA](https://github.com/OpenVPN/easy-rsa) **3.2.7 or later**, installed
  from a [release](https://github.com/OpenVPN/easy-rsa/releases) or Homebrew
  (most distro packages are older). `cvpnctl` checks the version and refuses
  anything older.
- An initialised EasyRSA PKI: the CA that your Client VPN endpoint trusts. If
  you create the endpoint's server certificate with EasyRSA, add
  `--san=DNS:server`: Client VPN requires a domain name on it, and EasyRSA no
  longer adds one by default.
- An AWS Client VPN endpoint using mutual (certificate) authentication
- AWS credentials with `acm:ImportCertificate`, `acm:DeleteCertificate`, and
  `ec2:ImportClientVpnClientCertificateRevocationList`
- Linux or macOS

## Install

```
curl -fsSL https://raw.githubusercontent.com/aartinian/cvpnctl/master/scripts/install.sh | bash
```

or with Go 1.26+:

```
go install github.com/aartinian/cvpnctl/cmd/cvpnctl@latest
```

## Configure

```
mkdir -p ~/.config/cvpnctl
cp cvpnctl.yaml.example ~/.config/cvpnctl/cvpnctl.yaml
cp base.ovpn.example ~/vpn/base.ovpn
```

```yaml
easyrsa:
  path: ~/easy-rsa                   # directory containing the easyrsa script
  pki_dir: ~/vpn-pki                 # your PKI
certs:
  output_dir: ~/certs                # per-user folders + state file
aws:
  region: eu-central-1
  profile: default                   # optional
  vpn_endpoint_id: cvpn-endpoint-0123456789abcdef0
ovpn:
  template: ~/vpn/base.ovpn
  output_dir: ~/vpn/clients
```

Keep the PKI in its own directory, not inside the EasyRSA folder or a git
clone of it. It holds your CA key, and upgrading or cleaning up EasyRSA should
never put that at risk.

The config is read from `--config`, else `./cvpnctl.yaml`,
`~/.config/cvpnctl/cvpnctl.yaml`, or `/etc/cvpnctl/cvpnctl.yaml`.

The template is a normal client config with `{{.CA}}`, `{{.Cert}}`, and
`{{.Key}}` where the inline blocks go. The easiest starting point is the
configuration file AWS lets you download for your endpoint; see
[`base.ovpn.example`](base.ovpn.example).

## Commands

| Command | What it does |
|---|---|
| `create -u <user>` | Issues a certificate, copies it to `certs.output_dir/<user>/`, imports it to ACM, writes `<user>.ovpn` |
| `renew -u <user>` | Issues a replacement, then revokes the old one and pushes the CRL |
| `revoke -u <user>` | Revokes, pushes the CRL, deletes from ACM, removes the user's files (asks first; `--yes` to skip) |
| `list` | Shows users, certificate expiry, and ACM ARNs |
| `push-crl` | Regenerates and pushes the CRL (to finish a failed renew, or refresh it before it expires) |

## Development

```
go test ./...      # lifecycle tests run if EasyRSA is installed
go vet ./...
go build ./cmd/cvpnctl
```

## License

MIT, see [LICENSE](LICENSE).
