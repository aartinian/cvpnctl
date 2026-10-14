# cvpnctl

[![CI](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml/badge.svg)](https://github.com/aartinian/cvpnctl/actions/workflows/ci.yaml)

`cvpnctl` manages OpenVPN client certificates for **AWS Client VPN** with
**EasyRSA**. One command issues a certificate, imports it to AWS Certificate
Manager, and writes a ready-to-send `.ovpn` file. Another revokes it and pushes
the updated CRL to the VPN endpoint, which ends the user's access within about
a minute, open sessions included.

```
$ cvpnctl create -u max.mustermann
Creating max.mustermann
  ✓ certificate issued         expires 2029-01-15
  ✓ files saved                ~/vpn/certs/max.mustermann/
  ✓ imported to ACM            …/287fe781
  ✓ .ovpn written              ~/vpn/clients/max.mustermann.ovpn
Done. Send ~/vpn/clients/max.mustermann.ovpn to max.mustermann securely.

$ cvpnctl renew  -u max.mustermann
$ cvpnctl revoke -u max.mustermann
$ cvpnctl status
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
- AWS credentials with the permissions below
- Linux or macOS

### AWS permissions

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

`acm:DescribeCertificate`, `ec2:ExportClientVpnClientCertificateRevocationList`
and `ec2:DescribeClientVpnEndpoints` are read-only, and only `status` uses them.

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
  output_dir: ~/vpn/certs            # per-user folders + state file
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

The config is read from `--config`, else the first of `./cvpnctl.yaml`,
`~/.config/cvpnctl/cvpnctl.yaml`, and `/etc/cvpnctl/cvpnctl.yaml`. If a file
further down that list also exists, cvpnctl warns that it is being ignored.

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
| `status` | Shows everything that expires, and whether the endpoint's CRL matches your PKI. Changes nothing. |

Every command can simply be run again if it fails halfway. `-v`/`--verbose`
shows EasyRSA's own output as it runs; otherwise it appears only when a step
fails. `-c`/`--config` picks a config file.

### Keeping an eye on expiry

`status` lists the CA, the endpoint's server certificate and client root, the
CRL (on this machine and on the endpoint), and every user, with how long each
has left. It marks anything expiring within 30 days with `!` and anything
expired or out of step with `✗`.

Its exit code is `0` when all is well, `2` when something needs attention, and
`1` when the check itself failed, so a scheduled job can warn you. For example,
in `crontab -e`, monthly, printing the table only when something is wrong
(cron mails a job's output, if mail is set up on the machine):

```
0 9 1 * * out=$(/usr/local/bin/cvpnctl status 2>&1) || echo "$out"
```

Use the full path, since cron's `PATH` is minimal. The job needs AWS
credentials that don't expire in between (an SSO session does). `status`
never needs the CA passphrase.

## How the pieces fit together

When a user connects, their VPN app checks the endpoint's **server
certificate** against the **CA** in their `.ovpn`. The endpoint checks the
user's **client certificate** against the same CA, and against the **CRL**.
Nothing involved may be expired.

| Piece | What it is | Where it lives | Default lifetime | When it expires |
|---|---|---|---|---|
| **CA** | The root of trust. Signs every certificate and the CRL. | Your PKI (`ca.crt`, `private/ca.key`) | 10 years | Everything stops. A new CA means a new endpoint, and every user needs a new `.ovpn`. Plan years ahead. |
| **Server certificate** | Proves to users that they reached your endpoint. | Your PKI and ACM | 825 days | Nobody can connect. Renew it with the same key and re-import it into the **same** ACM ARN; users' files don't change. |
| **Client root** | The ACM certificate whose chain tells the endpoint which CA to trust for clients. Fixed when the endpoint is created. | ACM | That certificate's lifetime | Re-import a renewed certificate into the same ARN before it expires. |
| **Client certificate** | Identifies one user. | Your PKI, that user's `.ovpn`, and ACM | 825 days | That user can't connect: `cvpnctl renew`, then send them the new `.ovpn`. |
| **CRL** | The CA-signed list of revoked client certificates. | Your PKI (`crl.pem`), imported to the endpoint | 180 days | **Nobody can connect.** Every `renew`, `revoke` and `push-crl` refreshes it; in quiet periods, run `push-crl`. |

`cvpnctl status` shows all of them. On a self-hosted OpenVPN server the rules
are the same, except that the CA, the server certificate and `crl.pem` are
files on the server rather than ACM entries and an imported CRL.

The server certificate needs a domain name for Client VPN. EasyRSA doesn't add
one by default, so create it with
`easyrsa --san=DNS:server build-server-full server nopass`.

## Protecting the CA key

Whoever holds `private/ca.key` can issue certificates your VPN accepts. Keep
the PKI on an encrypted disk, encrypt its backups, and consider a
**passphrase** on the key:

```
easyrsa --pki-dir=<your PKI> set-pass ca
```

What that means for cvpnctl:

- **Prompts.** EasyRSA asks for the passphrase each time the CA signs:
  once for `create` and `push-crl`, twice for `revoke`, three times for
  `renew`. cvpnctl says which step is asking. `list` and `status` never ask.
- **A terminal is required** for those commands, so they can't run from cron
  or CI. `EASYRSA_PASSIN` works for revoking and regenerating the CRL, but not
  for issuing certificates.
- **Keep the passphrase somewhere other than your AWS credentials**, such as a
  password manager. Stored next to them (in Secrets Manager, say), it stops
  being a second factor.
- **If it's lost, the CA can never sign again**: a new CA, a new endpoint, and
  new files for every user.

Without a passphrase, your disk encryption and the access controls around the
PKI are what protect the CA.

## Development

```
go test ./...      # lifecycle tests run if EasyRSA is installed
go vet ./...
go build ./cmd/cvpnctl
```

## License

MIT, see [LICENSE](LICENSE).
