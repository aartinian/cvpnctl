# Terraform for the shared PKI

Creates what [cvpnctl's S3 mode](../../README.md#shared-pki-in-s3) needs, in the endpoint's region:

- a **KMS key** with rotation, and the alias `alias/cvpnctl`;
- an **S3 bucket** with versioning (the PKI's history), default encryption with that key, all public access blocked, ACLs disabled, and a policy that refuses anything but TLS;
- **lifecycle rules** that expire old lock versions after a day, leftover `.ovpn` download files after 8 days, and earlier PKI versions after `history_days` (365 by default);
- an **IAM group** `cvpnctl-admins` with exactly the permissions in [docs/iam.md](../../docs/iam.md), scoped to this bucket, key and endpoint, and the users in `admin_users` as its members.

## Use it

Copy this directory into your infrastructure code (or apply it as it is). Then:

```
terraform init
terraform apply \
  -var region=eu-central-1 \
  -var bucket_name=acme-vpn-pki \
  -var vpn_endpoint_arn=arn:aws:ec2:eu-central-1:111122223333:client-vpn-endpoint/cvpn-endpoint-0123456789abcdef0 \
  -var 'admin_users=["max.mustermann","erika.musterfrau"]'
```

The `store_config` output is the section to add to `cvpnctl.yaml`, in place of `easyrsa.pki_dir`, `certs` and `ovpn`:

```
terraform output -raw store_config
```

Then move an existing local setup into the bucket with `cvpnctl store migrate --from <local config>`, and check with `cvpnctl status`: the `bucket` row must be ✓.

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `region` | (required) | Region of the Client VPN endpoint; the bucket goes there too |
| `bucket_name` | (required) | Globally unique bucket name (`store.bucket`) |
| `vpn_endpoint_arn` | (required) | The endpoint whose CRL the admins may import |
| `admin_users` | `[]` | IAM user names that may run cvpnctl; the group's only members |
| `prefix` | `cvpnctl/` | Key prefix in the bucket (`store.prefix`) |
| `name` | `cvpnctl` | Names the KMS alias and the IAM group |
| `history_days` | `365` | How long earlier PKI versions are kept for `store restore` |
| `force_destroy` | `false` | Let `terraform destroy` delete every version; only for a sandbox |

## Notes

- **Group membership is exclusive.** Users added to `cvpnctl-admins` outside Terraform are removed on the next apply. If you manage memberships elsewhere, remove `aws_iam_group_membership` and attach the group policy your own way.
- **Deleting is deliberately hard.** With `force_destroy = false`, `terraform destroy` fails while the bucket holds any version, and the KMS key is only scheduled for deletion (30 days). That protects the CA's private key and the PKI's history from a stray destroy.
- **Roles instead of users:** for SSO or assumed roles, attach the same policy to the role instead of the group. Download links then expire with the role session; cvpnctl warns about that when it prints a link.
