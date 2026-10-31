# IAM permissions

cvpnctl uses the AWS credentials of the admin running it (the default credential chain, or `aws.profile`). These are the permissions it needs. Replace the `<…>` placeholders with your values.

## Base policy (every setup)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "UserCertificates",
      "Effect": "Allow",
      "Action": ["acm:ImportCertificate", "acm:DeleteCertificate", "acm:DescribeCertificate"],
      "Resource": "*"
    },
    {
      "Sid": "EndpointCRL",
      "Effect": "Allow",
      "Action": [
        "ec2:ImportClientVpnClientCertificateRevocationList",
        "ec2:ExportClientVpnClientCertificateRevocationList"
      ],
      "Resource": "arn:aws:ec2:<region>:<account-id>:client-vpn-endpoint/<endpoint-id>"
    },
    {
      "Sid": "EndpointStatus",
      "Effect": "Allow",
      "Action": "ec2:DescribeClientVpnEndpoints",
      "Resource": "*"
    }
  ]
}
```

| Statement | Used by | Why |
|---|---|---|
| `UserCertificates` | `create`, `renew`, `revoke`, `status` | Each user's certificate is imported to ACM; `revoke` and `renew` delete the old one; `status` reads expiry dates. `ImportCertificate` creates a new ARN, so it can't be scoped to existing resources. |
| `EndpointCRL` | `revoke`, `renew`, `push-crl`, `status`, `store restore` | Importing the CRL is what ends a revoked user's access; exporting it lets `status` and `restore` compare it with the PKI. Scoped to your endpoint. |
| `EndpointStatus` | `status` | Finds the endpoint's server certificate and client root. Describe actions don't support resource-level permissions. |

`DescribeCertificate`, `ExportClientVpnClientCertificateRevocationList` and `DescribeClientVpnEndpoints` are read-only; an admin who only runs `status` needs just those.

## Additional policy for the shared PKI in S3

For the bucket `<bucket>` with the prefix `cvpnctl/` and the KMS key `<kms-key-arn>`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "StoreObjects",
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::<bucket>/cvpnctl/*"
    },
    {
      "Sid": "StoreBucket",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:ListBucketVersions",
        "s3:GetBucketVersioning",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketPublicAccessBlock"
      ],
      "Resource": "arn:aws:s3:::<bucket>"
    },
    {
      "Sid": "StoreEncryption",
      "Effect": "Allow",
      "Action": ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"],
      "Resource": "<kms-key-arn>"
    }
  ]
}
```

| Statement | Why |
|---|---|
| `StoreObjects` | Read and write the PKI archive (`pki.tar.gz`), the lock object, and the `.ovpn` files behind download links; `GetObjectVersion` reads earlier versions for `store versions --details` and `store restore`. `DeleteObject` releases the lock and removes links. |
| `StoreBucket` | List versions and links, and check that the bucket has versioning, KMS encryption and public access blocked (`store migrate` and `status`). |
| `StoreEncryption` | Everything is written encrypted with your KMS key. |

Deliberately **not** needed: `s3:DeleteObjectVersion`. No admin can erase the PKI's history through cvpnctl; deleting the archive only adds a delete marker, and `store restore` brings a version back.

The caller's identity (`sts:GetCallerIdentity`, recorded in the lock and in each archive version) needs no permission.

## Download links

A `.ovpn` download link is signed with the credentials of the admin who created it. It works only while those credentials are valid and still allow `s3:GetObject` and `kms:Decrypt` on the link's object: deactivating an admin's access key also ends their links. Temporary credentials (SSO, an assumed role) end a link when they expire; cvpnctl then prints the real expiry and warns.
