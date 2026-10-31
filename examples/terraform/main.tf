# Infrastructure for cvpnctl's shared PKI (S3 mode): a versioned, KMS-encrypted
# bucket with public access blocked, and an IAM group with exactly the
# permissions cvpnctl needs (docs/iam.md).

# --- KMS key: encrypts the archive, the lock and the .ovpn download files -----

resource "aws_kms_key" "cvpnctl" {
  description             = "${var.name} shared PKI"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  # The default key policy delegates to IAM; the group policy below grants use.
}

resource "aws_kms_alias" "cvpnctl" {
  name          = "alias/${var.name}"
  target_key_id = aws_kms_key.cvpnctl.key_id
}

# --- Bucket -------------------------------------------------------------------

resource "aws_s3_bucket" "pki" {
  bucket        = var.bucket_name
  force_destroy = var.force_destroy
}

# Every cvpnctl save is a version: the PKI's history for store versions/restore.
resource "aws_s3_bucket_versioning" "pki" {
  bucket = aws_s3_bucket.pki.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "pki" {
  bucket                  = aws_s3_bucket.pki.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "pki" {
  bucket = aws_s3_bucket.pki.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "pki" {
  bucket = aws_s3_bucket.pki.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.cvpnctl.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "pki" {
  bucket = aws_s3_bucket.pki.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "TLSOnly"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [aws_s3_bucket.pki.arn, "${aws_s3_bucket.pki.arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.pki]
}

resource "aws_s3_bucket_lifecycle_configuration" "pki" {
  bucket     = aws_s3_bucket.pki.id
  depends_on = [aws_s3_bucket_versioning.pki]

  # .ovpn download files: cvpnctl deletes them itself; this is the backstop.
  # 8 days is longer than the longest link (7 days).
  rule {
    id     = "delivery"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}delivery/"
    }
    expiration {
      days = 8
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
  }

  # The lock: every release leaves a delete marker and an old version.
  rule {
    id     = "lock"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}lock"
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
    expiration {
      expired_object_delete_marker = true
    }
  }

  # The PKI's history: earlier versions to restore from.
  rule {
    id     = "history"
    status = "Enabled"
    filter {
      prefix = "${var.prefix}pki.tar.gz"
    }
    noncurrent_version_expiration {
      noncurrent_days = var.history_days
    }
  }
}

# --- Admins -------------------------------------------------------------------

resource "aws_iam_group" "admins" {
  name = "${var.name}-admins"
}

# Exclusive: users added to this group outside Terraform are removed on apply.
resource "aws_iam_group_membership" "admins" {
  name  = "${var.name}-admins"
  group = aws_iam_group.admins.name
  users = var.admin_users
}

# The policies from docs/iam.md, scoped to this bucket, key and endpoint.
resource "aws_iam_group_policy" "admins" {
  name  = var.name
  group = aws_iam_group.admins.name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "StoreObjects"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:DeleteObject"]
        Resource = "${aws_s3_bucket.pki.arn}/${var.prefix}*"
      },
      {
        Sid    = "StoreBucket"
        Effect = "Allow"
        Action = [
          "s3:ListBucket", "s3:ListBucketVersions", "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock",
        ]
        Resource = aws_s3_bucket.pki.arn
      },
      {
        Sid      = "StoreEncryption"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.cvpnctl.arn
      },
      {
        Sid      = "UserCertificates"
        Effect   = "Allow"
        Action   = ["acm:ImportCertificate", "acm:DeleteCertificate", "acm:DescribeCertificate"]
        Resource = "*"
      },
      {
        Sid    = "EndpointCRL"
        Effect = "Allow"
        Action = [
          "ec2:ImportClientVpnClientCertificateRevocationList",
          "ec2:ExportClientVpnClientCertificateRevocationList",
        ]
        Resource = var.vpn_endpoint_arn
      },
      {
        Sid      = "EndpointStatus"
        Effect   = "Allow"
        Action   = "ec2:DescribeClientVpnEndpoints"
        Resource = "*"
      },
    ]
  })
}
