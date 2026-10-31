output "store_config" {
  description = "The store section for cvpnctl.yaml."
  value       = <<-EOT
    store:
      bucket: ${aws_s3_bucket.pki.id}
      prefix: ${var.prefix}
      kms_key_id: ${aws_kms_alias.cvpnctl.name}
      link_hours: 24
  EOT
}

output "admin_group" {
  description = "IAM group whose members may run cvpnctl."
  value       = aws_iam_group.admins.name
}
