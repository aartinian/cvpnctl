variable "region" {
  description = "Region of the Client VPN endpoint; the bucket is created there too (cvpnctl's aws.region)."
  type        = string
}

variable "bucket_name" {
  description = "Name of the bucket that holds the shared PKI (store.bucket). Must be globally unique."
  type        = string
}

variable "prefix" {
  description = "Key prefix inside the bucket (store.prefix). Ends with a slash."
  type        = string
  default     = "cvpnctl/"

  validation {
    condition     = endswith(var.prefix, "/")
    error_message = "prefix must end with a slash, e.g. \"cvpnctl/\"."
  }
}

variable "vpn_endpoint_arn" {
  description = "ARN of the Client VPN endpoint, arn:aws:ec2:<region>:<account-id>:client-vpn-endpoint/<endpoint-id>. The admins may import its CRL."
  type        = string
}

variable "admin_users" {
  description = "IAM user names allowed to run cvpnctl. They become the only members of the admin group."
  type        = list(string)
  default     = []
}

variable "name" {
  description = "Names the KMS alias (alias/<name>, store.kms_key_id) and the IAM group (<name>-admins)."
  type        = string
  default     = "cvpnctl"
}

variable "history_days" {
  description = "How long earlier versions of the PKI are kept for cvpnctl store restore."
  type        = number
  default     = 365
}

variable "force_destroy" {
  description = "Let terraform destroy delete the bucket with every version in it. Only for a sandbox."
  type        = bool
  default     = false
}
