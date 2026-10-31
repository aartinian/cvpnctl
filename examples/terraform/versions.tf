terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0, < 7.0"
    }
  }
}

# The bucket must be in the same region as the Client VPN endpoint, which is
# cvpnctl's aws.region.
provider "aws" {
  region = var.region
}
