# Example: Compliant S3 Bucket Configuration
# This example demonstrates a fully compliant S3 bucket that passes:
# - CIS AWS Foundations Benchmark 2.1.1, 2.1.2, 2.1.3, 2.1.4
# - ISO 27017 CLD.10.1.1, CLD.12.1.2
# - PCI-DSS 3.4.1, 10.5.1

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# KMS Key for S3 encryption (CIS-AWS-2.1.2, ISO-27017-CLD.10.1.1, PCI-DSS-3.4.1)
resource "aws_kms_key" "s3_encryption" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true # CIS-AWS-3.8

  tags = {
    Name               = "s3-encryption-key"
    Environment        = var.environment
    ManagedBy          = "Terraform"
    ComplianceStandard = "CIS-AWS-2.1.2,ISO-27017-CLD.10.1.1,PCI-DSS-3.4.1"
  }
}

resource "aws_kms_alias" "s3_encryption" {
  name          = "alias/s3-encryption-${var.environment}"
  target_key_id = aws_kms_key.s3_encryption.key_id
}

# S3 Bucket for access logs (required for CIS-AWS-2.1.3)
resource "aws_s3_bucket" "access_logs" {
  bucket = "compliant-access-logs-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Access Logs Bucket"
    Environment = var.environment
    Purpose     = "S3 Access Logging"
    ManagedBy   = "Terraform"
  }
}

# Block public access for logs bucket (CIS-AWS-2.1.4)
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for logs bucket (ISO-27017-CLD.12.1.2)
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Lifecycle policy for log retention (PCI-DSS-10.5.1)
resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "log-retention"
    status = "Enabled"

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = 2555 # 7 years for compliance
    }
  }
}

# COMPLIANT S3 BUCKET - Main Application Data
resource "aws_s3_bucket" "compliant" {
  bucket = "compliant-app-data-${var.environment}-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name                = "Compliant Application Data"
    Environment         = var.environment
    DataClassification  = var.data_classification
    ManagedBy           = "Terraform"
    ComplianceStandards = "CIS-AWS,ISO-27017,PCI-DSS"
  }
}

# CIS-AWS-2.1.4: Block all public access
resource "aws_s3_bucket_public_access_block" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# CIS-AWS-2.1.2: Enable KMS encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3_encryption.arn
    }
    bucket_key_enabled = true
  }
}

# CIS-AWS-2.1.3: Enable access logging
resource "aws_s3_bucket_logging" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "s3-access-logs/${aws_s3_bucket.compliant.id}/"
}

# ISO-27017-CLD.12.1.2: Enable versioning
resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.compliant.id
  versioning_configuration {
    status = "Enabled"
  }
}

# CIS-AWS-2.1.1: Enforce HTTPS-only access
resource "aws_s3_bucket_policy" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.compliant.arn,
          "${aws_s3_bucket.compliant.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.compliant.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      }
    ]
  })
}

# PCI-DSS-10.5.1: Protect audit logs
resource "aws_s3_bucket_lifecycle_configuration" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  rule {
    id     = "data-retention"
    status = "Enabled"

    # Archive old data
    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 180
      storage_class = "GLACIER_IR"
    }

    # For PCI data, retain for required period
    expiration {
      days = var.data_classification == "PCI" ? 2555 : 365
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }
}

# ISO-27017: Object Lock for immutability (optional, for critical data)
resource "aws_s3_bucket_object_lock_configuration" "compliant" {
  count  = var.enable_object_lock ? 1 : 0
  bucket = aws_s3_bucket.compliant.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}

# Enable bucket notifications for CloudTrail (CIS-AWS-3.x)
resource "aws_s3_bucket_notification" "compliant" {
  bucket = aws_s3_bucket.compliant.id

  # Notify on object creation (for audit)
  lambda_function {
    lambda_function_arn = var.audit_lambda_arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = "sensitive/"
  }
}

# NON-COMPLIANT EXAMPLE (will be caught by Checkov)
# Uncomment to test compliance checks
/*
resource "aws_s3_bucket" "non_compliant" {
  bucket = "non-compliant-bucket-${var.environment}"
  # Missing: encryption, public access block, logging
  # This will FAIL: CIS-AWS-2.1.1, 2.1.2, 2.1.3, 2.1.4
}
*/

# Data sources
data "aws_caller_identity" "current" {}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

variable "data_classification" {
  description = "Data classification level"
  type        = string
  default     = "Internal"
  validation {
    condition = contains(["Public", "Internal", "Confidential", "PCI", "PHI"], var.data_classification)
    error_message = "Invalid data classification."
  }
}

variable "enable_object_lock" {
  description = "Enable S3 Object Lock for immutability"
  type        = bool
  default     = false
}

variable "audit_lambda_arn" {
  description = "ARN of Lambda function for audit notifications"
  type        = string
  default     = ""
}

# Outputs
output "bucket_name" {
  description = "Name of the compliant S3 bucket"
  value       = aws_s3_bucket.compliant.id
}

output "bucket_arn" {
  description = "ARN of the compliant S3 bucket"
  value       = aws_s3_bucket.compliant.arn
}

output "kms_key_arn" {
  description = "ARN of KMS key used for encryption"
  value       = aws_kms_key.s3_encryption.arn
}

output "compliance_summary" {
  description = "Compliance standards met by this configuration"
  value = {
    cis_aws = [
      "2.1.1 - HTTPS-only access enforced",
      "2.1.2 - KMS encryption enabled",
      "2.1.3 - Access logging enabled",
      "2.1.4 - Public access blocked",
      "3.8 - KMS key rotation enabled"
    ]
    iso_27017 = [
      "CLD.10.1.1 - Data at rest encryption",
      "CLD.12.1.2 - Versioning enabled for log protection"
    ]
    pci_dss = [
      "3.4.1 - Cardholder data encrypted with KMS",
      "10.5.1 - Audit logs protected and retained"
    ]
  }
}
