# Terraform Configuration for Compliance Evidence S3 Bucket
# This bucket stores all compliance evidence with immutability and encryption

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

# Data sources
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# Variables
variable "aws_region" {
  description = "AWS region for evidence bucket"
  type        = string
  default     = "us-east-1"
}

variable "evidence_retention_days" {
  description = "Evidence retention period in days (7 years = 2555 days)"
  type        = number
  default     = 2555
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

# KMS Key for Evidence Encryption
resource "aws_kms_key" "evidence" {
  description             = "KMS key for compliance evidence encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow S3 to use the key"
        Effect = "Allow"
        Principal = {
          Service = "s3.amazonaws.com"
        }
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name        = "compliance-evidence-key"
    Environment = var.environment
    Purpose     = "Evidence Encryption"
    ManagedBy   = "Terraform"
  }
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/compliance-evidence-${var.environment}"
  target_key_id = aws_kms_key.evidence.key_id
}

# S3 Bucket for Compliance Evidence
resource "aws_s3_bucket" "evidence" {
  bucket = "compliance-evidence-${data.aws_caller_identity.current.account_id}"

  # Object lock must be enabled at bucket creation
  object_lock_enabled = true

  tags = {
    Name                = "Compliance Evidence Bucket"
    Environment         = var.environment
    Purpose             = "CIS Benchmark Compliance Evidence"
    ManagedBy           = "Terraform"
    CriticalData        = "true"
    ComplianceRequired  = "true"
    RetentionPeriod     = "${var.evidence_retention_days} days"
  }
}

# Versioning (Required for Object Lock)
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock Configuration (Immutability)
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    default_retention {
      mode = "GOVERNANCE"  # Allows deletion with special permissions
      days = var.evidence_retention_days
    }
  }
}

# Block All Public Access
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Server-Side Encryption (KMS)
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

# Access Logging
resource "aws_s3_bucket" "evidence_logs" {
  bucket = "compliance-evidence-logs-${data.aws_caller_identity.current.account_id}"

  tags = {
    Name        = "Compliance Evidence Access Logs"
    Environment = var.environment
    Purpose     = "S3 Access Logging"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket_logging" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  target_bucket = aws_s3_bucket.evidence_logs.id
  target_prefix = "evidence-access-logs/"
}

# Lifecycle Policy
resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  # Raw scans: Standard → IA → Glacier
  rule {
    id     = "raw-scans-lifecycle"
    status = "Enabled"

    filter {
      prefix = "raw-scans/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = var.evidence_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }
  }

  # Normalized findings: 3 years retention
  rule {
    id     = "normalized-findings-lifecycle"
    status = "Enabled"

    filter {
      prefix = "normalized-findings/"
    }

    transition {
      days          = 180
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 730
      storage_class = "GLACIER"
    }

    expiration {
      days = 1095  # 3 years
    }
  }

  # Remediations: 7 years retention
  rule {
    id     = "remediations-lifecycle"
    status = "Enabled"

    filter {
      prefix = "remediations/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = var.evidence_retention_days
    }
  }

  # Snapshots: 1 year retention
  rule {
    id     = "snapshots-lifecycle"
    status = "Enabled"

    filter {
      prefix = "snapshots/"
    }

    expiration {
      days = 365
    }
  }

  # Audit trail: 7 years retention
  rule {
    id     = "audit-trail-lifecycle"
    status = "Enabled"

    filter {
      prefix = "audit-trail/"
    }

    transition {
      days          = 90
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = 365
      storage_class = "GLACIER"
    }

    expiration {
      days = var.evidence_retention_days
    }
  }

  # Reports: Keep in Standard for easy access
  rule {
    id     = "reports-lifecycle"
    status = "Enabled"

    filter {
      prefix = "reports/"
    }

    transition {
      days          = 180
      storage_class = "STANDARD_IA"
    }

    expiration {
      days = var.evidence_retention_days
    }
  }
}

# Bucket Policy
resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Deny unencrypted uploads
      {
        Sid    = "DenyUnencryptedObjectUploads"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:PutObject"
        Resource = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = "aws:kms"
          }
        }
      },
      # Deny insecure transport
      {
        Sid    = "DenyInsecureTransport"
        Effect = "Deny"
        Principal = "*"
        Action = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      },
      # Require MFA for object deletion
      {
        Sid    = "RequireMFAForDeletion"
        Effect = "Deny"
        Principal = "*"
        Action = [
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent" = "false"
          }
        }
      }
    ]
  })
}

# IAM Role for Evidence Collector
resource "aws_iam_role" "evidence_collector" {
  name = "compliance-evidence-collector-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Name        = "Evidence Collector Role"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "evidence_collector" {
  name = "evidence-collector-policy"
  role = aws_iam_role.evidence_collector.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:PutObject",
          "s3:PutObjectTagging"
        ]
        Resource = "${aws_s3_bucket.evidence.arn}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.evidence.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}

# IAM Role for Auditors (Read-Only)
resource "aws_iam_role" "auditor" {
  name = "compliance-auditor-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = "auditor-access-${var.environment}"
          }
        }
      }
    ]
  })

  tags = {
    Name        = "Auditor Role"
    Environment = var.environment
    ManagedBy   = "Terraform"
  }
}

resource "aws_iam_role_policy" "auditor" {
  name = "auditor-policy"
  role = aws_iam_role.auditor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket",
          "s3:ListBucketVersions"
        ]
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.evidence.arn
      }
    ]
  })
}

# Outputs
output "evidence_bucket_name" {
  description = "Name of the evidence S3 bucket"
  value       = aws_s3_bucket.evidence.id
}

output "evidence_bucket_arn" {
  description = "ARN of the evidence S3 bucket"
  value       = aws_s3_bucket.evidence.arn
}

output "kms_key_id" {
  description = "ID of the KMS key for evidence encryption"
  value       = aws_kms_key.evidence.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key for evidence encryption"
  value       = aws_kms_key.evidence.arn
}

output "evidence_collector_role_arn" {
  description = "ARN of the IAM role for evidence collector"
  value       = aws_iam_role.evidence_collector.arn
}

output "auditor_role_arn" {
  description = "ARN of the IAM role for auditors"
  value       = aws_iam_role.auditor.arn
}

output "setup_complete" {
  description = "Evidence infrastructure setup details"
  value = {
    bucket_name    = aws_s3_bucket.evidence.id
    kms_key_alias  = aws_kms_alias.evidence.name
    versioning     = "Enabled"
    object_lock    = "Enabled (GOVERNANCE mode, ${var.evidence_retention_days} days)"
    encryption     = "KMS"
    public_access  = "Blocked"
    retention      = "${var.evidence_retention_days} days (7 years)"
  }
}
