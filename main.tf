# Vulnerable Terraform Configuration for Testing Checkov
# This file contains intentional security issues for demonstration purposes

# AWS Provider
provider "aws" {
  region = "us-east-1"
}

# Vulnerable S3 Bucket - No encryption, public access allowed
resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-test-bucket"

  # Missing: encryption configuration
  # Missing: versioning
  # Missing: logging
}

resource "aws_s3_bucket_public_access_block" "bad_public_access" {
  bucket = aws_s3_bucket.vulnerable_bucket.id

  # Allows public access - SECURITY ISSUE
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Vulnerable EC2 Instance - No encryption, open security group
resource "aws_instance" "vulnerable_instance" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"

  # No encryption for root volume - SECURITY ISSUE
  root_block_device {
    encrypted = false
  }

  # Missing: monitoring
  # Missing: IMDSv2 enforcement
  metadata_options {
    http_tokens = "optional" # Should be "required" for IMDSv2
  }

  vpc_security_group_ids = [aws_security_group.vulnerable_sg.id]
}

# Vulnerable Security Group - Wide open to the internet
resource "aws_security_group" "vulnerable_sg" {
  name        = "vulnerable-security-group"
  description = "Intentionally vulnerable security group"

  # SSH open to the world - CRITICAL SECURITY ISSUE
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # RDP open to the world - CRITICAL SECURITY ISSUE
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All traffic outbound - overly permissive
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerable RDS Database - No encryption, publicly accessible
resource "aws_db_instance" "vulnerable_database" {
  identifier           = "vulnerable-db"
  engine               = "mysql"
  engine_version       = "5.7"
  instance_class       = "db.t2.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123" # Hardcoded password - CRITICAL SECURITY ISSUE
  skip_final_snapshot  = true
  publicly_accessible  = true # Publicly accessible - SECURITY ISSUE
  storage_encrypted    = false # No encryption - SECURITY ISSUE

  # Missing: backup retention
  # Missing: deletion protection
  # Missing: monitoring
}

# Vulnerable IAM Policy - Too permissive
resource "aws_iam_policy" "vulnerable_policy" {
  name        = "vulnerable-admin-policy"
  description = "Overly permissive IAM policy"

  # Wildcard permissions - SECURITY ISSUE
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = "*"
        Resource = "*"
      }
    ]
  })
}

# Vulnerable CloudTrail - No encryption, no log validation
resource "aws_cloudtrail" "vulnerable_trail" {
  name                          = "vulnerable-trail"
  s3_bucket_name                = aws_s3_bucket.vulnerable_bucket.id
  include_global_service_events = true
  is_multi_region_trail         = false # Should be true - SECURITY ISSUE
  enable_log_file_validation    = false # No log validation - SECURITY ISSUE

  # Missing: KMS encryption
  # Missing: CloudWatch Logs integration
}

# Vulnerable EBS Volume - No encryption
resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-east-1a"
  size              = 40
  encrypted         = false # No encryption - SECURITY ISSUE

  # Missing: KMS key
}
