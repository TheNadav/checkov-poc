# Fresh Vulnerable Terraform Configuration for Testing
# Contains multiple security issues for Checkov to detect

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

# Vulnerable S3 Bucket - Multiple Issues
resource "aws_s3_bucket" "data_bucket" {
  bucket = "company-sensitive-data-bucket-2024"

  # Missing: server-side encryption
  # Missing: versioning
  # Missing: logging
  # Missing: public access block
}

resource "aws_s3_bucket_acl" "data_bucket_acl" {
  bucket = aws_s3_bucket.data_bucket.id
  acl    = "public-read" # CRITICAL: Bucket is publicly readable
}

# Vulnerable EC2 Instance
resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.medium"

  # CRITICAL: Using default VPC security group (too permissive)
  # Missing: encryption for EBS volumes
  # Missing: detailed monitoring
  # Missing: IMDSv2 requirement

  root_block_device {
    volume_size = 30
    encrypted   = false # No encryption at rest
    volume_type = "gp3"
  }

  ebs_block_device {
    device_name = "/dev/sdb"
    volume_size = 100
    encrypted   = false # Additional unencrypted volume
  }

  user_data = <<-EOF
              #!/bin/bash
              export DB_PASSWORD="SuperSecret123!" # Hardcoded credential
              echo "Server starting..."
              EOF
}

# Vulnerable Security Group - Wide Open
resource "aws_security_group" "web_sg" {
  name        = "web-server-sg"
  description = "Security group for web server"

  # SSH from anywhere - CRITICAL
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access from anywhere"
  }

  # HTTP from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP from anywhere"
  }

  # HTTPS from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS from anywhere"
  }

  # Database port exposed - CRITICAL
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "MySQL from anywhere"
  }

  # All egress traffic allowed
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerable RDS Instance
resource "aws_db_instance" "app_database" {
  identifier             = "app-production-db"
  engine                 = "postgres"
  engine_version         = "14.7"
  instance_class         = "db.t3.medium"
  allocated_storage      = 100
  storage_type           = "gp2"

  username = "admin"
  password = "Admin123456" # Hardcoded password - CRITICAL

  publicly_accessible    = true  # CRITICAL: Database exposed to internet
  storage_encrypted      = false # No encryption at rest

  backup_retention_period = 0    # No backups
  deletion_protection     = false # Can be accidentally deleted
  skip_final_snapshot     = true  # No final snapshot on deletion

  # Missing: automated backups
  # Missing: multi-AZ deployment
  # Missing: encryption
  # Missing: CloudWatch logging

  vpc_security_group_ids = [aws_security_group.web_sg.id]
}

# Vulnerable EKS Cluster
resource "aws_eks_cluster" "app_cluster" {
  name     = "production-cluster"
  role_arn = aws_iam_role.eks_role.arn

  vpc_config {
    subnet_ids              = ["subnet-12345", "subnet-67890"] # Placeholder IDs
    endpoint_public_access  = true  # Public API endpoint
    endpoint_private_access = false # No private access
    public_access_cidrs     = ["0.0.0.0/0"] # CRITICAL: Accessible from anywhere
  }

  # Missing: encryption of secrets
  # Missing: logging enabled
  # Missing: security group restrictions
}

# Overly Permissive IAM Role
resource "aws_iam_role" "eks_role" {
  name = "eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "eks.amazonaws.com"
        }
      }
    ]
  })
}

# Dangerous IAM Policy - Full Admin Access
resource "aws_iam_policy" "admin_policy" {
  name        = "developer-policy"
  description = "Policy for developers"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"          # CRITICAL: Full access to all services
        Resource = "*"          # CRITICAL: On all resources
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "eks_admin_attach" {
  role       = aws_iam_role.eks_role.name
  policy_arn = aws_iam_policy.admin_policy.arn
}

# Vulnerable Lambda Function
resource "aws_lambda_function" "processor" {
  filename      = "lambda.zip"
  function_name = "data-processor"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.8" # Outdated runtime

  environment {
    variables = {
      DATABASE_PASSWORD = "MyP@ssw0rd123" # Hardcoded password - CRITICAL
      API_KEY          = "sk-1234567890abcdef"
    }
  }

  # Missing: encryption at rest
  # Missing: VPC configuration
  # Missing: tracing
  # Missing: reserved concurrent executions
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Vulnerable KMS Key - No Rotation
resource "aws_kms_key" "app_key" {
  description             = "KMS key for application"
  deletion_window_in_days = 7
  enable_key_rotation     = false # No automatic rotation - SECURITY ISSUE

  # Missing: proper key policy
}

# Elasticsearch Domain - Publicly Accessible
resource "aws_elasticsearch_domain" "logs" {
  domain_name           = "application-logs"
  elasticsearch_version = "7.10"

  cluster_config {
    instance_type = "t3.small.elasticsearch"
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 35
  }

  encrypt_at_rest {
    enabled = false # No encryption - SECURITY ISSUE
  }

  node_to_node_encryption {
    enabled = false # No node-to-node encryption
  }

  # Missing: VPC configuration (publicly accessible)
  # Missing: enforce HTTPS
  # Missing: access policies
}
