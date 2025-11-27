resource "aws_s3_bucket" "vulnerable_bucket" {
  bucket = "my-vulnerable-bucket"
  acl    = "public-read" # Vulnerability: Public ACL

  versioning {
    enabled = false # Vulnerability: Versioning disabled
  }
}

resource "aws_ebs_volume" "vulnerable_volume" {
  availability_zone = "us-west-2a"
  size              = 40
  encrypted         = false # Vulnerability: Unencrypted volume
}

resource "aws_security_group" "vulnerable_sg" {
  name        = "allow_all"
  description = "Allow all inbound traffic"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"] # Vulnerability: Open to the world
  }
}
