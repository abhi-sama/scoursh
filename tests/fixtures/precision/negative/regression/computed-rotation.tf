resource "aws_kms_key" "conditional" { enable_key_rotation = var.rotation }
