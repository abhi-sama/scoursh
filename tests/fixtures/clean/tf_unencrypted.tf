# encryption enabled - safe equivalent for IAC-TF-UNENCRYPTED-01.
resource "aws_ebs_volume" "data" {
  availability_zone = "us-east-1a"
  size              = 100
  encrypted         = true
}
