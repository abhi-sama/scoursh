resource "aws_security_group" "web" {
 egress {
  cidr_blocks = ["0.0.0.0/0"]
 }
}
