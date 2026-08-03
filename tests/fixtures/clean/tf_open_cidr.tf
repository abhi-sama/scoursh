# ingress rule restricted to the operator's own network - safe equivalent
# for IAC-TF-OPEN_CIDR-01.
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }
}
