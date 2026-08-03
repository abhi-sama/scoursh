# ingress rule with no source restriction - true positive for
# IAC-TF-OPEN_CIDR-01.
resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
