resource "aws_security_group" "example" { egress { cidr_blocks = ["0.0.0.0/0"] } ingress { cidr_blocks = ["0.0.0.0/0"] } }
