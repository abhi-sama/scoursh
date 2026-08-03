# instance auto-assigns a public IP - true positive for
# IAC-TF-PUBLIC_IP-01.
resource "aws_instance" "web" {
  ami                         = "ami-0123456789abcdef0"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}
