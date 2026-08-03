# RDS instance reachable only inside the VPC - safe equivalent for
# IAC-TF-RDS_PUBLIC-01.
resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  publicly_accessible = false
}
