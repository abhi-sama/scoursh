# RDS instance reachable from the public internet - true positive for
# IAC-TF-RDS_PUBLIC-01.
resource "aws_db_instance" "app" {
  identifier          = "app-db"
  engine              = "postgres"
  publicly_accessible = true
}
