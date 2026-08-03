# database password hardcoded as a literal - true positive for
# IAC-TF-HARDCODED_SECRET-01.
resource "aws_db_instance" "app" {
  identifier = "app-db"
  engine     = "postgres"
  username   = "appuser"
  password   = "SuperSecretPassw0rd!"
}
