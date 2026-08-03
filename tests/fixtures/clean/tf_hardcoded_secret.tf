# database password sourced from a variable, never a literal - safe
# equivalent for IAC-TF-HARDCODED_SECRET-01.
resource "aws_db_instance" "app" {
  identifier = "app-db"
  engine     = "postgres"
  username   = "appuser"
  password   = var.db_password
}
