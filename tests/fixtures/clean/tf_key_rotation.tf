# aws_kms_key resource with automatic key rotation enabled - safe
# equivalent for IAC-TF-KEY_ROTATION_DISABLED-01.
resource "aws_kms_key" "app" {
  description             = "application data key"
  deletion_window_in_days = 7
  is_enabled              = true
  enable_key_rotation     = true
}
