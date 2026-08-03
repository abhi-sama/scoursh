# bucket ACL left private - safe equivalent for IAC-TF-PUBLIC_ACL-01.
resource "aws_s3_bucket_acl" "assets" {
  bucket = aws_s3_bucket.assets.id
  acl    = "private"
}
