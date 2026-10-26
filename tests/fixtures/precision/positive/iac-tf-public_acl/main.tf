resource "aws_s3_bucket_acl" "bad" {
 acl = "public-read"
}
