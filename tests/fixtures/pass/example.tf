resource "null_resource" "example" {
  triggers = {
    name_prefix = local.name_prefix
    tags        = jsonencode(local.common_tags)
  }
}
