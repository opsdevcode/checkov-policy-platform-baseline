locals {
  name_prefix = "${var.module_name}-${var.environment}"
  common_tags = merge(
    var.tags,
    {
      Owner       = var.owner
      Service     = var.service
      Environment = var.environment
      CostCenter  = var.cost_center
      managed_by  = "terraform"
    },
  )
}
