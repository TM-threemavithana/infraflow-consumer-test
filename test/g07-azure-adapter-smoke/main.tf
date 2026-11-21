# ==============================================================================
# InfraFlow G07.7 — Azure Adapter Smoke Fixture
#
# This module simulates an Azure workload deployment for offline cloud-free
# validation using InfraFlow's reusable-tf-azure.yml adapter.
#
# It uses only the built-in terraform_data resource — no azurerm provider is
# required, so terraform plan -backend=false succeeds without credentials.
# The plan produces one resource addition (has-changes=true, total-changes=1,
# has-destructive-changes=false), which allows the consumer workflow to verify
# the full output contract from the platform adapter.
#
# Security Invariants:
#   - No Azure provider block — zero credential exposure
#   - No backend block — cloud-free init only
#   - Consistent with InfraFlow's cloud-free speculative planning design
# ==============================================================================

resource "terraform_data" "azure_service" {
  input = {
    service         = var.service_name
    environment     = var.environment
    region          = var.azure_region
    subscription_id = var.subscription_id
    resource_group  = var.resource_group_name
    managed_by      = "infraflow"
    adapter         = "g07-azure"
    status          = "simulated"
  }
}
