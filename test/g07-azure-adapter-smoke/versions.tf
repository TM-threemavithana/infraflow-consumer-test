# ==============================================================================
# InfraFlow G07.7 — Azure Smoke Fixture
#
# Cloud-Free Design: This module deliberately uses only the built-in
# terraform_data resource to guarantee zero Azure provider authentication
# requirements during offline speculative planning (terraform init -backend=false
# && terraform plan). No azurerm provider, no ARM_* credentials, no cloud calls.
#
# Security Invariants:
#   1. Zero Azure credentials ($0 cloud spend).
#   2. No azurerm provider — avoids any authentication check at plan time.
#   3. Compatible with InfraFlow reusable-tf-azure.yml cloud-free-plan job.
# ==============================================================================

terraform {
  required_version = ">= 1.6.0"
}
