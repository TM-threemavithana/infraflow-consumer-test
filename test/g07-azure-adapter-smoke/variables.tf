variable "environment" {
  description = "Target deployment environment (e.g. smoke, dev, prod)"
  type        = string
  default     = "smoke"
}

variable "service_name" {
  description = "Logical name for the simulated service"
  type        = string
  default     = "infraflow-azure-smoke"
}

variable "azure_region" {
  description = "Target Azure region for the simulated deployment"
  type        = string
  default     = "eastus"
}

variable "subscription_id" {
  description = "Synthetic Azure Subscription ID (UUID placeholder — no real auth)"
  type        = string
  default     = "00000000-0000-0000-0000-000000000001"
}

variable "resource_group_name" {
  description = "Simulated Azure Resource Group name"
  type        = string
  default     = "rg-infraflow-smoke"
}
