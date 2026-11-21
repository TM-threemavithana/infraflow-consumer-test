output "service_name" {
  description = "Simulated service name for smoke verification"
  value       = terraform_data.azure_service.input.service
}

output "environment" {
  description = "Target environment for this smoke deployment"
  value       = terraform_data.azure_service.input.environment
}

output "region" {
  description = "Azure region for the simulated workload"
  value       = terraform_data.azure_service.input.region
}

output "adapter_version" {
  description = "InfraFlow adapter identifier"
  value       = terraform_data.azure_service.input.adapter
}

output "status" {
  description = "Simulated deployment status"
  value       = terraform_data.azure_service.input.status
}
