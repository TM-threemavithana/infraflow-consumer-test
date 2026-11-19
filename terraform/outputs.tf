output "service_status" {
  value = terraform_data.service.input.status
}

output "service_endpoint" {
  value = "https://${var.service_name}.${var.tier}.internal"
}
