resource "terraform_data" "service" {
  input = {
    service = var.service_name
    tier    = var.tier
    status  = "online"
  }
}
