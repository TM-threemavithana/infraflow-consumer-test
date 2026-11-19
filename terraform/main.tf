resource "terraform_data" "service" {
  input = {
    service = var.service_name
    tier    = var.tier
    status  = "online"
  }
}

resource "terraform_data" "broken" {
  malformed_syntax =
}
