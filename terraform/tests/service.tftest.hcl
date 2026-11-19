run "validate_service_online" {
  command = plan

  assert {
    condition     = output.service_status == "online"
    error_message = "Service status is not online"
  }

  assert {
    condition     = output.service_endpoint == "https://consumer-api.prod.internal"
    error_message = "Service endpoint mismatch"
  }
}
