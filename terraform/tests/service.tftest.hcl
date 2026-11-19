run "failing_assertion" {
  command = plan

  assert {
    condition     = output.service_status == "EXPECTED_FAILURE_STATUS"
    error_message = "Intentional negative test assertion failure."
  }
}
