output "pool" {
  value = google_iam_workload_identity_pool_provider.jwt.name
}
output "sa" {
  value = google_service_account.jwt_example.email
}
