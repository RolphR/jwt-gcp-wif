data "google_project" "project" {
  project_id = var.project
}

resource "google_iam_workload_identity_pool" "jwt" {
  project                   = var.project
  workload_identity_pool_id = "jwt-pool"
}

resource "google_iam_workload_identity_pool_provider" "jwt" {
  project                            = var.project
  workload_identity_pool_id          = google_iam_workload_identity_pool.jwt.workload_identity_pool_id
  workload_identity_pool_provider_id = "jwt-provider"
  display_name                       = "JWT provider"
  description                        = "JWT example provider"
  attribute_condition                = "attribute.environment == \"dev\""
  attribute_mapping = {
    "google.subject"        = "assertion.sub"
    "attribute.requester"   = "assertion.requester"
    "attribute.environment" = "assertion.environment"
  }
  oidc {
    allowed_audiences = [
      "https://example.tld/jwt-gcp-wif"
    ]
    issuer_uri = "https://github.com/RolphR/jwt-gcp-wif"
    jwks_json  = file("../jwt/jwks.json")
  }
}

resource "google_service_account" "jwt_example" {
  project      = var.project
  account_id   = "jwt-example"
  display_name = "Service Account for JWT WIF"
}

resource "google_service_account_iam_binding" "jwt_example_wif_user" {
  service_account_id = google_service_account.jwt_example.name
  role               = "roles/iam.workloadIdentityUser"

  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.jwt.name}/attribute.environment/dev",
  ]
}

resource "google_project_iam_member" "viewer_jwt_example" {
  project = var.project
  role    = "roles/viewer"
  member  = google_service_account.jwt_example.member
}
