# Workload Identity Federation using JWT

This example generates a jwks file.
It demonstrates how to convert a jwt signed with this key into a GCP access token for a service account.

## Run order

1. Instal pip requirements
2. Run python/main.py (it'll fail)
3. Run terraform
4. Run python/main.py again (it'll succeed)

## Audit logs

If you're interested in following the audit trail, enable audit logging on admin read in your GCP project.

Any request done via the jwt, will result in audit logs similar to:

```
{
  insertId: "REDACTED"
  logName: "projects/PROJECT_ID/logs/cloudaudit.googleapis.com%2Fdata_access"
  protoPayload: {
    @type: "type.googleapis.com/google.cloud.audit.AuditLog"
    authenticationInfo: {
      principalEmail: "jwt-example@PROJECT_ID.iam.gserviceaccount.com"
      principalSubject: "serviceAccount:jwt-example@PROJECT_ID.iam.gserviceaccount.com"
      serviceAccountDelegationInfo: [
        0: {
          principalSubject: "principal://iam.googleapis.com/projects/PROJECT_NUMBER/locations/global/workloadIdentityPools/jwt-pool/subject/test_user"
        }
      ]
    }
    ...
  }
  ...
}
```
