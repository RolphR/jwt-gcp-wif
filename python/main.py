import json
import os
import requests
from datetime import datetime, timezone
from jwcrypto import jwk
from jwcrypto import jwt


PROJECT_ID = ''
PROJECT_NUMBER = ''


def get_jwks():
  priv_keys = "jwt/jwks_priv.json"
  pub_keys = "jwt/jwks.json"
  if not os.path.isfile(priv_keys):
    def gen_key(kid):
      return jwk.JWK.generate(
            kty='RSA',
            size=2048,
            kid=kid,
            use='sig',
            e='AQAB',
            alg='RS256'
      )
    print("Generating new keys")
    jwks = jwk.JWKSet()
    jwks.add(gen_key('key1'))
    jwks.add(gen_key('key2'))
    with open(priv_keys, 'w') as f:
      f.write(jwks.export(private_keys=True))
    with open(pub_keys, 'w') as f:
      f.write(jwks.export(private_keys=False))
  with open(priv_keys, 'r') as f:
    keys_json = f.read()
    keys= jwk.JWKSet()
    keys.import_keyset(keys_json)
  return keys


def sign_token(keys, kid, subject, custom_claims={}, ttl=300):
  key = keys.get_key(kid)
  now = int(datetime.now(timezone.utc).timestamp())
  claims = custom_claims | {
    'iss': 'https://github.com/RolphR/jwt-gcp-wif',
    'aud': 'https://example.tld/jwt-gcp-wif',
    'token.aud': 'https://example.tld/jwt-gcp-wif',
    'sub': subject,
    'exp': now + ttl,
    "iat": now,
  }
  token = jwt.JWT(
    header = {
      'alg':'RS256',
      'kid':kid,
      },
    claims=claims,
    key=keys
    )
  token.make_signed_token(key)
  return token.serialize()


def get_sts_token(token):
  # https://cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token
  body = json.dumps({
    'grantType': 'urn:ietf:params:oauth:grant-type:token-exchange',
    'audience': '//iam.googleapis.com/projects/' + PROJECT_NUMBER + '/locations/global/workloadIdentityPools/jwt-pool/providers/jwt-provider',
    'scope': 'https://www.googleapis.com/auth/cloud-platform',
    'requestedTokenType': 'urn:ietf:params:oauth:token-type:access_token',
    'subjectToken': token,
    'subjectTokenType': 'urn:ietf:params:oauth:token-type:jwt',
    'options': json.dumps({
      "accessBoundary": {
        "accessBoundaryRules": []
      },
      "audiences": [
        'https://www.googleapis.com/auth/cloud-platform',
      ],
      "userProject": PROJECT_ID
    })
  })
  headers = {
    'Content-type': 'application/json'
  }
  r = requests.post('https://sts.googleapis.com/v1/token',
                data=body,
                headers=headers
                )
  r.raise_for_status()
  return r.json()


def impersonate_sa(sts_token, sa_email):
  # https://cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken
  body = json.dumps({
    'scope': [
      'https://www.googleapis.com/auth/cloud-platform',
    ],
    'lifetime': '600s',
  })
  headers = {
    'Content-type': 'application/json',
    'Authorization': sts_token['token_type'] + ' ' + sts_token['access_token'],
  }
  r = requests.post('https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/' + sa_email + ':generateAccessToken',
                data=body,
                headers=headers
                )
  r.raise_for_status()
  return r.json()


def token_info(access_token):
  # https://cloud.google.com/docs/authentication/token-types
  r = requests.get('https://oauth2.googleapis.com/tokeninfo?access_token=' + access_token)
  r.raise_for_status()
  return r.json()


def get_project_iam(project, access_token):
  body = json.dumps({
  })
  headers = {
    'Content-type': 'application/json',
    'Authorization': 'Bearer ' + access_token,
  }
  r = requests.post('https://cloudresourcemanager.googleapis.com/v3/projects/' + project + ':getIamPolicy',
                    data=body,
                    headers=headers
                )
  r.raise_for_status()
  return r.json()

if __name__ == '__main__':
  # https://cloud.google.com/iam/docs/workload-identity-federation-with-other-providers#oidc_1
  keys = get_jwks()
  token = sign_token(keys, 'key1', 'test_user', custom_claims={
    'environment': 'dev',
    'requester': 'someone',
  })
  sts_token = get_sts_token(token)
  sa_token = impersonate_sa(sts_token, 'jwt-example@' + PROJECT_ID +'.iam.gserviceaccount.com')
  print(json.dumps(token_info(sa_token['accessToken'])))
  iam = get_project_iam(PROJECT_ID, sa_token['accessToken'])
  print(json.dumps(iam['bindings']))
