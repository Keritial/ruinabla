const issuer = 'https://shikoch.in'

export const onRequestGet: PagesFunction = () =>
  Response.json(
    {
      issuer,
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/api/oidc/token`,
      userinfo_endpoint: `${issuer}/api/oidc/userinfo`,
      jwks_uri: `${issuer}/api/oidc/jwks`,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'email'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'iss', 'aud', 'iat', 'exp', 'nonce', 'email', 'email_verified'],
    },
    {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
        'Content-Type': 'application/json; charset=utf-8',
      },
    },
  )
