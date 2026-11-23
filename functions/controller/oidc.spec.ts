import { describe, expect, it, vi } from 'vitest'
import oidc from './oidc'

const user = { id: 'user-1', email: 'user@example.com', role: 'user' }
const client = {
  client_id: 'client-1',
  user_id: user.id,
  name: 'Example site',
  client_secret_hash: 'unused',
  redirect_uris: JSON.stringify([
    'https://client.example/callback?origin=app&state=registered-state',
  ]),
  created_at: 1_800_000_000,
}

function createDatabase(pendingRequest?: Record<string, unknown>) {
  const inserts: Array<{ sql: string; values: unknown[] }> = []
  const db = {
    prepare(sql: string) {
      let values: unknown[] = []
      const statement = {
        bind(...nextValues: unknown[]) {
          values = nextValues
          return statement
        },
        async first() {
          if (sql.includes('FROM sessions s')) {
            return {
              session_id: 'session-1',
              session_user_id: user.id,
              expires_at: 1_900_000_000,
              reauthenticated_at: null,
              user_id: user.id,
              email: user.email,
              role: user.role,
            }
          }
          if (sql.includes('FROM oidc_clients WHERE client_id = ?')) return client
          if (sql.includes('DELETE FROM oidc_auth_requests')) return pendingRequest ?? null
          return null
        },
        async run() {
          inserts.push({ sql, values })
          return { meta: { changes: 1 } }
        },
      }
      return statement
    },
  }
  return { db, inserts }
}

function base64Url(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

async function createTokenDatabase(code: string, verifier: string, clientSecret: string) {
  const clientSecretHash = base64Url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(clientSecret))),
  )
  const codeHash = base64Url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(code))),
  )
  const codeChallenge = base64Url(
    new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))),
  )
  let consumed = false
  let accessTokenCount = 0
  const db = {
    prepare(sql: string) {
      let values: unknown[] = []
      const statement = {
        bind(...nextValues: unknown[]) {
          values = nextValues
          return statement
        },
        async first() {
          if (sql.includes('FROM oidc_clients WHERE client_id = ?')) {
            return { ...client, client_secret_hash: clientSecretHash }
          }
          if (sql.includes('FROM oidc_authorization_codes')) {
            if (consumed || values[0] !== codeHash) return null
            return {
              code_hash: codeHash,
              client_id: client.client_id,
              user_id: user.id,
              redirect_uri: 'https://client.example/callback',
              scope: 'openid email',
              nonce: 'expected-nonce',
              code_challenge: codeChallenge,
              code_challenge_method: 'S256',
              expires_at: 1_900_000_000,
            }
          }
          if (sql.includes('FROM users WHERE id = ?')) return { ...user, email_verified: 1 }
          return null
        },
        async run() {
          if (sql.startsWith('DELETE FROM oidc_authorization_codes')) {
            if (consumed) return { meta: { changes: 0 } }
            consumed = true
            return { meta: { changes: 1 } }
          }
          if (sql.startsWith('INSERT INTO oidc_access_tokens')) accessTokenCount++
          return { meta: { changes: 1 } }
        },
      }
      return statement
    },
  }
  return { db, getAccessTokenCount: () => accessTokenCount }
}

const bindings = (RUINABLA_DB: unknown, OIDC_PRIVATE_JWK?: string) =>
  ({ RUINABLA_DB, OIDC_PRIVATE_JWK }) as never

function authenticatedPost(path: string, body: unknown) {
  return new Request(`https://shikoch.in${path}`, {
    method: 'POST',
    headers: {
      Authorization: 'Bearer session-1',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
}

describe('OIDC provider authorization safeguards', () => {
  it('rejects an unregistered redirect URI before creating an authorization request', async () => {
    const { db, inserts } = createDatabase()
    const response = await oidc.request(
      authenticatedPost('/authorize', {
        client_id: client.client_id,
        redirect_uri: 'https://attacker.example/callback',
        response_type: 'code',
        scope: 'openid email',
        state: 'state-1',
        nonce: 'nonce-1',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'S256',
      }),
      undefined,
      bindings(db),
    )

    expect(response.status).toBe(400)
    expect(inserts.some(({ sql }) => sql.includes('INSERT INTO oidc_auth_requests'))).toBe(false)
  })

  it('requires S256 PKCE before accepting an authorization request', async () => {
    const { db, inserts } = createDatabase()
    const response = await oidc.request(
      authenticatedPost('/authorize', {
        client_id: client.client_id,
        redirect_uri: JSON.parse(client.redirect_uris)[0],
        response_type: 'code',
        scope: 'openid email',
        state: 'state-1',
        nonce: 'nonce-1',
        code_challenge: 'a'.repeat(43),
        code_challenge_method: 'plain',
      }),
      undefined,
      bindings(db),
    )

    expect(response.status).toBe(400)
    expect(inserts.some(({ sql }) => sql.includes('INSERT INTO oidc_auth_requests'))).toBe(false)
  })

  it('returns consent denial to the exact registered redirect URI with the original state', async () => {
    const { db } = createDatabase({
      id: 'request-1',
      client_id: client.client_id,
      user_id: user.id,
      redirect_uri: JSON.parse(client.redirect_uris)[0],
      scope: 'openid email',
      state: 'state-1',
      nonce: 'nonce-1',
      code_challenge: 'a'.repeat(43),
      code_challenge_method: 'S256',
      expires_at: 1_900_000_000,
    })
    const response = await oidc.request(
      authenticatedPost('/authorize/consent', { requestId: 'request-1', approved: false }),
      undefined,
      bindings(db),
    )
    const data = (await response.json()) as { redirectUrl: string }
    const redirect = new URL(data.redirectUrl)

    expect(response.status).toBe(200)
    expect(redirect.origin).toBe('https://client.example')
    expect(redirect.pathname).toBe('/callback')
    expect(redirect.searchParams.get('origin')).toBe('app')
    expect(redirect.searchParams.get('error')).toBe('access_denied')
    expect(redirect.searchParams.getAll('state')).toEqual(['registered-state', 'state-1'])
  })

  it('does not publish a generated JWKS when the persistent signing key is missing', async () => {
    const logSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
    const response = await oidc.request('/jwks', {}, bindings(createDatabase().db))
    expect(response.status).toBe(503)
    expect(await response.json()).toMatchObject({ error: 'OIDC signing key is not configured' })
    logSpy.mockRestore()
  })

  it('exchanges a PKCE code once and includes the original nonce in the ID token', async () => {
    const code = 'authorization-code'
    const verifier = 'v'.repeat(43)
    const clientSecret = 'client-secret'
    const { db, getAccessTokenCount } = await createTokenDatabase(code, verifier, clientSecret)
    const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSASSA-PKCS1-v1_5',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      },
      true,
      ['sign', 'verify'],
    )
    const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey)
    const form = new URLSearchParams({
      client_id: client.client_id,
      client_secret: clientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: 'https://client.example/callback',
      code_verifier: verifier,
    })
    const request = () =>
      oidc.request(
        new Request('https://shikoch.in/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: form.toString(),
        }),
        undefined,
        bindings(db, JSON.stringify(privateJwk)),
      )

    const firstResponse = await request()
    const firstBody = (await firstResponse.json()) as { id_token: string }
    const [header, encodedPayload, encodedSignature] = firstBody.id_token.split('.')
    const decodeBase64Url = (value: string) => {
      const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
      const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
      return Uint8Array.from(binary, (character) => character.charCodeAt(0))
    }
    const claims = JSON.parse(new TextDecoder().decode(decodeBase64Url(encodedPayload!)))
    const signatureIsValid = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      keyPair.publicKey,
      decodeBase64Url(encodedSignature!),
      new TextEncoder().encode(`${header}.${encodedPayload}`),
    )
    const secondResponse = await request()

    expect(firstResponse.status).toBe(200)
    expect(JSON.parse(new TextDecoder().decode(decodeBase64Url(header!)))).toMatchObject({
      alg: 'RS256',
    })
    expect(signatureIsValid).toBe(true)
    expect(claims).toMatchObject({ nonce: 'expected-nonce', aud: client.client_id, sub: user.id })
    expect(secondResponse.status).toBe(400)
    expect(await secondResponse.json()).toMatchObject({ error: 'invalid_grant' })
    expect(getAccessTokenCount()).toBe(1)
  })
})
