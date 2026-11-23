import { Context, Hono } from 'hono'
import type { D1Database } from '@cloudflare/workers-types'
import { getAuthenticatedUser, requireAuth } from '../middleware/auth'
import { generateId } from '../utils/crypto'

const ISSUER = 'https://shikoch.in'
const CODE_LIFETIME = 5 * 60
const REQUEST_LIFETIME = 10 * 60
const ACCESS_TOKEN_LIFETIME = 60 * 60
const ALLOWED_SCOPES = new Set(['openid', 'email'])

type Bindings = {
  RUINABLA_DB: D1Database
  OIDC_PRIVATE_JWK?: string
}

type OidcContext = Context<{ Bindings: Bindings }>

type OidcClient = {
  client_id: string
  user_id: string
  name: string
  client_secret_hash: string
  redirect_uris: string
  created_at: number
}

type PendingRequest = {
  id: string
  client_id: string
  user_id: string
  redirect_uri: string
  scope: string
  state: string
  nonce: string
  code_challenge: string
  code_challenge_method: string
  expires_at: number
}

type SigningJwk = JsonWebKey & { kid?: string; alg?: string; use?: string }

const oidc = new Hono<{ Bindings: Bindings }>()

function now(): number {
  return Math.floor(Date.now() / 1000)
}

function base64Url(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function fromBase64Url(value: string): Uint8Array {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64 + '='.repeat((4 - (base64.length % 4)) % 4))
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)))
}

async function hashText(value: string): Promise<string> {
  return base64Url(await sha256(value))
}

async function getSigningJwk(c: OidcContext): Promise<SigningJwk> {
  if (!c.env.OIDC_PRIVATE_JWK) {
    throw new Error('OIDC_PRIVATE_JWK is not configured')
  }
  let jwk: SigningJwk
  try {
    jwk = JSON.parse(c.env.OIDC_PRIVATE_JWK) as SigningJwk
  } catch {
    throw new Error('OIDC_PRIVATE_JWK must contain a JSON private JWK')
  }
  if (jwk.kty !== 'RSA' || !jwk.n || !jwk.e || !jwk.d) {
    throw new Error('OIDC_PRIVATE_JWK must be an RSA private JWK')
  }
  if (fromBase64Url(jwk.n).length < 256) {
    throw new Error('OIDC_PRIVATE_JWK must use an RSA key of at least 2048 bits')
  }
  if (!jwk.kid) {
    jwk.kid = await hashText(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n }))
  }
  jwk.alg = 'RS256'
  jwk.use = 'sig'
  return jwk
}

async function getSigningKey(c: OidcContext): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'jwk',
    await getSigningJwk(c),
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  )
}

async function signIdToken(c: OidcContext, claims: Record<string, unknown>): Promise<string> {
  const jwk = await getSigningJwk(c)
  const header = base64Url(
    new TextEncoder().encode(JSON.stringify({ alg: 'RS256', kid: jwk.kid, typ: 'JWT' })),
  )
  const payload = base64Url(new TextEncoder().encode(JSON.stringify(claims)))
  const signingInput = `${header}.${payload}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    await getSigningKey(c),
    new TextEncoder().encode(signingInput),
  )
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`
}

function validRedirectUri(value: unknown): value is string {
  if (typeof value !== 'string' || value.length > 2048) return false
  try {
    const url = new URL(value)
    const localHttp =
      url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
    return (url.protocol === 'https:' || localHttp) && !url.username && !url.password && !url.hash
  } catch {
    return false
  }
}

function parseScopes(value: unknown): string[] | null {
  if (typeof value !== 'string' || value.length > 200) return null
  const scopes = [...new Set(value.split(/\s+/).filter(Boolean))]
  if (!scopes.includes('openid') || scopes.some((scope) => !ALLOWED_SCOPES.has(scope))) return null
  return scopes
}

function safeRedirect(base: string, values: Record<string, string>): string {
  const url = new URL(base)
  for (const [key, value] of Object.entries(values)) url.searchParams.append(key, value)
  return url.toString()
}

function oauthError(c: OidcContext, error: string, status = 400, description?: string) {
  return c.json({ error, ...(description ? { error_description: description } : {}) }, status)
}

async function getClient(db: D1Database, clientId: string): Promise<OidcClient | null> {
  return (await db
    .prepare(
      'SELECT client_id, user_id, name, client_secret_hash, redirect_uris, created_at FROM oidc_clients WHERE client_id = ?',
    )
    .bind(clientId)
    .first()) as OidcClient | null
}

function publicClient(client: OidcClient) {
  return {
    id: client.client_id,
    name: client.name,
    redirectUris: JSON.parse(client.redirect_uris) as string[],
    createdAt: Number(client.created_at),
  }
}

oidc.get('/clients', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const { results } = await c.env.RUINABLA_DB.prepare(
    'SELECT client_id, user_id, name, client_secret_hash, redirect_uris, created_at FROM oidc_clients WHERE user_id = ? ORDER BY created_at DESC',
  )
    .bind(user.id)
    .all<OidcClient>()
  return c.json({ clients: results.map(publicClient) })
})

oidc.post('/clients', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const body = await c.req.json<{ name?: unknown; redirectUris?: unknown }>().catch(() => ({}))
  const name = typeof body.name === 'string' ? body.name.trim() : ''
  if (!name || name.length > 80)
    return c.json({ error: 'Client name must be 1 to 80 characters' }, 400)
  if (
    !Array.isArray(body.redirectUris) ||
    body.redirectUris.length < 1 ||
    body.redirectUris.length > 10 ||
    !body.redirectUris.every(validRedirectUri) ||
    new Set(body.redirectUris).size !== body.redirectUris.length
  ) {
    return c.json({ error: 'Register 1 to 10 unique HTTPS redirect URIs' }, 400)
  }

  const { count } = (await c.env.RUINABLA_DB.prepare(
    'SELECT COUNT(*) AS count FROM oidc_clients WHERE user_id = ?',
  )
    .bind(user.id)
    .first<{ count: number }>()) ?? { count: 0 }
  if (Number(count) >= 20) return c.json({ error: 'Client limit reached' }, 429)

  const clientId = generateId(16)
  const clientSecret = generateId(32)
  const clientSecretHash = await hashText(clientSecret)
  const createdAt = now()
  await c.env.RUINABLA_DB.prepare(
    'INSERT INTO oidc_clients (client_id, user_id, name, client_secret_hash, redirect_uris, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  )
    .bind(clientId, user.id, name, clientSecretHash, JSON.stringify(body.redirectUris), createdAt)
    .run()

  return c.json(
    {
      client: {
        id: clientId,
        name,
        redirectUris: body.redirectUris,
        createdAt,
      },
      clientSecret,
    },
    201,
  )
})

oidc.delete('/clients/:clientId', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const result = await c.env.RUINABLA_DB.prepare(
    'DELETE FROM oidc_clients WHERE client_id = ? AND user_id = ?',
  )
    .bind(c.req.param('clientId'), user.id)
    .run()
  if (!result.meta.changes) return c.json({ error: 'Client not found' }, 404)
  return c.json({ success: true })
})

// The SPA calls this endpoint with its existing bearer session after reading the OIDC URL.
oidc.post('/authorize', requireAuth, async (c) => {
  const body = await c.req.json<Record<string, unknown>>().catch(() => ({}))
  const clientId = typeof body.client_id === 'string' ? body.client_id : ''
  const redirectUri = typeof body.redirect_uri === 'string' ? body.redirect_uri : ''
  const state = typeof body.state === 'string' ? body.state : ''
  const nonce = typeof body.nonce === 'string' ? body.nonce : ''
  const challenge = typeof body.code_challenge === 'string' ? body.code_challenge : ''
  const scopes = parseScopes(body.scope)

  if (body.response_type !== 'code') return oauthError(c, 'unsupported_response_type')
  if (!clientId || !redirectUri || !state || state.length > 512 || !nonce || nonce.length > 512) {
    return oauthError(c, 'invalid_request', 400, 'Required authorization parameters are missing')
  }
  if (!scopes) return oauthError(c, 'invalid_scope')
  if (body.code_challenge_method !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return oauthError(c, 'invalid_request', 400, 'PKCE with S256 is required')
  }

  const client = await getClient(c.env.RUINABLA_DB, clientId)
  if (!client) return oauthError(c, 'unauthorized_client')
  const redirectUris = JSON.parse(client.redirect_uris) as string[]
  if (!redirectUris.includes(redirectUri))
    return oauthError(c, 'invalid_request', 400, 'redirect_uri is not registered')

  const requestId = generateId(24)
  const expiresAt = now() + REQUEST_LIFETIME
  const user = getAuthenticatedUser(c)
  const currentTime = now()
  await c.env.RUINABLA_DB.batch([
    c.env.RUINABLA_DB.prepare('DELETE FROM oidc_auth_requests WHERE expires_at <= ?').bind(
      currentTime,
    ),
    c.env.RUINABLA_DB.prepare('DELETE FROM oidc_authorization_codes WHERE expires_at <= ?').bind(
      currentTime,
    ),
    c.env.RUINABLA_DB.prepare('DELETE FROM oidc_access_tokens WHERE expires_at <= ?').bind(
      currentTime,
    ),
  ])
  await c.env.RUINABLA_DB.prepare(
    `INSERT INTO oidc_auth_requests
      (id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge, code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'S256', ?)`,
  )
    .bind(
      requestId,
      clientId,
      user.id,
      redirectUri,
      scopes.join(' '),
      state,
      nonce,
      challenge,
      expiresAt,
    )
    .run()
  return c.json({ requestId })
})

oidc.get('/authorize/request', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const requestId = c.req.query('request_id')
  if (!requestId) return oauthError(c, 'invalid_request')
  const request = (await c.env.RUINABLA_DB.prepare(
    `SELECT id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge,
            code_challenge_method, expires_at
       FROM oidc_auth_requests WHERE id = ? AND user_id = ? AND expires_at > ?`,
  )
    .bind(requestId, user.id, now())
    .first()) as PendingRequest | null
  if (!request) return oauthError(c, 'invalid_request', 404, 'Authorization request expired')
  const client = await getClient(c.env.RUINABLA_DB, request.client_id)
  if (!client) return oauthError(c, 'invalid_request', 404, 'Client no longer exists')
  return c.json({
    requestId: request.id,
    client: { id: client.client_id, name: client.name, redirectUri: request.redirect_uri },
    scopes: request.scope.split(' '),
  })
})

oidc.post('/authorize/consent', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const { requestId, approved } = await c.req
    .json<{ requestId?: string; approved?: boolean }>()
    .catch(() => ({}))
  if (typeof requestId !== 'string' || typeof approved !== 'boolean')
    return oauthError(c, 'invalid_request')

  const request = (await c.env.RUINABLA_DB.prepare(
    `DELETE FROM oidc_auth_requests WHERE id = ? AND user_id = ? AND expires_at > ?
     RETURNING id, client_id, user_id, redirect_uri, scope, state, nonce, code_challenge,
               code_challenge_method, expires_at`,
  )
    .bind(requestId, user.id, now())
    .first()) as PendingRequest | null
  if (!request) return oauthError(c, 'invalid_request', 404, 'Authorization request expired')

  if (!approved) {
    return c.json({
      redirectUrl: safeRedirect(request.redirect_uri, {
        error: 'access_denied',
        state: request.state,
      }),
    })
  }

  const code = generateId(32)
  await c.env.RUINABLA_DB.prepare(
    `INSERT INTO oidc_authorization_codes
      (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
       code_challenge_method, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'S256', ?)`,
  )
    .bind(
      await hashText(code),
      request.client_id,
      request.user_id,
      request.redirect_uri,
      request.scope,
      request.nonce,
      request.code_challenge,
      now() + CODE_LIFETIME,
    )
    .run()
  return c.json({ redirectUrl: safeRedirect(request.redirect_uri, { code, state: request.state }) })
})

function readClientCredentials(c: OidcContext, form: URLSearchParams) {
  let clientId = form.get('client_id') || ''
  let clientSecret = form.get('client_secret') || ''
  const authorization = c.req.header('Authorization')
  if (authorization?.startsWith('Basic ')) {
    try {
      const decoded = atob(authorization.slice(6))
      const separator = decoded.indexOf(':')
      if (separator >= 0) {
        const decodeFormComponent = (value: string) => decodeURIComponent(value.replace(/\+/g, ' '))
        clientId = decodeFormComponent(decoded.slice(0, separator))
        clientSecret = decodeFormComponent(decoded.slice(separator + 1))
      }
    } catch {
      return { clientId: '', clientSecret: '' }
    }
  }
  return { clientId, clientSecret }
}

async function sameSecret(actual: string, expected: string): Promise<boolean> {
  const actualHash = await sha256(actual)
  const expectedBytes = fromBase64Url(expected)
  if (actualHash.length !== expectedBytes.length) return false
  let difference = 0
  for (let index = 0; index < actualHash.length; index++)
    difference |= actualHash[index]! ^ expectedBytes[index]!
  return difference === 0
}

oidc.post('/token', async (c) => {
  const form = new URLSearchParams(await c.req.text())
  const authorization = c.req.header('Authorization')
  if (authorization && !authorization.startsWith('Basic '))
    return oauthError(c, 'invalid_client', 401)
  if (authorization?.startsWith('Basic ') && (form.has('client_id') || form.has('client_secret'))) {
    return oauthError(c, 'invalid_request')
  }
  const { clientId, clientSecret } = readClientCredentials(c, form)
  const client = clientId ? await getClient(c.env.RUINABLA_DB, clientId) : null
  if (!client || !(await sameSecret(clientSecret, client.client_secret_hash))) {
    return oauthError(c, 'invalid_client', 401)
  }
  if (form.get('grant_type') !== 'authorization_code')
    return oauthError(c, 'unsupported_grant_type')

  const code = form.get('code') || ''
  const redirectUri = form.get('redirect_uri') || ''
  const verifier = form.get('code_verifier') || ''
  if (!code || !redirectUri || !/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))
    return oauthError(c, 'invalid_grant')

  const codeHash = await hashText(code)
  const authorizationCode = await c.env.RUINABLA_DB.prepare(
    `SELECT code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
            code_challenge_method, expires_at
       FROM oidc_authorization_codes WHERE code_hash = ? AND client_id = ? AND expires_at > ?`,
  )
    .bind(codeHash, clientId, now())
    .first<PendingRequest & { code_hash: string }>()
  if (!authorizationCode || authorizationCode.redirect_uri !== redirectUri)
    return oauthError(c, 'invalid_grant')
  if (
    authorizationCode.code_challenge_method !== 'S256' ||
    (await hashText(verifier)) !== authorizationCode.code_challenge
  ) {
    return oauthError(c, 'invalid_grant')
  }

  const user = await c.env.RUINABLA_DB.prepare(
    'SELECT id, email, email_verified FROM users WHERE id = ?',
  )
    .bind(authorizationCode.user_id)
    .first<{ id: string; email: string; email_verified: number | boolean }>()
  if (!user) return oauthError(c, 'invalid_grant')

  const issuedAt = now()
  const expiresAt = issuedAt + ACCESS_TOKEN_LIFETIME
  const accessToken = generateId(32)
  const claims: Record<string, unknown> = {
    iss: ISSUER,
    sub: user.id,
    aud: clientId,
    iat: issuedAt,
    exp: expiresAt,
    nonce: authorizationCode.nonce,
  }
  if (authorizationCode.scope.split(' ').includes('email')) {
    claims.email = user.email
    claims.email_verified = Boolean(user.email_verified)
  }

  try {
    const idToken = await signIdToken(c, claims)
    const consumed = await c.env.RUINABLA_DB.prepare(
      'DELETE FROM oidc_authorization_codes WHERE code_hash = ? AND client_id = ? AND expires_at > ?',
    )
      .bind(codeHash, clientId, now())
      .run()
    if (!consumed.meta.changes) return oauthError(c, 'invalid_grant')

    await c.env.RUINABLA_DB.prepare(
      'INSERT INTO oidc_access_tokens (token_hash, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?)',
    )
      .bind(await hashText(accessToken), clientId, user.id, authorizationCode.scope, expiresAt)
      .run()

    return c.json(
      {
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: ACCESS_TOKEN_LIFETIME,
        id_token: idToken,
        scope: authorizationCode.scope,
      },
      200,
      { 'Cache-Control': 'no-store', Pragma: 'no-cache' },
    )
  } catch (error) {
    console.error('OIDC signing configuration error:', error)
    return oauthError(c, 'server_error', 500, 'OIDC signing key is not configured')
  }
})

async function userInfo(c: OidcContext) {
  const authorization = c.req.header('Authorization') || ''
  if (!authorization.startsWith('Bearer ')) {
    return c.json({ error: 'invalid_token' }, 401, { 'Access-Control-Allow-Origin': '*' })
  }
  const tokenHash = await hashText(authorization.slice(7))
  const token = await c.env.RUINABLA_DB.prepare(
    'SELECT user_id, scope FROM oidc_access_tokens WHERE token_hash = ? AND expires_at > ?',
  )
    .bind(tokenHash, now())
    .first<{ user_id: string; scope: string }>()
  if (!token) return c.json({ error: 'invalid_token' }, 401, { 'Access-Control-Allow-Origin': '*' })
  const user = await c.env.RUINABLA_DB.prepare(
    'SELECT id, email, email_verified FROM users WHERE id = ?',
  )
    .bind(token.user_id)
    .first<{ id: string; email: string; email_verified: number | boolean }>()
  if (!user) return c.json({ error: 'invalid_token' }, 401, { 'Access-Control-Allow-Origin': '*' })
  const claims: Record<string, unknown> = { sub: user.id }
  if (token.scope.split(' ').includes('email')) {
    claims.email = user.email
    claims.email_verified = Boolean(user.email_verified)
  }
  return c.json(claims, 200, {
    'Access-Control-Allow-Origin': '*',
    'Cache-Control': 'no-store',
  })
}

oidc.get('/userinfo', userInfo)
oidc.post('/userinfo', userInfo)
oidc.options('/userinfo', (c) =>
  c.body(null, 204, {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    'Access-Control-Max-Age': '86400',
  }),
)

oidc.get('/jwks', async (c) => {
  try {
    const jwk = await getSigningJwk(c)
    return c.json(
      { keys: [{ kty: jwk.kty, n: jwk.n, e: jwk.e, kid: jwk.kid, alg: 'RS256', use: 'sig' }] },
      200,
      { 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=300' },
    )
  } catch (error) {
    console.error('OIDC JWKS configuration error:', error)
    return c.json({ error: 'OIDC signing key is not configured' }, 503)
  }
})

export default oidc
