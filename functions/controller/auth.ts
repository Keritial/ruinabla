import { Context, Hono } from 'hono'
import { D1Database } from '@cloudflare/workers-types'
import { createResendClient, sendPasswordResetEmail, sendVerificationEmail } from '../utils/email'
import { generateId, hashPassword, verifyPassword } from '../utils/crypto'
import {
  consumeKrtlLoginAttempt,
  createKrtlLinkAttempt,
  createKrtlLoginAttempt,
  exchangeKrtlCode,
  fetchKrtlUserInfo,
  KRTL_AUTHORIZATION_ENDPOINT,
  KRTL_REDIRECT_URI,
  KRTL_SCOPES,
  verifyKrtlIdToken,
} from '../utils/krtl'
import {
  consumeOpaqueLoginAttempt,
  consumeOpaqueRegistrationAttempt,
  consumePendingAuthChallenge,
  createOpaqueLoginAttempt,
  createOpaqueLoginResponse,
  createOpaqueRegistrationAttempt,
  createOpaqueRegistrationResponse,
  createPendingAuthChallenge,
  finishOpaqueLogin,
  getOpaqueServerSetup,
  getReauthExpiresAt,
  getSessionDurationDays,
  isRecentReauthenticationValid,
  buildOpaqueRegistrationRecordFromPassword,
  cleanupOpaqueArtifacts,
} from '../utils/opaque'
import {
  createSession,
  getAuthenticatedSession,
  getAuthenticatedUser,
  invalidateSession,
  markSessionReauthenticated,
  requireAuth,
} from '../middleware/auth'

type Bindings = {
  RUINABLA_DB: D1Database
  RESEND_API_KEY: string
  OPAQUE_SERVER_SETUP?: string
  ENVIRONMENT?: string
  KRTL_CLIENT_ID?: string
  KRTL_CLIENT_SECRET?: string
}

type AppContext = Context<{ Bindings: Bindings }>

type UserRecord = {
  id: string
  email: string
  password_hash: string | null
  opaque_registration_record: string | null
  role: string
}

type TwoFactorMethods = {
  totp: boolean
  passkey: boolean
}

const auth = new Hono<{ Bindings: Bindings }>()

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function base64UrlHash(value: string): Promise<string> {
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(value)).then((digest) => {
    let binary = ''
    for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte)
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
  })
}

function safeInternalRedirect(value: string | null | undefined): string {
  return value && value.startsWith('/') && !value.startsWith('//') ? value : '/'
}

function isDevelopmentRequest(c: AppContext): boolean {
  const requestUrl = new URL(c.req.url)
  return (
    c.env.ENVIRONMENT === 'development' ||
    requestUrl.hostname === 'localhost' ||
    requestUrl.hostname === '127.0.0.1'
  )
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase()
}

function validateEmail(email: string): string | null {
  const normalizedEmail = normalizeEmail(email)

  if (!emailRegex.test(normalizedEmail)) {
    return null
  }

  return normalizedEmail
}

async function getUserByEmail(db: D1Database, email: string): Promise<UserRecord | null> {
  const user = await db
    .prepare(
      'SELECT id, email, password_hash, opaque_registration_record, role FROM users WHERE email = ?',
    )
    .bind(email)
    .first()

  if (!user) {
    return null
  }

  return {
    id: user.id as string,
    email: user.email as string,
    password_hash: (user.password_hash as string | null) ?? null,
    opaque_registration_record: (user.opaque_registration_record as string | null) ?? null,
    role: user.role as string,
  }
}

async function getUserById(db: D1Database, userId: string) {
  return db.prepare('SELECT id, email, role FROM users WHERE id = ?').bind(userId).first()
}

async function getTwoFactorMethods(db: D1Database, userId: string): Promise<TwoFactorMethods> {
  const [totpRecord, passkeyRecord] = await Promise.all([
    db.prepare('SELECT enabled FROM totp_secrets WHERE user_id = ?').bind(userId).first(),
    db.prepare('SELECT id FROM passkeys WHERE user_id = ? LIMIT 1').bind(userId).first(),
  ])

  return {
    totp: Boolean(totpRecord && totpRecord.enabled),
    passkey: Boolean(passkeyRecord),
  }
}

async function sendVerificationEmailSafely(c: AppContext, email: string, token: string) {
  try {
    const resend = createResendClient(c.env.RESEND_API_KEY)
    const baseUrl = new URL(c.req.url).origin
    await sendVerificationEmail(resend, email, token, baseUrl)
  } catch (emailError) {
    console.error('Failed to send verification email:', emailError)
  }
}

async function createVerificationToken(db: D1Database, email: string): Promise<string> {
  const token = generateId(32)
  const expiresAt = Math.floor(Date.now() / 1000) + 3600

  await db
    .prepare(
      'INSERT INTO email_verification_tokens (token, email, type, expires_at) VALUES (?, ?, ?, ?)',
    )
    .bind(token, email, 'verify_email', expiresAt)
    .run()

  return token
}

async function getResetTokenRecord(db: D1Database, token: string) {
  const tokenRecord = await db
    .prepare('SELECT * FROM email_verification_tokens WHERE token = ? AND type = ?')
    .bind(token, 'reset_password')
    .first()

  if (!tokenRecord) {
    return null
  }

  const now = Math.floor(Date.now() / 1000)
  if (now > Number(tokenRecord.expires_at)) {
    await db.prepare('DELETE FROM email_verification_tokens WHERE token = ?').bind(token).run()
    return null
  }

  return tokenRecord
}

async function maybeCreateOpaqueRecordForLegacyPassword(
  c: AppContext,
  userId: string,
  password: string,
  existingOpaqueRecord: string | null,
) {
  if (existingOpaqueRecord) {
    return
  }

  try {
    const opaqueRegistrationRecord = await buildOpaqueRegistrationRecordFromPassword(
      getOpaqueServerSetup(c.env),
      userId,
      password,
    )

    await c.env.RUINABLA_DB.prepare(
      'UPDATE users SET opaque_registration_record = ?, updated_at = unixepoch() WHERE id = ?',
    )
      .bind(opaqueRegistrationRecord, userId)
      .run()
  } catch (error) {
    console.error('Failed to backfill OPAQUE record:', error)
  }
}

async function createPendingAuthResponse(
  db: D1Database,
  userId: string,
  durationDays: number,
  methods: TwoFactorMethods,
) {
  const pendingAuth = await createPendingAuthChallenge(db, userId, durationDays)

  return {
    requires2FA: true,
    pendingAuthId: pendingAuth.id,
    userId,
    methods,
  }
}

// Register new user through the legacy JSON endpoint.
auth.post('/register', async (c) => {
  const { email, password } = await c.req.json()

  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null
  if (!normalizedEmail || !password) {
    return c.json({ error: 'Email and password are required' }, 400)
  }

  if (password.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters' }, 400)
  }

  const existingUser = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(normalizedEmail)
    .first()

  if (existingUser) {
    return c.json({ error: 'Email already registered' }, 409)
  }

  try {
    const userId = generateId(16)
    const [passwordHash, opaqueRegistrationRecord] = await Promise.all([
      hashPassword(password),
      buildOpaqueRegistrationRecordFromPassword(getOpaqueServerSetup(c.env), userId, password),
    ])

    await c.env.RUINABLA_DB.prepare(
      `INSERT INTO users
         (id, email, password_hash, opaque_registration_record, email_verified, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(userId, normalizedEmail, passwordHash, opaqueRegistrationRecord, false, 'user')
      .run()

    const token = await createVerificationToken(c.env.RUINABLA_DB, normalizedEmail)
    await sendVerificationEmailSafely(c, normalizedEmail, token)

    return c.json({
      success: true,
      message: 'Registration successful. Please check your email to verify your account.',
      userId,
    })
  } catch (error) {
    console.error('Registration error:', error)
    return c.json({ error: 'Registration failed' }, 500)
  }
})

auth.post('/opaque/register/start', async (c) => {
  const { email, registrationRequest } = await c.req.json()
  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null

  if (!normalizedEmail || typeof registrationRequest !== 'string' || !registrationRequest) {
    return c.json({ error: 'Email and registration request are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)

  const existingUser = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(normalizedEmail)
    .first()

  if (existingUser) {
    return c.json({ error: 'Email already registered' }, 409)
  }

  try {
    const userId = generateId(16)
    const registrationResponse = await createOpaqueRegistrationResponse(
      getOpaqueServerSetup(c.env),
      userId,
      registrationRequest,
    )
    const attempt = await createOpaqueRegistrationAttempt(c.env.RUINABLA_DB, {
      userId,
      email: normalizedEmail,
      purpose: 'register',
      token: null,
    })

    return c.json({
      attemptId: attempt.id,
      registrationResponse,
    })
  } catch (error) {
    console.error('OPAQUE register start error:', error)
    return c.json({ error: 'Failed to start registration' }, 500)
  }
})

auth.post('/opaque/register/finish', async (c) => {
  const { attemptId, registrationRecord } = await c.req.json()

  if (
    typeof attemptId !== 'string' ||
    typeof registrationRecord !== 'string' ||
    !registrationRecord
  ) {
    return c.json({ error: 'Attempt ID and registration record are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)
  const attempt = await consumeOpaqueRegistrationAttempt(c.env.RUINABLA_DB, attemptId, 'register')

  if (!attempt) {
    return c.json({ error: 'Registration attempt not found or expired' }, 404)
  }

  const existingUser = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
    .bind(attempt.email)
    .first()

  if (existingUser) {
    return c.json({ error: 'Email already registered' }, 409)
  }

  try {
    await c.env.RUINABLA_DB.prepare(
      `INSERT INTO users
         (id, email, password_hash, opaque_registration_record, email_verified, role)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(attempt.userId, attempt.email, null, registrationRecord, false, 'user')
      .run()

    const token = await createVerificationToken(c.env.RUINABLA_DB, attempt.email)
    await sendVerificationEmailSafely(c, attempt.email, token)

    return c.json({
      success: true,
      userId: attempt.userId,
      message: 'Registration successful. Please check your email to verify your account.',
    })
  } catch (error) {
    console.error('OPAQUE register finish error:', error)
    return c.json({ error: 'Registration failed' }, 500)
  }
})

// Login through the legacy JSON endpoint.
auth.post('/login', async (c) => {
  const { email, password, remember } = await c.req.json()

  if (email === 'test@test.com' && password === 'testtest' && isDevelopmentRequest(c)) {
    const testId = 'test-user-id'

    await c.env.RUINABLA_DB.prepare(
      `INSERT INTO users (id, email, password_hash, email_verified, role)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET role = ?, email_verified = ?`,
    )
      .bind(testId, 'test@example.com', 'n/a', true, 'admin', 'admin', true)
      .run()

    const sessionId = await createSession(c.env.RUINABLA_DB, testId, 30 / 86400)

    return c.json({
      success: true,
      sessionId,
      user: {
        id: testId,
        email: 'test@example.com',
        role: 'admin',
      },
    })
  }

  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null
  if (!normalizedEmail || typeof password !== 'string' || !password) {
    return c.json({ error: 'Email and password are required' }, 400)
  }

  const user = await getUserByEmail(c.env.RUINABLA_DB, normalizedEmail)

  if (!user || !user.password_hash) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const isValid = await verifyPassword(password, user.password_hash)
  if (!isValid) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  await maybeCreateOpaqueRecordForLegacyPassword(
    c,
    user.id,
    password,
    user.opaque_registration_record,
  )

  const methods = await getTwoFactorMethods(c.env.RUINABLA_DB, user.id)
  const durationDays = getSessionDurationDays(Boolean(remember))

  if (methods.totp || methods.passkey) {
    return c.json(
      await createPendingAuthResponse(c.env.RUINABLA_DB, user.id, durationDays, methods),
    )
  }

  const sessionId = await createSession(c.env.RUINABLA_DB, user.id, durationDays)

  return c.json({
    success: true,
    sessionId,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  })
})

// Start sign-in with the krtl.net OpenID Connect provider.
auth.get('/krtl/start', async (c) => {
  const clientId = c.env.KRTL_CLIENT_ID
  const clientSecret = c.env.KRTL_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    return c.json({ error: 'KRTL login is not configured' }, 503)
  }

  const redirectPath = safeInternalRedirect(c.req.query('redirect'))
  await c.env.RUINABLA_DB.prepare(
    'DELETE FROM krtl_login_attempts WHERE expires_at <= unixepoch()',
  ).run()

  const { state, verifier, nonce } = await createKrtlLoginAttempt(c.env.RUINABLA_DB, redirectPath)
  const challenge = await base64UrlHash(verifier)
  const authorizationUrl = new URL(KRTL_AUTHORIZATION_ENDPOINT)
  authorizationUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: KRTL_REDIRECT_URI,
    response_type: 'code',
    scope: KRTL_SCOPES,
    state,
    nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }).toString()

  return c.redirect(authorizationUrl.toString(), 302)
})

// Start linking krtl.net to the currently authenticated local account.
auth.post('/krtl/link/start', requireAuth, async (c) => {
  const clientId = c.env.KRTL_CLIENT_ID
  const clientSecret = c.env.KRTL_CLIENT_SECRET
  if (!clientId || !clientSecret) {
    return c.json({ error: 'KRTL login is not configured' }, 503)
  }

  await c.env.RUINABLA_DB.prepare(
    'DELETE FROM krtl_login_attempts WHERE expires_at <= unixepoch()',
  ).run()
  const user = getAuthenticatedUser(c)
  const { state, verifier, nonce } = await createKrtlLinkAttempt(
    c.env.RUINABLA_DB,
    user.id,
    '/settings/accounts',
  )
  const authorizationUrl = new URL(KRTL_AUTHORIZATION_ENDPOINT)
  authorizationUrl.search = new URLSearchParams({
    client_id: clientId,
    redirect_uri: KRTL_REDIRECT_URI,
    response_type: 'code',
    scope: KRTL_SCOPES,
    state,
    nonce,
    code_challenge: await base64UrlHash(verifier),
    code_challenge_method: 'S256',
  }).toString()

  return c.json({ authorizationUrl: authorizationUrl.toString() })
})

// Complete the browser callback from https://shikoch.in/oidc/callback.
auth.post('/krtl/callback', async (c) => {
  const clientId = c.env.KRTL_CLIENT_ID
  const clientSecret = c.env.KRTL_CLIENT_SECRET
  if (!clientId || !clientSecret) return c.json({ error: 'KRTL login is not configured' }, 503)

  const body = await c.req.json<{ code?: unknown; state?: unknown }>().catch(() => ({}))
  const code = typeof body.code === 'string' ? body.code : ''
  const state = typeof body.state === 'string' ? body.state : ''
  if (!code || !state || code.length > 4096 || state.length > 256) {
    return c.json({ error: 'Authorization response is invalid' }, 400)
  }

  const attempt = await consumeKrtlLoginAttempt(c.env.RUINABLA_DB, state)
  if (!attempt) return c.json({ error: 'Authorization request expired' }, 400)

  try {
    const tokens = await exchangeKrtlCode(code, attempt.code_verifier, clientId, clientSecret)
    const claims = await verifyKrtlIdToken(tokens.id_token, attempt.nonce, clientId)
    const userInfo = await fetchKrtlUserInfo(tokens.access_token)
    if (typeof claims.sub !== 'string' || userInfo.sub !== claims.sub) {
      throw new Error('KRTL subject mismatch')
    }

    const rawEmail = typeof userInfo.email === 'string' ? userInfo.email : claims.email
    const email = typeof rawEmail === 'string' ? validateEmail(rawEmail) : null
    const emailVerified =
      userInfo.email_verified === true ||
      userInfo.email_verified === 1 ||
      userInfo.email_verified === 'true' ||
      claims.email_verified === true ||
      claims.email_verified === 1 ||
      claims.email_verified === 'true'
    if (!email || !emailVerified) {
      return c.json({ error: 'A verified krtl.net email is required' }, 403)
    }

    const existingExternal = await c.env.RUINABLA_DB.prepare(
      'SELECT user_id FROM external_accounts WHERE provider = ? AND subject = ?',
    )
      .bind('krtl', claims.sub)
      .first<{ user_id: string }>()

    if (attempt.mode === 'link') {
      if (!attempt.user_id) return c.json({ error: 'KRTL link request is invalid' }, 400)
      if (existingExternal && existingExternal.user_id !== attempt.user_id) {
        return c.json({ error: 'This krtl.net account is already connected to another user' }, 409)
      }

      if (existingExternal) {
        await c.env.RUINABLA_DB.prepare(
          'UPDATE external_accounts SET email = ?, updated_at = unixepoch() WHERE provider = ? AND subject = ?',
        )
          .bind(email, 'krtl', claims.sub)
          .run()
      } else {
        await c.env.RUINABLA_DB.prepare(
          'INSERT INTO external_accounts (provider, subject, user_id, email) VALUES (?, ?, ?, ?)',
        )
          .bind('krtl', claims.sub, attempt.user_id, email)
          .run()
      }

      return c.json({ success: true, linked: true, redirectPath: '/settings/accounts' })
    }

    let userId = existingExternal?.user_id
    if (!userId) {
      const existingUser = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
        .bind(email)
        .first<{ id: string }>()
      userId = existingUser?.id

      if (!userId) {
        userId = generateId(16)
        await c.env.RUINABLA_DB.prepare(
          `INSERT INTO users
             (id, email, password_hash, opaque_registration_record, email_verified, role)
           VALUES (?, ?, NULL, NULL, 1, 'user')`,
        )
          .bind(userId, email)
          .run()
      }

      await c.env.RUINABLA_DB.prepare(
        `INSERT INTO external_accounts (provider, subject, user_id, email)
         VALUES (?, ?, ?, ?)
         ON CONFLICT(provider, subject) DO UPDATE SET
           user_id = excluded.user_id, email = excluded.email, updated_at = unixepoch()`,
      )
        .bind('krtl', claims.sub, userId, email)
        .run()
    } else {
      await c.env.RUINABLA_DB.prepare(
        'UPDATE external_accounts SET email = ?, updated_at = unixepoch() WHERE provider = ? AND subject = ?',
      )
        .bind(email, 'krtl', claims.sub)
        .run()
    }

    const ticket = generateId(32)
    await c.env.RUINABLA_DB.prepare(
      `INSERT INTO auth_handoff_tokens (token_hash, user_id, redirect_path, expires_at)
       VALUES (?, ?, ?, ?)`,
    )
      .bind(
        await base64UrlHash(ticket),
        userId,
        safeInternalRedirect(attempt.redirect_path),
        Math.floor(Date.now() / 1000) + 300,
      )
      .run()

    return c.json({
      success: true,
      ticket,
      redirectPath: safeInternalRedirect(attempt.redirect_path),
    })
  } catch (error) {
    console.error('KRTL login callback failed:', error)
    return c.json({ error: 'KRTL login failed' }, 401)
  }
})

// Exchange the one-time browser handoff ticket for a local session.
auth.post('/krtl/complete', async (c) => {
  const { ticket } = await c.req.json<{ ticket?: unknown }>().catch(() => ({}))
  if (typeof ticket !== 'string' || !ticket || ticket.length > 128) {
    return c.json({ error: 'Login ticket is invalid' }, 400)
  }

  const handoff = await c.env.RUINABLA_DB.prepare(
    `DELETE FROM auth_handoff_tokens
     WHERE token_hash = ? AND expires_at > unixepoch()
     RETURNING user_id, redirect_path`,
  )
    .bind(await base64UrlHash(ticket))
    .first<{ user_id: string; redirect_path: string }>()
  if (!handoff) return c.json({ error: 'Login ticket is invalid or expired' }, 401)

  const user = await getUserById(c.env.RUINABLA_DB, handoff.user_id)
  if (!user) return c.json({ error: 'User not found' }, 404)

  const durationDays = getSessionDurationDays(false)
  const sessionId = await createSession(c.env.RUINABLA_DB, handoff.user_id, durationDays)
  return c.json({
    success: true,
    sessionId,
    redirectPath: safeInternalRedirect(handoff.redirect_path),
    user: { id: user.id, email: user.email, role: user.role },
  })
})

// Manage external login identities linked to the current account.
auth.get('/external-accounts', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const { results } = await c.env.RUINABLA_DB.prepare(
    `SELECT provider, subject, email, created_at, updated_at
       FROM external_accounts
      WHERE user_id = ?
      ORDER BY created_at ASC`,
  )
    .bind(user.id)
    .all()

  return c.json({
    accounts: results.map((account) => ({
      provider: account.provider as string,
      subject: account.subject as string,
      email: account.email as string | null,
      createdAt: Number(account.created_at),
      updatedAt: Number(account.updated_at),
    })),
  })
})

auth.delete('/external-accounts/:provider', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const session = getAuthenticatedSession(c)
  const provider = c.req.param('provider')
  if (provider !== 'krtl') return c.json({ error: 'Unsupported external account' }, 400)

  const localUser = await c.env.RUINABLA_DB.prepare(
    'SELECT password_hash, opaque_registration_record FROM users WHERE id = ?',
  )
    .bind(user.id)
    .first<{ password_hash: string | null; opaque_registration_record: string | null }>()
  const externalCount = await c.env.RUINABLA_DB.prepare(
    'SELECT COUNT(*) AS count FROM external_accounts WHERE user_id = ?',
  )
    .bind(user.id)
    .first<{ count: number }>()

  const hasLocalCredential = Boolean(
    localUser?.password_hash || localUser?.opaque_registration_record,
  )
  if (hasLocalCredential && !isRecentReauthenticationValid(session.reauthenticatedAt)) {
    return c.json(
      { error: 'Recent reauthentication is required to unlink an external account' },
      401,
    )
  }
  if (!hasLocalCredential && Number(externalCount?.count ?? 0) <= 1) {
    return c.json(
      { error: 'Set a local password before removing your only external login method' },
      409,
    )
  }

  const result = await c.env.RUINABLA_DB.prepare(
    'DELETE FROM external_accounts WHERE provider = ? AND user_id = ?',
  )
    .bind(provider, user.id)
    .run()
  if (!result.meta.changes) return c.json({ error: 'External account not found' }, 404)
  return c.json({ success: true })
})

// Permanently remove the authenticated user's account and its authentication artifacts.
auth.delete('/account', requireAuth, async (c) => {
  const user = getAuthenticatedUser(c)
  const session = getAuthenticatedSession(c)
  const body = await c.req.json<{ confirmation?: unknown }>().catch(() => ({}))
  if (body.confirmation !== 'DELETE') {
    return c.json({ error: 'Type DELETE to confirm account deletion' }, 400)
  }

  const localCredentials = await c.env.RUINABLA_DB.prepare(
    'SELECT password_hash, opaque_registration_record FROM users WHERE id = ?',
  )
    .bind(user.id)
    .first<{ password_hash: string | null; opaque_registration_record: string | null }>()
  if (
    (localCredentials?.password_hash || localCredentials?.opaque_registration_record) &&
    !isRecentReauthenticationValid(session.reauthenticatedAt)
  ) {
    return c.json(
      { error: 'Recent reauthentication is required before deleting your account' },
      401,
    )
  }

  const db = c.env.RUINABLA_DB
  const deletion = await db.batch([
    db.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM totp_secrets WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM passkeys WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM pending_auth_challenges WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM opaque_registration_attempts WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM opaque_login_attempts WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM email_verification_tokens WHERE email = ?').bind(user.email),
    db.prepare('DELETE FROM oidc_auth_requests WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM oidc_authorization_codes WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM oidc_access_tokens WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM oidc_clients WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM external_accounts WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM auth_handoff_tokens WHERE user_id = ?').bind(user.id),
    db.prepare('DELETE FROM users WHERE id = ?').bind(user.id),
  ])

  if (!deletion.at(-1)?.meta.changes) return c.json({ error: 'Account not found' }, 404)
  return c.json({ success: true })
})

auth.post('/opaque/login/start', async (c) => {
  const { email, startLoginRequest, remember } = await c.req.json()
  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null

  if (!normalizedEmail || typeof startLoginRequest !== 'string' || !startLoginRequest) {
    return c.json({ error: 'Email and login request are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)

  try {
    const user = await getUserByEmail(c.env.RUINABLA_DB, normalizedEmail)
    const hasOpaqueRecord = Boolean(user?.opaque_registration_record)
    const loginResponse = await createOpaqueLoginResponse(
      getOpaqueServerSetup(c.env),
      user?.id ?? `missing:${normalizedEmail}`,
      user?.opaque_registration_record,
      startLoginRequest,
    )
    const attempt = await createOpaqueLoginAttempt(c.env.RUINABLA_DB, {
      userId: user?.id ?? null,
      purpose: 'login',
      serverLoginState: loginResponse.serverLoginState,
      hasOpaqueRecord,
      sessionDurationDays: getSessionDurationDays(Boolean(remember)),
    })

    return c.json({
      attemptId: attempt.id,
      loginResponse: loginResponse.loginResponse,
    })
  } catch (error) {
    console.error('OPAQUE login start error:', error)
    return c.json({ error: 'Failed to start login' }, 500)
  }
})

auth.post('/opaque/login/finish', async (c) => {
  const { attemptId, finishLoginRequest } = await c.req.json()

  if (
    typeof attemptId !== 'string' ||
    typeof finishLoginRequest !== 'string' ||
    !finishLoginRequest
  ) {
    return c.json({ error: 'Attempt ID and login finish request are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)
  const attempt = await consumeOpaqueLoginAttempt(c.env.RUINABLA_DB, attemptId, 'login')

  if (!attempt || !attempt.userId || !attempt.hasOpaqueRecord) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  try {
    await finishOpaqueLogin(attempt.serverLoginState, finishLoginRequest)
  } catch (error) {
    console.error('OPAQUE login finish error:', error)
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const user = await getUserById(c.env.RUINABLA_DB, attempt.userId)
  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  const methods = await getTwoFactorMethods(c.env.RUINABLA_DB, attempt.userId)

  if (methods.totp || methods.passkey) {
    return c.json(
      await createPendingAuthResponse(
        c.env.RUINABLA_DB,
        attempt.userId,
        attempt.sessionDurationDays ?? getSessionDurationDays(false),
        methods,
      ),
    )
  }

  const sessionId = await createSession(
    c.env.RUINABLA_DB,
    attempt.userId,
    attempt.sessionDurationDays ?? getSessionDurationDays(false),
  )

  return c.json({
    success: true,
    sessionId,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  })
})

auth.post('/opaque/reauth/start', requireAuth, async (c) => {
  const session = getAuthenticatedSession(c)
  const { startLoginRequest } = await c.req.json()

  if (typeof startLoginRequest !== 'string' || !startLoginRequest) {
    return c.json({ error: 'Login request is required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)

  const user = await c.env.RUINABLA_DB.prepare(
    'SELECT opaque_registration_record FROM users WHERE id = ?',
  )
    .bind(session.userId)
    .first()

  const record = (user?.opaque_registration_record as string | null) ?? null
  if (!record) {
    return c.json({ error: 'OPAQUE reauthentication is unavailable. Please log in again.' }, 409)
  }

  try {
    const { loginResponse, serverLoginState } = await createOpaqueLoginResponse(
      getOpaqueServerSetup(c.env),
      session.userId,
      record,
      startLoginRequest,
    )
    const attempt = await createOpaqueLoginAttempt(c.env.RUINABLA_DB, {
      userId: session.userId,
      purpose: 'reauth',
      serverLoginState,
      hasOpaqueRecord: true,
      sessionDurationDays: null,
    })

    return c.json({
      attemptId: attempt.id,
      loginResponse,
    })
  } catch (error) {
    console.error('OPAQUE reauth start error:', error)
    return c.json({ error: 'Failed to start reauthentication' }, 500)
  }
})

auth.post('/opaque/reauth/finish', requireAuth, async (c) => {
  const session = getAuthenticatedSession(c)
  const { attemptId, finishLoginRequest } = await c.req.json()

  if (
    typeof attemptId !== 'string' ||
    typeof finishLoginRequest !== 'string' ||
    !finishLoginRequest
  ) {
    return c.json({ error: 'Attempt ID and login finish request are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)
  const attempt = await consumeOpaqueLoginAttempt(c.env.RUINABLA_DB, attemptId, 'reauth')

  if (!attempt || attempt.userId !== session.userId || !attempt.hasOpaqueRecord) {
    return c.json({ error: 'Invalid reauthentication attempt' }, 401)
  }

  try {
    await finishOpaqueLogin(attempt.serverLoginState, finishLoginRequest)
    await markSessionReauthenticated(c.env.RUINABLA_DB, session.id)

    return c.json({
      success: true,
      reauthExpiresAt: getReauthExpiresAt(),
    })
  } catch (error) {
    console.error('OPAQUE reauth finish error:', error)
    return c.json({ error: 'Invalid credentials' }, 401)
  }
})

// Verify TOTP and complete login.
auth.post('/verify-totp', async (c) => {
  const { pendingAuthId, userId, totpCode, remember } = await c.req.json()

  if (!totpCode) {
    return c.json({ error: 'TOTP code is required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)

  let resolvedUserId: string | null = typeof userId === 'string' ? userId : null
  let durationDays = getSessionDurationDays(Boolean(remember))

  if (typeof pendingAuthId === 'string' && pendingAuthId) {
    const pendingAuth = await consumePendingAuthChallenge(c.env.RUINABLA_DB, pendingAuthId)
    if (!pendingAuth) {
      return c.json({ error: 'Authentication challenge expired' }, 401)
    }
    resolvedUserId = pendingAuth.userId
    durationDays = pendingAuth.sessionDurationDays
  }

  if (!resolvedUserId) {
    return c.json({ error: 'User ID or pending auth ID is required' }, 400)
  }

  const totpRecord = await c.env.RUINABLA_DB.prepare(
    'SELECT secret, backup_codes FROM totp_secrets WHERE user_id = ? AND enabled = 1',
  )
    .bind(resolvedUserId)
    .first()

  if (!totpRecord) {
    return c.json({ error: 'TOTP not enabled for this user' }, 400)
  }

  const { verifyTOTP } = await import('../utils/crypto')
  const isValid = await verifyTOTP(totpRecord.secret as string, totpCode)

  if (!isValid) {
    const backupCodes = totpRecord.backup_codes ? JSON.parse(totpRecord.backup_codes as string) : []
    const backupCodeIndex = backupCodes.indexOf(totpCode.toUpperCase())

    if (backupCodeIndex === -1) {
      return c.json({ error: 'Invalid TOTP code' }, 401)
    }

    backupCodes.splice(backupCodeIndex, 1)
    await c.env.RUINABLA_DB.prepare('UPDATE totp_secrets SET backup_codes = ? WHERE user_id = ?')
      .bind(JSON.stringify(backupCodes), resolvedUserId)
      .run()
  }

  const user = await getUserById(c.env.RUINABLA_DB, resolvedUserId)
  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  const sessionId = await createSession(c.env.RUINABLA_DB, resolvedUserId, durationDays)

  return c.json({
    success: true,
    sessionId,
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  })
})

// Logout.
auth.post('/logout', requireAuth, async (c) => {
  const session = getAuthenticatedSession(c)
  await invalidateSession(c.env.RUINABLA_DB, session.id)
  return c.json({ success: true })
})

// Get current user.
auth.get('/me', requireAuth, async (c) => {
  const session = getAuthenticatedSession(c)
  const user = await getUserById(c.env.RUINABLA_DB, session.userId)

  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  return c.json({
    user: {
      id: user.id,
      email: user.email,
      role: user.role,
    },
  })
})

// Verify email.
auth.post('/verify-email', async (c) => {
  const { token } = await c.req.json()

  if (!token) {
    return c.json({ error: 'Token is required' }, 400)
  }

  try {
    const tokenRecord = await c.env.RUINABLA_DB.prepare(
      'SELECT * FROM email_verification_tokens WHERE token = ? AND type = ?',
    )
      .bind(token, 'verify_email')
      .first()

    if (!tokenRecord) {
      return c.json({ error: 'Invalid or expired token' }, 404)
    }

    const now = Math.floor(Date.now() / 1000)
    if (now > Number(tokenRecord.expires_at)) {
      await c.env.RUINABLA_DB.prepare('DELETE FROM email_verification_tokens WHERE token = ?')
        .bind(token)
        .run()
      return c.json({ error: 'Token has expired' }, 400)
    }

    await c.env.RUINABLA_DB.prepare('UPDATE users SET email_verified = ? WHERE email = ?')
      .bind(true, tokenRecord.email)
      .run()
    await c.env.RUINABLA_DB.prepare('DELETE FROM email_verification_tokens WHERE token = ?')
      .bind(token)
      .run()

    const user = await c.env.RUINABLA_DB.prepare(
      'SELECT id, email, role FROM users WHERE email = ?',
    )
      .bind(tokenRecord.email as string)
      .first()

    if (!user) {
      return c.json({ error: 'User not found' }, 404)
    }

    const sessionId = await createSession(
      c.env.RUINABLA_DB,
      user.id as string,
      getSessionDurationDays(false),
    )

    return c.json({
      success: true,
      message: 'Email verified successfully',
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
      },
    })
  } catch (error) {
    console.error('Email verification error:', error)
    return c.json({ error: 'Verification failed' }, 500)
  }
})

// Resend verification email.
auth.post('/resend-verification', async (c) => {
  const { email } = await c.req.json()
  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null

  if (!normalizedEmail) {
    return c.json({ error: 'Email is required' }, 400)
  }

  try {
    const user = await c.env.RUINABLA_DB.prepare(
      'SELECT id, email_verified FROM users WHERE email = ?',
    )
      .bind(normalizedEmail)
      .first()

    if (!user) {
      return c.json({ error: 'User not found' }, 404)
    }

    if (user.email_verified) {
      return c.json({ error: 'Email already verified' }, 400)
    }

    await c.env.RUINABLA_DB.prepare(
      'DELETE FROM email_verification_tokens WHERE email = ? AND type = ?',
    )
      .bind(normalizedEmail, 'verify_email')
      .run()

    const token = await createVerificationToken(c.env.RUINABLA_DB, normalizedEmail)
    const resend = createResendClient(c.env.RESEND_API_KEY)
    const baseUrl = new URL(c.req.url).origin
    await sendVerificationEmail(resend, normalizedEmail, token, baseUrl)

    return c.json({
      success: true,
      message: 'Verification email sent',
    })
  } catch (error) {
    console.error('Resend verification error:', error)
    return c.json({ error: 'Failed to resend verification email' }, 500)
  }
})

// Request password reset.
auth.post('/request-reset', async (c) => {
  const { email } = await c.req.json()
  const normalizedEmail = typeof email === 'string' ? validateEmail(email) : null

  if (!normalizedEmail) {
    return c.json({ error: 'Email is required' }, 400)
  }

  try {
    const user = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
      .bind(normalizedEmail)
      .first()

    if (!user) {
      return c.json({
        success: true,
        message: 'If the email exists, a reset link has been sent',
      })
    }

    await c.env.RUINABLA_DB.prepare(
      'DELETE FROM email_verification_tokens WHERE email = ? AND type = ?',
    )
      .bind(normalizedEmail, 'reset_password')
      .run()

    const token = generateId(32)
    const expiresAt = Math.floor(Date.now() / 1000) + 3600

    await c.env.RUINABLA_DB.prepare(
      'INSERT INTO email_verification_tokens (token, email, type, expires_at) VALUES (?, ?, ?, ?)',
    )
      .bind(token, normalizedEmail, 'reset_password', expiresAt)
      .run()

    const resend = createResendClient(c.env.RESEND_API_KEY)
    const baseUrl = new URL(c.req.url).origin
    await sendPasswordResetEmail(resend, normalizedEmail, token, baseUrl)

    return c.json({
      success: true,
      message: 'If the email exists, a reset link has been sent',
    })
  } catch (error) {
    console.error('Request reset error:', error)
    return c.json({ error: 'Failed to send reset email' }, 500)
  }
})

auth.post('/opaque/reset/start', async (c) => {
  const { token, registrationRequest } = await c.req.json()

  if (
    typeof token !== 'string' ||
    typeof registrationRequest !== 'string' ||
    !registrationRequest
  ) {
    return c.json({ error: 'Token and registration request are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)

  const tokenRecord = await getResetTokenRecord(c.env.RUINABLA_DB, token)
  if (!tokenRecord) {
    return c.json({ error: 'Invalid or expired token' }, 404)
  }

  const user = await c.env.RUINABLA_DB.prepare('SELECT id, email FROM users WHERE email = ?')
    .bind(tokenRecord.email as string)
    .first()

  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  try {
    const registrationResponse = await createOpaqueRegistrationResponse(
      getOpaqueServerSetup(c.env),
      user.id as string,
      registrationRequest,
    )
    const attempt = await createOpaqueRegistrationAttempt(c.env.RUINABLA_DB, {
      userId: user.id as string,
      email: user.email as string,
      purpose: 'reset_password',
      token,
    })

    return c.json({
      attemptId: attempt.id,
      registrationResponse,
    })
  } catch (error) {
    console.error('OPAQUE reset start error:', error)
    return c.json({ error: 'Failed to start password reset' }, 500)
  }
})

auth.post('/opaque/reset/finish', async (c) => {
  const { attemptId, registrationRecord } = await c.req.json()

  if (
    typeof attemptId !== 'string' ||
    typeof registrationRecord !== 'string' ||
    !registrationRecord
  ) {
    return c.json({ error: 'Attempt ID and registration record are required' }, 400)
  }

  await cleanupOpaqueArtifacts(c.env.RUINABLA_DB)
  const attempt = await consumeOpaqueRegistrationAttempt(
    c.env.RUINABLA_DB,
    attemptId,
    'reset_password',
  )

  if (!attempt || !attempt.token) {
    return c.json({ error: 'Reset attempt not found or expired' }, 404)
  }

  const tokenRecord = await getResetTokenRecord(c.env.RUINABLA_DB, attempt.token)
  if (!tokenRecord) {
    return c.json({ error: 'Invalid or expired token' }, 404)
  }

  try {
    await c.env.RUINABLA_DB.prepare(
      `UPDATE users
       SET password_hash = ?, opaque_registration_record = ?, updated_at = unixepoch()
       WHERE id = ?`,
    )
      .bind(null, registrationRecord, attempt.userId)
      .run()
    await c.env.RUINABLA_DB.prepare('DELETE FROM email_verification_tokens WHERE token = ?')
      .bind(attempt.token)
      .run()
    await c.env.RUINABLA_DB.prepare('DELETE FROM sessions WHERE user_id = ?')
      .bind(attempt.userId)
      .run()

    return c.json({
      success: true,
      message: 'Password reset successfully',
    })
  } catch (error) {
    console.error('OPAQUE reset finish error:', error)
    return c.json({ error: 'Failed to reset password' }, 500)
  }
})

// Reset password through the legacy JSON endpoint.
auth.post('/reset-password', async (c) => {
  const { token, newPassword } = await c.req.json()

  if (!token || !newPassword) {
    return c.json({ error: 'Token and new password are required' }, 400)
  }

  if (newPassword.length < 8) {
    return c.json({ error: 'Password must be at least 8 characters' }, 400)
  }

  try {
    const tokenRecord = await getResetTokenRecord(c.env.RUINABLA_DB, token)
    if (!tokenRecord) {
      return c.json({ error: 'Invalid or expired token' }, 404)
    }

    const user = await c.env.RUINABLA_DB.prepare('SELECT id FROM users WHERE email = ?')
      .bind(tokenRecord.email as string)
      .first()

    if (!user) {
      return c.json({ error: 'User not found' }, 404)
    }

    const [passwordHash, opaqueRegistrationRecord] = await Promise.all([
      hashPassword(newPassword),
      buildOpaqueRegistrationRecordFromPassword(
        getOpaqueServerSetup(c.env),
        user.id as string,
        newPassword,
      ),
    ])

    await c.env.RUINABLA_DB.prepare(
      `UPDATE users
       SET password_hash = ?, opaque_registration_record = ?, updated_at = unixepoch()
       WHERE email = ?`,
    )
      .bind(passwordHash, opaqueRegistrationRecord, tokenRecord.email)
      .run()
    await c.env.RUINABLA_DB.prepare('DELETE FROM email_verification_tokens WHERE token = ?')
      .bind(token)
      .run()
    await c.env.RUINABLA_DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id).run()

    return c.json({
      success: true,
      message: 'Password reset successfully',
    })
  } catch (error) {
    console.error('Reset password error:', error)
    return c.json({ error: 'Failed to reset password' }, 500)
  }
})

export default auth
