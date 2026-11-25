import { beforeEach, describe, expect, it, vi } from 'vitest'

const krtlMocks = vi.hoisted(() => ({
  consumeKrtlLoginAttempt: vi.fn(),
  exchangeKrtlCode: vi.fn(),
  fetchKrtlUserInfo: vi.fn(),
  verifyKrtlIdToken: vi.fn(),
}))

vi.mock('../utils/krtl', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../utils/krtl')>()
  return { ...actual, ...krtlMocks }
})

import auth from './auth'

function createDb(options: { existingExternalUserId?: string | null } = {}) {
  const statements: Array<{ sql: string; values: unknown[] }> = []
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
              session_user_id: 'current-user',
              expires_at: Math.floor(Date.now() / 1000) + 3600,
              reauthenticated_at: null,
              user_id: 'current-user',
              email: 'local@example.com',
              role: 'user',
            }
          }
          if (sql.includes('DELETE FROM krtl_login_attempts')) {
            return {
              code_verifier: 'pkce-verifier',
              nonce: 'expected-nonce',
              redirect_path: '/settings/accounts',
              expires_at: Math.floor(Date.now() / 1000) + 300,
            }
          }
          if (sql.includes('SELECT user_id FROM external_accounts')) {
            return options.existingExternalUserId
              ? { user_id: options.existingExternalUserId }
              : null
          }
          if (sql.includes('SELECT id FROM users WHERE email = ?')) return null
          return null
        },
        async run() {
          statements.push({ sql, values })
          return { meta: { changes: 1 } }
        },
      }
      return statement
    },
  }
  return { db, statements }
}

describe('KRTL first-login account provisioning', () => {
  beforeEach(() => {
    krtlMocks.consumeKrtlLoginAttempt.mockReset()
    krtlMocks.exchangeKrtlCode.mockReset()
    krtlMocks.fetchKrtlUserInfo.mockReset()
    krtlMocks.verifyKrtlIdToken.mockReset()
    krtlMocks.consumeKrtlLoginAttempt.mockResolvedValue({
      code_verifier: 'pkce-verifier',
      nonce: 'expected-nonce',
      redirect_path: '/settings/accounts',
      expires_at: Math.floor(Date.now() / 1000) + 300,
    })
    krtlMocks.exchangeKrtlCode.mockResolvedValue({
      access_token: 'provider-access-token',
      id_token: 'signed-id-token',
    })
    krtlMocks.verifyKrtlIdToken.mockResolvedValue({
      sub: 'krtl-subject-1',
      email: 'new-user@example.com',
      email_verified: true,
    })
    krtlMocks.fetchKrtlUserInfo.mockResolvedValue({
      sub: 'krtl-subject-1',
      email: 'new-user@example.com',
      email_verified: true,
    })
  })

  it('creates a local account and binds the verified provider identity on first login', async () => {
    const { db, statements } = createDb()
    const response = await auth.request(
      '/krtl/callback',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'authorization-code', state: 'valid-state' }),
      },
      {
        RUINABLA_DB: db,
        KRTL_CLIENT_ID: 'client-id',
        KRTL_CLIENT_SECRET: 'client-secret',
      } as never,
    )
    const result = (await response.json()) as {
      success: boolean
      ticket: string
      redirectPath: string
    }

    expect(response.status).toBe(200)
    expect(result.success).toBe(true)
    expect(result.ticket).toBeTruthy()
    expect(result.redirectPath).toBe('/settings/accounts')
    expect(
      statements.some(
        ({ sql, values }) =>
          sql.includes('INSERT INTO users') &&
          values[1] === 'new-user@example.com' &&
          sql.includes("VALUES (?, ?, NULL, NULL, 1, 'user')"),
      ),
    ).toBe(true)
    expect(
      statements.some(
        ({ sql, values }) =>
          sql.includes('INSERT INTO external_accounts') &&
          values[0] === 'krtl' &&
          values[1] === 'krtl-subject-1' &&
          values[3] === 'new-user@example.com',
      ),
    ).toBe(true)
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO auth_handoff_tokens'))).toBe(true)
  })

  it('does not provision an account when the provider email is not verified', async () => {
    krtlMocks.verifyKrtlIdToken.mockResolvedValue({
      sub: 'krtl-subject-2',
      email: 'unverified@example.com',
      email_verified: false,
    })
    krtlMocks.fetchKrtlUserInfo.mockResolvedValue({
      sub: 'krtl-subject-2',
      email: 'unverified@example.com',
      email_verified: false,
    })
    const { db, statements } = createDb()
    const response = await auth.request(
      '/krtl/callback',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'authorization-code', state: 'valid-state' }),
      },
      {
        RUINABLA_DB: db,
        KRTL_CLIENT_ID: 'client-id',
        KRTL_CLIENT_SECRET: 'client-secret',
      } as never,
    )

    expect(response.status).toBe(403)
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO users'))).toBe(false)
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO external_accounts'))).toBe(false)
  })

  it('starts account linking only for an authenticated user and returns an S256 authorization URL', async () => {
    const { db } = createDb()
    const response = await auth.request(
      '/krtl/link/start',
      { method: 'POST', headers: { Authorization: 'Bearer session-1' } },
      {
        RUINABLA_DB: db,
        KRTL_CLIENT_ID: 'client-id',
        KRTL_CLIENT_SECRET: 'client-secret',
      } as never,
    )
    const result = (await response.json()) as { authorizationUrl: string }
    const authorizationUrl = new URL(result.authorizationUrl)

    expect(response.status).toBe(200)
    expect(authorizationUrl.origin).toBe('https://krtl.net')
    expect(authorizationUrl.searchParams.get('client_id')).toBe('client-id')
    expect(authorizationUrl.searchParams.get('redirect_uri')).toBe(
      'https://shikoch.in/oidc/callback',
    )
    expect(authorizationUrl.searchParams.get('code_challenge_method')).toBe('S256')
    expect(authorizationUrl.searchParams.get('state')).toBeTruthy()
    expect(authorizationUrl.searchParams.get('nonce')).toBeTruthy()
  })

  it('links a provider identity to the initiating user without issuing a login ticket', async () => {
    krtlMocks.consumeKrtlLoginAttempt.mockResolvedValue({
      code_verifier: 'pkce-verifier',
      nonce: 'expected-nonce',
      redirect_path: '/settings/accounts',
      expires_at: Math.floor(Date.now() / 1000) + 300,
      mode: 'link',
      user_id: 'current-user',
    })
    const { db, statements } = createDb()
    const response = await auth.request(
      '/krtl/callback',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'authorization-code', state: 'valid-state' }),
      },
      {
        RUINABLA_DB: db,
        KRTL_CLIENT_ID: 'client-id',
        KRTL_CLIENT_SECRET: 'client-secret',
      } as never,
    )
    const result = (await response.json()) as Record<string, unknown>

    expect(response.status).toBe(200)
    expect(result).toMatchObject({
      success: true,
      linked: true,
      redirectPath: '/settings/accounts',
    })
    expect(result).not.toHaveProperty('ticket')
    expect(
      statements.some(
        ({ sql, values }) =>
          sql.includes('INSERT INTO external_accounts') &&
          values[0] === 'krtl' &&
          values[1] === 'krtl-subject-1' &&
          values[2] === 'current-user',
      ),
    ).toBe(true)
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO users'))).toBe(false)
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO auth_handoff_tokens'))).toBe(
      false,
    )
  })

  it('refuses to link a provider identity already owned by another user', async () => {
    krtlMocks.consumeKrtlLoginAttempt.mockResolvedValue({
      code_verifier: 'pkce-verifier',
      nonce: 'expected-nonce',
      redirect_path: '/settings/accounts',
      expires_at: Math.floor(Date.now() / 1000) + 300,
      mode: 'link',
      user_id: 'current-user',
    })
    const { db, statements } = createDb({ existingExternalUserId: 'other-user' })
    const response = await auth.request(
      '/krtl/callback',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code: 'authorization-code', state: 'valid-state' }),
      },
      {
        RUINABLA_DB: db,
        KRTL_CLIENT_ID: 'client-id',
        KRTL_CLIENT_SECRET: 'client-secret',
      } as never,
    )

    expect(response.status).toBe(409)
    expect(await response.json()).toMatchObject({
      error: 'This krtl.net account is already connected to another user',
    })
    expect(statements.some(({ sql }) => sql.includes('INSERT INTO external_accounts'))).toBe(false)
  })
})
