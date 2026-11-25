import { beforeEach, describe, expect, it, vi } from 'vitest'

const krtlMocks = vi.hoisted(() => ({
  consumeKrtlLoginAttempt: vi.fn(),
  exchangeKrtlCode: vi.fn(),
  fetchKrtlUserInfo: vi.fn(),
  verifyKrtlIdToken: vi.fn(),
}))

vi.mock('../utils/krtl', async () => {
  const actual = await vi.importActual<typeof import('../utils/krtl')>('../utils/krtl')
  return { ...actual, ...krtlMocks }
})

import auth from './auth'

function createDb(
  options: {
    reauthenticatedAt?: number | null
    credentials?: { password_hash: string | null; opaque_registration_record: string | null }
  } = {},
) {
  const operations: Array<{ sql: string; values: unknown[] }> = []
  let batchCalls = 0
  const user = { id: 'user-1', email: 'member@example.com', role: 'user' }
  const db = {
    prepare(sql: string) {
      let values: unknown[] = []
      const statement = {
        sql,
        get values() {
          return values
        },
        bind(...nextValues: unknown[]) {
          values = nextValues
          return statement
        },
        async first() {
          if (sql.includes('FROM sessions s')) {
            return {
              session_id: 'session-1',
              session_user_id: user.id,
              expires_at: Math.floor(Date.now() / 1000) + 3600,
              reauthenticated_at: options.reauthenticatedAt ?? null,
              user_id: user.id,
              email: user.email,
              role: user.role,
            }
          }
          if (sql.startsWith('SELECT password_hash, opaque_registration_record FROM users')) {
            return options.credentials ?? { password_hash: null, opaque_registration_record: null }
          }
          if (sql.startsWith('DELETE FROM krtl_login_attempts')) {
            return {
              code_verifier: 'code-verifier',
              nonce: 'login-nonce',
              redirect_path: '/settings',
            }
          }
          if (sql.startsWith('SELECT user_id FROM external_accounts')) return null
          if (sql.startsWith('SELECT id FROM users WHERE email = ?')) return null
          if (sql.startsWith('SELECT id, email, role FROM users WHERE id = ?')) return user
          return null
        },
        async all() {
          return { results: [] }
        },
        async run() {
          operations.push({ sql, values })
          return { meta: { changes: 1 } }
        },
      }
      return statement
    },
    async batch(statements: Array<{ sql: string; values: unknown[] }>) {
      batchCalls++
      for (const statement of statements) {
        operations.push({ sql: statement.sql, values: statement.values })
      }
      return statements.map((_, index) => ({
        meta: { changes: index === statements.length - 1 ? 1 : 0 },
      }))
    },
  }
  return {
    db,
    operations,
    get batchCalls() {
      return batchCalls
    },
  }
}

function bindings(db: unknown) {
  return {
    RUINABLA_DB: db,
    KRTL_CLIENT_ID: 'client-id',
    KRTL_CLIENT_SECRET: 'client-secret',
  } as never
}

function makeRequest(path: string, body: unknown, method = 'POST') {
  const options: RequestInit = {
    method,
    headers: {
      Authorization: 'Bearer session-1',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  }
  return new Request(`https://shikoch.in${path}`, options)
}

describe('account deletion and krtl account creation', () => {
  beforeEach(() => {
    krtlMocks.consumeKrtlLoginAttempt.mockResolvedValue({
      code_verifier: 'code-verifier',
      nonce: 'login-nonce',
      redirect_path: '/settings',
    })
    krtlMocks.exchangeKrtlCode.mockResolvedValue({
      access_token: 'provider-access-token',
      id_token: 'id-token',
    })
    krtlMocks.verifyKrtlIdToken.mockResolvedValue({
      sub: 'provider-subject',
      email: 'new@example.com',
      email_verified: true,
    })
    krtlMocks.fetchKrtlUserInfo.mockResolvedValue({
      sub: 'provider-subject',
      email: 'new@example.com',
      email_verified: true,
    })
  })

  it('creates a local account when a verified krtl identity has no existing account', async () => {
    const { db, operations } = createDb()
    const response = await auth.request(
      makeRequest('/krtl/callback', { code: 'authorization-code', state: 'state-token' }),
      undefined,
      bindings(db),
    )
    const result = (await response.json()) as { success: boolean; ticket: string }

    expect(response.status).toBe(200)
    expect(result.success).toBe(true)
    expect(result.ticket).toBeTruthy()
    expect(
      operations.some(
        ({ sql, values }) => sql.startsWith('INSERT INTO users') && values[1] === 'new@example.com',
      ),
    ).toBe(true)
    expect(operations.some(({ sql }) => sql.startsWith('INSERT INTO external_accounts'))).toBe(true)
  })

  it('requires the explicit deletion phrase before deleting account data', async () => {
    const { db, batchCalls } = createDb()
    const response = await auth.request(
      makeRequest('/account', { confirmation: 'delete' }, 'DELETE'),
      undefined,
      bindings(db),
    )

    expect(response.status).toBe(400)
    expect(batchCalls).toBe(0)
  })

  it('requires recent reauthentication when local credentials exist', async () => {
    const { db, batchCalls } = createDb({
      credentials: { password_hash: 'hash', opaque_registration_record: 'record' },
      reauthenticatedAt: null,
    })
    const response = await auth.request(
      makeRequest('/account', { confirmation: 'DELETE' }, 'DELETE'),
      undefined,
      bindings(db),
    )

    expect(response.status).toBe(401)
    expect(batchCalls).toBe(0)
  })

  it('deletes only the authenticated OAuth-only account after typed confirmation', async () => {
    const { db, operations } = createDb()
    const response = await auth.request(
      makeRequest('/account', { confirmation: 'DELETE' }, 'DELETE'),
      undefined,
      bindings(db),
    )

    expect(response.status).toBe(200)
    expect(await response.json()).toMatchObject({ success: true })
    expect(operations.at(-1)).toMatchObject({
      sql: 'DELETE FROM users WHERE id = ?',
      values: ['user-1'],
    })
    expect(
      operations.some(({ sql }) => sql.includes('DELETE FROM sessions WHERE user_id = ?')),
    ).toBe(true)
    expect(
      operations.some(({ sql }) => sql.includes('DELETE FROM external_accounts WHERE user_id = ?')),
    ).toBe(true)
  })
})
