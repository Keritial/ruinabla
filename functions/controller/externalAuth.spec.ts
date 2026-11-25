import { describe, expect, it } from 'vitest'
import auth from './auth'

type UserRow = { id: string; email: string; role: string }

function createDb(
  options: {
    reauthenticatedAt?: number | null
    credentials?: { password_hash: string | null; opaque_registration_record: string | null }
    externalCount?: number
    externalAccounts?: Array<Record<string, unknown>>
  } = {},
) {
  const runs: Array<{ sql: string; values: unknown[] }> = []
  const prepared: string[] = []
  const user: UserRow = { id: 'user-1', email: 'linked@example.com', role: 'user' }
  const db = {
    prepare(sql: string) {
      let values: unknown[] = []
      prepared.push(sql)
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
              expires_at: Math.floor(Date.now() / 1000) + 3600,
              reauthenticated_at: options.reauthenticatedAt ?? null,
              user_id: user.id,
              email: user.email,
              role: user.role,
            }
          }
          if (sql.includes('DELETE FROM auth_handoff_tokens')) {
            return { user_id: user.id, redirect_path: '/settings/security' }
          }
          if (sql.includes('SELECT id, email, role FROM users WHERE id = ?')) return user
          if (sql.includes('SELECT password_hash, opaque_registration_record FROM users')) {
            return options.credentials ?? { password_hash: null, opaque_registration_record: null }
          }
          if (sql.includes('SELECT COUNT(*) AS count FROM external_accounts')) {
            return { count: options.externalCount ?? 1 }
          }
          return null
        },
        async all() {
          return { results: options.externalAccounts ?? [] }
        },
        async run() {
          runs.push({ sql, values })
          return { meta: { changes: 1 } }
        },
      }
      return statement
    },
  }
  return { db, prepared, runs }
}

function bindings(db: unknown) {
  return { RUINABLA_DB: db } as never
}

describe('external authentication routes', () => {
  it('completes krtl sign-in without invoking local TOTP or Passkey challenges', async () => {
    const { db, prepared } = createDb()
    const response = await auth.request(
      '/krtl/complete',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ticket: 'one-time-ticket' }),
      },
      bindings(db),
    )
    const data = (await response.json()) as { success: boolean; sessionId: string }

    expect(response.status).toBe(200)
    expect(data.success).toBe(true)
    expect(data.sessionId).toBeTruthy()
    expect(prepared.some((sql) => sql.includes('FROM totp_secrets'))).toBe(false)
    expect(prepared.some((sql) => sql.includes('FROM passkeys'))).toBe(false)
  })

  it('lists only the authenticated user external account fields', async () => {
    const { db } = createDb({
      externalAccounts: [
        {
          provider: 'krtl',
          subject: 'subject-1',
          email: 'linked@example.com',
          created_at: 123,
          updated_at: 456,
          user_id: 'user-1',
        },
      ],
    })
    const response = await auth.request(
      '/external-accounts',
      { headers: { Authorization: 'Bearer session-1' } },
      bindings(db),
    )
    const data = (await response.json()) as { accounts: Array<Record<string, unknown>> }

    expect(response.status).toBe(200)
    expect(data.accounts).toEqual([
      {
        provider: 'krtl',
        subject: 'subject-1',
        email: 'linked@example.com',
        createdAt: 123,
        updatedAt: 456,
      },
    ])
  })

  it('requires recent reauthentication before unlinking when local credentials exist', async () => {
    const { db, runs } = createDb({
      credentials: { password_hash: 'hash', opaque_registration_record: 'opaque-record' },
      reauthenticatedAt: null,
    })
    const response = await auth.request(
      '/external-accounts/krtl',
      { method: 'DELETE', headers: { Authorization: 'Bearer session-1' } },
      bindings(db),
    )

    expect(response.status).toBe(401)
    expect(runs.some(({ sql }) => sql.startsWith('DELETE FROM external_accounts'))).toBe(false)
  })

  it('prevents unlinking the sole login method when no local credential exists', async () => {
    const { db, runs } = createDb({
      credentials: { password_hash: null, opaque_registration_record: null },
      externalCount: 1,
    })
    const response = await auth.request(
      '/external-accounts/krtl',
      { method: 'DELETE', headers: { Authorization: 'Bearer session-1' } },
      bindings(db),
    )
    const data = await response.json()

    expect(response.status).toBe(409)
    expect(data).toMatchObject({
      error: 'Set a local password before removing your only external login method',
    })
    expect(runs.some(({ sql }) => sql.startsWith('DELETE FROM external_accounts'))).toBe(false)
  })

  it('unlinks the provider account after recent reauthentication', async () => {
    const { db, runs } = createDb({
      credentials: { password_hash: 'hash', opaque_registration_record: null },
      reauthenticatedAt: Math.floor(Date.now() / 1000) - 10,
    })
    const response = await auth.request(
      '/external-accounts/krtl',
      { method: 'DELETE', headers: { Authorization: 'Bearer session-1' } },
      bindings(db),
    )

    expect(response.status).toBe(200)
    expect(
      runs.some(
        ({ sql, values }) =>
          sql.startsWith('DELETE FROM external_accounts') &&
          values[0] === 'krtl' &&
          values[1] === 'user-1',
      ),
    ).toBe(true)
  })
})
