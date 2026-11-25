import { afterEach, describe, expect, it, vi } from 'vitest'
import { verifyKrtlIdToken } from './krtl'

const clientId = 'krtl_client'

function base64Url(value: Uint8Array | string): string {
  const bytes = typeof value === 'string' ? new TextEncoder().encode(value) : value
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

async function makeIdToken(claims: Record<string, unknown>) {
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
  const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  const header = base64Url(JSON.stringify({ alg: 'RS256', kid: 'krtl-test', typ: 'JWT' }))
  const payload = base64Url(JSON.stringify(claims))
  const input = `${header}.${payload}`
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    keyPair.privateKey,
    new TextEncoder().encode(input),
  )

  return {
    token: `${input}.${base64Url(new Uint8Array(signature))}`,
    publicJwk: { ...publicJwk, kid: 'krtl-test', alg: 'RS256', use: 'sig' },
  }
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('KRTL ID token validation', () => {
  it('accepts a multi-audience token only when azp identifies this client', async () => {
    const { token, publicJwk } = await makeIdToken({
      iss: 'https://a.krtl.net',
      sub: 'krtl-subject',
      aud: [clientId, 'another-client'],
      azp: clientId,
      nonce: 'nonce-1',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    })
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ keys: [publicJwk] }))),
    )

    await expect(verifyKrtlIdToken(token, 'nonce-1', clientId)).resolves.toMatchObject({
      sub: 'krtl-subject',
    })
  })

  it('rejects a multi-audience token with a missing or incorrect azp', async () => {
    for (const azp of [undefined, 'another-client']) {
      const { token, publicJwk } = await makeIdToken({
        iss: 'https://a.krtl.net',
        sub: 'krtl-subject',
        aud: [clientId, 'another-client'],
        ...(azp ? { azp } : {}),
        nonce: 'nonce-1',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
      })
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue(new Response(JSON.stringify({ keys: [publicJwk] }))),
      )

      await expect(verifyKrtlIdToken(token, 'nonce-1', clientId)).rejects.toThrow(
        'Invalid KRTL ID token claims',
      )
    }
  })

  it('rejects tokens without a matching key id', async () => {
    const { token, publicJwk } = await makeIdToken({
      iss: 'https://a.krtl.net',
      sub: 'krtl-subject',
      aud: clientId,
      nonce: 'nonce-1',
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 300,
    })
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ keys: [{ ...publicJwk, kid: 'other' }] })),
        ),
    )

    await expect(verifyKrtlIdToken(token, 'nonce-1', clientId)).rejects.toThrow(
      'KRTL signing key not found',
    )
  })
})
