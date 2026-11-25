<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useHead } from '@unhead/vue'
import { useI18n } from 'vue-i18n'
import { localizeApiError } from '@/i18n/errors'
import { useAuthStore } from '@/stores/authStore'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const { t } = useI18n()

const error = ref('')
const loading = ref(true)
const show2FAOptions = ref(false)
const pendingAuthId = ref('')
const redirectPath = ref('/')
const totpCode = ref('')
const isTOTPEnabled = ref(false)
const hasPasskeys = ref(false)
const passkeyOptions = ref<any>(null)

useHead({ title: () => t('auth.login.krtlCallbackTitle') })

function queryValue(name: string): string {
  const value = route.query[name]
  return typeof value === 'string' ? value : ''
}

function safeRedirect(value: unknown): string {
  if (typeof value === 'string' && value.startsWith('/') && !value.startsWith('//')) return value
  return '/'
}

function storedRedirect(): string {
  const redirect = safeRedirect(sessionStorage.getItem('krtlLoginRedirect'))
  sessionStorage.removeItem('krtlLoginRedirect')
  return redirect
}

async function finishLogin(data: { sessionId?: string; user?: unknown; redirectPath?: unknown }) {
  if (!data.sessionId || !data.user) throw new Error(t('auth.login.messages.krtlFailed'))
  auth.setSessionData(data.sessionId, data.user as Parameters<typeof auth.setSessionData>[1])
  const target =
    typeof data.redirectPath === 'string' ? safeRedirect(data.redirectPath) : storedRedirect()
  await router.replace(target)
}

async function loadPasskeyOptions() {
  if (!hasPasskeys.value) return
  const response = await fetch('/api/passkey/2fa-options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ pendingAuthId: pendingAuthId.value }),
  })
  const data = await response.json()
  if (!response.ok)
    throw new Error(localizeApiError(data.error, 'auth.login.messages.passkeyOptionsFailed'))
  passkeyOptions.value = data.passkeyOptions
}

async function completeKrtlLogin(code: string, state: string) {
  const callbackResponse = await fetch('/api/auth/krtl/callback', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code, state }),
  })
  const callbackData = await callbackResponse.json().catch(() => ({}))
  if (callbackResponse.ok && callbackData.linked) {
    await router.replace(safeRedirect(callbackData.redirectPath || '/settings/accounts'))
    return
  }
  if (!callbackResponse.ok || !callbackData.ticket) {
    throw new Error(callbackData.error || t('auth.login.messages.krtlFailed'))
  }

  const completeResponse = await fetch('/api/auth/krtl/complete', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ticket: callbackData.ticket }),
  })
  const data = await completeResponse.json().catch(() => ({}))
  if (!completeResponse.ok) throw new Error(data.error || t('auth.login.messages.krtlFailed'))

  redirectPath.value = safeRedirect(data.redirectPath || callbackData.redirectPath)
  if (data.requires2FA) {
    pendingAuthId.value = data.pendingAuthId
    isTOTPEnabled.value = Boolean(data.methods?.totp)
    hasPasskeys.value = Boolean(data.methods?.passkey)
    show2FAOptions.value = true
    await loadPasskeyOptions()
    return
  }

  await finishLogin(data)
}

onMounted(async () => {
  const code = queryValue('code')
  const state = queryValue('state')
  const providerError = queryValue('error')

  if (providerError || !code || !state) {
    error.value = providerError || t('auth.login.messages.krtlInvalidCallback')
    loading.value = false
    sessionStorage.removeItem('krtlLoginRedirect')
    return
  }

  try {
    await completeKrtlLogin(code, state)
  } catch (caught) {
    error.value = (caught as Error).message
    sessionStorage.removeItem('krtlLoginRedirect')
  } finally {
    loading.value = false
  }
})

async function verifyWithTOTP() {
  const result = await auth.verifyTOTP(pendingAuthId.value, totpCode.value)
  if (result.success) await router.replace(redirectPath.value)
}

async function verifyWithPasskey() {
  if (!passkeyOptions.value) return

  try {
    const base64UrlToBuffer = (base64url: string) => {
      const padding = '='.repeat((4 - (base64url.length % 4)) % 4)
      const rawData = window.atob(base64url.replace(/-/g, '+').replace(/_/g, '/') + padding)
      const buffer = new Uint8Array(rawData.length)
      for (let i = 0; i < rawData.length; i++) buffer[i] = rawData.charCodeAt(i)
      return buffer.buffer
    }
    const bufferToBase64url = (buffer: ArrayBuffer) => {
      const bytes = new Uint8Array(buffer)
      let binary = ''
      for (const byte of bytes) binary += String.fromCharCode(byte)
      return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }
    const options = {
      challenge: base64UrlToBuffer(passkeyOptions.value.challenge),
      rpId: passkeyOptions.value.rpId,
      allowCredentials: passkeyOptions.value.allowCredentials.map((credential: any) => ({
        type: credential.type,
        id: typeof credential.id === 'string' ? base64UrlToBuffer(credential.id) : credential.id,
        transports: credential.transports,
      })),
      userVerification: passkeyOptions.value.userVerification,
      timeout: passkeyOptions.value.timeout,
    }
    const credential = (await navigator.credentials.get({
      publicKey: options,
    })) as PublicKeyCredential | null
    if (!credential) throw new Error(t('auth.login.messages.noCredential'))
    const response = credential.response as AuthenticatorAssertionResponse
    const verification = await fetch('/api/passkey/verify-2fa', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        pendingAuthId: pendingAuthId.value,
        credential: {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          response: {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            authenticatorData: bufferToBase64url(response.authenticatorData),
            signature: bufferToBase64url(response.signature),
            userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
          },
          type: credential.type,
        },
      }),
    })
    const data = await verification.json()
    if (!verification.ok || !data.success)
      throw new Error(localizeApiError(data.error, 'auth.login.passkeyFailed'))
    auth.setSessionData(data.sessionId, data.user)
    await router.replace(redirectPath.value)
  } catch (caught) {
    error.value = (caught as Error).message
  }
}
</script>

<template>
  <div class="auth-view krtl-callback-view">
    <div class="auth-card paper-panel">
      <template v-if="loading">
        <p class="eyebrow">{{ t('auth.login.krtlCallbackTitle') }}</p>
      </template>
      <template v-else-if="show2FAOptions">
        <p class="eyebrow">{{ t('auth.login.eyebrow') }}</p>
        <h1>{{ t('auth.login.title2fa') }}</h1>
        <p class="subtitle">{{ t('auth.login.subtitle2fa') }}</p>
        <div class="verification-methods">
          <div v-if="isTOTPEnabled" class="method-card paper-panel">
            <h3>📱 {{ t('auth.login.totpTitle') }}</h3>
            <p>{{ t('auth.login.totpDesc') }}</p>
            <input
              id="krtl-totp"
              v-model="totpCode"
              type="text"
              inputmode="numeric"
              maxlength="6"
            />
            <button class="primary" :disabled="!totpCode || auth.loading" @click="verifyWithTOTP">
              {{ t('auth.login.verify') }}
            </button>
          </div>
          <div v-if="hasPasskeys" class="method-card paper-panel">
            <h3>🔑 {{ t('auth.login.passkeyTitle') }}</h3>
            <p>{{ t('auth.login.passkeyDesc') }}</p>
            <button class="primary" :disabled="auth.loading" @click="verifyWithPasskey">
              {{ t('auth.login.usePasskeyVerify') }}
            </button>
          </div>
        </div>
        <p v-if="auth.error" class="error-message">{{ auth.error }}</p>
        <p v-if="error" class="error-message">{{ error }}</p>
      </template>
      <template v-else-if="error">
        <p class="eyebrow">{{ t('auth.login.eyebrow') }}</p>
        <h1>{{ t('auth.login.messages.krtlFailed') }}</h1>
        <p class="error-message">{{ error }}</p>
        <RouterLink class="back-link" to="/login">{{ t('common.login') }}</RouterLink>
      </template>
    </div>
  </div>
</template>

<style scoped>
.krtl-callback-view {
  min-height: 55vh;
  align-items: center;
}
.auth-card {
  width: min(100%, 560px);
  padding: 36px;
}
.auth-card h1 {
  margin: 8px 0 12px;
  font-size: 1.6rem;
}
.subtitle {
  margin: 0;
  color: var(--ruins-muted);
}
.verification-methods {
  display: grid;
  gap: 16px;
  margin-top: 20px;
}
.method-card {
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.method-card h3,
.method-card p {
  margin: 0;
}
.method-card p {
  color: var(--ruins-muted);
  font-size: 0.9rem;
}
.method-card input {
  border: 1px solid var(--ruins-border);
  background: transparent;
  color: var(--ruins-text);
  padding: 10px;
}
.error-message {
  color: var(--ruins-danger);
  overflow-wrap: anywhere;
}
.back-link {
  display: inline-flex;
  margin-top: 12px;
  border-bottom: 1px solid var(--ruins-border);
}
button {
  padding: 10px 18px;
  border: 1px solid var(--ruins-border);
  background: rgba(255, 255, 255, 0.1);
  color: var(--ruins-text);
  cursor: pointer;
}
button.primary {
  background: var(--ruins-accent-strong);
  color: var(--ruins-bg);
  border: 0;
}
button:disabled {
  opacity: 0.5;
  cursor: wait;
}
@media (max-width: 600px) {
  .auth-card {
    padding: 24px;
  }
}
</style>
