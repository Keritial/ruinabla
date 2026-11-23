<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useHead } from '@unhead/vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/authStore'
import { useToastStore } from '@/stores/toastStore'

type ConsentRequest = {
  requestId: string
  client: { id: string; name: string; redirectUri: string }
  scopes: string[]
}

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const toast = useToastStore()
const { t } = useI18n()
useHead({ title: () => t('auth.oidc.consentTitle') })

const request = ref<ConsentRequest | null>(null)
const loading = ref(true)
const submitting = ref(false)

async function loadRequest() {
  const requestId = String(route.query.request_id || '')
  if (!requestId) {
    toast.error(t('auth.oidc.messages.invalidRequest'))
    await router.push('/')
    return
  }

  try {
    const response = await fetch(
      `/api/oidc/authorize/request?request_id=${encodeURIComponent(requestId)}`,
      {
        headers: { Authorization: auth.getAuthHeader() },
      },
    )
    const data = await response.json()
    if (response.status === 401) {
      await auth.logout()
      const redirect = router.resolve({ path: '/oauth/consent', query: route.query }).fullPath
      await router.push({ name: 'login', query: { redirect } })
      return
    }
    if (!response.ok) throw new Error(data.error || t('auth.oidc.messages.invalidRequest'))
    request.value = {
      requestId: data.requestId,
      client: data.client,
      scopes: data.scopes,
    }
  } catch (error) {
    toast.error((error as Error).message)
    await router.push('/')
  } finally {
    loading.value = false
  }
}

async function decide(approved: boolean) {
  if (!request.value) return
  submitting.value = true
  try {
    const response = await fetch('/api/oidc/authorize/consent', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: auth.getAuthHeader() },
      body: JSON.stringify({ requestId: request.value.requestId, approved }),
    })
    const data = await response.json()
    if (response.status === 401) {
      await auth.logout()
      const redirect = router.resolve({ path: '/oauth/consent', query: route.query }).fullPath
      await router.push({ name: 'login', query: { redirect } })
      return
    }
    if (!response.ok) throw new Error(data.error || t('auth.oidc.messages.consentFailed'))
    if (data.redirectUrl) {
      window.location.assign(data.redirectUrl)
      return
    }
    await router.push('/')
  } catch (error) {
    toast.error((error as Error).message)
    submitting.value = false
  }
}

onMounted(async () => {
  if (!auth.isAuthenticated) {
    const redirect = router.resolve({ path: '/oauth/consent', query: route.query }).fullPath
    await router.push({ name: 'login', query: { redirect } })
    return
  }
  await loadRequest()
})
</script>

<template>
  <div class="auth-view consent-view">
    <div class="auth-card paper-panel">
      <template v-if="loading">
        <p class="eyebrow">{{ t('common.loading') }}</p>
      </template>
      <template v-else-if="request">
        <p class="eyebrow">{{ t('auth.oidc.consentEyebrow') }}</p>
        <h1>{{ t('auth.oidc.consentTitle') }}</h1>
        <p class="consent-copy">
          {{ t('auth.oidc.consentDescription', { client: request.client.name }) }}
        </p>
        <div class="scope-summary">
          <span v-for="scope in request.scopes" :key="scope" class="scope-row">
            <code>{{ scope }}</code>
            <span>{{ t(`auth.oidc.scopeDescriptions.${scope}`, scope) }}</span>
          </span>
        </div>
        <div class="consent-actions">
          <button type="button" class="primary" :disabled="submitting" @click="decide(true)">
            {{ t('auth.oidc.allow') }}
          </button>
          <button type="button" :disabled="submitting" @click="decide(false)">
            {{ t('auth.oidc.deny') }}
          </button>
        </div>
      </template>
    </div>
  </div>
</template>

<style scoped>
.consent-view {
  min-height: 60vh;
  align-items: center;
}
.auth-card {
  width: min(100%, 560px);
  padding: 40px;
}
.auth-card h1 {
  margin: 8px 0 14px;
}
.consent-copy {
  color: var(--ruins-muted);
  margin: 0 0 24px;
}
.scope-summary {
  display: flex;
  flex-direction: column;
  gap: 12px;
  border-top: 1px solid var(--ruins-border);
  border-bottom: 1px solid var(--ruins-border);
  padding: 18px 0;
}
.scope-row {
  display: flex;
  gap: 14px;
  align-items: baseline;
}
.scope-row code {
  min-width: 72px;
  font-family: var(--font-mono);
  color: var(--ruins-accent-strong);
}
.scope-row span:last-child {
  color: var(--ruins-muted);
}
.consent-actions {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 28px;
}
button {
  padding: 12px 24px;
  background: rgba(255, 255, 255, 0.1);
  border: 1px solid var(--ruins-border);
  color: var(--ruins-text);
  cursor: pointer;
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 0.9rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
}
button.primary {
  background: var(--ruins-accent-strong);
  color: var(--ruins-bg);
  border: 0;
}
button:disabled {
  opacity: 0.55;
  cursor: wait;
}
@media (max-width: 600px) {
  .auth-card {
    padding: 26px;
  }
  .scope-row {
    align-items: flex-start;
    flex-direction: column;
    gap: 3px;
  }
}
</style>
