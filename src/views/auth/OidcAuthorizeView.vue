<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useHead } from '@unhead/vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/authStore'

const route = useRoute()
const router = useRouter()
const auth = useAuthStore()
const { t } = useI18n()
const error = ref('')
const loading = ref(true)

useHead({ title: () => t('auth.oidc.authorizingTitle') })

function parameter(name: string): string {
  const value = route.query[name]
  return typeof value === 'string' ? value : ''
}

onMounted(async () => {
  if (!auth.isAuthenticated) {
    await router.replace({ name: 'login', query: { redirect: route.fullPath } })
    return
  }

  try {
    const response = await fetch('/api/oidc/authorize', {
      method: 'POST',
      headers: {
        Authorization: auth.getAuthHeader(),
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        client_id: parameter('client_id'),
        redirect_uri: parameter('redirect_uri'),
        response_type: parameter('response_type'),
        scope: parameter('scope'),
        state: parameter('state'),
        nonce: parameter('nonce'),
        code_challenge: parameter('code_challenge'),
        code_challenge_method: parameter('code_challenge_method'),
      }),
    })
    const data = await response.json()
    if (response.status === 401) {
      await auth.logout()
      await router.replace({ name: 'login', query: { redirect: route.fullPath } })
      return
    }
    if (!response.ok)
      throw new Error(
        data.error_description || data.error || t('auth.oidc.messages.invalidRequest'),
      )
    await router.replace({ name: 'oauth-consent', query: { request_id: data.requestId } })
  } catch (caught) {
    error.value = (caught as Error).message
  } finally {
    loading.value = false
  }
})
</script>

<template>
  <div class="auth-view authorize-view">
    <div class="auth-card paper-panel">
      <p v-if="loading" class="eyebrow">{{ t('auth.oidc.authorizingTitle') }}</p>
      <template v-else-if="error">
        <p class="eyebrow">{{ t('auth.oidc.consentEyebrow') }}</p>
        <h1>{{ t('auth.oidc.messages.invalidRequest') }}</h1>
        <p class="error-message">{{ error }}</p>
        <RouterLink class="back-link" to="/">{{ t('auth.oidc.backToSite') }}</RouterLink>
      </template>
    </div>
  </div>
</template>

<style scoped>
.authorize-view {
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
.error-message {
  color: var(--ruins-danger);
  overflow-wrap: anywhere;
}
.back-link {
  display: inline-flex;
  margin-top: 12px;
  border-bottom: 1px solid var(--ruins-border);
}
@media (max-width: 600px) {
  .auth-card {
    padding: 24px;
  }
}
</style>
