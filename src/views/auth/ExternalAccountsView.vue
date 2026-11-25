<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useHead } from '@unhead/vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'
import { useToastStore } from '@/stores/toastStore'
import { formatTimestamp } from '@/utils/temporal'

type ExternalAccount = {
  provider: string
  email: string | null
  createdAt: number
}

const auth = useAuthStore()
const router = useRouter()
const toast = useToastStore()
const { t, locale } = useI18n()

useHead({ title: () => t('auth.externalAccounts.title') })

const accounts = ref<ExternalAccount[]>([])
const loading = ref(true)
const removing = ref<string | null>(null)
const linking = ref(false)

function headers() {
  return { Authorization: auth.getAuthHeader() }
}

function providerName(provider: string) {
  return provider === 'krtl' || provider === 'https://a.krtl.net' ? 'krtl.net' : provider
}

function formatDate(timestamp: number) {
  return formatTimestamp(timestamp, locale.value)
}

async function connectKrtl() {
  if (linking.value) return
  linking.value = true
  try {
    const response = await fetch('/api/auth/krtl/link/start', {
      method: 'POST',
      headers: headers(),
    })
    const data = await response.json().catch(() => ({}))
    if (response.ok && data.authorizationUrl) {
      window.location.assign(data.authorizationUrl)
      return
    }
    throw new Error(data.error || t('auth.externalAccounts.messages.connectFailed'))
  } catch (error) {
    toast.error((error as Error).message)
    linking.value = false
  }
}

async function loadAccounts() {
  loading.value = true
  try {
    const response = await fetch('/api/auth/external-accounts', { headers: headers() })
    const data = await response.json().catch(() => ({}))
    if (response.status === 401) {
      await auth.logout()
      await router.push({ name: 'login', query: { redirect: '/settings/accounts' } })
      return
    }
    if (!response.ok) throw new Error(data.error || t('auth.externalAccounts.messages.loadFailed'))
    accounts.value = data.accounts || []
  } catch (error) {
    toast.error((error as Error).message)
  } finally {
    loading.value = false
  }
}

async function removeAccount(account: ExternalAccount) {
  if (
    !confirm(
      t('auth.externalAccounts.messages.confirmRemove', {
        provider: providerName(account.provider),
      }),
    )
  )
    return

  removing.value = account.provider
  try {
    const response = await fetch(
      `/api/auth/external-accounts/${encodeURIComponent(account.provider)}`,
      {
        method: 'DELETE',
        headers: headers(),
      },
    )
    const data = await response.json().catch(() => ({}))
    if (!response.ok) {
      const errorKey =
        response.status === 409
          ? 'auth.externalAccounts.messages.lastLoginMethod'
          : response.status === 401
            ? 'auth.externalAccounts.messages.reauthRequired'
            : 'auth.externalAccounts.messages.removeFailed'
      throw new Error(data.error || t(errorKey))
    }
    accounts.value = accounts.value.filter(({ provider }) => provider !== account.provider)
    toast.success(t('auth.externalAccounts.messages.removed'))
  } catch (error) {
    toast.error((error as Error).message)
  } finally {
    removing.value = null
  }
}

onMounted(async () => {
  if (!auth.isAuthenticated) {
    await router.push({ name: 'login', query: { redirect: '/settings/accounts' } })
    return
  }
  await loadAccounts()
})
</script>

<template>
  <div class="external-accounts-view">
    <div class="page-header">
      <h1>{{ t('auth.externalAccounts.title') }}</h1>
      <p class="subtitle">{{ t('auth.externalAccounts.subtitle') }}</p>
    </div>

    <section class="settings-section paper-panel">
      <div class="section-header">
        <div>
          <h2>{{ t('auth.externalAccounts.connectedTitle') }}</h2>
          <p class="section-desc">{{ t('auth.externalAccounts.connectedDescription') }}</p>
        </div>
        <button class="connect-button" type="button" :disabled="linking" @click="connectKrtl">
          {{ linking ? t('common.loading') : t('auth.externalAccounts.connectKrtl') }}
        </button>
      </div>

      <p v-if="loading" class="muted">{{ t('common.loading') }}</p>
      <p v-else-if="accounts.length === 0" class="muted">{{ t('auth.externalAccounts.empty') }}</p>
      <div v-else class="account-list">
        <div v-for="account in accounts" :key="account.provider" class="account-item">
          <div class="account-info">
            <strong>{{ providerName(account.provider) }}</strong>
            <small v-if="account.email">{{ account.email }}</small>
            <small>{{
              t('auth.externalAccounts.connectedAt', { date: formatDate(account.createdAt) })
            }}</small>
          </div>
          <button
            class="danger-link"
            type="button"
            :disabled="removing === account.provider"
            @click="removeAccount(account)"
          >
            {{
              removing === account.provider
                ? t('common.loading')
                : t('auth.externalAccounts.remove')
            }}
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.external-accounts-view {
  display: flex;
  flex-direction: column;
  gap: 32px;
  max-width: 800px;
}
.page-header h1 {
  margin: 0 0 8px;
  font-size: 2rem;
  font-family: var(--font-serif);
  color: var(--ruins-text);
}
.subtitle,
.section-desc,
.muted {
  color: var(--ruins-muted);
}
.subtitle {
  margin: 0;
}
.settings-section {
  padding: 32px;
  display: flex;
  flex-direction: column;
  gap: 24px;
}
.section-header {
  padding-bottom: 16px;
  border-bottom: 1px solid var(--ruins-border);
}
.section-header h2 {
  margin: 0 0 4px;
  font-size: 1.25rem;
  font-family: var(--font-serif);
}
.connect-button {
  padding: 8px 14px;
  border: 1px solid var(--ruins-border);
  background: rgba(255, 255, 255, 0.08);
  color: var(--ruins-text);
  cursor: pointer;
  flex-shrink: 0;
}
.section-desc {
  margin: 0;
  font-size: 0.9rem;
}
.account-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.account-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 18px;
  padding: 16px;
  border: 1px solid var(--ruins-border);
}
.account-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.account-info strong {
  color: var(--ruins-accent-strong);
}
.account-info small {
  color: var(--ruins-muted);
  overflow-wrap: anywhere;
}
button {
  padding: 8px 16px;
  background: transparent;
  border: 1px solid var(--ruins-border);
  color: var(--ruins-text);
  cursor: pointer;
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 0.8rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  flex-shrink: 0;
}
button:disabled {
  opacity: 0.55;
  cursor: wait;
}
.danger-link {
  border-color: var(--ruins-danger);
  color: var(--ruins-danger);
}
button.danger-link {
  border-color: var(--ruins-danger);
  color: var(--ruins-danger);
}
@media (max-width: 600px) {
  .settings-section {
    padding: 22px;
  }
  .account-item {
    align-items: flex-start;
    flex-direction: column;
  }
}
</style>
