<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useHead } from '@unhead/vue'
import { useI18n } from 'vue-i18n'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/authStore'
import { useToastStore } from '@/stores/toastStore'

type OidcClient = {
  id: string
  name: string
  redirectUris: string[]
  createdAt: number
}

const auth = useAuthStore()
const router = useRouter()
const toast = useToastStore()
const { t, locale } = useI18n()

useHead({ title: () => t('auth.oidc.title') })

const clients = ref<OidcClient[]>([])
const loading = ref(true)
const submitting = ref(false)
const name = ref('')
const redirectUris = ref('')
const newlyCreatedSecret = ref('')
const newlyCreatedId = ref('')

function authHeaders() {
  return {
    Authorization: auth.getAuthHeader(),
    'Content-Type': 'application/json',
  }
}

async function loadClients() {
  loading.value = true
  try {
    const response = await fetch('/api/oidc/clients', { headers: authHeaders() })
    if (response.status === 401) {
      await auth.logout()
      await router.push({ name: 'login', query: { redirect: '/settings/oidc' } })
      return
    }
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || t('auth.oidc.messages.loadFailed'))
    clients.value = data.clients || []
  } catch (error) {
    toast.error((error as Error).message)
  } finally {
    loading.value = false
  }
}

async function createClient() {
  const parsedRedirectUris = redirectUris.value
    .split(/\r?\n/)
    .map((uri) => uri.trim())
    .filter(Boolean)

  if (!name.value.trim() || parsedRedirectUris.length === 0) {
    toast.error(t('auth.oidc.messages.required'))
    return
  }

  submitting.value = true
  newlyCreatedSecret.value = ''
  newlyCreatedId.value = ''
  try {
    const response = await fetch('/api/oidc/clients', {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({
        name: name.value.trim(),
        redirectUris: parsedRedirectUris,
      }),
    })
    const data = await response.json()
    if (!response.ok) throw new Error(data.error || t('auth.oidc.messages.createFailed'))

    clients.value = [data.client, ...clients.value]
    newlyCreatedId.value = data.client.id
    newlyCreatedSecret.value = data.clientSecret || ''
    name.value = ''
    redirectUris.value = ''
    toast.success(t('auth.oidc.messages.created'))
  } catch (error) {
    toast.error((error as Error).message)
  } finally {
    submitting.value = false
  }
}

async function deleteClient(client: OidcClient) {
  if (!confirm(t('auth.oidc.messages.confirmDelete', { name: client.name }))) return

  try {
    const response = await fetch(`/api/oidc/clients/${encodeURIComponent(client.id)}`, {
      method: 'DELETE',
      headers: authHeaders(),
    })
    const data = await response.json().catch(() => ({}))
    if (!response.ok) throw new Error(data.error || t('auth.oidc.messages.deleteFailed'))
    clients.value = clients.value.filter(({ id }) => id !== client.id)
    toast.success(t('auth.oidc.messages.deleted'))
  } catch (error) {
    toast.error((error as Error).message)
  }
}

async function copyValue(value: string) {
  try {
    await navigator.clipboard.writeText(value)
    toast.success(t('auth.oidc.messages.copied'))
  } catch {
    toast.error(t('auth.oidc.messages.copyFailed'))
  }
}

function formatDate(value: number) {
  return new Intl.DateTimeFormat(locale.value, { dateStyle: 'medium' }).format(value * 1000)
}

onMounted(async () => {
  if (!auth.isAuthenticated) {
    await router.push({ name: 'login', query: { redirect: '/settings/oidc' } })
    return
  }
  await loadClients()
})
</script>

<template>
  <div class="oidc-view">
    <div class="page-header">
      <h1>{{ t('auth.oidc.title') }}</h1>
      <p class="subtitle">{{ t('auth.oidc.subtitle') }}</p>
    </div>

    <section class="settings-section paper-panel">
      <div class="section-header">
        <div>
          <h2>{{ t('auth.oidc.registerTitle') }}</h2>
          <p class="section-desc">{{ t('auth.oidc.registerDescription') }}</p>
        </div>
      </div>

      <form class="section-content" @submit.prevent="createClient">
        <div class="field">
          <label for="oidc-name">{{ t('auth.oidc.clientName') }}</label>
          <input
            id="oidc-name"
            v-model="name"
            required
            :placeholder="t('auth.oidc.clientNamePlaceholder')"
          />
        </div>
        <div class="field">
          <label for="oidc-redirects">{{ t('auth.oidc.redirectUris') }}</label>
          <textarea
            id="oidc-redirects"
            v-model="redirectUris"
            required
            rows="3"
            :placeholder="t('auth.oidc.redirectUrisPlaceholder')"
          />
          <small>{{ t('auth.oidc.redirectUrisHint') }}</small>
        </div>
        <p class="scope-info">
          <span>{{ t('auth.oidc.scopes') }}</span
          ><code>openid email</code>
        </p>
        <button class="primary" type="submit" :disabled="submitting">
          {{ submitting ? t('auth.oidc.creating') : t('auth.oidc.create') }}
        </button>
      </form>
    </section>

    <section v-if="newlyCreatedSecret" class="settings-section paper-panel secret-section">
      <div class="section-header">
        <div>
          <h2>{{ t('auth.oidc.secretTitle') }}</h2>
          <p class="section-desc">{{ t('auth.oidc.secretDescription') }}</p>
        </div>
      </div>
      <dl class="secret-values">
        <div>
          <dt>{{ t('auth.oidc.clientId') }}</dt>
          <dd>
            <code>{{ newlyCreatedId }}</code>
            <button type="button" class="copy-button" @click="copyValue(newlyCreatedId)">
              {{ t('auth.oidc.copy') }}
            </button>
          </dd>
        </div>
        <div>
          <dt>{{ t('auth.oidc.clientSecret') }}</dt>
          <dd>
            <code>{{ newlyCreatedSecret }}</code>
            <button type="button" class="copy-button" @click="copyValue(newlyCreatedSecret)">
              {{ t('auth.oidc.copy') }}
            </button>
          </dd>
        </div>
      </dl>
    </section>

    <section class="settings-section paper-panel">
      <div class="section-header">
        <div>
          <h2>{{ t('auth.oidc.clientsTitle') }}</h2>
          <p class="section-desc">{{ t('auth.oidc.clientsDescription') }}</p>
        </div>
      </div>
      <p v-if="loading" class="muted">{{ t('common.loading') }}</p>
      <p v-else-if="clients.length === 0" class="muted">{{ t('auth.oidc.empty') }}</p>
      <div v-else class="client-list">
        <div v-for="client in clients" :key="client.id" class="client-item">
          <div class="client-info">
            <strong>{{ client.name }}</strong>
            <small
              >{{ t('auth.oidc.clientId') }}: <code>{{ client.id }}</code></small
            >
            <small>{{ t('auth.oidc.createdAt') }}: {{ formatDate(client.createdAt) }}</small>
            <small v-for="uri in client.redirectUris" :key="uri" class="redirect-uri">{{
              uri
            }}</small>
          </div>
          <button class="danger-link" type="button" @click="deleteClient(client)">
            {{ t('common.delete') }}
          </button>
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.oidc-view {
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
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--ruins-border);
}
.section-header h2 {
  margin: 0 0 4px;
  font-size: 1.25rem;
  font-family: var(--font-serif);
}
.section-desc {
  margin: 0;
  font-size: 0.9rem;
}
.section-content {
  display: flex;
  flex-direction: column;
  gap: 16px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.field label {
  font-family: var(--font-mono);
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.05em;
  color: var(--ruins-muted);
}
.field input,
.field textarea {
  border: 1px solid var(--ruins-border);
  color: var(--ruins-text);
  background: transparent;
  padding: 12px;
  font-size: 1rem;
  border-radius: 6px;
  font-family: var(--font-sans);
}
.field textarea {
  resize: vertical;
  min-height: 82px;
}
.field input:focus,
.field textarea:focus {
  outline: none;
  border-color: var(--ruins-accent);
}
.field small {
  color: var(--ruins-muted);
}
.scope-info {
  display: flex;
  align-items: center;
  gap: 14px;
  margin: 0;
  color: var(--ruins-muted);
  font-family: var(--font-mono);
  font-size: 0.85rem;
}
.scope-info code {
  color: var(--ruins-text);
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
  width: fit-content;
}
button:disabled {
  opacity: 0.55;
  cursor: wait;
}
button.primary {
  background: var(--ruins-accent-strong);
  color: var(--ruins-bg);
  border: 0;
}
.secret-section {
  border-color: var(--ruins-success);
}
.secret-values {
  display: grid;
  gap: 14px;
  margin: 0;
}
.secret-values div {
  display: grid;
  gap: 5px;
}
.secret-values dt {
  color: var(--ruins-muted);
  font-family: var(--font-mono);
  font-size: 0.8rem;
  text-transform: uppercase;
}
.secret-values dd {
  margin: 0;
  overflow-wrap: anywhere;
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.secret-values code {
  font-family: var(--font-mono);
  color: var(--ruins-success);
  flex: 1;
  min-width: 0;
}
.copy-button {
  padding: 5px 9px;
  font-size: 0.7rem;
  text-transform: none;
  letter-spacing: 0;
  flex-shrink: 0;
}
.client-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}
.client-item {
  display: flex;
  justify-content: space-between;
  gap: 18px;
  align-items: flex-start;
  padding: 16px;
  border: 1px solid var(--ruins-border);
  border-radius: 6px;
}
.client-info {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.client-info strong {
  color: var(--ruins-accent-strong);
}
.client-info small {
  color: var(--ruins-muted);
  overflow-wrap: anywhere;
}
.client-info code {
  font-family: var(--font-mono);
}
.redirect-uri {
  color: var(--ruins-text) !important;
}
button.danger-link {
  background: transparent;
  border-color: var(--ruins-danger);
  color: var(--ruins-danger);
  padding: 8px 16px;
  font-size: 0.8rem;
  flex-shrink: 0;
}
@media (max-width: 600px) {
  .settings-section {
    padding: 22px;
  }
  .client-item {
    flex-direction: column;
  }
}
</style>
