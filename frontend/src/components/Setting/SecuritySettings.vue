<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  createCodexRelayKey,
  deleteCodexRelayKey,
  getCodexRelayKeySecret,
  listCodexRelayKeys,
  logoutAdmin,
  updateAdminCredentials,
  useAdminAuthState,
  type CodexRelayKeyCreateResult,
  type CodexRelayKeyListItem,
} from '../../services/adminAuth'
import { extractErrorMessage } from '../../utils/error'
import { showToast } from '../../utils/toast'

const { t } = useI18n()
const authState = useAdminAuthState()

const currentPassword = ref('')
const newUsername = ref('')
const newPassword = ref('')
const credentialsBusy = ref(false)

const keys = ref<CodexRelayKeyListItem[]>([])
const keysLoading = ref(false)
const keyBusyId = ref('')
const createBusy = ref(false)
const createName = ref('')
const createdKey = ref<CodexRelayKeyCreateResult | null>(null)

const formatDateTime = (value: string) => {
  if (!value) {
    return '--'
  }

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

const copyToClipboard = async (value: string) => {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value)
    return
  }

  const textArea = document.createElement('textarea')
  textArea.value = value
  textArea.style.position = 'fixed'
  textArea.style.opacity = '0'
  document.body.appendChild(textArea)
  textArea.focus()
  textArea.select()

  const success = document.execCommand('copy')
  document.body.removeChild(textArea)
  if (!success) {
    throw new Error(t('auth.errors.copyFailed'))
  }
}

const loadKeys = async () => {
  keysLoading.value = true
  try {
    keys.value = await listCodexRelayKeys()
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.loadKeysFailed')), 'error')
  } finally {
    keysLoading.value = false
  }
}

const handleUpdateCredentials = async () => {
  if (credentialsBusy.value) {
    return
  }

  credentialsBusy.value = true
  try {
    await updateAdminCredentials(
      currentPassword.value,
      newUsername.value.trim(),
      newPassword.value,
    )
    currentPassword.value = ''
    newUsername.value = ''
    newPassword.value = ''
    showToast(t('auth.security.updateSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.updateFailed')), 'error')
  } finally {
    credentialsBusy.value = false
  }
}

const handleLogout = async () => {
  if (credentialsBusy.value) {
    return
  }

  credentialsBusy.value = true
  try {
    await logoutAdmin()
    showToast(t('auth.security.logoutSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.logoutFailed')), 'error')
  } finally {
    credentialsBusy.value = false
  }
}

const handleCreateKey = async () => {
  if (createBusy.value) {
    return
  }

  createBusy.value = true
  try {
    createdKey.value = await createCodexRelayKey(createName.value.trim())
    createName.value = ''
    await loadKeys()
    showToast(t('auth.security.createSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.createFailed')), 'error')
  } finally {
    createBusy.value = false
  }
}

const handleCopyCreatedKey = async () => {
  if (!createdKey.value?.key) {
    return
  }

  try {
    await copyToClipboard(createdKey.value.key)
    showToast(t('auth.security.copied'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.errors.copyFailed')), 'error')
  }
}

const handleCopyExistingKey = async (id: string) => {
  keyBusyId.value = id
  try {
    const secret = await getCodexRelayKeySecret(id)
    await copyToClipboard(secret)
    showToast(t('auth.security.copied'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.copyFailed')), 'error')
  } finally {
    keyBusyId.value = ''
  }
}

const handleDeleteKey = async (key: CodexRelayKeyListItem) => {
  if (!window.confirm(t('auth.security.deleteConfirm', { name: key.name }))) {
    return
  }

  keyBusyId.value = key.id
  try {
    await deleteCodexRelayKey(key.id)
    if (createdKey.value?.id === key.id) {
      createdKey.value = null
    }
    await loadKeys()
    showToast(t('auth.security.deleteSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.deleteFailed')), 'error')
  } finally {
    keyBusyId.value = ''
  }
}

onMounted(async () => {
  await loadKeys()
})
</script>

<template>
  <section>
    <h2 class="mac-section-title">{{ t('components.general.title.security') }}</h2>
    <p class="mac-section-description">{{ t('auth.security.description') }}</p>

    <div class="mac-panel security-card">
      <div class="security-card-header">
        <div>
          <h3 class="security-card-title">{{ t('auth.security.adminCardTitle') }}</h3>
          <p class="security-card-description">
            {{ t('auth.security.adminCardDescription', { username: authState.username || '--' }) }}
          </p>
        </div>
        <span class="security-badge">{{ authState.username || '--' }}</span>
      </div>

      <div class="security-grid">
        <label class="security-field">
          <span>{{ t('auth.fields.currentPassword') }}</span>
          <input
            v-model="currentPassword"
            class="base-input"
            type="password"
            autocomplete="current-password"
            :placeholder="t('auth.placeholders.currentPassword')"
            :disabled="credentialsBusy"
          />
        </label>

        <label class="security-field">
          <span>{{ t('auth.fields.newUsername') }}</span>
          <input
            v-model="newUsername"
            class="base-input"
            type="text"
            autocomplete="username"
            :placeholder="t('auth.placeholders.newUsername')"
            :disabled="credentialsBusy"
          />
          <small>{{ t('auth.security.keepHint') }}</small>
        </label>

        <label class="security-field">
          <span>{{ t('auth.fields.newPassword') }}</span>
          <input
            v-model="newPassword"
            class="base-input"
            type="password"
            autocomplete="new-password"
            :placeholder="t('auth.placeholders.newPassword')"
            :disabled="credentialsBusy"
          />
          <small>{{ t('auth.security.keepHint') }}</small>
        </label>
      </div>

      <div class="security-actions">
        <button
          class="security-btn"
          :disabled="credentialsBusy"
          @click="handleUpdateCredentials"
        >
          {{ credentialsBusy ? t('auth.security.updating') : t('auth.security.update') }}
        </button>
        <button
          class="security-btn secondary"
          :disabled="credentialsBusy"
          @click="handleLogout"
        >
          {{ t('auth.security.logout') }}
        </button>
      </div>
    </div>

    <div class="mac-panel security-card">
      <div class="security-card-header">
        <div>
          <h3 class="security-card-title">{{ t('auth.security.keysCardTitle') }}</h3>
          <p class="security-card-description">{{ t('auth.security.keysCardDescription') }}</p>
        </div>
      </div>

      <div class="security-create-row">
        <label class="security-field security-field-grow">
          <span>{{ t('auth.security.createLabel') }}</span>
          <input
            v-model="createName"
            class="base-input"
            type="text"
            :placeholder="t('auth.security.createPlaceholder')"
            :disabled="createBusy"
            @keyup.enter="handleCreateKey"
          />
        </label>
        <button class="security-btn" :disabled="createBusy" @click="handleCreateKey">
          {{ createBusy ? t('auth.security.creating') : t('auth.security.create') }}
        </button>
      </div>

      <div v-if="createdKey" class="security-created">
        <div class="security-created-header">
          <div>
            <h4>{{ t('auth.security.oneTimeTitle') }}</h4>
            <p>{{ t('auth.security.oneTimeDescription') }}</p>
          </div>
          <button class="security-btn secondary" @click="handleCopyCreatedKey">
            {{ t('auth.security.copy') }}
          </button>
        </div>
        <code class="security-secret">{{ createdKey.key }}</code>
      </div>

      <div v-if="keysLoading" class="security-empty">
        {{ t('auth.security.loadingKeys') }}
      </div>
      <div v-else-if="keys.length === 0" class="security-empty">
        {{ t('auth.security.empty') }}
      </div>
      <div v-else class="security-key-list">
        <article v-for="key in keys" :key="key.id" class="security-key-row">
          <div class="security-key-meta">
            <strong>{{ key.name }}</strong>
            <span>{{ formatDateTime(key.createdAt) }}</span>
          </div>
          <code class="security-key-value">{{ key.maskedKey }}</code>
          <div class="security-key-actions">
            <button
              class="security-btn secondary"
              :disabled="keyBusyId === key.id"
              @click="handleCopyExistingKey(key.id)"
            >
              {{ t('auth.security.copy') }}
            </button>
            <button
              class="security-btn danger"
              :disabled="keyBusyId === key.id"
              @click="handleDeleteKey(key)"
            >
              {{ t('auth.security.delete') }}
            </button>
          </div>
        </article>
      </div>
    </div>
  </section>
</template>

<style scoped>
.security-card {
  padding: 22px;
  display: grid;
  gap: 20px;
}

.security-card + .security-card {
  margin-top: 14px;
}

.security-card-header {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
}

.security-card-title {
  margin: 0;
  font-size: 1rem;
}

.security-card-description {
  margin: 6px 0 0;
  color: var(--mac-text-secondary);
  line-height: 1.6;
}

.security-badge {
  display: inline-flex;
  align-items: center;
  min-height: 34px;
  padding: 0 14px;
  border-radius: 999px;
  background: color-mix(in srgb, var(--mac-accent) 12%, var(--mac-surface));
  color: var(--mac-text);
  font-size: 0.88rem;
  font-weight: 700;
}

.security-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 14px;
}

.security-field {
  display: grid;
  gap: 8px;
}

.security-field span {
  font-size: 0.9rem;
  font-weight: 600;
}

.security-field small {
  color: var(--mac-text-secondary);
  font-size: 0.76rem;
}

.security-actions,
.security-create-row,
.security-key-actions,
.security-created-header {
  display: flex;
  align-items: center;
  gap: 12px;
}

.security-actions {
  justify-content: flex-end;
}

.security-field-grow {
  flex: 1;
}

.security-btn {
  min-height: 42px;
  border: none;
  border-radius: 14px;
  padding: 0 16px;
  background: linear-gradient(135deg, #0a84ff 0%, #1271d5 100%);
  color: #fff;
  font-weight: 700;
  cursor: pointer;
  transition: opacity 0.18s ease, transform 0.18s ease;
}

.security-btn:hover:not(:disabled) {
  transform: translateY(-1px);
}

.security-btn:disabled {
  opacity: 0.65;
  cursor: wait;
}

.security-btn.secondary {
  background: color-mix(in srgb, var(--mac-text) 12%, var(--mac-surface));
  color: var(--mac-text);
}

.security-btn.danger {
  background: linear-gradient(135deg, #f43f5e 0%, #e11d48 100%);
}

.security-created {
  display: grid;
  gap: 12px;
  padding: 16px;
  border-radius: 18px;
  background: color-mix(in srgb, var(--mac-accent) 8%, var(--mac-surface));
  border: 1px solid color-mix(in srgb, var(--mac-accent) 18%, transparent);
}

.security-created-header {
  justify-content: space-between;
}

.security-created-header h4 {
  margin: 0;
}

.security-created-header p {
  margin: 6px 0 0;
  color: var(--mac-text-secondary);
}

.security-secret,
.security-key-value {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  font-size: 0.86rem;
  word-break: break-all;
}

.security-secret {
  display: block;
  padding: 14px 16px;
  border-radius: 16px;
  background: color-mix(in srgb, var(--mac-surface-strong) 86%, transparent);
}

.security-key-list {
  display: grid;
  gap: 12px;
}

.security-key-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(200px, 0.9fr) auto;
  align-items: center;
  gap: 16px;
  padding: 14px 16px;
  border-radius: 18px;
  background: color-mix(in srgb, var(--mac-surface-strong) 82%, transparent);
}

.security-key-meta {
  display: grid;
  gap: 4px;
}

.security-key-meta span {
  color: var(--mac-text-secondary);
  font-size: 0.82rem;
}

.security-empty {
  padding: 16px;
  border-radius: 18px;
  background: color-mix(in srgb, var(--mac-surface-strong) 82%, transparent);
  color: var(--mac-text-secondary);
}

@media (max-width: 900px) {
  .security-grid,
  .security-key-row {
    grid-template-columns: 1fr;
  }

  .security-card-header,
  .security-created-header,
  .security-create-row,
  .security-key-actions,
  .security-actions {
    flex-direction: column;
    align-items: stretch;
  }

  .security-badge {
    width: fit-content;
  }
}
</style>
