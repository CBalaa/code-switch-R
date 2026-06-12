<script setup lang="ts">
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  logoutAdmin,
  useAdminAuthState,
} from '../../services/adminAuth'
import { extractErrorMessage } from '../../utils/error'
import { showToast } from '../../utils/toast'

const { t } = useI18n()
const authState = useAdminAuthState()

const credentialsBusy = ref(false)

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

      <div class="security-actions">
        <button
          class="security-btn secondary"
          :disabled="credentialsBusy"
          @click="handleLogout"
        >
          {{ t('auth.security.logout') }}
        </button>
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
