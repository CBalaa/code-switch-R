<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { initializeAdmin, loginAdmin, useAdminAuthState } from '../../services/adminAuth'
import { extractErrorMessage } from '../../utils/error'
import { showToast } from '../../utils/toast'

const { t } = useI18n()
const authState = useAdminAuthState()

const username = ref('')
const password = ref('')
const confirmPassword = ref('')
const setupToken = ref('')
const submitting = ref(false)

const isSetupMode = computed(() => !authState.initialized)

const submit = async () => {
  if (submitting.value) {
    return
  }

  if (isSetupMode.value && password.value !== confirmPassword.value) {
    showToast(t('auth.errors.passwordMismatch'), 'error')
    return
  }

  submitting.value = true
  try {
    if (isSetupMode.value) {
      await initializeAdmin(username.value.trim(), password.value, setupToken.value.trim())
      showToast(t('auth.setup.success'), 'success')
    } else {
      await loginAdmin(username.value.trim(), password.value)
      showToast(t('auth.login.success'), 'success')
    }
    password.value = ''
    confirmPassword.value = ''
    setupToken.value = ''
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.errors.requestFailed')), 'error')
  } finally {
    submitting.value = false
  }
}
</script>

<template>
  <div class="auth-shell">
    <div class="auth-grid">
      <section class="auth-hero">
        <p class="auth-eyebrow">{{ t('auth.eyebrow') }}</p>
        <h1 class="auth-title">{{ t('auth.title') }}</h1>
        <p class="auth-lead">{{ t('auth.lead') }}</p>
        <div class="auth-note">
          <span class="auth-note-label">{{ t('auth.noteTitle') }}</span>
          <span>{{ t('auth.noteBody') }}</span>
        </div>
      </section>

      <section class="auth-panel">
        <div v-if="!authState.ready || authState.loading" class="auth-loading">
          <span class="auth-spinner" aria-hidden="true"></span>
          <span>{{ t('auth.statusChecking') }}</span>
        </div>

        <form v-else class="auth-form" @submit.prevent="submit">
          <p class="auth-form-eyebrow">
            {{ isSetupMode ? t('auth.setup.eyebrow') : t('auth.login.eyebrow') }}
          </p>
          <h2 class="auth-form-title">
            {{ isSetupMode ? t('auth.setup.title') : t('auth.login.title') }}
          </h2>
          <p class="auth-form-description">
            {{ isSetupMode ? t('auth.setup.description') : t('auth.login.description') }}
          </p>

          <label class="auth-field">
            <span>{{ t('auth.fields.username') }}</span>
            <input
              v-model="username"
              class="base-input"
              type="text"
              autocomplete="username"
              :placeholder="t('auth.placeholders.username')"
              :disabled="submitting"
              required
            />
          </label>

          <label class="auth-field">
            <span>{{ t('auth.fields.password') }}</span>
            <input
              v-model="password"
              class="base-input"
              type="password"
              autocomplete="current-password"
              :placeholder="t('auth.placeholders.password')"
              :disabled="submitting"
              required
            />
          </label>

          <label v-if="isSetupMode" class="auth-field">
            <span>{{ t('auth.fields.confirmPassword') }}</span>
            <input
              v-model="confirmPassword"
              class="base-input"
              type="password"
              autocomplete="new-password"
              :placeholder="t('auth.placeholders.confirmPassword')"
              :disabled="submitting"
              required
            />
          </label>

          <label v-if="isSetupMode" class="auth-field">
            <span>{{ t('auth.fields.setupToken') }}</span>
            <input
              v-model="setupToken"
              class="base-input"
              type="password"
              autocomplete="one-time-code"
              :placeholder="t('auth.placeholders.setupToken')"
              :disabled="submitting"
            />
            <small>{{ t('auth.setup.tokenHint') }}</small>
          </label>

          <button class="auth-submit" type="submit" :disabled="submitting">
            {{
              submitting
                ? isSetupMode
                  ? t('auth.setup.submitting')
                  : t('auth.login.submitting')
                : isSetupMode
                  ? t('auth.setup.submit')
                  : t('auth.login.submit')
            }}
          </button>
        </form>
      </section>
    </div>
  </div>
</template>

<style scoped>
.auth-shell {
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 32px;
  background:
    radial-gradient(circle at top left, rgba(10, 132, 255, 0.18), transparent 28%),
    radial-gradient(circle at bottom right, rgba(34, 197, 94, 0.12), transparent 30%),
    var(--app-background);
}

.auth-grid {
  width: min(980px, 100%);
  display: grid;
  grid-template-columns: minmax(0, 1.1fr) minmax(360px, 0.9fr);
  gap: 24px;
}

.auth-hero,
.auth-panel {
  border: 1px solid var(--mac-border);
  border-radius: 28px;
  background: color-mix(in srgb, var(--mac-surface) 92%, transparent);
  box-shadow: 0 24px 60px rgba(15, 23, 42, 0.12);
}

.auth-hero {
  padding: 40px;
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: 20px;
}

.auth-eyebrow,
.auth-form-eyebrow {
  margin: 0;
  font-size: 0.8rem;
  font-weight: 700;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  color: var(--mac-accent);
}

.auth-title,
.auth-form-title {
  margin: 0;
  font-size: clamp(2rem, 4vw, 3.2rem);
  line-height: 1.02;
}

.auth-form-title {
  font-size: 1.9rem;
}

.auth-lead,
.auth-form-description {
  margin: 0;
  color: var(--mac-text-secondary);
  line-height: 1.7;
}

.auth-note {
  display: grid;
  gap: 6px;
  padding: 16px 18px;
  border-radius: 20px;
  background: color-mix(in srgb, var(--mac-accent) 10%, var(--mac-surface));
  border: 1px solid color-mix(in srgb, var(--mac-accent) 18%, transparent);
  color: var(--mac-text-secondary);
}

.auth-note-label {
  font-size: 0.82rem;
  font-weight: 700;
  color: var(--mac-text);
}

.auth-panel {
  padding: 28px;
  display: flex;
  align-items: center;
}

.auth-loading,
.auth-form {
  width: 100%;
}

.auth-loading {
  min-height: 240px;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 12px;
  color: var(--mac-text-secondary);
}

.auth-spinner {
  width: 32px;
  height: 32px;
  border-radius: 999px;
  border: 3px solid rgba(10, 132, 255, 0.18);
  border-top-color: var(--mac-accent);
  animation: auth-spin 0.9s linear infinite;
}

.auth-form {
  display: grid;
  gap: 16px;
}

.auth-field {
  display: grid;
  gap: 8px;
  font-size: 0.92rem;
  font-weight: 600;
}

.auth-submit {
  margin-top: 8px;
  min-height: 48px;
  border: none;
  border-radius: 16px;
  background: linear-gradient(135deg, #0a84ff 0%, #1271d5 100%);
  color: #fff;
  font-size: 0.96rem;
  font-weight: 700;
  cursor: pointer;
  transition: transform 0.18s ease, opacity 0.18s ease, box-shadow 0.18s ease;
  box-shadow: 0 16px 32px rgba(10, 132, 255, 0.24);
}

.auth-submit:hover:not(:disabled) {
  transform: translateY(-1px);
}

.auth-submit:disabled {
  opacity: 0.65;
  cursor: wait;
  box-shadow: none;
}

@keyframes auth-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (max-width: 900px) {
  .auth-grid {
    grid-template-columns: 1fr;
  }

  .auth-hero,
  .auth-panel {
    padding: 24px;
  }
}
</style>
