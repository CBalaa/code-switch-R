<script setup lang="ts">
import { computed, ref, onActivated, onDeactivated, onMounted, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { Call } from '@wailsio/runtime'
import ListItem from '../Setting/ListRow.vue'
import LanguageSwitcher from '../Setting/LanguageSwitcher.vue'
import ThemeSetting from '../Setting/ThemeSetting.vue'
import SecuritySettings from '../Setting/SecuritySettings.vue'
import { fetchAppSettings, saveAppSettings, type AppSettings } from '../../services/appSettings'
import { fetchTrafficSummary, type TrafficSummary } from '../../services/logs'
import { logoutAdmin } from '../../services/adminAuth'
import { extractErrorMessage } from '../../utils/error'
import { showToast } from '../../utils/toast'
import { useI18n } from 'vue-i18n'

const { t } = useI18n()
const isWebRuntime = true

const router = useRouter()
// 从 localStorage 读取缓存值作为初始值，避免加载时的视觉闪烁
const getCachedValue = (key: string, defaultValue: boolean): boolean => {
  const cached = localStorage.getItem(`app-settings-${key}`)
  return cached !== null ? cached === 'true' : defaultValue
}
const homeTitleVisible = ref(getCachedValue('homeTitle', true))
const autoStartEnabled = ref(getCachedValue('autoStart', false))
const autoConnectivityTestEnabled = ref(getCachedValue('autoConnectivityTest', false))
const switchNotifyEnabled = ref(getCachedValue('switchNotify', true)) // 切换通知开关
const proxyLatencyMultithreadingEnabled = ref(true)
const proxyLatencyMaxConcurrency = ref(3)
const settingsLoading = ref(true)
const saveBusy = ref(false)
const logoutBusy = ref(false)
const trafficStats = ref<TrafficSummary | null>(null)
const TRAFFIC_AUTO_REFRESH_INTERVAL_MS = 30_000
let trafficAutoRefreshTimer: number | undefined
let trafficStatsPromise: Promise<void> | null = null
let isPageActive = false
let isUnmounted = false

const goBack = () => {
  router.push('/')
}

const handleLogout = async () => {
  if (logoutBusy.value) return

  logoutBusy.value = true
  try {
    await logoutAdmin()
    showToast(t('auth.security.logoutSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.logoutFailed')), 'error')
  } finally {
    logoutBusy.value = false
  }
}

const loadAppSettings = async () => {
  settingsLoading.value = true
  try {
    const data = await fetchAppSettings()
    homeTitleVisible.value = data?.show_home_title ?? true
    autoStartEnabled.value = data?.auto_start ?? false
    autoConnectivityTestEnabled.value = data?.auto_connectivity_test ?? false
    switchNotifyEnabled.value = data?.enable_switch_notify ?? true
    proxyLatencyMultithreadingEnabled.value = data?.enable_proxy_latency_multithreading ?? true
    proxyLatencyMaxConcurrency.value = data?.proxy_latency_max_concurrency ?? 3

    // 缓存到 localStorage，下次打开时直接显示正确状态
    localStorage.setItem('app-settings-homeTitle', String(homeTitleVisible.value))
    localStorage.setItem('app-settings-autoStart', String(autoStartEnabled.value))
    localStorage.setItem('app-settings-autoConnectivityTest', String(autoConnectivityTestEnabled.value))
    localStorage.setItem('app-settings-switchNotify', String(switchNotifyEnabled.value))
  } catch (error) {
    console.error('failed to load app settings', error)
    homeTitleVisible.value = true
    autoStartEnabled.value = false
    autoConnectivityTestEnabled.value = false
    switchNotifyEnabled.value = true
    proxyLatencyMultithreadingEnabled.value = true
    proxyLatencyMaxConcurrency.value = 3
  } finally {
    settingsLoading.value = false
  }
}

const persistAppSettings = async () => {
  if (settingsLoading.value || saveBusy.value) return
  saveBusy.value = true
  try {
    proxyLatencyMaxConcurrency.value = Math.min(4, Math.max(1, Math.trunc(proxyLatencyMaxConcurrency.value || 1)))
    const payload: AppSettings = {
      show_home_title: homeTitleVisible.value,
      auto_start: autoStartEnabled.value,
      auto_connectivity_test: autoConnectivityTestEnabled.value,
      enable_switch_notify: switchNotifyEnabled.value,
      enable_proxy_latency_multithreading: proxyLatencyMultithreadingEnabled.value,
      proxy_latency_max_concurrency: proxyLatencyMaxConcurrency.value,
    }
    await saveAppSettings(payload)

    // 同步自动可用性监控设置到 HealthCheckService（复用旧字段名）
    await Call.ByName(
      'codeswitch/services.HealthCheckService.SetAutoAvailabilityPolling',
      autoConnectivityTestEnabled.value
    )

    // 更新缓存
    localStorage.setItem('app-settings-homeTitle', String(homeTitleVisible.value))
    localStorage.setItem('app-settings-autoStart', String(autoStartEnabled.value))
    localStorage.setItem('app-settings-autoConnectivityTest', String(autoConnectivityTestEnabled.value))
    localStorage.setItem('app-settings-switchNotify', String(switchNotifyEnabled.value))

    window.dispatchEvent(new CustomEvent('app-settings-updated'))
  } catch (error) {
    console.error('failed to save app settings', error)
  } finally {
    saveBusy.value = false
  }
}

const formatBytes = (value?: number) => {
  const bytes = Math.max(Number(value) || 0, 0)
  if (bytes < 1024) return `${Math.round(bytes)} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB']
  let amount = bytes / 1024
  let unit = units[0]
  for (let index = 1; index < units.length && amount >= 1024; index += 1) {
    amount /= 1024
    unit = units[index]
  }
  return `${amount >= 100 ? amount.toFixed(0) : amount >= 10 ? amount.toFixed(1) : amount.toFixed(2)} ${unit}`
}

const trafficBodyTotal = (value?: { ingress_bytes?: number; egress_bytes?: number } | null) =>
  (value?.ingress_bytes ?? 0) + (value?.egress_bytes ?? 0)

const trafficDirectionHint = (value?: { ingress_bytes?: number; egress_bytes?: number } | null) =>
  t('components.general.traffic.inOut', {
    ingress: formatBytes(value?.ingress_bytes),
    egress: formatBytes(value?.egress_bytes),
  })

const trafficCards = computed(() => {
  const data = trafficStats.value
  return [
    {
      key: 'relay-client',
      label: t('components.general.traffic.relayClient'),
      value: data ? formatBytes(trafficBodyTotal(data.relay_client)) : '—',
      hint: data ? trafficDirectionHint(data.relay_client) : '—',
    },
    {
      key: 'upstream',
      label: t('components.general.traffic.upstream'),
      value: data ? formatBytes(trafficBodyTotal(data.upstream)) : '—',
      hint: data ? trafficDirectionHint(data.upstream) : '—',
    },
    {
      key: 'retry',
      label: t('components.general.traffic.retry'),
      value: data ? formatBytes(trafficBodyTotal(data.retry)) : '—',
      hint: data ? trafficDirectionHint(data.retry) : '—',
    },
    {
      key: 'admin',
      label: t('components.general.traffic.admin'),
      value: data ? formatBytes(trafficBodyTotal(data.admin)) : '—',
      hint: data ? trafficDirectionHint(data.admin) : '—',
    },
  ]
})

const loadTrafficStats = (): Promise<void> => {
  if (trafficStatsPromise) return trafficStatsPromise
  trafficStatsPromise = fetchTrafficSummary()
    .then((traffic) => {
      if (!isUnmounted) trafficStats.value = traffic ?? null
    })
    .catch((error) => {
      console.error('failed to load traffic stats', error)
    })
    .finally(() => {
      trafficStatsPromise = null
    })
  return trafficStatsPromise
}

const canPollTraffic = () =>
  isPageActive && !isUnmounted && document.visibilityState === 'visible'

const stopTrafficAutoRefresh = () => {
  if (trafficAutoRefreshTimer !== undefined) {
    clearInterval(trafficAutoRefreshTimer)
    trafficAutoRefreshTimer = undefined
  }
}

const startTrafficAutoRefresh = () => {
  stopTrafficAutoRefresh()
  if (!canPollTraffic()) return
  trafficAutoRefreshTimer = window.setInterval(() => {
    if (canPollTraffic()) void loadTrafficStats()
  }, TRAFFIC_AUTO_REFRESH_INTERVAL_MS)
}

const syncTrafficPollingState = () => {
  if (canPollTraffic()) {
    startTrafficAutoRefresh()
  } else {
    stopTrafficAutoRefresh()
  }
}

const handleVisibilityChange = () => {
  syncTrafficPollingState()
  if (canPollTraffic()) void loadTrafficStats()
}

onMounted(async () => {
  isUnmounted = false
  isPageActive = true
  document.addEventListener('visibilitychange', handleVisibilityChange)
  await Promise.all([loadAppSettings(), loadTrafficStats()])
  syncTrafficPollingState()
})

onActivated(() => {
  const wasActive = isPageActive
  isPageActive = true
  syncTrafficPollingState()
  if (!wasActive && canPollTraffic()) void loadTrafficStats()
})

onDeactivated(() => {
  isPageActive = false
  syncTrafficPollingState()
})

onUnmounted(() => {
  isUnmounted = true
  isPageActive = false
  document.removeEventListener('visibilitychange', handleVisibilityChange)
  stopTrafficAutoRefresh()
})
</script>

<template>
  <div class="main-shell general-shell">
    <div class="global-actions">
      <p class="global-eyebrow">{{ $t('components.general.title.application') }}</p>
      <button class="settings-logout-button" type="button" :disabled="logoutBusy" @click="handleLogout">
        {{ $t('auth.security.logout') }}
      </button>
      <button class="ghost-icon" :aria-label="$t('components.general.buttons.back')" @click="goBack">
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path
            d="M15 18l-6-6 6-6"
            fill="none"
            stroke="currentColor"
            stroke-width="1.5"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
    </div>

    <div class="general-page">
      <h1 class="sr-only">{{ $t('sidebar.settings') }}</h1>
      <section>
        <h2 class="mac-section-title">{{ $t('components.general.title.application') }}</h2>
        <div class="mac-panel">
          <ListItem v-slot="{ labelId }" :label="$t('components.general.label.homeTitle')">
            <label class="mac-switch">
              <input
                type="checkbox"
                role="switch"
                :aria-checked="homeTitleVisible"
                :aria-labelledby="labelId"
                :disabled="settingsLoading || saveBusy"
                v-model="homeTitleVisible"
                data-testid="setting-home-title"
                @change="persistAppSettings"
              />
              <span aria-hidden="true"></span>
            </label>
          </ListItem>
          <ListItem v-if="!isWebRuntime" v-slot="{ labelId }" :label="$t('components.general.label.autoStart')">
            <label class="mac-switch">
              <input
                type="checkbox"
                role="switch"
                :aria-checked="autoStartEnabled"
                :aria-labelledby="labelId"
                :disabled="settingsLoading || saveBusy"
                v-model="autoStartEnabled"
                data-testid="setting-auto-start"
                @change="persistAppSettings"
              />
              <span aria-hidden="true"></span>
            </label>
          </ListItem>
          <ListItem v-slot="{ labelId }" :label="$t('components.general.label.switchNotify')">
            <div class="toggle-with-hint">
              <label class="mac-switch">
                <input
                  type="checkbox"
                  role="switch"
                  :aria-checked="switchNotifyEnabled"
                  :aria-labelledby="labelId"
                  :disabled="settingsLoading || saveBusy"
                  v-model="switchNotifyEnabled"
                  data-testid="setting-switch-notify"
                  @change="persistAppSettings"
                />
                <span aria-hidden="true"></span>
              </label>
              <span class="hint-text">{{ $t('components.general.label.switchNotifyHint') }}</span>
            </div>
          </ListItem>
        </div>
      </section>

      <section>
        <h2 class="mac-section-title">{{ $t('components.general.title.connectivity') }}</h2>
        <div class="mac-panel">
          <ListItem v-slot="{ labelId }" :label="$t('components.general.label.autoConnectivityTest')">
            <div class="toggle-with-hint">
              <label class="mac-switch">
                <input
                  type="checkbox"
                  role="switch"
                  :aria-checked="autoConnectivityTestEnabled"
                  :aria-labelledby="labelId"
                  :disabled="settingsLoading || saveBusy"
                  v-model="autoConnectivityTestEnabled"
                  data-testid="setting-auto-connectivity"
                  @change="persistAppSettings"
                />
                <span aria-hidden="true"></span>
              </label>
              <span class="hint-text">{{ $t('components.general.label.autoConnectivityTestHint') }}</span>
            </div>
          </ListItem>
          <ListItem v-slot="{ labelId }" :label="$t('components.general.label.proxyLatencyMultithreading')">
            <div class="toggle-with-hint">
              <label class="mac-switch">
                <input
                  type="checkbox"
                  role="switch"
                  :aria-checked="proxyLatencyMultithreadingEnabled"
                  :aria-labelledby="labelId"
                  :disabled="settingsLoading || saveBusy"
                  v-model="proxyLatencyMultithreadingEnabled"
                  data-testid="setting-proxy-multithreading"
                  @change="persistAppSettings"
                />
                <span aria-hidden="true"></span>
              </label>
              <span class="hint-text">{{ $t('components.general.label.proxyLatencyMultithreadingHint') }}</span>
            </div>
          </ListItem>
          <ListItem v-if="proxyLatencyMultithreadingEnabled" v-slot="{ labelId }" :label="$t('components.general.label.proxyLatencyMaxConcurrency')">
            <input
              v-model.number="proxyLatencyMaxConcurrency"
              class="mac-input"
              type="number"
              min="1"
              max="4"
              step="1"
              :aria-labelledby="labelId"
              :disabled="settingsLoading || saveBusy"
              data-testid="setting-proxy-max-concurrency"
              @change="persistAppSettings"
            />
          </ListItem>
        </div>
      </section>

      <SecuritySettings />

      <section>
        <h2 class="mac-section-title">{{ $t('components.general.title.exterior') }}</h2>
        <div class="mac-panel">
          <ListItem :label="$t('components.general.label.language')">
            <LanguageSwitcher />
          </ListItem>
          <ListItem :label="$t('components.general.label.theme')">
            <ThemeSetting />
          </ListItem>
        </div>
      </section>

      <section class="traffic-settings-section">
        <div class="traffic-section-heading">
          <h2 class="mac-section-title">{{ $t('components.general.traffic.title') }}</h2>
          <span>{{ $t('components.general.traffic.window') }}</span>
        </div>
        <div class="mac-panel traffic-panel">
          <p v-if="trafficStats?.dropped_events" class="traffic-warning">
            {{ $t('components.general.traffic.dropped', { count: trafficStats.dropped_events }) }}
          </p>
          <div class="traffic-grid">
            <article v-for="card in trafficCards" :key="card.key" class="traffic-metric">
              <div class="traffic-metric__label">{{ card.label }}</div>
              <div class="traffic-metric__value">{{ card.value }}</div>
              <div class="traffic-metric__hint">{{ card.hint }}</div>
            </article>
          </div>
        </div>
      </section>
    </div>
  </div>
</template>

<style scoped>
.mac-input {
  padding: 6px 12px;
  border: 1px solid var(--mac-border);
  border-radius: 6px;
  background: var(--mac-surface);
  color: var(--mac-text);
  font-size: 13px;
  font-family: monospace;
  min-width: 160px;
  transition: border-color 0.2s;
}

.mac-input:focus {
  outline: none;
  border-color: var(--mac-accent);
}

.panel-title {
  margin: 0;
  padding: 12px 18px 6px;
  font-size: 12px;
  font-weight: 600;
  color: var(--mac-text-secondary);
  letter-spacing: 0.02em;
  border-bottom: 1px solid var(--mac-divider);
}

.mac-panel + .mac-panel {
  margin-top: 12px;
}

.traffic-section-heading {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 16px;
}

.traffic-section-heading span {
  color: var(--mac-text-secondary);
  font-size: 12px;
}

.traffic-panel {
  padding: 18px;
}

.traffic-warning {
  margin: 0 0 14px;
  color: #dc2626;
  font-size: 12px;
}

.traffic-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 16px;
}

.traffic-metric {
  min-width: 0;
}

.traffic-metric__label,
.traffic-metric__hint {
  color: var(--mac-text-secondary);
  font-size: 12px;
}

.traffic-metric__value {
  margin: 6px 0 4px;
  color: var(--mac-text);
  font-size: 18px;
  font-weight: 650;
  overflow-wrap: anywhere;
}

.settings-logout-button {
  min-height: 34px;
  border: 1px solid color-mix(in srgb, #ef4444 28%, var(--mac-border));
  border-radius: 10px;
  background: color-mix(in srgb, #ef4444 10%, var(--mac-surface));
  color: #b91c1c;
  font-size: 0.88rem;
  font-weight: 700;
  cursor: pointer;
  transition: background 0.18s ease, border-color 0.18s ease, opacity 0.18s ease;
}

.settings-logout-button:hover:not(:disabled) {
  border-color: color-mix(in srgb, #ef4444 45%, var(--mac-border));
  background: color-mix(in srgb, #ef4444 15%, var(--mac-surface));
}

.settings-logout-button:disabled {
  cursor: wait;
  opacity: 0.65;
}

.toggle-with-hint {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.input-with-hint {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 4px;
}

.hint-text {
  font-size: 11px;
  color: var(--mac-text-secondary);
  line-height: 1.4;
  max-width: 320px;
  text-align: right;
  white-space: nowrap;
}

:global(.dark) .hint-text {
  color: rgba(255, 255, 255, 0.5);
}

:global(.dark) .mac-input {
  background: var(--mac-surface-strong);
}

@media (max-width: 760px) {
  .traffic-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .traffic-section-heading {
    align-items: flex-start;
    flex-direction: column;
    gap: 2px;
  }

  .mac-input {
    width: 100%;
    min-width: 0;
    box-sizing: border-box;
  }

  .toggle-with-hint {
    align-items: flex-start;
    width: 100%;
  }

  .input-with-hint {
    align-items: flex-start;
    width: 100%;
  }

  .hint-text {
    max-width: 100%;
    text-align: left;
    white-space: normal;
  }
}
</style>
