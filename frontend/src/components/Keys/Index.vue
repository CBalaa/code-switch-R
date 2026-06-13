<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import {
  Chart,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Tooltip,
  Legend,
} from 'chart.js'
import type { ChartOptions } from 'chart.js'
import { Line } from 'vue-chartjs'
import {
  createCodexRelayKey,
  deleteCodexRelayKey,
  fetchCodexRelayKeyUsage,
  getCodexRelayKeySecret,
  listCodexRelayKeys,
  renameCodexRelayKey,
  type CodexRelayKeyCreateResult,
  type CodexRelayKeyListItem,
  type CodexRelayKeyUsageRange,
  type CodexRelayKeyUsageStats,
} from '../../services/adminAuth'
import { extractErrorMessage } from '../../utils/error'
import { showToast } from '../../utils/toast'
import { notifyRelayKeysUpdated } from '../../events/relayKeys'

Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

const { t } = useI18n()

const ranges: Array<{ value: CodexRelayKeyUsageRange; labelKey: string }> = [
  { value: '1h', labelKey: 'keys.ranges.oneHour' },
  { value: '5h', labelKey: 'keys.ranges.fiveHours' },
  { value: '1d', labelKey: 'keys.ranges.oneDay' },
  { value: '1w', labelKey: 'keys.ranges.oneWeek' },
  { value: '1mo', labelKey: 'keys.ranges.oneMonth' },
  { value: 'custom', labelKey: 'keys.ranges.custom' },
]

const tabs = [
  { id: 'management', labelKey: 'keys.tabs.management' },
  { id: 'usage', labelKey: 'keys.tabs.usage' },
] as const

type KeyTab = (typeof tabs)[number]['id']
type UsageMetric = 'tokens' | 'calls'

const chartColors = [
  '#0a84ff',
  '#10b981',
  '#f59e0b',
  '#ef4444',
  '#8b5cf6',
  '#06b6d4',
  '#ec4899',
  '#84cc16',
  '#f97316',
  '#14b8a6',
]

const keys = ref<CodexRelayKeyListItem[]>([])
const activeTab = ref<KeyTab>('management')
const selectedKeyId = ref('')
const keysLoading = ref(false)
const keyBusyId = ref('')
const createBusy = ref(false)
const createName = ref('')
const createdKey = ref<CodexRelayKeyCreateResult | null>(null)
const renameKeyId = ref('')
const renameName = ref('')
const usageRange = ref<CodexRelayKeyUsageRange>('1h')
const usageMetric = ref<UsageMetric>('tokens')
const usageLoading = ref(false)
const usageStatsByKey = ref<Record<string, CodexRelayKeyUsageStats>>({})

const toDateTimeLocalValue = (date: Date) => {
  const offsetMs = date.getTimezoneOffset() * 60 * 1000
  return new Date(date.getTime() - offsetMs).toISOString().slice(0, 16)
}

const customUsageStart = ref(toDateTimeLocalValue(new Date(Date.now() - 60 * 60 * 1000)))
const customUsageEnd = ref(toDateTimeLocalValue(new Date()))

const usageTotals = computed(() => {
  return Object.values(usageStatsByKey.value).reduce(
    (total, stats) => ({
      tokens: total.tokens + Number(stats?.totalTokens ?? 0),
      calls: total.calls + Number(stats?.totalCalls ?? 0),
    }),
    { tokens: 0, calls: 0 },
  )
})

const formatDateTime = (value: string) => {
  if (!value) return '--'
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

const padTimeUnit = (value: number) => value.toString().padStart(2, '0')

const formatUsageBucketLabel = (bucket: string) => {
  const date = new Date(bucket)
  if (Number.isNaN(date.getTime())) return bucket
  if (usageRange.value === '1w' || usageRange.value === '1mo') {
    return `${padTimeUnit(date.getMonth() + 1)}-${padTimeUnit(date.getDate())}`
  }
  if (usageRange.value === 'custom') {
    const start = new Date(customUsageStart.value)
    const end = new Date(customUsageEnd.value)
    if (!Number.isNaN(start.getTime()) && !Number.isNaN(end.getTime()) && end.getTime() - start.getTime() > 24 * 60 * 60 * 1000) {
      return `${padTimeUnit(date.getMonth() + 1)}-${padTimeUnit(date.getDate())} ${padTimeUnit(date.getHours())}:${padTimeUnit(date.getMinutes())}`
    }
  }
  return `${padTimeUnit(date.getHours())}:${padTimeUnit(date.getMinutes())}`
}

const formatNumber = (value?: number) => {
  const numeric = Number(value ?? 0)
  return new Intl.NumberFormat().format(numeric)
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
    if (!selectedKeyId.value || !keys.value.some((key) => key.id === selectedKeyId.value)) {
      selectedKeyId.value = keys.value[0]?.id ?? ''
    }
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.loadKeysFailed')), 'error')
  } finally {
    keysLoading.value = false
  }
}

const loadUsage = async () => {
  if (keys.value.length === 0) {
    usageStatsByKey.value = {}
    return
  }

  let start: string | undefined
  let end: string | undefined
  if (usageRange.value === 'custom') {
    const startDate = new Date(customUsageStart.value)
    const endDate = new Date(customUsageEnd.value)
    if (Number.isNaN(startDate.getTime()) || Number.isNaN(endDate.getTime()) || endDate <= startDate) {
      showToast(t('keys.errors.invalidCustomRange'), 'error')
      return
    }
    start = startDate.toISOString()
    end = endDate.toISOString()
  }

  usageLoading.value = true
  try {
    const entries = await Promise.all(
      keys.value.map(async (key) => {
        const stats = await fetchCodexRelayKeyUsage(key.id, usageRange.value, start, end)
        return [key.id, stats] as const
      }),
    )
    usageStatsByKey.value = Object.fromEntries(entries)
  } catch (error) {
    showToast(extractErrorMessage(error, t('keys.errors.loadUsage')), 'error')
  } finally {
    usageLoading.value = false
  }
}

const handleCreateKey = async () => {
  if (createBusy.value) return

  createBusy.value = true
  try {
    createdKey.value = await createCodexRelayKey(createName.value.trim())
    createName.value = ''
    await loadKeys()
    notifyRelayKeysUpdated()
    selectedKeyId.value = createdKey.value.id
    await loadUsage()
    showToast(t('auth.security.createSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.createFailed')), 'error')
  } finally {
    createBusy.value = false
  }
}

const handleCopyCreatedKey = async () => {
  if (!createdKey.value?.key) return

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

const startRename = (key: CodexRelayKeyListItem) => {
  renameKeyId.value = key.id
  renameName.value = key.name
}

const cancelRename = () => {
  renameKeyId.value = ''
  renameName.value = ''
}

const handleRenameKey = async (key: CodexRelayKeyListItem) => {
  const nextName = renameName.value.trim()
  if (!nextName || keyBusyId.value) return

  keyBusyId.value = key.id
  try {
    await renameCodexRelayKey(key.id, nextName)
    cancelRename()
    await loadKeys()
    notifyRelayKeysUpdated()
    showToast(t('keys.renameSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('keys.errors.rename')), 'error')
  } finally {
    keyBusyId.value = ''
  }
}

const handleDeleteKey = async (key: CodexRelayKeyListItem) => {
  if (!window.confirm(t('auth.security.deleteConfirm', { name: key.name }))) return

  keyBusyId.value = key.id
  try {
    await deleteCodexRelayKey(key.id)
    if (createdKey.value?.id === key.id) {
      createdKey.value = null
    }
    await loadKeys()
    notifyRelayKeysUpdated()
    await loadUsage()
    showToast(t('auth.security.deleteSuccess'), 'success')
  } catch (error) {
    showToast(extractErrorMessage(error, t('auth.security.deleteFailed')), 'error')
  } finally {
    keyBusyId.value = ''
  }
}

const handleUsageRangeClick = (range: CodexRelayKeyUsageRange) => {
  usageRange.value = range
  if (range !== 'custom') {
    void loadUsage()
  }
}

const handleApplyCustomUsageRange = () => {
  usageRange.value = 'custom'
  void loadUsage()
}

const chartData = computed(() => {
  const firstStats = keys.value
    .map((key) => usageStatsByKey.value[key.id])
    .find((stats) => stats?.points?.length)
  const points = firstStats?.points ?? []
  const buckets = points.map((point) => point.bucket || point.label)
  return {
    labels: points.map((point) => formatUsageBucketLabel(point.bucket || point.label)),
    datasets: keys.value.map((key, index) => {
      const stats = usageStatsByKey.value[key.id]
      const color = chartColors[index % chartColors.length]
      return {
        label: key.name,
        data: buckets.map((bucket) => {
          const point = (stats?.points ?? []).find((item) => (item.bucket || item.label) === bucket)
          if (!point) return 0
          return usageMetric.value === 'tokens' ? point.totalTokens : point.calls
        }),
        borderColor: color,
        backgroundColor: color,
        tension: 0.32,
        fill: false,
        yAxisID: 'value',
      }
    }),
  }
})

const chartOptions: ChartOptions<'line'> = {
  responsive: true,
  maintainAspectRatio: false,
  interaction: {
    mode: 'index',
    intersect: false,
  },
  plugins: {
    legend: {
      labels: {
        color: '#64748b',
        boxWidth: 12,
        usePointStyle: true,
      },
    },
  },
  scales: {
    x: {
      grid: { display: false },
      ticks: { color: '#94a3b8', maxRotation: 0 },
    },
    value: {
      beginAtZero: true,
      ticks: { color: '#64748b', precision: 0 },
      grid: { color: 'rgba(148, 163, 184, 0.18)' },
    },
  },
}

onMounted(async () => {
  await loadKeys()
  await loadUsage()
})
</script>

<template>
  <div class="keys-page">
    <header class="keys-header">
      <div>
        <p class="keys-eyebrow">{{ t('keys.eyebrow') }}</p>
        <h1>{{ t('keys.title') }}</h1>
        <p>{{ t('keys.subtitle') }}</p>
      </div>
    </header>

    <div class="keys-tab-bar" role="tablist" :aria-label="t('keys.tabs.ariaLabel')">
      <button
        v-for="tab in tabs"
        :key="tab.id"
        class="keys-tab"
        :class="{ active: activeTab === tab.id }"
        type="button"
        role="tab"
        :aria-selected="activeTab === tab.id"
        @click="activeTab = tab.id"
      >
        {{ t(tab.labelKey) }}
      </button>
    </div>

    <section class="keys-content">
      <div v-if="activeTab === 'management'" class="keys-panel keys-manager">
        <div class="panel-heading">
          <div>
            <h2>{{ t('keys.management') }}</h2>
            <p>{{ t('keys.managementHint') }}</p>
          </div>
        </div>

        <div class="create-row">
          <input
            v-model="createName"
            class="keys-input"
            type="text"
            :placeholder="t('auth.security.createPlaceholder')"
            :disabled="createBusy"
            @keyup.enter="handleCreateKey"
          />
          <button class="primary-btn" :disabled="createBusy" @click="handleCreateKey">
            {{ createBusy ? t('auth.security.creating') : t('auth.security.create') }}
          </button>
        </div>

        <div v-if="createdKey" class="created-key">
          <div>
            <strong>{{ t('auth.security.oneTimeTitle') }}</strong>
            <p>{{ t('auth.security.oneTimeDescription') }}</p>
          </div>
          <code>{{ createdKey.key }}</code>
          <button class="secondary-btn" @click="handleCopyCreatedKey">
            {{ t('auth.security.copy') }}
          </button>
        </div>

        <div v-if="keysLoading" class="empty-state">{{ t('auth.security.loadingKeys') }}</div>
        <div v-else-if="keys.length === 0" class="empty-state">{{ t('auth.security.empty') }}</div>
        <div v-else class="key-list">
          <article
            v-for="key in keys"
            :key="key.id"
            class="key-row"
            :class="{ selected: key.id === selectedKeyId }"
            @click="selectedKeyId = key.id"
          >
            <div class="key-main">
              <template v-if="renameKeyId === key.id">
                <input
                  v-model="renameName"
                  class="rename-input"
                  type="text"
                  @keyup.enter.stop="handleRenameKey(key)"
                  @keyup.esc.stop="cancelRename"
                  @click.stop
                />
              </template>
              <template v-else>
                <strong>{{ key.name }}</strong>
                <span>{{ formatDateTime(key.createdAt) }}</span>
              </template>
            </div>
            <code>{{ key.maskedKey }}</code>
            <div class="key-actions" @click.stop>
              <template v-if="renameKeyId === key.id">
                <button class="secondary-btn" :disabled="keyBusyId === key.id" @click="handleRenameKey(key)">
                  {{ t('common.save') }}
                </button>
                <button class="ghost-btn" @click="cancelRename">{{ t('common.cancel') }}</button>
              </template>
              <template v-else>
                <button class="secondary-btn" :disabled="keyBusyId === key.id" @click="handleCopyExistingKey(key.id)">
                  {{ t('auth.security.copy') }}
                </button>
                <button class="secondary-btn" @click="startRename(key)">{{ t('keys.rename') }}</button>
                <button class="danger-btn" :disabled="keyBusyId === key.id" @click="handleDeleteKey(key)">
                  {{ t('auth.security.delete') }}
                </button>
              </template>
            </div>
          </article>
        </div>
      </div>

      <div v-else class="keys-panel keys-usage">
        <div class="panel-heading usage-heading">
          <div>
            <h2>{{ t('keys.usage') }}</h2>
            <p>{{ t('keys.usageAllKeys') }}</p>
          </div>
          <div class="usage-controls">
            <div class="range-tabs">
              <button
                v-for="range in ranges"
                :key="range.value"
                :class="{ active: usageRange === range.value }"
                @click="handleUsageRangeClick(range.value)"
              >
                {{ t(range.labelKey) }}
              </button>
            </div>
            <div v-if="usageRange === 'custom'" class="custom-range-controls">
              <label>
                <span>{{ t('keys.customRange.start') }}</span>
                <input v-model="customUsageStart" type="datetime-local" />
              </label>
              <label>
                <span>{{ t('keys.customRange.end') }}</span>
                <input v-model="customUsageEnd" type="datetime-local" />
              </label>
              <button type="button" @click="handleApplyCustomUsageRange">
                {{ t('keys.customRange.apply') }}
              </button>
            </div>
            <div class="metric-tabs">
              <button
                :class="{ active: usageMetric === 'tokens' }"
                type="button"
                @click="usageMetric = 'tokens'"
              >
                {{ t('keys.chart.tokens') }}
              </button>
              <button
                :class="{ active: usageMetric === 'calls' }"
                type="button"
                @click="usageMetric = 'calls'"
              >
                {{ t('keys.chart.calls') }}
              </button>
            </div>
          </div>
        </div>

        <div class="usage-summary">
          <div>
            <span>{{ t('keys.summary.totalTokens') }}</span>
            <strong>{{ formatNumber(usageTotals.tokens) }}</strong>
          </div>
          <div>
            <span>{{ t('keys.summary.totalCalls') }}</span>
            <strong>{{ formatNumber(usageTotals.calls) }}</strong>
          </div>
        </div>

        <div class="chart-shell">
          <div v-if="usageLoading" class="chart-loading">{{ t('keys.loadingUsage') }}</div>
          <Line v-else :data="chartData" :options="chartOptions" />
        </div>
      </div>
    </section>
  </div>
</template>

<style scoped>
.keys-page {
  min-height: 100%;
  padding: 28px;
  background: var(--mac-bg);
  color: var(--mac-text);
}

.keys-header {
  margin-bottom: 18px;
}

.keys-eyebrow {
  margin: 0 0 8px;
  color: var(--mac-accent);
  font-size: 0.78rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.keys-header h1 {
  margin: 0;
  font-size: 1.9rem;
  letter-spacing: 0;
}

.keys-header p:last-child,
.panel-heading p {
  margin: 8px 0 0;
  color: var(--mac-text-secondary);
  line-height: 1.6;
}

.keys-tab-bar {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  max-width: 100%;
  margin-bottom: 18px;
  overflow-x: auto;
  white-space: nowrap;
}

.keys-tab {
  position: relative;
  min-height: 40px;
  border: none;
  border-radius: 999px;
  background: transparent;
  color: var(--mac-text-secondary);
  padding: 0 22px;
  font-weight: 700;
  cursor: pointer;
  transition: color 0.2s ease;
  isolation: isolate;
}

.keys-tab::before {
  content: '';
  position: absolute;
  inset: 0;
  z-index: -1;
  border-radius: inherit;
  background: transparent;
  transition: background 0.2s ease, box-shadow 0.2s ease;
}

.keys-tab.active {
  color: var(--mac-text);
}

.keys-tab.active::before {
  background: color-mix(in srgb, var(--mac-accent) 6%, var(--mac-surface-strong));
  box-shadow: inset 0 0 0 1px color-mix(in srgb, var(--mac-accent) 25%, transparent);
}

.keys-content {
  display: grid;
  gap: 18px;
}

.keys-panel {
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface);
  padding: 20px;
  box-shadow: 0 18px 42px rgba(15, 23, 42, 0.08);
}

.panel-heading {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  margin-bottom: 18px;
}

.panel-heading h2 {
  margin: 0;
  font-size: 1.08rem;
}

.create-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  gap: 10px;
  margin-bottom: 14px;
}

.keys-input,
.rename-input {
  min-height: 42px;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface-strong);
  color: var(--mac-text);
  padding: 0 12px;
  outline: none;
}

.rename-input {
  width: 100%;
}

.primary-btn,
.secondary-btn,
.danger-btn,
.ghost-btn {
  min-height: 38px;
  border: none;
  border-radius: 8px;
  padding: 0 12px;
  font-weight: 700;
  cursor: pointer;
  white-space: nowrap;
}

.primary-btn {
  min-height: 42px;
  color: #fff;
  background: linear-gradient(135deg, #0a84ff, #1271d5);
}

.secondary-btn,
.ghost-btn {
  background: color-mix(in srgb, var(--mac-text) 10%, var(--mac-surface));
  color: var(--mac-text);
}

.danger-btn {
  color: #fff;
  background: linear-gradient(135deg, #f43f5e, #e11d48);
}

button:disabled {
  opacity: 0.6;
  cursor: wait;
}

.created-key,
.empty-state,
.key-row {
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: color-mix(in srgb, var(--mac-surface-strong) 84%, transparent);
}

.created-key {
  display: grid;
  gap: 10px;
  margin-bottom: 14px;
  padding: 14px;
}

.created-key p {
  margin: 4px 0 0;
  color: var(--mac-text-secondary);
}

.created-key code,
.key-row code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  word-break: break-all;
}

.created-key code {
  padding: 12px;
  border-radius: 8px;
  background: var(--mac-bg);
}

.key-list {
  display: grid;
  gap: 10px;
}

.key-row {
  display: grid;
  grid-template-columns: minmax(150px, 0.9fr) minmax(170px, 0.8fr) auto;
  align-items: center;
  gap: 12px;
  padding: 14px;
  cursor: pointer;
  transition: border-color 0.18s ease, background 0.18s ease;
}

.key-row.selected {
  border-color: color-mix(in srgb, var(--mac-accent) 60%, var(--mac-border));
  background: color-mix(in srgb, var(--mac-accent) 8%, var(--mac-surface));
}

.key-main {
  display: grid;
  gap: 4px;
  min-width: 0;
}

.key-main span {
  color: var(--mac-text-secondary);
  font-size: 0.82rem;
}

.key-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.usage-heading {
  align-items: center;
}

.usage-controls {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 10px;
  flex-wrap: wrap;
}

.range-tabs,
.metric-tabs {
  display: inline-flex;
  gap: 4px;
  padding: 4px;
  border-radius: 8px;
  background: var(--mac-surface-strong);
}

.range-tabs button,
.metric-tabs button {
  min-height: 32px;
  border: none;
  border-radius: 6px;
  padding: 0 10px;
  background: transparent;
  color: var(--mac-text-secondary);
  font-weight: 700;
  cursor: pointer;
}

.range-tabs button.active,
.metric-tabs button.active {
  background: var(--mac-accent);
  color: #fff;
}

.custom-range-controls {
  display: flex;
  align-items: flex-end;
  gap: 8px;
  padding: 8px;
  border-radius: 8px;
  background: var(--mac-surface-strong);
}

.custom-range-controls label {
  display: grid;
  gap: 4px;
  color: var(--mac-text-secondary);
  font-size: 0.78rem;
  font-weight: 700;
}

.custom-range-controls input {
  min-height: 32px;
  border: 1px solid var(--mac-border);
  border-radius: 6px;
  background: var(--mac-surface);
  color: var(--mac-text);
  padding: 0 8px;
}

.custom-range-controls button {
  min-height: 32px;
  border: none;
  border-radius: 6px;
  padding: 0 12px;
  background: var(--mac-accent);
  color: #fff;
  font-weight: 700;
  cursor: pointer;
}

.usage-summary {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
  margin-bottom: 16px;
}

.usage-summary div {
  display: grid;
  gap: 6px;
  padding: 14px;
  border-radius: 8px;
  background: color-mix(in srgb, var(--mac-surface-strong) 86%, transparent);
}

.usage-summary span {
  color: var(--mac-text-secondary);
  font-size: 0.84rem;
}

.usage-summary strong {
  font-size: 1.55rem;
}

.chart-shell {
  position: relative;
  height: 360px;
}

.chart-loading {
  height: 100%;
  display: grid;
  place-items: center;
  color: var(--mac-text-secondary);
}

@media (max-width: 760px) {
  .keys-page {
    padding: 18px;
  }

  .keys-tab-bar {
    width: 100%;
  }

  .create-row,
  .key-row,
  .usage-summary {
    grid-template-columns: 1fr;
  }

  .panel-heading,
  .usage-heading {
    display: grid;
  }

  .usage-controls {
    justify-content: flex-start;
  }

  .range-tabs,
  .metric-tabs,
  .custom-range-controls {
    overflow-x: auto;
  }

  .custom-range-controls {
    width: 100%;
    flex-wrap: wrap;
  }

  .key-actions {
    justify-content: flex-start;
  }
}
</style>
