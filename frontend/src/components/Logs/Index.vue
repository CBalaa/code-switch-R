<template>
  <div class="logs-page">
    <div class="logs-header">
      <BaseButton variant="outline" type="button" @click="backToHome">
        {{ t('components.logs.back') }}
      </BaseButton>
      <div class="refresh-indicator">
        <span>{{ t('components.logs.nextRefresh', { seconds: countdown }) }}</span>
        <BaseButton size="sm" :disabled="loading" @click="manualRefresh">
          {{ t('components.logs.refresh') }}
        </BaseButton>
      </div>
    </div>

    <section class="logs-summary" v-if="statsCards.length">
      <article
        v-for="card in statsCards"
        :key="card.key"
        :class="['summary-card', { 'summary-card--clickable': card.key === 'tokens' }]"
        @click="handleCardClick(card.key)"
      >
        <div class="summary-card__label">{{ card.label }}</div>
        <div class="summary-card__value">
          {{ card.value }}
          <span v-if="card.subValue" class="summary-card__sub-value">({{ card.subValue }})</span>
        </div>
        <div class="summary-card__hint">{{ card.hint }}</div>
      </article>
    </section>

    <section class="logs-chart">
      <Line :data="chartData" :options="chartOptions" />
    </section>

    <form class="logs-filter-row" @submit.prevent="applyFilters">
      <div class="filter-fields">
        <label class="filter-field">
          <span>{{ t('components.logs.filters.platform') }}</span>
          <select v-model="filters.platform" class="mac-select">
            <option value="">{{ t('components.logs.filters.allPlatforms') }}</option>
            <option value="claude">Claude</option>
            <option value="openai-responses">OpenAI Responses</option>
            <option value="openai-chat">OpenAI Chat</option>
          </select>
        </label>
        <label class="filter-field">
          <span>{{ t('components.logs.filters.provider') }}</span>
          <select v-model="filters.provider" class="mac-select">
            <option value="">{{ t('components.logs.filters.allProviders') }}</option>
            <option v-for="provider in providerOptions" :key="provider" :value="provider">
              {{ provider }}
            </option>
          </select>
        </label>
      </div>
      <div class="filter-actions">
        <BaseButton type="submit" :disabled="loading">
          {{ t('components.logs.query') }}
        </BaseButton>
      </div>
    </form>

    <section class="logs-table-wrapper">
      <table ref="logsTableRef" class="logs-table">
        <colgroup>
          <col
            v-for="column in logTableColumns"
            :key="column.id"
            :style="{ width: `${logColumnWidths[column.id]}%` }"
          />
        </colgroup>
        <thead>
          <tr>
            <th
              v-for="(column, index) in logTableColumns"
              :key="column.id"
              :class="[column.className, 'log-resizable-th', { 'is-resizing': resizingColumnId === column.id }]"
            >
              <span class="column-header-label">{{ t(column.labelKey) }}</span>
              <span
                v-if="index < logTableColumns.length - 1"
                class="column-resize-handle"
                role="separator"
                aria-orientation="vertical"
                @pointerdown="startLogColumnResize(index, $event)"
              ></span>
            </th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="item in pagedLogs" :key="item.id" :class="isProcessingLog(item) ? 'processing-row' : ''">
            <td :data-label="t('components.logs.table.time')">{{ formatTime(item.created_at) }}</td>
            <td :data-label="t('components.logs.table.platform')">{{ item.platform || '—' }}</td>
            <td :data-label="t('components.logs.table.provider')" class="provider-cell">{{ item.provider || '—' }}</td>
            <td :data-label="t('components.logs.table.relayKey')" class="relay-key-cell">{{ formatRelayKey(item) }}</td>
            <td :data-label="t('components.logs.table.model')">{{ item.model || '—' }}</td>
            <td :data-label="t('components.logs.table.clientIp')" class="client-ip-cell">{{ item.client_ip || '—' }}</td>
            <td :data-label="t('components.logs.table.httpCode')" :class="['code', httpCodeClassForLog(item)]">
              <span v-if="isProcessingLog(item)" class="processing-tag">{{ t('components.logs.status.processing') }}</span>
              <span v-else>{{ item.http_code || '—' }}</span>
            </td>
            <td :data-label="t('components.logs.table.stream')"><span :class="['stream-tag', item.is_stream ? 'on' : 'off']">{{ formatStream(item.is_stream) }}</span></td>
            <td :data-label="t('components.logs.table.firstToken')"><span :class="['duration-tag', durationColorForLog(item, item.first_token_duration_sec)]">{{ formatFirstTokenDuration(item) }}</span></td>
            <td :data-label="t('components.logs.table.duration')"><span :class="['duration-tag', durationColor(item.duration_sec)]">{{ formatDuration(item.duration_sec) }}</span></td>
            <td :data-label="t('components.logs.table.tokens')" class="token-cell">
              <div>
                <span class="token-label">{{ t('components.logs.tokenLabels.input') }}</span>
                <span class="token-value">{{ formatLogTokenNumber(item, item.input_tokens) }}</span>
              </div>
              <div>
                <span class="token-label">{{ t('components.logs.tokenLabels.output') }}</span>
                <span class="token-value">{{ formatLogTokenNumber(item, item.output_tokens) }}</span>
              </div>
              <div>
                <span class="token-label">{{ t('components.logs.tokenLabels.cacheCreate') }}</span>
                <span class="token-value">{{ formatLogTokenNumber(item, item.cache_create_tokens) }}</span>
              </div>
              <div>
                <span class="token-label">{{ t('components.logs.tokenLabels.cacheRead') }}</span>
                <span class="token-value">{{ formatLogTokenNumber(item, item.cache_read_tokens) }}</span>
              </div>
              <div>
                <span class="token-label">{{ t('components.logs.tokenLabels.reasoning') }}</span>
                <span class="token-value">{{ formatLogTokenNumber(item, item.reasoning_tokens) }}</span>
              </div>
            </td>
          </tr>
          <tr v-if="!pagedLogs.length && !loading">
            <td colspan="11" class="empty">{{ t('components.logs.empty') }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="loading" class="empty">{{ t('components.logs.loading') }}</p>
    </section>

    <div class="logs-pagination">
      <span>{{ page }} / {{ totalPages }}</span>
      <div class="pagination-actions">
        <BaseButton variant="outline" size="sm" :disabled="page === 1 || loading" @click="prevPage">
          ‹
        </BaseButton>
        <BaseButton variant="outline" size="sm" :disabled="page >= totalPages || loading" @click="nextPage">
          ›
        </BaseButton>
      </div>
    </div>

    <!-- Token 明细弹窗 -->
    <BaseModal
      :open="tokenDetailModal.open"
      :title="t('components.logs.tokenDetail.title')"
      @close="closeTokenDetailModal"
    >
      <div class="token-detail-modal">
        <div class="token-detail-list">
          <div class="token-detail-item">
            <span class="token-detail-item__name">{{ t('components.logs.tokenLabels.input') }}</span>
            <span class="token-detail-item__value">{{ formatTokenNumber(stats?.input_tokens) }}</span>
          </div>
          <div class="token-detail-item">
            <span class="token-detail-item__name">{{ t('components.logs.tokenLabels.output') }}</span>
            <span class="token-detail-item__value">{{ formatTokenNumber(stats?.output_tokens) }}</span>
          </div>
          <div class="token-detail-item">
            <span class="token-detail-item__name">{{ t('components.logs.tokenLabels.cacheCreate') }}</span>
            <span class="token-detail-item__value">{{ formatTokenNumber(stats?.cache_create_tokens) }}</span>
          </div>
          <div class="token-detail-item">
            <span class="token-detail-item__name">{{ t('components.logs.tokenLabels.cacheRead') }}</span>
            <span class="token-detail-item__value">{{ formatTokenNumber(stats?.cache_read_tokens) }}</span>
          </div>
          <div class="token-detail-item">
            <span class="token-detail-item__name">{{ t('components.logs.tokenLabels.reasoning') }}</span>
            <span class="token-detail-item__value">{{ formatTokenNumber(stats?.reasoning_tokens) }}</span>
          </div>
        </div>
      </div>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref, onMounted, watch, onUnmounted } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import BaseModal from '../common/BaseModal.vue'
import {
  fetchRequestLogs,
  fetchLogProviders,
  fetchLogStats,
  type RequestLog,
  type LogStats,
  type LogStatsSeries,
  type LogPlatform,
} from '../../services/logs'
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

Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

const { t } = useI18n()
const router = useRouter()

const logs = ref<RequestLog[]>([])
const stats = ref<LogStats | null>(null)
const loading = ref(false)
const filters = reactive<{ platform: LogPlatform | ''; provider: string }>({ platform: '', provider: '' })
const page = ref(1)
const PAGE_SIZE = 15
const providerOptions = ref<string[]>([])
const statsSeries = computed<LogStatsSeries[]>(() => stats.value?.series ?? [])
const LOG_COLUMN_WIDTH_STORAGE_KEY = 'code-switch-r:logs-table-column-widths:v1'

const logTableColumns = [
  { id: 'time', className: 'col-time', labelKey: 'components.logs.table.time', defaultWidth: 11, minWidth: 120 },
  { id: 'platform', className: 'col-platform', labelKey: 'components.logs.table.platform', defaultWidth: 7, minWidth: 78 },
  { id: 'provider', className: 'col-provider', labelKey: 'components.logs.table.provider', defaultWidth: 12, minWidth: 96 },
  { id: 'relayKey', className: 'col-relay-key', labelKey: 'components.logs.table.relayKey', defaultWidth: 12, minWidth: 96 },
  { id: 'model', className: 'col-model', labelKey: 'components.logs.table.model', defaultWidth: 10, minWidth: 92 },
  { id: 'clientIp', className: 'col-client-ip', labelKey: 'components.logs.table.clientIp', defaultWidth: 8, minWidth: 86 },
  { id: 'http', className: 'col-http', labelKey: 'components.logs.table.httpCode', defaultWidth: 6, minWidth: 68 },
  { id: 'stream', className: 'col-stream', labelKey: 'components.logs.table.stream', defaultWidth: 6, minWidth: 72 },
  { id: 'firstToken', className: 'col-first-token', labelKey: 'components.logs.table.firstToken', defaultWidth: 7, minWidth: 82 },
  { id: 'duration', className: 'col-duration', labelKey: 'components.logs.table.duration', defaultWidth: 7, minWidth: 82 },
  { id: 'tokens', className: 'col-tokens', labelKey: 'components.logs.table.tokens', defaultWidth: 14, minWidth: 128 },
] as const

type LogTableColumnId = (typeof logTableColumns)[number]['id']
type LogColumnWidths = Record<LogTableColumnId, number>

const defaultLogColumnWidths = logTableColumns.reduce((acc, column) => {
  acc[column.id] = column.defaultWidth
  return acc
}, {} as LogColumnWidths)

const normalizeLogColumnWidths = (widths: LogColumnWidths): LogColumnWidths => {
  const total = logTableColumns.reduce((sum, column) => sum + (widths[column.id] || 0), 0)
  if (!Number.isFinite(total) || total <= 0) {
    return { ...defaultLogColumnWidths }
  }
  return logTableColumns.reduce((acc, column) => {
    acc[column.id] = (widths[column.id] / total) * 100
    return acc
  }, {} as LogColumnWidths)
}

const loadLogColumnWidths = (): LogColumnWidths => {
  try {
    const raw = window.localStorage.getItem(LOG_COLUMN_WIDTH_STORAGE_KEY)
    if (!raw) return { ...defaultLogColumnWidths }
    const parsed = JSON.parse(raw) as Partial<Record<LogTableColumnId, number>>
    const widths = { ...defaultLogColumnWidths }
    for (const column of logTableColumns) {
      const value = parsed[column.id]
      if (typeof value === 'number' && Number.isFinite(value) && value > 0) {
        widths[column.id] = value
      }
    }
    return normalizeLogColumnWidths(widths)
  } catch (error) {
    console.warn('failed to load log table column widths', error)
    return { ...defaultLogColumnWidths }
  }
}

const saveLogColumnWidths = () => {
  window.localStorage.setItem(LOG_COLUMN_WIDTH_STORAGE_KEY, JSON.stringify(logColumnWidths.value))
}

const logsTableRef = ref<HTMLTableElement | null>(null)
const logColumnWidths = ref<LogColumnWidths>(loadLogColumnWidths())
const resizingColumnId = ref<LogTableColumnId | null>(null)

let columnResizeState: {
  index: number
  startX: number
  leftStart: number
  rightStart: number
  tableWidth: number
} | null = null

const clampColumnWidth = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max)

const onLogColumnResizeMove = (event: PointerEvent) => {
  if (!columnResizeState) return
  const leftColumn = logTableColumns[columnResizeState.index]
  const rightColumn = logTableColumns[columnResizeState.index + 1]
  if (!leftColumn || !rightColumn) return

  const pairTotal = columnResizeState.leftStart + columnResizeState.rightStart
  const deltaPercent = ((event.clientX - columnResizeState.startX) / columnResizeState.tableWidth) * 100
  const leftMin = Math.min((leftColumn.minWidth / columnResizeState.tableWidth) * 100, pairTotal * 0.45)
  const rightMin = Math.min((rightColumn.minWidth / columnResizeState.tableWidth) * 100, pairTotal * 0.45)
  const nextLeft = clampColumnWidth(columnResizeState.leftStart + deltaPercent, leftMin, pairTotal - rightMin)

  logColumnWidths.value = {
    ...logColumnWidths.value,
    [leftColumn.id]: nextLeft,
    [rightColumn.id]: pairTotal - nextLeft,
  }
}

const stopLogColumnResize = () => {
  if (!columnResizeState) return
  columnResizeState = null
  resizingColumnId.value = null
  document.body.classList.remove('is-log-column-resizing')
  window.removeEventListener('pointermove', onLogColumnResizeMove)
  window.removeEventListener('pointerup', stopLogColumnResize)
  window.removeEventListener('pointercancel', stopLogColumnResize)
  saveLogColumnWidths()
}

const startLogColumnResize = (index: number, event: PointerEvent) => {
  const leftColumn = logTableColumns[index]
  const rightColumn = logTableColumns[index + 1]
  const tableWidth = logsTableRef.value?.getBoundingClientRect().width ?? 0
  if (!leftColumn || !rightColumn || tableWidth <= 0) return

  event.preventDefault()
  columnResizeState = {
    index,
    startX: event.clientX,
    leftStart: logColumnWidths.value[leftColumn.id],
    rightStart: logColumnWidths.value[rightColumn.id],
    tableWidth,
  }
  resizingColumnId.value = leftColumn.id
  document.body.classList.add('is-log-column-resizing')
  window.addEventListener('pointermove', onLogColumnResizeMove)
  window.addEventListener('pointerup', stopLogColumnResize)
  window.addEventListener('pointercancel', stopLogColumnResize)
}

// Token 明细弹窗状态
const tokenDetailModal = reactive<{
  open: boolean
}>({
  open: false,
})

// 处理卡片点击
const handleCardClick = (key: string) => {
  if (key === 'tokens') {
    openTokenDetailModal()
  }
}

// 打开 Token 明细弹窗
const openTokenDetailModal = () => {
  tokenDetailModal.open = true
}

// 关闭 Token 明细弹窗
const closeTokenDetailModal = () => {
  tokenDetailModal.open = false
}

const parseLogDate = (value?: string) => {
  if (!value) return null
  const normalize = value.replace(' ', 'T')
  const attempts = [value, `${normalize}`, `${normalize}Z`]
  for (const candidate of attempts) {
    const parsed = new Date(candidate)
    if (!Number.isNaN(parsed.getTime())) {
      return parsed
    }
  }
  const match = value.match(/^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2}) ([+-]\d{4}) UTC$/)
  if (match) {
    const [, day, time, zone] = match
    const zoneFormatted = `${zone.slice(0, 3)}:${zone.slice(3)}`
    const parsed = new Date(`${day}T${time}${zoneFormatted}`)
    if (!Number.isNaN(parsed.getTime())) {
      return parsed
    }
  }
  return null
}

const chartData = computed(() => {
  const series = statsSeries.value
  return {
    labels: series.map((item) => formatSeriesLabel(item.day)),
    datasets: [
      {
        label: t('components.logs.tokenLabels.input'),
        data: series.map((item) => item.input_tokens ?? 0),
        borderColor: '#34d399',
        backgroundColor: 'rgba(52, 211, 153, 0.25)',
        tension: 0.35,
        fill: true,
      },
      {
        label: t('components.logs.tokenLabels.output'),
        data: series.map((item) => item.output_tokens ?? 0),
        borderColor: '#60a5fa',
        backgroundColor: 'rgba(96, 165, 250, 0.2)',
        tension: 0.35,
        fill: true,
      },
      {
        label: t('components.logs.tokenLabels.cacheCreate'),
        data: series.map((item) => item.cache_create_tokens ?? 0),
        borderColor: '#f59e0b',
        backgroundColor: 'rgba(245, 158, 11, 0.12)',
        tension: 0.35,
        fill: false,
      },
      {
        label: t('components.logs.tokenLabels.cacheRead'),
        data: series.map((item) => item.cache_read_tokens ?? 0),
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56, 189, 248, 0.15)',
        tension: 0.35,
        fill: false,
      },
      {
        label: t('components.logs.tokenLabels.reasoning'),
        data: series.map((item) => item.reasoning_tokens ?? 0),
        borderColor: '#a78bfa',
        backgroundColor: 'rgba(167, 139, 250, 0.12)',
        tension: 0.35,
        fill: false,
      },
    ],
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
        color: '#0f172a',
        font: {
          size: 12,
          weight: 500,
        },
      },
    },
  },
  scales: {
    x: {
      grid: { display: false },
      ticks: { color: '#94a3b8' },
    },
    y: {
      beginAtZero: true,
      ticks: { color: '#94a3b8' },
      grid: { color: 'rgba(148, 163, 184, 0.2)' },
    },
  },
}
const formatSeriesLabel = (value?: string) => {
  if (!value) return ''
  const beijingTime = value.match(/^\d{4}-\d{2}-\d{2}[ T](\d{2}):(\d{2})/)
  if (beijingTime) {
    return `${beijingTime[1]}:${beijingTime[2]}`
  }
  const parsed = parseLogDate(value)
  if (parsed) {
    return `${padHour(parsed.getHours())}:00`
  }
  const match = value.match(/(\d{2}):(\d{2})/)
  if (match) {
    return `${match[1]}:${match[2]}`
  }
  return value
}

const REFRESH_INTERVAL = 30
const LOG_AUTO_REFRESH_INTERVAL_MS = 2000
const countdown = ref(REFRESH_INTERVAL)
let timer: number | undefined
let logAutoRefreshTimer: number | undefined
let logAutoRefreshBusy = false
let lastLogsSignature = ''

const resetTimer = () => {
  countdown.value = REFRESH_INTERVAL
}

const startCountdown = () => {
  stopCountdown()
  timer = window.setInterval(() => {
    if (countdown.value <= 1) {
      countdown.value = REFRESH_INTERVAL
      void loadDashboard()
    } else {
      countdown.value -= 1
    }
  }, 1000)
}

const stopCountdown = () => {
  if (timer) {
    clearInterval(timer)
    timer = undefined
  }
}

const startLogAutoRefresh = () => {
  stopLogAutoRefresh()
  logAutoRefreshTimer = window.setInterval(() => {
    void refreshLogsIfChanged()
  }, LOG_AUTO_REFRESH_INTERVAL_MS)
}

const stopLogAutoRefresh = () => {
  if (logAutoRefreshTimer) {
    clearInterval(logAutoRefreshTimer)
    logAutoRefreshTimer = undefined
  }
}

const normalizeProviderName = (value: string) => value.trim()

const syncProviderOptionsFromLogs = (items: RequestLog[]) => {
  if (!items.length) return
  const merged = new Set(providerOptions.value.map(normalizeProviderName).filter(Boolean))
  for (const item of items) {
    const name = normalizeProviderName(item.provider ?? '')
    if (name) {
      merged.add(name)
    }
  }
  const next = Array.from(merged)
  next.sort((a, b) => a.localeCompare(b))
  providerOptions.value = next
}

const logSignature = (item: RequestLog) => [
  item.status ?? '',
  item.id,
  item.created_at ?? '',
  item.platform ?? '',
  item.provider ?? '',
  item.relay_key_id ?? '',
  item.relay_key_name ?? '',
  item.model ?? '',
  item.client_ip ?? '',
  item.http_code ?? '',
  item.is_stream ?? '',
  item.duration_sec ?? '',
  item.first_token_duration_sec ?? '',
  item.input_tokens ?? '',
  item.output_tokens ?? '',
  item.cache_create_tokens ?? '',
  item.cache_read_tokens ?? '',
  item.reasoning_tokens ?? '',
  item.error_message ?? '',
].join('|')

const logsSignature = (items: RequestLog[]) => items.map(logSignature).join('\n')

const loadLogs = async () => {
  loading.value = true
  try {
    const data = await fetchRequestLogs({
      platform: filters.platform,
      provider: filters.provider,
      limit: 200,
    })
    logs.value = data ?? []
    lastLogsSignature = logsSignature(logs.value)
    page.value = Math.min(page.value, totalPages.value)
  } catch (error) {
    console.error('failed to load request logs', error)
  } finally {
    loading.value = false
  }
}

const refreshLogsIfChanged = async () => {
  if (logAutoRefreshBusy || loading.value) return
  logAutoRefreshBusy = true
  try {
    const data = await fetchRequestLogs({
      platform: filters.platform,
      provider: filters.provider,
      limit: 200,
    })
    const nextLogs = data ?? []
    const nextSignature = logsSignature(nextLogs)
    if (nextSignature !== lastLogsSignature) {
      logs.value = nextLogs
      lastLogsSignature = nextSignature
      page.value = Math.min(page.value, totalPages.value)
      syncProviderOptionsFromLogs(nextLogs)
      void loadStats()
    }
  } catch (error) {
    console.error('failed to auto refresh request logs', error)
  } finally {
    logAutoRefreshBusy = false
  }
}

const loadStats = async () => {
  try {
    const data = await fetchLogStats(filters.platform)
    stats.value = data ?? null
  } catch (error) {
    console.error('failed to load log stats', error)
  }
}

const loadDashboard = async () => {
  await Promise.all([loadLogs(), loadStats(), loadProviderOptions()])
  syncProviderOptionsFromLogs(logs.value)
}

const pagedLogs = computed(() => {
  const start = (page.value - 1) * PAGE_SIZE
  return logs.value.slice(start, start + PAGE_SIZE)
})

const totalPages = computed(() => Math.max(1, Math.ceil(logs.value.length / PAGE_SIZE)))

const applyFilters = async () => {
  page.value = 1
  await loadDashboard()
  resetTimer()
}

const refreshLogs = () => {
  void loadDashboard()
}

const manualRefresh = () => {
  resetTimer()
  void loadDashboard()
}

const nextPage = () => {
  if (page.value < totalPages.value) {
    page.value += 1
  }
}

const prevPage = () => {
  if (page.value > 1) {
    page.value -= 1
  }
}

const backToHome = () => {
  router.push('/')
}

const padHour = (num: number) => num.toString().padStart(2, '0')

const formatTime = (value?: string) => {
  if (value && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(value)) {
    return value.replace('T', ' ')
  }
  const date = parseLogDate(value)
  if (!date) return value || '—'
  return `${date.getFullYear()}-${padHour(date.getMonth() + 1)}-${padHour(date.getDate())} ${padHour(date.getHours())}:${padHour(date.getMinutes())}:${padHour(date.getSeconds())}`
}

const formatStream = (value?: boolean | number) => {
  const isOn = value === true || value === 1
  return isOn ? t('components.logs.streamOn') : t('components.logs.streamOff')
}

const formatRelayKey = (item: RequestLog) => {
  const name = String(item.relay_key_name ?? '').trim()
  if (name) return name
  const id = String(item.relay_key_id ?? '').trim()
  return id || '—'
}

const formatDuration = (value?: number) => {
  if (!value || Number.isNaN(value)) return '—'
  return `${value.toFixed(2)}s`
}

const isProcessingLog = (item: RequestLog) => item.status === 'processing'

const formatFirstTokenDuration = (item: RequestLog) => {
  if (isProcessingLog(item)) return '—'
  return formatDuration(item.first_token_duration_sec)
}

const httpCodeClass = (code: number) => {
  if (code >= 500) return 'http-server-error'
  if (code >= 400) return 'http-client-error'
  if (code >= 300) return 'http-redirect'
  if (code >= 200) return 'http-success'
  return 'http-info'
}

const httpCodeClassForLog = (item: RequestLog) => {
  if (isProcessingLog(item)) return 'http-processing'
  return httpCodeClass(item.http_code)
}

const durationColor = (value?: number) => {
  if (!value || Number.isNaN(value)) return 'neutral'
  if (value < 2) return 'fast'
  if (value < 5) return 'medium'
  return 'slow'
}

const durationColorForLog = (item: RequestLog, value?: number) => {
  if (isProcessingLog(item)) return 'neutral'
  return durationColor(value)
}

const formatNumber = (value?: number) => {
  if (value === undefined || value === null) return '—'
  return value.toLocaleString()
}

/**
 * 格式化 token 数值，支持 k/M/B 单位换算
 * @author sm
 */
const formatTokenNumber = (value?: number) => {
  if (value === undefined || value === null) return '—'

  if (value >= 1_000_000_000) {
    return `${(value / 1_000_000_000).toFixed(2)}B`
  }
  if (value >= 1_000_000) {
    return `${(value / 1_000_000).toFixed(2)}M`
  }
  if (value >= 1_000) {
    return `${(value / 1_000).toFixed(2)}k`
  }

  return value.toLocaleString()
}

const formatLogTokenNumber = (item: RequestLog, value?: number) => {
  if (isProcessingLog(item)) return '—'
  return formatTokenNumber(value)
}

/**
 * 计算缓存命中率
 * @param cacheRead 缓存读取 token 数
 * @param inputSideTokens 输入侧 token 数
 * @returns 命中率百分比字符串
 * @author sm
 */
const formatCacheHitRate = (cacheRead?: number, inputSideTokens?: number) => {
  const read = cacheRead ?? 0
  const total = inputSideTokens ?? 0

  if (total === 0) return '0%'

  const rate = Math.min(100, (read / total) * 100)
  return `${rate.toFixed(1)}%`
}

// OpenAI Responses/Chat 的 cached 和 reasoning token 是 input/output 的明细字段，
// 不应作为额外流量再次加到总量里。
const totalTokenTraffic = (data?: {
  input_tokens?: number
  output_tokens?: number
  cache_create_tokens?: number
} | null) =>
  (data?.input_tokens ?? 0) +
  (data?.output_tokens ?? 0) +
  (data?.cache_create_tokens ?? 0)

const inputSideTokenTraffic = (data?: {
  input_tokens?: number
  cache_create_tokens?: number
} | null) =>
  (data?.input_tokens ?? 0) +
  (data?.cache_create_tokens ?? 0)

const statsCards = computed(() => {
  const data = stats.value
  const totalTokens = totalTokenTraffic(data)
  const inputSideTokens = inputSideTokenTraffic(data)
  return [
    {
      key: 'requests',
      label: t('components.logs.summary.total'),
      hint: t('components.logs.summary.requests'),
      value: data ? formatNumber(data.total_requests) : '—',
    },
    {
      key: 'tokens',
      label: t('components.logs.summary.tokens'),
      hint: t('components.logs.summary.tokenHint'),
      value: data ? formatTokenNumber(totalTokens) : '—',
    },
    {
      key: 'cacheReads',
      label: t('components.logs.summary.cache'),
      hint: t('components.logs.summary.cacheHint'),
      value: data ? formatTokenNumber(data.cache_read_tokens) : '—',
      subValue: data ? formatCacheHitRate(data.cache_read_tokens, inputSideTokens) : '',
    },
  ]
})

const loadProviderOptions = async () => {
  try {
    const list = await fetchLogProviders(filters.platform)
    providerOptions.value = (list ?? []).map(normalizeProviderName).filter(Boolean)
    providerOptions.value.sort((a, b) => a.localeCompare(b))
  } catch (error) {
    console.error('failed to load provider options', error)
  }
}

watch(
  () => filters.platform,
  async () => {
    await loadProviderOptions()
    if (filters.provider && !providerOptions.value.includes(filters.provider)) {
      filters.provider = ''
    }
  },
)

onMounted(async () => {
  await loadDashboard()
  startCountdown()
  startLogAutoRefresh()
})

onUnmounted(() => {
  stopCountdown()
  stopLogAutoRefresh()
  stopLogColumnResize()
})
</script>

<style scoped>
.logs-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 1rem;
  margin-bottom: 0.75rem;
}

.summary-meta {
  grid-column: 1 / -1;
  font-size: 0.85rem;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  color: #64748b;
}

.summary-card {
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 16px;
  padding: 1rem 1.25rem;
  background: radial-gradient(circle at top, rgba(148, 163, 184, 0.1), rgba(15, 23, 42, 0));
  backdrop-filter: blur(6px);
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.summary-card__label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0.08em;
  color: #475569;
}

.summary-card__value {
  font-size: 1.85rem;
  font-weight: 600;
  color: #0f172a;
}

.summary-card__hint {
  font-size: 0.85rem;
  color: #94a3b8;
}

.summary-card__sub-value {
  font-size: 0.65em;
  font-weight: 400;
  color: #64748b;
  margin-left: 0.25rem;
}

html.dark .summary-card {
  border-color: rgba(255, 255, 255, 0.12);
  background: radial-gradient(circle at top, rgba(148, 163, 184, 0.2), rgba(15, 23, 42, 0.35));
}

html.dark .summary-card__label {
  color: rgba(248, 250, 252, 0.75);
}

html.dark .summary-card__value {
  color: rgba(248, 250, 252, 0.95);
}

html.dark .summary-card__hint {
  color: rgba(186, 194, 210, 0.8);
}

html.dark .summary-card__sub-value {
  color: #94a3b8;
}

@media (max-width: 768px) {
  .logs-summary {
    grid-template-columns: 1fr;
    gap: 0.75rem;
  }

  .summary-card {
    padding: 0.85rem 1rem;
    border-radius: 14px;
  }

  .summary-card__label {
    font-size: 0.75rem;
  }

  .summary-card__value {
    font-size: 1.35rem;
    line-height: 1.2;
    overflow-wrap: anywhere;
  }

  .summary-card__hint {
    font-size: 0.78rem;
  }
}

/* 可点击卡片 */
.summary-card--clickable {
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.summary-card--clickable:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(249, 115, 22, 0.15);
}
.summary-card--clickable:active {
  transform: translateY(0);
}
html.dark .summary-card--clickable:hover {
  box-shadow: 0 4px 12px rgba(249, 115, 22, 0.25);
}

/* Token 弹窗 */
.token-detail-modal {
  min-height: 80px;
}
.token-detail-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}
.token-detail-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 1rem;
  background: rgba(148, 163, 184, 0.08);
  border-radius: 8px;
  transition: background 0.15s ease;
}
.token-detail-item:hover {
  background: rgba(148, 163, 184, 0.12);
}
html.dark .token-detail-item {
  background: rgba(148, 163, 184, 0.12);
}
html.dark .token-detail-item:hover {
  background: rgba(148, 163, 184, 0.18);
}
.token-detail-item__name {
  font-weight: 500;
  color: #1e293b;
}
html.dark .token-detail-item__name {
  color: #f1f5f9;
}
.token-detail-item__value {
  font-weight: 600;
  color: #34d399;
  font-variant-numeric: tabular-nums;
}

</style>
