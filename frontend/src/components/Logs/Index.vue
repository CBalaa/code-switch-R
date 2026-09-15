<template>
  <div class="logs-page">
    <h1 class="sr-only">{{ t('sidebar.logs') }}</h1>
    <div class="logs-header">
      <BaseButton variant="outline" type="button" data-testid="logs-back" @click="backToHome">
        {{ t('components.logs.back') }}
      </BaseButton>
      <BaseButton size="sm" :disabled="loading" data-testid="logs-refresh" @click="manualRefresh">
        {{ t('components.logs.refresh') }}
      </BaseButton>
    </div>

    <section class="logs-summary">
      <!-- 这里的卡片保持 <article>：换成 <button> 会被全局 button 重置
           （style.css 里那条 !important 规则）接管成 inline-flex + 固定内边距，排版会散掉 -->
      <article
        v-for="card in statsCards"
        :key="card.key"
        :class="['summary-card', { 'summary-card--clickable': card.key === 'tokens' }]"
        :data-testid="'logs-summary-' + card.key"
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
      <Line :data="chartData" :options="chartOptions" role="img" :aria-label="t('components.logs.chartLabel')" />
    </section>

    <section class="logs-table-wrapper" :aria-busy="loading">
      <table ref="logsTableRef" class="logs-table">
        <caption class="sr-only">{{ t('components.logs.tableCaption') }}</caption>
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
              scope="col"
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
          <tr v-for="item in pagedLogs" :key="item.id" :class="isActiveLog(item) ? 'processing-row' : ''" :data-log-id="item.id">
            <td :data-label="t('components.logs.table.time')">{{ formatTime(item.created_at) }}</td>
            <td :data-label="t('components.logs.table.platform')">{{ item.platform || '—' }}</td>
            <td :data-label="t('components.logs.table.provider')" class="provider-cell">{{ item.provider || '—' }}</td>
            <td :data-label="t('components.logs.table.relayKey')" class="relay-key-cell">{{ formatRelayKey(item) }}</td>
            <td :data-label="t('components.logs.table.model')">{{ item.model || '—' }}</td>
            <td :data-label="t('components.logs.table.clientIp')" class="client-ip-cell">{{ item.client_ip || '—' }}</td>
            <td :data-label="t('components.logs.table.httpCode')" :class="['code', httpCodeClassForLog(item)]">
              <span v-if="isQueuedLog(item)" class="processing-tag queued-tag">{{ formatQueueStatus(item) }}</span>
              <span v-else-if="isProcessingLog(item)" class="processing-tag">
                {{ isRetryingLog(item) ? t('components.logs.retry.retrying') : t('components.logs.status.processing') }}
              </span>
              <span v-else>{{ item.http_code || '—' }}</span>
            </td>
            <td :data-label="t('components.logs.table.stream')"><span :class="['stream-tag', item.is_stream ? 'on' : 'off']">{{ formatStream(item.is_stream) }}</span></td>
            <td :data-label="t('components.logs.table.firstToken')"><span :class="['duration-tag', durationColorForLog(item, item.first_token_duration_sec)]">{{ formatFirstTokenDuration(item) }}</span></td>
            <td :data-label="t('components.logs.table.duration')"><span :class="['duration-tag', durationColor(item.duration_sec)]">{{ formatDuration(item.duration_sec) }}</span></td>
            <td :data-label="t('components.logs.table.tokens')" class="token-cell">
              <div v-if="isQueuedLog(item)" class="queued-token">{{ formatQueueStatus(item) }}</div>
              <div v-else-if="isRetryingLog(item)" class="retry-token-label" role="status">
                {{ t('components.logs.retry.retrying') }}
              </div>
              <button
                v-else-if="showRetryButton(item)"
                type="button"
                class="retry-token-button"
                :data-log-id="item.id"
                :aria-label="t('components.logs.retry.action') + ' #' + item.id"
                data-testid="logs-retry"
                @click="handleRetryLog(item)"
              >
                {{ t('components.logs.retry.action') }}
              </button>
              <div v-else class="token-breakdown">
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
              </div>
            </td>
          </tr>
          <tr v-if="!pagedLogs.length && !loading">
            <td colspan="11" class="empty">{{ t('components.logs.empty') }}</td>
          </tr>
        </tbody>
      </table>
      <p v-if="loading" class="empty" role="status">{{ t('components.logs.loading') }}</p>
    </section>

    <div class="logs-pagination">
      <span aria-live="polite" data-testid="logs-page-indicator">{{ page }} / {{ totalPages }}</span>
      <div class="pagination-actions">
        <BaseButton
          variant="outline"
          size="sm"
          :disabled="page === 1 || loading"
          :aria-label="t('components.logs.prevPage')"
          data-testid="logs-prev-page"
          @click="prevPage"
        >
          ‹
        </BaseButton>
        <BaseButton
          variant="outline"
          size="sm"
          :disabled="page >= totalPages || loading"
          :aria-label="t('components.logs.nextPage')"
          data-testid="logs-next-page"
          @click="nextPage"
        >
          ›
        </BaseButton>
      </div>
    </div>

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
import {
  computed,
  ref,
  onActivated,
  onDeactivated,
  onMounted,
  onUnmounted,
} from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import BaseModal from '../common/BaseModal.vue'
import {
  fetchActiveRequestLogs,
  fetchCompletedRequestLogs,
  fetchLogStats,
  retryActiveRequest,
  type LogStats,
  type LogStatsSeries,
  type RequestLog,
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
import { showToast } from '../../utils/toast'
import { ListAllPools, accountPoolKeyDisplayName } from '../../services/providerPool'
import {
  MAX_COMPLETED_REQUEST_LOGS,
  mergeCompletedRequestLogs,
} from '../../services/logMerge'

Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)

const { t } = useI18n()
const router = useRouter()

const activeLogs = ref<RequestLog[]>([])
const completedLogs = ref<RequestLog[]>([])
const stats = ref<LogStats | null>(null)
const loading = ref(false)
const retryingLogIds = ref<Set<number>>(new Set())
const page = ref(1)
const PAGE_SIZE = 15
const hiddenLogProviderKeys = ref<Set<string>>(new Set())
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

const tokenDetailModal = ref({ open: false })

const handleCardClick = (key: string) => {
  if (key === 'tokens') {
    tokenDetailModal.value.open = true
  }
}

const closeTokenDetailModal = () => {
  tokenDetailModal.value.open = false
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

const formatSeriesLabel = (value?: string) => {
  if (!value) return ''
  const bucketTime = value.match(/^\d{4}-\d{2}-\d{2}[ T](\d{2}):(\d{2})/)
  if (bucketTime) {
    return `${bucketTime[1]}:${bucketTime[2]}`
  }
  const parsed = parseLogDate(value)
  if (parsed) {
    return `${padHour(parsed.getHours())}:${padHour(parsed.getMinutes())}`
  }
  const time = value.match(/(\d{2}):(\d{2})/)
  if (time) {
    return `${time[1]}:${time[2]}`
  }
  return value
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
      ticks: {
        color: '#94a3b8',
        autoSkip: true,
        maxTicksLimit: 8,
        maxRotation: 0,
      },
    },
    y: {
      beginAtZero: true,
      ticks: { color: '#94a3b8' },
      grid: { color: 'rgba(148, 163, 184, 0.2)' },
    },
  },
}

const LOG_AUTO_REFRESH_INTERVAL_MS = 1000
let logAutoRefreshTimer: number | undefined
let refreshPromise: Promise<boolean> | null = null
let refreshPending = false
let statsPromise: Promise<void> | null = null
let statsPending = false
let lastSeenCompletedID = 0
let isPageActive = false
let isUnmounted = false
let initialLoadDone = false

const canPoll = () =>
  isPageActive && initialLoadDone && !isUnmounted && document.visibilityState === 'visible'

const startLogAutoRefresh = () => {
  stopLogAutoRefresh()
  if (!canPoll()) return
  logAutoRefreshTimer = window.setInterval(() => {
    if (!canPoll()) return
    void refreshLogs()
  }, LOG_AUTO_REFRESH_INTERVAL_MS)
}

const stopLogAutoRefresh = () => {
  if (logAutoRefreshTimer !== undefined) {
    clearInterval(logAutoRefreshTimer)
    logAutoRefreshTimer = undefined
  }
}

const syncPollingState = () => {
  if (canPoll()) {
    startLogAutoRefresh()
    return
  }
  stopLogAutoRefresh()
}

const handleVisibilityChange = () => {
  syncPollingState()
  if (canPoll()) {
    void refreshLogs()
  }
}

const normalizeProviderName = (value: string) => value.trim()

const providerVisibilityKey = (platform: string, provider: string) =>
  `${platform.trim()}\u0000${normalizeProviderName(provider)}`

const isHiddenLogProvider = (platform: string, provider: string) => {
  const normalizedProvider = normalizeProviderName(provider)
  if (!normalizedProvider) return false
  return hiddenLogProviderKeys.value.has(providerVisibilityKey(platform, normalizedProvider))
}

const visibleRequestLogs = (items: readonly RequestLog[]) =>
  items.filter((item) => !isHiddenLogProvider(item.platform ?? '', item.provider ?? ''))

// The cursor and 105-row completed quota intentionally apply to the raw DB
// window. hideFromLogs is display-only: backfilling until 105 visible rows could
// turn a bounded query into an unbounded historical scan.
const visibleActiveLogs = computed(() => visibleRequestLogs(activeLogs.value))
const visibleCompletedLogs = computed(() => visibleRequestLogs(completedLogs.value))

const loadHiddenLogProviders = async () => {
  try {
    const pools = await ListAllPools()
    const hiddenKeys = new Set<string>()
    for (const pool of pools ?? []) {
      if (pool.poolType !== 'account' || pool.hideFromLogs !== true) continue
      for (const key of pool.accountPoolConfig?.keys ?? []) {
        const provider = accountPoolKeyDisplayName(key)
        hiddenKeys.add(providerVisibilityKey(pool.platform, provider))
      }
    }
    hiddenLogProviderKeys.value = hiddenKeys
    page.value = Math.min(page.value, totalPages.value)
  } catch (error) {
    console.error('failed to load hidden log pools', error)
  }
}

const isPositiveDuration = (value?: number): value is number => typeof value === 'number' && Number.isFinite(value) && value > 0

const hasFirstResponse = (item: RequestLog) => {
  return isPositiveDuration(item.first_text_sec) || isPositiveDuration(item.first_token_duration_sec)
}

const isQueuedLog = (item: RequestLog) => item.status === 'queued'

const isProcessingLog = (item: RequestLog) => item.status === 'processing' || item.status === 'retrying'

const isActiveLog = (item: RequestLog) => isQueuedLog(item) || isProcessingLog(item)

const isRetryingLog = (item: RequestLog) => {
  if (!isProcessingLog(item)) return false
  return item.retry_requested === true
    || item.status === 'retrying'
    || item.error_message === '重试'
    || retryingLogIds.value.has(item.id)
}

const reconcileRetryingLogs = (items: RequestLog[]) => {
  if (!retryingLogIds.value.size) return

  const logsByID = new Map(items.map((item) => [item.id, item]))
  const next = new Set(retryingLogIds.value)
  for (const id of retryingLogIds.value) {
    const item = logsByID.get(id)
    // The local marker is only for the RPC round trip. Once the tracker has
    // started the replacement attempt it reports regular processing again.
    // Leaving this marker in place made successful retries look permanently
    // stuck at "Retrying" until the request completed.
    const trackerStillRetrying = item?.retry_requested === true
      || item?.status === 'retrying'
      || item?.error_message === '重试'
    if (!item || hasFirstResponse(item) || !isActiveLog(item) || !trackerStillRetrying) {
      next.delete(id)
    }
  }
  if (next.size !== retryingLogIds.value.size) {
    retryingLogIds.value = next
  }
}

const newestCompletedID = (items: readonly RequestLog[]) => {
  let newestID = 0
  for (const item of items) {
    if (item.id > newestID) newestID = item.id
  }
  return newestID
}

const applyActiveLogs = (items: readonly RequestLog[]) => {
  const nextActive = [...items]
  reconcileRetryingLogs(nextActive)
  activeLogs.value = nextActive
}

const loadStats = (): Promise<void> => {
  if (statsPromise) {
    statsPending = true
    return statsPromise
  }

  statsPromise = (async () => {
    do {
      statsPending = false
      try {
        const data = await fetchLogStats('')
        if (!isUnmounted) {
          stats.value = data ?? null
        }
      } catch (error) {
        console.error('failed to load log stats', error)
      }
    } while (statsPending && !isUnmounted)
  })().finally(() => {
    statsPromise = null
  })
  return statsPromise
}

const loadInitialLogs = async () => {
  loading.value = true
  try {
    await loadHiddenLogProviders()
    const [activeResult, completedResult] = await Promise.allSettled([
      fetchActiveRequestLogs(),
      fetchCompletedRequestLogs(-1, MAX_COMPLETED_REQUEST_LOGS),
      loadStats(),
    ])
    if (isUnmounted) return

    if (activeResult.status === 'fulfilled') {
      applyActiveLogs(activeResult.value ?? [])
    } else {
      console.error('failed to load active request logs', activeResult.reason)
    }
    if (completedResult.status === 'fulfilled') {
      const initialCompleted = completedResult.value ?? []
      lastSeenCompletedID = newestCompletedID(initialCompleted)
      completedLogs.value = mergeCompletedRequestLogs([], initialCompleted)
    } else {
      console.error('failed to load completed request logs', completedResult.reason)
    }
    page.value = Math.min(page.value, totalPages.value)
  } catch (error) {
    console.error('failed to load request logs', error)
  } finally {
    loading.value = false
  }
}

const refreshLogSnapshot = async () => {
  const afterID = lastSeenCompletedID
  const [activeResult, completedResult] = await Promise.allSettled([
    fetchActiveRequestLogs(),
    fetchCompletedRequestLogs(afterID, MAX_COMPLETED_REQUEST_LOGS),
  ])
  if (isUnmounted) return false

  if (activeResult.status === 'fulfilled') {
    applyActiveLogs(activeResult.value ?? [])
  } else {
    console.error('failed to refresh active request logs', activeResult.reason)
  }
  if (completedResult.status === 'fulfilled') {
    const incomingCompleted = completedResult.value ?? []
    lastSeenCompletedID = Math.max(lastSeenCompletedID, newestCompletedID(incomingCompleted))
    completedLogs.value = mergeCompletedRequestLogs(completedLogs.value, incomingCompleted)
    page.value = Math.min(page.value, totalPages.value)
    return incomingCompleted.length > 0
  } else {
    console.error('failed to refresh completed request logs', completedResult.reason)
  }
  page.value = Math.min(page.value, totalPages.value)
  return false
}

const refreshLogs = (): Promise<boolean> => {
  if (refreshPromise) {
    refreshPending = true
    return refreshPromise
  }

  refreshPromise = (async () => {
    let foundNewCompleted = false
    let statsNeedRefresh = false
    do {
      refreshPending = false
      const snapshotFoundNew = await refreshLogSnapshot()
      foundNewCompleted = snapshotFoundNew || foundNewCompleted
      statsNeedRefresh = snapshotFoundNew || statsNeedRefresh
      if (!refreshPending && statsNeedRefresh) {
        await loadStats()
        statsNeedRefresh = false
      }
    } while (refreshPending && !isUnmounted)
    return foundNewCompleted
  })().finally(() => {
    refreshPromise = null
  })
  return refreshPromise
}

const pagedLogs = computed(() => {
  const start = (page.value - 1) * PAGE_SIZE
  const completedPage = visibleCompletedLogs.value.slice(start, start + PAGE_SIZE)
  return [...visibleActiveLogs.value, ...completedPage]
})

const totalPages = computed(() => Math.max(1, Math.ceil(visibleCompletedLogs.value.length / PAGE_SIZE)))

const manualRefresh = () => {
  void (async () => {
    await loadHiddenLogProviders()
    const foundNewCompleted = await refreshLogs()
    if (!foundNewCompleted) {
      await loadStats()
    }
  })()
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

const showRetryButton = (item: RequestLog) => {
  return isProcessingLog(item) && !isRetryingLog(item) && !hasFirstResponse(item)
}

const canRetryLog = (item: RequestLog) => {
  return showRetryButton(item)
}

const markRetryingLog = (id: number) => {
  retryingLogIds.value = new Set([...retryingLogIds.value, id])
}

const clearRetryingLog = (id: number) => {
  const next = new Set(retryingLogIds.value)
  next.delete(id)
  retryingLogIds.value = next
}

const markLogFirstTokenSeen = (id: number, firstTokenSec?: number, firstTextSec?: number) => {
  if (!isPositiveDuration(firstTokenSec) && !isPositiveDuration(firstTextSec)) return

  const updateLog = (log: RequestLog) => {
    if (log.id !== id) return log
    return {
      ...log,
      first_token_duration_sec: isPositiveDuration(firstTokenSec) ? firstTokenSec : log.first_token_duration_sec,
      first_text_sec: isPositiveDuration(firstTextSec) ? firstTextSec : log.first_text_sec,
    }
  }
  activeLogs.value = activeLogs.value.map(updateLog)
  completedLogs.value = completedLogs.value.map(updateLog)
}

const retryRejectedMessage = (status?: string) => {
  switch (status) {
    case 'ignored_finished':
      return t('components.logs.retry.finished')
    case 'ignored_first_text':
    case 'ignored_response_started':
      return t('components.logs.retry.responseStarted')
    case 'ignored_unauthorized':
      return t('components.logs.retry.unauthorized')
    case 'ignored_queued':
      return t('components.logs.retry.queued')
    case 'ignored_transition':
      return t('components.logs.retry.transition')
    default:
      return t('components.logs.retry.rejected', { status: status || t('components.logs.retry.unknownStatus') })
  }
}

const handleRetryLog = async (item: RequestLog) => {
  if (!canRetryLog(item)) return
  markRetryingLog(item.id)
  try {
    const result = await retryActiveRequest(item.id)
    if (result?.status !== 'retried') {
      if (result?.status === 'ignored_first_text' || result?.status === 'ignored_response_started') {
        markLogFirstTokenSeen(item.id, result.first_token_duration_sec, result.first_text_sec)
      }
      showToast(retryRejectedMessage(result?.status), 'warning')
      await refreshLogs()
      clearRetryingLog(item.id)
      return
    }
    await refreshLogs()
  } catch (error) {
    console.error('failed to retry active request', error)
    clearRetryingLog(item.id)
    const message = error instanceof Error && error.message
      ? error.message
      : t('components.logs.retry.failed')
    showToast(message, 'error')
    await refreshLogs()
  }
}

const formatFirstTokenDuration = (item: RequestLog) => {
  return formatDuration(item.first_token_duration_sec)
}

const formatQueueStatus = (item: RequestLog) => {
  const position = item.queue_position
  if (typeof position === 'number' && Number.isFinite(position) && position > 0) {
    return t('components.logs.status.queuedWithPosition', { position })
  }
  return t('components.logs.status.queued')
}

const httpCodeClass = (code: number) => {
  if (code >= 500) return 'http-server-error'
  if (code >= 400) return 'http-client-error'
  if (code >= 300) return 'http-redirect'
  if (code >= 200) return 'http-success'
  return 'http-info'
}

const httpCodeClassForLog = (item: RequestLog) => {
  if (isActiveLog(item)) return 'http-processing'
  return httpCodeClass(item.http_code)
}

const durationColor = (value?: number) => {
  if (!value || Number.isNaN(value)) return 'neutral'
  if (value < 2) return 'fast'
  if (value < 5) return 'medium'
  return 'slow'
}

const durationColorForLog = (item: RequestLog, value?: number) => {
  if (isActiveLog(item) && (!value || Number.isNaN(value))) return 'neutral'
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
  if (isQueuedLog(item)) return formatQueueStatus(item)
  if (isProcessingLog(item)) return '—'
  return formatTokenNumber(value)
}

const formatCacheHitRate = (cacheRead?: number, inputSideTokens?: number) => {
  const read = cacheRead ?? 0
  const total = inputSideTokens ?? 0
  if (total === 0) return '0%'
  return `${Math.min(100, (read / total) * 100).toFixed(1)}%`
}

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
      value: data ? formatTokenNumber(totalTokenTraffic(data)) : '—',
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

onMounted(async () => {
  isUnmounted = false
  isPageActive = true
  document.addEventListener('visibilitychange', handleVisibilityChange)
  await loadInitialLogs()
  if (isUnmounted) return
  initialLoadDone = true
  syncPollingState()
})

onActivated(() => {
  const wasActive = isPageActive
  isPageActive = true
  syncPollingState()
  if (!wasActive && canPoll()) {
    void (async () => {
      await loadHiddenLogProviders()
      await refreshLogs()
    })()
  }
})

onDeactivated(() => {
  isPageActive = false
  syncPollingState()
  stopLogColumnResize()
})

onUnmounted(() => {
  isUnmounted = true
  isPageActive = false
  document.removeEventListener('visibilitychange', handleVisibilityChange)
  syncPollingState()
  stopLogColumnResize()
})
</script>

<style scoped>
.queued-tag,
.queued-token {
  color: #b45309;
  font-weight: 600;
  white-space: nowrap;
}

.queued-token {
  font-size: 0.85rem;
}

html.dark .queued-tag,
html.dark .queued-token {
  color: #fbbf24;
}

.logs-summary {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
  gap: 1rem;
  margin-bottom: 0.75rem;
}

.summary-card {
  border: 1px solid rgba(15, 23, 42, 0.08);
  border-radius: 8px;
  padding: 1rem 1.25rem;
  background: rgba(148, 163, 184, 0.06);
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.summary-card__label {
  font-size: 0.85rem;
  text-transform: uppercase;
  letter-spacing: 0;
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
  background: rgba(148, 163, 184, 0.1);
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
    border-radius: 8px;
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
