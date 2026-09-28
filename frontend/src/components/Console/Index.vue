<script setup lang="ts">
import {
  ref,
  nextTick,
  onActivated,
  onDeactivated,
  onMounted,
  onUnmounted,
} from 'vue'
import { useRouter } from 'vue-router'
import { Call } from '@wailsio/runtime'
import { showToast } from '../../utils/toast'

interface ConsoleLog {
  timestamp: string
  level: string
  message: string
}

interface ConsoleLogCursor {
  request_log_id: number
  pool_attempt_sequence: number
  console_sequence: number
}

interface ConsoleLogBatch {
  logs: ConsoleLog[]
  cursor: ConsoleLogCursor
}

const MAX_CONSOLE_LOGS = 200
const emptyCursor = (): ConsoleLogCursor => ({
  request_log_id: 0,
  pool_attempt_sequence: 0,
  console_sequence: 0,
})

const router = useRouter()
const logs = ref<ConsoleLog[]>([])
const autoScroll = ref(true)
const loading = ref(false)
const logsContainer = ref<HTMLElement>()
let refreshInterval: number | null = null
let loadLogsPromise: Promise<void> | null = null
let isPageActive = false
let isUnmounted = false
let initialLoadDone = false
let clearInProgress = false
let logsViewGeneration = 0
let logCursor = emptyCursor()

const canPoll = () =>
  isPageActive
  && initialLoadDone
  && !isUnmounted
  && !clearInProgress
  && document.visibilityState === 'visible'

const hasSelectedConsoleText = () => {
  const selection = window.getSelection()
  return Boolean(selection && !selection.isCollapsed && selection.toString().trim())
}

const goBack = () => {
  router.push('/')
}

const loadLogs = (): Promise<void> => {
  if (clearInProgress || hasSelectedConsoleText()) return Promise.resolve()
  if (!loadLogsPromise) {
    const requestGeneration = logsViewGeneration
    loadLogsPromise = (async () => {
      try {
        const result = await Call.ByName(
          'codeswitch/services.ConsoleService.GetLogUpdates',
          logCursor,
          MAX_CONSOLE_LOGS,
        ) as ConsoleLogBatch
        if (isUnmounted || requestGeneration !== logsViewGeneration) return
        // A selection may have started while this request was in flight. Keep
        // the cursor unchanged so the update is fetched after copying.
        if (hasSelectedConsoleText()) return
        const incoming = result?.logs ?? []
        logs.value = [...logs.value, ...incoming].slice(-MAX_CONSOLE_LOGS)
        logCursor = result?.cursor ?? logCursor

        if (incoming.length > 0 && autoScroll.value && isPageActive) {
          await nextTick()
          if (!isUnmounted && isPageActive) {
            scrollToBottom()
          }
        }
      } catch (error) {
        console.error('加载控制台日志失败:', error)
      }
    })().finally(() => {
      loadLogsPromise = null
    })
  }
  return loadLogsPromise
}

const stopPolling = () => {
  if (refreshInterval !== null) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

const startPolling = () => {
  stopPolling()
  if (!canPoll()) return
  refreshInterval = window.setInterval(() => {
    if (canPoll()) {
      void loadLogs()
    }
  }, 1000)
}

const syncPollingState = () => {
  if (canPoll()) {
    startPolling()
  } else {
    stopPolling()
  }
}

const handleVisibilityChange = () => {
  syncPollingState()
  if (canPoll()) {
    void loadLogs()
  }
}

const clearLogs = async () => {
  if (!confirm('确定要清空所有控制台日志吗？')) {
    return
  }

  clearInProgress = true
  logsViewGeneration += 1
  syncPollingState()
  try {
    await Call.ByName('codeswitch/services.ConsoleService.ClearLogs')
    logsViewGeneration += 1
    logs.value = []
    logCursor = emptyCursor()
  } catch (error) {
    console.error('清空日志失败:', error)
    showToast('清空失败：' + (error as Error).message, 'error')
  } finally {
    clearInProgress = false
    syncPollingState()
  }
}

const scrollToBottom = () => {
  if (logsContainer.value) {
    logsContainer.value.scrollTop = logsContainer.value.scrollHeight
  }
}

const formatTimestamp = (timestamp: string) => {
  const date = new Date(timestamp)
  return date.toLocaleTimeString('zh-CN', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

const getLevelClass = (level: string) => {
  switch (level.toUpperCase()) {
    case 'ERROR':
      return 'log-error'
    case 'WARN':
      return 'log-warn'
    default:
      return 'log-info'
  }
}

onMounted(async () => {
  isUnmounted = false
  isPageActive = true
  document.addEventListener('visibilitychange', handleVisibilityChange)
  loading.value = true
  await loadLogs()
  if (isUnmounted) return
  loading.value = false
  initialLoadDone = true
  syncPollingState()
})

onActivated(() => {
  const wasActive = isPageActive
  isPageActive = true
  syncPollingState()
  if (!wasActive && canPoll()) {
    void loadLogs()
  }
})

onDeactivated(() => {
  isPageActive = false
  syncPollingState()
})

onUnmounted(() => {
  isUnmounted = true
  isPageActive = false
  document.removeEventListener('visibilitychange', handleVisibilityChange)
  syncPollingState()
})
</script>

<template>
  <div class="main-shell console-shell">
    <div class="global-actions">
      <h1 class="global-eyebrow">控制台</h1>
      <div class="actions-group">
        <button class="secondary-btn" type="button" data-testid="console-clear" @click="clearLogs">清空日志</button>
        <div class="auto-scroll-toggle">
          <input id="console-auto-scroll" type="checkbox" v-model="autoScroll" data-testid="console-autoscroll" />
          <label for="console-auto-scroll">自动滚动</label>
        </div>
        <button class="ghost-icon" aria-label="返回" @click="goBack">
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
    </div>

    <div class="console-container">
      <div v-if="loading" class="loading-state" role="status">
        <div class="spinner"></div>
        <p>加载中...</p>
      </div>

      <div v-else class="console-content" ref="logsContainer" role="log" aria-live="polite" aria-relevant="additions" data-testid="console-log">
        <div v-if="logs.length === 0" class="empty-state">
          <p>暂无日志</p>
        </div>

        <div
          v-for="(log, index) in logs"
          :key="index"
          class="log-entry"
          :class="getLevelClass(log.level)"
        >
          <span class="log-timestamp">{{ formatTimestamp(log.timestamp) }}</span>
          <span class="log-level">{{ log.level }}</span>
          <span class="log-message">{{ log.message }}</span>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.console-shell {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.actions-group {
  display: flex;
  align-items: center;
  gap: 12px;
}

.auto-scroll-toggle {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 0.9rem;
  color: var(--mac-text-secondary);
  cursor: pointer;
  user-select: none;
}

.auto-scroll-toggle input[type="checkbox"] {
  cursor: pointer;
}

.console-container {
  flex: 1;
  overflow: hidden;
  background: var(--mac-surface);
  border: 1px solid var(--mac-border);
  border-radius: 12px;
  display: flex;
  flex-direction: column;
}

.console-content {
  flex: 1;
  overflow-y: auto;
  padding: 16px;
  font-family: 'SF Mono', 'Monaco', 'Inconsolata', 'Fira Code', 'Consolas', monospace;
  font-size: 0.85rem;
  line-height: 1.6;
  background: #1e1e1e;
  color: #d4d4d4;
  user-select: text;
  cursor: text;
}

html.dark .console-content {
  background: #0d1117;
  color: #e6edf3;
}

.log-entry {
  display: flex;
  gap: 12px;
  padding: 4px 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
  user-select: text;
}

.log-entry:last-child {
  border-bottom: none;
}

.log-timestamp {
  flex-shrink: 0;
  color: #858585;
  font-weight: 500;
}

.log-level {
  flex-shrink: 0;
  min-width: 50px;
  font-weight: 600;
}

.log-info .log-level {
  color: #4ec9b0;
}

.log-warn .log-level {
  color: #dcdcaa;
}

.log-error .log-level {
  color: #f48771;
}

.log-message {
  flex: 1;
  white-space: pre-wrap;
  word-break: break-word;
}

.loading-state,
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  height: 100%;
  /* The console body is #1e1e1e; the light-theme secondary grey only reached
     3.0:1 there. */
  color: #9da3ad;
}

.spinner {
  width: 32px;
  height: 32px;
  border: 3px solid rgba(0, 0, 0, 0.1);
  border-top-color: var(--mac-accent);
  border-radius: 50%;
  animation: spin 0.8s linear infinite;
  margin-bottom: 12px;
}

@keyframes spin {
  to { transform: rotate(360deg); }
}
</style>
