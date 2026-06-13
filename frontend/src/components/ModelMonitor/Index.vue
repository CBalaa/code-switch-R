<template>
  <div class="model-monitor-page">
    <header class="page-header">
      <div>
        <h1>{{ t('components.modelMonitor.title') }}</h1>
        <p>{{ t('components.modelMonitor.subtitle') }}</p>
      </div>
      <div class="header-actions">
        <BaseButton variant="outline" :disabled="loading || checkingAll" @click="loadAll">
          {{ t('components.modelMonitor.refresh') }}
        </BaseButton>
        <BaseButton :disabled="loading || checkingAll || !timelines.length" @click="runAllChecks">
          {{ checkingAll ? t('components.modelMonitor.checking') : t('components.modelMonitor.checkAll') }}
        </BaseButton>
      </div>
    </header>

    <section class="monitor-toolbar">
      <form class="target-form" @submit.prevent="saveTarget">
        <label>
          <span>{{ t('components.modelMonitor.platform') }}</span>
          <select v-model="form.platform" class="mac-select" @change="handlePlatformChange">
            <option value="claude">Claude</option>
            <option value="openai-responses">OpenAI Responses</option>
            <option value="openai-chat">OpenAI Chat</option>
          </select>
        </label>
        <label>
          <span>{{ t('components.modelMonitor.provider') }}</span>
          <select v-model.number="form.providerId" class="mac-select" @change="handleProviderChange">
            <option :value="0">{{ t('components.modelMonitor.selectProvider') }}</option>
            <option v-for="provider in currentProviders" :key="provider.id" :value="provider.id">
              {{ provider.name }}
            </option>
          </select>
        </label>
        <label>
          <span>{{ t('components.modelMonitor.model') }}</span>
          <div class="model-combobox">
            <input
              v-model.trim="form.model"
              class="mac-input"
              :placeholder="modelsLoading ? t('components.modelMonitor.loadingModels') : t('components.modelMonitor.modelPlaceholder')"
              @focus="modelDropdownOpen = true"
              @blur="modelDropdownOpen = false"
              @input="modelDropdownOpen = true"
              @keydown.down.prevent="focusFirstModelOption"
            />
            <button
              class="model-dropdown-toggle"
              type="button"
              :disabled="!form.providerId"
              @mousedown.prevent
              @click="toggleModelDropdown"
            >
              <svg viewBox="0 0 20 20" aria-hidden="true">
                <path d="M6 8l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
              </svg>
            </button>
            <div v-if="modelDropdownOpen" class="model-options">
              <button
                v-for="model in filteredModelOptions"
                :key="model"
                class="model-option"
                type="button"
                @mousedown.prevent="selectModel(model)"
              >
                {{ model }}
              </button>
              <div v-if="modelsLoading" class="model-option-empty">
                {{ t('components.modelMonitor.loadingModels') }}
              </div>
              <div v-else-if="!form.providerId" class="model-option-empty">
                {{ t('components.modelMonitor.selectProviderFirst') }}
              </div>
              <div v-else-if="!modelOptions.length" class="model-option-empty">
                {{ t('components.modelMonitor.noModelOptions') }}
              </div>
              <div v-else-if="!filteredModelOptions.length" class="model-option-empty">
                {{ t('components.modelMonitor.noModelMatches') }}
              </div>
            </div>
          </div>
        </label>
        <label>
          <span>{{ t('components.modelMonitor.interval') }}</span>
          <input v-model.number="form.intervalSeconds" class="mac-input" type="number" min="30" step="30" />
        </label>
        <label>
          <span>{{ t('components.modelMonitor.timeout') }}</span>
          <input v-model.number="form.timeoutMs" class="mac-input" type="number" min="1000" step="1000" />
        </label>
        <label class="switch-line">
          <input v-model="form.enabled" type="checkbox" />
          <span>{{ t('components.modelMonitor.enabled') }}</span>
        </label>
        <BaseButton type="submit" :disabled="saving || !canSave">
          {{ saving ? t('common.saving') : (form.id ? t('common.save') : t('components.modelMonitor.add')) }}
        </BaseButton>
        <BaseButton v-if="form.id" variant="outline" type="button" @click="resetForm">
          {{ t('common.cancel') }}
        </BaseButton>
      </form>
    </section>

    <section class="legend-row">
      <span class="legend-item"><i class="dot green"></i>{{ t('components.modelMonitor.legend.green') }}</span>
      <span class="legend-item"><i class="dot yellow"></i>{{ t('components.modelMonitor.legend.yellow') }}</span>
      <span class="legend-item"><i class="dot red"></i>{{ t('components.modelMonitor.legend.red') }}</span>
      <span class="legend-item"><i class="dot gray"></i>{{ t('components.modelMonitor.legend.gray') }}</span>
    </section>

    <section class="timeline-list">
      <article v-for="timeline in timelines" :key="timeline.target.id" class="timeline-card">
        <div class="timeline-main">
          <div class="target-title">
            <span class="platform-pill">{{ platformLabel(timeline.target.platform) }}</span>
            <strong>{{ timeline.target.providerName }}</strong>
            <span class="model-name">{{ timeline.target.model }}</span>
          </div>
          <div class="target-meta">
            <span>{{ latestLabel(timeline) }}</span>
            <span>{{ t('components.modelMonitor.uptime', { value: timeline.uptime.toFixed(1) }) }}</span>
            <span>{{ t('components.modelMonitor.avgLatency', { value: timeline.avgLatencyMs || 0 }) }}</span>
            <span>{{ t('components.modelMonitor.intervalValue', { value: timeline.target.intervalSeconds }) }}</span>
          </div>
          <div class="bar-strip" :aria-label="timeline.target.model">
            <span
              v-for="(segment, index) in timelineSegments(timeline)"
              :key="`${timeline.target.id}-${index}-${segment.key}`"
              :class="['bar-segment', segment.className]"
              :style="segment.style"
              :title="segment.title"
            ></span>
          </div>
          <p v-if="timeline.latest?.errorMessage" class="latest-error">{{ timeline.latest.errorMessage }}</p>
        </div>
        <div class="card-actions">
          <BaseButton size="sm" variant="outline" :disabled="checkingIds.has(timeline.target.id)" @click="runOne(timeline.target.id)">
            {{ checkingIds.has(timeline.target.id) ? t('components.modelMonitor.checking') : t('components.modelMonitor.checkNow') }}
          </BaseButton>
          <BaseButton size="sm" variant="outline" @click="editTarget(timeline.target)">
            {{ t('components.modelMonitor.edit') }}
          </BaseButton>
          <BaseButton size="sm" variant="danger" @click="deleteTarget(timeline.target.id)">
            {{ t('components.modelMonitor.delete') }}
          </BaseButton>
        </div>
      </article>

      <div v-if="!timelines.length && !loading" class="empty-state">
        {{ t('components.modelMonitor.empty') }}
      </div>
      <div v-if="loading" class="empty-state">
        {{ t('components.modelMonitor.loading') }}
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import { LoadProviders } from '../../../bindings/codeswitch/services/providerservice'
import type { Provider } from '../../../bindings/codeswitch/services/models'
import type { LogPlatform } from '../../services/logs'
import {
  deleteModelMonitorTarget,
  listProviderModels,
  listModelMonitorTimelines,
  runAllModelMonitorChecks,
  runModelMonitorTargetCheck,
  saveModelMonitorTarget,
  type ModelMonitorTarget,
  type ModelMonitorTimeline,
} from '../../services/modelMonitor'
import { showToast } from '../../utils/toast'

const { t } = useI18n()

const platforms: LogPlatform[] = ['claude', 'openai-responses', 'openai-chat']
const providers = reactive<Record<LogPlatform, Provider[]>>({
  claude: [],
  'openai-responses': [],
  'openai-chat': [],
})
const timelines = ref<ModelMonitorTimeline[]>([])
const loading = ref(false)
const saving = ref(false)
const checkingAll = ref(false)
const checkingIds = ref(new Set<number>())
const providerModels = ref<string[]>([])
const modelsLoading = ref(false)
const modelDropdownOpen = ref(false)

const form = reactive<{
  id: number
  platform: LogPlatform
  providerId: number
  model: string
  enabled: boolean
  intervalSeconds: number
  timeoutMs: number
}>({
  id: 0,
  platform: 'openai-responses',
  providerId: 0,
  model: '',
  enabled: true,
  intervalSeconds: 300,
  timeoutMs: 15000,
})

const currentProviders = computed(() => providers[form.platform] || [])
const selectedProvider = computed(() => currentProviders.value.find((provider) => Number(provider.id) === Number(form.providerId)) || null)
const configModelOptions = computed(() => {
  const provider = selectedProvider.value
  if (!provider) return []
  const models = new Set<string>()
  Object.keys(provider.supportedModels || {}).forEach((model) => models.add(model))
  Object.keys(provider.modelMapping || {}).forEach((model) => models.add(model))
  Object.values(provider.modelMapping || {}).forEach((model) => model && models.add(model))
  return Array.from(models).sort((a, b) => a.localeCompare(b))
})
const modelOptions = computed(() => {
  if (providerModels.value.length) return providerModels.value
  return configModelOptions.value
})
const filteredModelOptions = computed(() => {
  const prefix = form.model.trim().toLowerCase()
  const options = modelOptions.value
  if (!prefix) return options.slice(0, 60)
  return options.filter((model) => model.toLowerCase().startsWith(prefix)).slice(0, 60)
})
const canSave = computed(() => form.providerId > 0 && form.model.trim().length > 0)

const loadProviders = async () => {
  await Promise.all(platforms.map(async (platform) => {
    providers[platform] = await LoadProviders(platform)
  }))
}

const loadTimelines = async () => {
  timelines.value = await listModelMonitorTimelines()
}

const loadAll = async () => {
  loading.value = true
  try {
    await Promise.all([loadProviders(), loadTimelines()])
  } catch (error) {
    console.error('Failed to load model monitor data:', error)
    showToast(t('components.modelMonitor.loadFailed'), 'error')
  } finally {
    loading.value = false
  }
}

const resetForm = () => {
  form.id = 0
  form.platform = 'openai-responses'
  form.providerId = 0
  form.model = ''
  form.enabled = true
  form.intervalSeconds = 300
  form.timeoutMs = 15000
}

const handlePlatformChange = () => {
  form.providerId = 0
  form.model = ''
  providerModels.value = []
}

const handleProviderChange = async () => {
  providerModels.value = []
  if (!form.model && modelOptions.value.length) {
    form.model = modelOptions.value[0]
  }
  await loadProviderModels()
  if (!form.model && modelOptions.value.length) {
    form.model = modelOptions.value[0]
  }
}

const loadProviderModels = async () => {
  if (!form.providerId) return
  modelsLoading.value = true
  try {
    const result = await listProviderModels(form.platform, form.providerId)
    providerModels.value = result.models || []
  } catch (error) {
    console.warn('Failed to load provider models:', error)
    providerModels.value = []
  } finally {
    modelsLoading.value = false
  }
}

const selectModel = (model: string) => {
  form.model = model
  modelDropdownOpen.value = false
}

const toggleModelDropdown = async () => {
  if (!form.providerId) {
    modelDropdownOpen.value = !modelDropdownOpen.value
    return
  }
  modelDropdownOpen.value = !modelDropdownOpen.value
  if (modelDropdownOpen.value && !providerModels.value.length) {
    await loadProviderModels()
  }
}

const focusFirstModelOption = () => {
  const first = document.querySelector<HTMLButtonElement>('.model-option')
  first?.focus()
}

const saveTarget = async () => {
  if (!canSave.value) return
  saving.value = true
  try {
    await saveModelMonitorTarget({
      id: form.id,
      platform: form.platform,
      providerId: form.providerId,
      model: form.model,
      enabled: form.enabled,
      intervalSeconds: form.intervalSeconds,
      timeoutMs: form.timeoutMs,
    })
    showToast(t('components.modelMonitor.saveSuccess'), 'success')
    resetForm()
    await loadTimelines()
  } catch (error: any) {
    console.error('Failed to save model monitor target:', error)
    showToast(error?.message || t('components.modelMonitor.saveFailed'), 'error')
  } finally {
    saving.value = false
  }
}

const editTarget = (target: ModelMonitorTarget) => {
  form.id = target.id
  form.platform = target.platform
  form.providerId = target.providerId
  form.model = target.model
  form.enabled = target.enabled
  form.intervalSeconds = target.intervalSeconds || 300
  form.timeoutMs = target.timeoutMs || 15000
  void loadProviderModels()
}

const deleteTarget = async (targetId: number) => {
  if (!window.confirm(t('components.modelMonitor.deleteConfirm'))) return
  try {
    await deleteModelMonitorTarget(targetId)
    showToast(t('components.modelMonitor.deleteSuccess'), 'success')
    await loadTimelines()
  } catch (error: any) {
    console.error('Failed to delete model monitor target:', error)
    showToast(error?.message || t('components.modelMonitor.deleteFailed'), 'error')
  }
}

const runOne = async (targetId: number) => {
  checkingIds.value = new Set(checkingIds.value).add(targetId)
  try {
    await runModelMonitorTargetCheck(targetId)
    await loadTimelines()
  } catch (error: any) {
    console.error('Failed to run model monitor check:', error)
    showToast(error?.message || t('components.modelMonitor.checkFailed'), 'error')
  } finally {
    const next = new Set(checkingIds.value)
    next.delete(targetId)
    checkingIds.value = next
  }
}

const runAllChecks = async () => {
  checkingAll.value = true
  try {
    await runAllModelMonitorChecks()
    await loadTimelines()
  } catch (error: any) {
    console.error('Failed to run all model monitor checks:', error)
    showToast(error?.message || t('components.modelMonitor.checkFailed'), 'error')
  } finally {
    checkingAll.value = false
  }
}

const platformLabel = (platform: string) => {
  if (platform === 'claude') return 'Claude'
  if (platform === 'openai-chat') return 'OpenAI Chat'
  return 'OpenAI Responses'
}

const formatTime = (value?: string) => {
  if (!value) return t('components.modelMonitor.never')
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return value
  return date.toLocaleString()
}

const latestLabel = (timeline: ModelMonitorTimeline) => {
  const latest = timeline.latest
  if (!latest) return t('components.modelMonitor.noData')
  const latency = latest.latencyMs > 0 ? ` · ${latest.latencyMs}ms` : ''
  return `${statusLabelForItem(latest)} · ${formatTime(latest.checkedAt)}${latency}`
}

const statusLabel = (status: string) => {
  if (status === 'operational') return t('components.modelMonitor.status.operational')
  if (status === 'degraded') return t('components.modelMonitor.status.degraded')
  return t('components.modelMonitor.status.failed')
}

const statusLabelForItem = (item: { httpCode?: number; status: string; latencyMs?: number }) => {
  if (item.httpCode !== 200) return t('components.modelMonitor.status.failed')
  if ((item.latencyMs || 0) >= 2000) return t('components.modelMonitor.status.degraded')
  return t('components.modelMonitor.status.operational')
}

const interpolateColor = (start: [number, number, number], end: [number, number, number], ratio: number) => {
  const clamped = Math.max(0, Math.min(1, ratio))
  const channels = start.map((value, index) => Math.round(value + (end[index] - value) * clamped))
  return `rgb(${channels[0]}, ${channels[1]}, ${channels[2]})`
}

const latencyColor = (latencyMs: number) => {
  const green: [number, number, number] = [34, 197, 94]
  const yellow: [number, number, number] = [245, 158, 11]
  const red: [number, number, number] = [239, 68, 68]
  if (latencyMs <= 2000) return interpolateColor(green, green, 0)
  if (latencyMs < 5000) return interpolateColor(green, yellow, (latencyMs - 2000) / 3000)
  if (latencyMs < 10000) return interpolateColor(yellow, red, (latencyMs - 5000) / 5000)
  return interpolateColor(red, red, 0)
}

const timelineSegments = (timeline: ModelMonitorTimeline) => {
  const items = [...(timeline.items || [])].reverse()
  const padded = Array.from({ length: Math.max(0, 48 - items.length) }, (_, index) => ({
    key: `empty-${index}`,
    className: 'empty',
    style: undefined,
    title: t('components.modelMonitor.noData'),
  }))
  const segments = items.slice(-48).map((item) => ({
    key: item.id,
    className: item.httpCode === 200 ? 'ok' : 'fail',
    style: item.httpCode === 200 ? { backgroundColor: latencyColor(item.latencyMs || 0) } : undefined,
    title: `${statusLabelForItem(item)} · HTTP ${item.httpCode || 0} · ${formatTime(item.checkedAt)} · ${item.latencyMs || 0}ms${item.errorMessage ? ` · ${item.errorMessage}` : ''}`,
  }))
  return [...padded, ...segments].slice(-48)
}

onMounted(() => {
  void loadAll()
})
</script>

<style scoped>
.model-monitor-page {
  height: 100%;
  overflow-y: auto;
  padding: 28px;
  background: var(--mac-background);
  color: var(--mac-text);
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 18px;
}

.page-header h1 {
  margin: 0 0 6px;
  font-size: 1.7rem;
}

.page-header p {
  margin: 0;
  color: var(--mac-text-secondary);
}

.header-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.monitor-toolbar,
.timeline-card {
  background: var(--mac-surface);
  border: 1px solid var(--mac-border);
  border-radius: 8px;
}

.monitor-toolbar {
  padding: 14px;
  margin-bottom: 12px;
}

.target-form {
  display: grid;
  grid-template-columns: minmax(130px, 0.8fr) minmax(160px, 1fr) minmax(180px, 1.2fr) minmax(110px, 0.6fr) minmax(110px, 0.6fr) auto auto auto;
  gap: 10px;
  align-items: end;
}

.target-form label {
  display: grid;
  gap: 6px;
  font-size: 0.82rem;
  color: var(--mac-text-secondary);
}

.mac-select,
.mac-input {
  min-height: 34px;
  border: 1px solid var(--mac-border);
  border-radius: 6px;
  background: var(--mac-surface);
  color: var(--mac-text);
  padding: 0 10px;
  font-size: 0.9rem;
}

.model-combobox {
  position: relative;
}

.model-combobox .mac-input {
  width: 100%;
  padding-right: 34px;
}

.model-dropdown-toggle {
  position: absolute;
  top: 1px;
  right: 1px;
  width: 32px;
  height: 32px;
  border: 0;
  border-left: 1px solid var(--mac-border);
  border-radius: 0 6px 6px 0;
  background: transparent;
  color: var(--mac-text-secondary);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}

.model-dropdown-toggle:disabled {
  cursor: default;
  opacity: 0.45;
}

.model-dropdown-toggle svg {
  width: 16px;
  height: 16px;
}

.model-options {
  position: absolute;
  z-index: 20;
  top: calc(100% + 4px);
  left: 0;
  right: 0;
  max-height: 220px;
  overflow-y: auto;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface);
  box-shadow: 0 12px 32px rgba(15, 23, 42, 0.16);
  padding: 4px;
}

.model-option {
  width: 100%;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--mac-text);
  cursor: pointer;
  display: block;
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 0.82rem;
  padding: 7px 8px;
  text-align: left;
}

.model-option:hover,
.model-option:focus {
  background: rgba(59, 130, 246, 0.12);
  outline: none;
}

.model-option-empty {
  color: var(--mac-text-secondary);
  font-size: 0.82rem;
  padding: 9px 8px;
}

.switch-line {
  display: flex !important;
  grid-auto-flow: column;
  align-items: center;
  gap: 6px !important;
  min-height: 34px;
}

.legend-row {
  display: flex;
  gap: 14px;
  align-items: center;
  flex-wrap: wrap;
  margin: 12px 0 14px;
  color: var(--mac-text-secondary);
  font-size: 0.84rem;
}

.legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.dot {
  width: 9px;
  height: 9px;
  border-radius: 50%;
}

.dot.green { background: #22c55e; }
.dot.yellow { background: #f59e0b; }
.dot.red { background: #ef4444; }
.dot.gray { background: #cbd5e1; }

.timeline-list {
  display: grid;
  gap: 10px;
}

.timeline-card {
  display: grid;
  grid-template-columns: 1fr auto;
  gap: 16px;
  padding: 14px;
}

.target-title {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.platform-pill {
  padding: 3px 7px;
  border-radius: 999px;
  background: rgba(59, 130, 246, 0.12);
  color: #2563eb;
  font-size: 0.76rem;
  font-weight: 700;
}

.model-name {
  color: var(--mac-text-secondary);
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
}

.target-meta {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin: 8px 0 10px;
  font-size: 0.82rem;
  color: var(--mac-text-secondary);
}

.bar-strip {
  display: grid;
  grid-template-columns: repeat(48, minmax(3px, 1fr));
  gap: 3px;
  height: 34px;
}

.bar-segment {
  border-radius: 3px;
  background: #cbd5e1;
}

.bar-segment.ok { background: #22c55e; }
.bar-segment.slow { background: #f59e0b; }
.bar-segment.fail { background: rgba(100, 116, 139, 0.55); }
.bar-segment.empty { background: rgba(148, 163, 184, 0.22); }

.latest-error {
  margin: 10px 0 0;
  color: #dc2626;
  font-size: 0.84rem;
  word-break: break-word;
}

.card-actions {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  flex-wrap: wrap;
  justify-content: flex-end;
}

.empty-state {
  padding: 32px;
  text-align: center;
  color: var(--mac-text-secondary);
}

@media (max-width: 980px) {
  .page-header,
  .timeline-card {
    grid-template-columns: 1fr;
    display: grid;
  }

  .target-form {
    grid-template-columns: 1fr 1fr;
  }

  .card-actions,
  .header-actions {
    justify-content: flex-start;
  }
}

@media (max-width: 640px) {
  .model-monitor-page {
    padding: 18px;
  }

  .target-form {
    grid-template-columns: 1fr;
  }

  .bar-strip {
    gap: 2px;
  }
}
</style>
