<template>
  <BaseModal
    :open="open"
    :title="t('components.main.modelTrace.title')"
    test-id="modeltrace-modal"
    @close="$emit('close')"
  >
    <div class="modeltrace-body">
      <!-- 第一步：选择要检测的模型 -->
      <div class="modeltrace-section">
        <p class="modeltrace-label" id="modeltrace-model-label">
          {{ t('components.main.modelTrace.selectModel') }}
          <span class="modeltrace-provider">· {{ providerName }}</span>
        </p>
        <div
          class="modeltrace-model-grid"
          role="group"
          aria-labelledby="modeltrace-model-label"
          data-testid="modeltrace-models"
        >
          <button
            v-for="model in models"
            :key="model.id"
            type="button"
            :class="['modeltrace-model-chip', `family-${model.family}`, { selected: selectedModel === model.id }]"
            :aria-pressed="selectedModel === model.id"
            :data-model="model.id"
            data-testid="modeltrace-model-chip"
            @click="selectedModel = model.id"
          >
            {{ model.displayName || model.id }}
          </button>
        </div>
      </div>

      <!-- 操作按钮 -->
      <div class="modeltrace-actions">
        <BaseButton
          type="button"
          :disabled="!selectedModel || verifying"
          data-testid="modeltrace-verify"
          @click="handleVerify"
        >
          <span v-if="verifying" class="btn-spinner" aria-hidden="true"></span>
          {{ verifying ? t('components.main.modelTrace.verifying') : t('components.main.modelTrace.verify') }}
        </BaseButton>
      </div>

      <!-- 实时进度（检测过程中） -->
      <div
        v-if="verifying && progress"
        class="modeltrace-progress"
        role="status"
        aria-live="polite"
        data-testid="modeltrace-progress"
      >
        <div class="progress-steps">
          <div
            v-for="(step, index) in progressSteps"
            :key="step.key"
            :class="['progress-step', {
              active: step.active,
              done: step.done
            }]"
            :data-step-state="step.done ? 'done' : step.active ? 'active' : 'pending'"
          >
            <span class="step-dot" aria-hidden="true"></span>
            <span class="step-label">{{ step.label }}</span>
          </div>
        </div>
        <div class="progress-detail">
          <span class="progress-detail-text" :key="progress.detail">{{ progress.detail }}</span>
          <span class="progress-elapsed">{{ elapsedLabel }}</span>
        </div>
        <!-- 模型实时生成内容（小窗滚动展示，证明模型确实在生成而非卡住） -->
        <div ref="streamBoxRef" class="stream-box" aria-live="off" data-testid="modeltrace-stream">
          <span v-if="streamText" class="stream-text">{{ streamText }}</span>
          <span v-else class="stream-placeholder">
            <span class="stream-pulse-dot" aria-hidden="true"></span>
            {{ t('components.main.modelTrace.waitingStream') }}
          </span>
        </div>
      </div>

      <!-- 检测结果 -->
      <div v-if="result" class="modeltrace-result" aria-live="polite" data-testid="modeltrace-result">
        <!-- 判定横幅 -->
        <div
          v-if="result.verdict === 'match'"
          class="modeltrace-verdict verdict-match"
          :data-verdict="result.verdict"
          data-testid="modeltrace-verdict"
        >
          <span class="verdict-icon" aria-hidden="true">✓</span>
          <div class="verdict-text">
            <p class="verdict-title">{{ t('components.main.modelTrace.match') }}</p>
            <p class="verdict-detail">
              {{ t('components.main.modelTrace.matchDetail', {
                model: result.topModelName || result.topModel,
                probability: formatProbability(result.topProbability)
              }) }}
            </p>
          </div>
        </div>
        <div
          v-else-if="result.verdict === 'mismatch'"
          class="modeltrace-verdict verdict-mismatch"
          :data-verdict="result.verdict"
          data-testid="modeltrace-verdict"
        >
          <span class="verdict-icon" aria-hidden="true">⚠</span>
          <div class="verdict-text">
            <p class="verdict-title">{{ t('components.main.modelTrace.mismatch') }}</p>
            <p class="verdict-detail">
              {{ t('components.main.modelTrace.mismatchDetail', {
                expected: result.expectedModel,
                actual: result.topModelName || result.topModel,
                probability: formatProbability(result.topProbability)
              }) }}
            </p>
          </div>
        </div>
        <div
          v-else
          class="modeltrace-verdict verdict-error"
          :data-verdict="result.verdict"
          data-testid="modeltrace-verdict"
        >
          <span class="verdict-icon" aria-hidden="true">✕</span>
          <div class="verdict-text">
            <p class="verdict-title">{{ t('components.main.modelTrace.error') }}</p>
            <p class="verdict-detail" data-testid="modeltrace-error-message">{{ result.message }}</p>
          </div>
        </div>

        <!-- 概率分布（仅成功时展示 top 6） -->
        <template v-if="result.success && result.probabilities?.length">
          <p class="modeltrace-label" id="modeltrace-distribution-label">
            {{ t('components.main.modelTrace.distributionTitle') }}
          </p>
          <div
            class="modeltrace-bars"
            role="group"
            aria-labelledby="modeltrace-distribution-label"
            data-testid="modeltrace-bars"
          >
            <div
              v-for="item in topProbabilities"
              :key="item.model"
              :class="['modeltrace-bar-row', {
                'is-expected': item.model === result.expectedModel,
                'is-top': item.model === result.topModel
              }]"
              :data-model="item.model"
            >
              <span class="bar-model">{{ item.displayName || item.model }}</span>
              <div class="bar-track" aria-hidden="true">
                <div
                  class="bar-fill"
                  :class="item.model === result.topModel ? 'fill-top' : 'fill-normal'"
                  :style="{ width: barWidth(item.probability) }"
                ></div>
              </div>
              <span class="bar-value">{{ formatProbability(item.probability) }}</span>
            </div>
          </div>
          <div class="modeltrace-meta" data-testid="modeltrace-meta">
            <span>{{ t('components.main.modelTrace.validNumbers') }}: {{ result.validNumberCount }}</span>
            <span>{{ t('components.main.modelTrace.attempts') }}: {{ result.attempts }}</span>
            <span>{{ t('components.main.modelTrace.latency') }}: {{ result.latencyMs }}ms</span>
          </div>
        </template>
      </div>
    </div>

    <footer class="form-actions">
      <BaseButton
        v-if="result?.success"
        variant="outline"
        type="button"
        :disabled="verifying"
        data-testid="modeltrace-retry"
        @click="handleVerify"
      >
        {{ t('components.main.modelTrace.retry') }}
      </BaseButton>
      <BaseButton variant="outline" type="button" data-testid="modeltrace-close" @click="$emit('close')">
        {{ t('components.main.modelTrace.close') }}
      </BaseButton>
    </footer>
  </BaseModal>
</template>

<script setup lang="ts">
import { computed, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import BaseModal from '../common/BaseModal.vue'
import {
  getSupportedModels,
  verifyProviderModel,
  subscribeProgress,
  subscribeStream,
  type ModelTraceModelOption,
  type ModelTraceResult,
  type ModelTraceProgress,
} from '../../services/modeltrace'
import { extractErrorMessage } from '../../utils/error'

const props = defineProps<{
  open: boolean
  platform: string
  providerId: number
  providerName: string
}>()

defineEmits<{ (e: 'close'): void }>()

const { t } = useI18n()

const models = ref<ModelTraceModelOption[]>([])
const selectedModel = ref('')
const verifying = ref(false)
const result = ref<ModelTraceResult | null>(null)
// 请求序号：弹窗重开/重试时递增，旧请求的迟到响应按序号丢弃，避免覆盖新结果
const requestSeq = ref(0)
// 当前会话的实时进度。归属规则：
// RPC 调用是阻塞的，前端发起调用时还不知道后端生成的 sessionId，
// 因此首个事件用 (providerId, expectedModel) 匹配归属，命中后锁定
// 该 sessionId，后续事件只认这个 sessionId。
const progress = ref<ModelTraceProgress | null>(null)
const activeSessionId = ref('')
const activeRequest = ref<{ providerId: number; expectedModel: string } | null>(null)

const unsubscribeProgress = subscribeProgress((event) => {
  // 已锁定会话：只认该 sessionId 的事件
  if (activeSessionId.value) {
    if (event.sessionId !== activeSessionId.value) return
    progress.value = event
    return
  }
  // 未锁定：用请求参数匹配首个事件
  const request = activeRequest.value
  if (!request) return
  if (event.providerId !== request.providerId || event.expectedModel !== request.expectedModel) return
  activeSessionId.value = event.sessionId
  progress.value = event
})
onUnmounted(() => unsubscribeProgress())

// ===== 模型实时生成内容 =====
// 后端以 SSE 流式拉取模型输出并节流推送片段；这里按 sessionId
// 归属追加并滚动到最新。重试（新挑战）时清空重新展示。
const streamText = ref('')
const streamBoxRef = ref<HTMLElement | null>(null)

const unsubscribeStream = subscribeStream((event) => {
  if (activeSessionId.value) {
    if (event.sessionId !== activeSessionId.value) return
  } else {
    const req = activeRequest.value
    if (!req) return
    const matches =
      (event.providerId === req.providerId && event.expectedModel === req.expectedModel) ||
      event.sessionId.startsWith(`mt-${req.providerId}-`)
    if (!matches) return
    activeSessionId.value = event.sessionId
  }

  streamText.value += event.chunk
  // 限制展示长度，避免长回答撑爆内存/渲染
  if (streamText.value.length > 8000) {
    streamText.value = streamText.value.slice(-8000)
  }
  requestAnimationFrame(() => {
    const box = streamBoxRef.value
    if (box) box.scrollTop = box.scrollHeight
  })
})
onUnmounted(() => unsubscribeStream())

// 进度步骤条。后端 stage 到展示步骤的映射：
// 挑战发出只占几毫秒，等待模型生成才是主体——所以 sending 阶段
// 直接视为"发送"已完成、"生成回答"进行中，长等待期高亮第二步而非卡在第一步。
const progressSteps = computed(() => {
  if (!progress.value) return []
  const order = ['sending', 'received', 'done'] as const
  const labels: Record<string, string> = {
    sending: t('components.main.modelTrace.stepSending'),
    received: t('components.main.modelTrace.stepReceived'),
    done: t('components.main.modelTrace.stepDone'),
  }
  // stage -> 已完成的步骤数：sending(第0步完成,高亮第1步) / received(第1步完成,高亮第2步) / done(全部完成)
  const completedByStage: Record<string, number> = {
    sending: 1,
    retrying: 1,
    received: 2,
    done: 3,
    failed: 3,
  }
  const completed = completedByStage[progress.value.stage] ?? 1
  return order.map((key, index) => ({
    key,
    label: labels[key],
    done: index < completed,
    active: index === completed,
  }))
})

// 本地计时器：后端事件只在阶段切换时推送，几十秒的等待期内没有事件，
// 事件里的 elapsedMs 会一直停在阶段开始时刻。用前端本地时钟自己走秒，
// 展示时取 max(本地, 后端事件值) 防止倒退。
const localElapsedMs = ref(0)
let elapsedTimer: number | null = null

const elapsedLabel = computed(() =>
  `${(Math.max(localElapsedMs.value, progress.value?.elapsedMs ?? 0) / 1000).toFixed(1)}s`,
)

const startElapsedTimer = () => {
  stopElapsedTimer()
  localElapsedMs.value = 0
  const startedAt = Date.now()
  elapsedTimer = window.setInterval(() => {
    localElapsedMs.value = Date.now() - startedAt
  }, 100)
}

const stopElapsedTimer = () => {
  if (elapsedTimer !== null) {
    window.clearInterval(elapsedTimer)
    elapsedTimer = null
  }
}

onUnmounted(() => stopElapsedTimer())

// 打开时加载指纹库模型列表
watch(
  () => props.open,
  async (open) => {
    if (!open) return
    requestSeq.value += 1 // 使在途旧请求失效
    result.value = null
    verifying.value = false
    progress.value = null
    activeSessionId.value = ''
    activeRequest.value = null
    streamText.value = ''
    if (models.value.length === 0) {
      try {
        models.value = await getSupportedModels()
      } catch (error) {
        console.error('Failed to load supported models', error)
      }
    }
  },
)

const topProbabilities = computed(() =>
  (result.value?.probabilities ?? []).slice(0, 6),
)

const formatProbability = (value: number) => `${(value * 100).toFixed(1)}%`

const barWidth = (probability: number) => {
  const max = result.value?.topProbability || 1
  const ratio = max > 0 ? probability / max : 0
  return `${Math.max(ratio * 100, probability > 0 ? 2 : 0)}%`
}

const handleVerify = async () => {
  if (!selectedModel.value || verifying.value) return
  verifying.value = true
  result.value = null
  progress.value = null
  activeSessionId.value = ''
  streamText.value = ''
  activeRequest.value = { providerId: props.providerId, expectedModel: selectedModel.value }
  startElapsedTimer()
  const seq = ++requestSeq.value
  try {
    const response = await verifyProviderModel(
      props.platform,
      props.providerId,
      selectedModel.value,
    )
    if (seq !== requestSeq.value) return // 请求已过期（弹窗重开或重新发起），丢弃
    result.value = response
  } catch (error) {
    if (seq !== requestSeq.value) return
    result.value = {
      success: false,
      message: extractErrorMessage(error),
      expectedModel: selectedModel.value,
      expectedMatched: false,
      topModel: '',
      topModelName: '',
      topProbability: 0,
      verdict: 'error',
      validNumberCount: 0,
      attempts: 0,
      latencyMs: 0,
      probabilities: [],
    }
  } finally {
    if (seq === requestSeq.value) {
      verifying.value = false
      activeRequest.value = null
      stopElapsedTimer()
    }
  }
}
</script>

<style scoped>
.modeltrace-body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.modeltrace-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--mac-text, #1f2937);
  margin: 0 0 8px;
}

.modeltrace-provider {
  font-weight: 400;
  opacity: 0.7;
}

.modeltrace-model-grid {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.modeltrace-model-chip {
  padding: 6px 12px;
  border-radius: 999px;
  border: 1px solid rgba(15, 23, 42, 0.18);
  background: rgba(15, 23, 42, 0.04);
  color: var(--mac-text, #1f2937);
  font-size: 12.5px;
  cursor: pointer;
  transition: all 0.15s ease;
}

.modeltrace-model-chip:hover {
  border-color: rgba(15, 23, 42, 0.4);
}

.modeltrace-model-chip.selected {
  background: rgba(10, 132, 255, 0.14);
  border-color: #0a84ff;
  /* 蓝色 #0a84ff 在选中底色上只有 3.08:1，文字改用同色系更深的蓝 */
  color: #0060bf;
  font-weight: 600;
}

.modeltrace-model-chip.family-claude.selected {
  background: rgba(217, 119, 87, 0.14);
  border-color: #d97757;
  /* 品牌橙 #d97757 在选中底色上只有 2.71:1，文字压深 */
  color: #a2421f;
}

html.dark .modeltrace-model-chip {
  border-color: rgba(255, 255, 255, 0.2);
  background: rgba(255, 255, 255, 0.06);
}

/* 深色底上要用浅色文字，浅色模式的加深色在这里会反过来不达标 */
html.dark .modeltrace-model-chip.selected {
  background: rgba(10, 132, 255, 0.22);
  border-color: #6cb2ff;
  color: #6cb2ff;
}

html.dark .modeltrace-model-chip.family-claude.selected {
  background: rgba(217, 119, 87, 0.22);
  border-color: #f0a184;
  color: #f0a184;
}

.modeltrace-actions {
  display: flex;
  justify-content: flex-end;
}

/* ===== 实时进度 ===== */
.modeltrace-progress {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px 14px 12px;
  border-radius: 10px;
  background: rgba(10, 132, 255, 0.06);
  border: 1px solid rgba(10, 132, 255, 0.18);
}

html.dark .modeltrace-progress {
  background: rgba(10, 132, 255, 0.1);
}

.progress-steps {
  display: flex;
  align-items: center;
}

.progress-step {
  display: flex;
  align-items: center;
  gap: 6px;
  flex: 1;
  position: relative;
}

.progress-step:not(:last-child)::after {
  content: '';
  flex: 1;
  height: 2px;
  margin: 0 8px;
  background: rgba(15, 23, 42, 0.12);
  border-radius: 1px;
}

html.dark .progress-step:not(:last-child)::after {
  background: rgba(255, 255, 255, 0.15);
}

.progress-step.done:not(:last-child)::after,
.progress-step.active:not(:last-child)::after {
  background: #0a84ff;
}

.step-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: rgba(15, 23, 42, 0.2);
  flex-shrink: 0;
}

html.dark .step-dot {
  background: rgba(255, 255, 255, 0.25);
}

.progress-step.active .step-dot {
  background: #0a84ff;
  box-shadow: 0 0 0 0 rgba(10, 132, 255, 0.5);
  animation: step-pulse 1.4s ease-out infinite;
}

.progress-step.done .step-dot {
  background: #22c55e;
}

@keyframes step-pulse {
  0% { box-shadow: 0 0 0 0 rgba(10, 132, 255, 0.5); }
  70% { box-shadow: 0 0 0 7px rgba(10, 132, 255, 0); }
  100% { box-shadow: 0 0 0 0 rgba(10, 132, 255, 0); }
}

.step-label {
  font-size: 12px;
  color: var(--mac-text, #374151);
  opacity: 0.55;
  white-space: nowrap;
}

.progress-step.active .step-label {
  opacity: 1;
  font-weight: 600;
  /* 进度面板自带蓝色底纹，纯品牌蓝 #0a84ff 在其上不足 4.5:1 */
  color: #0060bf;
}

html.dark .progress-step.active .step-label {
  color: #6cb2ff;
}

.progress-step.done .step-label {
  opacity: 0.8;
}

.progress-detail {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 10px;
}

.progress-detail-text {
  font-size: 12.5px;
  line-height: 1.5;
  color: var(--mac-text, #374151);
  animation: progress-fade-in 0.3s ease;
}

@keyframes progress-fade-in {
  from { opacity: 0; transform: translateY(3px); }
  to { opacity: 1; transform: translateY(0); }
}

.progress-elapsed {
  font-size: 11.5px;
  font-variant-numeric: tabular-nums;
  /* 不用 opacity 降透明度：半透明文字在蓝色底纹上只有 3.7:1 */
  color: var(--mac-text-secondary);
  flex-shrink: 0;
}

html.dark .progress-elapsed {
  color: #b7bac7;
}

/* ===== 模型实时生成内容小窗 ===== */
.stream-box {
  margin-top: 2px;
  max-height: 88px;
  overflow-y: auto;
  padding: 8px 10px;
  border-radius: 8px;
  background: rgba(15, 23, 42, 0.05);
  border: 1px solid rgba(15, 23, 42, 0.08);
  font-family: ui-monospace, 'SF Mono', SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11.5px;
  line-height: 1.55;
  color: var(--mac-text, #374151);
  word-break: break-all;
  white-space: pre-wrap;
}

html.dark .stream-box {
  background: rgba(255, 255, 255, 0.05);
  border-color: rgba(255, 255, 255, 0.1);
}

.stream-box::-webkit-scrollbar {
  width: 4px;
}

.stream-box::-webkit-scrollbar-thumb {
  background: rgba(15, 23, 42, 0.2);
  border-radius: 2px;
}

.stream-placeholder {
  display: inline-flex;
  align-items: center;
  gap: 7px;
  color: var(--mac-text-secondary, #6b7280);
  font-size: 11px;
  user-select: none;
}

.stream-pulse-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: var(--primary-color, #3b82f6);
  display: inline-block;
  animation: stream-pulse 1.4s ease-in-out infinite;
}

@keyframes stream-pulse {
  0%, 100% {
    opacity: 0.3;
    transform: scale(0.85);
  }
  50% {
    opacity: 1;
    transform: scale(1.15);
  }
}

.modeltrace-result {
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.modeltrace-verdict {
  display: flex;
  gap: 12px;
  align-items: flex-start;
  padding: 12px 14px;
  border-radius: 10px;
}

.verdict-match {
  background: rgba(34, 197, 94, 0.1);
  border-left: 3px solid #22c55e;
}

.verdict-mismatch {
  background: rgba(239, 68, 68, 0.1);
  border-left: 3px solid #ef4444;
}

.verdict-error {
  background: rgba(239, 68, 68, 0.08);
  border-left: 3px solid #f59e0b;
}

.verdict-icon {
  font-size: 18px;
  line-height: 1.2;
}

.verdict-match .verdict-icon { color: #16a34a; }
.verdict-mismatch .verdict-icon { color: #dc2626; }
.verdict-error .verdict-icon { color: #d97706; }

.verdict-text { flex: 1; }

.verdict-title {
  margin: 0 0 2px;
  font-size: 14px;
  font-weight: 700;
}

/* 判定标题要在各自的浅色底纹上达到 4.5:1，因此比图标用的品牌色更深一档 */
.verdict-match .verdict-title { color: #137a3a; }
.verdict-mismatch .verdict-title { color: #b91c1c; }
.verdict-error .verdict-title { color: #a04a08; }

html.dark .verdict-match .verdict-title { color: #4ade80; }
html.dark .verdict-mismatch .verdict-title { color: #f87171; }
html.dark .verdict-error .verdict-title { color: #fbbf24; }

.verdict-detail {
  margin: 0;
  font-size: 12.5px;
  line-height: 1.5;
  color: var(--mac-text, #374151);
  opacity: 0.85;
  word-break: break-word;
}

.modeltrace-bars {
  display: flex;
  flex-direction: column;
  gap: 6px;
}

.modeltrace-bar-row {
  display: grid;
  grid-template-columns: 150px 1fr 52px;
  align-items: center;
  gap: 10px;
  font-size: 12px;
  padding: 2px 4px;
  border-radius: 6px;
}

.modeltrace-bar-row.is-top {
  background: rgba(10, 132, 255, 0.07);
}

.modeltrace-bar-row.is-expected .bar-model::after {
  content: ' ✓';
  color: #16a34a;
  font-weight: 700;
}

.bar-model {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.bar-track {
  height: 10px;
  border-radius: 5px;
  background: rgba(15, 23, 42, 0.08);
  overflow: hidden;
}

html.dark .bar-track {
  background: rgba(255, 255, 255, 0.12);
}

.bar-fill {
  height: 100%;
  border-radius: 5px;
  transition: width 0.4s ease;
}

.fill-top { background: #0a84ff; }
.fill-normal { background: rgba(10, 132, 255, 0.35); }

.bar-value {
  text-align: right;
  font-variant-numeric: tabular-nums;
  opacity: 0.75;
}

.modeltrace-meta {
  display: flex;
  gap: 14px;
  flex-wrap: wrap;
  font-size: 11.5px;
  opacity: 0.65;
}
</style>
