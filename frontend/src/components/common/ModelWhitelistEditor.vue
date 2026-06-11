<template>
  <div class="model-whitelist-editor">
    <div class="editor-header">
      <label class="editor-label">
        <span>{{ $t('components.provider.modelWhitelist.label') }}</span>
        <span class="help-hint-inline" @mouseenter="tooltipVisible = true" @mouseleave="tooltipVisible = false">
          <svg viewBox="0 0 24 24" class="qmark-icon" aria-hidden="true">
            <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            <line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
          <span v-if="tooltipVisible" class="hint-popup">
            <span class="hint-popup-title">{{ $t('components.provider.modelWhitelist.tooltip') }}</span>
            <span class="hint-popup-examples">
              <code>claude-sonnet-4</code> – {{ $t('components.provider.modelWhitelist.examples.exact') }}<br/>
              <code>claude-*</code> – {{ $t('components.provider.modelWhitelist.examples.prefix') }}<br/>
              <code>anthropic/claude-*</code> – {{ $t('components.provider.modelWhitelist.examples.vendor') }}
            </span>
          </span>
        </span>
      </label>
    </div>

    <!-- 已添加的模型列表 -->
    <div v-if="modelList.length > 0" class="model-tags">
      <div
        v-for="(model, index) in modelList"
        :key="index"
        class="model-tag"
      >
        <span class="model-name" :class="{ wildcard: isWildcard(model) }">{{ model }}</span>
        <button
          type="button"
          class="tag-remove"
          :aria-label="$t('components.provider.modelWhitelist.remove')"
          @click="removeModel(index)"
        >
          <svg viewBox="0 0 12 12" width="10" height="10" aria-hidden="true">
            <path
              d="M3 3l6 6M9 3l-6 6"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
            />
          </svg>
        </button>
      </div>
    </div>

    <!-- 添加新模型输入框 -->
    <div class="model-input-row">
      <BaseInput
        v-model="newModel"
        type="text"
        :placeholder="$t('components.provider.modelWhitelist.placeholder')"
        @keydown.enter.prevent="addModel"
      />
      <BaseButton
        type="button"
        variant="outline"
        @click="addModel"
      >
        {{ $t('components.provider.modelWhitelist.add') }}
      </BaseButton>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import BaseInput from './BaseInput.vue'
import BaseButton from './BaseButton.vue'

interface Props {
  modelValue?: Record<string, boolean>
}

interface Emits {
  (e: 'update:modelValue', value: Record<string, boolean>): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

// 将 Record<string, boolean> 转换为数组便于展示
const modelList = computed(() => {
  if (!props.modelValue) return []
  return Object.keys(props.modelValue).filter((key) => props.modelValue![key])
})

const newModel = ref('')
const tooltipVisible = ref(false)

const isWildcard = (model: string) => model.includes('*')

const addModel = () => {
  const trimmed = newModel.value.trim()
  if (!trimmed) return

  // 检查是否已存在
  if (props.modelValue && props.modelValue[trimmed]) {
    newModel.value = ''
    return
  }

  // 添加到模型列表
  const updated = { ...props.modelValue }
  updated[trimmed] = true
  emit('update:modelValue', updated)
  newModel.value = ''
}

const removeModel = (index: number) => {
  const modelName = modelList.value[index]
  if (!modelName) return

  const updated = { ...props.modelValue }
  delete updated[modelName]
  emit('update:modelValue', updated)
}

// 初始化空对象
watch(
  () => props.modelValue,
  (value) => {
    if (value === undefined) {
      emit('update:modelValue', {})
    }
  },
  { immediate: true }
)
</script>

<style scoped>
.model-whitelist-editor {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.editor-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.editor-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 500;
  font-size: 0.875rem;
  color: var(--foreground);
}

.help-hint-inline {
  position: relative;
  display: inline-flex;
  align-items: center;
  cursor: help;
}

.qmark-icon {
  width: 14px;
  height: 14px;
  color: var(--foreground-muted);
  transition: color 0.15s;
}

.help-hint-inline:hover .qmark-icon {
  color: var(--accent-primary);
}

.hint-popup {
  position: absolute;
  bottom: calc(100% + 8px);
  left: -8px;
  min-width: 200px;
  max-width: 360px;
  padding: 10px 14px;
  border-radius: 8px;
  background: #1e293b;
  color: #f1f5f9;
  font-size: 12px;
  line-height: 1.6;
  white-space: normal;
  z-index: 1000;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  pointer-events: none;
}

.hint-popup::after {
  content: '';
  position: absolute;
  top: 100%;
  left: 16px;
  border: 6px solid transparent;
  border-top-color: #1e293b;
}

.hint-popup-title {
  display: block;
  margin-bottom: 6px;
  font-weight: 600;
}

.hint-popup-examples {
  display: block;
  font-size: 11px;
  line-height: 1.7;
}

.hint-popup-examples code {
  padding: 1px 5px;
  background: rgba(255,255,255,0.12);
  border-radius: 3px;
  font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 11px;
}

.model-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  padding: 10px;
  background-color: var(--background-secondary);
  border-radius: 8px;
  min-height: 44px;
}

.model-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 8px 4px 10px;
  background-color: var(--background);
  border: 1px solid var(--border);
  border-radius: 6px;
  font-size: 0.8125rem;
  line-height: 1.4;
  transition: all 0.2s;
}

.model-tag:hover {
  background-color: var(--background-hover);
}

.model-name {
  color: var(--foreground);
  font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
}

.model-name.wildcard {
  color: var(--accent-primary);
  font-weight: 500;
}

.tag-remove {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 2px;
  border: none;
  background: none;
  color: var(--foreground-muted);
  cursor: pointer;
  border-radius: 3px;
  transition: all 0.2s;
}

.tag-remove:hover {
  color: var(--error);
  background-color: var(--error-bg);
}

.model-input-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.model-input-row :deep(input) {
  flex: 1;
  font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
}
</style>
