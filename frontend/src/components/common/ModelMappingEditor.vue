<template>
  <div class="model-mapping-editor">
    <div class="editor-header">
      <label class="editor-label">
        <span>{{ $t('components.provider.modelMapping.label') }}</span>
        <span class="help-hint-inline" @mouseenter="tooltipVisible = true" @mouseleave="tooltipVisible = false">
          <svg viewBox="0 0 24 24" class="qmark-icon" aria-hidden="true">
            <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="1.5" />
            <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
            <line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
          </svg>
          <span v-if="tooltipVisible" class="hint-popup">
            <span class="hint-popup-title">{{ $t('components.provider.modelMapping.tooltip') }}</span>
            <span class="hint-popup-examples">
              <code>claude-sonnet-4</code> → <code>anthropic/claude-sonnet-4</code><br/>
              {{ $t('components.provider.modelMapping.examples.exact') }}<br/><br/>
              <code>claude-*</code> → <code>anthropic/claude-*</code><br/>
              {{ $t('components.provider.modelMapping.examples.wildcard') }}<br/><br/>
              <code>gpt-*</code> → <code>openai/gpt-*</code><br/>
              {{ $t('components.provider.modelMapping.examples.prefix') }}
            </span>
          </span>
        </span>
      </label>
    </div>

    <!-- 已添加的映射规则列表 -->
    <div v-if="mappingList.length > 0" class="mapping-list">
      <div
        v-for="(mapping, index) in mappingList"
        :key="index"
        class="mapping-row"
      >
        <div class="mapping-content">
          <code class="mapping-key" :class="{ wildcard: isWildcard(mapping.key) }">
            {{ mapping.key }}
          </code>
          <svg class="mapping-arrow" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
            <path
              d="M6 4l4 4-4 4"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
          </svg>
          <code class="mapping-value" :class="{ wildcard: isWildcard(mapping.value) }">
            {{ mapping.value }}
          </code>
        </div>
        <button
          type="button"
          class="mapping-remove"
          :aria-label="$t('components.provider.modelMapping.remove')"
          @click="removeMapping(index)"
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

    <!-- 添加新映射规则输入框 -->
    <div class="mapping-input-row">
      <BaseInput
        v-model="newKey"
        type="text"
        :placeholder="$t('components.provider.modelMapping.keyPlaceholder')"
        @keydown.enter.prevent="focusValueInput"
      />
      <svg class="input-arrow" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
        <path
          d="M6 4l4 4-4 4"
          fill="none"
          stroke="currentColor"
          stroke-width="1.5"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </svg>
      <BaseInput
        ref="valueInputRef"
        v-model="newValue"
        type="text"
        :placeholder="$t('components.provider.modelMapping.valuePlaceholder')"
        @keydown.enter.prevent="addMapping"
      />
      <BaseButton
        type="button"
        variant="outline"
        @click="addMapping"
      >
        {{ $t('components.provider.modelMapping.add') }}
      </BaseButton>
    </div>

  </div>
</template>

<script setup lang="ts">
import { ref, computed } from 'vue'
import BaseInput from './BaseInput.vue'
import BaseButton from './BaseButton.vue'

interface Props {
  modelValue?: Record<string, string>
}

interface Emits {
  (e: 'update:modelValue', value: Record<string, string>): void
}

const props = defineProps<Props>()
const emit = defineEmits<Emits>()

// 将 Record<string, string> 转换为数组便于展示
const mappingList = computed(() => {
  if (!props.modelValue) return []
  return Object.entries(props.modelValue).map(([key, value]) => ({ key, value }))
})

const newKey = ref('')
const newValue = ref('')
const valueInputRef = ref<InstanceType<typeof BaseInput> | null>(null)
const tooltipVisible = ref(false)

const isWildcard = (text: string) => text.includes('*')

const focusValueInput = () => {
  // 当在 key 输入框按 Enter 时，聚焦到 value 输入框
  if (valueInputRef.value) {
    const inputElement = (valueInputRef.value as any).$el?.querySelector('input')
    if (inputElement) {
      inputElement.focus()
    }
  }
}

const addMapping = () => {
  const key = newKey.value.trim()
  const value = newValue.value.trim()

  if (!key || !value) return

  // 检查是否已存在相同的 key
  if (props.modelValue && props.modelValue[key]) {
    // 可以选择覆盖或提示用户
    // 这里选择覆盖
  }

  // 添加到映射列表
  const updated = { ...props.modelValue }
  updated[key] = value
  emit('update:modelValue', updated)

  // 清空输入框
  newKey.value = ''
  newValue.value = ''
}

const removeMapping = (index: number) => {
  const mapping = mappingList.value[index]
  if (!mapping) return

  const updated = { ...props.modelValue }
  delete updated[mapping.key]
  emit('update:modelValue', updated)
}
</script>

<style scoped>
.model-mapping-editor {
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

.mapping-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding: 10px;
  background-color: var(--background-secondary);
  border-radius: 8px;
}

.mapping-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 8px 10px;
  background-color: var(--background);
  border: 1px solid var(--border);
  border-radius: 6px;
  transition: all 0.2s;
}

.mapping-row:hover {
  background-color: var(--background-hover);
}

.mapping-content {
  display: flex;
  align-items: center;
  gap: 10px;
  flex: 1;
  min-width: 0;
}

.mapping-key,
.mapping-value {
  padding: 3px 7px;
  background-color: var(--background-secondary);
  border: 1px solid var(--border);
  border-radius: 4px;
  font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
  font-size: 0.75rem;
  color: var(--foreground);
  word-break: break-all;
}

.mapping-key.wildcard,
.mapping-value.wildcard {
  color: var(--accent-primary);
  font-weight: 500;
}

.mapping-arrow {
  flex-shrink: 0;
  color: var(--foreground-muted);
}

.mapping-remove {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 4px;
  border: none;
  background: none;
  color: var(--foreground-muted);
  cursor: pointer;
  border-radius: 3px;
  flex-shrink: 0;
  transition: all 0.2s;
}

.mapping-remove:hover {
  color: var(--error);
  background-color: var(--error-bg);
}

.mapping-input-row {
  display: flex;
  gap: 8px;
  align-items: center;
}

.mapping-input-row :deep(input) {
  flex: 1;
  font-family: 'SF Mono', 'Menlo', 'Monaco', 'Courier New', monospace;
}

.input-arrow {
  flex-shrink: 0;
  color: var(--foreground-muted);
}
</style>
