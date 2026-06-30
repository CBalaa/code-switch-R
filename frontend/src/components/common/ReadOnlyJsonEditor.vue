<script setup lang="ts">
import { computed } from 'vue'

type JsonToken = { text: string; className?: string }

const props = withDefaults(defineProps<{
  value: string
  height?: string
}>(), {
  value: '',
  height: '220px',
})

const formattedJson = computed(() => {
  const text = (props.value || '').trim()
  if (!text) return ''
  try {
    return JSON.stringify(JSON.parse(text), null, 2)
  } catch {
    return props.value || ''
  }
})

const tokens = computed<JsonToken[]>(() => {
  const text = formattedJson.value
  const parts: JsonToken[] = []
  const regex = /"(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g
  let lastIndex = 0
  let match: RegExpExecArray | null

  while ((match = regex.exec(text)) !== null) {
    if (match.index > lastIndex) {
      parts.push({ text: text.slice(lastIndex, match.index) })
    }

    const token = match[0]
    let className = 'json-string'
    if (token === 'true' || token === 'false') className = 'json-bool'
    else if (token === 'null') className = 'json-null'
    else if (/^-?\d/.test(token)) className = 'json-number'
    else if (text.slice(match.index + token.length).trimStart().startsWith(':')) className = 'json-key'
    parts.push({ text: token, className })
    lastIndex = match.index + token.length
  }

  if (lastIndex < text.length) {
    parts.push({ text: text.slice(lastIndex) })
  }

  return parts
})
</script>

<template>
  <div class="readonly-json-editor-shell">
    <pre class="readonly-json-editor" :style="{ minHeight: props.height, maxHeight: props.height }"><code><span
      v-for="(token, index) in tokens"
      :key="index"
      :class="token.className"
    >{{ token.text }}</span></code></pre>
  </div>
</template>

<style scoped>
.readonly-json-editor-shell {
  width: 100%;
  max-width: 100%;
  overflow-x: auto;
}

.readonly-json-editor {
  margin: 0;
  padding: 10px 12px;
  overflow: visible;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
  background: var(--mac-surface);
  color: var(--mac-text);
  white-space: pre;
  word-break: normal;
  tab-size: 2;
  font-family: 'SFMono-Regular', Menlo, Consolas, monospace;
  font-size: 13px;
  line-height: 1.5;
  width: fit-content;
  min-width: 100%;
}

.readonly-json-editor code {
  color: inherit;
  display: block;
  min-width: max-content;
}

.json-key { color: #9f1239; }
.json-string { color: #047857; }
.json-number { color: #2563eb; }
.json-bool { color: #b45309; }
.json-null { color: #7c3aed; }
</style>
