<template>
  <span class="help-hint" @mouseenter="show" @mouseleave="hide">
    <svg viewBox="0 0 24 24" class="help-icon" aria-hidden="true">
      <circle cx="12" cy="12" r="10" fill="none" stroke="currentColor" stroke-width="1.5" />
      <path d="M9.09 9a3 3 0 015.83 1c0 2-3 3-3 3" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" />
      <line x1="12" y1="17" x2="12.01" y2="17" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" />
    </svg>
    <span v-if="visible" class="help-tooltip">{{ text }}</span>
  </span>
</template>

<script setup lang="ts">
import { ref } from 'vue'

defineProps<{ text: string }>()
const visible = ref(false)
const show = () => { visible.value = true }
const hide = () => { visible.value = false }
</script>

<style scoped>
.help-hint {
  display: inline-flex;
  align-items: center;
  position: relative;
  margin-left: 4px;
  cursor: help;
}

.help-icon {
  width: 14px;
  height: 14px;
  color: var(--color-text-tertiary, #9ca3af);
  transition: color 0.15s;
}

.help-hint:hover .help-icon {
  color: var(--color-primary, #3b82f6);
}

.help-tooltip {
  position: absolute;
  bottom: calc(100% + 6px);
  left: -8px;
  min-width: 180px;
  max-width: 320px;
  padding: 8px 12px;
  border-radius: 8px;
  background: var(--color-bg-tooltip, #1e293b);
  color: var(--color-text-tooltip, #f1f5f9);
  font-size: 12px;
  line-height: 1.5;
  white-space: normal;
  z-index: 1000;
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
  pointer-events: none;
}

.help-tooltip::after {
  content: '';
  position: absolute;
  top: 100%;
  left: 16px;
  border: 6px solid transparent;
  border-top-color: var(--color-bg-tooltip, #1e293b);
}
</style>