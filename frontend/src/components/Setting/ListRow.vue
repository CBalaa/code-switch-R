<script setup lang="ts">
defineProps<{
   label: string
   subLabel?: string
 }>()
</script>

<template>
  <div class="mac-list-row">
    <div class="mac-list-text">
      <div class="mac-list-label">{{ label }}</div>
      <div v-if="subLabel" class="mac-list-sublabel">{{ subLabel }}</div>
    </div>
    <div class="mac-list-control">
      <slot />
    </div>
  </div>
</template>

<style scoped>
.mac-list-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  gap: 16px;
}

.mac-list-text {
  text-align: left;
}

.mac-list-label {
  font-size: 0.95rem;
  font-weight: 600;
  color: var(--mac-text);
}

.mac-list-sublabel {
  font-size: 0.8rem;
  color: var(--mac-text-secondary);
  margin-top: 4px;
}

.mac-list-control {
  display: inline-flex;
  align-items: center;
  justify-content: flex-end;
}

@media (max-width: 760px) {
  .mac-list-row {
    align-items: stretch;
    flex-direction: column;
    gap: 10px;
    padding: 14px;
  }

  .mac-list-control {
    justify-content: flex-start;
    width: 100%;
    min-width: 0;
  }
}
</style>
