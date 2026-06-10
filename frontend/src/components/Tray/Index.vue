<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, proxyRefs, ref } from 'vue'
import { Call } from '@wailsio/runtime'
import { fetchProxyStatus } from '../../services/claudeSettings'

type Platform = 'claude' | 'openai-responses'

const rootRef = ref<HTMLElement | null>(null)
let refreshBusy = false

const createTrayCard = (platform: Platform, brandName: string, brandIcon: string) => {
  const hostingEnabled = ref(false)
  const loading = ref(false)
  const hostingLabel = computed(() => (hostingEnabled.value ? '托管中' : '未托管'))

  const refresh = async () => {
    loading.value = true
    try {
      const status = await fetchProxyStatus(platform)
      hostingEnabled.value = Boolean(status?.enabled)
    } catch (error) {
      console.error(`failed to load ${platform} proxy status`, error)
    } finally {
      loading.value = false
    }
  }

  return proxyRefs({
    platform,
    brandName,
    brandIcon,
    hostingEnabled,
    hostingLabel,
    loading,
    refresh,
  })
}

const claudeCard = createTrayCard('claude', 'Claude Code', 'C')
const responsesCard = createTrayCard('openai-responses', 'OpenAI Responses', 'R')
const cards = [claudeCard, responsesCard]

const resizeToContent = async () => {
  await nextTick()
  if (!rootRef.value) return
  const height = Math.ceil(rootRef.value.getBoundingClientRect().height)
  if (height <= 0) return
  try {
    await Call.ByName('main.AppService.SetTrayWindowHeight', height)
  } catch (error) {
    console.error('failed to resize tray window', error)
  }
}

const refreshAll = async () => {
  if (refreshBusy) return
  refreshBusy = true
  try {
    await Promise.all(cards.map((card) => card.refresh()))
  } finally {
    refreshBusy = false
    await resizeToContent()
  }
}

const handleFocus = () => {
  void refreshAll()
}

onMounted(() => {
  void refreshAll()
  window.addEventListener('focus', handleFocus)
  window.addEventListener('app-settings-updated', handleFocus)
})

onUnmounted(() => {
  window.removeEventListener('focus', handleFocus)
  window.removeEventListener('app-settings-updated', handleFocus)
})
</script>

<template>
  <div ref="rootRef" class="tray-root">
    <div class="tray-list">
      <div v-for="card in cards" :key="card.platform" class="tray-panel">
        <div class="tray-header">
          <div class="tray-brand">
            <div class="tray-brand__icon" aria-hidden="true">{{ card.brandIcon }}</div>
            <span class="tray-brand__name">{{ card.brandName }}</span>
          </div>
          <div class="tray-status" :class="{ active: card.hostingEnabled, loading: card.loading }">
            <span class="tray-status__dot"></span>
            <span class="tray-status__text">{{ card.loading ? '刷新中' : card.hostingLabel }}</span>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.tray-root {
  padding: 10px;
}

.tray-list {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.tray-panel {
  background: #f1f2f4;
  border-radius: 16px;
  padding: 12px 14px;
  box-shadow: 0 10px 24px rgba(0, 0, 0, 0.18);
  border: 1px solid rgba(0, 0, 0, 0.05);
}

.tray-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.tray-brand {
  display: flex;
  align-items: center;
  gap: 10px;
}

.tray-brand__icon {
  width: 28px;
  height: 28px;
  border-radius: 8px;
  background: #ffffff;
  border: 1px solid rgba(0, 0, 0, 0.08);
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  font-weight: 700;
  color: #2f2f2f;
  box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08);
}

.tray-brand__name {
  font-size: 13px;
  font-weight: 600;
  color: #2f2f2f;
}

.tray-status {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  color: #7a7f86;
}

.tray-status__dot {
  width: 8px;
  height: 8px;
  border-radius: 999px;
  background: #cbd5e1;
  box-shadow: 0 0 0 2px rgba(203, 213, 225, 0.4);
}

.tray-status.active {
  color: #2f2f2f;
}

.tray-status.active .tray-status__dot {
  background: #5dbb63;
  box-shadow: 0 0 0 2px rgba(93, 187, 99, 0.25);
}

.tray-status.loading .tray-status__dot {
  background: #f59e0b;
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.25);
}
</style>
