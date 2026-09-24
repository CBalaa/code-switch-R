<script setup lang="ts">
import { computed, ref, watch, onMounted, onUnmounted, onActivated, onDeactivated } from 'vue'
import { useI18n } from 'vue-i18n'
import type { AutomationCard } from '../../data/cards'
import { newAPIAccountReady, newAPIAccountAmount, newAPIStates, newAPIAmount, newAPIExpiry, getProviderInfo, infoAmount, infoUnlimited, infoScope, infoRemaining, infoRate, infoTime, type ProviderInfo, type ProviderInfoRef } from '../../services/providerInfo'
import NewApiInfoDetails from './NewApiInfoDetails.vue'
import ProviderInfoDetails from './ProviderInfoDetails.vue'
const props = defineProps<{ card: AutomationCard; providerRef: ProviderInfoRef; revision: number; theme: string }>()
const { t } = useI18n()
const data = ref<ProviderInfo | null>(null)
const busy = ref(false)
const failed = ref(false)
const open = ref(false)
let generation = 0
let active = true
let timer: number | undefined
const identity = computed(() => JSON.stringify([props.providerRef, props.card.apiUrl, props.card.apiKey, props.card.upstreamInfo]))
const remaining = computed(() => infoRemaining(data.value?.usage))
const amount = computed(() => infoUnlimited(data.value?.usage) ? t('upstreamInfo.unlimited') : infoAmount(remaining.value, data.value?.usage?.unit || data.value?.usage?.quota?.unit))
const isNewAPI = computed(() => props.card.upstreamInfo?.type === 'newapi')
const states = computed(() => data.value ? (isNewAPI.value ? newAPIStates(data.value).map(p => p.state) : [data.value.usageState, data.value.billingState]) : [])
const stale = computed(() => states.value.some(s => s.stale))
const partial = computed(() => states.value.some(s => s.status !== 'ready'))
const refreshedAt = computed(() => states.value.map(s => s.updatedAt).filter((s): s is string => !!s).sort().at(-1))
async function refresh(force = false) {
  if (!active || document.hidden || busy.value || !props.providerRef.id) return
  const run = ++generation
  busy.value = true; failed.value = false
  try {
    const result = await getProviderInfo({ ...props.providerRef }, force)
    if (generation === run) data.value = result
  } catch {
    if (generation === run) {
      failed.value = true
      if (data.value?.accountState) data.value = { ...data.value, account: undefined, accountState: { status: 'network', stale: false } }
    }
  }
  finally { if (generation === run) busy.value = false }
}
function start() {
  if (!active || document.hidden) return
  if (timer != null) window.clearInterval(timer)
  void refresh()
  timer = window.setInterval(() => void refresh(), 300000)
}
function stop() { if (timer != null) window.clearInterval(timer); timer = undefined }
function visibility() { document.hidden ? stop() : start() }
watch(identity, () => { generation++; data.value = null; busy.value = false; failed.value = false; open.value = false; void refresh() })
watch(() => props.revision, () => { generation++; busy.value = false; void refresh() })
onMounted(() => { document.addEventListener('visibilitychange', visibility); start() })
onActivated(() => { active = true; start() })
onDeactivated(() => { active = false; open.value = false; stop() })
onUnmounted(() => { active = false; generation++; stop(); document.removeEventListener('visibilitychange', visibility) })
</script>
<template>
  <div class="upstream-panel" draggable="false" @click.stop @mousedown.stop @dragstart.stop.prevent>
    <div class="upstream-head">
      <span class="upstream-label">{{ t('upstreamInfo.title') }} <small>{{ isNewAPI ? 'New API' : 'sub2api' }}</small></span>
      <div class="upstream-actions">
        <button type="button" :disabled="busy" :aria-label="t('upstreamInfo.refresh')" @click="refresh(true)">{{ t(busy ? 'upstreamInfo.loading' : 'upstreamInfo.refresh') }}</button>
        <button type="button" @click="open = true">{{ t('upstreamInfo.details') }} ↗</button>
      </div>
    </div>
    <div v-if="isNewAPI && (data?.key || newAPIAccountReady(data))" class="upstream-metrics">
      <span v-if="newAPIAccountReady(data)" class="account-balance">{{ t('upstreamInfo.wallet') }} <strong :class="{ exhausted: data?.account?.quota != null && data.account.quota <= 0 }">{{ newAPIAccountAmount(data, t('upstreamInfo.rawUnit')) }}</strong></span>
      <template v-if="data?.key">
      <span>{{ t('upstreamInfo.keyQuota') }} <strong :class="{ exhausted: !data.key.unlimited_quota && data.key.total_available != null && data.key.total_available <= 0 }">{{ data.key.unlimited_quota ? t('upstreamInfo.unlimited') : newAPIAmount(data, 'remaining', t('upstreamInfo.rawUnit')) }}</strong></span>
      <span>{{ t('upstreamInfo.keyUsed') }} <strong>{{ newAPIAmount(data, 'used', t('upstreamInfo.rawUnit')) }}</strong></span>
      <span>{{ t('upstreamInfo.expires') }} <strong>{{ newAPIExpiry(data.key.expires_at, t('upstreamInfo.noExpiry')) }}</strong></span>
      </template>
    </div>
    <div v-else-if="!isNewAPI && (data?.usage || data?.billing)" class="upstream-metrics">
      <span>{{ t(`upstreamInfo.${infoScope(data?.usage)}`) }} <strong :class="{ exhausted: remaining != null && !infoUnlimited(data?.usage) && remaining <= 0 }">{{ amount }}</strong></span>
      <span>{{ t('upstreamInfo.todayActual') }} <strong>{{ infoAmount(data?.usage?.usage?.today?.actual_cost, 'USD') }}</strong></span>
      <span>{{ t('upstreamInfo.effectiveRate') }} <strong>{{ infoRate(data?.billing?.effective_rate_multiplier) }}</strong></span>
    </div>
    <p class="upstream-caption" aria-live="polite">
      <span v-if="busy && !data">{{ t('upstreamInfo.loading') }}</span>
      <span v-else-if="failed">{{ t('upstreamInfo.fetchFailed') }}</span>
      <span v-else-if="data?.accountState && !newAPIAccountReady(data)">{{ t('upstreamInfo.accountFallback') }}</span>
      <span v-else-if="partial">{{ t(stale ? 'upstreamInfo.stale' : 'upstreamInfo.partial') }}</span>
      <span v-else-if="!data">{{ t('upstreamInfo.pending') }}</span>
      <span v-if="refreshedAt">{{ t('upstreamInfo.updated') }} {{ infoTime(refreshedAt) }}</span>
    </p>
    <NewApiInfoDetails v-if="isNewAPI" :open="open" :name="card.name" :data="data" :busy="busy" :failed="failed" @close="open = false" @refresh="refresh(true)" />
    <ProviderInfoDetails v-else :open="open" :name="card.name" :data="data" :busy="busy" :failed="failed" :theme="theme" @close="open = false" @refresh="refresh(true)" />
  </div>
</template>
<style scoped>
.upstream-panel { margin-top: 10px; padding: 10px 12px; border: 1px solid var(--mac-border); border-radius: 10px; background: var(--mac-surface-strong); color: var(--mac-text); }
.upstream-head, .upstream-metrics, .upstream-actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.upstream-head { justify-content: space-between; }.upstream-label { font-size: 12px; font-weight: 600; }.upstream-label small { color: var(--mac-text-secondary); font-weight: 400; margin-left: 4px; }
.upstream-metrics { margin-top: 8px; column-gap: 18px; font-size: 12px; color: var(--mac-text-secondary); }.upstream-metrics strong { font-variant-numeric: tabular-nums; margin-left: 4px; color: var(--mac-text); }.upstream-metrics .exhausted { color: #dc5a50; }
.upstream-caption { display: flex; flex-wrap: wrap; gap: 8px; color: var(--mac-text-secondary); font-size: 11px; margin: 7px 0 0; }
button { border: 0; background: transparent; color: var(--mac-accent, #0a84ff); padding: 2px; cursor: pointer; font-size: 12px; }button:disabled { opacity: .5; cursor: wait; }
</style>
