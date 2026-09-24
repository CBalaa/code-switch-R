<script setup lang="ts">
import { computed, ref, watch, onUnmounted, nextTick } from 'vue'
import { useI18n } from 'vue-i18n'
import { Chart, CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend } from 'chart.js'
import BaseModal from '../common/BaseModal.vue'
import { infoAmount, infoUnlimited, infoNumber, infoRemaining, infoScope, infoRate, infoTime, type ProviderInfo, type Quota, type UsageStats } from '../../services/providerInfo'
Chart.register(CategoryScale, LinearScale, PointElement, LineElement, Tooltip, Legend)
const props = defineProps<{ open: boolean; name: string; data: ProviderInfo | null; busy: boolean; failed: boolean; theme: string }>()
defineEmits<{ (e: 'close'): void; (e: 'refresh'): void }>()
const { t, locale } = useI18n()
const usage = computed(() => props.data?.usage)
const billing = computed(() => props.data?.billing)
const remaining = computed(() => infoRemaining(usage.value))
const quotas = computed(() => {
  const items: Array<Quota & { label: string }> = []
  if (usage.value?.quota) items.push({ ...usage.value.quota, label: t('upstreamInfo.keyQuota') })
  for (const q of usage.value?.rate_limits || []) items.push({ ...q, unit: q.unit || usage.value?.unit || 'USD', label: `${t('upstreamInfo.window')} ${q.window}` })
  const sub = usage.value?.subscription
  if (sub) {
    for (const period of ['daily', 'weekly', 'monthly'] as const) {
      const limit = sub[`${period}_limit_usd`], used = sub[`${period}_usage_usd`]
      if (limit != null || used != null) items.push({ label: t(`upstreamInfo.${period}`), unit: 'USD', limit, used, remaining: limit != null && limit > 0 && used != null ? Math.max(0, limit - used) : undefined })
    }
  }
  return items
})
const models = computed(() => [...(usage.value?.model_stats || [])].sort((a, b) => (b.actual_cost ?? -1) - (a.actual_cost ?? -1)))
const days = computed(() => [...(usage.value?.daily_usage || [])].sort((a, b) => (a.date || '').localeCompare(b.date || '')))
const summary = computed(() => [ { label: t('upstreamInfo.today'), stats: usage.value?.usage?.today }, { label: t('upstreamInfo.total'), stats: usage.value?.usage?.total } ])
const metrics: Array<{ label: string; field: keyof UsageStats; money?: boolean }> = [
  { label: 'requests', field: 'requests' }, { label: 'input', field: 'input_tokens' }, { label: 'output', field: 'output_tokens' },
  { label: 'cacheRead', field: 'cache_read_tokens' }, { label: 'cacheWrite', field: 'cache_creation_tokens' }, { label: 'tokens', field: 'total_tokens' },
  { label: 'originalCost', field: 'cost', money: true }, { label: 'actualCost', field: 'actual_cost', money: true },
]
function metricValue(stats: UsageStats | undefined, field: keyof UsageStats, money = false) {
  const value = field === 'cache_creation_tokens' ? (stats?.cache_creation_tokens ?? stats?.cache_write_tokens) : stats?.[field]
  return money ? infoAmount(typeof value === 'number' ? value : undefined, 'USD') : infoNumber(typeof value === 'number' ? value : undefined)
}
const canvas = ref<HTMLCanvasElement | null>(null)
let chart: Chart<'line'> | undefined
let chartGeneration = 0
watch([canvas, days, () => props.open, () => props.theme, locale], async () => {
  const generation = ++chartGeneration
  chart?.destroy(); chart = undefined
  await nextTick()
  if (generation !== chartGeneration || !props.open || !canvas.value || !days.value.length) return
  const color = props.theme === 'dark' ? '#b7bac7' : '#6e6e73'
  chart = new Chart(canvas.value, {
    type: 'line',
    data: { labels: days.value.map(d => d.date || ''), datasets: [{ label: `${t('upstreamInfo.actualCost')} (USD)`, data: days.value.map(d => d.actual_cost ?? null), borderColor: '#0a84ff', backgroundColor: '#0a84ff', tension: .2, pointRadius: 2, spanGaps: false }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { labels: { color } } }, scales: { x: { ticks: { color, maxTicksLimit: 6 }, grid: { display: false } }, y: { beginAtZero: true, ticks: { color }, grid: { color: props.theme === 'dark' ? '#ffffff12' : '#00000012' } } } },
  })
}, { flush: 'post' })
onUnmounted(() => { chartGeneration++; chart?.destroy() })
</script>
<template>
  <BaseModal :open="open" :title="`${name} · ${t('upstreamInfo.title')}`" @close="$emit('close')">
    <div class="info-detail">
      <div class="detail-toolbar"><p>{{ t('upstreamInfo.scopeHint') }}</p><button :disabled="busy" type="button" @click="$emit('refresh')">{{ t(busy ? 'upstreamInfo.loading' : 'upstreamInfo.refresh') }}</button></div>
      <p v-if="failed" role="status">{{ t('upstreamInfo.fetchFailed') }}</p>
      <div v-if="data" class="section-states" aria-live="polite">
        <p v-for="part in (['usage', 'billing'] as const)" :key="part">
          <strong>{{ t(`upstreamInfo.${part}`) }}</strong> · {{ t(`upstreamInfo.status.${data[`${part}State`].status}`) }}
          <span v-if="data[`${part}State`].stale"> · {{ t('upstreamInfo.stale') }}</span>
          <span v-if="data[`${part}State`].updatedAt"> · {{ infoTime(data[`${part}State`].updatedAt) }}</span>
          <span v-if="data[`${part}State`].retryAt"> · {{ t('upstreamInfo.retryAt') }} {{ infoTime(data[`${part}State`].retryAt) }}</span>
        </p>
      </div>
      <template v-if="usage">
        <section class="balance-overview">
          <span>{{ t(`upstreamInfo.${infoScope(usage)}`) }}</span>
          <strong>{{ infoUnlimited(usage) ? t('upstreamInfo.unlimited') : infoAmount(remaining, usage.unit || usage.quota?.unit) }}</strong>
          <small v-if="usage.planName">{{ usage.planName }}</small>
          <small v-if="usage.status || usage.isValid != null">{{ t('upstreamInfo.keyStatus') }}: {{ usage.status ? (['active', 'expired', 'quota_exhausted', 'disabled'].includes(usage.status) ? t(`upstreamInfo.keyState.${usage.status}`) : usage.status) : t(usage.isValid ? 'upstreamInfo.recognized' : 'upstreamInfo.invalidKey') }}</small>
          <small v-if="usage.expires_at || usage.subscription?.expires_at">{{ t('upstreamInfo.expires') }} {{ infoTime(usage.expires_at || usage.subscription?.expires_at) }}</small>
        </section>
        <section v-if="quotas.length">
          <h3>{{ t('upstreamInfo.quotas') }}</h3>
          <div v-for="q in quotas" :key="q.label" class="quota-row">
            <div><strong>{{ q.label }}</strong><span>{{ t('upstreamInfo.used') }} {{ infoAmount(q.used, q.unit) }} / {{ q.limit === 0 || q.limit === -1 ? t('upstreamInfo.unlimited') : infoAmount(q.limit, q.unit) }}</span></div>
            <progress v-if="q.limit != null && q.limit > 0 && q.used != null" :max="q.limit" :value="Math.max(0, Math.min(q.limit, q.used))" :aria-label="q.label" />
            <small v-if="q.remaining != null">{{ t('upstreamInfo.remaining') }} {{ q.remaining === -1 ? t('upstreamInfo.unlimited') : infoAmount(q.remaining, q.unit) }}</small>
            <small v-if="q.reset_at">{{ t('upstreamInfo.resets') }} {{ infoTime(q.reset_at) }}</small>
          </div>
        </section>
        <section>
          <h3>{{ t('upstreamInfo.keyUsage') }}</h3><p class="hint">{{ t('upstreamInfo.todayHint') }}</p>
          <div class="table-scroll"><table><thead><tr><th>{{ t('upstreamInfo.metric') }}</th><th v-for="s in summary" :key="s.label">{{ s.label }}</th></tr></thead><tbody><tr v-for="metric in metrics" :key="metric.field"><td>{{ t(`upstreamInfo.${metric.label}`) }}</td><td v-for="s in summary" :key="s.label">{{ metricValue(s.stats, metric.field, metric.money) }}</td></tr></tbody></table></div>
          <dl v-if="usage.usage" class="billing-grid throughput">
            <template v-if="usage.usage.rpm != null"><dt>RPM</dt><dd>{{ infoNumber(usage.usage.rpm) }}</dd></template>
            <template v-if="usage.usage.tpm != null"><dt>TPM</dt><dd>{{ infoNumber(usage.usage.tpm) }}</dd></template>
            <template v-if="usage.usage.average_duration_ms != null"><dt>{{ t('upstreamInfo.averageDuration') }}</dt><dd>{{ infoNumber(usage.usage.average_duration_ms) }} ms</dd></template>
          </dl>
          <p class="hint">{{ t('upstreamInfo.costHint') }}</p>
        </section>
        <section>
          <h3>{{ t('upstreamInfo.trend') }}</h3><p class="hint">{{ t('upstreamInfo.dailyTimezone') }} {{ data?.dailyTimezone }}</p>
          <div v-if="days.some(d => d.actual_cost != null)" class="chart-wrap"><canvas ref="canvas" role="img" :aria-label="t('upstreamInfo.trend')" /></div>
          <p v-else class="hint">{{ t('upstreamInfo.noData') }}</p>
          <details v-if="days.length"><summary>{{ t('upstreamInfo.dailyDetails') }}</summary><div class="table-scroll"><table><thead><tr><th>{{ t('upstreamInfo.date') }}</th><th>{{ t('upstreamInfo.requests') }}</th><th>{{ t('upstreamInfo.tokens') }}</th><th>{{ t('upstreamInfo.actualCost') }}</th></tr></thead><tbody><tr v-for="day in days" :key="day.date"><td>{{ day.date }}</td><td>{{ infoNumber(day.requests) }}</td><td>{{ infoNumber(day.total_tokens) }}</td><td>{{ infoAmount(day.actual_cost, 'USD') }}</td></tr></tbody></table></div></details>
        </section>
        <section>
          <h3>{{ t('upstreamInfo.models') }}</h3><p class="hint">{{ t('upstreamInfo.modelPeriod') }}</p>
          <div v-if="models.length" class="table-scroll"><table><thead><tr><th>{{ t('upstreamInfo.model') }}</th><th v-for="metric in metrics" :key="metric.field">{{ t(`upstreamInfo.${metric.label}`) }}</th></tr></thead><tbody><tr v-for="model in models" :key="model.model"><td>{{ model.model }}</td><td v-for="metric in metrics" :key="metric.field">{{ metricValue(model, metric.field, metric.money) }}</td></tr></tbody></table></div>
          <p v-else class="hint">{{ t('upstreamInfo.noData') }}</p>
        </section>
      </template>
      <section>
        <h3>{{ t('upstreamInfo.billing') }}</h3>
        <dl v-if="billing" class="billing-grid">
          <dt>{{ t('upstreamInfo.groupRate') }}</dt><dd>{{ infoRate(billing.group_rate_multiplier) }}</dd>
          <template v-if="billing.user_rate_multiplier != null"><dt>{{ t('upstreamInfo.userRate') }}</dt><dd>{{ infoRate(billing.user_rate_multiplier) }}</dd></template>
          <dt>{{ t('upstreamInfo.resolvedRate') }}</dt><dd>{{ infoRate(billing.resolved_rate_multiplier) }}</dd>
          <dt>{{ t('upstreamInfo.effectiveRate') }}</dt><dd>{{ infoRate(billing.effective_rate_multiplier) }}</dd>
          <template v-if="billing.peak_rate_enabled"><dt>{{ t('upstreamInfo.peak') }}</dt><dd>{{ billing.peak_start }}–{{ billing.peak_end }} {{ billing.timezone }}</dd><dt>{{ t('upstreamInfo.peakRate') }}</dt><dd>{{ infoRate(billing.peak_rate_multiplier) }}</dd><dt>{{ t('upstreamInfo.appliedPeak') }}</dt><dd>{{ infoRate(billing.applied_peak_multiplier) }}</dd></template>
          <dt>{{ t('upstreamInfo.observed') }}</dt><dd>{{ infoTime(billing.observed_at) }}</dd>
        </dl>
        <p class="hint">{{ t('upstreamInfo.pricingHint') }}</p>
      </section>
    </div>
  </BaseModal>
</template>
<style scoped>
.info-detail { color: var(--mac-text); display: grid; gap: 20px; min-width: 0; font-size: 13px; }
.info-detail > * { min-width: 0; }
.section-states p { overflow-wrap: anywhere; }
.detail-toolbar { display: flex; align-items: center; justify-content: space-between; gap: 12px; }.detail-toolbar p { margin: 0; color: var(--mac-text-secondary); font-size: 12px; }
button { border: 1px solid var(--mac-border); background: var(--mac-surface-strong); color: var(--mac-text); padding: 7px 12px; border-radius: 8px; white-space: nowrap; cursor: pointer; }button:disabled { opacity: .5; }
.section-states { padding: 10px 12px; border-radius: 10px; background: var(--mac-surface-strong); font-size: 11px; }.section-states p { margin: 4px 0; }
.balance-overview { display: flex; flex-direction: column; gap: 6px; padding: 20px; background: var(--mac-surface-strong); border: 1px solid var(--mac-border); border-radius: 12px; }.balance-overview > strong { font-size: 30px; font-variant-numeric: tabular-nums; }.balance-overview small { color: var(--mac-text-secondary); }
h3 { font-size: 14px; margin: 0 0 10px; }.hint { color: var(--mac-text-secondary); font-size: 12px; line-height: 1.6; }
.quota-row { display: grid; gap: 6px; margin: 12px 0; }.quota-row > div { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 8px; }.quota-row small { color: var(--mac-text-secondary); }progress { width: 100%; height: 7px; accent-color: #0a84ff; }
.table-scroll { overflow: auto; max-height: 330px; }table { border-collapse: collapse; width: 100%; font-size: 12px; font-variant-numeric: tabular-nums; }th, td { padding: 9px 10px; text-align: right; white-space: nowrap; border-bottom: 1px solid var(--mac-border); }th:first-child, td:first-child { text-align: left; }th { background: var(--mac-surface-strong); font-weight: 500; }
.throughput { margin-top: 14px; }
.chart-wrap { height: 210px; position: relative; }details { margin-top: 12px; }summary { cursor: pointer; color: var(--mac-text-secondary); }
.billing-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 0; }dt { color: var(--mac-text-secondary); }dd { margin: 0; text-align: right; overflow-wrap: anywhere; }
@media (max-width: 480px) { .balance-overview { padding: 14px; }.detail-toolbar { align-items: start; } }
</style>

