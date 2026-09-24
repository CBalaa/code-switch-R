<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import BaseModal from '../common/BaseModal.vue'
import { newAPIAccountReady, newAPIAccountAmount, newAPIAmount, newAPIExpiry, newAPIStates, infoNumber, infoTime, infoRate, type ProviderInfo } from '../../services/providerInfo'
const props = defineProps<{ open: boolean; name: string; data: ProviderInfo | null; busy: boolean; failed: boolean }>()
defineEmits<{ (e: 'close'): void; (e: 'refresh'): void }>()
const { t } = useI18n()
const key = computed(() => props.data?.key)
const search = ref(''), group = ref(''), page = ref(1)
const rows = computed(() => props.data?.pricing?.rows || [])
const groups = computed(() => [...new Set(rows.value.map(row => row.group).filter(Boolean))].sort())
const filtered = computed(() => rows.value.filter(row => (!group.value || row.group === group.value) && row.model.toLowerCase().includes(search.value.trim().toLowerCase())))
const pages = computed(() => Math.max(1, Math.ceil(filtered.value.length / 20)))
const visible = computed(() => filtered.value.slice((page.value - 1) * 20, page.value * 20))
const limits = computed(() => Object.entries(key.value?.model_limits || {}).filter(([, enabled]) => enabled).map(([name]) => name).sort())
watch([search, group], () => { page.value = 1 })
watch(rows, () => { if (group.value && !groups.value.includes(group.value)) group.value = ''; page.value = Math.min(page.value, pages.value) })
watch(() => props.open, open => { if (open) { search.value = ''; group.value = ''; page.value = 1 } })
// Keep tiny positive prices distinct from a genuinely free model.
const price = (value?: number) => value == null ? '—' : value === 0 ? t('upstreamInfo.free') : `$${value.toLocaleString(undefined, { maximumSignificantDigits: 8 })}`
</script>
<template>
  <BaseModal :open="open" :title="`${name} · New API`" @close="$emit('close')">
    <div class="newapi-detail">
      <div class="toolbar"><p class="hint">{{ t('upstreamInfo.newapiScope') }}</p><button type="button" :disabled="busy" @click="$emit('refresh')">{{ t(busy ? 'upstreamInfo.loading' : 'upstreamInfo.refresh') }}</button></div>
      <p v-if="failed" role="status">{{ t('upstreamInfo.fetchFailed') }}</p>
      <div v-if="data" class="section-states" aria-live="polite">
        <p v-for="part in newAPIStates(data)" :key="part.label"><strong>{{ t(`upstreamInfo.${part.label}`) }}</strong> · {{ t(`upstreamInfo.status.${part.state.status}`) }}<span v-if="part.state.stale"> · {{ t('upstreamInfo.stale') }}</span><span v-if="part.state.updatedAt"> · {{ infoTime(part.state.updatedAt) }}</span><span v-if="part.state.retryAt"> · {{ t('upstreamInfo.retryAt') }} {{ infoTime(part.state.retryAt) }}</span></p>
      </div>
      <section v-if="newAPIAccountReady(data)" class="quota account-quota">
        <span>{{ t('upstreamInfo.wallet') }}</span>
        <strong class="balance">{{ newAPIAccountAmount(data, t('upstreamInfo.rawUnit')) }}</strong>
        <small>{{ t('upstreamInfo.rawRemaining') }}: {{ infoNumber(data?.account?.quota) }}</small>
        <p class="hint">{{ t('upstreamInfo.accountScope') }}</p>
      </section>
      <p v-else-if="data?.accountState" class="hint">{{ t('upstreamInfo.accountFallback') }}</p>
      <section v-if="key" class="quota">
        <span>{{ t('upstreamInfo.keyQuota') }}</span>
        <strong class="balance">{{ key.unlimited_quota ? t('upstreamInfo.unlimited') : newAPIAmount(data, 'remaining', t('upstreamInfo.rawUnit')) }}</strong>
        <dl>
          <dt>{{ t('upstreamInfo.keyName') }}</dt><dd>{{ key.name || '—' }}</dd>
          <dt>{{ t('upstreamInfo.used') }}</dt><dd>{{ newAPIAmount(data, 'used', t('upstreamInfo.rawUnit')) }}</dd>
          <template v-if="!key.unlimited_quota"><dt>{{ t('upstreamInfo.quotaTotal') }}</dt><dd>{{ newAPIAmount(data, 'total', t('upstreamInfo.rawUnit')) }}</dd></template>
          <dt>{{ t('upstreamInfo.expires') }}</dt><dd>{{ newAPIExpiry(key.expires_at, t('upstreamInfo.noExpiry')) }}</dd>
        </dl>
        <progress v-if="!key.unlimited_quota && key.total_granted != null && key.total_granted > 0 && key.total_used != null" :max="key.total_granted" :value="Math.max(0, Math.min(key.total_granted, key.total_used))" :aria-label="t('upstreamInfo.used')" />
        <p v-if="key.expires_at != null && key.expires_at > 0 && key.expires_at * 1000 <= Date.now()" class="hint">{{ t('upstreamInfo.keyState.expired') }}</p>
        <p class="hint">{{ t('upstreamInfo.modelLimits') }}: {{ key.model_limits_enabled == null ? '—' : key.model_limits_enabled ? (limits.join(', ') || t('upstreamInfo.noData')) : t('upstreamInfo.noModelLimits') }}</p>
      </section>
      <section>
        <h3>{{ t('upstreamInfo.site') }}</h3>
        <p class="hint">{{ t('upstreamInfo.conversionHint') }}</p>
        <p v-if="data?.site">1 USD = {{ infoNumber(data.site.quota_per_unit) }} {{ t('upstreamInfo.rawUnit') }}<span v-if="data.siteState?.stale"> · {{ t('upstreamInfo.stale') }}</span></p>
        <p v-else class="hint">{{ t('upstreamInfo.rawFallback') }}</p>
        <dl v-if="key"><dt>{{ t('upstreamInfo.rawRemaining') }}</dt><dd>{{ infoNumber(key.total_available) }}</dd><dt>{{ t('upstreamInfo.rawUsed') }}</dt><dd>{{ infoNumber(key.total_used) }}</dd><dt>{{ t('upstreamInfo.rawTotal') }}</dt><dd>{{ infoNumber(key.total_granted) }}</dd></dl>
      </section>
      <section>
        <h3>{{ t('upstreamInfo.pricing') }}</h3>
        <p class="hint">{{ t('upstreamInfo.publicPriceHint') }}</p>
        <template v-if="data?.pricing">
          <div class="filters">
            <input v-model="search" type="search" :aria-label="t('upstreamInfo.searchModel')" :placeholder="t('upstreamInfo.searchModel')" />
            <select v-model="group" :aria-label="t('upstreamInfo.group')"><option value="">{{ t('upstreamInfo.allGroups') }}</option><option v-for="g in groups" :key="g" :value="g">{{ g }}</option></select>
          </div>
          <p class="hint">{{ t('upstreamInfo.priceUnits') }}</p>
          <div v-if="visible.length" class="table-scroll"><table>
            <thead><tr><th>{{ t('upstreamInfo.model') }}</th><th>{{ t('upstreamInfo.group') }}</th><th>{{ t('upstreamInfo.groupRate') }}</th><th>{{ t('upstreamInfo.priceMode') }}</th><th>{{ t('upstreamInfo.input') }}</th><th>{{ t('upstreamInfo.output') }}</th><th>{{ t('upstreamInfo.cacheRead') }}</th><th>{{ t('upstreamInfo.cacheWrite') }}</th><th>{{ t('upstreamInfo.perRequest') }}</th></tr></thead>
            <tbody><tr v-for="(row, index) in visible" :key="`${row.model}:${row.group}:${index}`"><td>{{ row.model }}</td><td>{{ row.group || '—' }}</td><td>{{ infoRate(row.groupRatio) }}</td><td>{{ t(`upstreamInfo.priceModes.${row.mode}`) }}</td><td>{{ price(row.input) }}</td><td>{{ price(row.output) }}</td><td>{{ price(row.cacheRead) }}</td><td>{{ price(row.cacheWrite) }}</td><td>{{ price(row.request) }}</td></tr></tbody>
          </table></div>
          <p v-else class="hint">{{ t('upstreamInfo.noPrices') }}</p>
          <div class="pagination"><button type="button" :disabled="page <= 1" @click="page--">{{ t('upstreamInfo.previous') }}</button><span aria-live="polite">{{ page }} / {{ pages }} · {{ filtered.length }} {{ t('upstreamInfo.priceRows') }}</span><button type="button" :disabled="page >= pages" @click="page++">{{ t('upstreamInfo.next') }}</button></div>
        </template>
        <p v-else class="hint">{{ t('upstreamInfo.priceUnavailable') }}</p>
      </section>
    </div>
  </BaseModal>
</template>
<style scoped>
.newapi-detail { display: grid; gap: 20px; min-width: 0; color: var(--mac-text); font-size: 13px; }
.newapi-detail > * { min-width: 0; }p, dd { overflow-wrap: anywhere; }
.toolbar, .filters, .pagination { display: flex; align-items: center; gap: 12px; justify-content: space-between; }.filters, .pagination { flex-wrap: wrap; }
.hint { color: var(--mac-text-secondary); font-size: 12px; line-height: 1.6; }.toolbar p { margin: 0; }
button, input, select { border: 1px solid var(--mac-border); background: var(--mac-surface-strong); color: var(--mac-text); padding: 8px 12px; border-radius: 8px; min-width: 0; }button { cursor: pointer; white-space: nowrap; }button:disabled { opacity: .5; cursor: default; }.filters input { flex: 1 1 180px; }.filters select { max-width: 100%; }
.section-states { background: var(--mac-surface-strong); padding: 10px 12px; border-radius: 10px; font-size: 11px; }.section-states p { margin: 4px 0; }
.quota { display: grid; gap: 10px; padding: 18px; background: var(--mac-surface-strong); border: 1px solid var(--mac-border); border-radius: 12px; }.balance { font-size: 30px; overflow-wrap: anywhere; }
dl { display: grid; grid-template-columns: minmax(0, 1fr) minmax(0, 1fr); gap: 10px; margin: 10px 0; }dt { color: var(--mac-text-secondary); }dd { margin: 0; text-align: right; }progress { width: 100%; accent-color: #0a84ff; }
h3 { font-size: 14px; margin: 0 0 10px; }.table-scroll { overflow: auto; max-height: 400px; }table { border-collapse: collapse; width: 100%; font-size: 12px; }th, td { padding: 9px 10px; white-space: nowrap; text-align: right; border-bottom: 1px solid var(--mac-border); }th:first-child, td:first-child { text-align: left; }th { background: var(--mac-surface-strong); }.pagination { margin-top: 12px; font-size: 12px; }
@media (max-width: 480px) { .toolbar { align-items: start; }.quota { padding: 12px; } }
</style>

