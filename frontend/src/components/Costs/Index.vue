<template>
  <div class="costs-page">
    <div class="costs-header">
      <div>
        <p class="costs-eyebrow">{{ t('components.costs.eyebrow') }}</p>
        <h1>{{ t('components.costs.title') }}</h1>
        <p class="costs-description">{{ t('components.costs.description') }}</p>
      </div>
      <div class="costs-actions">
        <BaseButton type="button" @click="openPriceEditor">
          {{ t('components.costs.settings.editModels') }}
        </BaseButton>
        <BaseButton variant="outline" type="button" @click="backToHome">
          {{ t('components.logs.back') }}
        </BaseButton>
      </div>
    </div>

    <form class="costs-filter-row" @submit.prevent="applyFilters">
      <div class="filter-field">
        <label for="costs-platform-filter">{{ t('components.costs.filters.platform') }}</label>
        <select id="costs-platform-filter" v-model="filters.platform" class="mac-select" data-testid="costs-platform-filter">
          <option value="">{{ t('components.costs.filters.allPlatforms') }}</option>
          <option value="claude">Claude</option>
          <option value="openai-responses">OpenAI Responses</option>
          <option value="openai-chat">OpenAI Chat</option>
        </select>
      </div>
      <div class="filter-field">
        <label for="costs-provider-filter">{{ t('components.costs.filters.provider') }}</label>
        <select id="costs-provider-filter" v-model="filters.provider" class="mac-select" data-testid="costs-provider-filter">
          <option value="">{{ t('components.costs.filters.allProviders') }}</option>
          <option v-for="provider in availableProviderOptions" :key="provider" :value="provider">
            {{ provider }}
          </option>
        </select>
      </div>
      <BaseButton type="submit" :disabled="loading" data-testid="costs-query">
        {{ t('components.costs.query') }}
      </BaseButton>
    </form>

    <section v-if="hasQueried" class="costs-summary-grid">
      <article class="cost-summary-card highlight">
        <span>{{ t('components.costs.summary.totalCost') }}</span>
        <strong>{{ formatTotalCost(summary.totalCost) }}</strong>
        <small>{{ t('components.costs.summary.todayOnly') }}</small>
      </article>
      <article class="cost-summary-card">
        <span>{{ t('components.costs.summary.billableTokens') }}</span>
        <strong>{{ formatInteger(summary.billableTokens) }}</strong>
        <small>{{ t('components.costs.summary.billableHint') }}</small>
      </article>
      <article class="cost-summary-card">
        <span>{{ t('components.costs.summary.unpricedModels') }}</span>
        <strong>{{ summary.unpricedModels }}</strong>
        <small>{{ t('components.costs.summary.unpricedHint') }}</small>
      </article>
      <article class="cost-summary-card">
        <span>{{ t('components.costs.summary.requests') }}</span>
        <strong>{{ formatInteger(summary.requests) }}</strong>
        <small>{{ t('components.costs.summary.successOnly') }}</small>
      </article>
    </section>

    <section class="costs-panel">
      <div class="panel-header">
        <div>
          <h2>{{ t('components.costs.details.title') }}</h2>
          <p>{{ detailHint }}</p>
        </div>
      </div>

      <div v-if="loading" class="empty-state">{{ t('components.logs.loading') }}</div>
      <div v-else-if="!hasQueried" class="empty-state">{{ t('components.costs.queryPrompt') }}</div>
      <div v-else-if="!groups.length" class="empty-state">{{ t('components.costs.empty') }}</div>
      <div v-else class="cost-detail-groups">
        <article v-for="group in groups" :key="group.key" class="provider-group">
          <h3 v-if="showProviderGroups" class="provider-group-title">
            <span class="provider-group-platform">{{ group.platform || '—' }}</span>
            <span>{{ group.provider || t('components.costs.unknownProvider') }}</span>
          </h3>
          <div class="model-table-wrapper">
            <table class="model-cost-table">
              <thead>
                <tr>
                  <th scope="col">{{ t('components.costs.table.model') }}</th>
                  <th scope="col">{{ t('components.costs.table.requests') }}</th>
                  <th scope="col">{{ t('components.costs.table.tokens') }}</th>
                  <th scope="col">{{ t('components.costs.table.prices') }}</th>
                  <th scope="col">{{ t('components.costs.table.multiplier') }}</th>
                  <th scope="col">{{ t('components.costs.table.subtotal') }}</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in group.rows" :key="row.key" :class="{ 'is-unpriced': !row.price }">
                  <td class="model-name-cell">
                    <strong>{{ row.model || '—' }}</strong>
                    <span v-if="!row.price" class="missing-pill">{{ t('components.costs.missingPrice') }}</span>
                    <span v-else-if="row.priceSource === 'override'" class="override-pill">{{ t('components.costs.overridePrice') }}</span>
                    <span v-else class="source-pill">{{ row.defaultPrice?.source }}</span>
                  </td>
                  <td>{{ formatInteger(row.totalRequests) }}</td>
                  <td class="tokens-cell">
                    <span>{{ t('components.costs.tokenLabels.input') }}: {{ formatInteger(row.inputTokens) }}</span>
                    <span>{{ t('components.costs.tokenLabels.output') }}: {{ formatInteger(row.outputTokens) }}</span>
                    <span>{{ t('components.costs.tokenLabels.cacheRead') }}: {{ formatInteger(row.cacheReadTokens) }}</span>
                    <span class="not-billed">{{ t('components.costs.tokenLabels.cacheCreate') }}: {{ formatInteger(row.cacheCreateTokens) }}</span>
                    <span class="not-billed">{{ t('components.costs.tokenLabels.reasoning') }}: {{ formatInteger(row.reasoningTokens) }}</span>
                  </td>
                  <td class="prices-cell">
                    <span>{{ t('components.costs.price.input') }}: {{ formatPrice(row.price?.input) }}</span>
                    <span>{{ t('components.costs.price.output') }}: {{ formatPrice(row.price?.output) }}</span>
                    <span>{{ t('components.costs.price.cacheRead') }}: {{ formatPrice(row.price?.cache_read) }}</span>
                  </td>
                  <td>{{ formatMultiplier(row.multiplier) }}</td>
                  <td class="subtotal-cell">
                    <strong v-if="row.price">{{ formatSubtotal(row.subtotal) }}</strong>
                    <span v-else>{{ t('components.costs.notCounted') }}</span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </article>
      </div>
    </section>

    <BaseModal
      :open="priceEditorOpen"
      :title="t('components.costs.settings.editModels')"
      size="wide"
      @close="closePriceEditor"
    >
      <section class="price-editor-modal">
        <p class="price-editor-unit">{{ t('components.costs.settings.unit') }}</p>
        <div class="price-editor-table-wrapper">
          <table class="price-editor-table">
            <thead>
              <tr>
                <th scope="col">{{ t('components.costs.table.model') }}</th>
                <th scope="col">{{ t('components.costs.price.input') }}</th>
                <th scope="col">{{ t('components.costs.price.output') }}</th>
                <th scope="col">{{ t('components.costs.price.cacheRead') }}</th>
                <th scope="col"><span class="sr-only">{{ t('components.costs.settings.removeModel') }}</span></th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in modelPriceDrafts" :key="row.id" :data-row-id="row.id">
                <td><BaseInput v-model="row.model" :aria-label="t('components.costs.settings.modelName')" :placeholder="t('components.costs.settings.modelName')" data-testid="price-model" /></td>
                <td><BaseInput v-model="row.input" type="number" min="0" step="0.000001" :aria-label="t('components.costs.price.input')" data-testid="price-input" /></td>
                <td><BaseInput v-model="row.output" type="number" min="0" step="0.000001" :aria-label="t('components.costs.price.output')" data-testid="price-output" /></td>
                <td><BaseInput v-model="row.cache_read" type="number" min="0" step="0.000001" :aria-label="t('components.costs.price.cacheRead')" data-testid="price-cache-read" /></td>
                <td class="price-editor-remove-cell">
                  <BaseButton variant="outline" type="button" :disabled="saving" :data-row-id="row.id" data-testid="price-remove" @click="removeModelPrice(row.id)">
                    {{ t('components.costs.settings.removeModel') }}
                  </BaseButton>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <BaseButton variant="outline" type="button" :disabled="saving" data-testid="price-add-model" @click="addModelPrice">
          {{ t('components.costs.settings.addModel') }}
        </BaseButton>
      </section>
      <footer class="form-actions price-editor-actions">
        <BaseButton variant="outline" type="button" :disabled="saving" data-testid="price-cancel" @click="closePriceEditor">
          {{ t('components.main.form.actions.cancel') }}
        </BaseButton>
        <BaseButton type="button" :disabled="saving" data-testid="price-save" @click="savePriceEditor">
          {{ t('components.costs.settings.save') }}
        </BaseButton>
      </footer>
    </BaseModal>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import BaseButton from '../common/BaseButton.vue'
import BaseInput from '../common/BaseInput.vue'
import BaseModal from '../common/BaseModal.vue'
import { LoadProviders } from '../../../bindings/codeswitch/services/providerservice'
import { type LogPlatform } from '../../services/logs'
import {
  costModelKey,
  costProviderKey,
  defaultCostSettings,
  fetchCostSettings,
  fetchTodayCostUsage,
  findDefaultPrice,
  normalizeCostModelName,
  saveCostSettings,
  type CostPrice,
  type CostSettings,
  type CostUsageItem,
  type DefaultModelPrice,
} from '../../services/costs'
import { showToast } from '../../utils/toast'

const { t } = useI18n()
const router = useRouter()

const loading = ref(false)
const saving = ref(false)
const priceEditorOpen = ref(false)
const hasQueried = ref(false)
const usageItems = ref<CostUsageItem[]>([])
const settings = ref<CostSettings>(defaultCostSettings())
const providerOptions = ref<string[]>([])
const COST_PROVIDER_PLATFORMS: LogPlatform[] = ['claude', 'openai-responses', 'openai-chat']
type ModelPriceDraft = { id: string; model: string; input: string; output: string; cache_read: string }
const modelPriceDrafts = ref<ModelPriceDraft[]>([])
const filters = reactive<{ platform: LogPlatform | ''; provider: string }>({ platform: '', provider: '' })
let isUnmounted = false
let providerLoadVersion = 0
let settingsLoadVersion = 0
let costQueryPromise: Promise<void> | null = null

const showProviderGroups = computed(() => filters.provider === '')
const availableProviderOptions = computed(() => {
  const options = new Set<string>()
  for (const provider of providerOptions.value) {
    if (provider.trim()) {
      options.add(provider)
    }
  }
  for (const item of usageItems.value) {
    if ((!filters.platform || item.platform === filters.platform) && item.provider.trim()) {
      options.add(item.provider)
    }
  }
  return Array.from(options).sort((a, b) => a.localeCompare(b))
})

const backToHome = () => router.push('/')

const multiplier = (platform: string, provider: string) => {
  const value = settings.value.provider_multipliers[costProviderKey(platform, provider)]
  return value && value > 0 ? value : 1
}

const overridePriceFor = (platform: string, provider: string, model: string): CostPrice | null => {
  return settings.value.model_price_overrides[costModelKey(platform, provider, model)] ?? null
}

const effectivePriceFor = (item: CostUsageItem): { price: CostPrice | null; source: 'override' | 'default' | 'missing'; defaultPrice: DefaultModelPrice | null } => {
  const globalPrice = settings.value.model_prices[normalizeCostModelName(item.model)]
  const override = overridePriceFor(item.platform, item.provider, item.model)
  const defaultPrice = findDefaultPrice(item.platform, item.model)
  if (globalPrice) return { price: globalPrice, source: 'override', defaultPrice }
  if (override) return { price: override, source: 'override', defaultPrice }
  if (defaultPrice) return { price: defaultPrice, source: 'default', defaultPrice }
  return { price: null, source: 'missing', defaultPrice: null }
}

const billableInputTokens = (item: CostUsageItem) => Math.max(item.input_tokens - item.cache_read_tokens, 0)
const billableTokenTotal = (item: CostUsageItem) => billableInputTokens(item) + item.output_tokens + item.cache_read_tokens

const rowViewModels = computed(() => usageItems.value.map((item) => {
  const priceInfo = effectivePriceFor(item)
  const rowMultiplier = multiplier(item.platform, item.provider)
  const chargedInputTokens = billableInputTokens(item)
  const subtotal = priceInfo.price
    ? ((chargedInputTokens * priceInfo.price.input)
      + (item.output_tokens * priceInfo.price.output)
      + (item.cache_read_tokens * priceInfo.price.cache_read)) / 1_000_000 * rowMultiplier
    : 0
  return {
    key: `${item.platform}::${item.provider}::${item.model}`,
    platform: item.platform,
    provider: item.provider,
    model: item.model,
    modelKey: normalizeCostModelName(item.model),
    totalRequests: item.total_requests,
    inputTokens: item.input_tokens,
    outputTokens: item.output_tokens,
    cacheCreateTokens: item.cache_create_tokens,
    cacheReadTokens: item.cache_read_tokens,
    reasoningTokens: item.reasoning_tokens,
    billableTokens: billableTokenTotal(item),
    multiplier: rowMultiplier,
    subtotal,
    price: priceInfo.price,
    priceSource: priceInfo.source,
    defaultPrice: priceInfo.defaultPrice,
  }
}))

const groups = computed(() => {
  const map = new Map<string, { key: string; platform: string; provider: string; rows: typeof rowViewModels.value }>()
  for (const row of rowViewModels.value) {
    const key = showProviderGroups.value ? `${row.platform}::${row.provider}` : 'selected'
    if (!map.has(key)) {
      map.set(key, { key, platform: row.platform, provider: row.provider, rows: [] })
    }
    map.get(key)?.rows.push(row)
  }
  return Array.from(map.values())
})

const summary = computed(() => {
  const priced = rowViewModels.value.filter((row) => row.price)
  const unpricedModelKeys = new Set(rowViewModels.value.filter((row) => !row.price).map((row) => row.key))
  return {
    totalCost: priced.reduce((sum, row) => sum + row.subtotal, 0),
    billableTokens: rowViewModels.value.reduce((sum, row) => sum + row.billableTokens, 0),
    unpricedModels: unpricedModelKeys.size,
    requests: rowViewModels.value.reduce((sum, row) => sum + row.totalRequests, 0),
  }
})

const detailHint = computed(() => showProviderGroups.value
  ? t('components.costs.details.groupedByProvider')
  : t('components.costs.details.groupedByModel'))

const formatInteger = (value?: number) => new Intl.NumberFormat().format(value ?? 0)
const formatTotalCost = (value: number) => `$${value < 0.01 ? value.toFixed(6) : value.toFixed(4)}`
const formatSubtotal = (value: number) => `$${value.toFixed(6)}`
const formatMultiplier = (value: number) => `${trimNumber(value)}x`
const formatPrice = (value?: number) => value == null ? '—' : `$${trimNumber(value)}`
const formatPricePlaceholder = (value?: number) => value == null ? '' : trimNumber(value)
const trimNumber = (value: number) => Number(value.toFixed(6)).toString()

const normalizeProviderOption = (value: string | undefined) => (value ?? '').trim()

const loadConfiguredProviderNames = async (platform: LogPlatform | '') => {
  const platforms = platform ? [platform] : COST_PROVIDER_PLATFORMS
  const results = await Promise.allSettled(platforms.map((kind) => LoadProviders(kind)))
  const names: string[] = []
  for (const result of results) {
    if (result.status !== 'fulfilled') {
      console.error('failed to load configured providers', result.reason)
      continue
    }
    for (const provider of result.value ?? []) {
      const name = normalizeProviderOption(provider.name)
      if (name) {
        names.push(name)
      }
    }
  }
  return names
}

const loadProviders = async () => {
  const requestedPlatform = filters.platform
  const requestVersion = ++providerLoadVersion
  const configuredProviders = await loadConfiguredProviderNames(requestedPlatform)
  if (
    isUnmounted
    || requestVersion !== providerLoadVersion
    || requestedPlatform !== filters.platform
  ) return

  const merged = new Set<string>()
  for (const provider of configuredProviders) {
    const name = normalizeProviderOption(provider)
    if (name) {
      merged.add(name)
    }
  }
  providerOptions.value = Array.from(merged).sort((a, b) => a.localeCompare(b))
  if (filters.provider && providerOptions.value.length > 0 && !providerOptions.value.includes(filters.provider)) {
    filters.provider = ''
  }
}

const loadSettings = async () => {
  const requestVersion = ++settingsLoadVersion
  try {
    const nextSettings = await fetchCostSettings()
    if (!isUnmounted && requestVersion === settingsLoadVersion) {
      settings.value = nextSettings
    }
  } catch (error: any) {
    if (!isUnmounted && requestVersion === settingsLoadVersion) {
      showToast(error?.message || t('components.costs.loadFailed'), 'error')
    }
  }
}

const clearUsageResults = () => {
  usageItems.value = []
  hasQueried.value = false
}

const runCostQuery = async () => {
  if (costQueryPromise) return costQueryPromise

  const requestedPlatform = filters.platform
  const requestedProvider = filters.provider
  loading.value = true
  costQueryPromise = (async () => {
    try {
      const nextUsage = await fetchTodayCostUsage(requestedPlatform, requestedProvider)
      if (
        isUnmounted
        || requestedPlatform !== filters.platform
        || requestedProvider !== filters.provider
      ) return

      usageItems.value = nextUsage
      hasQueried.value = true
    } catch (error: any) {
      if (
        !isUnmounted
        && requestedPlatform === filters.platform
        && requestedProvider === filters.provider
      ) {
        showToast(error?.message || t('components.costs.loadFailed'), 'error')
      }
    }
  })().finally(() => {
    costQueryPromise = null
    loading.value = false
  })
  return costQueryPromise
}

const openPriceEditor = () => {
  syncModelPriceDrafts()
  priceEditorOpen.value = true
}

const closePriceEditor = () => {
  priceEditorOpen.value = false
}

const applyFilters = () => {
  void runCostQuery()
}

const newModelPriceDraft = (): ModelPriceDraft => ({
  id: typeof crypto?.randomUUID === 'function' ? crypto.randomUUID() : `${Date.now()}-${Math.random()}`,
  model: '',
  input: '',
  output: '',
  cache_read: '',
})

const syncModelPriceDrafts = () => {
  const models = new Map<string, string>()
  for (const item of usageItems.value) {
    const model = item.model.trim()
    if (model) models.set(normalizeCostModelName(model), model)
  }
  for (const model of Object.keys(settings.value.model_prices)) {
    if (model) models.set(normalizeCostModelName(model), model)
  }
  modelPriceDrafts.value = Array.from(models.entries())
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, model]) => {
      const price = settings.value.model_prices[key]
      return {
        id: key,
        model,
        input: price ? String(price.input) : '',
        output: price ? String(price.output) : '',
        cache_read: price ? String(price.cache_read) : '',
      }
    })
}

const addModelPrice = () => {
  modelPriceDrafts.value.push(newModelPriceDraft())
}

const removeModelPrice = (id: string) => {
  modelPriceDrafts.value = modelPriceDrafts.value.filter((row) => row.id !== id)
}

const parseOptionalPrice = (raw: string): number | null => {
  const trimmed = raw.trim()
  if (trimmed === '') return null
  const value = Number(trimmed)
  if (!Number.isFinite(value) || value < 0) return null
  return value
}

const saveSettings = async (): Promise<boolean> => {
  saving.value = true
  try {
    const nextSettings: CostSettings = {
      provider_multipliers: { ...settings.value.provider_multipliers },
      model_prices: {},
      model_price_overrides: { ...settings.value.model_price_overrides },
    }
    for (const row of modelPriceDrafts.value) {
      const model = normalizeCostModelName(row.model)
      if (!model) continue
      const input = parseOptionalPrice(row.input)
      const output = parseOptionalPrice(row.output)
      const cacheRead = parseOptionalPrice(row.cache_read)
      if (input == null && output == null && cacheRead == null) continue
      nextSettings.model_prices[model] = {
        input: input ?? 0,
        output: output ?? 0,
        cache_read: cacheRead ?? 0,
      }
    }

    settings.value = await saveCostSettings(nextSettings)
    syncModelPriceDrafts()
    showToast(t('components.costs.settings.saved'), 'success')
		return true
  } catch (error: any) {
    showToast(error?.message || t('components.costs.settings.saveFailed'), 'error')
		return false
  } finally {
    saving.value = false
  }
}

const savePriceEditor = async () => {
  if (await saveSettings()) {
    priceEditorOpen.value = false
  }
}

watch(() => filters.platform, () => {
  clearUsageResults()
  void loadProviders()
})

watch(() => filters.provider, () => {
  clearUsageResults()
})

onMounted(async () => {
  isUnmounted = false
  await Promise.all([loadSettings(), loadProviders()])
})

onUnmounted(() => {
  isUnmounted = true
  providerLoadVersion += 1
  settingsLoadVersion += 1
})
</script>

<style scoped>
.costs-page {
  padding: 32px;
  color: var(--mac-text);
}

.costs-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 24px;
}

.costs-eyebrow {
  margin: 0 0 8px;
  color: var(--mac-text-secondary);
  font-size: 0.78rem;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.costs-header h1 {
  margin: 0;
  font-size: 2rem;
}

.costs-description {
  margin: 8px 0 0;
  color: var(--mac-text-secondary);
}

.costs-actions,
.costs-filter-row {
  display: flex;
  gap: 12px;
  align-items: flex-end;
  flex-wrap: wrap;
}

.costs-filter-row {
  margin-bottom: 20px;
  padding: 16px;
  border: 1px solid var(--mac-border);
  border-radius: 14px;
  background: var(--mac-surface);
}

.filter-field {
  display: grid;
  gap: 6px;
  min-width: 220px;
  color: var(--mac-text-secondary);
  font-size: 0.9rem;
}

.mac-select {
  min-height: 36px;
  border-radius: 8px;
  border: 1px solid var(--mac-border);
  background: var(--mac-bg);
  color: var(--mac-text);
  padding: 0 10px;
}

.costs-summary-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
  margin-bottom: 20px;
}

.cost-summary-card,
.costs-panel {
  border: 1px solid var(--mac-border);
  background: var(--mac-surface);
  border-radius: 16px;
  box-shadow: var(--mac-shadow-sm);
}

.cost-summary-card {
  padding: 18px;
  display: grid;
  gap: 8px;
}

.cost-summary-card span,
.cost-summary-card small,
.panel-header p,
.price-editor-unit,
.settings-empty {
  color: var(--mac-text-secondary);
}

.cost-summary-card strong {
  font-size: 1.55rem;
}

.cost-summary-card.highlight strong {
  color: var(--mac-accent);
}

.costs-panel {
  padding: 18px;
  margin-bottom: 20px;
}

.panel-header {
  display: flex;
  justify-content: space-between;
  gap: 16px;
  align-items: flex-start;
  margin-bottom: 16px;
}

.panel-header h2 {
  margin: 0 0 4px;
}

.panel-header p {
  margin: 0;
}

.settings-empty,
.empty-state {
  padding: 28px;
  text-align: center;
}

.settings-content {
  display: grid;
  gap: 16px;
}

.price-editor-modal {
  display: grid;
  gap: 16px;
}

.price-editor-unit {
  margin: 0;
}

.price-editor-actions {
  margin-top: 18px;
  padding-top: 16px;
  border-top: 1px solid var(--mac-border);
}

.multiplier-field {
  display: flex;
  gap: 10px;
  align-items: center;
  flex-wrap: wrap;
}

.multiplier-field input {
  width: 140px;
}

.multiplier-suffix {
  color: var(--mac-text-secondary);
}

.price-editor-list,
.cost-detail-groups {
  display: grid;
  gap: 12px;
}

.price-editor-table-wrapper {
  overflow-x: auto;
  border: 1px solid var(--mac-border);
  border-radius: 8px;
}

.price-editor-table {
  width: 100%;
  min-width: 720px;
  border-collapse: collapse;
}

.price-editor-table th,
.price-editor-table td {
  padding: 10px;
  border-bottom: 1px solid var(--mac-border);
  text-align: left;
  vertical-align: middle;
}

.price-editor-table th {
  color: var(--mac-text-secondary);
  font-size: 0.85rem;
  font-weight: 600;
}

.price-editor-table tbody tr:last-child td {
  border-bottom: 0;
}

.price-editor-table th:first-child,
.price-editor-table td:first-child {
  min-width: 220px;
}

.price-editor-table td input {
  width: 100%;
}

.price-editor-remove-cell {
  width: 1%;
  white-space: nowrap;
}

.price-editor-card {
  border: 1px solid var(--mac-border);
  border-radius: 12px;
  padding: 14px;
  background: var(--mac-bg);
}

.price-editor-title {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  margin-bottom: 12px;
}

.price-editor-fields {
  display: grid;
  grid-template-columns: repeat(3, minmax(130px, 1fr)) auto;
  gap: 10px;
  align-items: end;
}

.price-editor-fields label {
  display: grid;
  gap: 5px;
  color: var(--mac-text-secondary);
  font-size: 0.85rem;
}

.provider-group-title {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  margin: 0 0 10px;
  border: 1px solid var(--mac-border);
  border-radius: 999px;
  padding: 4px 10px;
  background: var(--mac-bg);
  font-size: 0.9rem;
  font-weight: 600;
  line-height: 1.3;
}

.provider-group-platform {
  color: var(--mac-text-secondary);
  font-size: 0.78rem;
  font-weight: 500;
}

.model-table-wrapper {
  overflow-x: auto;
}

.model-cost-table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
  min-width: 980px;
}

.model-cost-table th:nth-child(1) {
  width: 22%;
}

.model-cost-table th:nth-child(2) {
  width: 8%;
}

.model-cost-table th:nth-child(3) {
  width: 29%;
}

.model-cost-table th:nth-child(4) {
  width: 18%;
}

.model-cost-table th:nth-child(5) {
  width: 9%;
}

.model-cost-table th:nth-child(6) {
  width: 14%;
}

.model-cost-table th,
.model-cost-table td {
  padding: 12px;
  border-bottom: 1px solid var(--mac-border);
  text-align: left;
  vertical-align: top;
}

.model-cost-table th {
  color: var(--mac-text-secondary);
  font-weight: 600;
  font-size: 0.85rem;
}

.model-name-cell strong,
.model-name-cell span,
.tokens-cell span,
.prices-cell span {
  display: block;
  margin-bottom: 6px;
}

.model-name-cell strong {
  overflow-wrap: anywhere;
}

.tokens-cell,
.prices-cell {
  font-size: 0.88rem;
  line-height: 1.45;
}

.not-billed {
  color: var(--mac-text-secondary);
}

.subtotal-cell strong {
  color: var(--mac-accent);
}

.source-pill,
.override-pill,
.missing-pill {
  display: inline-flex;
  align-items: center;
  width: fit-content;
  border-radius: 999px;
  padding: 2px 8px;
  font-size: 0.75rem;
}

.source-pill {
  background: rgba(34, 197, 94, 0.12);
  color: #16a34a;
}

.override-pill {
  background: rgba(59, 130, 246, 0.12);
  color: #2563eb;
}

.missing-pill {
  background: rgba(245, 158, 11, 0.14);
  color: #d97706;
}

.is-unpriced {
  background: rgba(245, 158, 11, 0.04);
}

@media (max-width: 900px) {
  .costs-page {
    padding: 20px;
  }

  .costs-header,
  .panel-header {
    display: grid;
  }

  .costs-summary-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .price-editor-fields {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 640px) {
  .costs-summary-grid {
    grid-template-columns: 1fr;
  }
}
</style>
