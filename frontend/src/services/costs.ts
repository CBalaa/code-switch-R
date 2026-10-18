import { Call } from '@wailsio/runtime'
import type { LogPlatform } from './logs'

const SERVICE = 'codeswitch/services.CostService'

export type CostUsageItem = {
  platform: LogPlatform | string
  provider: string
  model: string
  total_requests: number
  input_tokens: number
  output_tokens: number
  cache_create_tokens: number
  cache_read_tokens: number
  reasoning_tokens: number
}

export type CostPrice = {
  input: number
  output: number
  cache_read: number
}

export type CostSettings = {
  provider_multipliers: Record<string, number>
  model_prices: Record<string, CostPrice>
  model_price_overrides: Record<string, CostPrice>
}

export type DefaultModelPrice = CostPrice & {
  platformGroup: 'claude' | 'openai'
  model: string
  label: string
  aliases?: string[]
  source: string
}

export const defaultCostSettings = (): CostSettings => ({
  provider_multipliers: {},
  model_prices: {},
  model_price_overrides: {},
})

export const normalizeCostModelName = (model: string): string => model.trim().toLowerCase()

export const costProviderKey = (platform: string, provider: string): string => `${platform.trim()}::${provider.trim()}`

export const costModelKey = (platform: string, provider: string, model: string): string =>
  `${costProviderKey(platform, provider)}::${normalizeCostModelName(model)}`

export const fetchTodayCostUsage = async (
  platform: LogPlatform | '' = '',
  provider = '',
): Promise<CostUsageItem[]> => {
  return Call.ByName(`${SERVICE}.TodayUsage`, platform, provider)
}

export const fetchCostSettings = async (): Promise<CostSettings> => {
  const settings = await Call.ByName(`${SERVICE}.GetSettings`) as CostSettings
  return {
    ...defaultCostSettings(),
    ...settings,
    provider_multipliers: settings?.provider_multipliers ?? {},
    model_prices: settings?.model_prices ?? {},
    model_price_overrides: settings?.model_price_overrides ?? {},
  }
}

export const saveCostSettings = async (settings: CostSettings): Promise<CostSettings> => {
  return Call.ByName(`${SERVICE}.SaveSettings`, settings)
}

export const resetProviderMultiplier = async (platform: string, provider: string): Promise<void> => {
  return Call.ByName(`${SERVICE}.ResetProviderMultiplier`, platform, provider)
}

export const resetModelOverride = async (platform: string, provider: string, model: string): Promise<void> => {
  return Call.ByName(`${SERVICE}.ResetModelOverride`, platform, provider, model)
}

// 单位：USD / 1M tokens。只内置官方定价页可确认的模型；未知模型由用户手动覆盖。
export const DEFAULT_MODEL_PRICES: DefaultModelPrice[] = [
  {
    platformGroup: 'claude',
    model: 'claude-haiku-4-5',
    label: 'Claude Haiku 4.5',
    aliases: ['claude-haiku-4-5-20251001'],
    input: 1,
    output: 5,
    cache_read: 0.1,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-sonnet-4-5',
    label: 'Claude Sonnet 4.5',
    aliases: ['claude-sonnet-4-5-20250929'],
    input: 3,
    output: 15,
    cache_read: 0.3,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-sonnet-4-6',
    label: 'Claude Sonnet 4.6',
    input: 3,
    output: 15,
    cache_read: 0.3,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-sonnet-4',
    label: 'Claude Sonnet 4',
    aliases: ['claude-sonnet-4-20250514'],
    input: 3,
    output: 15,
    cache_read: 0.3,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-opus-4-8',
    label: 'Claude Opus 4.8',
    input: 5,
    output: 25,
    cache_read: 0.5,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-opus-4-7',
    label: 'Claude Opus 4.7',
    input: 5,
    output: 25,
    cache_read: 0.5,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-opus-4-6',
    label: 'Claude Opus 4.6',
    input: 5,
    output: 25,
    cache_read: 0.5,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-opus-4-5',
    label: 'Claude Opus 4.5',
    input: 5,
    output: 25,
    cache_read: 0.5,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'claude',
    model: 'claude-opus-4-1',
    label: 'Claude Opus 4.1',
    aliases: ['claude-opus-4-1-20250805'],
    input: 15,
    output: 75,
    cache_read: 1.5,
    source: 'Anthropic pricing',
  },
  {
    platformGroup: 'openai',
    model: 'gpt-5.5',
    label: 'GPT-5.5',
    aliases: ['GPT-5.5'],
    input: 5,
    output: 30,
    cache_read: 0.5,
    source: 'OpenAI API pricing',
  },
  {
    platformGroup: 'openai',
    model: 'gpt-5.4',
    label: 'GPT-5.4',
    aliases: ['GPT-5.4'],
    input: 2.5,
    output: 15,
    cache_read: 0.25,
    source: 'OpenAI API pricing',
  },
]

const defaultPriceByModel = new Map<string, DefaultModelPrice>()
for (const price of DEFAULT_MODEL_PRICES) {
  defaultPriceByModel.set(normalizeCostModelName(price.model), price)
  for (const alias of price.aliases ?? []) {
    defaultPriceByModel.set(normalizeCostModelName(alias), price)
  }
}

export const platformPriceGroup = (platform: string): 'claude' | 'openai' | 'unknown' => {
  if (platform === 'claude') return 'claude'
  if (platform === 'openai-responses' || platform === 'openai-chat' || platform === 'openai-images') return 'openai'
  return 'unknown'
}

export const findDefaultPrice = (platform: string, model: string): DefaultModelPrice | null => {
  const price = defaultPriceByModel.get(normalizeCostModelName(model)) ?? null
  if (!price) return null
  return price.platformGroup === platformPriceGroup(platform) ? price : null
}
