import { Call } from '@wailsio/runtime'

export type LogPlatform = 'claude' | 'codex' | 'gemini'

export type RequestLog = {
  id: number
  platform: LogPlatform | ''
  model: string
  provider: string
  relay_key_id?: string
  relay_key_name?: string
  http_code: number
  input_tokens: number
  output_tokens: number
  cache_create_tokens: number
  cache_read_tokens: number
  reasoning_tokens: number
  is_stream?: boolean | number
  duration_sec?: number
  upstream_header_sec?: number
  first_event_sec?: number
  first_text_sec?: number
  created_at: string
}

type RequestLogQuery = {
  platform?: LogPlatform | ''
  provider?: string
  limit?: number
}

export const fetchRequestLogs = async (query: RequestLogQuery = {}): Promise<RequestLog[]> => {
  const platform = query.platform ?? ''
  const provider = query.provider ?? ''
  const limit = query.limit ?? 100
  return Call.ByName('codeswitch/services.LogService.ListRequestLogs', platform, provider, limit)
}

export const fetchLogProviders = async (platform: LogPlatform | '' = ''): Promise<string[]> => {
  return Call.ByName('codeswitch/services.LogService.ListProviders', platform)
}

export type LogStatsSeries = {
  day: string
  total_requests: number
  input_tokens: number
  output_tokens: number
  reasoning_tokens: number
  cache_create_tokens: number
  cache_read_tokens: number
}

export type LogStats = {
  total_requests: number
  input_tokens: number
  output_tokens: number
  reasoning_tokens: number
  cache_create_tokens: number
  cache_read_tokens: number
  series: LogStatsSeries[]
}

export const fetchLogStats = async (platform: LogPlatform | '' = ''): Promise<LogStats> => {
  return Call.ByName('codeswitch/services.LogService.StatsSince', platform)
}

export type ProviderDailyStat = {
  provider: string
  total_requests: number
  successful_requests: number
  failed_requests: number
  success_rate: number
  input_tokens: number
  output_tokens: number
  reasoning_tokens: number
  cache_create_tokens: number
  cache_read_tokens: number
}

export const fetchProviderDailyStats = async (
  platform: LogPlatform | '' = '',
): Promise<ProviderDailyStat[]> => {
  return Call.ByName('codeswitch/services.LogService.ProviderDailyStats', platform)
}
