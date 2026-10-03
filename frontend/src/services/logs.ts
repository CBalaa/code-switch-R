import { Call } from '@wailsio/runtime'

export type LogPlatform = 'claude' | 'openai-responses' | 'openai-chat' | 'gemini'

export type RequestLog = {
  id: number
  platform: LogPlatform | ''
  model: string
  requested_model?: string
  response_model?: string
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
  first_token_duration_sec?: number
  client_ip?: string
  upstream_header_sec?: number
  first_event_sec?: number
  first_text_sec?: number
  error_message?: string
  created_at: string
  status?: 'queued' | 'processing' | 'retrying' | 'completed' | string
  retry_requested?: boolean
  traffic_trace_id?: string
  client_network_scope?: 'local' | 'public' | 'unknown' | string
  client_request_bytes?: number
  client_response_bytes?: number
  upstream_request_bytes?: number
  upstream_response_bytes?: number
  retry_request_bytes?: number
  retry_response_bytes?: number
  upstream_attempts?: number
  public_ingress_bytes?: number
  public_egress_bytes?: number
  local_ingress_bytes?: number
  local_egress_bytes?: number
  queue_position?: number
  queue_started_at?: string
}

export const fetchActiveRequestLogs = async (): Promise<RequestLog[]> => {
  return Call.ByName('codeswitch/services.LogService.ListActiveRequestLogs')
}

export const fetchCompletedRequestLogs = async (
  afterID: number,
  limit: number,
): Promise<RequestLog[]> => {
  return Call.ByName('codeswitch/services.LogService.ListCompletedRequestLogs', afterID, limit)
}

export type RetryActiveRequestResult = {
  status:
    | 'retried'
    | 'ignored_finished'
    | 'ignored_first_text'
    | 'ignored_response_started'
    | 'ignored_unauthorized'
    | 'ignored_queued'
    | 'ignored_transition'
    | string
  first_token_duration_sec?: number
  first_text_sec?: number
}

export const retryActiveRequest = async (id: number): Promise<RetryActiveRequestResult> => {
  return Call.ByName('codeswitch/services.LogService.RetryActiveRequest', id)
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

export type TrafficBreakdown = {
  ingress_bytes: number
  egress_bytes: number
  events: number
}

export type TrafficSummary = {
  since: string
  generated_at: string
  relay_client: TrafficBreakdown
  upstream: TrafficBreakdown
  retry: TrafficBreakdown
  admin: TrafficBreakdown
  accounting_description: string
  dropped_events: number
}

export const fetchTrafficSummary = async (): Promise<TrafficSummary> => {
  return Call.ByName('codeswitch/services.TrafficService.Today')
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
