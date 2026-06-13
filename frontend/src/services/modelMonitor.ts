import { Call } from '@wailsio/runtime'
import type { LogPlatform } from './logs'

const SERVICE_PATH = 'codeswitch/services.ModelMonitorService'

export type ModelMonitorStatus = 'operational' | 'degraded' | 'failed' | 'validation_failed'
export type ModelMonitorSource = 'active' | 'manual' | 'real_traffic'

export type ModelMonitorTarget = {
  id: number
  userId?: string
  platform: LogPlatform
  providerId: number
  providerName: string
  model: string
  enabled: boolean
  intervalSeconds: number
  timeoutMs: number
  createdAt: string
  updatedAt: string
  lastCheckedAt?: string
}

export type ModelMonitorResult = {
  id: number
  targetId: number
  userId?: string
  platform: LogPlatform
  providerId: number
  providerName: string
  model: string
  endpoint: string
  httpCode: number
  status: ModelMonitorStatus
  latencyMs: number
  errorMessage: string
  source: ModelMonitorSource
  checkedAt: string
}

export type ModelMonitorTimeline = {
  target: ModelMonitorTarget
  latest?: ModelMonitorResult | null
  items: ModelMonitorResult[]
  uptime: number
  avgLatencyMs: number
}

export type ProviderModelList = {
  models: string[]
  source: 'remote' | 'config' | string
}

export const listModelMonitorTimelines = async (): Promise<ModelMonitorTimeline[]> => {
  return Call.ByName(`${SERVICE_PATH}.ListTimelines`)
}

export const listProviderModels = async (
  platform: LogPlatform,
  providerId: number,
): Promise<ProviderModelList> => {
  return Call.ByName(`${SERVICE_PATH}.ListProviderModels`, platform, providerId)
}

export const saveModelMonitorTarget = async (
  target: Partial<ModelMonitorTarget>,
): Promise<ModelMonitorTarget> => {
  return Call.ByName(`${SERVICE_PATH}.SaveTarget`, target)
}

export const deleteModelMonitorTarget = async (targetId: number): Promise<void> => {
  return Call.ByName(`${SERVICE_PATH}.DeleteTarget`, targetId)
}

export const runModelMonitorTargetCheck = async (targetId: number): Promise<ModelMonitorResult> => {
  return Call.ByName(`${SERVICE_PATH}.RunTargetCheck`, targetId)
}

export const runAllModelMonitorChecks = async (): Promise<ModelMonitorResult[]> => {
  return Call.ByName(`${SERVICE_PATH}.RunAllChecks`)
}
