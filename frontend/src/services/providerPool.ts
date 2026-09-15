// ProviderPoolService Wails 绑定
// 通过 RPC 调用后端 ProviderPoolService 的方法

import { Call } from '../wails-runtime'

export type ProviderPoolMode = 'managed' | 'manual'
export type ProviderPoolType = 'normal' | 'account'
export type AccountPoolProxySelection = 'none' | 'auto' | 'node'

export interface AccountPoolProxyConfig {
  enabled: boolean
  selection: AccountPoolProxySelection
  proxyNodeId?: string
  autoDisableWhenNoAvailable?: boolean
}

export interface ProxyNode {
  id: string
  configName: string
  originalName: string
  name: string
  uploader: string
}

export interface ProxyConfigSummary {
  /** Stable server-side identifier. Do not derive this from the YAML file name. */
  id: string
  name: string
  fileName: string
  uploader: string
  uploadedAt: string
  /** True only for the user who originally uploaded this YAML configuration. */
  isOwner: boolean
  nodes: ProxyNode[]
}

export interface ProxySpeedTestResult {
  proxyLatencyMs?: number
  responsesLatencyMs?: number
  responsesStatus?: number
  responsesError?: string
  responsesCloudflareBlocked?: boolean
  proxyError?: string
  cleanupError?: string
}

export interface ProxyNodeLatencyResult {
  nodeId: string
  tested: boolean
  proxyLatencyMs?: number
  proxyError?: string
  responsesLatencyMs?: number
  responsesStatus?: number
  responsesError?: string
  responsesCloudflareBlocked?: boolean
}

export interface ProxySpeedTestSnapshot {
  testedAt?: string
  results: ProxyNodeLatencyResult[]
}

export interface AccountPoolKey {
  id: number
  apiKey: string
}

/** Mirrors the relay's secret-safe account-key provider label. */
export function accountPoolKeyDisplayName(key: AccountPoolKey): string {
  const apiKey = key.apiKey.trim()
  const maskedKey = apiKey.length <= 4 ? '****' : `****${apiKey.slice(-4)}`
  return `Account Key ${maskedKey} (#${Math.abs(key.id)})`
}

export interface AccountPoolConfig {
  apiUrl: string
  /** openai-responses 号池的协议端点（仅 responses 号池使用） */
  responsesEndpoint?: string
  /** openai-chat 号池的协议端点（仅 chat 号池使用） */
  chatEndpoint?: string
  keys: AccountPoolKey[]
}

export interface ProviderPoolMember {
  providerId: number
  enabled: boolean
  level?: number
  priority?: number
  weight?: number
}

export type SpecialBlacklistDurationType = 'duration' | 'until'

export interface SpecialBlacklistRule {
  id: string
  name: string
  httpStatus: number
  jsonPath?: string
  expectedJsonValue?: string
  threshold: number
  durationMinutes: number
  /** 'duration' = 按时长拉黑（缺省行为）；'until' = 拉黑到指定日期时间 */
  durationType?: SpecialBlacklistDurationType
  /** durationType = 'until' 时生效：0 = 当天，1 = 次日，以此类推 */
  untilDayOffset?: number | null
  /** durationType = 'until' 时生效：HH:MM（服务器本地时间） */
  untilTime?: string
}

export interface ProviderPool {
  id: string
  platform: string
  name: string
  poolType: ProviderPoolType
  mode: ProviderPoolMode
  manualProviderId?: number | null
  members: ProviderPoolMember[]
  accountPoolConfig?: AccountPoolConfig
  proxyConfig?: AccountPoolProxyConfig
  excludeFromTotalTraffic?: boolean
  hideFromLogs?: boolean
  createdAt: string
  updatedAt: string
  /** 自动拉黑配置（仅 managed 模式生效） */
  autoBlacklistEnabled: boolean
  autoBlacklistThreshold: number
  autoBlacklistDurationMinutes: number
  specialBlacklistRules: SpecialBlacklistRule[]
  firstTextRetryEnabled: boolean
  firstTextRetryTimeoutSeconds: number
}

export interface ProviderPoolWithProviders extends ProviderPool {
  /** 成员供应商的详细信息（前端组装） */
  memberProviders: PoolMemberProvider[]
}

export interface PoolMemberProvider {
  id: number
  name: string
  apiUrl: string
  enabled: boolean
  /** 该成员在池子中的启用状态 */
  memberEnabled: boolean
}

/**
 * 列出指定 platform 的所有池子
 */
export async function ListPools(platform: string): Promise<ProviderPool[]> {
  return Call.ByName('codeswitch/services.ProviderPoolService.ListPools', platform)
}

/**
 * 列出所有池子
 */
export async function ListAllPools(): Promise<ProviderPool[]> {
  return Call.ByName('codeswitch/services.ProviderPoolService.ListAllPools')
}

/**
 * 获取单个池子
 */
export async function GetPool(poolID: string): Promise<ProviderPool | null> {
  return Call.ByName('codeswitch/services.ProviderPoolService.GetPool', poolID)
}

/**
 * 保存池子（创建或更新）
 * 返回池子 ID
 */
export async function SavePool(pool: Partial<ProviderPool> & { platform: string; name: string; mode: ProviderPoolMode }): Promise<string> {
  return Call.ByName('codeswitch/services.ProviderPoolService.SavePool', pool)
}

/**
 * 删除池子
 */
export async function DeletePool(poolID: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProviderPoolService.DeletePool', poolID)
}

export async function ListProxyConfigs(): Promise<ProxyConfigSummary[]> {
  return Call.ByName('codeswitch/services.ProxyService.ListProxyConfigs')
}

export async function UploadProxyConfig(fileName: string, content: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProxyService.UploadProxyConfig', fileName, content)
}

export async function ImportProxySubscription(subscriptionURL: string, configName: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProxyService.ImportProxySubscription', subscriptionURL, configName)
}

export async function DeleteProxyConfig(configID: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProxyService.DeleteProxyConfig', configID)
}

export async function HideProxyConfig(configID: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProxyService.HideProxyConfig', configID)
}

export async function ListHiddenProxyConfigs(): Promise<ProxyConfigSummary[]> {
  return Call.ByName('codeswitch/services.ProxyService.ListHiddenProxyConfigs')
}

export async function UnhideProxyConfig(configID: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProxyService.UnhideProxyConfig', configID)
}

export async function RefreshProxyConfigs(): Promise<ProxyConfigSummary[]> {
  return Call.ByName('codeswitch/services.ProxyService.RefreshProxyConfigs')
}

export async function TestProxy(poolID: string, nodeID: string, responsesURL: string, signal?: AbortSignal): Promise<ProxySpeedTestResult> {
  if (signal) {
    return Call.ByNameWithSignal('codeswitch/services.ProxyService.TestProxy', signal, poolID, nodeID, responsesURL)
  }
  return Call.ByName('codeswitch/services.ProxyService.TestProxy', poolID, nodeID, responsesURL)
}

export async function GetProxySpeedTests(poolID: string, responsesURL: string): Promise<ProxySpeedTestSnapshot> {
  return Call.ByName('codeswitch/services.ProxyService.GetProxySpeedTests', poolID, responsesURL)
}

/**
 * 确保 relay key 绑定了指定 platform 的池子
 */
export async function SetPoolBinding(keyID: string, platform: string, poolID: string): Promise<void> {
  return Call.ByName('codeswitch/services.CodexRelayKeyService.SetPoolBinding', keyID, platform, poolID)
}

/**
 * 获取 relay key 在指定 platform 的池子绑定
 */
export async function GetPoolBinding(keyID: string, platform: string): Promise<{ poolID: string; found: boolean }> {
  const result = await Call.ByName<[string, boolean]>('codeswitch/services.CodexRelayKeyService.GetPoolBinding', keyID, platform)
  return { poolID: result[0], found: result[1] }
}

export interface RelayKeyItem {
  id: string
  name: string
  maskedKey: string
  enabled: boolean
  poolBindings?: Record<string, string>
}

/**
 * 池子内 provider 的拉黑状态
 */
export interface ProviderPoolProviderPenalty {
  platform: string
  poolID: string
  providerID: number
  failureCount: number
  lastFailureAt: string
  blacklistedUntil: string
  lastReason: string
}

/**
 * 列出指定池子内所有 provider 的拉黑状态
 */
export async function ListProviderBlacklistStatus(platform: string, poolID: string): Promise<ProviderPoolProviderPenalty[]> {
  return Call.ByName('codeswitch/services.ProviderRelayService.ListProviderBlacklistStatus', platform, poolID)
}

/**
 * 手动清除指定池子内某个 provider 的拉黑状态
 */
export async function ClearProviderBlacklist(platform: string, poolID: string, providerID: number): Promise<void> {
  return Call.ByName('codeswitch/services.ProviderRelayService.ClearProviderBlacklist', platform, poolID, providerID)
}

/**
 * 清除号池内所有已拉黑的密钥
 */
export async function ClearAllProviderBlacklists(platform: string, poolID: string): Promise<void> {
  return Call.ByName('codeswitch/services.ProviderRelayService.ClearAllProviderBlacklists', platform, poolID)
}

/**
 * 列出所有 relay key（包含 poolBindings）
 */
export async function ListRelayKeys(): Promise<RelayKeyItem[]> {
  return Call.ByName<RelayKeyItem[]>('codeswitch/services.CodexRelayKeyService.ListKeys')
}
