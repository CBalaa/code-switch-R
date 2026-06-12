// ProviderPoolService Wails 绑定
// 通过 RPC 调用后端 ProviderPoolService 的方法

import { Call } from '../wails-runtime'

export type ProviderPoolMode = 'managed' | 'manual'

export interface ProviderPoolMember {
  providerId: number
  enabled: boolean
  level?: number
  priority?: number
  weight?: number
}

export interface ProviderPool {
  id: string
  platform: string
  name: string
  mode: ProviderPoolMode
  manualProviderId?: number | null
  members: ProviderPoolMember[]
  createdAt: string
  updatedAt: string
  /** 自动拉黑配置（仅 managed 模式生效） */
  autoBlacklistEnabled: boolean
  autoBlacklistThreshold: number
  autoBlacklistDurationMinutes: number
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
 * 列出所有 relay key（包含 poolBindings）
 */
export async function ListRelayKeys(): Promise<RelayKeyItem[]> {
  return Call.ByName<RelayKeyItem[]>('codeswitch/services.CodexRelayKeyService.ListKeys')
}
