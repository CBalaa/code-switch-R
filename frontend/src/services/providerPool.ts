// ProviderPoolService Wails 绑定
// 通过 RPC 调用后端 ProviderPoolService 的方法

import { Call } from '../wails-runtime'

export type ProviderPoolMode = 'managed' | 'manual'

export interface ProviderPoolMember {
  providerId: number
  enabled: boolean
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
 * 列出所有 relay key（包含 poolBindings）
 */
export async function ListRelayKeys(): Promise<RelayKeyItem[]> {
  return Call.ByName<RelayKeyItem[]>('codeswitch/services.CodexRelayKeyService.ListKeys')
}
