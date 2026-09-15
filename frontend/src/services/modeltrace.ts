import { Call, Events } from '@wailsio/runtime'

const SERVICE = 'codeswitch/services.ModelTraceService'

/** 指纹库覆盖的模型 */
export interface ModelTraceModelOption {
  id: string
  displayName: string
  family: string
  familyName: string
}

/** 单模型归因概率 */
export interface ModelTraceProbability {
  model: string
  displayName: string
  family: string
  familyName: string
  probability: number
  profileSimilarity: number
}

/** 鉴伪结果 */
export interface ModelTraceResult {
  success: boolean
  message: string
  expectedModel: string
  expectedMatched: boolean
  topModel: string
  topModelName: string
  topProbability: number
  verdict: 'match' | 'mismatch' | 'error'
  validNumberCount: number
  attempts: number
  latencyMs: number
  probabilities: ModelTraceProbability[]
  rawOutput?: string
}

/**
 * 获取指纹库覆盖的模型列表（用于检测目标选择器）
 */
export const getSupportedModels = async (): Promise<ModelTraceModelOption[]> => {
  return Call.ByName(`${SERVICE}.GetSupportedModels`)
}

/**
 * 对指定 provider + 模型执行一次指纹鉴伪
 * @param platform 平台（claude / codex / ...）
 * @param providerId 供应商 ID
 * @param expectedModel 用户选择要检测的模型（须在指纹库覆盖范围内）
 */
export const verifyProviderModel = async (
  platform: string,
  providerId: number,
  expectedModel: string,
): Promise<ModelTraceResult> => {
  return Call.ByName(`${SERVICE}.VerifyProviderModel`, platform, providerId, expectedModel)
}

/** 鉴伪过程进度事件（modeltrace:progress） */
export interface ModelTraceProgress {
  sessionId: string
  providerId: number
  expectedModel: string
  stage: 'sending' | 'received' | 'analyzing' | 'retrying' | 'done' | 'failed'
  attempt: number
  maxAttempts: number
  detail: string
  elapsedMs: number
}

/**
 * 订阅鉴伪进度事件。返回取消订阅函数。
 * 事件是全局广播的，回调里应按 sessionId 过滤归属。
 */
export const subscribeProgress = (
  callback: (progress: ModelTraceProgress) => void,
): (() => void) => {
  const unsubscribe = Events.On('modeltrace:progress', (event) => {
    const data = (event as unknown as { data: ModelTraceProgress }).data
    if (data && typeof data === 'object') {
      callback(data)
    }
  })
  return () => unsubscribe()
}

/** 流式生成片段事件（modeltrace:stream） */
export interface ModelTraceStreamChunk {
  sessionId: string
  providerId?: number
  expectedModel?: string
  chunk: string
  totalChars: number
}

/**
 * 订阅流式生成片段。返回取消订阅函数。
 * 事件是全局广播的，回调里应按 sessionId 过滤归属。
 */
export const subscribeStream = (
  callback: (chunk: ModelTraceStreamChunk) => void,
): (() => void) => {
  const unsubscribe = Events.On('modeltrace:stream', (event) => {
    const data = (event as unknown as { data: ModelTraceStreamChunk }).data
    if (data && typeof data === 'object') {
      callback(data)
    }
  })
  return () => unsubscribe()
}

