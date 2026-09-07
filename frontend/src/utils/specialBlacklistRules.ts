// 高级拉黑规则的纯函数逻辑：模式归一化、编辑表单兼容、保存前校验与载荷清理。
// 后端接受大小写/空格变体（如 " UNTIL "）并在保存时规范化存储，运行时匹配也是宽松的，
// 前端判断必须同样宽松，否则手工配置的这类规则在编辑保存后会被静默改回按时长模式。
import type { SpecialBlacklistDurationType, SpecialBlacklistRule } from '../services/providerPool'

export type SpecialBlacklistRuleError = 'durationType' | 'untilDayOffset' | 'untilTime'

export function normalizeSpecialRuleDurationType(value: unknown): string {
  return typeof value === 'string' ? value.trim().toLowerCase() : ''
}

// 兼容旧数据：durationType 缺省视为按时长拉黑；天数偏移缺省视为当天（0 是合法值，不能默认成 1）。
// 无法识别的模式保留原值，由保存校验显式报错，避免静默改变行为。
export function normalizeSpecialRuleForm(rule: SpecialBlacklistRule): SpecialBlacklistRule {
  const type = normalizeSpecialRuleDurationType(rule.durationType)
  return {
    ...rule,
    durationType: type === 'until' ? 'until' : type === '' || type === 'duration' ? 'duration' : type as SpecialBlacklistDurationType,
    untilDayOffset: typeof rule.untilDayOffset === 'number' ? rule.untilDayOffset : 0,
    untilTime: rule.untilTime ?? '00:00',
  }
}

// 返回 null 表示规则可提交；否则返回错误种类，由调用方负责提示。
// 关闭弹窗的保存路径会绕过 HTML 表单校验，这里必须严格检查原始值，
// 不做任何静默修正（空值/小数/越界一律报错）。
export function validateSpecialRuleForSave(rule: SpecialBlacklistRule): SpecialBlacklistRuleError | null {
  const type = normalizeSpecialRuleDurationType(rule.durationType)
  if (type !== 'until' && type !== 'duration' && type !== '') {
    return 'durationType'
  }
  if (type === 'until') {
    const dayOffset = rule.untilDayOffset
    if (typeof dayOffset !== 'number' || !Number.isInteger(dayOffset) || dayOffset < 0 || dayOffset > 99) {
      return 'untilDayOffset'
    }
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test((rule.untilTime ?? '').trim())) {
      return 'untilTime'
    }
  }
  return null
}

export interface SpecialBlacklistRulesPayload {
  rules: SpecialBlacklistRule[]
  error: SpecialBlacklistRuleError | null
}

export function buildSpecialBlacklistRulesPayload(rules: SpecialBlacklistRule[]): SpecialBlacklistRulesPayload {
  const payload: SpecialBlacklistRule[] = []
  for (const rule of rules) {
    const error = validateSpecialRuleForSave(rule)
    if (error) {
      return { rules: [], error }
    }
    const type = normalizeSpecialRuleDurationType(rule.durationType)
    if (type === 'until') {
      payload.push({ ...rule, durationType: 'until', untilDayOffset: rule.untilDayOffset as number, untilTime: (rule.untilTime ?? '').trim() })
    } else {
      payload.push({ ...rule, durationType: 'duration', untilDayOffset: 0, untilTime: '' })
    }
  }
  return { rules: payload, error: null }
}

// 脏检查签名用规范化：把后端可能的大小写/空格变体折算成 until/duration，保证比较稳定。
export function canonicalSpecialRuleDurationType(value: unknown): SpecialBlacklistDurationType {
  return normalizeSpecialRuleDurationType(value) === 'until' ? 'until' : 'duration'
}
