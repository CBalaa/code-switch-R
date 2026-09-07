import assert from 'node:assert/strict'
import test from 'node:test'

import {
  buildSpecialBlacklistRulesPayload,
  canonicalSpecialRuleDurationType,
  normalizeSpecialRuleForm,
  validateSpecialRuleForSave,
} from '../src/utils/specialBlacklistRules.ts'

import type { SpecialBlacklistRule } from '../src/services/providerPool.ts'

const untilRule = (overrides: Partial<SpecialBlacklistRule> = {}): SpecialBlacklistRule => ({
  id: 'rule-1',
  name: 'quota',
  httpStatus: 429,
  threshold: 1,
  durationMinutes: 0,
  durationType: 'until',
  untilDayOffset: 0,
  untilTime: '23:59',
  ...overrides,
})

test('hand-edited duration type variants keep until mode through the form round trip', () => {
  for (const variant of [' UNTIL ', 'UNTIL', 'until ']) {
    const normalized = normalizeSpecialRuleForm(untilRule({ durationType: variant as SpecialBlacklistRule['durationType'] }))
    assert.equal(normalized.durationType, 'until', `variant ${variant} should stay until mode`)
    const payload = buildSpecialBlacklistRulesPayload([normalized])
    assert.equal(payload.error, null)
    assert.equal(payload.rules[0].durationType, 'until')
    assert.equal(payload.rules[0].untilDayOffset, 0)
    assert.equal(payload.rules[0].untilTime, '23:59')
  }
})

test('legacy duration variants normalize to duration and clear until fields', () => {
  for (const variant of [undefined, '', '  ', 'Duration']) {
    const normalized = normalizeSpecialRuleForm(untilRule({ durationType: variant as SpecialBlacklistRule['durationType'], durationMinutes: 5 }))
    assert.equal(normalized.durationType, 'duration')
    const payload = buildSpecialBlacklistRulesPayload([normalized])
    assert.equal(payload.error, null)
    assert.equal(payload.rules[0].durationType, 'duration')
    assert.equal(payload.rules[0].untilDayOffset, 0)
    assert.equal(payload.rules[0].untilTime, '')
    assert.equal(payload.rules[0].durationMinutes, 5)
  }
})

test('unknown duration types are rejected instead of silently becoming duration', () => {
  const normalized = normalizeSpecialRuleForm(untilRule({ durationType: 'weekly' as SpecialBlacklistRule['durationType'] }))
  assert.equal(normalized.durationType, 'weekly', 'unknown type must be preserved for the explicit error')
  assert.equal(validateSpecialRuleForSave(normalized), 'durationType')
  assert.equal(buildSpecialBlacklistRulesPayload([normalized]).error, 'durationType')
})

test('day offset 0 (today) survives normalization and payload build', () => {
  const normalized = normalizeSpecialRuleForm(untilRule({ untilDayOffset: 0 }))
  assert.equal(normalized.untilDayOffset, 0)
  const payload = buildSpecialBlacklistRulesPayload([normalized])
  assert.equal(payload.error, null)
  assert.equal(payload.rules[0].untilDayOffset, 0)
})

test('missing day offset defaults to today (0), not tomorrow', () => {
  const normalized = normalizeSpecialRuleForm(untilRule({ untilDayOffset: null }))
  assert.equal(normalized.untilDayOffset, 0)
  const missing = normalizeSpecialRuleForm(untilRule({ untilDayOffset: undefined }))
  assert.equal(missing.untilDayOffset, 0)
})

test('empty, fractional, and out-of-range day offsets are rejected without coercion', () => {
  const cases: Array<SpecialBlacklistRule['untilDayOffset']> = ['', 1.5, -1, 100, Number.NaN]
  for (const dayOffset of cases) {
    const rule = untilRule({ untilDayOffset: dayOffset })
    assert.equal(validateSpecialRuleForSave(rule), 'untilDayOffset', `offset ${String(dayOffset)} must be rejected`)
    assert.equal(buildSpecialBlacklistRulesPayload([rule]).error, 'untilDayOffset')
  }
})

test('invalid until times are rejected', () => {
  for (const untilTime of ['', '24:00', '12:60', '9:30', 'abc']) {
    assert.equal(validateSpecialRuleForSave(untilRule({ untilTime })), 'untilTime', `time ${untilTime} must be rejected`)
  }
})

test('valid until rule passes save validation', () => {
  assert.equal(validateSpecialRuleForSave(untilRule({ untilDayOffset: 1, untilTime: '00:00' })), null)
  assert.equal(validateSpecialRuleForSave(untilRule({ untilDayOffset: 99, untilTime: '23:59' })), null)
})

test('canonical duration type folds case and space variants', () => {
  assert.equal(canonicalSpecialRuleDurationType(' UNTIL '), 'until')
  assert.equal(canonicalSpecialRuleDurationType('Duration'), 'duration')
  assert.equal(canonicalSpecialRuleDurationType(undefined), 'duration')
  assert.equal(canonicalSpecialRuleDurationType(null), 'duration')
})
