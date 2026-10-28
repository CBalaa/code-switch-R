import assert from 'node:assert/strict'
import test from 'node:test'
import {
  accountPoolScheduleForm,
  accountPoolScheduleSignature,
  buildAccountPoolSchedulePayload,
  copyAccountPoolScheduleDay,
  nextAccountPoolScheduleRefreshDelay,
} from '../src/utils/accountPoolSchedule.ts'
import type { AccountPoolSchedule, AccountPoolScheduleWindow } from '../src/services/providerPool.ts'

const window = (overrides: Partial<AccountPoolScheduleWindow> = {}): AccountPoolScheduleWindow => ({
  weekday: 1, startTime: '18:00', endTime: '23:59', ...overrides,
})
const schedule = (windows = [window()], enabled = true): AccountPoolSchedule => ({ enabled, windows })

test('old pools default to unrestricted with independent form data', () => {
  assert.deepEqual(accountPoolScheduleForm(), { enabled: false, windows: [] })
  assert.equal(accountPoolScheduleSignature(), accountPoolScheduleSignature(schedule([], false)))
  const saved = schedule()
  const form = accountPoolScheduleForm(saved)
  form.windows[0].startTime = '09:00'
  assert.equal(saved.windows[0].startTime, '18:00')
})

test('save validation catches empty, invalid and overnight periods even when scheduling is disabled', () => {
  assert.equal(buildAccountPoolSchedulePayload(schedule([])).error, 'empty')
  assert.equal(buildAccountPoolSchedulePayload(schedule([], false)).error, null)
  for (const weekday of [0, 8, 1.5, Number.NaN]) {
    assert.equal(buildAccountPoolSchedulePayload(schedule([window({ weekday })])).error, 'weekday')
  }
  for (const startTime of ['', '9:00', '24:00', '12:60', '18:00:00']) {
    assert.equal(buildAccountPoolSchedulePayload(schedule([window({ startTime })])).error, 'time')
  }
  assert.equal(buildAccountPoolSchedulePayload(schedule([window({ endTime: '' })], false)).error, 'time')
  assert.equal(buildAccountPoolSchedulePayload(schedule([window({ startTime: '23:00', endTime: '06:00' })])).error, 'overnight')
})

test('one minute, full day, duplicate, adjacent and overlapping periods are all supported', () => {
  const windows = [
    window({ startTime: '18:00', endTime: '18:00' }),
    window({ weekday: 2, startTime: '00:00', endTime: '23:59' }),
    window(), window(),
    window({ startTime: '17:00', endTime: '17:59' }),
    window({ startTime: '19:00', endTime: '20:00' }),
  ]
  const result = buildAccountPoolSchedulePayload(schedule(windows))
  assert.equal(result.error, null)
  assert.equal(result.schedule.windows.length, windows.length)
  const disabled = buildAccountPoolSchedulePayload(schedule(windows, false))
  assert.equal(disabled.error, null)
  assert.deepEqual(disabled.schedule.windows, result.schedule.windows)
})

test('canonical signatures ignore order and whitespace but retain schedule changes', () => {
  const first = schedule([window(), window({ weekday: 2, startTime: ' 09:00 ', endTime: '10:00' })])
  const second = schedule([window({ weekday: 2, startTime: '09:00', endTime: '10:00' }), window()])
  assert.equal(accountPoolScheduleSignature(first), accountPoolScheduleSignature(second))
  assert.notEqual(accountPoolScheduleSignature(first), accountPoolScheduleSignature({ ...first, enabled: false }))
  assert.notEqual(accountPoolScheduleSignature(first), accountPoolScheduleSignature(schedule([window({ endTime: '23:58' })])))
})

test('copy replaces only chosen days and copies every period without sharing objects', () => {
  const original = schedule([
    window(), window({ startTime: '09:00', endTime: '10:00' }),
    window({ weekday: 2, startTime: '07:00', endTime: '08:00' }),
    window({ weekday: 3, startTime: '11:00', endTime: '12:00' }),
  ])
  const copied = copyAccountPoolScheduleDay(original, 1, [1, 2, 2, 7, 0])
  assert.equal(copied.windows.filter((entry) => entry.weekday === 1).length, 2)
  assert.deepEqual(copied.windows.filter((entry) => entry.weekday === 2).map((entry) => entry.startTime), ['18:00', '09:00'])
  assert.equal(copied.windows.filter((entry) => entry.weekday === 7).length, 2)
  assert.deepEqual(copied.windows.find((entry) => entry.weekday === 3), original.windows[3])
  copied.windows.find((entry) => entry.weekday === 2)!.startTime = '01:00'
  assert.equal(copied.windows.find((entry) => entry.weekday === 1)!.startTime, '18:00')
  assert.equal(original.windows[2].startTime, '07:00')
})

test('next refresh uses server time rather than the client clock and chooses the earliest transition', () => {
  assert.equal(nextAccountPoolScheduleRefreshDelay({
    serverNow: '2000-01-01T17:59:30+08:00',
    statuses: [
      { poolId: 'a', enabled: true, isOpen: false, nextChangeAt: '2000-01-01T18:00:00+08:00' },
      { poolId: 'b', enabled: true, isOpen: true, nextChangeAt: '2000-01-02T00:00:00+08:00' },
      { poolId: 'c', enabled: false, isOpen: true },
    ],
  }), 30_000)
  assert.equal(nextAccountPoolScheduleRefreshDelay({ serverNow: 'invalid', statuses: [] }), null)
  assert.equal(nextAccountPoolScheduleRefreshDelay({ serverNow: '2000-01-01T00:00:00Z', statuses: [] }), null)
})

test('network time is deducted and a potentially passed boundary requires an immediate refresh', () => {
  const snapshot = {
    serverNow: '2000-01-01T17:59:50+08:00',
    statuses: [{ poolId: 'a', enabled: true, isOpen: false, nextChangeAt: '2000-01-01T18:00:00+08:00' }],
  }
  assert.equal(nextAccountPoolScheduleRefreshDelay(snapshot, 2_500), 7_500)
  assert.equal(nextAccountPoolScheduleRefreshDelay(snapshot, 10_000), 0)
  assert.equal(nextAccountPoolScheduleRefreshDelay(snapshot, 20_000), 0)
  assert.equal(nextAccountPoolScheduleRefreshDelay({ ...snapshot, statuses: [] }, 20_000), null)
})
