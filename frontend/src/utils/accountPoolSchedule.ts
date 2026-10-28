import type {
  AccountPoolSchedule,
  AccountPoolScheduleStatuses,
  AccountPoolScheduleWindow,
} from '../services/providerPool'

export const ACCOUNT_POOL_WEEKDAYS = [1, 2, 3, 4, 5, 6, 7] as const
export type AccountPoolScheduleError = 'weekday' | 'time' | 'overnight' | 'empty'

/** Clone form data so editing never mutates the saved pool or copied weekdays. */
export function accountPoolScheduleForm(schedule?: AccountPoolSchedule): AccountPoolSchedule {
  return {
    enabled: schedule?.enabled === true,
    windows: (schedule?.windows ?? []).map((window) => ({ ...window })),
  }
}

/** Explicit validation also covers closing the editor, which bypasses HTML constraints. */
export function buildAccountPoolSchedulePayload(schedule: AccountPoolSchedule): {
  schedule: AccountPoolSchedule
  error: AccountPoolScheduleError | null
} {
  const windows: AccountPoolScheduleWindow[] = []
  const fail = (error: AccountPoolScheduleError) => ({ schedule: accountPoolScheduleForm(schedule), error })
  for (const window of schedule.windows) {
    if (!Number.isInteger(window.weekday) || window.weekday < 1 || window.weekday > 7) return fail('weekday')
    const startTime = window.startTime.trim()
    const endTime = window.endTime.trim()
    const timePattern = /^([01]\d|2[0-3]):[0-5]\d$/
    if (!timePattern.test(startTime) || !timePattern.test(endTime)) return fail('time')
    if (startTime > endTime) return fail('overnight')
    windows.push({ weekday: window.weekday, startTime, endTime })
  }
  if (schedule.enabled && windows.length === 0) return fail('empty')
  windows.sort((a, b) => a.weekday - b.weekday || a.startTime.localeCompare(b.startTime) || a.endTime.localeCompare(b.endTime))
  return { schedule: { enabled: schedule.enabled, windows }, error: null }
}

/** Copy explicitly replaces the selected days, while keeping the source independent. */
export function copyAccountPoolScheduleDay(
  schedule: AccountPoolSchedule,
  sourceWeekday: number,
  targetWeekdays: number[],
): AccountPoolSchedule {
  const targets = new Set(targetWeekdays.filter((day) => Number.isInteger(day) && day >= 1 && day <= 7 && day !== sourceWeekday))
  const next = accountPoolScheduleForm(schedule)
  const source = next.windows.filter((window) => window.weekday === sourceWeekday)
  next.windows = next.windows.filter((window) => !targets.has(window.weekday))
  for (const weekday of targets) {
    next.windows.push(...source.map((window) => ({ ...window, weekday })))
  }
  return next
}

/** Missing legacy schedules and explicit disabled empty schedules have the same signature. */
export function accountPoolScheduleSignature(schedule?: AccountPoolSchedule): string {
  const form = accountPoolScheduleForm(schedule)
  return JSON.stringify(buildAccountPoolSchedulePayload(form).schedule)
}

/** Subtract the full request duration conservatively, using a monotonic client timer. */
export function nextAccountPoolScheduleRefreshDelay(snapshot: AccountPoolScheduleStatuses, requestElapsedMs = 0): number | null {
  const serverNow = Date.parse(snapshot.serverNow)
  if (!Number.isFinite(serverNow)) return null
  const changes = snapshot.statuses
    .map((status) => Date.parse(status.nextChangeAt ?? ''))
    .filter((time) => Number.isFinite(time) && time > serverNow)
  return changes.length ? Math.max(0, Math.min(...changes) - serverNow - Math.max(0, requestElapsedMs)) : null
}
