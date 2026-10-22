import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const readSource = (relativePath: string) => readFile(new URL(relativePath, import.meta.url), 'utf8')

test('Costs only queries request_log usage from the explicit query handler', async () => {
  const source = await readSource('../src/components/Costs/Index.vue')

  assert.doesNotMatch(source, /setInterval\s*\(/)
  assert.doesNotMatch(source, /visibilitychange/)
  assert.match(source, /const runCostQuery = async \(\) =>/)

  const queryHandlerStart = source.indexOf('const runCostQuery = async () =>')
  const nextFunctionStart = source.indexOf('\nconst ', queryHandlerStart + 1)
  const queryHandler = source.slice(queryHandlerStart, nextFunctionStart)
  assert.match(queryHandler, /fetchTodayCostUsage\(/)

  const withoutImport = source.replace(/fetchTodayCostUsage,\s*/, '')
  assert.equal((withoutImport.match(/fetchTodayCostUsage\(/g) ?? []).length, 1)
})

test('Logs keeps provider filters removed and refreshes usage stats only from bounded triggers', async () => {
  const source = await readSource('../src/components/Logs/Index.vue')

  assert.doesNotMatch(source, /fetchLogProviders|ListProviders/)
  assert.doesNotMatch(source, /filters\.platform|filters\.provider|components\.logs\.query/)
  assert.match(source, /fetchLogStats\(''\)/)
  assert.match(source, /<section class="logs-summary"/)
  assert.match(source, /<section class="logs-chart"/)
  assert.match(source, /fetchActiveRequestLogs\(/)
  assert.match(source, /fetchCompletedRequestLogs\(/)

  const initialLoadStart = source.indexOf('const loadInitialLogs = async () =>')
  const initialLoadEnd = source.indexOf('\nconst refreshLogSnapshot =', initialLoadStart)
  assert.match(source.slice(initialLoadStart, initialLoadEnd), /loadStats\(\)/)

  const refreshStart = source.indexOf('const refreshLogs = (): Promise<boolean> =>')
  const refreshEnd = source.indexOf('\nconst pagedLogs =', refreshStart)
  const refreshHandler = source.slice(refreshStart, refreshEnd)
  assert.match(refreshHandler, /statsNeedRefresh = snapshotFoundNew \|\| statsNeedRefresh/)
  assert.match(refreshHandler, /await loadStats\(\)/)

  const manualStart = source.indexOf('const manualRefresh = () =>')
  const manualEnd = source.indexOf('\nconst nextPage =', manualStart)
  const manualHandler = source.slice(manualStart, manualEnd)
  assert.match(manualHandler, /const foundNewCompleted = await refreshLogs\(\)/)
  assert.match(manualHandler, /if \(!foundNewCompleted\)/)
  assert.match(manualHandler, /await loadStats\(\)/)

  const timerStart = source.indexOf('const startLogAutoRefresh = () =>')
  const timerEnd = source.indexOf('\nconst stopLogAutoRefresh =', timerStart)
  assert.doesNotMatch(source.slice(timerStart, timerEnd), /loadStats\(/)
})

test('Logs keeps a raw 105-row completed window before display filtering', async () => {
  const source = await readSource('../src/components/Logs/Index.vue')
  const refreshStart = source.indexOf('const refreshLogSnapshot = async () =>')
  const refreshEnd = source.indexOf('\nconst refreshLogs =', refreshStart)
  const refreshSnapshot = source.slice(refreshStart, refreshEnd)

  assert.match(refreshSnapshot, /lastSeenCompletedID = Math\.max\(/)
  assert.match(refreshSnapshot, /mergeCompletedRequestLogs\(completedLogs\.value, incomingCompleted\)/)
  assert.doesNotMatch(refreshSnapshot, /visibleRequestLogs\(/)
  assert.match(source, /const visibleCompletedLogs = computed\(\(\) => visibleRequestLogs\(completedLogs\.value\)\)/)
  assert.match(source, /visibleCompletedLogs\.value\.slice\(start, start \+ PAGE_SIZE\)/)
})

test('Claude provider creation defaults the test model to Claude Opus 4.8', async () => {
  const source = await readSource('../src/components/Main/Index.vue')

  // 函数已从单行三元表达式演进为按平台返回；这里改为截取函数体做语义断言。
  const defaultTestModelStart = source.indexOf('const getDefaultTestModel = (platform: ProviderTab) =>')
  assert.notEqual(defaultTestModelStart, -1)
  const defaultTestModelEnd = source.indexOf('\nconst ', defaultTestModelStart + 1)
  const defaultTestModelSource = source.slice(defaultTestModelStart, defaultTestModelEnd)
  assert.match(defaultTestModelSource, /if \(platform === 'claude'\) return 'claude-opus-4-8'/)
  assert.match(defaultTestModelSource, /if \(platform === 'openai-images'\) return 'gpt-image-2'/)

  const createStart = source.indexOf('const openCreateModal = () =>')
  const createEnd = source.indexOf('\nconst openEditModal =', createStart)
  const createHandler = source.slice(createStart, createEnd)
  assert.match(createHandler, /providerTestModel\.value = getDefaultTestModel\(activeTab\.value\)/)
})

test('Main exposes the supported provider platforms', async () => {
  const source = await readSource('../src/components/Main/Index.vue')

  assert.match(source, /\{ id: 'claude', label: 'Claude Code' \}/)
  assert.match(source, /\{ id: 'openai-responses', label: 'OpenAI Responses' \}/)
  assert.match(source, /\{ id: 'openai-chat', label: 'OpenAI Chat' \}/)
  assert.match(source, /\{ id: 'openai-images', label: 'OpenAI Images' \}/)
  assert.doesNotMatch(source, /\{ id: 'others'/)
  assert.doesNotMatch(source, /CustomCliConfigEditor|customCliService|components\.main\.customCli/)
})
