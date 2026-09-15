import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const readSource = (relativePath: string) => readFile(new URL(relativePath, import.meta.url), 'utf8')

const MODAL = '../src/components/Main/ModelTraceModal.vue'
const PANEL = '../src/components/Main/PoolPanel.vue'
const INDEX = '../src/components/Main/Index.vue'
const SERVICE = '../src/services/modeltrace.ts'

// ===== 后端契约 =====

test('model trace RPC targets the user-scoped ModelTraceService', async () => {
  const source = await readSource(SERVICE)

  assert.match(source, /const SERVICE = 'codeswitch\/services\.ModelTraceService'/)
  assert.match(source, /Call\.ByName\(`\$\{SERVICE\}\.GetSupportedModels`\)/)
  assert.match(source, /Call\.ByName\(`\$\{SERVICE\}\.VerifyProviderModel`, platform, providerId, expectedModel\)/)
  // userID 由服务端从登录态解析，前端不得自行指定
  assert.doesNotMatch(source, /userId|userID/)
})

test('progress and stream subscriptions listen on the backend event names', async () => {
  const source = await readSource(SERVICE)

  assert.match(source, /Events\.On\('modeltrace:progress'/)
  assert.match(source, /Events\.On\('modeltrace:stream'/)
})

// ===== 组件接线 =====

test('provider cards expose a model trace action wired through PoolPanel', async () => {
  const panel = await readSource(PANEL)

  assert.match(panel, /modelTrace: \[card: AutomationCard\]/)
  assert.match(panel, /\$emit\('modelTrace', card\)/)
  // 按钮必须带可访问名，否则 ego/读屏都定位不到
  assert.match(
    panel,
    /:aria-label="t\('components\.main\.modelTrace\.tooltip'\)"[\s\S]{0,200}data-testid="provider-modeltrace"[\s\S]{0,200}@click\.stop="\$emit\('modelTrace', card\)"/,
  )
})

test('Index passes the active protocol tab to the model trace modal', async () => {
  const source = await readSource(INDEX)

  assert.match(source, /@model-trace="openModelTrace"/)
  assert.match(source, /import ModelTraceModal from '\.\/ModelTraceModal\.vue'/)
  // 平台即协议：必须用当前标签页，不能写死
  assert.match(source, /modelTraceState\.platform = activeTab\.value/)
  assert.match(source, /:platform="modelTraceState\.platform"/)
})

// ===== 无障碍 / 自动化约定 =====

test('model trace modal exposes stable test hooks', async () => {
  const source = await readSource(MODAL)

  for (const testId of [
    'modeltrace-modal',
    'modeltrace-models',
    'modeltrace-model-chip',
    'modeltrace-verify',
    'modeltrace-progress',
    'modeltrace-stream',
    'modeltrace-result',
    'modeltrace-verdict',
    'modeltrace-error-message',
    'modeltrace-bars',
    'modeltrace-meta',
    'modeltrace-retry',
    'modeltrace-close',
  ]) {
    assert.ok(
      source.includes(`data-testid="${testId}"`) || source.includes(`test-id="${testId}"`),
      `缺少 data-testid="${testId}"`,
    )
  }
})

test('model trace modal keeps controls accessible', async () => {
  const source = await readSource(MODAL)

  // 单选模型：按钮组 + aria-pressed，读屏与 ego 都能读到选中态
  assert.match(source, /role="group"/)
  assert.match(source, /:aria-pressed="selectedModel === model\.id"/)
  // 进度与结果用 live region 播报，纯装饰元素不进无障碍树
  assert.match(source, /role="status"[\s\S]{0,120}aria-live="polite"/)
  assert.match(source, /class="stream-box" aria-live="off"/)
  assert.match(source, /class="bar-track" aria-hidden="true"/)
  assert.match(source, /class="verdict-icon" aria-hidden="true"/)
  // 每个可点元素都要有可访问名（文本或 aria-label）
  assert.doesNotMatch(source, /<button(?![^>]*aria-label)(?![^>]*aria-pressed)[^>]*>\s*<svg/)
})

// ===== i18n =====

const loadLocale = async (name: string) =>
  JSON.parse(await readSource(`../src/locales/${name}.json`)) as Record<string, any>

test('every model trace string exists in both locales', async () => {
  const modal = await readSource(MODAL)
  const service = await readSource(SERVICE)
  const keys = new Set<string>()
  for (const source of [modal, service]) {
    for (const match of source.matchAll(/components\.main\.modelTrace\.([A-Za-z0-9_]+)/g)) {
      keys.add(match[1])
    }
  }
  assert.ok(keys.size > 0, '未在组件中解析到任何 modelTrace i18n key')

  for (const locale of ['zh', 'en']) {
    const bundle = await loadLocale(locale)
    const block = bundle?.components?.main?.modelTrace
    assert.ok(block, `${locale}.json 缺少 components.main.modelTrace`)
    for (const key of keys) {
      assert.equal(typeof block[key], 'string', `${locale}.json 缺少 modelTrace.${key}`)
      assert.ok(block[key].length > 0, `${locale}.json 的 modelTrace.${key} 为空`)
    }
  }
})

test('model trace interpolation placeholders match across locales', async () => {
  const placeholders = (value: string) =>
    [...value.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((match) => match[1]).sort()

  const [zh, en] = await Promise.all([loadLocale('zh'), loadLocale('en')])
  const zhBlock = zh.components.main.modelTrace as Record<string, string>
  const enBlock = en.components.main.modelTrace as Record<string, string>

  for (const key of Object.keys(zhBlock)) {
    assert.deepEqual(
      placeholders(zhBlock[key]),
      placeholders(enBlock[key]),
      `modelTrace.${key} 的插值占位符在 zh/en 之间不一致`,
    )
  }
})
