import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import test from 'node:test'

const readSource = (relativePath: string) => readFile(new URL(relativePath, import.meta.url), 'utf8')

test('account pool provider keys are collapsed by default and remain user-toggleable', async () => {
  const source = await readSource('../src/components/Main/PoolPanel.vue')

  assert.match(source, /const expandedAccountPoolKeys = ref<Set<string>>\(new Set\(\)\)/)
  assert.match(
    source,
    /const isAccountKeysCollapsed = \(poolID: string\): boolean => !expandedAccountPoolKeys\.value\.has\(poolID\)/,
  )

  const toggleStart = source.indexOf('const toggleAccountKeysCollapsed = (poolID: string) =>')
  const toggleEnd = source.indexOf('\n}', toggleStart) + 2
  const toggleHandler = source.slice(toggleStart, toggleEnd)
  assert.match(toggleHandler, /new Set\(expandedAccountPoolKeys\.value\)/)
  assert.match(toggleHandler, /next\.delete\(poolID\)/)
  assert.match(toggleHandler, /next\.add\(poolID\)/)
  assert.match(toggleHandler, /expandedAccountPoolKeys\.value = next/)
})

test('account pools are offered for both OpenAI Responses and OpenAI Chat', async () => {
  const source = await readSource('../src/components/Main/PoolPanel.vue')

  // A single platform predicate drives both the selector and the save payload,
  // so chat cannot silently fall back to a normal pool.
  assert.match(
    source,
    /const supportsAccountPool = \(platform: string\): boolean =>\s*\n\s*platform === 'openai-responses' \|\| platform === 'openai-chat'/,
  )
  assert.match(source, /v-if="supportsAccountPool\(props\.platform\)" class="form-field"/)
  assert.match(
    source,
    /const poolType: ProviderPoolType = supportsAccountPool\(props\.platform\)\s*\n\s*\? poolModalState\.form\.poolType\s*\n\s*: 'normal'/,
  )
})

test('account pool endpoint field follows the pool platform protocol', async () => {
  const source = await readSource('../src/components/Main/PoolPanel.vue')

  assert.match(
    source,
    /const defaultAccountPoolEndpoint = \(platform: string\): string =>\s*\n\s*isChatAccountPool\(platform\) \? '\/v1\/chat\/completions' : '\/responses'/,
  )
  assert.match(source, /v-model="poolModalState\.form\.accountEndpoint"/)
  assert.match(source, /readAccountPoolEndpoint\(pool\)/)
  // The save payload must send the platform's own wire field and clear the other.
  assert.match(source, /responsesEndpoint: isChatAccountPool\(props\.platform\) \? '' : accountEndpoint/)
  assert.match(source, /chatEndpoint: isChatAccountPool\(props\.platform\) \? accountEndpoint : ''/)
})

test('both account pool endpoint locales are declared', async () => {
  const zh = JSON.parse(await readSource('../src/locales/zh.json'))
  const en = JSON.parse(await readSource('../src/locales/en.json'))
  for (const locale of [zh, en]) {
    const pool = locale.components.main.pool
    assert.equal(typeof pool.responsesEndpoint, 'string')
    assert.equal(typeof pool.responsesEndpointPlaceholder, 'string')
    assert.equal(typeof pool.chatEndpoint, 'string')
    assert.equal(typeof pool.chatEndpointPlaceholder, 'string')
  }
})
