import assert from 'node:assert/strict'
import { readdir, readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import test from 'node:test'

// README 约定：data-testid 之间不能互为子串。
// ego 的 loc=testid:foo 是子串匹配，一旦互为子串就会命中多个元素而报错，
// 所以这里做全量守卫，新增 testid 时立刻能发现冲突。

const SRC_ROOT = fileURLToPath(new URL('../src', import.meta.url))

async function collectVueFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true })
  const files: string[] = []
  for (const entry of entries) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...(await collectVueFiles(full)))
    } else if (entry.name.endsWith('.vue')) {
      files.push(full)
    }
  }
  return files
}

test('no data-testid is a substring of another', async () => {
  const files = await collectVueFiles(SRC_ROOT)
  assert.ok(files.length > 0, '未找到任何 .vue 文件')

  const owners = new Map<string, string>()
  for (const file of files) {
    const source = await readFile(file, 'utf8')
    // 只检查静态 testid；动态绑定的值无法在构建期穷举
    for (const match of source.matchAll(/(?:data-testid|test-id)="([^"{}]+)"/g)) {
      const id = match[1]
      if (id.includes('$') || id.includes(':')) continue
      if (owners.has(id)) continue
      owners.set(id, path.relative(SRC_ROOT, file))
    }
  }

  const ids = [...owners.keys()].sort()
  assert.ok(ids.length > 100, `收集到的 testid 太少（${ids.length}），解析可能失效`)

  const collisions: string[] = []
  for (const outer of ids) {
    for (const inner of ids) {
      if (outer === inner) continue
      if (outer.includes(inner)) {
        collisions.push(`${inner} (${owners.get(inner)}) 是 ${outer} (${owners.get(outer)}) 的子串`)
      }
    }
  }

  assert.deepEqual(collisions, [], `testid 互为子串会让 loc=testid: 匹配到多个元素:\n${collisions.join('\n')}`)
})
