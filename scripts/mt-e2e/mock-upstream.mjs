// Mock Anthropic 上游：延迟后返回一条真实指纹回答（取自 golden.json 的 gpt-5.4 用例）。
// 用于无额度跑通"模型真伪检测"整条链路。
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'

const goldenPath = process.env.MT_GOLDEN
if (!goldenPath) {
  console.error('[mock] 需要 MT_GOLDEN 指向 services/modeltrace/testdata/golden.json')
  process.exit(1)
}
const port = Number(process.env.MT_MOCK_PORT || 18888)
const delayMs = Number(process.env.MT_MOCK_DELAY_MS || 3000)

const golden = JSON.parse(readFileSync(goldenPath, 'utf8'))
const answerText = golden[0].outputs[0].text

const server = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => {
    console.log(`[mock] ${req.method} ${req.url}`)
    if (!req.url.includes('/v1/messages')) {
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end('{}')
      return
    }
    setTimeout(() => {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end(JSON.stringify({
        id: 'msg_mock',
        type: 'message',
        role: 'assistant',
        model: 'mock',
        content: [{ type: 'text', text: answerText }],
        stop_reason: 'end_turn',
      }))
      console.log('[mock] replied with', answerText.length, 'chars')
    }, delayMs)
  })
})
server.listen(port, '127.0.0.1', () => console.log(`[mock] listening on ${port}`))
