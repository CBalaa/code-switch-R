// Mock Anthropic 上游（流式 SSE）：分片吐出一条真实指纹回答，
// 用于验证"实时生成片段"事件链路。
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'

const goldenPath = process.env.MT_GOLDEN
if (!goldenPath) {
  console.error('[mock-stream] 需要 MT_GOLDEN 指向 services/modeltrace/testdata/golden.json')
  process.exit(1)
}
const port = Number(process.env.MT_MOCK_PORT || 18888)

const golden = JSON.parse(readFileSync(goldenPath, 'utf8'))
const answerText = golden[0].outputs[0].text

const server = createServer((req, res) => {
  let body = ''
  req.on('data', (chunk) => { body += chunk })
  req.on('end', () => {
    console.log(`[mock-stream] ${req.method} ${req.url} stream=${body.includes('"stream":true')}`)
    if (!req.url.includes('/v1/messages')) {
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end('{}')
      return
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
    })
    const chunkSize = 30
    let offset = 0
    const timer = setInterval(() => {
      if (offset >= answerText.length) {
        clearInterval(timer)
        res.write('event: message_delta\ndata: {"type":"message_delta","delta":{},"stop_reason":"end_turn"}\n\n')
        res.write('event: message_stop\ndata: {"type":"message_stop"}\n\n')
        res.end()
        return
      }
      const piece = answerText.slice(offset, offset + chunkSize)
      offset += chunkSize
      const payload = { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: piece } }
      res.write(`event: content_block_delta\ndata: ${JSON.stringify(payload)}\n\n`)
    }, 200)
  })
})
server.listen(port, '127.0.0.1', () => console.log(`[mock-stream] listening on ${port}`))
