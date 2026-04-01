# Code Switch

> 用网页管理 Claude Code / Codex / Gemini CLI 的供应商、代理、MCP 和提示词

## 这是什么

**Code Switch** 现在是一个适合 Linux 服务器的 Web 管理界面 + 本地代理服务，不再依赖桌面窗口或显示器。

它解决的是这类问题：

- 你有多个 AI API 供应商，想统一配置和切换
- 某个供应商挂了，想自动降级到备用供应商
- 想统计请求量、Token、成本和日志
- 想集中管理 MCP、CLI 配置、自定义提示词

一句话总结：浏览器负责配置，后台进程负责代理，Claude Code / Codex / Gemini CLI 继续走本机代理完成请求转发。

## 当前运行方式

当前仓库已经改成 Web 模式，默认会启动两个监听地址：

| 组件 | 默认地址 | 作用 |
|------|----------|------|
| Web 管理界面 | `0.0.0.0:8080` | 浏览器访问的管理后台 |
| Provider Relay | `0.0.0.0:18100` | Claude Code / Codex / Gemini CLI 实际走的本机代理 |

数据默认写入：

- `~/.code-switch/app.db`
- `~/.code-switch/app.json`
- `~/.code-switch/claude-code.json`
- `~/.code-switch/codex.json`
- `~/.code-switch/codex-relay-keys.json`
- `~/.code-switch/mcp.json`
- `~/.code-switch/prompts.json`
- `~/.code-switch/proxy-state/`

注意：

- Web 管理界面可以通过 SSH 隧道或反向代理从远端浏览器访问
- `8080` 管理后台现在内置管理员账号密码登录、首次公网初始化 setup token、登录限流和同源校验
- 非本机来源直接用明文 HTTP 访问 `8080` 会被拒绝，公网访问应走 HTTPS 反向代理
- `18100` 上的 Codex API 现在只接受后台生成的 relay key
- 代理服务默认监听 `0.0.0.0:18100`
- 也就是说，Claude Code / Codex / Gemini CLI 应该运行在同一台服务器上

## Ubuntu 部署

下面的步骤已按当前机器验证：

- 系统：Ubuntu 24.04.3 LTS
- 仓库路径示例：`/home/chh/gitprojects/code-switch-R`
- Node.js：`v24.14.0`
- npm：`11.9.0`
- Go 构建环境：conda 环境 `code-switch-go-build-cgo`，`go1.26.1`

### 1. 准备构建环境

如果你已经有这个 conda 环境，直接激活即可：

```bash
conda activate code-switch-go-build-cgo
```

如果还没有，按当前机器的方式创建：

```bash
conda create -y -n code-switch-go-build-cgo -c conda-forge \
  'go=1.26.1' \
  'gcc_linux-64' \
  'gxx_linux-64'
conda activate code-switch-go-build-cgo
```

当前机器的 Node.js / npm 是系统里现成的。如果你的机器没有 Node.js，先安装一个可用版本，建议 `node >= 20`。

### 2. 构建前端

```bash
cd /home/chh/gitprojects/code-switch-R/frontend
npm install
npm run build
```

构建结果会输出到 `frontend/dist`。后端启动后会直接托管这个目录。

### 3. 构建后端

```bash
cd /home/chh/gitprojects/code-switch-R
conda activate code-switch-go-build-cgo
go build -o codeswitch-web .
```

### 4. 启动服务

```bash
cd /home/chh/gitprojects/code-switch-R
./codeswitch-web
```

正常启动后会看到类似日志：

```text
admin setup token (save it before first initialization): <generated-token>
web admin listening on http://0.0.0.0:8080
provider relay listening on http://0.0.0.0:18100
```

如果管理员账号已经初始化过，就不会再输出 `admin setup token`。

### 5. 验证服务

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

预期返回：

```json
{"ok":true}
```

浏览器访问：

- 本机访问：`http://127.0.0.1:8080`
- 远程机器访问：推荐 `https://<你的域名>`，由 Nginx / Caddy 反向代理到本机 `8080`
- 如果你不想直接暴露管理端，也可以继续用 SSH 隧道

SSH 隧道示例：

```bash
ssh -L 8080:127.0.0.1:8080 -L 18100:127.0.0.1:18100 your-user@your-server
```

## 作为守护进程运行

下面给一个 Ubuntu `systemd` 例子。路径按当前机器写，换机器时改成你的实际路径。

创建 `/etc/systemd/system/codeswitch.service`：

```ini
[Unit]
Description=Code Switch Web Service
After=network.target

[Service]
Type=simple
User=chh
WorkingDirectory=/home/chh/gitprojects/code-switch-R
Environment=CODE_SWITCH_WEB_ADDR=127.0.0.1:8080
Environment=CODE_SWITCH_SETUP_TOKEN=replace-with-a-long-random-token
ExecStart=/home/chh/gitprojects/code-switch-R/codeswitch-web
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

加载并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now codeswitch
```

查看日志：

```bash
sudo journalctl -u codeswitch -f
```

更新程序后的常见流程：

```bash
cd /home/chh/gitprojects/code-switch-R
git pull
cd frontend && npm install && npm run build
cd ..
conda activate code-switch-go-build-cgo
go build -o codeswitch-web .
sudo systemctl restart codeswitch
```

## 远程访问和安全建议

默认配置下，Web 管理界面监听 `0.0.0.0:8080`，但现在后台只接受两类访问：

1. 服务器本机直接访问
2. 经过受信反向代理转发的 HTTPS 访问

也就是说，把 `8080` 直接裸露到公网并用 `http://<公网IP>:8080` 打开，服务会返回 `403`，这是故意的安全策略，不是故障。

推荐公网部署方式：

1. `codeswitch-web` 监听本机：`127.0.0.1:8080`
2. Nginx / Caddy 对外监听 `443`
3. 反向代理把 HTTPS 请求转发到 `127.0.0.1:8080`
4. 第一次公网初始化时，在页面输入 setup token
5. `18100` 只对可信来源放行，或者也放到反向代理 / 网关后面

仓库里已经附了两份可直接改域名后使用的示例：

- Nginx: [deploy/nginx/code-switch.conf](/home/chh/gitprojects/code-switch-R/deploy/nginx/code-switch.conf)
- Caddy: [deploy/caddy/Caddyfile](/home/chh/gitprojects/code-switch-R/deploy/caddy/Caddyfile)

管理界面监听地址可以通过环境变量修改：

```bash
export CODE_SWITCH_WEB_ADDR=0.0.0.0:8080
```

首次公网初始化 token 可以显式指定：

```bash
export CODE_SWITCH_SETUP_TOKEN='change-this-to-a-long-random-token'
```

如果不设置，程序会在“管理员尚未初始化”时自动生成一次并打印到启动日志。

如果你的 HTTPS 反代不在同一台机器上，或者是 Docker / 容器网段转发，需要把代理地址加入受信列表，例如：

```bash
export CODE_SWITCH_TRUSTED_PROXIES='127.0.0.1/32,::1/128,172.18.0.0/16'
```

如果反向代理改写了 Host，而不是把原始域名转发给后端，再补一个公网 Origin：

```bash
export CODE_SWITCH_PUBLIC_ORIGIN='https://admin.example.com'
```

静态文件目录也可以改：

```bash
export CODE_SWITCH_STATIC_DIR=/your/path/to/frontend/dist
```

重要说明：

- 当前应用已经内置 `8080` 管理员登录鉴权、首次初始化 token、登录限流、服务端 session、`HttpOnly`/`SameSite=Strict` Cookie、同源校验和安全响应头
- 如果要对公网开放，推荐仍然是“本机监听 + HTTPS 反向代理”，而不是直接裸露 `8080`
- `18100` 是 CLI / API relay 端口，默认监听 `0.0.0.0:18100`
- `18100` 已经加了 Codex relay key 校验，但如果要直接暴露到公网，仍建议配合防火墙、反向代理、WAF 或来源限制
- Codex 相关接口现在必须使用后台生成的 relay key，不能再随便填任意密钥

### Nginx 示例

适合“同机部署”：

- `codeswitch-web` 监听 `127.0.0.1:8080`
- Nginx 监听公网 `443`
- 默认情况下，不需要额外设置 `CODE_SWITCH_TRUSTED_PROXIES`

示例文件见：[deploy/nginx/code-switch.conf](/home/chh/gitprojects/code-switch-R/deploy/nginx/code-switch.conf)

使用前你只需要改这几项：

1. `server_name admin.example.com`
2. `ssl_certificate`
3. `ssl_certificate_key`

如果你用的是 `certbot`，常见部署步骤类似：

```bash
sudo cp /home/chh/gitprojects/code-switch-R/deploy/nginx/code-switch.conf /etc/nginx/sites-available/code-switch.conf
sudo ln -sf /etc/nginx/sites-available/code-switch.conf /etc/nginx/sites-enabled/code-switch.conf
sudo nginx -t
sudo systemctl reload nginx
```

### Caddy 示例

Caddy 更省事，前提是：

- 你有一个域名
- 这个域名已经解析到当前服务器公网 IP
- 80/443 端口能从公网打到这台机器

示例文件见：[deploy/caddy/Caddyfile](/home/chh/gitprojects/code-switch-R/deploy/caddy/Caddyfile)

改完域名后常见启动方式类似：

```bash
sudo cp /home/chh/gitprojects/code-switch-R/deploy/caddy/Caddyfile /etc/caddy/Caddyfile
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl reload caddy
```

### 必须要域名吗

不是绝对必须，但如果你的目标是：

- 从公网浏览器稳定访问
- 浏览器不报证书不可信
- 用标准 HTTPS 保护管理员登录和 Cookie

那基本上应该有域名。

原因很简单：

- Nginx / Caddy 给浏览器做一张“被系统信任的 HTTPS 证书”时，最常见的方案就是给域名签证书
- 没域名时，你仍然可以给公网 IP 做反代，但通常只能用自签名证书，浏览器会报不安全
- 对管理员后台来说，这种体验和安全边界都不理想

如果你没有域名，实际可行的方案是这几个：

1. 最稳：继续走 SSH 隧道，只从本机浏览器访问 `127.0.0.1:8080`
2. 也可以：用 Tailscale / ZeroTier / WireGuard 之类的内网组网，再通过内网地址访问
3. 勉强可用：公网 IP + 自签名 HTTPS 反代，但不推荐当正式方案

如果你愿意上公网正式使用，我的建议是：

1. 准备一个域名，例如 `admin.example.com`
2. 把它解析到你的服务器
3. 用 Caddy 或 Nginx + Let's Encrypt
4. `codeswitch-web` 只监听 `127.0.0.1:8080`

## 如何使用

### 1. 本机上怎么开启服务

先构建前端，再构建并启动后端：

```bash
cd /home/chh/gitprojects/code-switch-R/frontend
npm install
npm run build

cd /home/chh/gitprojects/code-switch-R
go build -o codeswitch-web .
./codeswitch-web
```

启动后会同时提供：

- Web 管理后台：`http://0.0.0.0:8080`
- Provider Relay：`http://0.0.0.0:18100`

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

### 2. 远程怎么用

当前版本里，`8080` 和 `18100` 都默认对外监听。

如果你只是想远程打开网页后台，不要直接访问裸露的 `http://<服务器IP>:8080`。推荐两种方式：

1. SSH 隧道
2. `https://<你的域名>` 反向代理到 `127.0.0.1:8080`

如果你还想在本地电脑上把远程机器的 `18100` 映射成自己电脑上的本地端口，SSH 隧道仍然是最稳的方式。

如果服务跑在远程服务器，而你想在自己电脑上使用：

```bash
ssh -L 8080:127.0.0.1:8080 -L 18100:127.0.0.1:18100 your-user@your-server
```

隧道建立后：

- 本地浏览器访问 `http://127.0.0.1:8080`
- 本地脚本 / 客户端访问 `http://127.0.0.1:18100`

例如在本地测试 Codex relay：

```bash
curl http://127.0.0.1:18100/v1/models \
  -H "Authorization: Bearer csk_xxx"
```

### 3. 网页端怎么用

第一次打开网页后台：

1. 浏览器打开本机 `http://127.0.0.1:8080`，或远程 `https://<你的域名>`
2. 先创建管理员账号和密码
3. 如果这是第一次公网初始化，再填写启动日志里的 setup token
4. 创建成功后会自动登录

以后再次访问：

1. 打开本机 `http://127.0.0.1:8080`，或远程 `https://<你的域名>`
2. 输入管理员账号密码登录

### 4. 在网页里配置供应商

进入主界面后：

1. 点击右上角 `+`
2. 填写供应商名称、API URL、API Key
3. 按需配置模型支持和模型映射
4. 保存

推荐至少配置两个供应商，这样自动降级才有意义。

### 5. 在网页里打开对应 CLI 的代理

在主界面分别可以给这些目标打开代理：

- Claude Code
- Codex
- Gemini CLI
- 自定义 CLI

打开代理后，Code Switch 会把对应 CLI 的配置改为走本机代理 `127.0.0.1:18100`。

即使服务端实际监听的是 `0.0.0.0:18100`，写回本机 CLI 配置时仍会优先使用 `127.0.0.1:18100`，避免把 `0.0.0.0` 写进客户端配置导致连接异常。

如果后续要恢复原始直连配置，直接在页面里把对应代理关闭即可。

### 6. 生成 Codex relay key

如果你要把 `18100` 当作 Codex API 服务给脚本、客户端或远程隧道后的本地工具使用：

1. 打开 `设置`
2. 进入 `安全设置`
3. 点击 `生成 key`
4. 复制生成出来的 `csk_...` key

调用时可以放在这些头里：

- `Authorization: Bearer csk_xxx`
- `X-Code-Switch-Key: csk_xxx`
- `X-API-Key: csk_xxx`

示例：

```bash
curl http://127.0.0.1:18100/responses \
  -H "Authorization: Bearer csk_xxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5-codex","input":"hello"}'
```

如果你只是通过网页打开 Codex CLI 代理，程序会为本机 Codex 配置注入可用的 relay key，一般不需要手动再填一遍。

### 7. 重启 CLI

代理配置切换后，建议重启一次相关 CLI 进程，再发起新请求。

### 8. 在日志和统计页面确认生效

确认是否正常工作，最简单的方法是：

1. 在 Claude Code / Codex / Gemini CLI 里实际发起一次请求
2. 回到网页的日志页面查看是否出现新记录
3. 再看统计页里的请求量、Token 和成本是否增长

### 9. MCP、提示词和配置管理

网页里还可以继续做这些事情：

- 管理 MCP Server
- 管理自定义提示词
- 编辑 CLI 配置
- 做供应商测速
- 查看可用性检查和黑名单状态

## 工作原理

```text
浏览器
  ↓
Code Switch Web UI (:8080)
  ↓
Go 服务层 / 配置管理 / 日志 / 事件
  ↓
Provider Relay (:18100)
  ↓
实际 API 供应商
```

实际请求链路是这样的：

1. 你在网页里配置供应商和代理开关
2. Code Switch 修改本机 CLI 配置，让 Claude Code / Codex / Gemini CLI 指向本地代理
3. CLI 请求发到 `127.0.0.1:18100`
4. Relay 按优先级、模型映射和健康状态选择供应商
5. 成功时返回结果，失败时自动尝试下一个供应商

## Web 模式和原桌面版的区别

当前仓库已经不是“有托盘的桌面应用”形态，主要差异如下：

- 没有系统托盘常驻入口
- 没有桌面窗口和显示器依赖
- 自动启动入口在 Web 模式下不再作为主流程
- 更新操作会跳转到发布页，不做原生自动下载和重启
- 桌面原生通知默认不作为主要交互方式，页面事件和日志仍然可用

这正是它适合跑在 Linux 服务器上的原因。

## 界面预览

| 亮色主题 | 暗色主题 |
|---------|---------|
| ![亮色主界面](resources/images/code-switch.png) | ![暗色主界面](resources/images/code-swtich-dark.png) |
| ![日志亮色](resources/images/code-switch-logs.png) | ![日志暗色](resources/images/code-switch-logs-dark.png) |

## 常见问题

### 浏览器关掉后，代理还在吗？

只要 `codeswitch-web` 进程还在，代理就还在。浏览器只是管理界面，不是服务本体。

### 页面打不开，提示找不到前端资源

先确认你已经执行过：

```bash
cd frontend
npm install
npm run build
```

后端需要 `frontend/dist/index.html` 才能提供 Web UI。

### Claude Code / Codex / Gemini CLI 没走代理

按顺序检查：

1. 对应平台的代理开关是否已经打开
2. CLI 是否已经重启
3. `codeswitch-web` 进程是否还活着
4. `127.0.0.1:18100` 是否在监听
5. 供应商 API URL / API Key 是否正确

### 配置怎么备份

直接备份整个目录即可：

```bash
~/.code-switch/
```

## 开发说明

当前开发方式不再是 `wails3 task dev`。

前端构建：

```bash
cd frontend
npm install
npm run build
```

后端运行：

```bash
cd /home/chh/gitprojects/code-switch-R
conda activate code-switch-go-build-cgo
go run .
```

常用检查命令：

```bash
go build ./...
go test ./...
cd frontend && npm run build
```

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Go + Gin + SQLite |
| 前端 | Vue 3 + TypeScript + Vite |
| 通信 | HTTP RPC + SSE |
| 数据目录 | `~/.code-switch/` |

## 开源协议

MIT License

---

问题反馈：<https://github.com/Rogers-F/code-switch-R/issues>
