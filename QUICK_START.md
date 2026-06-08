# 模型白名单与映射功能快速上手指南

## 🚀 5分钟快速启动

### Step 1: 启动应用

```bash
cd G:\claude-lit\cc-r
wails3 task dev
```

### Step 2: 配置示例（手动编辑 JSON）

打开配置文件：`~/.code-switch/claude-code.json`

```json
{
  "providers": [
    {
      "id": 1,
      "name": "Anthropic Official",
      "apiUrl": "https://api.anthropic.com",
      "apiKey": "你的真实密钥",
      "enabled": true,
      "supportedModels": {
        "claude-3-5-sonnet-20241022": true,
        "claude-sonnet-4-5-20250929": true
      }
    },
    {
      "id": 2,
      "name": "OpenRouter",
      "apiUrl": "https://openrouter.ai/api",
      "apiKey": "你的真实密钥",
      "enabled": true,
      "supportedModels": {
        "anthropic/claude-*": true,
        "openai/gpt-*": true
      },
      "modelMapping": {
        "claude-*": "anthropic/claude-*",
        "gpt-*": "openai/gpt-*"
      }
    }
  ]
}
```

### Step 3: 重启应用观察日志

```bash
# 查看启动日志
======== Provider 配置验证警告 ========
[INFO] [claude/Anthropic Official] 配置有效
[INFO] [claude/OpenRouter] 配置有效，支持通配符映射
========================================
provider relay server listening on :18100
```

### Step 4: 测试降级场景

#### 场景 1：正常请求
```bash
# Claude Code 请求
请求: {"model": "claude-sonnet-4-5-20250929", ...}
→ [INFO] Provider Anthropic Official 支持该模型
→ [INFO] ✓ 成功: Anthropic Official
```

#### 场景 2：降级成功（关键测试）
```bash
# 手动停用 Provider 1 或模拟失败
请求: {"model": "claude-sonnet-4", ...}
→ [WARN] ✗ 失败: Anthropic Official - timeout
→ [INFO] Provider OpenRouter 映射模型: claude-sonnet-4 -> anthropic/claude-sonnet-4
→ [INFO] [2/2] 尝试 provider: OpenRouter (model: anthropic/claude-sonnet-4)
→ [INFO] ✓ 成功: OpenRouter
```

### Step 5: 验证功能

打开 Claude Code / Codex，正常使用，观察：
- ✅ 降级时没有报错
- ✅ 日志显示正确的模型映射
- ✅ 请求成功完成

---

## 📝 配置模板速查

### 模板 1：Anthropic Official（精确匹配）
```json
{
  "id": 1,
  "name": "Anthropic",
  "apiUrl": "https://api.anthropic.com",
  "apiKey": "sk-ant-xxx",
  "enabled": true,
  "supportedModels": {
    "claude-3-5-sonnet-20241022": true,
    "claude-sonnet-4-5-20250929": true
  }
}
```

### 模板 2：OpenRouter（通配符推荐）
```json
{
  "id": 2,
  "name": "OpenRouter",
  "apiUrl": "https://openrouter.ai/api",
  "apiKey": "sk-or-xxx",
  "enabled": true,
  "supportedModels": {
    "anthropic/claude-*": true,
    "openai/gpt-*": true
  },
  "modelMapping": {
    "claude-*": "anthropic/claude-*",
    "gpt-*": "openai/gpt-*"
  }
}
```

### 模板 3：自定义中转（混合模式）
```json
{
  "id": 3,
  "name": "Custom Relay",
  "apiUrl": "https://api.custom.com",
  "apiKey": "sk-xxx",
  "enabled": true,
  "supportedModels": {
    "native-model-a": true,
    "vendor/mapped-model": true
  },
  "modelMapping": {
    "mapped-model": "vendor/mapped-model"
  }
}
```

---

## 🐛 故障排查

### 问题 1：启动时警告 "未配置 supportedModels"
**原因**：旧配置未添加模型白名单
**影响**：功能仍可用，但降级时可能失败
**解决**：为该 provider 添加 `supportedModels` 字段

### 问题 2：降级失败 "不支持模型 xxx"
**原因**：所有 provider 都不支持请求的模型
**解决**：
1. 检查模型名是否正确
2. 为至少一个 provider 配置该模型的支持
3. 使用通配符模式（如 `claude-*`）

### 问题 3：保存配置报错 "映射无效"
**原因**：`modelMapping` 的目标模型不在 `supportedModels` 中
**解决**：
```json
// ❌ 错误
{
  "supportedModels": {"model-a": true},
  "modelMapping": {"external": "model-b"}  // model-b 不存在
}

// ✅ 正确
{
  "supportedModels": {"model-a": true, "model-b": true},
  "modelMapping": {"external": "model-b"}
}
```

---

## 💡 最佳实践

1. **优先使用通配符**：
   ```json
   "supportedModels": {"anthropic/claude-*": true}
   "modelMapping": {"claude-*": "anthropic/claude-*"}
   ```
   - ✅ 配置简洁
   - ✅ 支持未来新模型
   - ✅ 维护成本低

2. **分层配置**：
   - 主力 provider：精确模型列表
   - 备用 provider：通配符模式

3. **定期检查日志**：
   ```bash
   # 查找配置警告
   grep "配置验证" logs.txt

   # 查找降级事件
   grep "映射模型" logs.txt
   ```

---

## 🎓 进阶使用

### 技巧 1：多区域降级
```json
[
  {
    "id": 1,
    "name": "Anthropic US",
    "apiUrl": "https://api.anthropic.com",
    "enabled": true
  },
  {
    "id": 2,
    "name": "Anthropic EU (via Proxy)",
    "apiUrl": "https://eu.proxy.com",
    "enabled": true,
    "modelMapping": {
      "claude-*": "anthropic/claude-*"
    }
  }
]
```

---

## 📚 相关文档

- 完整配置指南：`CLAUDE.md` 第 454-778 行
- 测试文档：`services/TEST_README.md`
- 配置示例：`services/testdata/example-claude-config.json`
