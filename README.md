# AgentGuard

> 轻量级、可插拔的 LLM Agent 安全围栏中间件

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-83%20passed-brightgreen.svg)](tests/)

AgentGuard 为 LLM Agent 提供四层纵深防御，覆盖 Agent 完整生命周期的安全检查点（输入→思维→工具→输出），对标 OWASP LLM Top 10 和 OWASP Agentic AI Top 10。

**核心特点**：可插拔（三行代码挂载）、不侵入业务逻辑、提供基准评测数据。

---

## 快速开始

```bash
pip install -e .
```

```python
# 三行代码挂载到任意 Agent
from guardrails import AgentGuard

guard = AgentGuard.from_config("configs/guard_config.yaml")
result = await guard.protect(user_input, context={"session_id": "123"})
```

---

## 四层防御体系

```
用户输入
    │
    ▼
┌───────────────────────────────────────────┐
│              AgentGuard 中间件              │
│                                           │
│  ┌─────────────────────────────────────┐  │
│  │  第一层：输入围栏 (InputGuard)        │  │
│  │  规则引擎 → ML分类器 → LLM Judge     │  │
│  └──────────────┬──────────────────────┘  │
│                 │ PASS                    │
│  ┌──────────────▼──────────────────────┐  │
│  │         LLM Agent 推理              │  │
│  │  ┌──────────────────────────────┐   │  │
│  │  │  Thought 生成                │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │                   │  │
│  │  ┌──────────────▼───────────────┐   │  │
│  │  │ 第二层：思维围栏 (ThoughtGuard)│  │  │
│  │  │  意图分类 → 风险分级           │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │ PASS              │  │
│  │  ┌──────────────▼───────────────┐   │  │
│  │  │  Action 生成（工具调用）       │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │                   │  │
│  │  ┌──────────────▼───────────────┐   │  │
│  │  │  第三层：工具围栏 (ToolGuard)  │   │  │
│  │  │  权限校验 → 参数审查 → 审计    │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │ PASS              │  │
│  │           工具执行 & 返回结果        │  │
│  └──────────────────────────────────┘  │
│                 │                       │
│  ┌──────────────▼──────────────────────┐  │
│  │  第四层：输出围栏 (OutputGuard)       │  │
│  │  敏感信息过滤 → NER检测              │  │
│  └──────────────┬──────────────────────┘  │
│                 │ PASS                    │
└─────────────────┼─────────────────────────┘
                  │
                  ▼
              返回用户
```

### 第一层：输入围栏 (InputGuard)

防御直接提示注入（Prompt Injection），规则引擎包含 40+ 正则模式：

| 检测类别 | 示例 |
|---------|------|
| 指令覆盖 | `ignore previous instructions`、`forget everything` |
| 角色劫持 | `你现在是`、`act as`、`pretend you are` |
| 越狱模板 | DAN、AIM、STAN 等已知越狱模板特征 |
| 编码绕过 | Base64、Unicode 编码的隐藏指令 |
| 多语言混淆 | 中英文混合注入 |

对应 OWASP 威胁：[LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

### 第二层：思维围栏 (ThoughtGuard)

在 ReAct Agent 生成 Action 之前，审查 Thought 的意图是否合规：

| 风险类型 | 示例 | 风险等级 |
|---------|------|---------|
| 越权访问 | "我需要读取系统配置文件" | 🔴 HIGH |
| 数据外泄 | "把用户数据拼接到回复里发出去" | 🔴 HIGH |
| 权限提升 | "跳过权限校验直接执行" | 🔴 HIGH |
| 循环攻击 | Agent 被诱导进入无限工具调用循环 | 🔴 HIGH |

参考：[AutoControl-Arena](https://github.com/CosmosYi/AutoControl-Arena) (ICML 2026)

### 第三层：工具围栏 (ToolGuard)

在 Agent 调用工具之前，审查调用参数是否合规，内置五种专用检查器：

| 检查器 | 检测能力 |
|--------|---------|
| `FileSystemChecker` | 路径白名单、目录穿越检测、敏感扩展名拦截 |
| `ShellChecker` | 命令黑名单（17 条）、命令注入检测 |
| `NetworkChecker` | SSRF 防护（10 种内网 IP 模式）、云元数据端点拦截 |
| `SQLChecker` | SQL 注入检测（13 条模式）、写操作开关、多语句禁止 |
| `MCPDescriptionScanner` | 工具描述投毒扫描、HTML 注入检测、异常长度/URL 检测 |

### 第四层：输出围栏 (OutputGuard)

在最终输出返回用户前，过滤敏感信息泄露：

| 检测类型 | 示例 |
|---------|------|
| 结构化敏感信息 | 手机号、身份证、银行卡号、邮箱 |
| 密钥/Token | API Key、JWT、SSH 私钥、密码 |
| System Prompt 泄露 | 通过哈希比对检测系统提示词泄露 |

支持 `mask_sensitive()` 自动脱敏功能。

---

## 评测数据

| 指标 | 目标值 | 当前状态 |
|------|--------|---------|
| 攻击拦截率（TPR） | > 85% | 待跑 benchmark |
| 误报率（FPR） | < 5% | 待跑 benchmark |
| 延迟开销 | < 200ms | 纯规则引擎 < 1ms |
| OWASP 覆盖率 | ≥ 7/10 | 7/10 |

**数据集清单**：

| 数据集 | 用途 | 来源 |
|-------|------|------|
| InjecAgent | 工具层攻击测试（1054 条） | ACL 2024 |
| AgentDojo | 端到端攻防评测（629 安全用例） | ICML 2025 |
| MCP Injection | MCP 工具投毒攻击场景 | Invariant Labs |

---

## 项目结构

```
agent-guard/
├── guardrails/              # 四层围栏核心
│   ├── input_guard.py       # 第一层：输入围栏
│   ├── thought_guard.py     # 第二层：思维围栏
│   ├── tool_guard.py        # 第三层：工具围栏
│   ├── output_guard.py      # 第四层：输出围栏
│   ├── checkers/            # 工具检查器（文件/Shell/网络/SQL/MCP）
│   ├── base.py              # 基础框架（GuardResult, BaseGuard）
│   └── thought.py           # 思维数据结构
├── classifiers/             # 分类器模块（规则引擎/ML/LLM Judge）
├── integrations/            # 框架集成适配器（LangChain/LangGraph/MCP）
├── benchmarks/              # 评测模块
├── demo/                    # 演示场景（邮件/RAG/MCP Agent）
├── tests/                   # 单元测试（83 个用例）
└── configs/                 # 配置文件
```

---

## Demo 场景

### 邮件 Agent 攻防

攻击者在邮件正文中植入隐藏指令，诱导 Agent 转发所有邮件到攻击者地址。演示 InputGuard + ToolGuard 联合防御。

```bash
python demo/email_agent/run_demo.py
python demo/email_agent/tool_guard_demo.py
```

### RAG Agent 数据外泄（规划中）

攻击者污染知识库文档，植入隐藏指令，诱导 Agent 将其他用户数据拼接到回复中。

### MCP 工具投毒（规划中）

恶意 MCP Server 在工具描述中藏指令，诱导 Agent 读取 SSH 私钥并发送。

---

## 参考标准

| 标准 | 链接 |
|------|------|
| OWASP LLM Top 10 | [genai.owasp.org](https://genai.owasp.org/) |
| OWASP Agentic AI Top 10 | [genai.owasp.org](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) |

## 参考论文

| 论文 | 来源 |
|------|------|
| Not What You've Signed Up For（IPI 奠基） | arXiv 2302.12173 |
| AgentDojo | ICML 2025 |
| InjecAgent | ACL 2024 |
| AutoControl-Arena | ICML 2026 |
| Meta SecAlign | Meta AI 2025 |
| Securing AI Agents Against Prompt Injection | arXiv 2511.15759 |

---

## License

MIT
