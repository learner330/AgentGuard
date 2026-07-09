# AgentGuard

> 轻量级、可插拔的 LLM Agent 安全围栏中间件

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)]()

AgentGuard 为 LLM Agent 提供三层纵深防御，覆盖 Agent 完整生命周期的安全检查点（输入→工具→输出），对标 OWASP LLM Top 10 和 OWASP Agentic AI Top 10。

**核心特点**：可插拔（三行代码挂载）、不侵入业务逻辑、提供基准评测数据。

---

## 一键测试（推荐）

运行全部测试、MCP 攻击复现，并生成可视化 HTML 报告：

**macOS / Linux:**

```bash
bash scripts/run_demo.sh
```

**Windows:**

```cmd
scripts\run_demo.bat
```

脚本会自动完成：检查 Python 环境 → 创建虚拟环境 → 安装依赖 → 检查 Ollama（可选）→ 运行 67 个单元测试 → 执行三种 MCP 攻击场景（无防护 vs 有防护对比）→ 运行 Benchmark（87.5% 准确率）→ 生成可视化 HTML 报告并在浏览器中打开。

参数选项：

- `--no-mcp` — 跳过 MCP 攻击复现（无需 Ollama），仅运行单元测试和 Benchmark
- `--model <name>` — 指定 Ollama 模型（默认 qwen2.5:3b）
- `--help` — 显示帮助信息

---

## 手动安装与使用

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

## 三层防御体系

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
│  │  │  Thought → Action 生成        │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │                   │  │
│  │  ┌──────────────▼───────────────┐   │  │
│  │  │  第二层：工具围栏 (ToolGuard)  │   │  │
│  │  │  参数审查 → 循环检测 → 审计    │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │ PASS              │  │
│  │           工具执行 & 返回结果        │  │
│  └──────────────────────────────────┘  │
│                 │                       │
│  ┌──────────────▼──────────────────────┐  │
│  │  第三层：输出围栏 (OutputGuard)       │  │
│  │  敏感信息过滤 → 脱敏处理             │  │
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

### 第二层：工具围栏 (ToolGuard)

在 Agent 调用工具之前，审查调用参数是否合规。内置五种专用检查器 + 循环攻击检测：

| 检查器 | 检测能力 |
|--------|---------|
| `FileSystemChecker` | 路径白名单、目录穿越检测、敏感扩展名拦截 |
| `ShellChecker` | 命令黑名单（17 条）、命令注入检测 |
| `NetworkChecker` | SSRF 防护（10 种内网 IP 模式）、云元数据端点拦截 |
| `SQLChecker` | SQL 注入检测（13 条模式）、写操作开关、多语句禁止 |
| `MCPDescriptionScanner` | 工具描述投毒扫描、HTML 注入检测、异常长度/URL 检测 |
| 循环攻击检测 | 工具调用频率异常、连续相同调用检测 |

### 第三层：输出围栏 (OutputGuard)

在最终输出返回用户前，过滤敏感信息泄露：

| 检测类型 | 示例 |
|---------|------|
| 结构化敏感信息 | 手机号、身份证、银行卡号、邮箱 |
| 密钥/Token | API Key、JWT、SSH 私钥、密码 |
| System Prompt 泄露 | 通过哈希比对检测系统提示词泄露 |

支持 `mask_sensitive()` 自动脱敏功能。

---

## 可视化测试报告

一键脚本执行完毕后，会自动在浏览器中打开 `report.html`。报告包含以下内容：

- **汇总卡片**：单元测试通过数、MCP 攻击场景数、Benchmark 准确率、检测率
- **覆盖进度条**：测试覆盖率可视化
- **攻击场景卡片**：每场攻击场景展示"无防护时 Agent 的行为"和"有防护时的拦截结果"，不同颜色表示不同状态（绿色=攻击成功+防御成功，青色=仅防御成功，黄色=无攻击触发，红色=防御失败）
- **Benchmark 详情**：准确率、误报率、F1 分数等指标表格

---

## 评测数据

| 指标 | 目标值 | 当前状态 |
|------|--------|---------|
| 攻击拦截率（TPR） | > 85% | **87.5%**（Benchmark 实测） |
| 误报率（FPR） | < 5% | 待跑完整 benchmark |
| 延迟开销 | < 200ms | 纯规则引擎 < 1ms |
| OWASP 覆盖率 | ≥ 7/10 | 7/10 |
| 单元测试 | — | **67 个全部通过** |

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
├── guardrails/              # 三层围栏核心
│   ├── input_guard.py       # 第一层：输入围栏
│   ├── tool_guard.py        # 第二层：工具围栏
│   ├── output_guard.py      # 第三层：输出围栏
│   ├── agent_guard.py       # 总控类
│   ├── checkers/            # 工具检查器（文件/Shell/网络/SQL/MCP）
│   └── base.py              # 基础框架（GuardResult, BaseGuard）
├── classifiers/             # 分类器模块（规则引擎/ML/LLM Judge）
├── integrations/            # 框架集成适配器（LangGraph）
├── attacks/                 # MCP 攻击复现（端到端）
│   ├── agent_runner.py      # ReAct Agent 运行器
│   └── mcp_server/          # 恶意 MCP Server（sleeper/query_files/send_email）
├── benchmarks/              # 评测模块
├── demo/                    # 演示场景（邮件/RAG/MCP Agent）
├── tests/                   # 单元测试（67 个）
├── scripts/                 # 一键脚本与报告生成
│   ├── run_demo.sh          # macOS/Linux 一键启动
│   ├── run_demo.bat         # Windows 一键启动
│   └── generate_report.py   # HTML 报告生成器
└── configs/                 # 配置文件
```

---

## Demo 场景

### 一键运行所有场景

推荐使用一键脚本，自动运行所有 Demo 并生成可视化报告：

```bash
# macOS / Linux
bash scripts/run_demo.sh

# Windows
scripts\run_demo.bat

# 跳过 MCP 复现（无需 LLM）
bash scripts/run_demo.sh --no-mcp
```

### 邮件 Agent 攻防

攻击者在邮件正文中植入隐藏指令，诱导 Agent 转发所有邮件到攻击者地址。演示 InputGuard + ToolGuard 联合防御。

```bash
python demo/email_agent/run_demo.py
python demo/email_agent/tool_guard_demo.py
```

### RAG Agent 数据外泄

攻击者污染知识库文档，植入隐藏指令，诱导 Agent 将其他用户数据拼接到回复中。

```bash
python demo/rag_agent/run_demo.py
```

### MCP 工具投毒

恶意 MCP Server 在工具描述中藏指令，诱导 Agent 读取 SSH 私钥并发送。

```bash
python demo/mcp_agent/run_demo.py
```

---

## MCP 攻击复现演示（端到端）

使用真实 LLM (Ollama + qwen2.5:3b) 端到端验证三种攻击场景：

| 场景 | 攻击方式 | 检测规则 | 无防护结果 | 有防护结果 |
|------|---------|---------|-----------|-----------|
| 查询文件投毒 | `query_files` 描述中藏 `<IMPORTANT>` 指令 | MCP-000 | Agent 执行 `ls /etc/passwd` | **被 MCP 描述扫描器阻断** |
| 发送邮件投毒 | `send_email` 描述中藏 `在发送前请先执行` | MCP-013 | Agent 先收集信息再发送 | **被 MCP 描述扫描器阻断** |
| 天气查询潜伏 | `get_weather` 第二次调用触发 `ls /etc/passwd` | SHELL-S01 | Agent 执行敏感文件读取 | **被 ShellChecker 阻断** |

```bash
# 端到端运行攻击复现
python attacks/agent_runner.py --model qwen2.5:3b --scene all

# 单项运行
python attacks/agent_runner.py --model qwen2.5:3b --scene query-files
python attacks/agent_runner.py --model qwen2.5:3b --scene send-email
python attacks/agent_runner.py --model qwen2.5:3b --scene weather-sleeper
```

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
