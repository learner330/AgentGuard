# AgentGuard

> 轻量级、可插拔的 LLM Agent 安全围栏中间件

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.5.0-blue.svg)]()

AgentGuard 为 LLM Agent 提供三层纵深防御，覆盖 Agent 完整生命周期的安全检查点（输入→工具→输出），对标 OWASP LLM Top 10 和 OWASP Agentic AI Top 10。

**核心设计哲学**：语义分析取代模式匹配，白名单策略取代黑名单规则。所有用于注入检测的正则模式已被移除，替换为 LLM Judge 语义分析和基于行为策略的白名单检查。

**核心特点**：可插拔（三行代码挂载）、不侵入业务逻辑、基于真实数据集评测。

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

脚本会自动完成：检查 Python 环境 → 创建虚拟环境 → 安装依赖 → 检查 Ollama（可选）→ 运行 60 个单元测试 → 执行三种 MCP 攻击场景（无防护 vs 有防护对比）→ 运行 Benchmark（InjecAgent 真实数据 1054 条）→ 生成可视化 HTML 报告并在浏览器中打开。

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
│  │  Embedding 语义相似度 → LLM Judge    │  │
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
│  │  │  白名单审查 → 循环检测 → MCP扫描 │   │  │
│  │  └──────────────┬───────────────┘   │  │
│  │                 │ PASS              │  │
│  │           工具执行 & 返回结果        │  │
│  └──────────────────────────────────┘  │
│                 │                       │
│  ┌──────────────▼──────────────────────┐  │
│  │  第三层：输出围栏 (OutputGuard)       │  │
│  │  敏感信息检测 → 自动脱敏             │  │
│  └──────────────┬──────────────────────┘  │
│                 │ PASS                    │
└─────────────────┼─────────────────────────┘
                  │
                  ▼
              返回用户
```

### 第一层：输入围栏 (InputGuard)

防御直接提示注入（Prompt Injection），采用两层语义分析策略：

| 检测层 | 机制 | 说明 |
|--------|------|------|
| Embedding 语义层 | `all-MiniLM-L6-v2` 模型计算输入与 26 条已知注入参考文本的余弦相似度 | 可选开启，阈值可配（默认 0.72） |
| LLM Judge 层 | 通过 OpenAI 兼容 API（支持 Ollama 本地模型）做行为意图分析 | 主要检测层，提出 5 个行为问题判断风险 |

LLM Judge 的 5 个行为检测维度：指令覆盖（是否试图 ignore previous instructions）、角色劫持（是否试图 act as / pretend）、越狱模板（DAN/AIM 等）、编码混淆（Base64/Unicode 隐藏指令）、执行操纵（诱导执行非预期操作）。返回 JSON 格式的风险等级和违规列表，超过阈值（默认 medium）则阻断。

没有 LLM 客户端时，所有输入直接 PASS——不再有正则层兜底，这是有意为之的设计选择。

对应 OWASP 威胁：[LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

### 第二层：工具围栏 (ToolGuard)

在 Agent 调用工具之前，审查调用参数是否合规。内置五种白名单检查器 + MCP 描述扫描器 + 循环攻击检测：

| 检查器 | 检测策略 | 检测能力 |
|--------|---------|---------|
| `FileSystemChecker` | 路径白名单 | `Path.resolve()` 真实路径解析（跟随符号链接），`Path.relative_to()` 严格子目录判断，敏感系统路径和扩展名拦截 |
| `ShellChecker` | 命令白名单 | `shlex` 语法解析，只允许基础命令（ls/cat/grep 等），拦截管道、重定向、子 shell、命令替换、脚本解释器执行 |
| `NetworkChecker` | DNS 解析 + IP 分类 | 先 DNS 解析域名获取真实 IP，再用 `ipaddress` 模块分类检测（回环/私网/链路本地/保留/组播），拦截云元数据端点 |
| `SQLChecker` | AST 解析 | `sqlparse` 解析语句类型，只允许 SELECT/SHOW/DESCRIBE/EXPLAIN，检测 UNION 注入、子查询、堆叠查询、时间盲注 |
| `MCPDescriptionScanner` | LLM 语义分析 | 对 MCP 工具描述做行为意图分析（功能相关性、敏感访问、外部通信、隐藏行为、指令覆盖），唯一结构检查为描述长度上限 |
| 循环攻击检测 | 频率 + 重复 | 工具调用频率异常检测（窗口内超过阈值）、连续相同调用检测 |

所有检查器均基于行为策略和白名单，不依赖关键词或正则模式匹配。

### 第三层：输出围栏 (OutputGuard)

在最终输出返回用户前，过滤敏感信息泄露。这是项目中唯一保留正则的地方，用于结构化数据匹配（格式确定的数据用正则是正确的方法）：

| 检测类型 | 示例 |
|---------|------|
| 结构化敏感信息 | 手机号、身份证、银行卡号、邮箱 |
| 密钥/Token | API Key、JWT、SSH 私钥、密码格式 |
| System Prompt 泄露 | 通过 MD5 哈希比对检测系统提示词泄露 |

支持 `mask_sensitive()` 自动脱敏，对不同类型信息有定制脱敏规则（如手机号 138****5678）。

---

## 可视化测试报告

一键脚本执行完毕后，会自动在浏览器中打开 `report.html`。报告包含以下内容：

- **汇总卡片**：单元测试通过数、MCP 攻击场景数、Benchmark 准确率、检测率
- **覆盖进度条**：测试覆盖率可视化
- **攻击场景卡片**：每场攻击场景展示"无防护时 Agent 的行为"和"有防护时的拦截结果"，不同颜色表示不同状态（绿色=攻击成功+防御成功，青色=仅防御成功，黄色=无攻击触发，红色=防御失败）
- **Benchmark 详情**：准确率、误报率、检测率等指标表格

---

## 评测数据

| 指标 | 目标值 | 当前状态 |
|------|--------|---------|
| 攻击拦截率（TPR） | > 85% | LLM Judge 在 InjecAgent 真实数据上的检测率 |
| 误报率（FPR） | < 5% | 良性样本误报率 |
| 延迟开销 | < 200ms | 白名单检查器 < 1ms，LLM Judge 取决于模型 |
| OWASP 覆盖率 | ≥ 7/10 | 7/10 |
| 单元测试 | — | **60 个全部通过** |

**数据集清单**：

| 数据集 | 用途 | 来源 |
|-------|------|------|
| InjecAgent (1054 条) | 间接注入检测评测（510 Direct Harm + 544 Data Stealing） | ACL 2024 |
| Adversarial Samples | LLM Judge 鲁棒性评测（3 基础攻击 + 6 变体 + 4 良性） | 自建 |
| MCP Injection | MCP 工具投毒攻击场景（3 种） | Invariant Labs |

---

## 项目结构

```
agent-guard/
├── guardrails/              # 三层围栏核心
│   ├── input_guard.py       # 第一层：输入围栏（Embedding + LLM Judge）
│   ├── tool_guard.py        # 第二层：工具围栏（白名单检查器编排）
│   ├── output_guard.py      # 第三层：输出围栏（PII 检测 + 脱敏）
│   ├── agent_guard.py       # 总控类
│   ├── tool_call.py         # ToolCall 数据结构
│   ├── base.py              # 基础框架（GuardResult, BaseGuard, GuardSeverity）
│   └── checkers/            # 工具检查器
│       ├── file_checker.py    # 文件系统白名单检查
│       ├── shell_checker.py   # Shell 命令白名单检查
│       ├── network_checker.py # 网络 SSRF 防护
│       ├── sql_checker.py     # SQL AST 解析检查
│       └── mcp_scanner.py     # MCP 描述 LLM 语义扫描
├── integrations/            # 框架集成适配器
│   └── langgraph_adapter.py # LangGraph 中间件适配器
├── attacks/                 # MCP 攻击复现（端到端）
│   ├── agent_runner.py      # ReAct Agent 运行器（政策检测）
│   └── mcp_server/          # 恶意 MCP Server
│       ├── malicious_server.py  # 直接工具投毒
│       ├── shadow_server.py     # 工具劫持
│       └── sleeper_server.py    # 延迟触发
├── benchmarks/              # 评测模块
│   ├── injecagent/          # InjecAgent 真实数据评测
│   │   ├── real_data.py     # 1054 条真实攻击数据加载
│   │   └── real_runner.py   # LLM Judge 检测评测
│   ├── adversarial/         # 对抗鲁棒性评测
│   │   ├── samples.py       # 基础攻击 + 变体 + 良性样本
│   │   └── runner.py        # 鲁棒性差距计算
│   ├── common/
│   │   └── metrics.py       # 评测指标（TP/FP/FN/TN/F1）
│   └── run_all.py           # 统一入口
├── datasets/                # 真实数据集
│   ├── injecagent_dh_base.json  # Direct Harm 攻击数据
│   └── injecagent_ds_base.json  # Data Stealing 攻击数据
├── demo/                    # 演示场景
│   ├── email_agent/         # 邮件 Agent 攻防
│   ├── rag_agent/           # RAG Agent 数据外泄
│   └── mcp_agent/           # MCP 工具投毒
├── tests/                   # 单元测试（60 个）
├── scripts/                 # 一键脚本与报告生成
│   ├── run_demo.sh          # macOS/Linux 一键启动
│   ├── run_demo.bat         # Windows 一键启动
│   └── generate_report.py   # HTML 报告生成器
└── configs/                 # 配置文件
    └── guard_config.yaml   # 各层围栏开关与参数
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

使用真实 LLM (Ollama + qwen2.5:3b) 端到端验证三种攻击场景。攻击是否成功基于**策略违规检测**：用独立的 ToolGuard 实例检查 Agent 实际执行的工具调用，如果调用违反白名单策略（路径越权、域名不在白名单、命令不在白名单），则判定为攻击成功。不依赖硬编码的攻击特征关键词。

| 场景 | 攻击方式 | 无防护结果 | 有防护结果 |
|------|---------|-----------|-----------|
| 直接工具投毒 | `query_files` 描述中藏 `<IMPORTANT>` 指令，诱导读取 SSH 私钥 | Agent 执行越权文件读取和网络外发 | **MCP 描述扫描器（LLM Judge）阻断** |
| 工具劫持 | `send_email` 描述中藏中文注入指令，诱导先收集信息再发送 | Agent 先读取通讯录再发邮件 | **MCP 描述扫描器（LLM Judge）阻断** |
| 延迟触发 | `get_weather` 第二次调用返回值中嵌入注入指令 | Agent 执行 `ls /etc/passwd` | **ShellChecker 白名单阻断** |

```bash
# 端到端运行攻击复现
python attacks/agent_runner.py --model qwen2.5:3b --scene all

# 单项运行
python attacks/agent_runner.py --model qwen2.5:3b --scene query-files
python attacks/agent_runner.py --model qwen2.5:3b --scene send-email
python attacks/agent_runner.py --model qwen2.5:3b --scene weather-sleeper
```

---

## 评测模块

### InjecAgent 真实数据评测

使用 ACL 2024 论文的 1054 条真实攻击数据（510 Direct Harm + 544 Data Stealing），测试 LLM Judge 对间接注入的检测能力。按攻击类型分组报告检测率和误报率。

```bash
python -m benchmarks.injecagent.real_runner --samples 50
```

### 对抗鲁棒性评测

测试 LLM Judge 对措辞变异的鲁棒性。包含 3 个基础攻击、6 个语义等价的对抗变体（不同措辞）和 4 个良性描述。计算基础检测率、变体检测率和鲁棒性差距（gap），gap 小于 15% 说明不依赖具体措辞。

```bash
python -m benchmarks.adversarial.runner
```

### 统一入口

```bash
python -m benchmarks.run_all
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
