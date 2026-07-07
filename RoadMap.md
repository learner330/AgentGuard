# AgentGuard 项目设计文档 v0.1

> 一个轻量级、可插拔的 LLM Agent 安全围栏中间件

---

## 一、项目定位与目标

**定位**：一个轻量级、可插拔的 LLM Agent 安全围栏中间件

**核心目标**：
- 覆盖 Agent 完整生命周期的四个安全检查点（输入 → 思维 → 工具 → 输出）
- 不侵入 Agent 业务逻辑，三行代码完成挂载
- 提供量化的防御效果评测报告

**对标标准**：[OWASP LLM Top 10](https://genai.owasp.org/) + [OWASP Agentic AI Top 10](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)

---

## 二、项目目录结构

```
agent-guard/
│
├── guardrails/                    # 四层围栏核心模块
│   ├── __init__.py
│   ├── base.py                    # 围栏基类，定义 GuardResult 数据结构
│   ├── input_guard.py             # 第一层：输入围栏
│   ├── thought_guard.py           # 第二层：思维围栏
│   ├── tool_guard.py              # 第三层：工具围栏
│   └── output_guard.py            # 第四层：输出围栏
│
├── classifiers/                   # 分类器模块（可替换）
│   ├── rule_based.py              # 规则引擎（关键词 + 正则）
│   ├── ml_classifier.py           # 机器学习分类器（deberta 微调）
│   └── llm_judge.py               # LLM-as-Judge（用小模型做意图判断）
│
├── integrations/                  # 框架集成适配器
│   ├── langchain_adapter.py       # LangChain 适配
│   ├── langgraph_adapter.py       # LangGraph 适配
│   └── mcp_adapter.py             # MCP Server 适配
│
├── benchmarks/                    # 评测模块
│   ├── run_agentdojo.py           # AgentDojo 评测接入
│   ├── run_injecagent.py          # InjecAgent 评测接入
│   ├── run_mcp_injection.py       # MCP 注入场景评测
│   └── metrics.py                 # 指标计算（拦截率、误报率、延迟）
│
├── datasets/                      # 数据集管理
│   ├── download.py                # 数据集下载脚本
│   └── README.md                  # 数据集说明
│
├── demo/                          # 演示场景
│   ├── email_agent/               # 邮件 Agent 攻防演示
│   ├── rag_agent/                 # RAG Agent 攻防演示
│   └── mcp_agent/                 # MCP Agent 攻防演示
│
├── tests/                         # 单元测试
│   ├── test_input_guard.py
│   ├── test_tool_guard.py
│   ├── test_thought_guard.py
│   └── test_output_guard.py
│
├── docs/                          # 文档
│   ├── design.md                  # 本设计文档
│   ├── attack_scenarios.md        # 攻击场景说明
│   └── benchmark_results.md       # 评测结果
│
├── configs/                       # 配置文件
│   └── guard_config.yaml          # 各层围栏开关与参数配置
│
└── README.md
```

---

## 三、四层围栏详细设计

### 第一层：输入围栏 `input_guard`

**防御目标**：拦截用户输入中的直接提示注入（Direct Prompt Injection）

**检测内容**：

| 检测类型 | 具体内容 |
|---|---|
| 指令覆盖 | `ignore previous instructions`、`forget everything` 等 |
| 角色劫持 | `你现在是`、`act as`、`pretend you are` 等 |
| 越狱模板 | DAN、AIM、STAN 等已知越狱模板特征 |
| 编码绕过 | Base64、Unicode 编码的隐藏指令 |
| 多语言混淆 | 中英文混合注入、特殊字符插入 |

**检测策略（三层叠加）**：

```
用户输入
    │
    ▼
┌─────────────────┐
│  规则引擎        │  关键词匹配 + 正则，速度快，零延迟
└────────┬────────┘
         │ 未命中
         ▼
┌─────────────────┐
│  ML 分类器       │  deberta-v3-base 微调，精度高
└────────┬────────┘
         │ 置信度低
         ▼
┌─────────────────┐
│  LLM Judge      │  小模型兜底判断，覆盖边界情况
└────────┬────────┘
         │
         ▼
     GuardResult（PASS / WARN / BLOCK）
```

**对应 OWASP 威胁**：[LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)

---

### 第二层：思维围栏 `thought_guard`

**防御目标**：在 ReAct Agent 生成 Action 之前，审查 Thought 的意图是否合规

**检测内容**：

| 风险类型 | 示例 Thought 特征 |
|---|---|
| 越权访问 | "我需要读取系统配置文件" |
| 数据外泄 | "把用户数据拼接到回复里发出去" |
| 权限提升 | "跳过权限校验直接执行" |
| 循环攻击 | Agent 被诱导进入无限工具调用循环 |

**风险分级机制**：

```
Thought 文本
    │
    ▼
意图分类器（参考 AutoControl-Arena 框架）
    │
    ├──► 🟢 低风险   → 直接放行，记录日志
    │
    ├──► 🟡 中风险   → 输出警告，降级执行（只读不写）
    │
    └──► 🔴 高风险   → 阻断执行，触发 Human-in-the-loop
```

**参考来源**：
- [AutoControl-Arena](https://github.com/CosmosYi/AutoControl-Arena)（ICML 2026）
- [arXiv 2603.07427](https://arxiv.org/abs/2603.07427)

---

### 第三层：工具围栏 `tool_guard`

**防御目标**：在 Agent 调用工具之前，审查调用参数是否合规，防止工具越权和工具投毒

**检测内容**：

| 工具类型 | 检测项 |
|---|---|
| 文件读写工具 | 路径白名单、目录穿越检测（`../../`） |
| 数据库工具 | SQL 注入检测、只读/读写权限分离 |
| 网络请求工具 | 域名白名单、SSRF 检测 |
| Shell 工具 | 命令黑名单、危险参数检测 |
| MCP 工具 | 工具描述语义扫描（防工具投毒） |

**MCP 工具描述扫描流程**：

```
MCP Server 注册工具
    │
    ▼
工具描述文本
    │
    ▼
┌──────────────────────────┐
│  语义扫描器               │
│  - 检测隐藏指令关键词      │
│  - 检测异常长度描述        │
│  - 检测 HTML/特殊字符注入  │
└──────────┬───────────────┘
           │
    ┌──────┴──────┐
    ▼             ▼
  安全工具       可疑工具
  正常注册       隔离 + 告警
```

**参考来源**：
- [mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)
- [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan)
- [Elastic MCP 攻防分析](https://www.elastic.co/security-labs/mcp-tools-attack-defense-recommendations)

---

### 第四层：输出围栏 `output_guard`

**防御目标**：在 Agent 最终输出返回用户之前，过滤敏感信息泄露

**检测内容**：

| 类型 | 检测项 |
|---|---|
| 结构化敏感信息 | 手机号、身份证、银行卡号、邮箱 |
| 密钥 / Token | API Key、JWT、SSH 私钥、密码 |
| 系统信息泄露 | 系统提示词（System Prompt）内容 |
| 非预期数据外带 | 检测输出中是否包含非用户请求的文件内容 |

**检测策略**：正则匹配（结构化数据）+ NER 模型（非结构化敏感实体）

---

## 四、数据集清单

| 数据集 | 用途 | 来源 |
|---|---|---|
| JailbreakBench | 输入围栏训练数据（越狱样本） | [github.com/JailbreakBench/jailbreakbench](https://github.com/JailbreakBench/jailbreakbench) |
| AdvBench | 输入围栏训练数据（对抗样本） | [github.com/llm-attacks/llm-attacks](https://github.com/llm-attacks/llm-attacks) |
| SecureNexusLab Handbook | 提示注入样本（直接 + 间接） | [github.com/SecureNexusLab/llm-prompt-injection-security-handbook](https://github.com/SecureNexusLab/llm-prompt-injection-security-handbook) |
| InjecAgent Dataset | 工具层攻击测试用例（1054 条） | [github.com/uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) |
| AgentDojo Tasks | 端到端攻防评测（97 任务 + 629 安全用例） | [github.com/ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo) |
| MCP Injection Experiments | MCP 工具投毒攻击场景 | [github.com/invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) |

---

## 五、参考论文与项目

| 类型 | 名称 | 链接 |
|---|---|---|
| 论文 | Not What You've Signed Up For（IPI 奠基论文） | [arXiv 2302.12173](https://arxiv.org/abs/2302.12173) |
| 论文 | AgentDojo（ICML 2025） | [arXiv 2406.13352](https://arxiv.org/abs/2406.13352) |
| 论文 | InjecAgent（ACL 2024） | [uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) |
| 论文 | Meta SecAlign（Meta AI 2025） | [facebookresearch/Meta_SecAlign](https://github.com/facebookresearch/Meta_SecAlign) |
| 论文 | AutoControl-Arena（ICML 2026） | [arXiv 2603.07427](https://arxiv.org/abs/2603.07427) |
| 论文 | Securing AI Agents Against Prompt Injection | [arXiv 2511.15759](https://arxiv.org/abs/2511.15759) |
| 项目 | mcp-scan（MCP 工具扫描器） | [invariantlabs-ai/mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) |
| 项目 | PyRIT（微软红队框架） | [microsoft/PyRIT](https://github.com/microsoft/PyRIT) |
| 项目 | garak（NVIDIA LLM 漏洞扫描） | [NVIDIA/garak](https://github.com/NVIDIA/garak) |
| 标准 | OWASP LLM Top 10 | [genai.owasp.org](https://genai.owasp.org/) |
| 标准 | OWASP Agentic AI Top 10 | [OWASP Agentic AI](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/) |

---

## 六、完整请求流程图

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

---

## 七、评测指标设计

| 指标 | 说明 | 目标值 |
|---|---|---|
| 攻击拦截率（TPR） | 成功拦截的攻击数 / 总攻击数 | > 85% |
| 误报率（FPR） | 正常请求被误拦截的比例 | < 5% |
| 延迟开销 | 围栏引入的额外推理时间 | < 200ms |
| 覆盖率 | 覆盖 OWASP Top 10 的条目数 | ≥ 7/10 |

**评测矩阵**（有无围栏的对比）：

```
                      无 AgentGuard    有 AgentGuard
AgentDojo 攻击成功率       X%            Y%（目标降低 50%+）
InjecAgent 攻击成功率      X%            Y%
MCP 注入成功率             X%            Y%
正常任务完成率             100%          ≥ 95%（误报影响）
```

---

## 八、Demo 场景设计

### Demo 1：邮件 Agent 攻防

```
攻击场景：
  攻击者在邮件正文中植入隐藏指令
  → Agent 读取邮件
  → 被诱导转发所有邮件到攻击者地址

防御演示：
  输入围栏（无效，因为是间接注入）
  → 工具围栏拦截异常的 send_email 调用
  → 输出围栏过滤泄露内容
```

### Demo 2：RAG Agent 数据外泄

```
攻击场景：
  攻击者污染知识库文档，植入隐藏指令
  → Agent 检索文档
  → 被诱导将其他用户数据拼接到回复中

防御演示：
  检索后消毒层过滤隐藏指令
  → 输出围栏检测异常数据外带
```

### Demo 3：MCP 工具投毒

```
攻击场景：
  恶意 MCP Server 在工具描述中藏指令
  → Agent 注册工具
  → 被诱导读取 SSH 私钥并发送

防御演示：
  MCP 适配器在工具注册时扫描描述
  → 检测到可疑内容，隔离工具，告警
```

---

## 九、执行计划

```
第 1 周
  └─ 搭项目骨架，实现 input_guard（规则引擎版）
  └─ 接入 email_agent_demo，验证基础拦截效果

第 2 周
  └─ 实现 tool_guard（白名单 + 审计日志）
  └─ 接入 InjecAgent 跑基准测试

第 3 周
  └─ 实现 thought_guard（意图分类器）
  └─ 接入 AgentDojo 跑完整评测

第 4 周
  └─ 实现 output_guard
  └─ 整理 README，写清楚攻击场景 + 防御效果对比数据
  └─ 发布 v0.1.0
```

> 💡 **项目亮点**：
> - **可插拔**：三行代码挂载到任意 LangGraph Agent，不侵入业务逻辑
> - **有数据**：接入两个顶会 benchmark，有量化的防御效果
> - **有对比**：加围栏 vs 不加围栏的攻击成功率对比，说服力强
> - **有演示**：三个真实 Demo 场景，面试时可以直接跑
