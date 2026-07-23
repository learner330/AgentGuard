# AI Agent 安全方向学习路径与可落地项目指南

> 整理日期：2026-07-03
> 适合人群：有开发背景、希望转入 AI 安全方向的工程师

---

## 一、AI 安全综述资源

| 论文 / 报告 | 简介 | 链接 |
|---|---|---|
| Large Language Model Safety: A Holistic Survey | 全面覆盖 LLM 安全四大类：价值对齐偏差、对抗鲁棒性、滥用风险、自主 AI 风险 | [arxiv.org/abs/2412.17686](https://arxiv.org/abs/2412.17686) |
| Attacks, Defenses and Evaluations for LLM Conversation Safety | 系统梳理 LLM 对话安全的攻击、防御与评估三大维度 | [arxiv.org/abs/2402.09283](https://arxiv.org/abs/2402.09283) |
| International AI Safety Report 2025 | 30 国 96 位专家联合撰写，首份国际 AI 安全科学报告 | [arxiv.org/abs/2501.17805](https://arxiv.org/abs/2501.17805) |
| LLM-Agent Threat Model Survey | 首次建立 LLM-Agent 生态统一威胁模型，覆盖 30+ 攻击技术 | [arxiv.org/abs/2506.23260](https://arxiv.org/html/2506.23260v1) |

---

## 二、学习路径

### 第一阶段：基础（1-2 个月）

- 机器学习基础：吴恩达 Machine Learning（Coursera）+ 李沐《动手学深度学习》
- Python + PyTorch 基本使用
- 阅读 [OWASP LLM Top 10](https://genai.owasp.org/) 和 [OWASP Agentic AI Top 10](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)

### 第二阶段：AI 安全核心知识（2-3 个月）

| 方向 | 核心内容 | 入门资源 |
|---|---|---|
| 对抗攻击与防御 | FGSM、PGD、C&W 攻击；对抗训练防御 | [ART 库](https://github.com/Trusted-AI/adversarial-robustness-toolbox) |
| LLM 安全 | 越狱攻击、提示注入、后门攻击 | [TextAttack](https://github.com/QData/TextAttack) |
| Agent 安全 | 工具越权、间接注入、MCP 安全 | [garak](https://github.com/NVIDIA/garak) |
| 模型隐私 | 成员推断攻击、差分隐私 | Google Privacy Sandbox 文档 |

### 第三阶段：动手实践（持续进行）

- 复现经典论文，跑通攻防 Demo
- 参与 CTF 竞赛（DEF CON AI Village、AISC）
- 贡献开源项目，积累 GitHub 可见度

---

## 三、可落地 GitHub 项目

### ⭐ 入门级（1-2 周）

---

#### 项目 1：MCP 工具投毒攻击复现 + 检测器

**复现来源**：Invariant Labs 披露的 MCP Tool Poisoning 攻击

**核心仓库**：[invariantlabs-ai/mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments)

**具体步骤**：
1. 克隆仓库，跑通三个攻击场景：
   - `direct-poisoning.py`：在工具描述里藏指令，诱导 Agent 读取 SSH 私钥
   - `shadowing.py`：劫持另一个可信工具（如 send_email）的行为
   - `whatsapp-takeover.py`：延迟触发的 Sleeper 攻击
2. 自己实现一个 MCP 工具描述扫描器，检测可疑模式（如 `<IMPORTANT>`、`ignore previous`、隐藏指令关键词），参考 [mcp-scan](https://github.com/invariantlabs-ai/mcp-scan) 思路实现轻量版

**使用框架**：
- `mcp` Python SDK（Anthropic 官方）
- `fastmcp`（快速搭建 MCP Server）
- Ollama + 本地模型（零成本推理）

**难度**：⭐ | **认可度**：极高（已被 OWASP 收录）

---

#### 项目 2：AI 邮件助手间接注入靶场

**复现论文**：*Not What You've Signed Up For: Compromising Real-World LLM-Integrated Applications with Indirect Prompt Injections*
[arxiv.org/abs/2302.12173](https://arxiv.org/abs/2302.12173)

**参考数据集**：[SecureNexusLab/llm-prompt-injection-security-handbook](https://github.com/SecureNexusLab/llm-prompt-injection-security-handbook)

**具体步骤**：
1. 用 LangChain 搭一个带邮件读取工具的 Agent（工具可 mock）
2. 在"邮件正文"里植入隐藏指令（白色字体、HTML 注释、Base64 编码三种变体）
3. 观察 Agent 是否被诱导执行"转发所有邮件到攻击者地址"
4. 实现防御：在工具返回内容进入 LLM 上下文前，加语义分类器区分"数据内容"和"指令内容"

**使用框架**：
- LangChain（工具调用）
- `transformers`（`deberta-v3-base` 微调分类器）
- Ollama（本地推理）

**难度**：⭐ | **认可度**：高（该领域引用最多的 IPI 论文）

---

### ⭐⭐ 初级（2-4 周）

---

#### 项目 3：基于 AgentDojo 的攻防评测平台扩展

**复现论文**：*AgentDojo: A Dynamic Environment to Evaluate Attacks and Defenses for LLM Agents*（ICML 2025）
[arxiv.org/abs/2406.13352](https://arxiv.org/abs/2406.13352)

**核心仓库**：[ethz-spylab/agentdojo](https://github.com/ethz-spylab/agentdojo)

**具体步骤**：
1. 安装并跑通 AgentDojo，理解其 97 个真实任务 + 629 个安全测试用例的结构
2. 新增 1-2 个自定义任务套件（如代码审查 Agent 或数据库查询 Agent），编写对应攻击注入用例
3. 测试不同防御策略（prompt sandwich、输入过滤、指令层级隔离）的效果，生成对比报告

**使用框架**：
- `agentdojo`（pip 直接安装）
- OpenAI API 或 Ollama（框架支持自定义模型）

**难度**：⭐⭐ | **认可度**：极高（ICML 顶会，框架持续维护）

---

#### 项目 4：基于 InjecAgent 的工具集成 Agent 漏洞评测

**复现论文**：*InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents*（ACL 2024）

**核心仓库**：[uiuc-kang-lab/InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent)

**具体步骤**：
1. 跑通 1054 个测试用例（覆盖 17 种用户工具 + 62 种攻击工具）
2. 用本地模型（Ollama + Llama3/Qwen）替换原来的 GPT-4，对比不同模型在 IPI 攻击下的脆弱性差异
3. 针对失败率最高的攻击类型，设计并实现针对性防御 patch，验证防御效果

**使用框架**：
- `InjecAgent`（直接克隆）
- Ollama（本地模型推理，零成本）

**难度**：⭐⭐ | **认可度**：高（ACL 顶会，benchmark 被广泛引用）

---

#### 项目 5：RAG 系统间接注入 + 数据外泄复现

**复现来源**：
- EchoLeak（CVE-2025-32711，Microsoft 365 Copilot 零点击漏洞）攻击模式
- 防御参考论文：[Securing AI Agents Against Prompt Injection Attacks](https://arxiv.org/abs/2511.15759)

**具体步骤**：
1. 用 LlamaIndex 搭一个本地 RAG 系统（知识库用本地文档）
2. 在知识库文档中植入隐藏指令（白色字体、HTML 注释、正常段落末尾追加三种方式）
3. 验证 Agent 是否被诱导执行数据外泄
4. 实现**检索后消毒层**：对所有检索回来的文本做语义级扫描，过滤疑似指令内容

**使用框架**：
- LlamaIndex（RAG 搭建）
- `sentence-transformers`（语义相似度检测）
- Ollama（本地推理）

**难度**：⭐⭐ | **认可度**：高（复现真实 CVE 漏洞攻击模式）

---

### ⭐⭐⭐ 中级（1-2 个月）

---

#### 项目 6：Meta SecAlign 防御方案复现与评测

**复现论文**：*Meta SecAlign: A Secure Foundation LLM Against Prompt Injection Attacks*（Meta AI Research，2025）

**核心仓库**：[facebookresearch/Meta_SecAlign](https://github.com/facebookresearch/Meta_SecAlign)

**具体步骤**：
1. 克隆仓库，理解核心思路：通过对齐训练让模型天然区分"数据内容"和"指令内容"
2. 在 AgentDojo 和 InjecAgent 两个 benchmark 上跑通评测流程（仓库已内置测试脚本）
3. 用 Ollama 本地模型（Llama3/Qwen）替换 Meta 模型，对比"有 SecAlign 对齐"和"无对齐"的表现差异，分析对齐训练的迁移效果

**使用框架**：
- `Meta_SecAlign`（含完整评测脚本）
- `agentdojo`、`InjecAgent`（评测环境）
- `transformers` + `lm-eval-harness`

**难度**：⭐⭐⭐ | **认可度**：极高（Meta 官方出品，已开源商用）

---

#### 项目 7：Agent Thought-level 安全监控系统

**复现论文**：AutoControl-Arena（ICML 2026，复旦大学 + 上海创智学院）
[arxiv.org/abs/2603.07427](https://arxiv.org/abs/2603.07427)

**核心仓库**：[CosmosYi/AutoControl-Arena](https://github.com/CosmosYi/AutoControl-Arena)

**具体步骤**：
1. 用 LangGraph 搭一个带文件读写 + 数据库操作的 ReAct Agent
2. 在 Agent 的 Thought 阶段加入**安全审查节点**：在生成 Action 之前，对 Thought 做意图分类，判断是否存在越权意图
3. 实现**分级审批机制**：
   - 低风险操作：直接执行
   - 中风险操作：输出警告
   - 高风险操作：强制 Human-in-the-loop 确认
4. 用 AutoControl-Arena 的测试场景验证效果

**使用框架**：
- LangGraph（带状态的 Agent 编排，天然支持节点间插入安全检查）
- `AutoControl-Arena`（测试场景）
- Ollama（本地推理）

**难度**：⭐⭐⭐ | **认可度**：极高（ICML 顶会，方向极新，做的人极少）

---

## 四、项目总览

| 项目 | 复现来源 | 核心 GitHub | 难度 | 认可度 |
|---|---|---|---|---|
| MCP 工具投毒复现 + 检测器 | Invariant Labs | [mcp-injection-experiments](https://github.com/invariantlabs-ai/mcp-injection-experiments) | ⭐ | 极高 |
| AI 邮件助手间接注入靶场 | arXiv 2302.12173 | [SecureNexusLab handbook](https://github.com/SecureNexusLab/llm-prompt-injection-security-handbook) | ⭐ | 高 |
| AgentDojo 攻防评测扩展 | arXiv 2406.13352 (ICML) | [agentdojo](https://github.com/ethz-spylab/agentdojo) | ⭐⭐ | 极高 |
| InjecAgent 漏洞评测 | ACL 2024 | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | ⭐⭐ | 高 |
| RAG 间接注入 + 数据外泄复现 | CVE-2025-32711 | [arxiv.org/abs/2511.15759](https://arxiv.org/abs/2511.15759) | ⭐⭐ | 高 |
| Meta SecAlign 防御复现 | Meta AI Research 2025 | [Meta_SecAlign](https://github.com/facebookresearch/Meta_SecAlign) | ⭐⭐⭐ | 极高 |
| Agent Thought-level 安全监控 | ICML 2026 / arXiv 2603.07427 | [AutoControl-Arena](https://github.com/CosmosYi/AutoControl-Arena) | ⭐⭐⭐ | 极高 |

---

## 五、推荐落地路径

```
第 1 周
  └─ 跑通 mcp-injection-experiments 三个攻击场景
  └─ 自己写一个 MCP 工具描述扫描器（第一个可展示的项目）

第 2 周
  └─ 跑通 InjecAgent benchmark，换本地模型对比脆弱性

第 3-4 周
  └─ 在 AgentDojo 上新增自定义任务套件（可直接提 PR 给原仓库）

第 1 月
  └─ 搭 RAG 间接注入靶场 + 检索后消毒防御层

第 1-2 月
  └─ LangGraph + Thought-level 安全审查框架（差异化竞争力最强的项目）
```

> 💡 建议：前三个项目做完后，整合成一个统一仓库（如 `agent-security-lab`），包含"攻击复现 + 防御实现 + benchmark 评测"三个模块，展示效果更好。

---

## 六、持续跟进渠道

| 渠道 | 说明 |
|---|---|
| arXiv cs.CR + cs.LG | 搜索 `LLM agent security`、`prompt injection` |
| OWASP GenAI Project | [genai.owasp.org](https://genai.owasp.org/) |
| awesome-llm-security | [github.com/corca-ai/awesome-llm-security](https://github.com/corca-ai/awesome-llm-security) |
| awesome-agent-skills-security | [github.com/LLMSecurity/awesome-agent-skills-security](https://github.com/LLMSecurity/awesome-agent-skills-security) |
| DEF CON AI Village CTF | 每年举办，专注 AI 安全攻防 |
| IEEE S&P / CCS / USENIX Security | AI 安全方向顶会 |
