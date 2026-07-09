#!/bin/bash
# ============================================================
# AgentGuard 一键测试脚本 (macOS / Linux)
#
# 用法:
#   bash scripts/run_demo.sh              # 完整测试（含 MCP 攻击复现）
#   bash scripts/run_demo.sh --no-mcp     # 跳过 MCP 攻击复现（无 Ollama）
#   bash scripts/run_demo.sh --model qwen2.5:7b  # 指定模型
#
# 前置条件:
#   - Python 3.10+
#   - Ollama (可选，用于 MCP 攻击复现)
# ============================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
VENV_DIR="$PROJECT_DIR/.venv"
MODEL="${OLLAMA_MODEL:-qwen2.5:3b}"
NO_MCP=false

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --no-mcp) NO_MCP=true; shift ;;
        --model) MODEL="$2"; shift 2 ;;
        --help|-h)
            echo "用法: bash scripts/run_demo.sh [选项]"
            echo ""
            echo "选项:"
            echo "  --no-mcp          跳过 MCP 攻击复现（无需 Ollama）"
            echo "  --model MODEL     指定 Ollama 模型 (默认: qwen2.5:3b)"
            echo "  --help, -h        显示帮助"
            exit 0
            ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

echo -e "${BOLD}${BLUE}============================================================${NC}"
echo -e "${BOLD}${BLUE}  AgentGuard 一键测试脚本${NC}"
echo -e "${BOLD}${BLUE}============================================================${NC}"
echo ""
echo -e "  ${DIM}版本: v0.5.0 | 方式: ${NC}${GREEN}一键运行${NC}${DIM} | 输出: HTML 报告${NC}"
[ "$NO_MCP" = true ] && echo -e "  ${YELLOW}⚠ 已跳过 MCP 攻击复现 (--no-mcp)${NC}"
echo ""

# ============================================================
# 核心辅助函数
# ============================================================

# 获取指定 python 解释器的版本，格式如 "3.12"
python_version() {
    $1 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))'
}

# 检查依赖是否就绪：只需核心模块可导入即可
venv_has_deps() {
    local py="$1"
    $py -c "import pydantic, pytest, openai, mcp, fastmcp, yaml, structlog" 2>/dev/null
}

PYTHON=""

# ============================================================
# Step 1: 检测并选择 Python 环境
# ============================================================
echo -e "${BOLD}[1/5] 检查 Python 环境...${NC}"

# 1. 优先检查项目已有的 .venv
if [ -x "$VENV_DIR/bin/python" ]; then
    v=$($VENV_DIR/bin/python -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    major=$(echo "$v" | cut -d. -f1)
    minor=$(echo "$v" | cut -d. -f2)
    if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ] && venv_has_deps "$VENV_DIR/bin/python"; then
        PYTHON="$VENV_DIR/bin/python"
        echo -e "  ${GREEN}✓${NC} 使用项目 .venv: Python $(${PYTHON} --version)"
        echo -e "  ${GREEN}✓${NC} 核心依赖已就绪，跳过环境准备"
        SKIP_ENV_PREP=1
    fi
fi

# 2. 有 .venv 但 Python 版本不够或依赖不全，再考虑创建/安装
if [ -z "$PYTHON" ]; then
    SKIP_ENV_PREP=0

    # 2a. 扫描系统 Python 版本
    for cmd in python3.14 python3.13 python3.12 python3.11 python3.10 python3 python; do
        if command -v "$cmd" &>/dev/null; then
            v=$(python_version "$cmd")
            major=$(echo "$v" | cut -d. -f1)
            minor=$(echo "$v" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                PYTHON=$(command -v "$cmd")
                break
            fi
        fi
    done

    # 2b. 扫描常见路径
    if [ -z "$PYTHON" ]; then
        for candidate in \
            /opt/homebrew/bin/python3.* \
            /usr/local/bin/python3.* \
            /opt/homebrew/bin/python3 \
            /usr/local/bin/python3; do
            if [ -x "$candidate" ]; then
                v=$(python_version "$candidate")
                major=$(echo "$v" | cut -d. -f1)
                minor=$(echo "$v" | cut -d. -f2)
                if [ "$major" -ge 3 ] && [ "$minor" -ge 10 ]; then
                    PYTHON="$candidate"
                    break
                fi
            fi
        done
    fi

    if [ -z "$PYTHON" ]; then
        echo -e "${RED}[错误] 需要 Python 3.10+，系统默认 Python 是 3.9.6。${NC}"
        echo -e "${RED}        请通过以下方式安装 Python 3.10+：${NC}"
        echo "        - brew install python@3.12"
        echo "        - 或访问 https://python.org 下载"
        exit 1
    fi

    echo -e "  ${GREEN}✓${NC} 找到 Python $(${PYTHON} --version)"
fi

# ============================================================
# Step 2: 准备虚拟环境（仅在需要时执行）
# ============================================================
if [ "$SKIP_ENV_PREP" -eq 0 ]; then
    echo ""
    echo -e "${BOLD}[2/5] 准备虚拟环境...${NC}"

    if [ ! -d "$VENV_DIR" ]; then
        echo "  创建 .venv ..."
        $PYTHON -m venv "$VENV_DIR"
    fi

    source "$VENV_DIR/bin/activate"

    # 确保后续始终使用 venv 里的 Python，不依赖 activate 的 PATH 修改
    PYTHON="$VENV_DIR/bin/python"

    echo -e "  ${GREEN}✓${NC} 虚拟环境已激活"

    # ============================================================
    # Step 3: 安装依赖（仅在需要时执行）
    # ============================================================
    echo ""
    echo -e "${BOLD}[3/5] 安装依赖...${NC}"

    # 检查 pip 是否可用（uv/poetry 创建的 venv 可能不带 pip）
    if ! $PYTHON -m pip --version &>/dev/null; then
        echo "  pip 未安装，正在通过 ensurepip 安装..."
        $PYTHON -m ensurepip --default-pip --upgrade
    fi

    if [ ! -f "$VENV_DIR/.deps_installed" ]; then
        $PYTHON -m pip install --quiet --upgrade pip
        $PYTHON -m pip install --quiet pydantic pyyaml structlog openai mcp fastmcp pytest pytest-asyncio
        touch "$VENV_DIR/.deps_installed"
        echo -e "  ${GREEN}✓${NC} 依赖安装完成"
    else
        echo -e "  ${GREEN}✓${NC} 依赖已存在 (跳过)"
    fi
else
    echo ""
    echo -e "${BOLD}[2/5] 虚拟环境已就绪，跳过${NC}"
    echo -e "  ${GREEN}✓${NC} .venv 存在且核心依赖已可用"

    echo ""
    echo -e "${BOLD}[3/5] 依赖已就绪，跳过${NC}"
    echo -e "  ${GREEN}✓${NC} 使用现有 .venv 依赖"
fi

# ============================================================
# Step 4: 检查 Ollama (可选)
# ============================================================
if [ "$NO_MCP" = false ]; then
    echo ""
    echo -e "${BOLD}[4/5] 检查 Ollama...${NC}"

    if ! command -v ollama &>/dev/null; then
        echo -e "  ${YELLOW}⚠${NC} 未检测到 Ollama"
        echo ""
        echo "  MCP 攻击复现需要 Ollama。你可以:"
        echo "    1. 安装 Ollama: brew install ollama"
        echo "    2. 启动服务: ollama serve"
        echo "    3. 拉取模型: ollama pull $MODEL"
        echo "    4. 重新运行本脚本"
        echo ""
        echo "  或者跳过 MCP 测试: bash scripts/run_demo.sh --no-mcp"
        echo ""
        read -p "  是否跳过 MCP 测试并继续? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            NO_MCP=true
            echo -e "  ${YELLOW}→${NC} 跳过 MCP 测试"
        else
            echo "  已取消"
            exit 0
        fi
    else
        # 检查 Ollama 是否在运行
        if curl -s http://localhost:11434/api/tags &>/dev/null; then
            echo -e "  ${GREEN}✓${NC} Ollama 服务运行中"
        else
            echo -e "  ${YELLOW}⚠${NC} Ollama 服务未运行，尝试启动..."
            ollama serve &>/dev/null &
            sleep 2
            if curl -s http://localhost:11434/api/tags &>/dev/null; then
                echo -e "  ${GREEN}✓${NC} Ollama 服务已启动"
            else
                echo -e "  ${RED}✗${NC} 无法启动 Ollama 服务"
                NO_MCP=true
            fi
        fi

        # 检查模型
        if [ "$NO_MCP" = false ]; then
            if ollama list 2>/dev/null | grep -q "$MODEL"; then
                echo -e "  ${GREEN}✓${NC} 模型 $MODEL 已就绪"
            else
                echo -e "  ${YELLOW}⚠${NC} 模型 $MODEL 未找到，正在拉取..."
                ollama pull "$MODEL" && echo -e "  ${GREEN}✓${NC} 模型拉取完成" || {
                    echo -e "  ${RED}✗${NC} 模型拉取失败"
                    NO_MCP=true
                }
            fi
        fi
    fi
else
    echo ""
    echo -e "${BOLD}[4/5] 跳过 MCP 测试 (--no-mcp)${NC}"
fi

# ============================================================
# Step 5: 运行测试并生成报告
# ============================================================
echo ""
echo -e "${BOLD}[5/5] 运行测试并生成报告...${NC}"
echo ""

echo -e "  ${DIM}┌──────────────────────────────────────────────────────┐${NC}"
echo -e "  ${DIM}│${NC}  ${BOLD}即将执行:${NC}                                          ${DIM}│${NC}"
echo -e "  ${DIM}│${NC}  ${BLUE}📋${NC} 单元测试 ($(${PYTHON} -m pytest --collect-only -q 2>/dev/null | tail -1 || echo '67 项'))       ${DIM}│${NC}"
if [ "$NO_MCP" = false ]; then
    echo -e "  ${DIM}│${NC}  ${PURPLE}🔴${NC} MCP 攻击复现 (3 种场景)                       ${DIM}│${NC}"
fi
echo -e "  ${DIM}│${NC}  ${YELLOW}📊${NC} Benchmark 评测                                 ${DIM}│${NC}"
echo -e "  ${DIM}│${NC}  ${GREEN}📄${NC} HTML 报告生成                                  ${DIM}│${NC}"
echo -e "  ${DIM}└──────────────────────────────────────────────────────┘${NC}"
echo ""

cd "$PROJECT_DIR"

if [ "$NO_MCP" = true ]; then
    "$VENV_DIR/bin/python" scripts/generate_report.py --no-mcp --model "$MODEL" --output "$PROJECT_DIR/report.html"
else
    "$VENV_DIR/bin/python" scripts/generate_report.py --model "$MODEL" --output "$PROJECT_DIR/report.html"
fi

echo ""
echo -e "${BOLD}${GREEN}============================================================${NC}"
echo -e "${BOLD}${GREEN}  测试完成!${NC}"
echo -e "${BOLD}${GREEN}============================================================${NC}"
echo ""
echo -e "  ${BOLD}📊 报告文件:${NC} $PROJECT_DIR/report.html"
echo ""
echo -e "  ${BOLD}${BLUE}环境信息:${NC}"
echo -e "    Python:   $(${PYTHON} --version 2>/dev/null || echo 'N/A')"
echo -e "    .venv:    $([ -d "$VENV_DIR" ] && echo "${GREEN}已就绪${NC}" || echo "${YELLOW}未配置${NC}")"
if [ "$NO_MCP" = false ]; then
    echo -e "    Ollama:   $([ curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 ] && echo "${GREEN}运行中${NC}" || echo "${YELLOW}未运行${NC}")"
    echo -e "    模型:     ${MODEL}"
fi
echo ""
echo -e "  ${BOLD}Tip:${NC} 也可以用以下命令单独运行各个演示:"
echo -e "    ${DIM}.venv/bin/python demo/email_agent/run_demo.py${NC}"
echo -e "    ${DIM}.venv/bin/python demo/rag_agent/run_demo.py${NC}"
echo -e "    ${DIM}.venv/bin/python attacks/agent_runner.py --model $MODEL --scene all${NC}"
echo ""
