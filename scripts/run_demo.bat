@echo off
REM ============================================================
REM AgentGuard 一键测试脚本 (Windows)
REM
REM 用法:
REM   scripts\run_demo.bat                   完整测试（含 MCP 攻击复现）
REM   scripts\run_demo.bat --no-mcp          跳过 MCP 攻击复现
REM   scripts\run_demo.bat --model qwen2.5:7b  指定模型
REM
REM 前置条件:
REM   - Python 3.10+
REM   - Ollama (可选，用于 MCP 攻击复现)
REM ============================================================

setlocal enabledelayedexpansion

set PROJECT_DIR=%~dp0..
set VENV_DIR=%PROJECT_DIR%\.venv
set MODEL=qwen2.5:3b
set NO_MCP=0
set ARG_INDEX=0

REM 解析参数
:parse_args
if "%~1"=="" goto :start
if /I "%~1"=="--no-mcp" (
    set NO_MCP=1
    shift
    goto :parse_args
)
if /I "%~1"=="--model" (
    set MODEL=%~2
    shift
    shift
    goto :parse_args
)
if /I "%~1"=="--help" (
    echo 用法: scripts\run_demo.bat [选项]
    echo.
    echo 选项:
    echo   --no-mcp          跳过 MCP 攻击复现（无需 Ollama）
    echo   --model MODEL     指定 Ollama 模型 (默认: qwen2.5:3b)
    echo   --help            显示帮助
    exit /b 0
)
shift
goto :parse_args

:start
echo ============================================================
echo   AgentGuard 一键测试脚本 (Windows)
echo ============================================================
echo.

REM ============================================================
REM Step 1: Check Python
REM ============================================================
echo [1/5] 检查 Python 环境...

set PYTHON=
for %%p in (python python3) do (
    where %%p >nul 2>nul
    if not errorlevel 1 (
        for /f "tokens=2" %%v in ('%%p --version 2^>^&1') do (
            set PYTHON=%%p
            set PYTHON_VER=%%v
        )
    )
)

if "%PYTHON%"=="" (
    echo [错误] 需要 Python 3.10+，请先安装: https://python.org
    pause
    exit /b 1
)

echo   [OK] %PYTHON_VER%

REM ============================================================
REM Step 2: Create virtual environment
REM ============================================================
echo.
echo [2/5] 准备虚拟环境...

if not exist "%VENV_DIR%" (
    echo   创建 .venv ...
    %PYTHON% -m venv "%VENV_DIR%"
)

call "%VENV_DIR%\Scripts\activate.bat"
echo   [OK] 虚拟环境已激活

REM ============================================================
REM Step 3: Install dependencies
REM ============================================================
echo.
echo [3/5] 安装依赖...

if not exist "%VENV_DIR%\.deps_installed" (
    pip install --quiet --upgrade pip
    pip install --quiet pydantic pyyaml structlog openai mcp fastmcp pytest pytest-asyncio
    type nul > "%VENV_DIR%\.deps_installed"
    echo   [OK] 依赖安装完成
) else (
    echo   [OK] 依赖已存在 (跳过)
)

REM ============================================================
REM Step 4: Check Ollama (optional)
REM ============================================================
if %NO_MCP%==1 goto :skip_ollama

echo.
echo [4/5] 检查 Ollama...

where ollama >nul 2>nul
if errorlevel 1 (
    echo   [WARN] 未检测到 Ollama
    echo.
    echo   MCP 攻击复现需要 Ollama。你可以:
    echo     1. 安装 Ollama: https://ollama.com
    echo     2. 拉取模型: ollama pull %MODEL%
    echo     3. 重新运行本脚本
    echo.
    echo   或者跳过 MCP 测试: scripts\run_demo.bat --no-mcp
    echo.
    set /p SKIP="  是否跳过 MCP 测试并继续? (y/n) "
    if /I "!SKIP!"=="y" (
        set NO_MCP=1
        echo   [OK] 跳过 MCP 测试
    ) else (
        echo   已取消
        pause
        exit /b 0
    )
) else (
    echo   [OK] Ollama 已安装

    REM 检查模型
    ollama list 2>nul | findstr /C:"%MODEL%" >nul
    if errorlevel 1 (
        echo   [WARN] 模型 %MODEL% 未找到，正在拉取...
        ollama pull %MODEL%
    ) else (
        echo   [OK] 模型 %MODEL% 已就绪
    )
)

:skip_ollama
if %NO_MCP%==1 (
    echo.
    echo [4/5] 跳过 MCP 测试 (--no-mcp)
)

REM ============================================================
REM Step 5: Run tests and generate report
REM ============================================================
echo.
echo [5/5] 运行测试并生成报告...
echo.

cd /d "%PROJECT_DIR%"

if %NO_MCP%==1 (
    python scripts\generate_report.py --no-mcp --model "%MODEL%" --output "%PROJECT_DIR%\report.html"
) else (
    python scripts\generate_report.py --model "%MODEL%" --output "%PROJECT_DIR%\report.html"
)

echo.
echo ============================================================
echo   测试完成!
echo ============================================================
echo.
echo   报告文件: %PROJECT_DIR%\report.html
echo.
echo   Tip: 也可以用以下命令单独运行各个演示:
echo     python demo\email_agent\run_demo.py
echo     python demo\rag_agent\run_demo.py
echo     python demo\mcp_agent\run_demo.py --model %MODEL%
echo.

REM 打开报告
start "" "%PROJECT_DIR%\report.html"

pause
