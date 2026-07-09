"""Shell 命令安全检查器（基于语法解析 + 白名单）

从正则黑名单升级为：
1. shlex 语法解析：正确拆分命令结构
2. 命令白名单：只允许明确安全的命令
3. 危险元字符检测：管道、重定向、子 shell 等
4. 保留敏感文件访问检测（行为层面）
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall


# 命令白名单：只允许这些命令执行
# 企业可根据实际需求扩展，但保持最小权限原则
DEFAULT_ALLOWED_COMMANDS = frozenset(
    [
        "ls",
        "cat",
        "grep",
        "find",
        "wc",
        "head",
        "tail",
        "sort",
        "uniq",
        "awk",
        "sed",
        "cut",
        "tr",
        "echo",
        "printf",
        "date",
        "whoami",
        "id",
        "pwd",
        "which",
        "file",
        "stat",
        "md5sum",
        "sha256sum",
        "tar",
        "zip",
        "unzip",
        "gzip",
        "gunzip",
        "diff",
        "comm",
    ]
)

# Shell 危险元字符（阻止命令链和子 shell）
DANGEROUS_METACHARACTERS = frozenset(
    [
        "|",      # 管道
        ";",      # 顺序执行
        "&",      # 后台 / 逻辑与
        "&&",     # 逻辑与
        "||",     # 逻辑或
        ">",      # 输出重定向
        ">>",     # 追加重定向
        "<",      # 输入重定向
        "<<",     # here document
        "`",      # 命令替换
        "$",      # 变量扩展（在 tokens 中检测）
        "(",      # 子 shell
        ")",
        "{",      # 代码块
        "}",
    ]
)

# 系统敏感文件路径（行为层面检测）
SENSITIVE_SYSTEM_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh",
    "/proc",
    "/sys",
    "/root",
    "/var/log",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/.aws/credentials",
    "/.env",
]


class ShellChecker:
    """基于语法解析的 Shell 命令安全检查器

    核心改进：
    1. 使用 shlex 做 Shell 语法解析，正确识别命令结构
    2. 白名单策略：只允许明确安全的命令，拒绝所有其他命令
    3. 检测危险元字符（管道、重定向、子 shell、命令替换）
    4. 检测通过 Shell 访问敏感文件的行为
    5. 阻止 Python/Node/Perl 等内嵌脚本执行
    """

    def __init__(
        self,
        allowed_commands: Optional[set[str]] = None,
        allow_redirect: bool = False,
        allow_pipe: bool = False,
    ) -> None:
        """
        Args:
            allowed_commands: 允许执行的命令白名单（默认 DEFAULT_ALLOWED_COMMANDS）
            allow_redirect: 是否允许重定向（默认 False，安全优先）
            allow_pipe: 是否允许管道（默认 False，安全优先）
        """
        self.allowed_commands = allowed_commands or DEFAULT_ALLOWED_COMMANDS
        self.allow_redirect = allow_redirect
        self.allow_pipe = allow_pipe

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查 Shell 命令"""
        cmd = call.tool_args.get("command", "")
        if not isinstance(cmd, str) or not cmd.strip():
            return None

        # 1. 语法解析：使用 shlex 正确拆分命令
        try:
            tokens = shlex.split(cmd, comments=True, posix=True)
        except ValueError:
            # 语法错误（如不匹配引号）
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message="Malformed shell command (syntax error)",
                rule_id="SHELL-SYNTAX",
                details={"command": cmd[:200]},
            )

        if not tokens:
            return None

        # 2. 检测危险元字符（原始字符串层面）
        meta_result = self._check_metacharacters(cmd)
        if meta_result:
            return meta_result

        # 3. 提取并检查命令名（去除路径）
        base_cmd = Path(tokens[0]).name

        # 4. 白名单检查：不在白名单中的命令一律拒绝
        if base_cmd not in self.allowed_commands:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Command not in whitelist: {base_cmd}",
                rule_id="SHELL-WHITELIST",
                details={
                    "command": base_cmd,
                    "allowed": sorted(list(self.allowed_commands)),
                },
            )

        # 5. 检测通过 Shell 访问敏感系统文件
        # 即使命令在白名单中，如果参数是敏感文件，也要拦截
        sensitive_result = self._check_sensitive_file_access(tokens)
        if sensitive_result:
            return sensitive_result

        # 6. 检测内嵌脚本执行（python -c, node -e, perl -e 等）
        script_result = self._check_inline_execution(base_cmd, tokens)
        if script_result:
            return script_result

        return None

    def _check_metacharacters(self, cmd: str) -> Optional[GuardResult]:
        """检测危险 Shell 元字符

        在原始字符串中检测，因为 shlex 已经做过解析，
        但我们需要确认解析前的命令是否包含危险的 Shell 构造。
        """
        # 管道检测
        if "|" in cmd and not self.allow_pipe:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message="Shell pipelines not allowed",
                rule_id="SHELL-PIPE",
                details={"command": cmd[:200]},
            )

        # 重定向检测
        if not self.allow_redirect:
            for ch in [">>", ">", "<", "<<"]:
                if ch in cmd:
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Shell redirection ({ch}) not allowed",
                        rule_id="SHELL-REDIRECT",
                        details={"command": cmd[:200]},
                    )

        # 子 shell 检测
        if "$(" in cmd or "${" in cmd:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message="Command substitution not allowed",
                rule_id="SHELL-SUBST",
                details={"command": cmd[:200]},
            )

        # 反引号检测
        if "`" in cmd:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message="Backtick command substitution not allowed",
                rule_id="SHELL-BACKTICK",
                details={"command": cmd[:200]},
            )

        # 逻辑运算符检测
        if ";" in cmd or "&&" in cmd or "||" in cmd:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message="Shell command chaining not allowed",
                rule_id="SHELL-CHAIN",
                details={"command": cmd[:200]},
            )

        return None

    def _check_sensitive_file_access(self, tokens: list[str]) -> Optional[GuardResult]:
        """检查命令参数是否包含敏感系统文件路径"""
        # 将所有参数拼接为字符串，检查敏感路径
        args_text = " ".join(tokens[1:])
        args_lower = args_text.lower()

        for sensitive in SENSITIVE_SYSTEM_PATHS:
            if sensitive.lower() in args_lower:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Shell command targeting sensitive file: {sensitive}",
                    rule_id="SHELL-SENSITIVE",
                    details={"sensitive_path": sensitive},
                )
        return None

    def _check_inline_execution(self, base_cmd: str, tokens: list[str]) -> Optional[GuardResult]:
        """检测内嵌脚本执行（Python, Node, Perl, Ruby, PHP 等）"""
        # 命令本身就是脚本解释器
        script_interpreters = {
            "python", "python3", "python2",
            "node", "nodejs",
            "perl", "ruby",
            "php", "php7", "php8",
            "bash", "sh", "zsh", "csh", "tcsh",
            "eval", "exec",
        }

        if base_cmd in script_interpreters:
            # 检查是否带有内嵌执行参数
            dangerous_flags = {"-c", "-e", "--eval", "--exec"}
            for token in tokens[1:]:
                if token in dangerous_flags:
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Inline {base_cmd} execution not allowed",
                        rule_id="SHELL-INLINE",
                        details={"interpreter": base_cmd, "flag": token},
                    )

            # 如果脚本解释器访问了敏感文件，也拦截
            # 例如：python script.py 访问敏感文件（在文件检查器层面处理更合理）
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Script interpreter execution not allowed: {base_cmd}",
                rule_id="SHELL-INTERPRETER",
                details={"interpreter": base_cmd},
            )

        return None
