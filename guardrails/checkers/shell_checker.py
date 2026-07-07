"""Shell 命令安全检查器"""

from __future__ import annotations

import re
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# 危险命令黑名单
DANGEROUS_COMMANDS: list[tuple[str, str]] = [
    (r"\brm\s+(-[rfRF]+\s+)?(/|\*|\.)", "SHELL-001"),
    (r"\bchmod\s+777", "SHELL-002"),
    (r"\bmkfs\.", "SHELL-003"),
    (r"\bdd\s+if=", "SHELL-004"),
    (r"\b(shutdown|reboot|halt|poweroff)\b", "SHELL-005"),
    (r"\b(crontab|at\s+)\b", "SHELL-006"),
    (r"\biptables\s+", "SHELL-007"),
    (r"\b(useradd|userdel|usermod)\b", "SHELL-008"),
    (r"\b(curl|wget)\s+.*\|.*sh", "SHELL-009"),
    (r"\bnc\s+(-[a-z]*e|l)", "SHELL-010"),
    (r"\bpython\s+-c\s", "SHELL-011"),
    (r"\bperl\s+-e\s", "SHELL-012"),
    (r"\bexec\s+/bin/(ba)?sh", "SHELL-013"),
    (r"\b/dev/(tcp|udp)/", "SHELL-014"),
    (r"\b(chown|chgrp)\s+(-R\s+)?/", "SHELL-015"),
]

# 命令注入模式
INJECTION_PATTERNS: list[tuple[str, str]] = [
    (r"[;&|]\s*rm\b", "SHELL-A01"),
    (r"\$\(.*rm\b", "SHELL-A02"),
    (r"`[^`]*rm[^`]*`", "SHELL-A03"),
    (r">\s*/dev/", "SHELL-A04"),
]


class ShellChecker:
    """Shell 命令安全检查器"""

    def __init__(self, extra_blocked: Optional[list[str]] = None) -> None:
        self._compiled_cmds = [
            (re.compile(p), rule_id) for p, rule_id in DANGEROUS_COMMANDS
        ]
        self._compiled_injection = [
            (re.compile(p), rule_id) for p, rule_id in INJECTION_PATTERNS
        ]
        self._extra_blocked = extra_blocked or []

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查 shell 命令"""
        cmd_keys = ["command", "cmd", "script", "shell"]
        for key in cmd_keys:
            if key in call.tool_args and isinstance(call.tool_args[key], str):
                result = self._check_command(key, call.tool_args[key])
                if result:
                    return result
        return None

    def _check_command(self, arg_name: str, cmd: str) -> Optional[GuardResult]:
        """检查单个命令"""
        # 危险命令检测
        for pattern, rule_id in self._compiled_cmds:
            if pattern.search(cmd):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Dangerous command blocked: {cmd[:50]}...",
                    rule_id=rule_id,
                    details={"arg": arg_name, "command": cmd},
                )

        # 命令注入检测
        for pattern, rule_id in self._compiled_injection:
            if pattern.search(cmd):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Command injection detected: {cmd[:50]}...",
                    rule_id=rule_id,
                    details={"arg": arg_name, "command": cmd},
                )

        # 自定义黑名单
        for blocked in self._extra_blocked:
            if blocked in cmd:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Blocked pattern: {blocked}",
                    rule_id="SHELL-CUSTOM",
                    details={"arg": arg_name, "command": cmd},
                )

        return None
