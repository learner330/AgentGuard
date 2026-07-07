"""文件操作安全检查器

检测目录穿越、敏感系统文件访问、敏感扩展名、路径白名单等。
"""

from __future__ import annotations

import os
import re
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# 危险的路径模式
DANGEROUS_PATH_PATTERNS: list[tuple[str, str]] = [
    (r"\.\./", "PATH-001"),              # 目录穿越
    (r"\.\.\\", "PATH-001"),
    (r"\.\.\\\\", "PATH-001"),
    (r"/etc/(passwd|shadow|hosts)", "PATH-002"),  # 敏感系统文件
    (r"/proc/", "PATH-003"),             # proc 文件系统
    (r"/sys/", "PATH-004"),              # sys 文件系统
    (r"/dev/", "PATH-005"),              # dev 文件系统
    (r"C:\\Windows\\System32", "PATH-006"),  # Windows 系统目录
    (r"\.(ssh|gnupg|aws|docker)", "PATH-007"),  # 敏感配置目录
]

# 敏感文件扩展名
SENSITIVE_EXTENSIONS = {
    ".pem", ".key", ".p12", ".pfx",  # 证书
    ".env", ".secret",                # 配置
    ".shadow", ".passwd",             # 密码
}


class FileSystemChecker:
    """文件操作安全检查器"""

    def __init__(
        self,
        allowed_paths: Optional[list[str]] = None,
        blocked_paths: Optional[list[str]] = None,
        allow_sensitive_ext: bool = False,
    ) -> None:
        self.allowed_paths = allowed_paths or []
        self.blocked_paths = blocked_paths or ["/etc", "/proc", "/sys", "/dev"]
        self.allow_sensitive_ext = allow_sensitive_ext
        self._compiled_patterns = [
            (re.compile(p), rule_id) for p, rule_id in DANGEROUS_PATH_PATTERNS
        ]

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查文件操作"""
        # 提取路径参数
        path_keys = ["path", "file_path", "filepath", "src", "dest", "src_path", "dest_path"]
        paths: list[tuple[str, str]] = []
        for key in path_keys:
            if key in call.tool_args and isinstance(call.tool_args[key], str):
                paths.append((key, call.tool_args[key]))

        if not paths:
            return None

        for arg_name, path in paths:
            result = self._check_path(arg_name, path)
            if result:
                return result
        return None

    def _check_path(self, arg_name: str, path: str) -> Optional[GuardResult]:
        """检查单个路径"""
        # 1. 目录穿越检测
        if ".." in path or "~" in path:
            normalized = os.path.normpath(path)
            if ".." in path.split(os.sep):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Directory traversal detected in '{arg_name}': {path}",
                    rule_id="PATH-001",
                    details={"arg": arg_name, "path": path},
                )

        # 2. 已知危险模式检测
        for pattern, rule_id in self._compiled_patterns:
            if pattern.search(path):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Dangerous path pattern in '{arg_name}': {path}",
                    rule_id=rule_id,
                    details={"arg": arg_name, "path": path, "matched": pattern.pattern},
                )

        # 3. 敏感扩展名检测
        if not self.allow_sensitive_ext:
            ext = os.path.splitext(path)[1].lower()
            if ext in SENSITIVE_EXTENSIONS:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Access to sensitive file type blocked: {path}",
                    rule_id="PATH-008",
                    details={"arg": arg_name, "path": path, "extension": ext},
                )

        # 4. 路径白名单检查
        if self.allowed_paths:
            is_allowed = False
            for allowed in self.allowed_paths:
                if path.startswith(allowed):
                    is_allowed = True
                    break
            if not is_allowed:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Path '{path}' not in allowed paths list",
                    rule_id="PATH-009",
                    details={"arg": arg_name, "path": path},
                )

        return None
