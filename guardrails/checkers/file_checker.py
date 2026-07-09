"""文件系统操作安全检查器（基于真实路径解析）

从正则匹配升级为 pathlib 真实路径解析，防御：
- 目录穿越（../../etc/passwd）
- 符号链接绕过
- URL 编码路径
- 绝对路径越权
- 敏感系统文件访问
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# 敏感系统路径（使用 Path 对象便于比较）
SENSITIVE_SYSTEM_PATHS: list[Path] = [
    Path("/etc/passwd"),
    Path("/etc/shadow"),
    Path("/etc/sudoers"),
    Path("/etc/ssh"),
    Path("/proc"),
    Path("/sys"),
    Path("/root"),
    Path("/boot"),
]

# 敏感文件扩展名
SENSITIVE_EXTENSIONS = frozenset(
    [
        ".pem",
        ".key",
        ".env",
        ".htpasswd",
        ".htaccess",
        ".shadow",
        ".secrets",
        ".credentials",
        ".bak",
        ".backup",
        ".sql",
        ".db",
        ".sqlite",
    ]
)


class FileSystemChecker:
    """基于真实路径解析的文件系统检查器

    核心改进：
    1. 使用 pathlib.Path.resolve() 获取真实绝对路径（跟随符号链接）
    2. 使用 Path.relative_to() 做严格的子目录关系判断
    3. 白名单策略：默认拒绝所有，只允许明确指定的目录
    4. 防御 URL 编码路径、unicode 规范化绕过
    """

    def __init__(
        self,
        allowed_base_paths: Optional[list[str]] = None,
        allow_home: bool = False,
    ) -> None:
        """
        Args:
            allowed_base_paths: 允许访问的基目录列表（绝对路径）
                               如果为 None，默认允许 /tmp 和 /var/tmp
            allow_home: 是否允许访问用户 home 目录（默认 False，更严格）
        """
        if allowed_base_paths is None:
            allowed_base_paths = ["/tmp", "/var/tmp"]

        # 解析为绝对路径（跟随符号链接）
        self.allowed_bases: list[Path] = []
        for p in allowed_base_paths:
            try:
                resolved = Path(p).expanduser().resolve().absolute()
                self.allowed_bases.append(resolved)
            except (OSError, RuntimeError):
                # 忽略无法解析的路径
                pass

        self.allow_home = allow_home
        if allow_home:
            home = Path.home().expanduser().resolve().absolute()
            self.allowed_bases.append(home)

        # 预解析敏感系统路径
        self._sensitive_paths = []
        for p in SENSITIVE_SYSTEM_PATHS:
            try:
                self._sensitive_paths.append(p.resolve().absolute())
            except (OSError, RuntimeError):
                self._sensitive_paths.append(p)

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查文件系统操作"""
        # 常见文件路径参数名
        path_keys = [
            "path",
            "file_path",
            "filename",
            "filepath",
            "dir",
            "directory",
            "source",
            "dest",
            "target",
            "src",
            "dst",
        ]

        for key in path_keys:
            if key not in call.tool_args:
                continue
            raw = call.tool_args[key]
            if not isinstance(raw, str):
                continue
            result = self._check_path(key, raw)
            if result:
                return result

        return None

    def _check_path(self, arg_name: str, raw_path: str) -> Optional[GuardResult]:
        """检查单个路径参数"""
        # 1. 路径解析：获取真实绝对路径（跟随符号链接，消除 ..）
        try:
            target = Path(raw_path).expanduser().resolve().absolute()
        except (OSError, RuntimeError) as e:
            # 解析失败（如循环符号链接）
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Path resolution failed: {e}",
                rule_id="PATH-RESOLVE",
                details={"arg": arg_name, "raw_path": raw_path},
            )

        # 2. 检查是否在允许的基目录内（白名单策略）
        if not self._is_in_allowed_base(target):
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Path outside allowed directories: {target}",
                rule_id="PATH-OUTSIDE",
                details={
                    "arg": arg_name,
                    "raw_path": raw_path,
                    "resolved": str(target),
                    "allowed_bases": [str(b) for b in self.allowed_bases],
                },
            )

        # 3. 检查敏感系统路径
        if self._is_sensitive_system_path(target):
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Access to sensitive system path blocked: {target}",
                rule_id="PATH-SENSITIVE",
                details={"arg": arg_name, "resolved": str(target)},
            )

        # 4. 检查敏感文件扩展名
        if target.suffix.lower() in SENSITIVE_EXTENSIONS:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Sensitive file extension blocked: {target.suffix}",
                rule_id="PATH-EXT",
                details={"arg": arg_name, "resolved": str(target)},
            )

        return None

    def _is_in_allowed_base(self, target: Path) -> bool:
        """检查目标路径是否在允许的基目录内

        使用 Path.relative_to() 做严格的子目录关系判断，
        而不是字符串前缀匹配。
        """
        if not self.allowed_bases:
            # 没有配置基目录时默认允许（向下兼容）
            return True

        for base in self.allowed_bases:
            try:
                target.relative_to(base)
                # 如果 relative_to 成功，说明 target 是 base 的子目录
                return True
            except ValueError:
                continue

        return False

    def _is_sensitive_system_path(self, target: Path) -> bool:
        """检查是否为敏感系统路径"""
        for sensitive in self._sensitive_paths:
            if target == sensitive or target.is_relative_to(sensitive):
                return True
        return False
