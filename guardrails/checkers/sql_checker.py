"""SQL 注入检查器"""

from __future__ import annotations

import re
from typing import Optional

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall

# SQL 注入模式
SQL_INJECTION_PATTERNS: list[tuple[str, str]] = [
    # 逻辑绕过
    (r"'\s*(OR|AND)\s+'?\d+'?\s*=\s*'?\d+", "SQL-001"),
    (r"'\s*(OR|AND)\s+'[^']*'\s*=\s*'", "SQL-002"),
    (r"\b(OR|AND)\s+1\s*=\s*1", "SQL-003"),
    (r"'\s*;\s*--", "SQL-004"),
    # 堆叠查询
    (r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b.*\b(INTO|TABLE|DATABASE)\b", "SQL-005"),
    (r";\s*(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\b", "SQL-006"),
    # 时间盲注
    (r"\b(SLEEP|BENCHMARK|WAITFOR|DELAY)\s*\(", "SQL-007"),
    # 联合查询
    (r"\bUNION\s+(ALL\s+)?SELECT\b", "SQL-008"),
    # 错误注入
    (r"\b(EXTRACTVALUE|UPDATEXML|FLOOR|RAND)\s*\(", "SQL-009"),
    # 信息获取
    (r"\b(INFORMATION_SCHEMA|SYSOBJECTS|SYSCOLUMNS)\b", "SQL-010"),
    (r"\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b", "SQL-011"),
    (r"\bSLEEP\s*\(\s*\d+\s*\)", "SQL-012"),
    # 编码绕过
    (r"(0x[0-9a-fA-F]+|CHAR\s*\()", "SQL-013"),
]


class SQLChecker:
    """SQL 注入检查器"""

    def __init__(
        self,
        allow_write: bool = False,
        allow_multi_statement: bool = False,
    ) -> None:
        """
        Args:
            allow_write: 是否允许写操作（INSERT/UPDATE/DELETE/DROP）
            allow_multi_statement: 是否允许多语句执行（分号分隔）
        """
        self.allow_write = allow_write
        self.allow_multi_statement = allow_multi_statement
        self._compiled_patterns = [
            (re.compile(p, re.IGNORECASE), rule_id) for p, rule_id in SQL_INJECTION_PATTERNS
        ]

    def check(self, call: ToolCall) -> Optional[GuardResult]:
        """检查 SQL 查询"""
        sql_keys = ["query", "sql", "statement", "db_query"]
        for key in sql_keys:
            if key in call.tool_args and isinstance(call.tool_args[key], str):
                result = self._check_sql(key, call.tool_args[key])
                if result:
                    return result
        return None

    def _check_sql(self, arg_name: str, sql: str) -> Optional[GuardResult]:
        """检查单个 SQL 语句"""
        # SQL 注入模式检测
        for pattern, rule_id in self._compiled_patterns:
            if pattern.search(sql):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"SQL injection pattern detected: {sql[:50]}...",
                    rule_id=rule_id,
                    details={"arg": arg_name, "sql": sql},
                )

        # 多语句检查
        if not self.allow_multi_statement:
            if ";" in sql and sql.strip().endswith(";"):
                # 检查分号后是否有额外语句
                parts = [p.strip() for p in sql.split(";") if p.strip()]
                if len(parts) > 1:
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message="Multiple SQL statements not allowed",
                        rule_id="SQL-MULTI",
                        details={"arg": arg_name, "sql": sql},
                    )

        # 写操作检查
        if not self.allow_write:
            write_keywords = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE"]
            sql_upper = sql.upper().strip()
            for kw in write_keywords:
                if sql_upper.startswith(kw):
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"Write operation not allowed: {kw}",
                        rule_id="SQL-WRITE",
                        details={"arg": arg_name, "sql": sql},
                    )

        return None
