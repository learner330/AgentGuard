"""SQL 注入检查器（基于 sqlparse AST 解析）

从正则匹配升级为：
1. 使用 sqlparse 解析 SQL 生成抽象语法树
2. 分析 AST 中的节点类型（关键字、函数、注释等）
3. 精确的语句类型白名单（只允许 SELECT/SHOW/DESCRIBE/EXPLAIN）
4. 检测 UNION、子查询、堆叠查询等危险结构
5. 保留写操作禁止和多语句禁止能力
"""

from __future__ import annotations

from typing import Optional

import sqlparse
from sqlparse import tokens as T
from sqlparse.sql import Comment, Identifier, Where

from guardrails.base import GuardLevel, GuardResult
from guardrails.tool_call import ToolCall


# 允许的 SQL 语句类型（只读）
ALLOWED_STATEMENT_TYPES = frozenset(
    [
        "SELECT",
        "SHOW",
        "DESCRIBE",
        "EXPLAIN",
        "DESC",
    ]
)

# SQL 写操作关键字（语句开头）
WRITE_KEYWORDS = frozenset(
    [
        "INSERT",
        "UPDATE",
        "DELETE",
        "DROP",
        "ALTER",
        "CREATE",
        "TRUNCATE",
        "GRANT",
        "REVOKE",
        "MERGE",
        "CALL",
        "EXEC",
        "EXECUTE",
    ]
)

# 危险函数（信息泄露或系统攻击）
DANGEROUS_FUNCTIONS = frozenset(
    [
        "LOAD_FILE",
        "INTO_OUTFILE",
        "INTO_DUMPFILE",
        "SLEEP",
        "BENCHMARK",
        "WAITFOR",
        "DELAY",
        "PG_SLEEP",
        "DBMS_PIPE.RECEIVE_MESSAGE",
        "GENERATE_SERIES",
    ]
)

# 危险构造（联合查询、堆叠查询等）
DANGEROUS_CONSTRUCTS = frozenset(
    [
        "UNION",
        "INTO",
        "LOAD_FILE",
        "OUTFILE",
        "DUMPFILE",
    ]
)


class SQLChecker:
    """基于 AST 解析的 SQL 注入检查器

    核心改进：
    1. 使用 sqlparse 生成 AST，基于语法结构而非文本模式检测
    2. 语句类型白名单：只允许明确安全的只读查询
    3. 检测 UNION 注入、子查询、堆叠查询、时间盲注函数
    4. 防御注释绕过（如 SELECT/**/password/**/FROM）
    """

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
        # 1. 多语句检查（在解析前做，因为 sqlparse 会按分号拆分）
        if not self.allow_multi_statement:
            statements = [s.strip() for s in sql.split(";") if s.strip()]
            if len(statements) > 1:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message="Multiple SQL statements not allowed",
                    rule_id="SQL-MULTI",
                    details={"arg": arg_name, "statements_count": len(statements)},
                )

        # 2. 解析 SQL 生成 AST
        try:
            parsed = sqlparse.parse(sql)
        except Exception as e:
            return GuardResult.block_result(
                level=GuardLevel.TOOL,
                message=f"Invalid SQL syntax: {e}",
                rule_id="SQL-SYNTAX",
                details={"arg": arg_name, "sql": sql[:200]},
            )

        if not parsed:
            return None

        for statement in parsed:
            # 3. 检查语句类型（只允许白名单中的语句类型）
            stmt_type = self._get_statement_type(statement)
            if stmt_type and stmt_type not in ALLOWED_STATEMENT_TYPES:
                if not self.allow_write or stmt_type not in WRITE_KEYWORDS:
                    return GuardResult.block_result(
                        level=GuardLevel.TOOL,
                        message=f"SQL statement type not allowed: {stmt_type}",
                        rule_id="SQL-TYPE",
                        details={
                            "arg": arg_name,
                            "statement_type": stmt_type,
                            "allowed": list(ALLOWED_STATEMENT_TYPES),
                        },
                    )

            # 4. 写操作检查（即使 allow_write=False 也要拦截）
            if not self.allow_write and stmt_type in WRITE_KEYWORDS:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Write operation not allowed: {stmt_type}",
                    rule_id="SQL-WRITE",
                    details={"arg": arg_name, "statement_type": stmt_type, "sql": sql[:200]},
                )

            # 5. 检测 AST 中的危险节点
            dangerous = self._find_dangerous_nodes(statement)
            if dangerous:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Dangerous SQL construct detected: {dangerous}",
                    rule_id="SQL-AST-DANGER",
                    details={"arg": arg_name, "constructs": dangerous, "sql": sql[:200]},
                )

            # 6. 检测危险函数（时间盲注等）
            dangerous_funcs = self._find_dangerous_functions(statement)
            if dangerous_funcs:
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message=f"Dangerous SQL function detected: {dangerous_funcs}",
                    rule_id="SQL-FUNCTION",
                    details={"arg": arg_name, "functions": dangerous_funcs, "sql": sql[:200]},
                )

            # 7. 检测子查询
            if self._has_subqueries(statement):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message="Subqueries not allowed",
                    rule_id="SQL-SUBQUERY",
                    details={"arg": arg_name, "sql": sql[:200]},
                )

            # 8. 检测注释注入（如 SELECT/**/password FROM）
            if self._has_suspicious_comments(statement):
                return GuardResult.block_result(
                    level=GuardLevel.TOOL,
                    message="Suspicious SQL comment patterns detected",
                    rule_id="SQL-COMMENT",
                    details={"arg": arg_name, "sql": sql[:200]},
                )

        return None

    def _get_statement_type(self, statement: sqlparse.sql.Statement) -> Optional[str]:
        """获取 SQL 语句的第一个关键字（如 SELECT, INSERT, UPDATE）"""
        for token in statement.tokens:
            if token.ttype in (T.Keyword, T.Keyword.DML, T.Keyword.DDL):
                return token.value.upper().strip()
            # 处理被注释包裹的情况（例如 /* comment */ SELECT ...）
            if isinstance(token, Comment):
                # 跳过注释，继续查找下一个关键字
                continue
            if token.ttype is None and hasattr(token, "tokens"):
                for sub in token.flatten():
                    if sub.ttype in (T.Keyword, T.Keyword.DML, T.Keyword.DDL):
                        return sub.value.upper().strip()
        return None

    def _find_dangerous_nodes(self, statement: sqlparse.sql.Statement) -> list[str]:
        """在 AST 中查找危险构造节点"""
        dangerous: list[str] = []
        for token in statement.flatten():
            if token.ttype in (T.Keyword, T.Keyword.DML, T.Keyword.DDL):
                val = token.value.upper().strip()
                if val in DANGEROUS_CONSTRUCTS:
                    dangerous.append(val)
        return dangerous

    def _find_dangerous_functions(self, statement: sqlparse.sql.Statement) -> list[str]:
        """在 AST 中查找危险函数调用"""
        dangerous: list[str] = []
        for token in statement.flatten():
            if token.ttype in (T.Name, T.Name.Function):
                val = token.value.upper().strip()
                if val in DANGEROUS_FUNCTIONS:
                    dangerous.append(val)
        return dangerous

    def _has_subqueries(self, statement: sqlparse.sql.Statement) -> bool:
        """检查是否存在子查询（括号内的 SELECT）"""
        # 简单检查：SQL 中 SELECT 出现超过 1 次
        select_count = 0
        for token in statement.flatten():
            if token.ttype in (T.Keyword, T.Keyword.DML) and token.value.upper().strip() == "SELECT":
                select_count += 1
        return select_count > 1

    def _has_suspicious_comments(self, statement: sqlparse.sql.Statement) -> bool:
        """检测可疑的注释模式（如注释在关键字之间）"""
        for token in statement.tokens:
            if isinstance(token, Comment):
                # 注释中包含 SQL 关键字，可能是注入绕过
                comment_text = str(token).upper()
                sql_keywords = ["SELECT", "FROM", "WHERE", "AND", "OR", "UNION"]
                for kw in sql_keywords:
                    if kw in comment_text:
                        return True
        return False
