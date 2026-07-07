"""第四层：输出围栏 OutputGuard

过滤最终输出中的敏感信息泄露。

检测内容：
- 结构化敏感信息：手机号、身份证、银行卡号、邮箱
- 密钥 / Token：API Key、JWT、SSH 私钥、密码
- 系统信息泄露：System Prompt 内容
- 非预期数据外带
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Optional

from guardrails.base import (
    BaseGuard,
    GuardLevel,
    GuardResult,
    GuardSeverity,
)


# ============ 敏感数据正则模式 ============

# 中国手机号（11位，1开头）
PHONE_PATTERN = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")

# 中国身份证号（18位）
ID_CARD_PATTERN = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")

# 银行卡号（13-19位数字）
BANK_CARD_PATTERN = re.compile(r"(?<!\d)\d{13,19}(?!\d)")

# 邮箱
EMAIL_PATTERN = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

# API Key / Token 模式
API_KEY_PATTERNS: list[tuple[str, str]] = [
    (r"sk-[a-zA-Z0-9]{20,}", "API-OPENAI"),          # OpenAI API Key
    (r"AKIA[0-9A-Z]{16}", "API-AWS"),                 # AWS Access Key
    (r"AIza[0-9A-Za-z_-]{35}", "API-GOOGLE"),         # Google API Key
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "API-GITHUB"),   # GitHub Token
    (r"<jwt>", "API-JWT"),                             # JWT placeholder
    (r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "API-SSHKEY"),
]

# JWT 完整格式
JWT_PATTERN = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)

# 密码模式（password=xxx, pwd=xxx 等）
PASSWORD_PATTERNS: list[tuple[str, str]] = [
    (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+", "PWD-001"),
    (r"(?i)(secret|access[_-]?token|api[_-]?key)\s*[:=]\s*\S+", "PWD-002"),
]


class OutputMasker:
    """敏感数据脱敏处理器"""

    @staticmethod
    def mask_phone(match: re.Match) -> str:
        """手机号脱敏: 138****5678"""
        text = match.group(0)
        if len(text) == 11:
            return text[:3] + "****" + text[7:]
        return "*" * len(text)

    @staticmethod
    def mask_id_card(match: re.Match) -> str:
        """身份证脱敏: 110101********1234"""
        text = match.group(0)
        if len(text) == 18:
            return text[:6] + "********" + text[14:]
        return "*" * len(text)

    @staticmethod
    def mask_bank_card(match: re.Match) -> str:
        """银行卡脱敏: **** **** **** 1234"""
        text = match.group(0)
        return "*" * (len(text) - 4) + text[-4:]

    @staticmethod
    def mask_email(match: re.Match) -> str:
        """邮箱脱敏: a***@example.com"""
        text = match.group(0)
        local, domain = text.split("@", 1)
        if len(local) <= 2:
            return f"*{local[1:]}@{domain}"
        return f"{local[0]}***@{domain}"

    @staticmethod
    def mask_api_key(match: re.Match) -> str:
        """API Key 脱敏: sk-***xyz"""
        text = match.group(0)
        if len(text) > 6:
            return text[:3] + "***" + text[-3:]
        return "*" * len(text)


class OutputGuard(BaseGuard):
    """第四层：输出围栏

    在 Agent 最终输出返回用户之前，过滤敏感信息泄露。

    使用方式：
        guard = OutputGuard()

        # 仅检测
        result = await guard.check("你的手机号是 13812345678")

        # 脱敏输出
        masked_text = guard.mask_sensitive("你的手机号是 13812345678")
        # "你的手机号是 138****5678"
    """

    def __init__(
        self,
        enabled: bool = True,
        config: Optional[dict[str, Any]] = None,
        system_prompt: Optional[str] = None,
        mask_output: bool = True,
    ) -> None:
        super().__init__(level=GuardLevel.OUTPUT, enabled=enabled, config=config)
        self.mask_output = mask_output
        self.system_prompt = system_prompt
        self.masker = OutputMasker()

        # 编译 API Key 模式
        self._compiled_api_patterns = [
            (re.compile(p), name) for p, name in API_KEY_PATTERNS
        ]
        self._compiled_pwd_patterns = [
            (re.compile(p), rule_id) for p, rule_id in PASSWORD_PATTERNS
        ]

        # 如果提供了 System Prompt，预计算关键词用于检测泄露
        self._system_prompt_hashes: set[str] = set()
        if system_prompt:
            self._system_prompt_hashes = self._compute_prompt_hashes(system_prompt)

    def _compute_prompt_hashes(self, prompt: str) -> set[str]:
        """计算 System Prompt 中关键句子的哈希（用于检测泄露）"""
        hashes: set[str] = set()
        # 按句子分割
        sentences = re.split(r"[。！？.!?\n]", prompt)
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) > 20:  # 只处理有意义的长句子
                h = hashlib.md5(sentence.encode()).hexdigest()
                hashes.add(h)
        return hashes

    async def check(self, data: Any, context: Optional[dict[str, Any]] = None) -> GuardResult:
        """检测输出中的敏感信息

        Args:
            data: 输出文本
            context: 额外上下文

        Returns:
            GuardResult: PASS / WARN (含敏感信息)
        """
        if not self.enabled:
            return GuardResult.pass_result(level=self.level, message="guard disabled")

        if not isinstance(data, str):
            data = str(data)

        if not data.strip():
            return GuardResult.pass_result(level=self.level, message="empty output")

        findings: list[dict[str, Any]] = []

        # 1. 手机号检测
        phone_matches = PHONE_PATTERN.findall(data)
        if phone_matches:
            findings.append({"type": "phone", "count": len(phone_matches)})

        # 2. 身份证检测
        id_matches = ID_CARD_PATTERN.findall(data)
        if id_matches:
            findings.append({"type": "id_card", "count": len(id_matches)})

        # 3. 银行卡检测
        bank_matches = BANK_CARD_PATTERN.findall(data)
        if bank_matches:
            findings.append({"type": "bank_card", "count": len(bank_matches)})

        # 4. 邮箱检测
        email_matches = EMAIL_PATTERN.findall(data)
        if email_matches:
            findings.append({"type": "email", "count": len(email_matches)})

        # 5. API Key / Token 检测
        for pattern, name in self._compiled_api_patterns:
            if pattern.search(data):
                findings.append({"type": "api_key", "subtype": name})
                break

        # 6. JWT 检测
        if JWT_PATTERN.search(data):
            findings.append({"type": "jwt"})

        # 7. 密码泄露检测
        for pattern, rule_id in self._compiled_pwd_patterns:
            if pattern.search(data):
                findings.append({"type": "password", "rule_id": rule_id})
                break

        # 8. System Prompt 泄露检测
        if self._system_prompt_hashes:
            prompt_leak = self._detect_prompt_leak(data)
            if prompt_leak:
                findings.append({"type": "system_prompt_leak"})

        if findings:
            types = list(set(f.get("type", "unknown") for f in findings))
            return GuardResult.warn_result(
                level=self.level,
                message=f"Sensitive data in output: {types}",
                rule_id="OUTPUT-SENSITIVE",
                details={"findings": findings, "output_length": len(data)},
            )

        return GuardResult.pass_result(level=self.level, message="output is clean")

    def mask_sensitive(self, text: str) -> str:
        """对文本中的敏感数据进行脱敏"""
        if not text:
            return text

        # 脱敏顺序：先长后短，避免重叠
        # 1. 身份证（18位）
        text = ID_CARD_PATTERN.sub(self.masker.mask_id_card, text)
        # 2. 银行卡（13-19位）
        text = BANK_CARD_PATTERN.sub(self.masker.mask_bank_card, text)
        # 3. 手机号（11位）
        text = PHONE_PATTERN.sub(self.masker.mask_phone, text)
        # 4. 邮箱
        text = EMAIL_PATTERN.sub(self.masker.mask_email, text)
        # 5. API Key / Token
        for pattern, _ in self._compiled_api_patterns:
            text = pattern.sub(self.masker.mask_api_key, text)
        # 6. JWT
        text = JWT_PATTERN.sub(lambda m: m.group(0)[:6] + "***", text)
        # 7. 密码
        for pattern, _ in self._compiled_pwd_patterns:
            text = pattern.sub(lambda m: m.group(0).split("=")[0] + "=***", text)

        return text

    def _detect_prompt_leak(self, output: str) -> bool:
        """检测输出中是否包含 System Prompt 内容"""
        # 方法1：哈希匹配
        sentences = re.split(r"[。！？.!?\n]", output)
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) > 20:
                h = hashlib.md5(sentence.encode()).hexdigest()
                if h in self._system_prompt_hashes:
                    return True
        return False
