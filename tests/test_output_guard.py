"""OutputGuard 单元测试"""

import pytest

from guardrails.base import GuardSeverity
from guardrails.output_guard import OutputGuard


@pytest.fixture
def guard() -> OutputGuard:
    return OutputGuard()


# ============ 手机号检测与脱敏 ============

class TestPhoneDetection:
    @pytest.mark.asyncio
    async def test_chinese_phone(self, guard: OutputGuard) -> None:
        result = await guard.check("联系人：13812345678")
        assert result.severity == GuardSeverity.WARN

    def test_phone_masking(self, guard: OutputGuard) -> None:
        masked = guard.mask_sensitive("我的手机号是13812345678，请记下")
        assert "138****5678" in masked

    @pytest.mark.asyncio
    async def test_not_phone(self, guard: OutputGuard) -> None:
        result = await guard.check("短数字 12345 不是手机号")
        assert result.severity == GuardSeverity.PASS


class TestIdCardDetection:
    @pytest.mark.asyncio
    async def test_id_card(self, guard: OutputGuard) -> None:
        result = await guard.check("身份证号：110101199001011234")
        assert result.severity == GuardSeverity.WARN

    def test_id_card_masking(self, guard: OutputGuard) -> None:
        masked = guard.mask_sensitive("身份证：110101199001011234")
        assert "110101********1234" in masked


class TestBankCardDetection:
    @pytest.mark.asyncio
    async def test_bank_card(self, guard: OutputGuard) -> None:
        result = await guard.check("银行卡：6222021234567890123")
        assert result.severity == GuardSeverity.WARN


class TestEmailDetection:
    @pytest.mark.asyncio
    async def test_email(self, guard: OutputGuard) -> None:
        result = await guard.check("发送到 admin@example.com")
        assert result.severity == GuardSeverity.WARN

    def test_email_masking(self, guard: OutputGuard) -> None:
        masked = guard.mask_sensitive("联系 admin@example.com")
        assert "***@example.com" in masked


class TestApiKeyDetection:
    @pytest.mark.asyncio
    async def test_openai_key(self, guard: OutputGuard) -> None:
        result = await guard.check("key: sk-abcdefghijklmnopqrstuvwxyz123456")
        assert result.severity == GuardSeverity.WARN

    @pytest.mark.asyncio
    async def test_jwt(self, guard: OutputGuard) -> None:
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123signature"
        result = await guard.check(f"token: {jwt}")
        assert result.severity == GuardSeverity.WARN

    @pytest.mark.asyncio
    async def test_ssh_key(self, guard: OutputGuard) -> None:
        result = await guard.check("key: -----BEGIN RSA PRIVATE KEY-----")
        assert result.severity == GuardSeverity.WARN


class TestPasswordDetection:
    @pytest.mark.asyncio
    async def test_password(self, guard: OutputGuard) -> None:
        result = await guard.check("password=supersecret123")
        assert result.severity == GuardSeverity.WARN


class TestSystemPromptLeak:
    @pytest.mark.asyncio
    async def test_prompt_leak(self) -> None:
        prompt = "你是一个专为金融服务设计的 AI助手，你必须遵守银行安全规范并验证用户身份"
        guard = OutputGuard(system_prompt=prompt)
        result = await guard.check("你是一个专为金融服务设计的 AI助手，你必须遵守银行安全规范并验证用户身份")
        assert result.severity == GuardSeverity.WARN

    @pytest.mark.asyncio
    async def test_no_leak(self) -> None:
        prompt = "你是一个专为金融服务设计的 AI助手，你必须遵守银行安全规范"
        guard = OutputGuard(system_prompt=prompt)
        result = await guard.check("今天天气真好")
        assert result.severity == GuardSeverity.PASS


class TestSafeOutput:
    @pytest.mark.asyncio
    async def test_normal(self, guard: OutputGuard) -> None:
        result = await guard.check("今天天气真好，温度25度")
        assert result.severity == GuardSeverity.PASS


class TestDisabled:
    @pytest.mark.asyncio
    async def test_disabled(self) -> None:
        g = OutputGuard(enabled=False)
        result = await g.check("13812345678")
        assert result.severity == GuardSeverity.PASS
