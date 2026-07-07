"""LangGraph 集成适配器

将 AgentGuard 四层围栏嵌入到 LangGraph 工作流中。

使用方式：
    from guardrails.integrations.langgraph_adapter import AgentGuardMiddleware

    workflow = StateGraph(AgentState)
    middleware = AgentGuardMiddleware(guard)
    workflow = middleware.wrap(workflow)
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from guardrails.base import GuardLevel, GuardResult, GuardSeverity
from guardrails.input_guard import InputGuard
from guardrails.thought_guard import ThoughtGuard
from guardrails.tool_guard import ToolGuard
from guardrails.output_guard import OutputGuard
from guardrails.thought import ThoughtContext
from guardrails.tool_call import ToolCall


class GuardBlockedError(Exception):
    """围栏阻断异常"""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        super().__init__(f"Agent blocked by {result.level.value} guard: {result.message}")


class AgentGuardMiddleware:
    """LangGraph 围栏中间件

    将四层围栏注入 LangGraph StateGraph 的节点间。

    嵌入点：
    - before_agent: 在 agent 节点执行前，校验用户输入
    - after_thought: 在 agent 生成 Thought 后、Action 执行前
    - before_tool: 在工具调用前，审查参数
    - before_output: 在返回用户前，过滤输出

    使用示例：
        from langgraph.graph import StateGraph
        from guardrails import InputGuard, ThoughtGuard, ToolGuard, OutputGuard

        middleware = AgentGuardMiddleware(
            input_guard=InputGuard(),
            thought_guard=ThoughtGuard(),
            tool_guard=ToolGuard(allowed_paths=["/workspace"]),
            output_guard=OutputGuard(mask_output=True),
        )

        # 方式 1：手动在节点中调用
        state["messages"] = await middleware.before_agent(state["messages"][-1])

        # 方式 2：自动包装 workflow（实验性）
        workflow = middleware.wrap(workflow)
    """

    def __init__(
        self,
        input_guard: InputGuard | None = None,
        thought_guard: ThoughtGuard | None = None,
        tool_guard: ToolGuard | None = None,
        output_guard: OutputGuard | None = None,
        strict_mode: bool = False,
        on_block: Optional[Callable[[GuardResult], Any]] = None,
    ) -> None:
        """
        Args:
            input_guard: 输入围栏实例
            thought_guard: 思维围栏实例
            tool_guard: 工具围栏实例
            output_guard: 输出围栏实例
            strict_mode: 严格模式——WARN 也阻断（默认仅 BLOCK 阻断）
            on_block: 阻断时的回调函数（用于自定义日志/告警）
        """
        self.input_guard = input_guard or InputGuard()
        self.thought_guard = thought_guard or ThoughtGuard()
        self.tool_guard = tool_guard or ToolGuard()
        self.output_guard = output_guard or OutputGuard()
        self.strict_mode = strict_mode
        self.on_block = on_block

    async def before_agent(self, user_input: str, context: Optional[dict[str, Any]] = None) -> str:
        """在 Agent 处理前校验用户输入

        对应 LangGraph 中 agent 节点的前置检查。
        如果输入被阻断，抛出 GuardBlockedError。
        """
        result = await self.input_guard.check(user_input, context)
        self._handle_result(result)
        return user_input

    async def after_thought(
        self,
        thought: str,
        user_request: str = "",
        action_planned: Optional[str] = None,
        action_args: Optional[dict[str, Any]] = None,
        tool_call_history: Optional[list[dict[str, Any]]] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> ThoughtContext:
        """在 Agent 生成 Thought 后、执行 Action 前进行审查

        对应 LangGraph 中 agent → tools 过渡节点的检查。
        """
        ctx = ThoughtContext(
            thought=thought,
            user_request=user_request,
            action_planned=action_planned,
            action_args=action_args or {},
            tool_call_history=tool_call_history or [],
        )
        result = await self.thought_guard.check(ctx, context)
        self._handle_result(result)
        return ctx

    async def before_tool(
        self,
        tool_name: str,
        tool_args: dict[str, Any],
        tool_description: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> ToolCall:
        """在工具调用前审查参数

        对应 LangGraph 中 tools 节点的前置检查。
        """
        call = ToolCall(
            tool_name=tool_name,
            tool_args=tool_args,
            tool_description=tool_description,
        )
        result = await self.tool_guard.check(call, context)
        self._handle_result(result)
        return call

    async def before_output(self, output: str, context: Optional[dict[str, Any]] = None) -> str:
        """在最终输出返回用户前过滤敏感信息

        对应 LangGraph 中返回结果节点的后置检查。

        如果启用了 mask_output，会自动脱敏；否则仅检测并告警。
        """
        result = await self.output_guard.check(output, context)
        self._handle_result(result)

        if self.output_guard.mask_output:
            return self.output_guard.mask_sensitive(output)
        return output

    def _handle_result(self, result: GuardResult) -> None:
        """处理围栏结果：阻断时抛出异常或触发回调"""
        if result.severity == GuardSeverity.BLOCK:
            if self.on_block:
                self.on_block(result)
            raise GuardBlockedError(result)

        if self.strict_mode and result.severity == GuardSeverity.WARN:
            if self.on_block:
                self.on_block(result)
            raise GuardBlockedError(result)

    def create_guard_node(
        self,
        node_name: str,
        guard_type: str,
    ) -> Callable:
        """创建可嵌入 LangGraph 的围栏节点

        返回一个符合 LangGraph node 签名的 callable：
            def guard_node(state: dict) -> dict

        Args:
            node_name: 节点名称
            guard_type: 围栏类型 (input/thought/tool/output)
        """
        async def input_guard_node(state: dict) -> dict:
            messages = state.get("messages", [])
            if messages:
                last_message = messages[-1]
                content = last_message.content if hasattr(last_message, "content") else str(last_message)
                await self.before_agent(content)
            return state

        async def thought_guard_node(state: dict) -> dict:
            thought = state.get("current_thought", "")
            user_request = state.get("user_request", "")
            if thought:
                await self.after_thought(thought=thought, user_request=user_request)
            return state

        async def tool_guard_node(state: dict) -> dict:
            tool_name = state.get("tool_name", "")
            tool_args = state.get("tool_args", {})
            if tool_name:
                await self.before_tool(tool_name, tool_args)
            return state

        async def output_guard_node(state: dict) -> dict:
            output = state.get("output", "") or state.get("messages", [{}])[-1] if state.get("messages") else ""
            content = output.content if hasattr(output, "content") else str(output)
            cleaned = await self.before_output(content)
            state["output"] = cleaned
            return state

        nodes = {
            "input": input_guard_node,
            "thought": thought_guard_node,
            "tool": tool_guard_node,
            "output": output_guard_node,
        }
        return nodes.get(guard_type, input_guard_node)
