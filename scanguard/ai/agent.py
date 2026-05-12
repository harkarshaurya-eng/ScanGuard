"""High-level agent behavior for chat and planning."""

from __future__ import annotations

from dataclasses import dataclass

from scanguard.ai.groq_client import GroqClient
from scanguard.ai.memory import format_recent_messages
from scanguard.ai.prompts import build_prompt_bundle, render_chat_messages
from scanguard.ai.safety import classify_user_message
from scanguard.config import AppSettings
from scanguard.mcp.registry import ToolRegistry
from scanguard.mcp.schemas import ToolPlan
from scanguard.storage.workspace import ProjectWorkspace


@dataclass(slots=True)
class AgentReply:
    plan: ToolPlan
    message: str


class ReconAgent:
    """Coordinates safety checks, planning, and AI answering."""

    def __init__(self, settings: AppSettings, registry: ToolRegistry) -> None:
        self.settings = settings
        self.registry = registry
        self.groq = GroqClient(settings)

    async def close(self) -> None:
        await self.groq.close()

    async def plan_message(self, workspace: ProjectWorkspace, message: str) -> AgentReply:
        plan = classify_user_message(message, self.registry, workspace.project.target)
        if plan.response_type == "unsafe_request":
            return AgentReply(plan=plan, message=plan.answer or plan.reason)
        if plan.response_type == "propose_tool":
            assert plan.tool_name is not None
            tool = self.registry.get(plan.tool_name)
            return AgentReply(
                plan=plan,
                message=(
                    f"I recommend `{tool.name}` next because {tool.description.lower()} "
                    f"Risk level: `{tool.category.value}`."
                ),
            )
        if plan.response_type == "run_tool_request":
            return AgentReply(plan=plan, message=f"Planned tool execution: `{plan.tool_name}`. {plan.reason}")
        if plan.response_type == "generate_report":
            return AgentReply(plan=plan, message="I can generate a professional report from the stored project evidence.")
        if plan.response_type == "explain_finding":
            return AgentReply(plan=plan, message="Tell me the finding ID or use `/explain FINDING_ID` for a specific explanation.")
        return AgentReply(plan=plan, message=await self.answer_question(workspace, message))

    async def answer_question(self, workspace: ProjectWorkspace, message: str) -> str:
        if not self.settings.groq_api_key:
            return self._offline_answer(workspace, message)
        bundle = build_prompt_bundle(
            workspace,
            f"Recent chat context:\n{format_recent_messages(workspace)}\n\nUser message:\n{message}",
        )
        messages = render_chat_messages(bundle)
        return await self.groq.complete_chat(messages)

    async def stream_answer(self, workspace: ProjectWorkspace, message: str) -> str:
        if not self.settings.groq_api_key:
            return self._offline_answer(workspace, message)
        bundle = build_prompt_bundle(
            workspace,
            f"Recent chat context:\n{format_recent_messages(workspace)}\n\nUser message:\n{message}",
        )
        output_parts: list[str] = []
        async for token in self.groq.astream_chat(render_chat_messages(bundle)):
            output_parts.append(token)
        return "".join(output_parts)

    def _offline_answer(self, workspace: ProjectWorkspace, message: str) -> str:
        findings = workspace.database.fetch_findings(workspace.project.id)
        tool_runs = workspace.database.fetch_tool_runs(workspace.project.id)
        if "next" in message.lower():
            if not tool_runs:
                return "Start with passive intel such as whois, DNS records, and passive subdomain enumeration."
            if not findings:
                return "The current evidence does not show flagged findings yet. A safe next step is httpx or nmap_basic, depending on the target type."
            top = findings[0]
            return f"Highest-priority current finding: {top.title} on {top.affected_asset}. Validate it and consider a related confirming tool run."
        return (
            "Groq is not configured, so I am answering in offline mode. I can still help with safe tool planning, "
            "scope checks, findings review, and report generation from the stored evidence."
        )


