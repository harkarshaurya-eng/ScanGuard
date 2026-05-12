"""Prompt construction helpers."""

from __future__ import annotations

import json

from recon_ai.config import PromptBundle, load_user_prompt
from recon_ai.constants import IMMUTABLE_SAFETY_PROMPT, TOOL_POLICY_PROMPT
from recon_ai.storage.workspace import ProjectWorkspace


def build_project_context_prompt(workspace: ProjectWorkspace) -> str:
    """Render live project context for the model."""
    findings = workspace.database.fetch_findings(workspace.project.id)[:10]
    tool_runs = workspace.database.fetch_tool_runs(workspace.project.id)[-10:]
    context = {
        "project_id": workspace.project.id,
        "target": workspace.project.target,
        "scope_file": workspace.project.scope_file,
        "status": workspace.project.status,
        "recent_tools": [
            {
                "tool_name": run.tool_name,
                "exit_code": run.exit_code,
                "created_at": run.created_at,
            }
            for run in tool_runs
        ],
        "top_findings": [
            {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "affected_asset": finding.affected_asset,
            }
            for finding in findings
        ],
    }
    return f"Project context:\n{json.dumps(context, indent=2)}"


def build_prompt_bundle(workspace: ProjectWorkspace, user_message: str) -> PromptBundle:
    """Create all prompt layers for the current interaction."""
    return PromptBundle(
        immutable_safety_prompt=IMMUTABLE_SAFETY_PROMPT,
        user_editable_system_prompt=load_user_prompt(),
        tool_policy_prompt=TOOL_POLICY_PROMPT,
        project_context_prompt=build_project_context_prompt(workspace),
        current_user_message=user_message,
    )


def render_chat_messages(bundle: PromptBundle) -> list[dict[str, str]]:
    """Convert layered prompts into chat messages."""
    return [
        {"role": "system", "content": bundle.immutable_safety_prompt},
        {"role": "system", "content": bundle.user_editable_system_prompt},
        {"role": "system", "content": bundle.tool_policy_prompt},
        {"role": "system", "content": bundle.project_context_prompt},
        {"role": "user", "content": bundle.current_user_message},
    ]

