"""Chat memory helpers."""

from __future__ import annotations

from scanguard.storage.workspace import ProjectWorkspace


def get_recent_messages(workspace: ProjectWorkspace, limit: int = 12) -> list[dict[str, str]]:
    """Return recent chat history from the workspace database."""
    return workspace.database.fetch_chat_messages(workspace.project.id, limit=limit)


def format_recent_messages(workspace: ProjectWorkspace, limit: int = 12) -> str:
    """Render recent chat history as plain text."""
    lines: list[str] = []
    for item in get_recent_messages(workspace, limit=limit):
        lines.append(f"{item['role']}: {item['content']}")
    return "\n".join(lines)


