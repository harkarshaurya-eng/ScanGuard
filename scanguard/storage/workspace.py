"""Workspace management."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from scanguard.storage.database import Database
from scanguard.storage.models import ProjectRecord
from scanguard.utils.files import ensure_dir, write_json
from scanguard.utils.time import utc_iso


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "project"


@dataclass(slots=True)
class ProjectWorkspace:
    project: ProjectRecord
    root: Path
    raw_dir: Path
    parsed_dir: Path
    reports_dir: Path
    metadata_dir: Path
    database: Database


def create_workspace(
    workspace_root: Path,
    target: str,
    scope_file: Path,
    sqlite_busy_timeout_ms: int = 5000,
) -> ProjectWorkspace:
    """Create the directory and database layout for a project."""
    project_id = f"{_slugify(target)}-{uuid4().hex[:8]}"
    root = ensure_dir(workspace_root / project_id)
    raw_dir = ensure_dir(root / "raw")
    parsed_dir = ensure_dir(root / "parsed")
    reports_dir = ensure_dir(root / "reports")
    metadata_dir = ensure_dir(root / "metadata")
    db = Database(root / "workspace.db", busy_timeout_ms=sqlite_busy_timeout_ms)
    db.initialize()

    project = ProjectRecord(
        id=project_id,
        target=target,
        scope_file=str(scope_file),
        workspace_path=str(root),
        status="initialized",
        created_at=utc_iso(),
    )
    db.insert_project(project)
    write_json(
        metadata_dir / "project.json",
        {"id": project.id, "target": target, "scope_file": str(scope_file), "created_at": project.created_at},
    )
    return ProjectWorkspace(
        project=project,
        root=root,
        raw_dir=raw_dir,
        parsed_dir=parsed_dir,
        reports_dir=reports_dir,
        metadata_dir=metadata_dir,
        database=db,
    )


def load_workspace(project_root: Path) -> ProjectWorkspace:
    """Load an existing project workspace."""
    db = Database(project_root / "workspace.db")
    project = db.fetch_projects()[0]
    return ProjectWorkspace(
        project=project,
        root=project_root,
        raw_dir=project_root / "raw",
        parsed_dir=project_root / "parsed",
        reports_dir=project_root / "reports",
        metadata_dir=project_root / "metadata",
        database=db,
    )


def discover_projects(workspace_root: Path) -> list[ProjectRecord]:
    """Enumerate projects stored under the workspace root."""
    projects: list[ProjectRecord] = []
    if not workspace_root.exists():
        return projects
    for candidate in workspace_root.iterdir():
        if not candidate.is_dir():
            continue
        db_path = candidate / "workspace.db"
        if not db_path.exists():
            continue
        db = Database(db_path)
        try:
            projects.extend(db.fetch_projects())
        finally:
            db.close()
    return sorted(projects, key=lambda item: item.created_at, reverse=True)

