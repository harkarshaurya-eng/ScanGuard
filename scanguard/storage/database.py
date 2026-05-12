"""SQLite persistence layer."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from scanguard.storage.models import FindingRecord, ProjectRecord, ToolRunRecord
from scanguard.utils.time import utc_iso


class Database:
    """Thin SQLite wrapper for project persistence."""

    def __init__(self, path: Path, busy_timeout_ms: int = 5000) -> None:
        self.path = path
        self.connection = sqlite3.connect(path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute(f"PRAGMA busy_timeout = {busy_timeout_ms}")
        self.connection.execute("PRAGMA foreign_keys = ON")

    def close(self) -> None:
        self.connection.close()

    def initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scope_file TEXT NOT NULL,
                workspace_path TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS tool_runs (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                target TEXT NOT NULL,
                command TEXT NOT NULL,
                safety_category TEXT NOT NULL,
                exit_code INTEGER NOT NULL,
                stdout_path TEXT NOT NULL,
                stderr_path TEXT NOT NULL,
                raw_json_path TEXT,
                parsed_json_path TEXT,
                requires_confirmation INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS raw_outputs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_run_id TEXT NOT NULL,
                stdout_path TEXT NOT NULL,
                stderr_path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(tool_run_id) REFERENCES tool_runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS parsed_assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tool_run_id TEXT NOT NULL,
                asset_type TEXT NOT NULL,
                value TEXT NOT NULL,
                metadata_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(tool_run_id) REFERENCES tool_runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                evidence TEXT NOT NULL,
                affected_asset TEXT NOT NULL,
                source_tool TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                report_format TEXT NOT NULL,
                path TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
            );
            """
        )
        self.connection.commit()

    def insert_project(self, project: ProjectRecord) -> None:
        self.connection.execute(
            """
            INSERT INTO projects (id, target, scope_file, workspace_path, status, created_at)
            VALUES (:id, :target, :scope_file, :workspace_path, :status, :created_at)
            """,
            project.model_dump(),
        )
        self.connection.execute(
            "INSERT INTO targets (project_id, value, created_at) VALUES (?, ?, ?)",
            (project.id, project.target, project.created_at),
        )
        self.connection.commit()

    def update_project_status(self, project_id: str, status: str) -> None:
        self.connection.execute("UPDATE projects SET status = ? WHERE id = ?", (status, project_id))
        self.connection.commit()

    def insert_tool_run(self, record: ToolRunRecord) -> None:
        self.connection.execute(
            """
            INSERT INTO tool_runs (
              id, project_id, tool_name, target, command, safety_category, exit_code,
              stdout_path, stderr_path, raw_json_path, parsed_json_path,
              requires_confirmation, created_at
            ) VALUES (
              :id, :project_id, :tool_name, :target, :command, :safety_category, :exit_code,
              :stdout_path, :stderr_path, :raw_json_path, :parsed_json_path,
              :requires_confirmation, :created_at
            )
            """,
            record.model_dump(),
        )
        self.connection.execute(
            "INSERT INTO raw_outputs (tool_run_id, stdout_path, stderr_path, created_at) VALUES (?, ?, ?, ?)",
            (record.id, record.stdout_path, record.stderr_path, record.created_at),
        )
        self.connection.commit()

    def insert_parsed_asset(self, tool_run_id: str, asset_type: str, value: str, metadata_json: str) -> None:
        self.connection.execute(
            """
            INSERT INTO parsed_assets (tool_run_id, asset_type, value, metadata_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tool_run_id, asset_type, value, metadata_json, utc_iso()),
        )
        self.connection.commit()

    def insert_finding(self, finding: FindingRecord) -> None:
        self.connection.execute(
            """
            INSERT OR REPLACE INTO findings (
              id, project_id, title, severity, confidence, evidence, affected_asset,
              source_tool, recommendation, created_at
            ) VALUES (
              :id, :project_id, :title, :severity, :confidence, :evidence, :affected_asset,
              :source_tool, :recommendation, :created_at
            )
            """,
            finding.model_dump(),
        )
        self.connection.commit()

    def insert_report(self, project_id: str, report_format: str, path: str) -> None:
        self.connection.execute(
            "INSERT INTO reports (project_id, report_format, path, created_at) VALUES (?, ?, ?, ?)",
            (project_id, report_format, path, utc_iso()),
        )
        self.connection.commit()

    def add_chat_message(self, project_id: str, role: str, content: str) -> None:
        self.connection.execute(
            "INSERT INTO chat_messages (project_id, role, content, created_at) VALUES (?, ?, ?, ?)",
            (project_id, role, content, utc_iso()),
        )
        self.connection.commit()

    def fetch_projects(self) -> list[ProjectRecord]:
        rows = self.connection.execute(
            "SELECT id, target, scope_file, workspace_path, status, created_at FROM projects ORDER BY created_at DESC"
        ).fetchall()
        return [ProjectRecord.model_validate(dict(row)) for row in rows]

    def fetch_project(self, project_id: str) -> ProjectRecord:
        row = self.connection.execute(
            "SELECT id, target, scope_file, workspace_path, status, created_at FROM projects WHERE id = ?",
            (project_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Project not found: {project_id}")
        return ProjectRecord.model_validate(dict(row))

    def fetch_tool_runs(self, project_id: str) -> list[ToolRunRecord]:
        rows = self.connection.execute(
            """
            SELECT id, project_id, tool_name, target, command, safety_category, exit_code,
                   stdout_path, stderr_path, raw_json_path, parsed_json_path,
                   requires_confirmation, created_at
            FROM tool_runs
            WHERE project_id = ?
            ORDER BY created_at ASC
            """,
            (project_id,),
        ).fetchall()
        return [ToolRunRecord.model_validate(dict(row)) for row in rows]

    def fetch_tool_run(self, tool_run_id: str) -> ToolRunRecord:
        row = self.connection.execute(
            """
            SELECT id, project_id, tool_name, target, command, safety_category, exit_code,
                   stdout_path, stderr_path, raw_json_path, parsed_json_path,
                   requires_confirmation, created_at
            FROM tool_runs
            WHERE id = ?
            """,
            (tool_run_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Tool run not found: {tool_run_id}")
        return ToolRunRecord.model_validate(dict(row))

    def fetch_findings(self, project_id: str) -> list[FindingRecord]:
        rows = self.connection.execute(
            """
            SELECT id, project_id, title, severity, confidence, evidence, affected_asset,
                   source_tool, recommendation, created_at
            FROM findings
            WHERE project_id = ?
            ORDER BY CASE severity
                WHEN 'critical' THEN 5
                WHEN 'high' THEN 4
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 2
                ELSE 1
            END DESC, created_at ASC
            """,
            (project_id,),
        ).fetchall()
        return [FindingRecord.model_validate(dict(row)) for row in rows]

    def fetch_finding(self, finding_id: str) -> FindingRecord:
        row = self.connection.execute(
            """
            SELECT id, project_id, title, severity, confidence, evidence, affected_asset,
                   source_tool, recommendation, created_at
            FROM findings
            WHERE id = ?
            """,
            (finding_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Finding not found: {finding_id}")
        return FindingRecord.model_validate(dict(row))

    def fetch_assets(self, project_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT pa.tool_run_id, pa.asset_type, pa.value, pa.metadata_json, pa.created_at
            FROM parsed_assets pa
            JOIN tool_runs tr ON pa.tool_run_id = tr.id
            WHERE tr.project_id = ?
            ORDER BY pa.created_at ASC
            """,
            (project_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def fetch_reports(self, project_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT report_format, path, created_at FROM reports WHERE project_id = ? ORDER BY created_at DESC",
            (project_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def fetch_chat_messages(self, project_id: str, limit: int = 50) -> list[dict[str, str]]:
        rows = self.connection.execute(
            """
            SELECT role, content, created_at
            FROM chat_messages
            WHERE project_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (project_id, limit),
        ).fetchall()
        data = [dict(row) for row in rows]
        data.reverse()
        return data


