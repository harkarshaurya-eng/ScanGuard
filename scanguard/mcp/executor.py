"""Tool execution engine."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from scanguard.mcp.permissions import evaluate_tool_permission
from scanguard.mcp.schemas import ToolDefinition, ToolExecutionInput
from scanguard.storage.models import FindingRecord, ParsedToolOutput, ToolRunRecord
from scanguard.storage.workspace import ProjectWorkspace
from scanguard.utils.files import write_json, write_text
from scanguard.utils.shell import safe_run_command
from scanguard.utils.time import utc_iso


class ToolExecutionError(RuntimeError):
    """Raised when a tool cannot be executed safely."""


class ToolExecutor:
    """Executes registered tools with safe defaults and persistence."""

    def execute(
        self,
        workspace: ProjectWorkspace,
        tool: ToolDefinition,
        execution_input: ToolExecutionInput,
        auto_safe: bool = False,
    ) -> ToolRunRecord:
        decision = evaluate_tool_permission(
            tool=tool,
            target=execution_input.target,
            auto_safe=auto_safe,
            user_confirmed=execution_input.user_confirmed,
        )
        if not decision.allowed:
            raise ToolExecutionError(decision.reason)

        self._enforce_rate_limit(workspace, tool)
        args = tool.command_builder(execution_input)
        result = safe_run_command(args, timeout=tool.timeout_seconds, cwd=workspace.root)

        run_id = hashlib.sha1(
            f"{workspace.project.id}:{tool.name}:{result.started_at}".encode("utf-8")
        ).hexdigest()[:16]
        stdout_path = workspace.raw_dir / f"{run_id}-{tool.name}.stdout.txt"
        stderr_path = workspace.raw_dir / f"{run_id}-{tool.name}.stderr.txt"
        raw_json_path = workspace.raw_dir / f"{run_id}-{tool.name}.json"
        parsed_json_path = workspace.parsed_dir / f"{run_id}-{tool.name}.json"

        write_text(stdout_path, result.stdout)
        write_text(stderr_path, result.stderr)
        write_json(
            raw_json_path,
            {
                "tool": tool.name,
                "args": result.args,
                "exit_code": result.exit_code,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )

        parsed = tool.parser(result.stdout, execution_input.target)
        write_json(parsed_json_path, parsed.model_dump(mode="json"))

        record = ToolRunRecord(
            id=run_id,
            project_id=workspace.project.id,
            tool_name=tool.name,
            target=execution_input.target,
            command=" ".join(result.args),
            safety_category=tool.category.value,
            exit_code=result.exit_code,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            raw_json_path=str(raw_json_path),
            parsed_json_path=str(parsed_json_path),
            requires_confirmation=tool.requires_confirmation,
            created_at=result.started_at,
        )
        workspace.database.insert_tool_run(record)
        self._persist_parsed_output(workspace, record.id, parsed)
        return record

    def _enforce_rate_limit(self, workspace: ProjectWorkspace, tool: ToolDefinition) -> None:
        previous_runs = [
            run for run in workspace.database.fetch_tool_runs(workspace.project.id) if run.tool_name == tool.name
        ]
        if not previous_runs:
            return
        latest = previous_runs[-1]
        delta_seconds = (
            datetime.fromisoformat(utc_iso()) - datetime.fromisoformat(latest.created_at)
        ).total_seconds()
        if delta_seconds < tool.rate_limit_seconds:
            remaining = int(tool.rate_limit_seconds - delta_seconds)
            raise ToolExecutionError(
                f"Tool {tool.name} is rate-limited. Try again in about {remaining} seconds."
            )

    def _persist_parsed_output(
        self,
        workspace: ProjectWorkspace,
        tool_run_id: str,
        parsed: ParsedToolOutput,
    ) -> None:
        for asset in parsed.assets:
            workspace.database.insert_parsed_asset(
                tool_run_id,
                asset.asset_type,
                asset.value,
                json.dumps(asset.metadata, sort_keys=True),
            )
        for finding in parsed.findings:
            fingerprint = hashlib.sha1(
                f"{workspace.project.id}:{finding.title}:{finding.affected_asset}:{finding.source_tool}".encode(
                    "utf-8"
                )
            ).hexdigest()[:20]
            workspace.database.insert_finding(
                FindingRecord(
                    id=fingerprint,
                    project_id=workspace.project.id,
                    title=finding.title,
                    severity=finding.severity,
                    confidence=finding.confidence,
                    evidence=finding.evidence,
                    affected_asset=finding.affected_asset,
                    source_tool=finding.source_tool,
                    recommendation=finding.recommendation,
                    created_at=utc_iso(),
                )
            )


