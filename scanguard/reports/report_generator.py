"""Professional report generation."""

from __future__ import annotations

import json
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from scanguard.storage.models import ReportArtifact
from scanguard.storage.workspace import ProjectWorkspace
from scanguard.utils.files import write_json, write_text
from scanguard.utils.time import utc_iso


class ReportGenerator:
    """Render Markdown, HTML, and JSON reports from stored evidence."""

    def __init__(self) -> None:
        templates_dir = Path(__file__).parent / "templates"
        self.environment = Environment(
            loader=FileSystemLoader(templates_dir),
            autoescape=select_autoescape(["html"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def generate(self, workspace: ProjectWorkspace, report_format: str) -> ReportArtifact:
        context = self._build_context(workspace)
        created_at = utc_iso()
        if report_format == "json":
            path = workspace.reports_dir / f"{workspace.project.id}-report.json"
            write_json(path, context)
        else:
            template_name = "report.md.j2" if report_format == "markdown" else "report.html.j2"
            extension = "md" if report_format == "markdown" else "html"
            template = self.environment.get_template(template_name)
            path = workspace.reports_dir / f"{workspace.project.id}-report.{extension}"
            write_text(path, template.render(**context))
        workspace.database.insert_report(workspace.project.id, report_format, str(path))
        return ReportArtifact(format=report_format, path=path, created_at=created_at)

    def _build_context(self, workspace: ProjectWorkspace) -> dict[str, object]:
        project = workspace.project
        tool_runs = workspace.database.fetch_tool_runs(project.id)
        findings = workspace.database.fetch_findings(project.id)
        assets = workspace.database.fetch_assets(project.id)
        services = [asset for asset in assets if asset["asset_type"] == "service"]
        web_assets = [asset for asset in assets if asset["asset_type"] == "web_asset"]
        severity_counts = {name: 0 for name in ["critical", "high", "medium", "low", "info"]}
        for finding in findings:
            severity_counts[finding.severity] += 1

        executive_summary = (
            f"Scope target {project.target} produced {len(findings)} flagged findings across "
            f"{len(tool_runs)} recorded tool runs. Highest observed severity: "
            f"{next((level for level, count in severity_counts.items() if count > 0), 'none')}."
        )
        return {
            "title": f"ScanGuard Recon Report - {project.target}",
            "generated_at": utc_iso(),
            "project": project.model_dump(),
            "legal_notice": "Authorized security testing only. Validate that written permission exists before using these results.",
            "executive_summary": executive_summary,
            "scope": workspace.project.scope_file,
            "methodology": [
                "Validated the target against a local scope definition before execution.",
                "Executed only registered MCP-style wrappers with safe defaults and recorded command metadata.",
                "Parsed raw outputs into structured assets and findings for analyst review.",
            ],
            "tools_used": sorted({run.tool_name for run in tool_runs}),
            "asset_inventory": assets,
            "open_services": services,
            "web_assets": web_assets,
            "findings": [finding.model_dump() for finding in findings],
            "timeline": [run.model_dump() for run in tool_runs],
            "raw_output_appendix": [
                {
                    "tool_name": run.tool_name,
                    "stdout_path": run.stdout_path,
                    "stderr_path": run.stderr_path,
                    "exit_code": run.exit_code,
                }
                for run in tool_runs
            ],
            "severity_counts": severity_counts,
            "raw_assets_json": json.dumps(assets, indent=2),
        }


