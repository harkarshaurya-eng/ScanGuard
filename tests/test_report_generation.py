from pathlib import Path

from scanguard.reports.report_generator import ReportGenerator
from scanguard.storage.models import FindingRecord, ToolRunRecord
from scanguard.storage.workspace import create_workspace
from scanguard.utils.time import utc_iso


def test_report_generation_outputs_all_formats(tmp_path: Path) -> None:
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("example.com\n", encoding="utf-8")
    workspace = create_workspace(tmp_path / "projects", "example.com", scope_file)
    tool_run = ToolRunRecord(
        id="run-1",
        project_id=workspace.project.id,
        tool_name="nmap_basic",
        target="example.com",
        command="nmap -Pn -T3 -sV --top-ports 1000 -oX - example.com",
        safety_category="active_safe",
        exit_code=0,
        stdout_path=str(workspace.raw_dir / "nmap.stdout.txt"),
        stderr_path=str(workspace.raw_dir / "nmap.stderr.txt"),
        raw_json_path=None,
        parsed_json_path=None,
        requires_confirmation=True,
        created_at=utc_iso(),
    )
    workspace.database.insert_tool_run(tool_run)
    workspace.database.insert_parsed_asset("run-1", "service", "tcp/443 https", '{"port":443}')
    workspace.database.insert_finding(
        FindingRecord(
            id="finding-1",
            project_id=workspace.project.id,
            title="Admin interface exposed",
            severity="medium",
            confidence="medium",
            evidence="https://example.com/admin",
            affected_asset="https://example.com/admin",
            source_tool="httpx_probe",
            recommendation="Restrict administrative access.",
            created_at=utc_iso(),
        )
    )
    generator = ReportGenerator()
    md = generator.generate(workspace, "markdown")
    html = generator.generate(workspace, "html")
    js = generator.generate(workspace, "json")
    assert md.path.exists()
    assert html.path.exists()
    assert js.path.exists()
    assert "Admin interface exposed" in md.path.read_text(encoding="utf-8")


