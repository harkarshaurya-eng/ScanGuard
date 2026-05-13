"""Typer CLI entrypoints."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import typer
from loguru import logger
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanguard.ai.agent import ReconAgent
from scanguard.config import AppSettings, ensure_env_file, ensure_user_prompt
from scanguard.constants import APP_NAME
from scanguard.logging_config import configure_logging
from scanguard.mcp.executor import ToolExecutionError, ToolExecutor
from scanguard.mcp.registry import ToolRegistry
from scanguard.mcp.schemas import ToolExecutionInput
from scanguard.reports.report_generator import ReportGenerator
from scanguard.storage.models import ToolRunRecord
from scanguard.storage.workspace import ProjectWorkspace, create_workspace, discover_projects, load_workspace
from scanguard.utils.files import ensure_dir, write_json
from scanguard.utils.validators import ScopeAuthorizer, normalize_target

app = typer.Typer(help="AI-assisted reconnaissance for authorized testing on Kali Linux.")
console = Console()


def get_settings() -> AppSettings:
    return AppSettings()


def get_registry() -> ToolRegistry:
    return ToolRegistry.with_defaults()


def resolve_workspace(settings: AppSettings, project_id: str) -> ProjectWorkspace:
    workspace_path = settings.workspace_root / project_id
    if not workspace_path.exists():
        raise typer.BadParameter(f"Project workspace not found: {project_id}")
    return load_workspace(workspace_path)


def render_banner() -> None:
    banner = f"""
  ____                  _____                     _       _   _
 / ___|  ___ __ _ _ __ |  ___|__  _ __ ___  _   _| | __ _| |_(_) ___  _ __
 \\___ \\ / __/ _` | '_ \\| |_ / _ \\| '__/ _ \\| | | | |/ _` | __| |/ _ \\| '_ \\
  ___) | (_| (_| | | | |  _| (_) | | | (_) | |_| | | (_| | |_| | (_) | | | |
 |____/ \\___\\__,_|_| |_|_|  \\___/|_|  \\___/ \\__,_|_|\\__,_|\\__|_|\\___/|_| |_|
    """.rstrip("\n")
    console.print(Panel.fit(banner, title=APP_NAME, border_style="cyan"))


def show_project_summary(workspace: ProjectWorkspace) -> None:
    findings = workspace.database.fetch_findings(workspace.project.id)
    tool_runs = workspace.database.fetch_tool_runs(workspace.project.id)
    body = "\n".join(
        [
            f"Project ID: {workspace.project.id}",
            f"Target: {workspace.project.target}",
            f"Scope: {workspace.project.scope_file}",
            f"Tool runs: {len(tool_runs)}",
            f"Findings: {len(findings)}",
            f"Workspace: {workspace.root}",
        ]
    )
    console.print(Panel(body, title="Project Summary", border_style="green"))


def show_findings_table(workspace: ProjectWorkspace) -> None:
    findings = workspace.database.fetch_findings(workspace.project.id)
    table = Table(title=f"Findings for {workspace.project.id}")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Asset")
    table.add_column("Tool")
    for finding in findings:
        table.add_row(finding.id, finding.severity, finding.title, finding.affected_asset, finding.source_tool)
    console.print(table)


def execute_tool(
    workspace: ProjectWorkspace,
    registry: ToolRegistry,
    executor: ToolExecutor,
    tool_name: str,
    target: str,
    auto_safe: bool,
    confirmed: bool,
    wordlist: str | None = None,
) -> ToolRunRecord:
    tool = registry.get(tool_name)
    record = executor.execute(
        workspace,
        tool,
        ToolExecutionInput(
            project_id=workspace.project.id,
            target=target,
            user_confirmed=confirmed,
            wordlist=wordlist,
        ),
        auto_safe=auto_safe,
    )
    console.print(
        Panel(
            f"Tool: {record.tool_name}\nExit code: {record.exit_code}\nStdout: {record.stdout_path}\nParsed: {record.parsed_json_path}",
            title="Tool Run Complete",
            border_style="blue",
        )
    )
    return record


def validate_target_and_scope(target: str, scope_file: Path) -> tuple[str, ScopeAuthorizer]:
    authorizer = ScopeAuthorizer.from_file(scope_file)
    normalized_target = normalize_target(target)
    if not authorizer.is_authorized(target):
        raise typer.BadParameter(f"Target {normalized_target} is not authorized by scope file {scope_file}.")
    return normalized_target, authorizer


@app.command()
def init() -> None:
    """Create config files and check available binaries."""
    settings = get_settings()
    configure_logging(settings.log_level)
    prompt_path = ensure_user_prompt()
    env_path = ensure_env_file(Path.cwd())
    ensure_dir(settings.workspace_root)
    registry = get_registry()
    binaries = sorted({tool.binary for tool in registry.list()})
    table = Table(title="Tool Availability")
    table.add_column("Binary")
    table.add_column("Status")
    for binary in binaries:
        from shutil import which

        table.add_row(binary, "installed" if which(binary) else "missing")
    render_banner()
    console.print(Panel(f"Prompt file: {prompt_path}\nLocal env file: {env_path}\nWorkspace root: {settings.workspace_root}", title="Initialization"))
    console.print(table)


@app.command()
def autopilot(
    target: str = typer.Option(..., "--target"),
    scope: Path = typer.Option(..., "--scope"),
    objective: str = typer.Option(
        "Run a safe reconnaissance workflow, collect findings, and generate reports.",
        "--objective",
        help="Operator intent provided to the AI planner.",
    ),
    auto_safe: bool = typer.Option(
        True,
        "--auto-safe/--no-auto-safe",
        help="Allow active_safe tools to run automatically during autopilot.",
    ),
    allow_careful: bool = typer.Option(
        False,
        "--allow-careful",
        help="Explicitly allow active_careful tools in the autonomous workflow.",
    ),
    max_steps: int = typer.Option(8, "--max-steps", min=1, max=20),
    report_format: list[str] = typer.Option(
        ["markdown", "html", "json"],
        "--report-format",
        help="Report formats to generate at the end. Repeat the option to limit formats.",
    ),
) -> None:
    """Run a one-shot AI-planned recon workflow and generate reports plus target_name.recon.txt."""
    settings = get_settings()
    configure_logging(settings.log_level)
    normalized_target, authorizer = validate_target_and_scope(target, scope)
    render_banner()
    console.print(
        Panel(
            f"Target `{normalized_target}` is authorized.\nScope rules:\n" + "\n".join(authorizer.explain()),
            title="Scope Validation",
        )
    )

    workspace = create_workspace(settings.workspace_root, normalized_target, scope, settings.sqlite_busy_timeout_ms)
    workspace.database.update_project_status(workspace.project.id, "autopilot-running")
    workspace.project.status = "autopilot-running"
    show_project_summary(workspace)

    registry = get_registry()
    executor = ToolExecutor()
    agent = ReconAgent(settings, registry)

    try:
        plan = asyncio.run(
            agent.plan_autonomous_recon(
                workspace,
                objective,
                auto_safe=auto_safe,
                allow_careful=allow_careful,
                max_steps=max_steps,
            )
        )
    finally:
        asyncio.run(agent.close())

    plan_payload = plan.model_dump(mode="json")
    write_json(workspace.metadata_dir / "autopilot-plan.json", plan_payload)
    workspace.database.add_chat_message(workspace.project.id, "system", f"Autopilot objective: {objective}")
    workspace.database.add_chat_message(workspace.project.id, "assistant", f"Autopilot strategy: {plan.strategy}")

    plan_table = Table(title="Autopilot Plan")
    plan_table.add_column("#")
    plan_table.add_column("Tool")
    plan_table.add_column("Reason")
    for index, step in enumerate(plan.steps, start=1):
        plan_table.add_row(str(index), step.tool_name, step.reason)
    console.print(Panel(plan.strategy, title="AI Strategy", border_style="magenta"))
    console.print(plan_table)

    for index, step in enumerate(plan.steps, start=1):
        tool = registry.get(step.tool_name)
        step_target = step.target or normalized_target
        if not authorizer.is_authorized(step_target):
            console.print(
                Panel(
                    f"Skipped step {index}: target `{step_target}` is outside authorized scope.",
                    title="Autopilot Skip",
                    border_style="yellow",
                )
            )
            continue
        confirmed = tool.category.value == "passive"
        if tool.category.value == "active_safe":
            confirmed = auto_safe
        elif tool.category.value == "active_careful":
            confirmed = allow_careful

        if tool.requires_confirmation and not confirmed:
            console.print(
                Panel(
                    f"Skipped `{tool.name}` because its safety category requires an explicit opt-in for autopilot.",
                    title="Autopilot Skip",
                    border_style="yellow",
                )
            )
            continue

        try:
            execute_tool(
                workspace,
                registry,
                executor,
                tool.name,
                step_target,
                auto_safe=auto_safe,
                confirmed=confirmed,
            )
        except (ToolExecutionError, FileNotFoundError, PermissionError, ValueError) as exc:
            logger.warning("Autopilot step {} ({}) failed: {}", index, tool.name, exc)
            console.print(
                Panel(
                    f"Step {index} `{tool.name}` failed or was unavailable: {exc}",
                    title="Autopilot Warning",
                    border_style="yellow",
                )
            )

    normalized_formats: list[str] = []
    for fmt in report_format:
        if fmt not in {"markdown", "html", "json"}:
            raise typer.BadParameter(f"Unsupported report format: {fmt}")
        if fmt not in normalized_formats:
            normalized_formats.append(fmt)
    if not normalized_formats:
        normalized_formats = plan.report_formats

    generated_reports: list[str] = []
    for fmt in normalized_formats:
        artifact = ReportGenerator().generate(workspace, fmt)
        generated_reports.append(str(artifact.path))
    recon_summary_path = ReportGenerator().generate_recon_summary(workspace)
    generated_reports.append(str(recon_summary_path))

    summary_payload = {
        "objective": objective,
        "strategy": plan.strategy,
        "executed_steps": [step.model_dump(mode="json") for step in plan.steps],
        "report_paths": generated_reports,
        "report_formats": normalized_formats,
        "recon_summary_path": str(recon_summary_path),
    }
    write_json(workspace.metadata_dir / "autopilot-summary.json", summary_payload)
    workspace.database.update_project_status(workspace.project.id, "autopilot-complete")
    workspace.project.status = "autopilot-complete"
    console.print(
        Panel(
            "\n".join(
                [
                    f"Project ID: {workspace.project.id}",
                    f"Workspace: {workspace.root}",
                    f"Recon Summary: {recon_summary_path}",
                    f"Reports: {json.dumps(generated_reports, indent=2)}",
                ]
            ),
            title="Autopilot Complete",
            border_style="green",
        )
    )


@app.command()
def report(
    project: str = typer.Option(..., "--project"),
    format: str = typer.Option("markdown", "--format"),
) -> None:
    """Generate a professional report."""
    settings = get_settings()
    workspace = resolve_workspace(settings, project)
    if format not in {"markdown", "html", "json"}:
        raise typer.BadParameter("Format must be markdown, html, or json.")
    artifact = ReportGenerator().generate(workspace, format)
    console.print(Panel(f"Report written to {artifact.path}", title="Report"))


@app.command()
def projects() -> None:
    """List previous project workspaces."""
    settings = get_settings()
    project_records = discover_projects(settings.workspace_root)
    table = Table(title="Projects")
    table.add_column("Project ID")
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Created")
    table.add_column("Workspace")
    for record in project_records:
        table.add_row(record.id, record.target, record.status, record.created_at, record.workspace_path)
    console.print(table)


@app.command()
def findings(project: str = typer.Option(..., "--project")) -> None:
    """Show flagged findings for a project."""
    settings = get_settings()
    workspace = resolve_workspace(settings, project)
    show_findings_table(workspace)

