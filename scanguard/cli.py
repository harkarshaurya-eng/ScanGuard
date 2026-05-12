"""Typer CLI entrypoints."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from loguru import logger
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from scanguard.ai.agent import ReconAgent
from scanguard.config import AppSettings, ensure_env_file, ensure_user_prompt
from scanguard.constants import APP_NAME, BASELINE_TOOLS
from scanguard.logging_config import configure_logging
from scanguard.mcp.executor import ToolExecutionError, ToolExecutor
from scanguard.mcp.registry import ToolRegistry
from scanguard.mcp.schemas import ToolExecutionInput
from scanguard.reports.report_generator import ReportGenerator
from scanguard.storage.workspace import ProjectWorkspace, create_workspace, discover_projects, load_workspace
from scanguard.utils.files import ensure_dir
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


def show_tools(registry: ToolRegistry) -> None:
    table = Table(title="Registered MCP-Style Tools")
    table.add_column("Name")
    table.add_column("Category")
    table.add_column("Confirmation")
    table.add_column("Binary")
    for tool in registry.list():
        table.add_row(tool.name, tool.category.value, "yes" if tool.requires_confirmation else "no", tool.binary)
    console.print(table)


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
) -> None:
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


def validate_target_and_scope(target: str, scope_file: Path) -> tuple[str, ScopeAuthorizer]:
    authorizer = ScopeAuthorizer.from_file(scope_file)
    normalized_target = normalize_target(target)
    if not authorizer.is_authorized(target):
        raise typer.BadParameter(f"Target {normalized_target} is not authorized by scope file {scope_file}.")
    return normalized_target, authorizer


async def run_agent_chat(workspace: ProjectWorkspace, settings: AppSettings, auto_safe: bool) -> None:
    registry = get_registry()
    executor = ToolExecutor()
    agent = ReconAgent(settings, registry)
    workspace.database.add_chat_message(workspace.project.id, "system", "Interactive chat session started.")
    show_project_summary(workspace)

    try:
        while True:
            user_input = Prompt.ask("[bold cyan]scanguard[/bold cyan]")
            if not user_input.strip():
                continue
            if user_input == "/exit":
                break
            if user_input == "/help":
                console.print(
                    Markdown(
                        "\n".join(
                            [
                                "- `/help` show chat commands",
                                "- `/tools` list registered tools",
                                "- `/scope` show normalized scope rules",
                                "- `/findings` list flagged findings",
                                "- `/report` generate a Markdown report",
                                "- `/raw TOOL_RUN_ID` print raw stdout for a tool run",
                                "- `/explain FINDING_ID` explain a finding",
                                "- `/clear` clear the screen",
                                "- `/exit` leave chat",
                            ]
                        )
                    )
                )
                continue
            if user_input == "/tools":
                show_tools(registry)
                continue
            if user_input == "/findings":
                show_findings_table(workspace)
                continue
            if user_input == "/scope":
                authorizer = ScopeAuthorizer.from_file(Path(workspace.project.scope_file))
                console.print(Panel("\n".join(authorizer.explain()), title="Authorized Scope"))
                continue
            if user_input == "/report":
                artifact = ReportGenerator().generate(workspace, "markdown")
                console.print(Panel(f"Report written to {artifact.path}", title="Report"))
                continue
            if user_input == "/clear":
                console.clear()
                continue
            if user_input.startswith("/raw "):
                _, tool_run_id = user_input.split(maxsplit=1)
                tool_run = workspace.database.fetch_tool_run(tool_run_id)
                console.print(Path(tool_run.stdout_path).read_text(encoding="utf-8"))
                continue
            if user_input.startswith("/explain "):
                _, finding_id = user_input.split(maxsplit=1)
                finding = workspace.database.fetch_finding(finding_id)
                explanation = (
                    f"{finding.title} on {finding.affected_asset} was flagged by {finding.source_tool}. "
                    f"Severity is {finding.severity}, confidence is {finding.confidence}. "
                    f"Recommendation: {finding.recommendation}"
                )
                console.print(Panel(explanation, title=f"Finding {finding_id}"))
                continue

            workspace.database.add_chat_message(workspace.project.id, "user", user_input)
            reply = await agent.plan_message(workspace, user_input)
            if reply.plan.response_type == "run_tool_request" and reply.plan.tool_name:
                console.print(reply.message)
                tool = registry.get(reply.plan.tool_name)
                confirmed = auto_safe if tool.category.value == "active_safe" else False
                if not confirmed:
                    confirmed = Confirm.ask(f"Run {tool.name} against {workspace.project.target}?")
                if confirmed:
                    try:
                        execute_tool(
                            workspace,
                            registry,
                            executor,
                            tool.name,
                            workspace.project.target,
                            auto_safe=auto_safe,
                            confirmed=confirmed,
                        )
                        assistant_message = f"Executed {tool.name} successfully."
                    except (ToolExecutionError, FileNotFoundError, PermissionError, ValueError) as exc:
                        assistant_message = f"Tool execution failed: {exc}"
                else:
                    assistant_message = f"Skipped {tool.name}."
                console.print(Panel(assistant_message, title="Assistant"))
                workspace.database.add_chat_message(workspace.project.id, "assistant", assistant_message)
                continue

            if reply.plan.response_type == "generate_report":
                artifact = ReportGenerator().generate(workspace, "markdown")
                assistant_message = f"Generated report at {artifact.path}"
                console.print(Panel(assistant_message, title="Assistant"))
                workspace.database.add_chat_message(workspace.project.id, "assistant", assistant_message)
                continue

            if settings.groq_api_key and reply.plan.response_type == "answer_question":
                answer = await agent.stream_answer(workspace, user_input)
            else:
                answer = reply.message
            console.print(Panel(answer, title="Assistant"))
            workspace.database.add_chat_message(workspace.project.id, "assistant", answer)
    finally:
        await agent.close()


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
def start(
    target: str = typer.Option(..., "--target"),
    scope: Path = typer.Option(..., "--scope"),
    auto_safe: bool = typer.Option(False, "--auto-safe", help="Automatically allow active_safe tools."),
) -> None:
    """Validate scope, create a workspace, run baseline recon, and start chat."""
    settings = get_settings()
    configure_logging(settings.log_level)
    normalized_target, authorizer = validate_target_and_scope(target, scope)
    console.print(Panel(f"Target `{normalized_target}` is authorized.\nScope rules:\n" + "\n".join(authorizer.explain()), title="Scope Validation"))

    workspace = create_workspace(settings.workspace_root, normalized_target, scope, settings.sqlite_busy_timeout_ms)
    registry = get_registry()
    executor = ToolExecutor()
    workspace.database.update_project_status(workspace.project.id, "running")
    workspace.project.status = "running"
    render_banner()
    show_project_summary(workspace)

    should_run_baseline = auto_safe or Confirm.ask("Run the safe baseline recon plan now?")
    if should_run_baseline:
        for tool_name in BASELINE_TOOLS:
            try:
                execute_tool(
                    workspace,
                    registry,
                    executor,
                    tool_name,
                    normalized_target,
                    auto_safe=auto_safe,
                    confirmed=True,
                )
            except (ToolExecutionError, FileNotFoundError, PermissionError, ValueError) as exc:
                logger.warning("Baseline tool {} failed: {}", tool_name, exc)
                console.print(Panel(f"{tool_name} skipped or failed: {exc}", title="Baseline Warning", border_style="yellow"))
    workspace.database.update_project_status(workspace.project.id, "baseline-complete")
    workspace.project.status = "baseline-complete"
    asyncio.run(run_agent_chat(workspace, settings, auto_safe))


@app.command("chat")
def chat_project(
    project: str = typer.Option(..., "--project"),
    auto_safe: bool = typer.Option(False, "--auto-safe"),
) -> None:
    """Resume interactive AI chat for an existing project."""
    settings = get_settings()
    configure_logging(settings.log_level)
    workspace = resolve_workspace(settings, project)
    render_banner()
    asyncio.run(run_agent_chat(workspace, settings, auto_safe))


@app.command("run-tool")
def run_tool_command(
    tool_name: str = typer.Argument(...),
    target: str = typer.Option(..., "--target"),
    project: str | None = typer.Option(None, "--project"),
    scope: Path | None = typer.Option(None, "--scope"),
    auto_safe: bool = typer.Option(False, "--auto-safe"),
    wordlist: str | None = typer.Option(None, "--wordlist"),
) -> None:
    """Run a registered tool manually and persist its outputs."""
    settings = get_settings()
    configure_logging(settings.log_level)
    registry = get_registry()
    executor = ToolExecutor()

    if project:
        workspace = resolve_workspace(settings, project)
        validate_target_and_scope(target, Path(workspace.project.scope_file))
    else:
        if scope is None:
            raise typer.BadParameter("--scope is required when --project is not provided.")
        normalized_target, _ = validate_target_and_scope(target, scope)
        workspace = create_workspace(settings.workspace_root, normalized_target, scope, settings.sqlite_busy_timeout_ms)
        target = normalized_target

    tool = registry.get(tool_name)
    confirmed = auto_safe if tool.category.value == "active_safe" else False
    if not confirmed and tool.requires_confirmation:
        confirmed = Confirm.ask(f"Run {tool.name} against {target}?")
    execute_tool(workspace, registry, executor, tool_name, target, auto_safe=auto_safe, confirmed=confirmed, wordlist=wordlist)


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

