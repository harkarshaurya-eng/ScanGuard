# ScanGuard-ai

ScanGuard-ai is a production-style, terminal-first reconnaissance assistant for **authorized** cybersecurity testing on Kali Linux. It combines a local MCP-style tool registry, safety-enforced subprocess execution, structured result parsing, SQLite-backed project storage, Rich terminal UX, and optional Groq-powered AI guidance.

The CLI entrypoint is `recon-ai`, and the Python package is `recon_ai`.

## Legal and Ethical Warning

Use this tool only with **explicit written authorization** for the target environment. ScanGuard-ai is designed for safe reconnaissance workflows, not exploitation. It intentionally refuses credential attacks, brute forcing, destructive exploitation, persistence, stealth, payload delivery, malware behavior, or denial-of-service activity.

You are responsible for:

- confirming that the target is in scope
- obtaining permission before any active testing
- reviewing tool output manually before acting on it
- respecting local laws, contracts, and program rules

## What It Does

ScanGuard-ai provides:

- scope validation from `scope.txt` files
- project workspace creation per target
- local MCP-style tool registration with schemas and execution rules
- safe wrappers around common Kali recon tools
- raw output capture plus parsed findings and assets
- SQLite-backed storage for projects, runs, findings, reports, and chat messages
- terminal chat with AI-assisted planning and offline fallback guidance
- professional reports in Markdown, HTML, and JSON

## Supported Tools

Passive or low-risk wrappers:

- `whois`
- `dig`
- `nslookup`
- `host`
- `subfinder`
- `amass` passive mode
- `theHarvester`

Active but controlled wrappers:

- `httpx`
- `wafw00f`
- `whatweb`
- `nmap`
- `nikto`
- `nuclei`
- `sslscan`
- `gobuster`
- `ffuf`

Intentionally excluded:

- `hydra`
- `medusa`
- automated exploitation
- brute force
- reverse shells
- DoS tooling
- malware or persistence tooling

## Architecture

The codebase is organized like this:

```text
recon_ai/
├── ai/         # Groq client, prompt layering, safety, memory, agent behavior
├── mcp/        # tool schemas, permissions, executor, registry
├── parsers/    # parser modules for nmap, httpx, nuclei, nikto, generic text
├── reports/    # Jinja2 report generator and templates
├── storage/    # SQLite database wrapper and workspace lifecycle
├── tools/      # wrappers for Kali binaries with safe defaults
└── utils/      # shell safety, scope validation, files, time helpers
```

### MCP-Style Tool Registry

Each tool is defined in code with:

- name
- description
- safety category
- required binary
- input schema
- confirmation requirement
- command builder
- parser
- timeout
- rate limit
- allowed target types

The registry lives in [recon_ai/mcp/registry.py](recon_ai/mcp/registry.py) and produces a strict local catalog. Execution is handled by [recon_ai/mcp/executor.py](recon_ai/mcp/executor.py), which:

- avoids `shell=True`
- validates arguments before subprocess launch
- blocks unsafe flags
- enforces timeouts
- records stdout, stderr, exit code, timestamps, and command line
- persists parsed assets and findings to SQLite

## Safe Scanning Policy

The default safety model is:

- validate scope before every run
- require confirmation for active tools unless `--auto-safe` is used for `active_safe` wrappers
- block dangerous nmap flags like `-A`, `--script`, spoofing flags, and high timing
- exclude intrusive Nuclei tags (`intrusive`, `dos`, `fuzz`, `brute-force`)
- use low-rate defaults for `gobuster` and `ffuf`
- refuse unsafe natural-language requests before calling the model

## Installation on Kali Linux

### 1. Clone the project

```bash
git clone https://github.com/your-org/recon-ai.git
cd recon-ai
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
```

### 3. Install the package

```bash
python3 -m pip install -e .
```

For development extras:

```bash
python3 -m pip install -e ".[dev]"
```

### 4. Run initialization

```bash
recon-ai init
```

This will:

- create `~/.config/recon-ai/system_prompt.md` if missing
- create a local `.env` in your current directory if missing
- create the workspace root
- show which supported binaries are installed or missing

## Groq Configuration

Set your Groq API key in `.env` or environment variables:

```env
GROQ_API_KEY=your_key_here
GROQ_MODEL=llama-3.3-70b-versatile
GROQ_BASE_URL=https://api.groq.com/openai/v1
RECON_AI_AUTO_SAFE=false
```

The code does **not** hardcode API keys.

If `GROQ_API_KEY` is missing, the tool still works in offline guidance mode for:

- scope validation
- tool execution
- result parsing
- findings review
- report generation

## System Prompt Customization

The user-editable prompt lives at:

```text
~/.config/recon-ai/system_prompt.md
```

The final prompt stack always includes:

1. immutable safety prompt
2. user-editable system prompt
3. tool policy prompt
4. project context prompt
5. current user message

The immutable safety layer is defined in [recon_ai/constants.py](recon_ai/constants.py) and is always prepended before any Groq request.

## Usage

### Initialize

```bash
recon-ai init
```

### Start a project

```bash
recon-ai start --target example.com --scope examples/scope.txt
```

### Start with automatic approval for `active_safe` tools

```bash
recon-ai start --target example.com --scope examples/scope.txt --auto-safe
```

### Resume chat

```bash
recon-ai chat --project example-com-1234abcd
```

### Manually run a tool inside an existing project

```bash
recon-ai run-tool nmap_basic --project example-com-1234abcd --target example.com
```

### Manually run a tool by creating a new scoped workspace

```bash
recon-ai run-tool httpx_probe --target https://example.com --scope examples/scope.txt --auto-safe
```

### Generate reports

```bash
recon-ai report --project example-com-1234abcd --format markdown
recon-ai report --project example-com-1234abcd --format html
recon-ai report --project example-com-1234abcd --format json
```

### List projects and findings

```bash
recon-ai projects
recon-ai findings --project example-com-1234abcd
```

## Interactive Chat Commands

Inside `recon-ai chat` or `recon-ai start`, you can use:

- `/help`
- `/tools`
- `/scope`
- `/findings`
- `/report`
- `/raw TOOL_RUN_ID`
- `/explain FINDING_ID`
- `/clear`
- `/exit`

You can also ask natural-language questions such as:

- `run dns enumeration`
- `run nuclei`
- `generate a report`
- `what should I check next?`
- `explain this finding`

## Scope File Format

Example:

```text
example.com
*.example.com
192.168.1.0/24
```

Validation supports:

- exact domains
- wildcard subdomains
- CIDR ranges

And it rejects:

- out-of-scope domains
- malformed targets
- path-style bypasses

## Report Output

Report sections include:

- title
- legal authorization reminder
- executive summary
- scope
- methodology
- tools used
- asset inventory
- open ports and services
- web assets
- findings table
- detailed findings
- raw output appendix
- timeline

## How to Add a New Tool Wrapper

1. Add a wrapper in one of the modules under [recon_ai/tools](recon_ai/tools).
2. Define a `ToolDefinition` with:
   - a safe command builder
   - allowed target types
   - timeout and rate limit
   - parser callback
   - confirmation behavior
3. Register the tool in [recon_ai/mcp/registry.py](recon_ai/mcp/registry.py).
4. Add or update a parser under [recon_ai/parsers](recon_ai/parsers).
5. Add tests covering:
   - argument safety
   - parser behavior
   - registry visibility

## Troubleshooting

### Groq is not answering

- confirm `GROQ_API_KEY` is set
- confirm outbound HTTPS access
- check that the model name is valid for your account

### A Kali tool is missing

Run `recon-ai init` and review the availability table. Install the required package on Kali and rerun the command.

### The target is rejected as out of scope

- verify the scope file path
- check wildcard formatting
- confirm you did not pass a URL/path that normalizes outside the allowed host

### Tool execution fails

- verify the binary exists in `PATH`
- confirm the active tool was approved
- confirm the target type matches the wrapper
- check the saved stderr file in the project workspace

## Development

Run tests:

```bash
pytest
```

Run Ruff:

```bash
ruff check .
```

Run mypy:

```bash
mypy recon_ai
```

## Security Limitations

- Parser coverage is intentionally conservative and does not replace analyst review.
- The tool does not verify legal authorization; it only enforces local scope files.
- Some third-party binaries have their own network behavior and output formats.
- Active tools can still generate logs on the target side.
- Offline mode does not provide model-generated summaries.

## Future Improvements

- central multi-project inventory database
- richer parser coverage for Gobuster and ffuf structured output
- streaming Rich UI with live token rendering
- multi-target batch orchestration
- stronger deduplication and evidence correlation
- optional SARIF export

