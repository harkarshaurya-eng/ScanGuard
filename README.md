# ScanGuard

## Installation Commands

```bash
cd ScanGuard
git clone https://github.com/harkarshaurya-eng/ScanGuard.git

python3 -m venv .venv
source .venv/bin/activate
cp .env.example .env
python3 -m pip install --force-reinstall -e 
htop 
```

Use the single Groq key you already pasted into `.env`.

## Scope File

Add your authorized in-scope items to:

```text
scope.txt
```

Example:

```text
example.com
*.example.com
192.168.1.0/24
```

## Single Recon Command

```bash
scanguard --target example.com
```

If your shell still uses an older installed launcher after a pull, refresh it with:

```bash
python3 -m pip install --force-reinstall -e .
```

ScanGuard automatically reads `./scope.txt`, validates the target, runs AI-planned recon, and writes reports plus:

```text
target_name.recon.txt
```

Example:

```text
example.com.recon.txt
```

## Optional Variants

```bash
scanguard --target example.com --scope myscope.txt
scanguard --target example.com --allow-careful
scanguard --target example.com --objective "Map the external attack surface and generate reports"
python3 -m scanguard --target example.com --scope myscope.txt
```

If `httpx_probe` picks the wrong `httpx` binary on your system, set the ProjectDiscovery path in `.env`:

```text
SCANGUARD_HTTPX_BINARY=/usr/local/bin/httpx
```

## Other Commands

```bash
scanguard report --project PROJECT_ID --format markdown
scanguard report --project PROJECT_ID --format html
scanguard report --project PROJECT_ID --format json
scanguard projects
scanguard findings --project PROJECT_ID
```

## Tools The AI Can Use Independently

### Autonomous By Default In `scanguard`

Passive:

- `whois_lookup`
- `dns_records`
- `dnsrecon_standard`
- `host_lookup`
- `nslookup_query`
- `subfinder_passive`
- `assetfinder_passive`
- `amass_passive`
- `theharvester_passive`

Active safe:

- `httpx_probe`
- `curl_headers`
- `waf_detection`
- `whatweb_fingerprint`
- `nmap_basic`
- `naabu_top_ports`
- `sslscan_basic`

### Autonomous Only When `--allow-careful` Is Set

Active careful:

- `nikto_basic`
- `nuclei_safe`
- `gobuster_dirs`
- `ffuf_dirs`
- `nmap_syn_safe`
