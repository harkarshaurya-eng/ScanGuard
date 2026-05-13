# ScanGuard

## CLI Commands

```bash
scanguard init
scanguard autopilot --target TARGET --scope SCOPE_FILE
scanguard autopilot --target TARGET --scope SCOPE_FILE --allow-careful
scanguard autopilot --target TARGET --scope SCOPE_FILE --objective "Map the external attack surface and generate reports"
scanguard report --project PROJECT_ID --format markdown
scanguard report --project PROJECT_ID --format html
scanguard report --project PROJECT_ID --format json
scanguard projects
scanguard findings --project PROJECT_ID
```

## Tools The AI Can Use Independently

### Autonomous By Default In `scanguard autopilot`

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

## Example Autopilot Command

```bash
scanguard autopilot --target example.com --scope examples/scope.txt
```

## Automatic Findings File

After `scanguard autopilot` finishes, ScanGuard automatically writes a plain-text findings file named:

```text
target_name.recon.txt
```

Example:

```text
example.com.recon.txt
```

The file is written into the project `reports` directory for that run.

## How To Provide The Target

Pass the target directly with `--target`.

```bash
scanguard autopilot --target example.com --scope examples/scope.txt
```
