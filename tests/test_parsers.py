from scanguard.parsers.httpx_parser import parse_httpx_output
from scanguard.parsers.nikto_parser import parse_nikto_output
from scanguard.parsers.nmap_parser import parse_nmap_xml
from scanguard.parsers.nuclei_parser import parse_nuclei_output


def test_nmap_parser_extracts_service_and_risky_port() -> None:
    xml = """
    <nmaprun>
      <host>
        <ports>
          <port protocol="tcp" portid="21">
            <state state="open" />
            <service name="ftp" product="vsftpd" version="3.0.3" />
          </port>
        </ports>
      </host>
    </nmaprun>
    """
    parsed = parse_nmap_xml(xml, "example.com")
    assert parsed.assets
    assert parsed.findings
    assert parsed.findings[0].title == "FTP service exposed"


def test_httpx_and_nuclei_parsers_generate_findings() -> None:
    httpx_stdout = '{"url":"https://example.com/admin","status_code":200,"title":"Admin Portal","tech":["WordPress"]}\n'
    nuclei_stdout = '{"template-id":"exposed-panel","matched-at":"https://example.com/admin","info":{"name":"Exposed Panel","severity":"high","description":"Panel detected"}}\n'
    httpx_parsed = parse_httpx_output(httpx_stdout, "example.com")
    nuclei_parsed = parse_nuclei_output(nuclei_stdout, "example.com")
    assert any("admin" in finding.evidence.lower() for finding in httpx_parsed.findings)
    assert nuclei_parsed.findings[0].severity == "high"


def test_nikto_parser_flags_directory_listing() -> None:
    stdout = "+ /icons/: Directory indexing found.\n"
    parsed = parse_nikto_output(stdout, "https://example.com")
    assert parsed.findings[0].title == "Directory listing exposed"


