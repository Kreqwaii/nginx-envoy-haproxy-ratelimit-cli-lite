#!/usr/bin/env python3
"""
nginx-envoy-haproxy-ratelimit-cli-lite
Offline reverse-proxy security & reliability linter for Nginx, HAProxy, and Envoy.
100% pure Python 3.9+ stdlib (zero external dependencies).
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

__version__ = "1.0.0"

SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    proxy_type: str
    file: str
    line: int
    message: str
    remediation: str


def _strip_comments(text: str, comment_char: str = "#") -> List[Tuple[int, str]]:
    """Return list of (1-based line_no, stripped_line) ignoring full-line comments."""
    lines: List[Tuple[int, str]] = []
    for idx, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped or stripped.startswith(comment_char):
            continue
        # Strip inline comments if not inside quotes (simple heuristic)
        if comment_char in stripped and '"' not in stripped and "'" not in stripped:
            stripped = stripped.split(comment_char, 1)[0].strip()
        if stripped:
            lines.append((idx, stripped))
    return lines


def detect_proxy_type(path: Path, content: str) -> str:
    name = path.name.lower()
    if name.endswith(".cfg") or "haproxy" in name:
        return "haproxy"
    if name.endswith((".yaml", ".yml")) or "envoy" in name:
        return "envoy"
    if name.endswith(".conf") or "nginx" in name:
        return "nginx"
    # Content-based fallback
    if "static_resources:" in content or "envoy.filters" in content:
        return "envoy"
    if re.search(r"^\s*(frontend|backend|listen)\s+", content, re.MULTILINE):
        return "haproxy"
    return "nginx"


# ---------------------------------------------------------------------------
# Nginx Linter
# ---------------------------------------------------------------------------

def lint_nginx(path: str, content: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = _strip_comments(content, "#")
    joined = "\n".join(line for _, line in lines)

    # NGX001: Deprecated TLSv1 / TLSv1.1
    for line_no, line in lines:
        if re.search(r"\bssl_protocols\b", line):
            if re.search(r"\bTLSv1(?:\.1)?\b(?!\.2|\.3)", line):
                findings.append(
                    Finding(
                        rule_id="NGX001",
                        severity="CRITICAL",
                        proxy_type="nginx",
                        file=path,
                        line=line_no,
                        message="Deprecated TLS protocol (TLSv1 or TLSv1.1) enabled in ssl_protocols.",
                        remediation="Use 'ssl_protocols TLSv1.2 TLSv1.3;' only.",
                    )
                )

    # NGX002: Missing server_tokens off
    if not re.search(r"\bserver_tokens\s+off\s*;", joined):
        findings.append(
            Finding(
                rule_id="NGX002",
                severity="MEDIUM",
                proxy_type="nginx",
                file=path,
                line=1,
                message="Missing 'server_tokens off;' — Nginx version may be exposed in Server header.",
                remediation="Add 'server_tokens off;' in http or server block.",
            )
        )

    # NGX003: Missing security headers (HSTS, X-Content-Type-Options, X-Frame-Options)
    has_hsts = bool(re.search(r"Strict-Transport-Security", joined, re.IGNORECASE))
    has_xcto = bool(re.search(r"X-Content-Type-Options", joined, re.IGNORECASE))
    has_xfo = bool(re.search(r"X-Frame-Options", joined, re.IGNORECASE))
    missing_headers = [
        h
        for h, ok in [
            ("Strict-Transport-Security", has_hsts),
            ("X-Content-Type-Options", has_xcto),
            ("X-Frame-Options", has_xfo),
        ]
        if not ok
    ]
    if missing_headers:
        findings.append(
            Finding(
                rule_id="NGX003",
                severity="HIGH",
                proxy_type="nginx",
                file=path,
                line=1,
                message=f"Missing security header(s): {', '.join(missing_headers)}.",
                remediation="Add 'add_header <Header> ... always;' in server/location blocks.",
            )
        )

    # NGX004: Missing rate limiting (limit_req_zone / limit_req) on API locations
    has_api_location = bool(re.search(r"\blocation\b[^\{]*(?:/api\b|/api/)", joined))
    has_limit_zone = bool(re.search(r"\blimit_req_zone\b", joined))
    has_limit_req = bool(re.search(r"\blimit_req\b", joined))
    if has_api_location and (not has_limit_zone or not has_limit_req):
        findings.append(
            Finding(
                rule_id="NGX004",
                severity="HIGH",
                proxy_type="nginx",
                file=path,
                line=1,
                message="API location detected without 'limit_req_zone' and 'limit_req' rate limiting.",
                remediation="Define 'limit_req_zone' in http block and apply 'limit_req zone=... burst=...;' on API locations.",
            )
        )

    # NGX005: Missing upstream connect/read timeouts
    has_proxy_pass = bool(re.search(r"\bproxy_pass\b", joined))
    has_connect_timeout = bool(re.search(r"\bproxy_connect_timeout\b", joined))
    has_read_timeout = bool(re.search(r"\bproxy_read_timeout\b", joined))
    if has_proxy_pass and (not has_connect_timeout or not has_read_timeout):
        findings.append(
            Finding(
                rule_id="NGX005",
                severity="MEDIUM",
                proxy_type="nginx",
                file=path,
                line=1,
                message="Missing 'proxy_connect_timeout' or 'proxy_read_timeout' for upstream proxy_pass.",
                remediation="Set explicit 'proxy_connect_timeout' and 'proxy_read_timeout' (e.g., 5s / 30s).",
            )
        )

    # NGX006: proxy_pass without proxy_set_header Host
    if has_proxy_pass and not re.search(r"\bproxy_set_header\s+Host\b", joined):
        findings.append(
            Finding(
                rule_id="NGX006",
                severity="MEDIUM",
                proxy_type="nginx",
                file=path,
                line=1,
                message="'proxy_pass' used without 'proxy_set_header Host $host;'.",
                remediation="Add 'proxy_set_header Host $host;' alongside proxy_pass.",
            )
        )

    # NGX007: Wildcard CORS '*' with credentials
    has_wildcard_origin = bool(
        re.search(r"Access-Control-Allow-Origin\s+['\"]?\*['\"]?", joined, re.IGNORECASE)
    )
    has_cors_creds = bool(
        re.search(r"Access-Control-Allow-Credentials\s+['\"]?true['\"]?", joined, re.IGNORECASE)
    )
    if has_wildcard_origin and has_cors_creds:
        findings.append(
            Finding(
                rule_id="NGX007",
                severity="CRITICAL",
                proxy_type="nginx",
                file=path,
                line=1,
                message="Wildcard CORS 'Access-Control-Allow-Origin *' combined with 'Access-Control-Allow-Credentials true'.",
                remediation="Restrict Access-Control-Allow-Origin to explicit trusted origins when credentials are enabled.",
            )
        )

    # NGX008: Missing gzip / brotli compression
    has_gzip = bool(re.search(r"\bgzip\s+on\s*;", joined))
    has_brotli = bool(re.search(r"\bbrotli\s+on\s*;", joined))
    if not has_gzip and not has_brotli:
        findings.append(
            Finding(
                rule_id="NGX008",
                severity="LOW",
                proxy_type="nginx",
                file=path,
                line=1,
                message="Neither 'gzip on;' nor 'brotli on;' compression is enabled.",
                remediation="Enable 'gzip on;' (and/or 'brotli on;') for text/JSON payloads.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# HAProxy Linter
# ---------------------------------------------------------------------------

def lint_haproxy(path: str, content: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = _strip_comments(content, "#")
    joined = "\n".join(line for _, line in lines)

    # HAP001: Deprecated TLSv1 / TLSv1.1
    for line_no, line in lines:
        if re.search(r"\b(no-tlsv10|no-tlsv11)\b", line):
            continue
        if re.search(r"\bforce-tlsv1[01]\b", line) or re.search(r"\bssl-min-ver\s+TLSv1(?:\.1)?\b(?!\.2|\.3)", line):
            findings.append(
                Finding(
                    rule_id="HAP001",
                    severity="CRITICAL",
                    proxy_type="haproxy",
                    file=path,
                    line=line_no,
                    message="Deprecated TLSv1/TLSv1.1 configured in HAProxy.",
                    remediation="Set 'ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets'.",
                )
            )

    # HAP002: Missing option httplog
    if not re.search(r"\boption\s+httplog\b", joined):
        findings.append(
            Finding(
                rule_id="HAP002",
                severity="MEDIUM",
                proxy_type="haproxy",
                file=path,
                line=1,
                message="Missing 'option httplog' in HAProxy defaults/frontend.",
                remediation="Add 'option httplog' for structured HTTP request logging.",
            )
        )

    # HAP003: Missing timeout client / timeout server / timeout connect
    missing_timeouts = [
        t
        for t in ("timeout connect", "timeout client", "timeout server")
        if not re.search(rf"\b{t}\b", joined)
    ]
    if missing_timeouts:
        findings.append(
            Finding(
                rule_id="HAP003",
                severity="HIGH",
                proxy_type="haproxy",
                file=path,
                line=1,
                message=f"Missing HAProxy timeout directive(s): {', '.join(missing_timeouts)}.",
                remediation="Configure 'timeout connect', 'timeout client', and 'timeout server' in defaults.",
            )
        )

    # HAP004: Missing rate limiting (stick-table / http-request deny/tarpit)
    if not re.search(r"\bstick-table\b", joined):
        findings.append(
            Finding(
                rule_id="HAP004",
                severity="HIGH",
                proxy_type="haproxy",
                file=path,
                line=1,
                message="No 'stick-table' rate-limiting policy detected in HAProxy.",
                remediation="Add a 'stick-table' with 'http_req_rate' tracking and 'http-request deny' threshold.",
            )
        )

    # HAP005: Missing security headers (HSTS / X-Frame-Options)
    if not re.search(r"Strict-Transport-Security", joined, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="HAP005",
                severity="MEDIUM",
                proxy_type="haproxy",
                file=path,
                line=1,
                message="Missing Strict-Transport-Security header in HAProxy responses.",
                remediation="Add 'http-response set-header Strict-Transport-Security \"max-age=31536000; includeSubDomains\"'.",
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Envoy Linter
# ---------------------------------------------------------------------------

def lint_envoy(path: str, content: str) -> List[Finding]:
    findings: List[Finding] = []
    lines = _strip_comments(content, "#")
    joined = "\n".join(line for _, line in lines)

    # ENV001: Deprecated TLSv1_0 / TLSv1_1
    for line_no, line in lines:
        if re.search(r"\bTLSv1_[01]\b", line):
            findings.append(
                Finding(
                    rule_id="ENV001",
                    severity="CRITICAL",
                    proxy_type="envoy",
                    file=path,
                    line=line_no,
                    message="Deprecated TLSv1_0 or TLSv1_1 configured in Envoy tls_params.",
                    remediation="Set 'tls_minimum_protocol_version: TLSv1_2' (or TLSv1_3).",
                )
            )

    # ENV002: Missing local_ratelimit / ratelimit filter
    if not re.search(r"ratelimit", joined, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="ENV002",
                severity="HIGH",
                proxy_type="envoy",
                file=path,
                line=1,
                message="No rate-limit HTTP filter (envoy.filters.http.local_ratelimit or ratelimit) detected.",
                remediation="Add 'envoy.filters.http.local_ratelimit' or external ratelimit filter to http_filters.",
            )
        )

    # ENV003: Missing cluster connect_timeout
    if "clusters:" in joined and not re.search(r"\bconnect_timeout\s*:", joined):
        findings.append(
            Finding(
                rule_id="ENV003",
                severity="MEDIUM",
                proxy_type="envoy",
                file=path,
                line=1,
                message="Envoy cluster(s) missing explicit 'connect_timeout'.",
                remediation="Set 'connect_timeout: 5s' on each cluster.",
            )
        )

    # ENV004: Wildcard CORS '*' with allow_credentials: true
    has_wildcard = bool(re.search(r"allow_origin_string_match[\s\S]*?\*", joined))
    has_creds = bool(re.search(r"allow_credentials\s*:\s*true", joined, re.IGNORECASE))
    if has_wildcard and has_creds:
        findings.append(
            Finding(
                rule_id="ENV004",
                severity="CRITICAL",
                proxy_type="envoy",
                file=path,
                line=1,
                message="Wildcard CORS '*' combined with 'allow_credentials: true' in Envoy.",
                remediation="Restrict 'allow_origin_string_match' to explicit trusted origins.",
            )
        )

    # ENV005: Missing gzip/compressor filter
    if not re.search(r"compressor|gzip", joined, re.IGNORECASE):
        findings.append(
            Finding(
                rule_id="ENV005",
                severity="LOW",
                proxy_type="envoy",
                file=path,
                line=1,
                message="No HTTP compression filter (envoy.filters.http.compressor) detected.",
                remediation="Enable 'envoy.filters.http.compressor' with gzip/brotli.",
            )
        )

    return findings


def lint_file(path: Path, proxy_type: Optional[str] = None) -> List[Finding]:
    content = path.read_text(encoding="utf-8", errors="replace")
    detected = proxy_type or detect_proxy_type(path, content)
    if detected == "nginx":
        return lint_nginx(str(path), content)
    if detected == "haproxy":
        return lint_haproxy(str(path), content)
    if detected == "envoy":
        return lint_envoy(str(path), content)
    raise ValueError(f"Unsupported proxy type: {detected}")


def format_markdown(findings: Sequence[Finding]) -> str:
    if not findings:
        return "## Proxy Security & Reliability Audit\n\nNo issues found.\n"
    lines = [
        "## Proxy Security & Reliability Audit",
        "",
        "| Severity | Rule | Proxy | File | Line | Message |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for f in findings:
        msg = f.message.replace("|", "\\|")
        lines.append(
            f"| {f.severity} | `{f.rule_id}` | {f.proxy_type} | `{f.file}` | {f.line} | {msg} |"
        )
    return "\n".join(lines) + "\n"


def format_json(findings: Sequence[Finding]) -> str:
    payload = {
        "tool": "nginx-envoy-haproxy-ratelimit-cli-lite",
        "version": __version__,
        "total_findings": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    return json.dumps(payload, indent=2)


def should_fail(findings: Sequence[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = SEVERITY_ORDER[fail_on.upper()]
    return any(SEVERITY_ORDER.get(f.severity.upper(), 0) >= threshold for f in findings)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proxy-lint",
        description="Offline reverse-proxy security & reliability linter for Nginx, HAProxy, and Envoy.",
    )
    parser.add_argument(
        "paths",
        nargs="+",
        help="Config file(s) to lint (nginx.conf, haproxy.cfg, envoy.yaml).",
    )
    parser.add_argument(
        "--type",
        choices=["nginx", "haproxy", "envoy"],
        default=None,
        help="Override auto-detected proxy type.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown"],
        default="markdown",
        help="Output format (default: markdown).",
    )
    parser.add_argument(
        "--fail-on",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Exit with code 1 if any finding meets or exceeds this severity.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    all_findings: List[Finding] = []
    for raw_path in args.paths:
        p = Path(raw_path)
        if not p.is_file():
            print(f"Error: file not found: {raw_path}", file=sys.stderr)
            return 2
        all_findings.extend(lint_file(p, proxy_type=args.type))

    if args.format == "json":
        print(format_json(all_findings))
    else:
        print(format_markdown(all_findings))

    return 1 if should_fail(all_findings, args.fail_on) else 0


if __name__ == "__main__":
    sys.exit(main())
