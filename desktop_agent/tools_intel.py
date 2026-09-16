"""
Threat Intelligence & OSINT Tools.

Wraps: VirusTotal, AbuseIPDB, Shodan, CVE, AlienVault OTX, GreyNoise, urlscan.io, SecurityTrails, DNSDB, PassiveTotal, ThreatFox, MalwareBazaar, URLhaus.
Requires API keys for most services.
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import os
import time
from typing import Any, Dict, List, Optional

from .registry import ToolError, register

# API keys should be set as environment variables
# VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, SHODAN_API_KEY, OTX_API_KEY, GREYNOISE_API_KEY, URLSCAN_API_KEY, SECURITYTRAILS_API_KEY


def _get_api_key(name: str) -> Optional[str]:
    """Get API key from environment."""
    return os.environ.get(name)


def _run_cmd(cmd: List[str], timeout: int = 60, input_data: str = "") -> Dict[str, Any]:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_data if input_data else None
        )
        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "command": " ".join(shlex.quote(c) for c in cmd)
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": f"Command timed out after {timeout}s", "command": " ".join(shlex.quote(c) for c in cmd)}
    except Exception as e:
        return {"success": False, "error": str(e), "command": " ".join(shlex.quote(c) for c in cmd)}


# --- VIRUSTOTAL ---
@register("vtFileScan")
def vt_file_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Scan file with VirusTotal."""
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise ToolError("VIRUSTOTAL_API_KEY environment variable not set.")

    file_path = args.get("file_path")
    if not file_path or not os.path.isfile(file_path):
        raise ToolError("Parameter 'file_path' is required and must exist.")

    # Use vt CLI if available, otherwise use curl
    vt_cli = _find_tool("vt")
    if vt_cli:
        cmd = [vt_cli, "file", "scan", file_path, "--apikey", api_key, "--format", "json"]
        result = _run_cmd(cmd, timeout=120)
        if result["success"]:
            try:
                return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
            except Exception:
                pass

    # Fallback: use curl
    import subprocess
    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://www.virustotal.com/api/v3/files",
        "-H", f"x-apikey: {api_key}",
        "-F", f"file=@{file_path}"
    ]
    result = _run_cmd(curl_cmd, timeout=120)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("vtUrlScan")
def vt_url_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Scan URL with VirusTotal."""
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise ToolError("VIRUSTOTAL_API_KEY environment variable not set.")

    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://www.virustotal.com/api/v3/urls",
        "-H", f"x-apikey: {api_key}",
        "-d", f"url={url}"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("vtGetReport")
def vt_get_report(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get VirusTotal report for hash/IP/domain/URL."""
    api_key = _get_api_key("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise ToolError("VIRUSTOTAL_API_KEY environment variable not set.")

    identifier = args.get("id")
    id_type = args.get("type", "file")  # file, ip, domain, url
    if not identifier:
        raise ToolError("Parameter 'id' is required.")

    endpoints = {
        "file": f"https://www.virustotal.com/api/v3/files/{identifier}",
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{identifier}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{identifier}",
        "url": f"https://www.virustotal.com/api/v3/urls/{identifier}",
    }

    if id_type not in endpoints:
        raise ToolError(f"Type must be: {', '.join(endpoints.keys())}")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        endpoints[id_type],
        "-H", f"x-apikey: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- ABUSEIPDB ---
@register("abuseipdbCheck")
def abuseipdb_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check IP reputation with AbuseIPDB."""
    api_key = _get_api_key("ABUSEIPDB_API_KEY")
    if not api_key:
        raise ToolError("ABUSEIPDB_API_KEY environment variable not set.")

    ip = args.get("ip")
    if not ip:
        raise ToolError("Parameter 'ip' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        "https://api.abuseipdb.com/api/v2/check",
        "-H", f"Key: {api_key}",
        "-H", "Accept: application/json",
        "-d", f"ipAddress={ip}",
        "-d", f"maxAgeInDays={args.get('max_age', 90)}",
        "-d", f"verbose={str(args.get('verbose', True)).lower()}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("abuseipdbReport")
def abuseipdb_report(args: Dict[str, Any]) -> Dict[str, Any]:
    """Report abusive IP to AbuseIPDB."""
    api_key = _get_api_key("ABUSEIPDB_API_KEY")
    if not api_key:
        raise ToolError("ABUSEIPDB_API_KEY environment variable not set.")

    ip = args.get("ip")
    categories = args.get("categories", [14, 18, 19])  # Default: Port Scan, Brute Force, Web App Attack
    comment = args.get("comment", "Reported via Yashi")

    if not ip:
        raise ToolError("Parameter 'ip' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://api.abuseipdb.com/api/v2/report",
        "-H", f"Key: {api_key}",
        "-H", "Accept: application/json",
        "-d", f"ip={ip}",
        "-d", f"categories={','.join(map(str, categories))}",
        "-d", f"comment={comment}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- SHODAN ---
@register("shodanHost")
def shodan_host(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get Shodan host information."""
    api_key = _get_api_key("SHODAN_API_KEY")
    if not api_key:
        raise ToolError("SHODAN_API_KEY environment variable not set.")

    ip = args.get("ip")
    if not ip:
        raise ToolError("Parameter 'ip' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://api.shodan.io/shodan/host/{ip}",
        "-d", f"key={api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("shodanSearch")
def shodan_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search Shodan."""
    api_key = _get_api_key("SHODAN_API_KEY")
    if not api_key:
        raise ToolError("SHODAN_API_KEY environment variable not set.")

    query = args.get("query")
    if not query:
        raise ToolError("Parameter 'query' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        "https://api.shodan.io/shodan/host/search",
        "-d", f"key={api_key}",
        "-d", f"query={query}",
        "-d", f"page={args.get('page', 1)}",
        "-d", f"minify={str(args.get('minify', True)).lower()}"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- ALIENVAULT OTX ---
@register("otxPulse")
def otx_pulse(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get OTX pulse details."""
    api_key = _get_api_key("OTX_API_KEY")
    if not api_key:
        raise ToolError("OTX_API_KEY environment variable not set.")

    pulse_id = args.get("pulse_id")
    if not pulse_id:
        raise ToolError("Parameter 'pulse_id' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}",
        "-H", f"X-OTX-API-KEY: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("otxSearch")
def otx_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search OTX pulses."""
    api_key = _get_api_key("OTX_API_KEY")
    if not api_key:
        raise ToolError("OTX_API_KEY environment variable not set.")

    query = args.get("query")
    if not query:
        raise ToolError("Parameter 'query' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        "https://otx.alienvault.com/api/v1/pulses/search",
        "-H", f"X-OTX-API-KEY: {api_key}",
        "-d", f"q={query}",
        "-d", f"limit={args.get('limit', 20)}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("otxIndicators")
def otx_indicators(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get indicators for IP/domain/hostname from OTX."""
    api_key = _get_api_key("OTX_API_KEY")
    if not api_key:
        raise ToolError("OTX_API_KEY environment variable not set.")

    indicator = args.get("indicator")
    indicator_type = args.get("type", "ip")  # ip, domain, hostname, url, file
    if not indicator:
        raise ToolError("Parameter 'indicator' is required.")

    endpoints = {
        "ip": f"https://otx.alienvault.com/api/v1/indicators/ipv4/{indicator}/general",
        "domain": f"https://otx.alienvault.com/api/v1/indicators/domain/{indicator}/general",
        "hostname": f"https://otx.alienvault.com/api/v1/indicators/hostname/{indicator}/general",
        "url": f"https://otx.alienvault.com/api/v1/indicators/url/{indicator}/general",
        "file": f"https://otx.alienvault.com/api/v1/indicators/file/{indicator}/general",
    }

    if indicator_type not in endpoints:
        raise ToolError(f"Type must be: {', '.join(endpoints.keys())}")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        endpoints[indicator_type],
        "-H", f"X-OTX-API-KEY: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- GREYNOISE ---
@register("greynoiseIp")
def greynoise_ip(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get GreyNoise context for IP."""
    api_key = _get_api_key("GREYNOISE_API_KEY")
    if not api_key:
        raise ToolError("GREYNOISE_API_KEY environment variable not set.")

    ip = args.get("ip")
    if not ip:
        raise ToolError("Parameter 'ip' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://api.greynoise.io/v3/community/{ip}",
        "-H", f"key: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("greynoiseQuick")
def greynoise_quick(args: Dict[str, Any]) -> Dict[str, Any]:
    """Quick GreyNoise lookup (multiple IPs)."""
    api_key = _get_api_key("GREYNOISE_API_KEY")
    if not api_key:
        raise ToolError("GREYNOISE_API_KEY environment variable not set.")

    ips = args.get("ips")
    if not ips or not isinstance(ips, list):
        raise ToolError("Parameter 'ips' (list) is required.")

    import subprocess
    results = {}
    for ip in ips[:10]:  # Limit to 10
        curl_cmd = [
            "curl", "-s", "-G",
            f"https://api.greynoise.io/v3/community/{ip}",
            "-H", f"key: {api_key}"
        ]
        result = _run_cmd(curl_cmd, timeout=10)
        try:
            results[ip] = json.loads(result["stdout"])
        except Exception:
            results[ip] = result["stdout"]
        time.sleep(0.1)  # Rate limit

    return {"ok": True, "result": results}


# --- URLSCAN.IO ---
@register("urlscanSubmit")
def urlscan_submit(args: Dict[str, Any]) -> Dict[str, Any]:
    """Submit URL for scanning."""
    api_key = _get_api_key("URLSCAN_API_KEY")
    if not api_key:
        raise ToolError("URLSCAN_API_KEY environment variable not set.")

    url = args.get("url")
    if not url:
        raise ToolError("Parameter 'url' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://urlscan.io/api/v1/scan/",
        "-H", f"API-Key: {api_key}",
        "-H", "Content-Type: application/json",
        "-d", json.dumps({"url": url, "public": args.get("public", "on")})
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("urlscanResult")
def urlscan_result(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get urlscan.io result."""
    api_key = _get_api_key("URLSCAN_API_KEY")
    if not api_key:
        raise ToolError("URLSCAN_API_KEY environment variable not set.")

    uuid = args.get("uuid")
    if not uuid:
        raise ToolError("Parameter 'uuid' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://urlscan.io/api/v1/result/{uuid}/",
        "-H", f"API-Key: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- SECURITYTRAILS ---
@register("securitytrailsDomain")
def securitytrails_domain(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get domain info from SecurityTrails."""
    api_key = _get_api_key("SECURITYTRAILS_API_KEY")
    if not api_key:
        raise ToolError("SECURITYTRAILS_API_KEY environment variable not set.")

    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://api.securitytrails.com/v1/domain/{domain}",
        "-H", f"apikey: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("securitytrailsSubdomains")
def securitytrails_subdomains(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get subdomains from SecurityTrails."""
    api_key = _get_api_key("SECURITYTRAILS_API_KEY")
    if not api_key:
        raise ToolError("SECURITYTRAILS_API_KEY environment variable not set.")

    domain = args.get("domain")
    if not domain:
        raise ToolError("Parameter 'domain' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        "-H", f"apikey: {api_key}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- CVE / NVD ---
@register("cveSearch")
def cve_search(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search CVEs from NVD."""
    query = args.get("query")
    if not query:
        raise ToolError("Parameter 'query' is required.")

    import subprocess
    # Use NVD API 2.0
    curl_cmd = [
        "curl", "-s", "-G",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "-d", f"keywordSearch={query}",
        "-d", f"resultsPerPage={args.get('limit', 20)}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("cveGet")
def cve_get(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get specific CVE details."""
    cve_id = args.get("cve_id")
    if not cve_id:
        raise ToolError("Parameter 'cve_id' is required (e.g., CVE-2021-44228).")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "-d", f"cveId={cve_id}"
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- THREATFOX ---
@register("threatfoxQuery")
def threatfox_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query ThreatFox for IOCs."""
    api_key = _get_api_key("THREATFOX_API_KEY")  # Optional

    query_type = args.get("type", "ioc")  # ioc, malware, tag
    value = args.get("value")
    if not value:
        raise ToolError("Parameter 'value' is required.")

    import subprocess
    payload = {"query": "search_ioc", "search_term": value} if query_type == "ioc" else {"query": "get_iocs", "malware": value}

    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://threatfox-api.abuse.ch/api/v1/",
        "-H", "Content-Type: application/json",
        "-d", json.dumps(payload)
    ]
    if api_key:
        curl_cmd.extend(["-H", f"Auth-Key: {api_key}"])

    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- MALWAREBAZAAR ---
@register("malwarebazaarQuery")
def malwarebazaar_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query MalwareBazaar."""
    query_type = args.get("type", "hash")  # hash, tag, signature
    value = args.get("value")
    if not value:
        raise ToolError("Parameter 'value' is required.")

    import subprocess
    payload = {"query": "get_info", "hash": value} if query_type == "hash" else {"query": "get_taginfo", "tag": value}

    curl_cmd = [
        "curl", "-s", "-X", "POST",
        "https://mb-api.abuse.ch/api/v1/",
        "-d", json.dumps(payload)
    ]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- URLHAUS ---
@register("urlhausQuery")
def urlhaus_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query URLhaus for malicious URLs."""
    query_type = args.get("type", "url")  # url, host, payload
    value = args.get("value")
    if not value:
        raise ToolError("Parameter 'value' is required.")

    import subprocess
    endpoints = {
        "url": f"https://urlhaus-api.abuse.ch/v1/url/{value}/",
        "host": f"https://urlhaus-api.abuse.ch/v1/host/{value}/",
        "payload": f"https://urlhaus-api.abuse.ch/v1/payload/{value}/",
    }

    if query_type not in endpoints:
        raise ToolError(f"Type must be: {', '.join(endpoints.keys())}")

    curl_cmd = ["curl", "-s", "-G", endpoints[query_type]]
    result = _run_cmd(curl_cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- PASSIVETOTAL ---
@register("passivetotalQuery")
def passivetotal_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query PassiveTotal (RiskIQ)."""
    api_user = _get_api_key("PASSIVETOTAL_USER")
    api_key = _get_api_key("PASSIVETOTAL_KEY")
    if not api_user or not api_key:
        raise ToolError("PASSIVETOTAL_USER and PASSIVETOTAL_KEY environment variables required.")

    endpoint = args.get("endpoint", "enrichment")  # enrichment, ssl, dns, etc.
    query = args.get("query")
    if not query:
        raise ToolError("Parameter 'query' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-u", f"{api_user}:{api_key}",
        "-G", f"https://api.passivetotal.org/v2/{endpoint}/",
        "-d", f"query={query}"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- DNSDB ---
@register("dnsdbQuery")
def dnsdb_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query DNSDB (Farsight)."""
    api_key = _get_api_key("DNSDB_API_KEY")
    if not api_key:
        raise ToolError("DNSDB_API_KEY environment variable not set.")

    query = args.get("query")
    query_type = args.get("type", "rrset")  # rrset, rdata
    if not query:
        raise ToolError("Parameter 'query' is required.")

    import subprocess
    curl_cmd = [
        "curl", "-s", "-G",
        f"https://api.dnsdb.info/dnsdb/v2/lookup/{query_type}/name/{query}",
        "-H", f"X-API-Key: {api_key}",
        "-H", "Accept: application/json"
    ]
    result = _run_cmd(curl_cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- UTILITY: Check all API keys ---
@register("intelApiStatus")
def intel_api_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check which threat intel API keys are configured."""
    keys = {
        "VIRUSTOTAL_API_KEY": "VirusTotal",
        "ABUSEIPDB_API_KEY": "AbuseIPDB",
        "SHODAN_API_KEY": "Shodan",
        "OTX_API_KEY": "AlienVault OTX",
        "GREYNOISE_API_KEY": "GreyNoise",
        "URLSCAN_API_KEY": "urlscan.io",
        "SECURITYTRAILS_API_KEY": "SecurityTrails",
        "THREATFOX_API_KEY": "ThreatFox",
        "PASSIVETOTAL_USER": "PassiveTotal (user)",
        "PASSIVETOTAL_KEY": "PassiveTotal (key)",
        "DNSDB_API_KEY": "DNSDB",
    }

    results = {}
    for env, name in keys.items():
        results[name] = {"configured": bool(os.environ.get(env))}

    return {"ok": True, "result": results}


def _find_tool(name: str) -> Optional[str]:
    """Find tool in PATH."""
    try:
        result = subprocess.run(
            ["which", name] if platform.system() != "Windows" else ["where", name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip().split("\n")[0]
    except Exception:
        pass
    return None


__all__ = [
    "vt_file_scan", "vt_url_scan", "vt_get_report",
    "abuseipdb_check", "abuseipdb_report",
    "shodan_host", "shodan_search",
    "otx_pulse", "otx_search", "otx_indicators",
    "greynoise_ip", "greynoise_quick",
    "urlscan_submit", "urlscan_result",
    "securitytrails_domain", "securitytrails_subdomains",
    "cve_search", "cve_get",
    "threatfox_query", "malwarebazaar_query", "urlhaus_query",
    "passivetotal_query", "dnsdb_query", "intel_api_status"
]