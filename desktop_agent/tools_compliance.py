"""
Compliance & Security Audit Tools.

Wraps: Lynis, OpenSCAP, CIS benchmarks, auditd, oscap, scap-workbench, oscap-docker, kube-bench, kube-hunter, trivy, checkov, tfsec, cdk, prowler, scoutsuite, cloud-custodian.
"""

from __future__ import annotations

import json
import platform
import shlex
import subprocess
import os
from typing import Any, Dict, List, Optional

from .registry import ToolError, register

_TOOL_CACHE: Dict[str, Optional[str]] = {}


def _find_tool(name: str) -> Optional[str]:
    if name in _TOOL_CACHE:
        return _TOOL_CACHE[name]

    extra_paths: List[str] = []
    system = platform.system()
    if system == "Darwin":
        extra_paths = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin"]
    elif system == "Linux":
        extra_paths = ["/usr/local/bin", "/opt/openscap/bin"]
    elif system == "Windows":
        extra_paths = []

    for path_dir in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] + extra_paths:
        full = os.path.join(path_dir, name)
        if system == "Windows" and not full.endswith(".exe"):
            full += ".exe"
        if os.path.isfile(full) and os.access(full, os.X_OK):
            _TOOL_CACHE[name] = full
            return full

    try:
        result = subprocess.run(
            ["which", name] if system != "Windows" else ["where", name],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            path = result.stdout.strip().split("\n")[0]
            _TOOL_CACHE[name] = path
            return path
    except Exception:
        pass

    _TOOL_CACHE[name] = None
    return None


def _run_cmd(cmd: List[str], timeout: int = 600, input_data: str = "") -> Dict[str, Any]:
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


def _require_tool(name: str) -> str:
    path = _find_tool(name)
    if not path:
        raise ToolError(f"Tool '{name}' not found. Install it first.")
    return path


# --- LYNIS ---
@register("lynisAudit")
def lynis_audit(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Lynis security audit.
    Args: categories (list), quick, pentest, upload, no-colors, output_format (json, text)
    """
    lynis = _require_tool("lynis")
    cmd = [lynis, "audit", "system"]

    if "categories" in args:
        for cat in args["categories"]:
            cmd.extend(["--tests-category", cat])

    if args.get("quick", False):
        cmd.append("--quick")
    if args.get("pentest", False):
        cmd.append("--pentest")
    if args.get("no_colors", True):
        cmd.append("--no-colors")

    # Output format
    if args.get("json", False):
        cmd.extend(["--format", "json"])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        # Lynis returns non-zero on findings, check stderr
        if "ERROR" not in result["stderr"].upper():
            pass
        else:
            return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("lynisShow")
def lynis_show(args: Dict[str, Any]) -> Dict[str, Any]:
    """Show Lynis information (version, tests, categories)."""
    lynis = _require_tool("lynis")
    cmd = [lynis, "show"]

    if "what" in args:
        cmd.append(args["what"])  # version, tests, categories, profiles

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- OPENSCAP ---
@register("oscapScan")
def oscap_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run OpenSCAP scan.
    Args: profile (xccdf profile id), content (datastream file), results_file, report_file, fetch_remote_resources
    """
    oscap = _require_tool("oscap")
    profile = args.get("profile")
    content = args.get("content")

    if not profile or not content:
        raise ToolError("Parameters 'profile' and 'content' are required.")

    cmd = [oscap, "xccdf", "eval", "--profile", profile]

    if "results_file" in args:
        cmd.extend(["--results", args["results_file"]])
    if "report_file" in args:
        cmd.extend(["--report", args["report_file"]])
    if args.get("fetch_remote", False):
        cmd.append("--fetch-remote-resources")

    cmd.append(content)

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    # Parse results if ARF file generated
    if "results_file" in args and os.path.isfile(args["results_file"]):
        try:
            with open(args["results_file"], "r") as f:
                return {"ok": True, "result": f.read(), "command": result["command"]}
        except Exception:
            pass

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("oscapInfo")
def oscap_info(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get OpenSCAP content information."""
    oscap = _require_tool("oscap")
    content = args.get("content")
    if not content:
        raise ToolError("Parameter 'content' is required.")

    cmd = [oscap, "info", content]

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("oscapOval")
def oscap_oval(args: Dict[str, Any]) -> Dict[str, Any]:
    """Evaluate OVAL definition."""
    oscap = _require_tool("oscap")
    oval_file = args.get("oval_file")
    if not oval_file:
        raise ToolError("Parameter 'oval_file' is required.")

    cmd = [oscap, "oval", "eval"]

    if "results_file" in args:
        cmd.extend(["--results", args["results_file"]])
    if "report_file" in args:
        cmd.extend(["--report", args["report_file"]])

    cmd.append(oval_file)

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- AUDITD ---
@register("auditdRules")
def auditd_rules(args: Dict[str, Any]) -> Dict[str, Any]:
    """Manage auditd rules."""
    auditctl = _require_tool("auditctl")
    action = args.get("action", "list")

    if action == "list":
        cmd = [auditctl, "-l"]
    elif action == "add":
        rule = args.get("rule")
        if not rule:
            raise ToolError("Parameter 'rule' required for add action.")
        cmd = [auditctl, "-a", rule]
    elif action == "delete":
        rule = args.get("rule")
        if not rule:
            raise ToolError("Parameter 'rule' required for delete action.")
        cmd = [auditctl, "-d", rule]
    elif action == "clear":
        cmd = [auditctl, "-D"]
    else:
        raise ToolError("Action must be: list, add, delete, clear")

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("ausearchQuery")
def ausearch_query(args: Dict[str, Any]) -> Dict[str, Any]:
    """Query audit logs with ausearch."""
    ausearch = _require_tool("ausearch")
    cmd = [ausearch]

    if "start" in args:
        cmd.extend(["-ts", args["start"]])
    if "end" in args:
        cmd.extend(["-te", args["end"]])
    if "event" in args:
        cmd.extend(["-m", args["event"]])
    if "pid" in args:
        cmd.extend(["-p", str(args["pid"])])
    if "uid" in args:
        cmd.extend(["-ui", str(args["uid"])])
    if "key" in args:
        cmd.extend(["-k", args["key"]])
    if args.get("raw", False):
        cmd.append("--raw")
    if args.get("interpret", True):
        cmd.append("-i")

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- KUBE-BENCH ---
@register("kubebenchRun")
def kubebench_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run kube-bench for Kubernetes CIS benchmark."""
    kubebench = _require_tool("kube-bench")
    cmd = [kubebench, "run"]

    if "targets" in args:
        cmd.extend(["--targets", args["targets"]])
    if "version" in args:
        cmd.extend(["--version", args["version"]])
    if "config_dir" in args:
        cmd.extend(["--config-dir", args["config_dir"]])
    if args.get("json", True):
        cmd.append("--json")
    if "benchmark" in args:
        cmd.extend(["--benchmark", args["benchmark"]])

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- KUBE-HUNTER ---
@register("kubehunterRun")
def kubehunter_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run kube-hunter for Kubernetes penetration testing."""
    kubehunter = _require_tool("kube-hunter")
    cmd = [kubehunter]

    if "remote" in args:
        cmd.extend(["--remote", args["remote"]])
    if "cidr" in args:
        cmd.extend(["--cidr", args["cidr"]])
    if "interface" in args:
        cmd.extend(["--interface", args["interface"]])
    if args.get("active", False):
        cmd.append("--active")
    if args.get("json", False):
        cmd.append("--json")

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- TRIVY ---
@register("trivyScan")
def trivy_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """
    Run Trivy vulnerability scanner.
    Args: target (image, fs, repo), path, severity, format (json, table, template), output, scanners (vuln, config, secret, license)
    """
    trivy = _require_tool("trivy")
    target = args.get("target")
    path = args.get("path")

    if not target or not path:
        raise ToolError("Parameters 'target' and 'path' are required.")

    cmd = [trivy, target, path]

    if "severity" in args:
        cmd.extend(["--severity", args["severity"]])
    if "format" in args:
        cmd.extend(["--format", args["format"]])
    if "output" in args:
        cmd.extend(["-o", args["output"]])
    if "scanners" in args:
        cmd.extend(["--scanners", args["scanners"]])
    if args.get("ignore_unfixed", False):
        cmd.append("--ignore-unfixed")
    if "exit_code" in args:
        cmd.extend(["--exit-code", str(args["exit_code"])])

    cmd.append("--no-progress")

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    try:
        return {"ok": True, "result": json.loads(result["stdout"]), "command": result["command"]}
    except Exception:
        return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- CHECKOV ---
@register("checkovScan")
def checkov_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run Checkov for IaC security scanning."""
    checkov = _require_tool("checkov")
    cmd = [checkov]

    if "directory" in args:
        cmd.extend(["-d", args["directory"]])
    if "file" in args:
        cmd.extend(["-f", args["file"]])
    if "framework" in args:
        cmd.extend(["--framework", args["framework"]])
    if "check" in args:
        cmd.extend(["--check", args["check"]])
    if "skip_check" in args:
        cmd.extend(["--skip-check", args["skip_check"]])
    if args.get("quiet", False):
        cmd.append("--quiet")
    if args.get("compact", False):
        cmd.append("--compact")

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- TFSEC ---
@register("tfsecScan")
def tfsec_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run tfsec for Terraform security scanning."""
    tfsec = _require_tool("tfsec")
    path = args.get("path", ".")
    cmd = [tfsec, path]

    if args.get("no_colour", True):
        cmd.append("--no-colour")
    if args.get("json", False):
        cmd.append("--format=json")
    if args.get("include_passed", False):
        cmd.append("--include-passed")
    if "minimum_severity" in args:
        cmd.extend(["--minimum-severity", args["minimum_severity"]])

    result = _run_cmd(cmd, timeout=120)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- CDK (Cloud Development Kit) ---
@register("cdkDoctor")
def cdk_doctor(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run CDK doctor for AWS CDK issues."""
    cdk = _require_tool("cdk")
    cmd = [cdk, "doctor"]

    result = _run_cmd(cmd, timeout=60)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- PROWLER ---
@register("prowlerScan")
def prowler_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run Prowler for AWS security assessment."""
    prowler = _require_tool("prowler")
    cmd = [prowler]

    if "provider" in args:
        cmd.extend(["-p", args["provider"]])  # aws, gcp, azure
    if "profile" in args:
        cmd.extend(["--profile", args["profile"]])
    if "region" in args:
        cmd.extend(["-r", args["region"]])
    if "check_id" in args:
        cmd.extend(["-c", args["check_id"]])
    if "service" in args:
        cmd.extend(["-s", args["service"]])
    if args.get("json", False):
        cmd.extend(["-o", "json"])
    if args.get("csv", False):
        cmd.extend(["-o", "csv"])
    if args.get("html", False):
        cmd.extend(["-o", "html"])
    if "output_dir" in args:
        cmd.extend(["--output-dir", args["output_dir"]])

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- SCOUTSUITE ---
@register("scoutsuiteScan")
def scoutsuite_scan(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run ScoutSuite for multi-cloud security auditing."""
    scout = _find_tool("scout.py") or _find_tool("scoutsuite")
    if not scout:
        raise ToolError("ScoutSuite not found. Install with 'pip install scoutsuite'.")

    cmd = ["python3", scout]

    if "provider" in args:
        cmd.extend(["--provider", args["provider"]])
    if "profile" in args:
        cmd.extend(["--profile", args["profile"]])
    if "region" in args:
        cmd.extend(["--region", args["region"]])
    if "report_dir" in args:
        cmd.extend(["--report-dir", args["report_dir"]])
    if args.get("no_browser", True):
        cmd.append("--no-browser")

    result = _run_cmd(cmd, timeout=600)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- CLOUD CUSTODIAN ---
@register("c7nRun")
def c7n_run(args: Dict[str, Any]) -> Dict[str, Any]:
    """Run Cloud Custodian policy."""
    c7n = _require_tool("custodian")
    policy_file = args.get("policy_file")
    if not policy_file:
        raise ToolError("Parameter 'policy_file' is required.")

    cmd = [c7n, "run", "-s", args.get("output_dir", "c7n_output")]

    if "config" in args:
        cmd.extend(["-c", args["config"]])

    cmd.append(policy_file)

    result = _run_cmd(cmd, timeout=300)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


@register("c7nSchema")
def c7n_schema(args: Dict[str, Any]) -> Dict[str, Any]:
    """Get Cloud Custodian resource schema."""
    c7n = _require_tool("custodian")
    resource = args.get("resource")
    if not resource:
        raise ToolError("Parameter 'resource' is required (e.g., aws.ec2).")

    cmd = [c7n, "schema", resource]

    result = _run_cmd(cmd, timeout=30)

    if not result["success"]:
        return {"ok": False, "error": result.get("error") or result["stderr"], "command": result["command"]}

    return {"ok": True, "result": result["stdout"], "command": result["command"]}


# --- COMPLIANCE CHECK ---
@register("complianceCheck")
def compliance_check(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check which compliance tools are installed."""
    tools = {
        "lynis": "Lynis (system audit)",
        "oscap": "OpenSCAP (SCAP scanner)",
        "auditctl": "auditd (Linux audit)",
        "ausearch": "ausearch (audit log query)",
        "kube-bench": "kube-bench (K8s CIS)",
        "kube-hunter": "kube-hunter (K8s pen test)",
        "trivy": "Trivy (vuln scanner)",
        "checkov": "Checkov (IaC scanner)",
        "tfsec": "tfsec (Terraform scanner)",
        "cdk": "AWS CDK",
        "prowler": "Prowler (AWS audit)",
        "scout.py": "ScoutSuite (multi-cloud)",
        "custodian": "Cloud Custodian (policy)",
    }

    results = {}
    for tool, desc in tools.items():
        path = _find_tool(tool)
        results[desc] = {"installed": path is not None, "path": path}

    installed = [k for k, v in results.items() if v["installed"]]
    return {"ok": True, "result": {"installed": installed, "details": results}}


__all__ = [
    "lynis_audit", "lynis_show",
    "oscap_scan", "oscap_info", "oscap_oval",
    "auditd_rules", "ausearch_query",
    "kubebench_run", "kubehunter_run",
    "trivy_scan", "checkov_scan", "tfsec_scan",
    "cdk_doctor", "prowler_scan", "scoutsuite_scan",
    "c7n_run", "c7n_schema", "compliance_check"
]