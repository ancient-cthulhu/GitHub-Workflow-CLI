#!/usr/bin/env python3
"""Bulk Veracode SAST build and scan triage.

For each configured organization, this script discovers recent Static Code
Analysis runs, uses github-workflow-cli-sast-fixed.py to fetch the complete run
log, retains only build/AutoPackager/upload/prescan/pipeline-scan/policy-scan
jobs, and reports the real operational failure instead of cleanup noise.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

SAST_WORKFLOW_NAME = "Static Code Analysis"

STAGE_ORDER = {
    "collection": 0,
    "validation": 10,
    "build": 20,
    "autopackager": 30,
    "artifact": 40,
    "upload": 50,
    "prescan": 60,
    "pipeline_scan": 70,
    "policy_scan": 80,
    "results": 90,
}


@dataclass(frozen=True)
class Rule:
    code: str
    stage: str
    title: str
    severity: str
    owner: str
    recommendation: str
    patterns: tuple[str, ...]
    priority: int


RULES: tuple[Rule, ...] = (
    Rule("VERACODE_AUTH", "validation", "Veracode API authentication failed", "high", "Veracode configuration",
         "Correct or replace the Veracode API credentials and verify permissions and expiration.",
         (r"VERACODE_API_ID.*invalid", r"Invalid credentials", r"authentication failed.*Veracode", r"401 Unauthorized.*Veracode"), 10),
    Rule("INVALID_POLICY", "validation", "Veracode policy validation failed", "high", "Veracode configuration",
         "Correct the policy name or verify the API identity can access the configured policy.",
         (r"invalid policy", r"policy .* not found", r"validatePolicyName.*failed"), 10),
    Rule("CHECKOUT_AUTH", "build", "Repository checkout or Git authentication failed", "high", "GitHub configuration",
         "Verify repository access, token permissions, organization policy, and the requested ref.",
         (r"fatal: Authentication failed", r"Repository not found", r"couldn't find remote ref", r"Permission to .* denied"), 10),
    Rule("DOTNET_TARGETING_PACK", "autopackager", "Missing .NET Framework targeting pack", "high", "repository/runner",
         "Install the required .NET Framework Developer/Targeting Pack on the runner or retarget the application.",
         (r"MSB3644:.*reference assemblies for \.NETFramework,Version=v([0-9.]+) were not found",), 10),
    Rule("NUGET_PRIVATE_FEED", "autopackager", "Private NuGet package or feed unavailable", "high", "repository/runner",
         "Configure and authenticate the private NuGet source before AutoPackager runs, then verify restore independently.",
         (r"NU1101: Unable to find package", r"No packages exist with this id in source\(s\)"), 10),
    Rule("NUGET_AUTH", "autopackager", "NuGet feed authentication failed", "high", "repository/runner",
         "Correct private NuGet feed credentials and verify the runner can access the service index.",
         (r"NU1301: Unable to load the service index", r"401 \(Unauthorized\).*NuGet", r"Response status code does not indicate success: 401"), 10),
    Rule("MAVEN_DEPENDENCY", "autopackager", "Maven dependency resolution failed", "high", "repository/runner",
         "Configure the required Maven repository and credentials and verify the Maven build before packaging.",
         (r"Could not resolve dependencies for project", r"Could not find artifact .* in ", r"Non-resolvable parent POM"), 10),
    Rule("GRADLE_DEPENDENCY", "autopackager", "Gradle dependency resolution failed", "high", "repository/runner",
         "Configure the required Gradle repository and credentials and verify the Gradle build before packaging.",
         (r"Could not resolve all files for configuration", r"Could not resolve .* Required by:", r"Could not find .*\.pom"), 10),
    Rule("NODE_DEPENDENCY", "autopackager", "Node package installation failed", "high", "repository/runner",
         "Configure the required npm registry and credentials, then verify npm, Yarn, or pnpm installation.",
         (r"npm ERR!", r"yarn error", r"ERR_PNPM_", r"401 Unauthorized.*registry"), 10),
    Rule("JAVA_BUILD", "autopackager", "Java build or compilation failed", "high", "repository",
         "Run the same Maven or Gradle build outside Veracode and correct the first build error.",
         (r"BUILD FAILURE", r"COMPILATION ERROR", r"Execution failed for task .*compile"), 20),
    Rule("DOTNET_BUILD", "autopackager", ".NET build or publish failed", "high", "repository",
         "Run the same dotnet or MSBuild command outside AutoPackager and correct the first compiler or restore error.",
         (r"Build FAILED", r"error CS\d{4}", r"error MSB\d{4}", r"dotnet.*publish.*failed"), 30),
    Rule("DOCKER_PERMISSION", "autopackager", "Docker is unavailable to AutoPackager", "high", "runner",
         "Provide approved Docker access to the runner or use the supported rootless/container configuration.",
         (r"permission denied.*docker\.sock", r"Cannot connect to the Docker daemon", r"docker: command not found"), 10),
    Rule("DISK_SPACE", "autopackager", "Runner disk space exhausted", "high", "runner",
         "Free runner disk space or increase the runner volume.",
         (r"No space left on device", r"ENOSPC", r"not enough space on the disk"), 10),
    Rule("OUT_OF_MEMORY", "autopackager", "Build or AutoPackager ran out of memory", "high", "runner",
         "Increase runner memory or reduce build parallelism and package size.",
         (r"OutOfMemory", r"Java heap space", r"exit code 137", r"Killed process .* out of memory"), 10),
    Rule("NETWORK_TLS", "autopackager", "Network, proxy, DNS, or TLS failure", "high", "runner/network",
         "Verify outbound connectivity, proxy settings, DNS, and enterprise CA trust from the runner.",
         (r"certificate verify failed", r"unable to get local issuer certificate", r"PKIX path building failed", r"Could not resolve host", r"Connection timed out"), 20),
    Rule("AUTOPACKAGER_UNSUPPORTED", "autopackager", "AutoPackager could not identify a supported project", "high", "repository/product",
         "Confirm the application type is supported or provide a manual build-and-upload workflow.",
         (r"No supported projects found", r"unsupported TargetFrameworkVersion", r"Could not find a supported build configuration"), 60),
    Rule("AUTOPACKAGER_FAILED", "autopackager", "AutoPackager build or publish failed", "high", "repository/build",
         "Inspect the first restore, compiler, or toolchain error and reproduce the build outside AutoPackager.",
         (r"Packaging .* artifacts .* failed", r"Publish failed", r"Packager\(s\).*unsuccessful"), 80),
    Rule("NO_ARTIFACTS", "autopackager", "No scan artifacts were produced", "high", "repository/build",
         "Inspect the earlier build error and confirm the application produces supported compiled artifacts.",
         (r"no artifacts identified", r"No artifacts were produced", r"No files were found with the provided path"), 90),
    Rule("UPLOAD_FAILED", "upload", "Artifact upload to Veracode failed", "high", "Veracode/runner",
         "Inspect the upload response, API permissions, application profile, archive format, network path, and file limits.",
         (r"Failed to upload.*Veracode", r"Unable to upload.*Veracode", r"upload.*failed"), 20),
    Rule("PRESCAN_FAILED", "prescan", "Veracode prescan failed", "high", "repository/Veracode",
         "Review prescan module errors, unsupported binaries, duplicate modules, and packaging guidance.",
         (r"prescan.*failed", r"pre-scan.*failed", r"prescan.*error"), 10),
    Rule("NO_MODULES", "prescan", "Prescan found no scannable modules", "high", "repository/build",
         "Verify the uploaded archive contains supported compiled modules.",
         (r"no modules.*selected", r"no modules.*found", r"No modules were detected"), 10),
    Rule("PIPELINE_SCAN_FAILED", "pipeline_scan", "Pipeline scan failed operationally", "high", "Veracode/workflow",
         "Inspect the first pipeline-scan error, confirm artifact validity and API access, and retry.",
         (r"pipeline scan.*failed", r"Pipeline Scan.*error", r"pipeline_scan.*exit code [1-9]"), 20),
    Rule("SCAN_TIMEOUT", "pipeline_scan", "SAST scan timed out", "high", "Veracode/workflow",
         "Review scan status, package size, workflow timeout, and Veracode service health.",
         (r"scan.*timed out", r"Timed out waiting for.*scan", r"timeout.*results"), 10),
    Rule("SCAN_CANCELED", "pipeline_scan", "SAST scan was canceled", "medium", "workflow/user",
         "Determine whether concurrency, a user action, or Veracode canceled the scan.",
         (r"scan.*cancelled", r"scan.*canceled", r"build status.*canceled"), 10),
    Rule("POLICY_SCAN_FAILED", "policy_scan", "Policy scan failed operationally", "high", "Veracode/workflow",
         "Inspect the first policy-scan or results-retrieval error and verify API access and scan completion.",
         (r"policy scan.*failed", r"failed to retrieve.*results", r"Unable to get.*results"), 20),
    Rule("POLICY_FAILED", "policy_scan", "SAST completed but failed policy", "medium", "application team",
         "Review and remediate or mitigate the Veracode policy violations. The scanner completed successfully.",
         (r"policy status.*did not pass", r"policy compliance status.*fail", r"Did Not Pass", r"policy.*failed due to flaws"), 40),
)


@dataclass
class Finding:
    organization: str
    workflow_repository: str
    source_repository: str
    run_id: str
    result: str
    failure_stage: str
    primary_code: str
    primary_failure: str
    severity: str
    owner: str
    recommendation: str
    validation_status: str
    build_status: str
    autopackager_status: str
    artifact_status: str
    upload_status: str
    prescan_status: str
    pipeline_scan_status: str
    policy_scan_status: str
    all_codes: str
    failing_job: str
    evidence: str
    missing_package: str
    actionable_sast: bool
    cleanup_status: str
    cleanup_code: str
    cleanup_evidence: str
    sast_jobs: str
    cleanup_jobs: str
    log_file: str
    manifest_file: str
    collection_exit_code: int


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Bulk Veracode SAST build and scan triage")
    parser.add_argument("--tenant", default="ACX")
    parser.add_argument("--repo", default="veracode")
    parser.add_argument(
        "--targets", type=Path,
        help=("Target file with one org/repo or organization per line. "
              "An organization-only entry processes every repository in that organization."),
    )
    parser.add_argument("--limit", type=positive_int, default=50)
    parser.add_argument("--runs-per-org", type=positive_int, default=10)
    parser.add_argument("--failed-only", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--cli", type=Path, default=Path("github-workflow-cli-sast-fixed.py"))
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--output-dir", type=Path, default=Path("workflow-output"))
    parser.add_argument("--analyze-dir", type=Path)
    parser.add_argument("--include-ok", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    return parser.parse_args()


def load_targets(path: Path) -> list[str]:
    """Load unique org/repo or organization targets from a text file."""
    if not path.is_file():
        raise ValueError(f"targets file not found: {path}")
    targets: list[str] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        target = raw_line.split("#", 1)[0].strip().strip("/")
        if not target:
            continue
        parts = target.split("/")
        if len(parts) > 2 or any(not part.strip() for part in parts):
            raise ValueError(f"invalid target on line {line_number}: {raw_line!r}; expected org/repo or org")
        normalized = "/".join(part.strip() for part in parts)
        if normalized not in targets:
            targets.append(normalized)
    if not targets:
        raise ValueError(f"targets file contains no targets: {path}")
    return targets


def extract_repositories(output: str, organization: str) -> list[str]:
    """Extract org/repo names from the CLI's CSV repository listing."""
    repositories: list[str] = []
    try:
        for row in csv.DictReader(output.splitlines()):
            name = (row.get("name") or "").strip()
            if name:
                repositories.append(f"{organization}/{name}")
    except csv.Error:
        return []
    return list(dict.fromkeys(repositories))


def safe_target_name(repository: str) -> str:
    """Return a filesystem-safe, collision-resistant name for org/repo."""
    return re.sub(r"[^A-Za-z0-9._-]+", "-", repository).strip("-") or "unknown"


def run_capture(command: list[str], output_file: Path) -> tuple[int, str]:
    try:
        completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   encoding="utf-8", errors="replace", text=True, check=False)
        output = completed.stdout or ""
        code = completed.returncode
    except OSError as exc:
        output = f"Unable to start command: {exc}\n"
        code = 127
    output_file.write_text(output, encoding="utf-8")
    return code, output


def extract_run_ids(output: str, maximum: int) -> list[str]:
    ids: list[str] = []
    header = False
    for line in output.splitlines():
        columns = [column.strip() for column in line.split("|")]
        normalized = [column.lower() for column in columns]
        if "number" in normalized and "id" in normalized and "name" in normalized:
            header = True
            continue
        if header and len(columns) >= 3 and columns[1].isdigit():
            ids.append(columns[1])
    if not ids:
        ids.extend(re.findall(r"/actions/runs/(\d{6,20})", output))
    return list(dict.fromkeys(ids))[:maximum]


def source_repository(text: str, organization: str) -> str:
    for pattern in (r"source_repository:\s*([^\s]+)", r"Syncing repository:\s*([^\s]+/[^\s]+)",
                    r"repository:\s*([^\s]+/[^\s]+)", r"INPUT_REPO:\s*([^\s]+)"):
        match = re.search(pattern, text, re.I)
        if match:
            value = match.group(1).strip().rstrip(".,")
            return value if "/" in value else f"{organization}/{value}"
    return "unknown"


def matching_line(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for line in text.splitlines():
            if rx.search(line):
                return re.sub(r"\x1b\[[0-9;]*m", "", line).strip()[-800:]
    return ""


def line_job_name(line: str) -> str:
    return line.split("\t", 1)[0].strip().lstrip("\ufeff") if "\t" in line else ""


def failing_job_for(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for line in text.splitlines():
            if rx.search(line):
                return line_job_name(line)
    return ""


def detect_missing_package(text: str) -> str:
    patterns = (
        r"NU1101: Unable to find package\s+([^\.\s]+(?:\.[^\.\s]+)*)\.",
        r"Could not find artifact\s+([^\s]+)",
        r"Could not resolve\s+([^\s]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).rstrip(".")
    return ""


def default_statuses(failure_stage: str) -> dict[str, str]:
    statuses = {stage: "NOT_STARTED" for stage in STAGE_ORDER if stage != "collection"}
    if failure_stage == "collection":
        return statuses
    failure_rank = STAGE_ORDER[failure_stage]
    for stage, rank in STAGE_ORDER.items():
        if stage == "collection":
            continue
        if rank < failure_rank:
            statuses[stage] = "REACHED"
        elif rank == failure_rank:
            statuses[stage] = "FAILED"
    return statuses


def load_manifest(path: Path | None) -> dict:
    if not path or not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def select_job_lines(text: str, job_names: list[str]) -> str:
    names = set(job_names)
    return "\n".join(
        line for line in text.splitlines()
        if line_job_name(line) in names
    )


def infer_sast_jobs(text: str) -> list[str]:
    jobs: list[str] = []
    pattern = re.compile(
        r"^(?:Validations|build|package|packager|artifact|upload|prescan|pre.?scan|pipeline_scan|policy_scan|scan|results?)(?:\s*/|$)",
        re.I,
    )
    for line in text.splitlines():
        name = line_job_name(line)
        if name and pattern.search(name) and name not in jobs:
            jobs.append(name)
    return jobs


def infer_cleanup_jobs(text: str) -> list[str]:
    jobs: list[str] = []
    for line in text.splitlines():
        name = line_job_name(line)
        if name and re.search(r"^cleanup(?:\s*/|$)", name, re.I) and name not in jobs:
            jobs.append(name)
    return jobs


def first_sast_error(text: str) -> str:
    patterns = (
        r"##\[error\]", r"Process completed with exit code [1-9]",
        r"\b(?:error|fatal|exception|failed|failure)\b",
        r"The operation was canceled", r"The operation was cancelled",
    )
    # Prefer the last specific error over setup warnings, but never use cleanup.
    candidates = []
    for line in text.splitlines():
        if any(re.search(p, line, re.I) for p in patterns):
            candidates.append(re.sub(r"\x1b\[[0-9;]*m", "", line).strip())
    return (candidates[-1] if candidates else "")[-800:]


def infer_failure_stage(job_name: str, text: str) -> str:
    name = job_name.lower()
    if "policy" in name: return "policy_scan"
    if "pipeline" in name or re.search(r"pipeline scan", text, re.I): return "pipeline_scan"
    if "prescan" in name or "pre-scan" in name: return "prescan"
    if "upload" in name: return "upload"
    if "artifact" in name: return "artifact"
    if "validation" in name: return "validation"
    if "build" in name or "package" in name: return "autopackager"
    return "results"


def classify(path: Path, organization: str, workflow_repo: str, run_id: str,
             manifest: Path | None, collection_exit_code: int = 0) -> Finding:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    metadata = load_manifest(manifest)
    sast_jobs = list(metadata.get("sast_jobs") or infer_sast_jobs(text))
    cleanup_jobs = list(metadata.get("cleanup_jobs") or infer_cleanup_jobs(text))
    sast_text = select_job_lines(text, sast_jobs) if sast_jobs else ""
    cleanup_text = select_job_lines(text, cleanup_jobs) if cleanup_jobs else ""
    actionable_sast = bool(sast_jobs and sast_text.strip())
    cleanup_patterns = (
        r"sudo: .*incorrect password attempts", r"sudo: a password is required",
        r"no tty present and no askpass program",
    )
    cleanup_failure = any(re.search(p, cleanup_text or text, re.I) for p in cleanup_patterns)
    cleanup_evidence = matching_line(cleanup_text or text, cleanup_patterns) if cleanup_failure else ""

    # Critical: primary SAST rules are evaluated only against SAST job lines.
    matches = [(rule, matching_line(sast_text, rule.patterns)) for rule in RULES
               if any(re.search(pattern, sast_text, re.I | re.M) for pattern in rule.patterns)]

    if matches:
        primary, evidence = sorted(matches, key=lambda item: item[0].priority)[0]
        codes = ";".join(rule.code for rule, _ in sorted(matches, key=lambda item: item[0].priority))
        result = "POLICY_FAILED" if primary.code == "POLICY_FAILED" else "OPERATIONAL_FAILURE"
    elif collection_exit_code != 0:
        primary = Rule("LOG_COLLECTION_FAILED", "collection", "GitHub run log collection failed", "high", "log collection",
                       "Inspect the gh error, permissions, run ID, and log retention.", (), 999)
        evidence = next((line.strip() for line in text.splitlines() if line.startswith("Error:")), "Log collection failed")
        codes = primary.code
        result = "COLLECTION_FAILED"
    elif actionable_sast:
        evidence = first_sast_error(sast_text)
        error_job = line_job_name(evidence)
        if evidence:
            stage = infer_failure_stage(error_job, evidence)
            primary = Rule("UNCLASSIFIED_SAST_FAILURE", stage, "Actionable SAST job has an unclassified failure", "medium", "triage",
                           "Inspect this SAST-job evidence and add a reusable classifier.", (), 999)
            result = "UNCLASSIFIED_SAST_FAILURE"
        else:
            primary = Rule("SAST_NO_FAILURE_OBSERVED", "results", "SAST jobs were present but no SAST error was observed", "info", "workflow/triage",
                           "The workflow likely failed outside SAST (for example cleanup or registration).", (), 999)
            result = "SAST_NO_FAILURE_OBSERVED"
        codes = primary.code
    elif cleanup_jobs:
        primary = Rule("NO_ACTIONABLE_SAST_LOGS", "collection", "Run has cleanup but no build or scan jobs", "info", "workflow/triage",
                       "Record cleanup separately and inspect another run for the same target.", (), 999)
        evidence = cleanup_evidence or "Cleanup job was present; no SAST jobs were present."
        codes = primary.code
        result = "CLEANUP_ONLY"
    else:
        primary = Rule("NO_ACTIONABLE_SAST_LOGS", "collection", "No recognized SAST jobs were present", "info", "workflow/triage",
                       "Review workflow job names or another run for the same target.", (), 999)
        evidence = "No recognized SAST jobs were present."
        codes = primary.code
        result = "NO_ACTIONABLE_JOBS"

    statuses = default_statuses(primary.stage)
    # Refine successful validation and completed policy states from direct signals.
    if re.search(r"VERACODE_API_ID and VERACODE_API_KEY is valid", sast_text, re.I):
        statuses["validation"] = "SUCCEEDED"
    if primary.code == "POLICY_FAILED":
        statuses["pipeline_scan"] = "COMPLETED"
        statuses["policy_scan"] = "FAILED_POLICY"
    if re.search(r"policy.*pass|passed policy", sast_text, re.I):
        statuses["policy_scan"] = "PASSED"

    return Finding(
        organization=organization,
        workflow_repository=workflow_repo,
        source_repository=source_repository(sast_text or text, organization),
        run_id=run_id,
        result=result,
        failure_stage=primary.stage,
        primary_code=primary.code,
        primary_failure=primary.title,
        severity=primary.severity,
        owner=primary.owner,
        recommendation=primary.recommendation,
        validation_status=statuses["validation"],
        build_status=statuses["build"],
        autopackager_status=statuses["autopackager"],
        artifact_status=statuses["artifact"],
        upload_status=statuses["upload"],
        prescan_status=statuses["prescan"],
        pipeline_scan_status=statuses["pipeline_scan"],
        policy_scan_status=statuses["policy_scan"],
        all_codes=codes,
        failing_job=(failing_job_for(sast_text, primary.patterns) if primary.patterns else line_job_name(evidence)),
        evidence=evidence,
        missing_package=detect_missing_package(sast_text),
        actionable_sast=actionable_sast,
        cleanup_status="FAILED" if cleanup_failure else ("PRESENT" if cleanup_jobs else "NOT_DETECTED"),
        cleanup_code="CLEANUP_SUDO_FAILED" if cleanup_failure else "",
        cleanup_evidence=cleanup_evidence,
        sast_jobs=";".join(sast_jobs),
        cleanup_jobs=";".join(cleanup_jobs),
        log_file=str(path),
        manifest_file=str(manifest) if manifest else "",
        collection_exit_code=collection_exit_code,
    )


def write_reports(directory: Path, findings: list[Finding], include_ok: bool) -> None:
    rows = findings
    fields = list(Finding.__dataclass_fields__)
    with (directory / "sast-findings.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)
    (directory / "sast-findings.json").write_text(
        json.dumps([asdict(row) for row in rows], indent=2), encoding="utf-8")

    counts: dict[str, int] = {}
    for row in rows:
        if row.actionable_sast:
            counts[row.primary_code] = counts.get(row.primary_code, 0) + 1
    cleanup_failed = sum(1 for row in rows if row.cleanup_status == "FAILED")
    cleanup_only = sum(1 for row in rows if row.result == "CLEANUP_ONLY")
    lines = ["# Bulk Veracode SAST triage", "", f"Analyzed: {len(findings)}", f"Reported: {len(rows)}", "", "## SAST outcomes", ""]
    for code, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        title = next(row.primary_failure for row in rows if row.primary_code == code)
        lines.append(f"- **{count}** — `{code}` — {title}")
    lines.extend(["", "## Secondary workflow issues", "", f"- **{cleanup_failed}** — `CLEANUP_SUDO_FAILED`", f"- **{cleanup_only}** — `CLEANUP_ONLY`", "", "## Findings", ""])
    for row in sorted(rows, key=lambda item: (item.organization, item.source_repository, item.run_id)):
        lines.extend([
            f"### {row.source_repository} — run {row.run_id}",
            f"- Result: **{row.result}**",
            f"- Failure stage: `{row.failure_stage}`",
            f"- Cause: **{row.primary_failure}** (`{row.primary_code}`)",
            f"- Job: `{row.failing_job or 'unknown'}`",
            f"- Missing package: `{row.missing_package}`" if row.missing_package else "- Missing package: none detected",
            f"- Validation: `{row.validation_status}`; AutoPackager: `{row.autopackager_status}`; Upload: `{row.upload_status}`; Pipeline scan: `{row.pipeline_scan_status}`; Policy scan: `{row.policy_scan_status}`",
            f"- SAST jobs: `{row.sast_jobs or 'none'}`",
            f"- Cleanup: `{row.cleanup_status}`" + (f" (`{row.cleanup_code}`)" if row.cleanup_code else ""),
            f"- Owner: {row.owner}",
            f"- Action: {row.recommendation}",
            f"- Evidence: `{row.evidence}`" if row.evidence else "- Evidence: no known signature",
            "",
        ])
    (directory / "sast-summary.md").write_text("\n".join(lines), encoding="utf-8")


def infer_filename(path: Path) -> tuple[str, str]:
    match = re.match(r"(.+?)-sast-(\d+)\.log$", path.name)
    return (match.group(1), match.group(2)) if match else ("unknown", "unknown")


def main() -> int:
    args = parse_args()
    result_dir = args.output_dir / f"sast-bulk-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    result_dir.mkdir(parents=True, exist_ok=True)
    findings: list[Finding] = []
    operational_failures = 0

    if args.analyze_dir:
        if not args.analyze_dir.is_dir():
            print(f"ERROR: analysis directory not found: {args.analyze_dir}", file=sys.stderr)
            return 2
        for path in sorted(args.analyze_dir.rglob("*.log")):
            if path.name.endswith("-discovery.log"):
                continue
            organization, run_id = infer_filename(path)
            manifest = path.with_name(f"{path.stem}-jobs.json")
            findings.append(classify(path, organization, f"{organization}/{args.repo}", run_id,
                                     manifest if manifest.is_file() else None))
    else:
        if not args.cli.is_file():
            print(f"ERROR: CLI not found: {args.cli}", file=sys.stderr)
            return 2
        if not args.targets:
            print("ERROR: --targets is required unless --analyze-dir is used", file=sys.stderr)
            return 2
        try:
            requested_targets = load_targets(args.targets)
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2

        workflow_repositories: list[str] = []
        for target in requested_targets:
            if "/" in target:
                workflow_repositories.append(target)
                continue
            organization = target
            repository_list_file = result_dir / f"{safe_target_name(organization)}-repos-discovery.log"
            repository_list_command = [args.python_executable, str(args.cli), "--tenant", args.tenant,
                                       "repos", "--org", organization, "--csv"]
            print(f"Discovering repositories: {organization}")
            code, output = run_capture(repository_list_command, repository_list_file)
            if code != 0:
                operational_failures += 1
                print(f"WARNING: repository discovery failed for {organization}", file=sys.stderr)
                if args.fail_fast:
                    break
                continue
            repositories = extract_repositories(output, organization)
            if not repositories:
                operational_failures += 1
                print(f"WARNING: no repositories found for {organization}", file=sys.stderr)
                if args.fail_fast:
                    break
                continue
            workflow_repositories.extend(repositories)

        for workflow_repo in dict.fromkeys(workflow_repositories):
            organization = workflow_repo.split("/", 1)[0]
            target_name = safe_target_name(workflow_repo)
            discovery_file = result_dir / f"{target_name}-sast-discovery.log"
            discovery = [args.python_executable, str(args.cli), "--tenant", args.tenant,
                         "workflows", "--repo", workflow_repo, "--limit", str(args.limit),
                         "--name", SAST_WORKFLOW_NAME, "--name-break"]
            if args.failed_only:
                discovery.extend(["--conclusion", "failure,cancelled,timed_out,action_required"])
            print(f"Discovering: {workflow_repo}")
            code, output = run_capture(discovery, discovery_file)
            if code != 0:
                operational_failures += 1
                print(f"WARNING: discovery failed for {workflow_repo}", file=sys.stderr)
                if args.fail_fast:
                    break
                continue
            run_ids = extract_run_ids(output, args.runs_per_org)
            for run_id in run_ids:
                log = result_dir / f"{target_name}-sast-{run_id}.log"
                manifest = result_dir / f"{target_name}-sast-{run_id}-jobs.json"
                command = [args.python_executable, str(args.cli), "--tenant", args.tenant,
                           "logs", "--repo", workflow_repo, "--run-id", run_id,
                           "--relevant-only", "--manifest", str(manifest)]
                print(f"Fetching build and scan steps: {workflow_repo} run {run_id}")
                log_code, _ = run_capture(command, log)
                if log_code != 0:
                    operational_failures += 1
                findings.append(classify(log, organization, workflow_repo, run_id,
                                         manifest if manifest.is_file() else None, log_code))
                if log_code != 0 and args.fail_fast:
                    break

    write_reports(result_dir, findings, args.include_ok)
    print(f"\nAnalyzed: {len(findings)}")
    print(f"Summary:  {result_dir / 'sast-summary.md'}")
    print(f"CSV:      {result_dir / 'sast-findings.csv'}")
    print(f"JSON:     {result_dir / 'sast-findings.json'}")
    return 1 if operational_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
