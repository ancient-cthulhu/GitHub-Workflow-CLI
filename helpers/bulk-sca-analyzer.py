#!/usr/bin/env python3
"""Bulk Veracode SCA (agent-based) run triage.

Discovers recent "Software Composition Analysis" runs in each organization's
central workflow repository (the Veracode workflows run only there and scan
the org's other repositories as sources), fetches the complete run logs, and
classifies each run:

* Operational failures (token, agent download, unsupported project, build
  graph resolution, runner problems) are grouped by root cause with evidence.
* Severity gate failures are the gate working, not an error: the scan itself
  succeeded. For these the helper extracts the actionable scan intelligence:
  threshold, finding counts by severity, vulnerable/total libraries, package
  managers, the platform scan URL, and Update Advisor quick wins.
* Clean passes are counted (and listed with --include-ok).
"""

from __future__ import annotations

import argparse
import csv
import os
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")

SCA_WORKFLOW_NAME = "Software Composition Analysis"

# SCA pipeline is simpler than SAST: checkout -> agent setup -> scan ->
# results handling -> severity gate.
STAGE_ORDER = {
    "collection": 0,
    "checkout": 10,
    "agent": 20,
    "scan": 30,
    "results": 40,
    "gate": 50,
}
PIPELINE_STAGES = tuple(stage for stage in STAGE_ORDER if stage != "collection")

PRIMARY_RESULTS = ("OPERATIONAL_FAILURE", "GATE_FAILED", "UNCLASSIFIED_SCA_FAILURE")


@dataclass(frozen=True)
class Rule:
    code: str
    stage: str
    title: str
    severity: str
    recommendation: str
    patterns: tuple[str, ...]
    priority: int


# Priority: lower wins. 5-10 credential/config/infra signatures, 20-40 build
# graph and scan errors, 60 the severity gate, 80+ generic catch-alls.
RULES: tuple[Rule, ...] = (
    # ---- agent credentials and setup ---------------------------------------
    Rule("SRCCLR_AUTH", "agent", "SCA agent token invalid or missing", "high",
         "Rotate or correct the SRCCLR_API_TOKEN secret and verify it is an agent-based scan token with access to the workspace.",
         (r"SRCCLR_API_TOKEN.*(?:invalid|not set|is empty|missing)",
          r"Invalid (?:API )?token", r"401 Unauthorized.*(?:srcclr|sourceclear|veracode)",
          r"authentication failed.*(?:srcclr|sourceclear)"), 5),
    Rule("SRCCLR_FORBIDDEN", "agent", "SCA agent token lacks permissions", "high",
         "Grant the agent token access to the target workspace/team or use a token that has it.",
         (r"403 Forbidden.*(?:srcclr|sourceclear|veracode)",
          r"not authorized.*(?:workspace|scan)"), 5),
    Rule("SRCCLR_RATE_LIMIT", "agent", "SCA service rate limit reached", "medium",
         "Reduce scan frequency or parallelism and retry after the limit window.",
         (r"429 Too Many Requests", r"rate limit.*(?:srcclr|sourceclear)"), 10),
    Rule("AGENT_DOWNLOAD_FAILED", "agent", "SCA agent download or bootstrap failed", "high",
         "Verify the runner can reach download.sourceclear.com (proxy, DNS, TLS) and retry; pin a cached agent if the mirror is flaky.",
         (r"curl.*(?:sourceclear|ci\.sh).*(?:failed|error|\(\d+\))",
          r"Could not resolve host.*(?:sourceclear|veracode)",
          r"Failed to (?:download|install).*agent", r"ci\.sh.*(?:No such file|not found)"), 10),
    Rule("WORKFLOW_INVALID", "checkout", "Workflow file is invalid", "high",
         "Fix the workflow YAML: the run failed before any job could start.",
         (r"Invalid workflow file", r"workflow is not valid", r"error parsing called workflow"), 10),
    # ---- checkout -----------------------------------------------------------
    Rule("CHECKOUT_AUTH", "checkout", "Repository checkout or Git authentication failed", "high",
         "Verify repository access, token permissions, organization policy, and the requested ref.",
         (r"fatal: Authentication failed", r"Repository not found",
          r"couldn't find remote ref", r"Permission to .* denied"), 10),
    Rule("SUBMODULE_FAILED", "checkout", "Git submodule checkout failed", "high",
         "Grant the checkout token access to the submodule repositories or disable submodule checkout.",
         (r"Failed to recurse into submodule", r"No url found for submodule"), 10),
    Rule("GIT_LFS_FAILED", "checkout", "Git LFS object retrieval failed", "high",
         "Verify LFS is enabled, quota is available, and the token can read LFS objects.",
         (r"smudge filter lfs failed", r"Error downloading object"), 10),
    # ---- scan (dependency graph resolution inside the agent) ----------------
    Rule("NO_SUPPORTED_PROJECTS", "scan", "SCA agent found no supported projects", "high",
         "Confirm the repository contains a supported package manager manifest (pom.xml, build.gradle, package.json with lockfile, etc.) or adjust the scan path.",
         (r"No supported projects", r"Could not find any supported project",
          r"did not find any supported"), 10),
    Rule("LOCKFILE_MISSING", "scan", "Lockfile missing or could not be generated", "high",
         "Commit the lockfile or fix the lockfile generator step so the agent can resolve the dependency graph.",
         (r"lockfile.*(?:missing|not found|could not)", r"this will fail - exiting",
          r"yarn-lock-file-generator.*(?:failed|error)", r"pnpm-helper.*(?:failed|error)"), 10),
    Rule("MAVEN_RESOLUTION", "scan", "Maven dependency resolution failed during SCA", "high",
         "Configure the required Maven repository and credentials; the agent must resolve the full graph to scan it.",
         (r"Could not resolve dependencies for project", r"Could not find artifact .* in ",
          r"Non-resolvable parent POM"), 15),
    Rule("GRADLE_RESOLUTION", "scan", "Gradle dependency resolution failed during SCA", "high",
         "Configure the required Gradle repository and credentials; the agent must resolve the full graph to scan it.",
         (r"Could not resolve all files for configuration", r"Could not resolve .* Required by:"), 15),
    Rule("NODE_RESOLUTION", "scan", "Node dependency resolution failed during SCA", "high",
         "Configure the required npm registry and credentials, and make sure the lockfile matches package.json.",
         (r"npm ERR!", r"yarn error", r"ERR_PNPM_"), 15),
    Rule("PYTHON_RESOLUTION", "scan", "Python dependency resolution failed during SCA", "high",
         "Configure the required index/credentials for pip so the agent can resolve requirements.",
         (r"No matching distribution found for", r"Could not find a version that satisfies"), 15),
    Rule("GO_RESOLUTION", "scan", "Go module resolution failed during SCA", "high",
         "Verify GOPROXY/GOPRIVATE settings and module credentials.",
         (r"go: .*unknown revision", r"missing go\.sum entry", r"go: .*module .* not found"), 15),
    Rule("OUT_OF_MEMORY", "scan", "SCA agent ran out of memory", "high",
         "Raise JAVA_OPTS heap limits or runner memory; very large graphs need more than the defaults.",
         (r"OutOfMemory", r"Java heap space", r"exit code 137",
          r"Killed process .* out of memory"), 10),
    Rule("DISK_SPACE", "scan", "Runner disk space exhausted", "high",
         "Free runner disk space or increase the runner volume.",
         (r"No space left on device", r"ENOSPC"), 10),
    Rule("NETWORK_TLS", "scan", "Network, proxy, DNS, or TLS failure", "high",
         "Verify outbound connectivity, proxy settings, DNS, and enterprise CA trust from the runner.",
         (r"certificate verify failed", r"unable to get local issuer certificate",
          r"PKIX path building failed", r"Could not resolve host", r"Connection timed out",
          r"407 Proxy Authentication Required"), 20),
    Rule("GITHUB_RATE_LIMIT", "scan", "GitHub API rate limit reached", "medium",
         "Wait for the rate-limit window, reduce API-heavy steps, or use a token with higher limits.",
         (r"API rate limit exceeded", r"secondary rate limit"), 15),
    Rule("SCAN_ERROR", "scan", "SCA scan failed operationally", "high",
         "Inspect the first agent error; rerun with debug enabled if the cause is unclear.",
         (r"Scan failed", r"Scan finished with exit code:\s*[1-9]",
          r"Error during scan"), 30),
    # ---- results handling / fail-closed gate plumbing ------------------------
    Rule("GATE_SCRIPT_MISSING", "results", "Severity gate script missing (helper checkout failed)", "high",
         "Fix the helper repository checkout (sparse path, token access); the gate fails closed without it.",
         (r"Gate script missing", r"helper checkout failed.*cannot gate"), 10),
    Rule("RESULTS_FILE_MISSING", "results", "No SCA results file was produced", "high",
         "The scan step did not write scaResults.txt/json; inspect the scan step, it likely failed or was skipped.",
         (r"No SCA results file", r"scan may not have run.*[Ff]ailing closed"), 10),
    # ---- the severity gate itself (working as intended) ----------------------
    Rule("SCA_GATE_FAILED", "gate", "Scan succeeded; severity gate failed on findings", "medium",
         "This is the security gate working: remediate the reported components, prioritizing Update Advisor safe versions and criticals, or tune the threshold deliberately.",
         (r"Veracode SCA gate failed", r"severity gate.*FAILED",
          r"##\[error\].*finding\(s\) at or above"), 60),
    # ---- workflow/runner generics (late priority) ----------------------------
    Rule("RUNNER_LOST", "results", "Runner lost communication or was shut down", "medium",
         "Rerun; if recurring, investigate runner stability or resource exhaustion.",
         (r"lost communication with the server", r"runner has received a shutdown signal"), 50),
    Rule("JOB_TIMEOUT", "results", "Job exceeded its maximum execution time", "medium",
         "Increase the job timeout or scan scope; very large graphs can exceed defaults.",
         (r"has exceeded the maximum execution time", r"exceeded the timeout"), 50),
    Rule("CONCURRENCY_CANCELED", "results", "Run was canceled (concurrency, newer run, or manual)", "low",
         "Usually benign: a newer commit or concurrency group superseded this run. Confirm the latest run for the ref succeeded.",
         (r"Canceling since a higher priority waiting request",
          r"The (?:run|operation) was cancell?ed"), 85),
)

CLEANUP_SUDO_PATTERNS = (
    r"sudo: .*incorrect password attempts", r"sudo: a password is required",
    r"no tty present and no askpass program",
)
CLEANUP_GENERIC_PATTERNS = (
    r"##\[error\]", r"Process completed with exit code [1-9]",
)

GATE_PASS_PATTERNS = (
    r"severity gate.*PASSED", r"0 finding\(s\) at or above",
    r"gate passed",
)



@dataclass
class RunnerInfo:
    runner_image: str = ""
    runner_os: str = ""
    runner_name: str = ""
    runner_type: str = "unknown"
    runner_group: str = ""
    requested_labels: str = ""


def detect_runner(text: str) -> RunnerInfo:
    """Detect the runner each job ran on from the Set up job block.

    GitHub-hosted runners print a Runner Image block (Image: ubuntu-24.04,
    windows-2022, macos-14, ...). Note this is the resolved image, not the
    literal runs_on label: windows-latest shows up as its current image.
    Self-hosted runners print Runner name / Machine name instead.
    """
    info = RunnerInfo()
    images: list[str] = []
    os_line = ""
    for raw in text.splitlines():
        content = line_content(raw).strip()
        match = re.match(r"^Image:\s*([A-Za-z0-9._-]+)\s*$", content)
        if match and match.group(1) not in images:
            images.append(match.group(1))
            continue
        if not os_line:
            match = re.match(r"^(Ubuntu|Microsoft Windows.*|Windows Server.*|macOS.*)\s*$", content)
            if match:
                os_line = match.group(1)
        if not info.runner_name:
            match = re.search(r"Runner name:\s*'([^']+)'", content)
            if match:
                info.runner_name = match.group(1)
        if not info.runner_group:
            match = re.search(r"Runner group name:\s*'([^']+)'", content)
            if match:
                info.runner_group = match.group(1)
        if not info.requested_labels:
            match = re.search(r"Requested labels:\s*(.+)$", content)
            if match:
                info.requested_labels = match.group(1).strip()
    info.runner_image = ";".join(images)
    first_image = images[0].lower() if images else ""
    if first_image.startswith("ubuntu"):
        info.runner_os = "linux"
    elif first_image.startswith("windows"):
        info.runner_os = "windows"
    elif first_image.startswith("macos"):
        info.runner_os = "macos"
    elif os_line:
        lowered = os_line.lower()
        info.runner_os = ("windows" if "windows" in lowered
                          else "macos" if "macos" in lowered
                          else "linux" if "ubuntu" in lowered else "")
    if re.search(r"Hosted Compute Agent|Runner Image Provisioner", text):
        info.runner_type = "github-hosted"
    elif info.runner_name:
        info.runner_type = "self-hosted"
    return info


def runner_display(row) -> str:
    label = row.runner_image or row.runner_name or "unknown"
    return f"{label} ({row.runner_type})" if row.runner_type != "unknown" else label


@dataclass
class RunMeta:
    run_id: str
    branch: str = ""
    created_at: str = ""
    conclusion: str = ""
    name: str = ""


@dataclass
class ScanMetrics:
    scan_id: str = ""
    scan_url: str = ""
    threshold: str = ""
    gate_findings: int = -1
    findings_critical: int = -1
    findings_high: int = -1
    findings_medium: int = -1
    findings_low: int = -1
    total_libraries: int = -1
    direct_libraries: int = -1
    transitive_libraries: int = -1
    vulnerable_libraries: int = -1
    package_managers: str = ""
    analysis_time: str = ""
    agent_exit_code: int = -1
    update_advisor: list[str] = field(default_factory=list)
    scan_completed: bool = False


@dataclass
class Finding:
    organization: str
    workflow_repository: str
    source_repository: str
    run_id: str
    run_url: str
    branch: str
    created_at: str
    conclusion: str
    runner_image: str
    runner_os: str
    runner_name: str
    runner_type: str
    runner_group: str
    requested_labels: str
    result: str
    failure_stage: str
    primary_code: str
    primary_failure: str
    severity: str
    recommendation: str
    scan_id: str
    scan_url: str
    threshold: str
    gate_findings: int
    findings_critical: int
    findings_high: int
    findings_medium: int
    findings_low: int
    total_libraries: int
    direct_libraries: int
    transitive_libraries: int
    vulnerable_libraries: int
    package_managers: str
    analysis_time: str
    agent_exit_code: int
    update_advisor: str
    all_codes: str
    failing_job: str
    queue_seconds: str = ""
    jobs_duration_seconds: str = ""
    evidence: str
    cleanup_status: str
    cleanup_code: str
    cleanup_evidence: str
    log_file: str
    collection_exit_code: int


def positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Bulk Veracode SCA (agent-based) run triage",
        epilog=("Without --targets, every organization the token can reach is "
                "discovered via the CLI's 'orgs' command; each maps to its "
                "<org>/<workflow-repo> central workflow repository."),
    )
    parser.add_argument(
        "--targets", type=Path,
        help=("Optional target file with one org/repo or organization per line. "
              "A bare organization maps to <org>/<workflow-repo>."),
    )
    parser.add_argument("--workflow-repo", "--repo", dest="workflow_repo", default="veracode",
                        help=("Name of the central repository that hosts the Veracode workflows "
                              "in each organization (default: veracode)."))
    parser.add_argument("--limit", type=positive_int, default=200,
                        help="Maximum workflow runs to list per repository during discovery")
    parser.add_argument("--runs-per-repo", type=positive_int, default=10,
                        help="Maximum runs to fetch logs for, per repository")
    parser.add_argument("--failed-only", action=argparse.BooleanOptionalAction, default=True,
                        help=("Only analyze failed/cancelled/timed-out runs (default: on). "
                              "Gate failures mark the run as failed, so they are included."))
    parser.add_argument("--verbose", action="store_true",
                        help="Per-run log fetch progress and warnings on the "
                             "console. Default: one aggregate line per repo; "
                             "full detail is always in the findings CSV.")
    parser.add_argument("--last", type=positive_int, metavar="N",
                        help=("Troubleshoot mode: analyze the newest N runs "
                              "chronologically, success or failure alike. "
                              "Shorthand for --no-failed-only --include-ok "
                              "--max-age-days 0 --runs-per-repo N with strict "
                              "newest-first selection (no per-target dedup)."))
    parser.add_argument("--cli", type=Path, default=Path("github-workflow-cli.py"),
                        help="Path to the GitHub Workflow CLI")
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--output-dir", type=Path, default=Path("workflow-output"))
    parser.add_argument("--analyze-dir", type=Path,
                        help="Re-analyze previously collected logs instead of fetching")
    parser.add_argument("--include-ok", action="store_true",
                        help="Also report runs that passed the gate cleanly")
    parser.add_argument("--fetch-configs", action=argparse.BooleanOptionalAction, default=False,
                        help=("Opt in to also save each org's workflow config files (default files: "
                              "veracode.yml and repo-list.yml) under config-files/<org>/ in the "
                              "output folder. Off by default."))
    parser.add_argument("--config-file", dest="config_files", action="append", metavar="NAME",
                        help=("Config file name to fetch from the workflow repo root; repeatable. "
                              "Overrides the default list when given."))
    parser.add_argument("--max-age-days", type=int, default=30,
                        help=("Ignore matched runs older than this many days (default: 30; "
                              "0 disables). Keeps triage focused on current, re-triggerable "
                              "failures instead of stale history."))
    parser.add_argument("--fail-fast", action="store_true")
    return parser.parse_args()


def load_targets(path: Path) -> list[str]:
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


def extract_csv_column(output: str, column: str) -> list[str]:
    values: list[str] = []
    try:
        for row in csv.DictReader(output.splitlines()):
            value = (row.get(column) or "").strip()
            if value:
                values.append(value)
    except csv.Error:
        return []
    return list(dict.fromkeys(values))


def safe_target_name(repository: str) -> str:
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

def first_error_line(output: str) -> str:
    """First line of captured output that looks like an error, for diagnostics."""
    for line in output.splitlines():
        stripped = line.strip()
        if re.search(r"(?:^Error\b|error:|HTTP \d{3}|Not Found|Unauthorized|Forbidden|"
                     r"rate limit|Unable to run|timed out|Traceback)", stripped, re.I):
            return stripped[:300]
    for line in output.splitlines():
        if line.strip():
            return line.strip()[:300]
    return "(no output captured)"


def failure_hint(output: str, workflow_repo: str) -> str:
    """Targeted next step for the most common systematic discovery failures."""
    if re.search(r"HTTP 404|Not Found", output, re.I):
        return (f"hint: {workflow_repo} was not found; if your central workflow repo has a "
                f"different name, set --workflow-repo (verify with: repos --org "
                f"{workflow_repo.split('/', 1)[0]} --csv)")
    if re.search(r"HTTP 401|Unauthorized|Bad credentials", output, re.I):
        return "hint: token rejected; verify GITHUB_TOKEN is exported in this shell (check with: token-info)"
    if re.search(r"HTTP 403|Forbidden|rate limit", output, re.I):
        return "hint: access denied or rate limited; check token scopes/SSO authorization and gh api rate_limit"
    if re.search(r"Unable to run gh|No such file or directory: 'gh'", output, re.I):
        return "hint: the gh CLI is not on PATH for this shell"
    if re.search(r"timed out", output, re.I):
        return "hint: gh timed out; retry or check network/proxy from this host"
    if re.search(r"log not found|HTTP 410", output, re.I):
        return ("hint: run logs expired or were deleted (Actions log retention); "
                "the helper falls back to newer candidates automatically")
    return ""

# Mirror of LOG_ERROR_EXIT_CODES in github-workflow-cli.py.
EXIT_GONE, EXIT_IN_PROGRESS, EXIT_TRANSIENT, EXIT_AUTH, EXIT_NOT_FOUND = 4, 5, 6, 7, 8


def log_failure_category(exit_code: int, output: str) -> str:
    """Categorize a log fetch failure: exit code first, text markers second.

    The CLI emits Error[CATEGORY] markers and category exit codes; the text
    fallback keeps this working against an older CLI copy.
    """
    by_code = {EXIT_GONE: "GONE", EXIT_IN_PROGRESS: "IN_PROGRESS",
               EXIT_TRANSIENT: "TRANSIENT", EXIT_AUTH: "AUTH",
               EXIT_NOT_FOUND: "NOT_FOUND"}
    if exit_code in by_code:
        return by_code[exit_code]
    marker = re.search(r"Error\[(GONE|IN_PROGRESS|TRANSIENT|AUTH|NOT_FOUND)\]", output)
    if marker:
        return marker.group(1)
    if logs_unavailable(output):
        return "GONE"
    if re.search(r"still in progress", output, re.I):
        return "IN_PROGRESS"
    return "UNKNOWN"


def logs_unavailable(output: str) -> bool:
    """True when the failure is expired/deleted run logs, not a real error.

    GitHub deletes run logs after the org's Actions retention window; gh then
    reports "log not found" (API: HTTP 410 Gone). This is a data-availability
    condition, not a tooling failure, and gets fallback handling.
    """
    return bool(re.search(r"log not found|HTTP 410|\bGone\b|logs?(?: have)? expired",
                          output, re.I))




def extract_runs(output: str) -> list[RunMeta]:
    """Parse discovery output (CSV preferred, URL fallback) into run metadata."""
    runs: list[RunMeta] = []
    seen: set[str] = set()
    try:
        for row in csv.DictReader(output.splitlines()):
            run_id = (row.get("id") or "").strip()
            if run_id.isdigit() and run_id not in seen:
                seen.add(run_id)
                runs.append(RunMeta(
                    run_id=run_id,
                    branch=(row.get("branch") or "").strip(),
                    created_at=(row.get("created") or "").strip(),
                    conclusion=(row.get("conclusion") or "").strip(),
                    name=(row.get("name") or "").strip(),
                ))
    except csv.Error:
        pass
    if not runs:
        for run_id in re.findall(r"/actions/runs/(\d{6,20})", output):
            if run_id not in seen:
                seen.add(run_id)
                runs.append(RunMeta(run_id=run_id))
    return runs



def parse_run_time(value: str):
    """Parse an ISO-8601 run timestamp; None when absent or malformed."""
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def run_sort_key(run: RunMeta):
    """Newest first: created timestamp, then run id (higher id is newer)."""
    created = parse_run_time(run.created_at)
    created_key = created.timestamp() if created else 0.0
    id_key = int(run.run_id) if run.run_id.isdigit() else 0
    return (-created_key, -id_key)


def select_runs(runs: list[RunMeta], maximum: int, max_age_days: int,
                newest_overall: bool = False) -> tuple[list[RunMeta], int, int]:
    """Pick the most recent, most actionable runs.

    This is the freshness core of the helper, deliberately defensive:
    1. Age gate: drop runs older than max_age_days (0 disables). Runs with a
       missing or unparsable timestamp are kept, never silently dropped.
    2. Deterministic newest-first ordering by created time then run id, so we
       never depend on upstream output ordering.
    3. Coverage pass: the newest run per distinct run name first. Run names
       encode the scan target (e.g. "Software Composition Analysis -
       verademo"), so every still-failing target gets its latest failure into
       the quota before any target gets a second one.
    4. Backfill pass: remaining quota filled with the next-newest runs overall
       (recent failure history for flapping targets).

    Returns (selected, fallback_pool, matched_count, skipped_by_age).
    """
    matched = len(runs)
    if max_age_days > 0:
        cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=max_age_days)
        fresh = []
        for run in runs:
            created = parse_run_time(run.created_at)
            if created is None or created >= cutoff:
                fresh.append(run)
        runs = fresh
    skipped_by_age = matched - len(runs)

    ordered = sorted(runs, key=run_sort_key)
    if newest_overall:
        # --last mode: literal newest N runs, older ones become fallback.
        return ordered[:maximum], ordered[maximum:], matched, skipped_by_age
    selected: list[RunMeta] = []
    chosen_ids: set[str] = set()
    seen_names: set[str] = set()
    for run in ordered:                      # coverage: newest per scan target
        if len(selected) >= maximum:
            break
        name = getattr(run, "name", "") or ""
        if name and name in seen_names:
            continue
        seen_names.add(name)
        selected.append(run)
        chosen_ids.add(run.run_id)
    for run in ordered:                      # backfill: next newest overall
        if len(selected) >= maximum:
            break
        if run.run_id not in chosen_ids:
            selected.append(run)
            chosen_ids.add(run.run_id)
    selected.sort(key=run_sort_key)
    # Fallback pool: remaining fresh runs, newest first, used when a selected
    # run's logs turn out to be expired so the quota still yields real logs.
    fallback = [run for run in ordered if run.run_id not in chosen_ids]
    return selected, fallback, matched, skipped_by_age


def line_job_name(line: str) -> str:
    return line.split("\t", 1)[0].strip().lstrip("\ufeff") if "\t" in line else ""


def line_content(line: str) -> str:
    """Strip the gh log job/step columns and leading ISO timestamp."""
    content = line.rsplit("\t", 1)[-1] if "\t" in line else line
    return re.sub(r"^\s*\d{4}-\d{2}-\d{2}T[\d:.]+Z\s?", "", content)


def matching_line(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for line in text.splitlines():
            if rx.search(line):
                return re.sub(r"\x1b\[[0-9;]*m", "", line).strip()[-800:]
    return ""


def failing_job_for(text: str, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        rx = re.compile(pattern, re.I)
        for line in text.splitlines():
            if rx.search(line):
                return line_job_name(line)
    return ""


def search_int(text: str, pattern: str) -> int:
    match = re.search(pattern, text, re.I | re.M)
    return int(match.group(1)) if match else -1


def search_str(text: str, pattern: str) -> str:
    match = re.search(pattern, text, re.I | re.M)
    return match.group(1).strip() if match else ""


def extract_update_advisor(text: str) -> list[str]:
    """Parse the Update Advisor table into 'lib current -> safe (breaking: X)' rows."""
    rows: list[str] = []
    in_block = False
    for raw in text.splitlines():
        content = line_content(raw).rstrip()
        if re.match(r"^Update Advisor\s*$", content):
            in_block = True
            continue
        if not in_block:
            continue
        if not content.strip() or content.startswith("Full Report Details"):
            if rows:
                break
            continue
        if "Safe Version" in content:
            continue
        match = re.match(r"^(.+?\S)\s{2,}(\S+)\s{2,}(Yes|No)\s*$", content)
        if match:
            library, safe, breaking = match.groups()
            rows.append(f"{library} -> {safe} (breaking: {breaking.lower()})")
    return rows


def extract_metrics(text: str) -> ScanMetrics:
    metrics = ScanMetrics()
    metrics.scan_id = search_str(text, r"Scan ID\s+([0-9a-fA-F-]{8,})")
    metrics.scan_url = search_str(text, r"Full Report Details\s+(https://\S+)") \
        or search_str(text, r"(https://sca\.analysiscenter\.veracode\.com/\S+)")
    metrics.threshold = search_str(text, r"Resolved SCA severity threshold:\s*(\S+)") \
        or search_str(text, r"at or above '([^']+)'")
    metrics.gate_findings = search_int(text, r"(\d+) finding\(s\) at or above")
    metrics.findings_critical = search_int(text, r"Critical Risk Vulnerabilities\s+(\d+)")
    metrics.findings_high = search_int(text, r"High Risk Vulnerabilities\s+(\d+)")
    metrics.findings_medium = search_int(text, r"Medium Risk Vulnerabilities\s+(\d+)")
    metrics.findings_low = search_int(text, r"Low Risk Vulnerabilities\s+(\d+)")
    metrics.total_libraries = search_int(text, r"Total Libraries\s+(\d+)")
    metrics.direct_libraries = search_int(text, r"Direct Libraries\s+(\d+)")
    metrics.transitive_libraries = search_int(text, r"Transitive Libraries\s+(\d+)")
    metrics.vulnerable_libraries = search_int(text, r"Vulnerable Libraries\s+(\d+)")
    metrics.package_managers = search_str(text, r"Package Manager\(s\)\s+(.+?)\s*$")
    metrics.analysis_time = search_str(text, r"Analysis time\s+(.+?)\s*$")
    metrics.agent_exit_code = search_int(text, r"Scan finished with exit code:\s*(\d+)")
    metrics.update_advisor = extract_update_advisor(text)
    metrics.scan_completed = bool(metrics.scan_url or metrics.agent_exit_code == 0
                                  or "Summary Report" in text)
    return metrics


def source_repository(text: str, run_name: str, organization: str) -> str:
    for pattern in (r"profile_name:\s*(\S+)", r"SCAN_REPO:\s*(\S+)",
                    r"Syncing repository:\s*(\S+/\S+)"):
        match = re.search(pattern, text, re.I)
        if match:
            value = match.group(1).strip().rstrip(".,")
            return value if "/" in value else f"{organization}/{value}"
    match = re.search(rf"{re.escape(SCA_WORKFLOW_NAME)}\s*-\s*(\S+)", run_name)
    if match:
        return f"{organization}/{match.group(1)}"
    return "unknown"


def infer_cleanup_jobs(text: str) -> list[str]:
    jobs: list[str] = []
    for line in text.splitlines():
        name = line_job_name(line)
        if name and re.search(r"^cleanup(?:\s*/|$)", name, re.I) and name not in jobs:
            jobs.append(name)
    return jobs


def select_job_lines(text: str, job_names: list[str]) -> str:
    names = set(job_names)
    return "\n".join(line for line in text.splitlines() if line_job_name(line) in names)


def classify_cleanup(cleanup_text: str, fallback_text: str) -> tuple[str, str]:
    scope = cleanup_text or fallback_text
    evidence = matching_line(scope, CLEANUP_SUDO_PATTERNS)
    if evidence:
        return "CLEANUP_SUDO_FAILED", evidence
    if cleanup_text:
        evidence = matching_line(cleanup_text, CLEANUP_GENERIC_PATTERNS)
        if evidence:
            return "CLEANUP_FAILED", evidence
    return "", ""


def first_error(text: str) -> str:
    patterns = (r"##\[error\]", r"Process completed with exit code [1-9]",
                r"\b(?:error|fatal|exception|failed|failure)\b")
    candidates = []
    for line in text.splitlines():
        if any(re.search(p, line, re.I) for p in patterns):
            candidates.append(re.sub(r"\x1b\[[0-9;]*m", "", line).strip())
    return (candidates[-1] if candidates else "")[-800:]


def run_url_for(workflow_repo: str, run_id: str) -> str:
    if "/" in workflow_repo and run_id.isdigit():
        return f"https://github.com/{workflow_repo}/actions/runs/{run_id}"
    return ""


def default_statuses(failure_stage: str) -> dict[str, str]:
    statuses = {stage: "NOT_STARTED" for stage in PIPELINE_STAGES}
    if failure_stage == "collection":
        return statuses
    failure_rank = STAGE_ORDER[failure_stage]
    for stage in PIPELINE_STAGES:
        rank = STAGE_ORDER[stage]
        if rank < failure_rank:
            statuses[stage] = "REACHED"
        elif rank == failure_rank:
            statuses[stage] = "FAILED"
    return statuses


def classify(path: Path, organization: str, workflow_repo: str, run_meta: RunMeta,
             collection_exit_code: int = 0) -> Finding:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    cleanup_jobs = infer_cleanup_jobs(text)
    cleanup_text = select_job_lines(text, cleanup_jobs) if cleanup_jobs else ""
    cleanup_code, cleanup_evidence = classify_cleanup(cleanup_text, text)
    metrics = extract_metrics(text)
    runner = detect_runner(text)

    matches = [(rule, matching_line(text, rule.patterns)) for rule in RULES
               if any(re.search(pattern, text, re.I | re.M) for pattern in rule.patterns)]

    gate_passed = any(re.search(p, text, re.I) for p in GATE_PASS_PATTERNS)

    if matches:
        primary, evidence = sorted(matches, key=lambda item: item[0].priority)[0]
        codes = ";".join(rule.code for rule, _ in sorted(matches, key=lambda item: item[0].priority))
        result = "GATE_FAILED" if primary.code == "SCA_GATE_FAILED" else "OPERATIONAL_FAILURE"
    elif collection_exit_code != 0:
        primary = Rule("LOG_COLLECTION_FAILED", "collection", "GitHub run log collection failed", "high",
                       "Inspect the gh error, permissions, run ID, and log retention.", (), 999)
        evidence = next((line.strip() for line in text.splitlines() if line.startswith("Error:")),
                        "Log collection failed")
        codes = primary.code
        result = "COLLECTION_FAILED"
    elif metrics.scan_completed and (gate_passed or run_meta.conclusion == "success"):
        primary = Rule("SCA_PASSED", "gate", "Scan completed and passed the severity gate", "info",
                       "No action needed.", (), 999)
        evidence = ""
        codes = primary.code
        result = "SCA_PASSED"
    else:
        evidence = first_error(text)
        if evidence:
            primary = Rule("UNCLASSIFIED_SCA_FAILURE", "scan", "Run failed with an unclassified error", "medium",
                           "Inspect this evidence and add a reusable classifier rule for it.", (), 999)
            result = "UNCLASSIFIED_SCA_FAILURE"
        else:
            primary = Rule("SCA_NO_FAILURE_OBSERVED", "results", "No SCA error was observed in the run log", "info",
                           "The workflow likely failed outside the SCA job.", (), 999)
            result = "SCA_NO_FAILURE_OBSERVED"
        codes = primary.code

    failing_job = (failing_job_for(text, primary.patterns) if primary.patterns
                   else line_job_name(evidence))
    statuses = default_statuses(primary.stage)
    if metrics.scan_completed:
        for stage in ("checkout", "agent", "scan"):
            if statuses[stage] in ("NOT_STARTED", "REACHED"):
                statuses[stage] = "COMPLETED"
    if result == "GATE_FAILED":
        statuses["results"] = "COMPLETED"
        statuses["gate"] = "FAILED_GATE"
    if result == "SCA_PASSED":
        statuses = {stage: "COMPLETED" for stage in PIPELINE_STAGES}

    return Finding(
        organization=organization,
        workflow_repository=workflow_repo,
        source_repository=source_repository(text, run_meta.name, organization),
        run_id=run_meta.run_id,
        run_url=run_url_for(workflow_repo, run_meta.run_id),
        branch=run_meta.branch,
        created_at=run_meta.created_at,
        conclusion=run_meta.conclusion,
        runner_image=runner.runner_image,
        runner_os=runner.runner_os,
        runner_name=runner.runner_name,
        runner_type=runner.runner_type,
        runner_group=runner.runner_group,
        requested_labels=runner.requested_labels,
        result=result,
        failure_stage=primary.stage,
        primary_code=primary.code,
        primary_failure=primary.title,
        severity=primary.severity,
        recommendation=primary.recommendation,
        scan_id=metrics.scan_id,
        scan_url=metrics.scan_url,
        threshold=metrics.threshold,
        gate_findings=metrics.gate_findings,
        findings_critical=metrics.findings_critical,
        findings_high=metrics.findings_high,
        findings_medium=metrics.findings_medium,
        findings_low=metrics.findings_low,
        total_libraries=metrics.total_libraries,
        direct_libraries=metrics.direct_libraries,
        transitive_libraries=metrics.transitive_libraries,
        vulnerable_libraries=metrics.vulnerable_libraries,
        package_managers=metrics.package_managers,
        analysis_time=metrics.analysis_time,
        agent_exit_code=metrics.agent_exit_code,
        update_advisor=";".join(metrics.update_advisor),
        all_codes=codes,
        failing_job=failing_job,
        evidence=evidence,
        cleanup_status="FAILED" if cleanup_code else ("PRESENT" if cleanup_jobs else "NOT_DETECTED"),
        cleanup_code=cleanup_code,
        cleanup_evidence=cleanup_evidence,
        log_file=str(path),
        collection_exit_code=collection_exit_code,
    )


def finding_link(row: Finding) -> str:
    label = f"{row.workflow_repository} run {row.run_id}"
    return f"[{label}]({row.run_url})" if row.run_url else label


def count_or_na(value: int) -> str:
    return str(value) if value >= 0 else "n/a"


def is_reportable(row: Finding, include_ok: bool) -> bool:
    if include_ok:
        return True
    return not (row.result in ("SCA_PASSED", "SCA_NO_FAILURE_OBSERVED") and not row.cleanup_code)


def write_markdown(directory: Path, rows: list[Finding], scope: str = "") -> None:
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    operational = [r for r in rows if r.result in ("OPERATIONAL_FAILURE", "UNCLASSIFIED_SCA_FAILURE")]
    gate_failures = [r for r in rows if r.result == "GATE_FAILED"]
    secondary = [r for r in rows if r.result not in PRIMARY_RESULTS]
    title = f"# Veracode SCA triage: {scope}" if scope else "# Bulk Veracode SCA (agent-based) triage"
    lines = [
        title,
        "",
        f"Generated: {generated}",
        f"Runs analyzed: {len(rows)}",
        f"Operational failures: {len(operational)}",
        f"Severity gate failures (scan succeeded): {len(gate_failures)}",
        f"Secondary or non-actionable runs: {len(secondary)}",
        "",
        "## Failure breakdown",
        "",
    ]
    counts: dict[str, int] = {}
    titles: dict[str, str] = {}
    for row in operational:
        counts[row.primary_code] = counts.get(row.primary_code, 0) + 1
        titles.setdefault(row.primary_code, row.primary_failure)
    for code, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- **{count}** `{code}`: {titles[code]}")
    if gate_failures:
        lines.append(f"- **{len(gate_failures)}** `SCA_GATE_FAILED`: Scan succeeded; severity gate failed on findings")
    if not counts and not gate_failures:
        lines.append("- No failures classified.")
    lines.append("")

    runner_counts: dict[str, int] = {}
    for row in rows:
        runner_counts[runner_display(row)] = runner_counts.get(runner_display(row), 0) + 1
    lines.extend(["## Runner breakdown", ""])
    for label, count in sorted(runner_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- **{count}** on `{label}`")
    lines.append("")

    lines.extend(["## Operational failures by cause", ""])
    if not operational:
        lines.extend(["None.", ""])
    for code, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        group = sorted((r for r in operational if r.primary_code == code),
                       key=lambda r: (r.organization, r.source_repository, r.run_id))
        sample = group[0]
        lines.extend([
            f"### `{code}`: {sample.primary_failure} ({len(group)} run{'s' if len(group) != 1 else ''})",
            "",
            f"**Action:** {sample.recommendation}",
            "",
        ])
        for row in group:
            lines.append(f"- {finding_link(row)}")
            meta_bits = [bit for bit in (
                f"branch `{row.branch}`" if row.branch else "", row.created_at) if bit]
            if meta_bits:
                lines.append(f"  - When/where: {', '.join(meta_bits)}")
            if row.source_repository not in ("unknown", row.workflow_repository):
                lines.append(f"  - Source repository: `{row.source_repository}`")
            lines.append(f"  - Failed at: `{row.failure_stage}`"
                         + (f" in job `{row.failing_job}`" if row.failing_job else ""))
            lines.append(f"  - Runner: `{runner_display(row)}`")
            lines.append(f"  - Evidence: `{row.evidence}`" if row.evidence
                         else "  - Evidence: no known signature")
            if row.all_codes and ";" in row.all_codes:
                lines.append(f"  - Other signals: `{row.all_codes}`")
            lines.append(f"  - Local log: `{row.log_file}`")
            lines.append("")

    lines.extend(["## Severity gate failures (scan intelligence)", ""])
    if gate_failures:
        lines.extend([
            "These scans completed successfully; the gate blocked on findings.",
            "Remediation work belongs to the application teams.",
            "",
        ])
        for row in sorted(gate_failures, key=lambda r: (-max(r.gate_findings, 0), r.source_repository)):
            title = row.source_repository if row.source_repository != "unknown" else row.workflow_repository
            lines.append(f"### {title}")
            lines.append("")
            lines.append(f"- Run: {finding_link(row)}"
                         + (f", branch `{row.branch}`" if row.branch else "")
                         + (f", {row.created_at}" if row.created_at else ""))
            lines.append(f"- Runner: `{runner_display(row)}`")
            threshold = row.threshold or "unknown"
            lines.append(f"- Gate: **{count_or_na(row.gate_findings)}** finding(s) at or above threshold **{threshold}**")
            lines.append(f"- Severity split: critical {count_or_na(row.findings_critical)}, "
                         f"high {count_or_na(row.findings_high)}, "
                         f"medium {count_or_na(row.findings_medium)}, "
                         f"low {count_or_na(row.findings_low)}")
            lines.append(f"- Libraries: {count_or_na(row.vulnerable_libraries)} vulnerable of "
                         f"{count_or_na(row.total_libraries)} total "
                         f"({count_or_na(row.direct_libraries)} direct, "
                         f"{count_or_na(row.transitive_libraries)} transitive)")
            if row.package_managers:
                lines.append(f"- Package manager(s): {row.package_managers}"
                             + (f"; analysis time {row.analysis_time}" if row.analysis_time else ""))
            if row.scan_url:
                lines.append(f"- Full report: {row.scan_url}")
            advisor = [entry for entry in row.update_advisor.split(";") if entry]
            if advisor:
                lines.append("- Update Advisor quick wins (safe versions already identified):")
                for entry in advisor[:8]:
                    lines.append(f"  - `{entry}`")
                if len(advisor) > 8:
                    lines.append(f"  - plus {len(advisor) - 8} more in the CSV/JSON output")
            lines.append("")
    else:
        lines.extend(["None.", ""])

    cleanup_failures = [r for r in rows if r.cleanup_code]
    other_secondary = [r for r in secondary if not r.cleanup_code]
    lines.extend([
        "## Secondary issues",
        "",
        "Cleanup failures are real workflow failures but are not scan blockers;",
        "they are tracked here so they never mask the primary cause.",
        "",
        f"### Cleanup failures ({len(cleanup_failures)})",
        "",
    ])
    if cleanup_failures:
        for row in sorted(cleanup_failures, key=lambda r: (r.organization, r.source_repository, r.run_id)):
            lines.append(f"- {finding_link(row)}: `{row.cleanup_code}`")
            if row.cleanup_evidence:
                lines.append(f"  - Evidence: `{row.cleanup_evidence}`")
    else:
        lines.append("- None detected.")
    lines.append("")
    lines.extend([f"### Non-actionable, passed, or collection-limited runs ({len(other_secondary)})", ""])
    if other_secondary:
        for row in sorted(other_secondary, key=lambda r: (r.organization, r.source_repository, r.run_id)):
            lines.append(f"- {finding_link(row)}: `{row.result}` ({row.primary_failure})")
    else:
        lines.append("- None.")
    lines.append("")
    (directory / "sca-summary.md").write_text("\n".join(lines), encoding="utf-8")


def write_org_reports(org_dir: Path, organization: str, rows: list[Finding]) -> None:
    org_dir.mkdir(parents=True, exist_ok=True)
    fields = list(Finding.__dataclass_fields__)
    with (org_dir / "sca-findings.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)
    (org_dir / "sca-findings.json").write_text(
        json.dumps([asdict(row) for row in rows], indent=2), encoding="utf-8")
    write_markdown(org_dir, rows, scope=organization)


def write_index(directory: Path, by_org: dict[str, list[Finding]]) -> None:
    """Fleet index: one row per org with counts and a link to its report."""
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Veracode SCA triage index",
        "",
        f"Generated: {generated}",
        f"Organizations: {len(by_org)}",
        "",
        "| Org | Runs | Operational failures | Gate failures | Top cause | Report |",
        "|:--|:--|:--|:--|:--|:--|",
    ]
    for organization in sorted(by_org):
        rows = by_org[organization]
        operational = [r for r in rows if r.result in ("OPERATIONAL_FAILURE", "UNCLASSIFIED_SCA_FAILURE")]
        gates = [r for r in rows if r.result == "GATE_FAILED"]
        cause_counts: dict[str, int] = {}
        for row in operational:
            cause_counts[row.primary_code] = cause_counts.get(row.primary_code, 0) + 1
        top_cause = max(cause_counts.items(), key=lambda item: item[1])[0] if cause_counts \
            else ("SCA_GATE_FAILED" if gates else "none")
        folder = safe_target_name(organization)
        lines.append(f"| {organization} | {len(rows)} | {len(operational)} | {len(gates)} "
                     f"| `{top_cause}` | [sca-summary.md](orgs/{folder}/sca-summary.md) |")
    lines.append("")
    (directory / "index.md").write_text("\n".join(lines), encoding="utf-8")


def parse_config_runs_on(text: str) -> dict[str, str]:
    """Best-effort runs_on extraction from a veracode.yml, no YAML dependency.

    Handles inline (runs_on: self-hosted) and list form. Tracks the YAML path
    by indentation so default:runs_on and actions:<scan>:build:runs_on are
    kept apart. Tolerant of partial or slightly malformed files by design.
    """
    results = {"default": "", "build_static": "", "build_sca": ""}
    lines = text.splitlines()
    stack: list[tuple[int, str]] = []
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("- "):
            continue
        indent = len(raw) - len(raw.lstrip())
        match = re.match(r"([A-Za-z_][\w-]*):\s*(.*)$", stripped)
        if not match:
            continue
        key, value = match.group(1), match.group(2).strip()
        while stack and stack[-1][0] >= indent:
            stack.pop()
        path = [name for _, name in stack] + [key]
        if key == "runs_on":
            labels = value
            if not labels:
                items = []
                for follow in lines[index + 1:]:
                    follow_stripped = follow.strip()
                    follow_indent = len(follow) - len(follow.lstrip())
                    if follow_stripped.startswith("- ") and follow_indent > indent:
                        items.append(follow_stripped[2:].strip().strip("'\""))
                    elif follow_stripped and not follow_stripped.startswith("#"):
                        break
                labels = ", ".join(items)
            labels = labels.strip().strip("'\"")
            if path[0] == "default":
                results["default"] = labels
            elif "actions" in path and "build" in path:
                if "veracode_static_scan" in path:
                    results["build_static"] = labels
                elif "veracode_sca_scan" in path:
                    results["build_sca"] = labels
        stack.append((indent, key))
    return results



GITHUB_HOSTED_LABEL = re.compile(r"^(ubuntu|windows|macos)-", re.I)


def looks_github_hosted(label: str) -> bool:
    """True for GitHub-hosted label shapes (ubuntu-*, windows-*, macos-*).

    Custom self-hosted labels (runner1, build-box) do not match, so runs on
    custom-labeled runners are not misclassified as hosted.
    """
    return bool(GITHUB_HOSTED_LABEL.match(label.strip()))


def lint_runs_on(text: str) -> tuple[str, list[str]]:
    """Parse default:runs_on and flag the config mistakes that silently
    disable it. Returns (parsed default value, warnings)."""
    warnings: list[str] = []
    if re.search(r"^\s*runs-on\s*:", text, re.M):
        warnings.append("found 'runs-on:' (hyphen); the integration key is runs_on")
    if re.search(r"^\s*default_runs_on\s*:", text, re.M):
        warnings.append("found 'default_runs_on:'; the shape is 'default:' with nested 'runs_on:'")
    if "\t" in text:
        warnings.append("file contains tab characters; YAML indentation must be spaces")
    parsed = parse_config_runs_on(text)
    if not parsed["default"] and re.search(r"^\s+runs_on\s*:", text, re.M):
        warnings.append("runs_on exists but not under top-level 'default:'; "
                        "it is ignored for the default runner")
    return parsed["default"], warnings


def fetch_run_jobs(args: argparse.Namespace, workflow_repo: str, run_id: str) -> dict:
    """Per-job requested labels and resolved runner via the CLI 'jobs' command.

    state is per run: 'github-hosted' (all jobs hosted), 'self-hosted' (none),
    'mixed' (both in one run; hosted_jobs names which ones). Resolved runner
    group is authoritative (GitHub-hosted always reports group
    "GitHub Actions"); label shape is the fallback for unplaced jobs. Jobs
    metadata outlives log retention, so this works for expired-log runs too.
    """
    command = [args.python_executable, str(args.cli), "jobs",
               "--repo", workflow_repo, "--run-id", run_id]
    info: dict = {"labels": set(), "runner_names": set(),
                  "runner_groups": set(), "state": None, "hosted_jobs": [],
                  "first_started": "", "last_completed": ""}
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return info
    if completed.returncode != 0 or not completed.stdout.strip():
        return info
    votes = []
    for row in csv.DictReader(completed.stdout.splitlines()):
        labels = (row.get("labels") or "").strip()
        name = (row.get("runner_name") or "").strip()
        group = (row.get("runner_group") or "").strip()
        job_name = (row.get("name") or "").strip()
        started = (row.get("started_at") or "").strip()
        completed = (row.get("completed_at") or "").strip()
        if started and (not info["first_started"]
                        or started < info["first_started"]):
            info["first_started"] = started
        if completed and completed > info["last_completed"]:
            info["last_completed"] = completed
        if labels:
            info["labels"].add(labels)
        if name:
            info["runner_names"].add(name)
        if group:
            info["runner_groups"].add(group)
            hosted = group == "GitHub Actions"
        elif labels:
            hosted = all(looks_github_hosted(part)
                         for part in labels.split(";"))
        else:
            continue
        votes.append(hosted)
        if hosted and job_name:
            info["hosted_jobs"].append(job_name)
    if votes:
        if all(votes):
            info["state"] = "github-hosted"
        elif not any(votes):
            info["state"] = "self-hosted"
        else:
            info["state"] = "mixed"
    return info


def fetch_org_runner_inventory(args: argparse.Namespace,
                               organization: str) -> dict[str, dict]:
    """Org self-hosted runner inventory via the CLI 'runners' command.

    name -> {os, status, labels}. Any runner name observed on a job that is
    NOT in this inventory is a GitHub-hosted larger runner or an
    enterprise-level runner: hosted infrastructure with a custom group name,
    which group-based classification alone cannot distinguish.
    """
    command = [args.python_executable, str(args.cli), "runners",
               "--org", organization]
    inventory: dict[str, dict] = {}
    try:
        completed = subprocess.run(command, capture_output=True, text=True,
                                   timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return inventory
    if completed.returncode != 0 or not completed.stdout.strip():
        return inventory
    for row in csv.DictReader(completed.stdout.splitlines()):
        name = (row.get("name") or "").strip()
        if name:
            inventory[name] = {
                "os": (row.get("os") or "").strip(),
                "status": (row.get("status") or "").strip(),
                "labels": (row.get("labels") or "").strip(),
            }
    return inventory


def compute_timings(run_created: str, info: dict) -> tuple[str, str]:
    """(queue_seconds, jobs_duration_seconds) from ISO timestamps.

    Queue = dispatch to first job start; the single best signal for label
    mismatch or saturated self-hosted runners. Empty strings when data is
    missing or malformed rather than guessing.
    """
    def parse(stamp: str):
        try:
            return dt.datetime.fromisoformat(stamp.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            return None
    created = parse(run_created)
    first = parse(info.get("first_started", ""))
    last = parse(info.get("last_completed", ""))
    queue = ""
    duration = ""
    if created and first:
        seconds = int((first - created).total_seconds())
        if seconds >= 0:
            queue = str(seconds)
    if first and last:
        seconds = int((last - first).total_seconds())
        if seconds >= 0:
            duration = str(seconds)
    return queue, duration


def apply_jobs_info(finding, info: dict) -> None:
    """Prefer API-sourced runner facts over log scraping on the finding."""
    if info["labels"]:
        finding.requested_labels = " | ".join(sorted(info["labels"]))
    if info["runner_groups"]:
        finding.runner_group = ";".join(sorted(info["runner_groups"]))
    if info["state"]:
        finding.runner_type = info["state"]
    if info["state"] in ("self-hosted", "mixed") and info["runner_names"]:
        finding.runner_name = ";".join(
            name for name in sorted(info["runner_names"])
            if not name.startswith("GitHub Actions"))


def write_reports(directory: Path, findings: list[Finding], include_ok: bool) -> None:
    """Write per-org report folders plus a fleet index, never one big report."""
    reportable = [row for row in findings if is_reportable(row, include_ok)]
    by_org: dict[str, list[Finding]] = {}
    for row in reportable:
        by_org.setdefault(row.organization, []).append(row)
    for organization, rows in sorted(by_org.items()):
        write_org_reports(directory / "orgs" / safe_target_name(organization), organization, rows)
    write_index(directory, by_org)


def infer_filename(path: Path) -> tuple[str, str]:
    match = re.match(r"(.+?)-sca-(\d+)\.log$", path.name)
    return (match.group(1), match.group(2)) if match else ("unknown", "unknown")



DEFAULT_CONFIG_FILES = ("veracode.yml", "repo-list.yml")


def fetch_config_files(args: argparse.Namespace, result_dir: Path,
                       workflow_repo: str, fetched_orgs: set[str]) -> None:
    """Save the org's workflow config files under config-files/<org>/.

    Fetches each configured file (default: veracode.yml and repo-list.yml)
    from the root of the central workflow repository. Missing files are
    normal in some orgs and only produce a note, never a failure.
    """
    organization = workflow_repo.split("/", 1)[0]
    if organization in fetched_orgs:
        return
    fetched_orgs.add(organization)
    config_dir = result_dir / "config-files" / safe_target_name(organization)
    for name in (args.config_files or list(DEFAULT_CONFIG_FILES)):
        command = [args.python_executable, str(args.cli),
                   "contents", "--repo", workflow_repo, "--path", name]
        try:
            completed = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       encoding="utf-8", errors="replace", text=True, check=False)
        except OSError as exc:
            print(f"WARNING: unable to fetch {workflow_repo}/{name}: {exc}", file=sys.stderr)
            continue
        if completed.returncode != 0 or not (completed.stdout or "").strip():
            print(f"NOTE: {name} not found in {workflow_repo}")
            continue
        config_dir.mkdir(parents=True, exist_ok=True)
        destination = config_dir / Path(name).name
        destination.write_text(completed.stdout, encoding="utf-8")
        print(f"Saved config: {destination}")


def discover_organizations(args: argparse.Namespace, result_dir: Path) -> list[str]:
    discovery_file = result_dir / "orgs-discovery.log"
    command = [args.python_executable, str(args.cli), "orgs", "--csv"]
    print("Discovering organizations accessible to the token")
    code, output = run_capture(command, discovery_file)
    if code != 0:
        print("ERROR: organization discovery failed; provide --targets or check the token", file=sys.stderr)
        return []
    organizations = extract_csv_column(output, "org")
    if not organizations:
        print("ERROR: token has no visible organizations; provide --targets", file=sys.stderr)
    return organizations


def main() -> int:
    args = parse_args()
    if args.last:
        # One flag, one intent: recent runs regardless of outcome.
        args.failed_only = False
        args.include_ok = True
        args.max_age_days = 0
        args.runs_per_repo = args.last
    result_dir = args.output_dir / f"sca-bulk-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
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
            findings.append(classify(path, organization, f"{organization}/{args.workflow_repo}",
                                     RunMeta(run_id=run_id)))
    else:
        if not args.cli.is_file():
            print(f"ERROR: CLI not found: {args.cli}", file=sys.stderr)
            return 2

        if args.targets:
            try:
                requested_targets = load_targets(args.targets)
            except (OSError, UnicodeError, ValueError) as exc:
                print(f"ERROR: {exc}", file=sys.stderr)
                return 2
        else:
            requested_targets = discover_organizations(args, result_dir)
            if not requested_targets:
                return 2

        workflow_repositories: list[str] = []
        for target in requested_targets:
            # The Veracode workflows run only in the central workflow repo of
            # each org, so a bare organization maps straight to it.
            if "/" in target:
                workflow_repositories.append(target)
            else:
                workflow_repositories.append(f"{target}/{args.workflow_repo}")

        fetched_config_orgs: set[str] = set()
        for workflow_repo in dict.fromkeys(workflow_repositories):
            organization = workflow_repo.split("/", 1)[0]
            target_name = safe_target_name(workflow_repo)
            logs_dir = result_dir / "orgs" / safe_target_name(organization) / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            if args.fetch_configs:
                fetch_config_files(args, result_dir, workflow_repo, fetched_config_orgs)
            discovery_file = logs_dir / f"{target_name}-sca-discovery.log"
            discovery = [args.python_executable, str(args.cli),
                         "workflows", "--repo", workflow_repo, "--limit", str(args.limit),
                         "--name", SCA_WORKFLOW_NAME, "--csv"]
            if args.failed_only:
                discovery.extend(["--conclusion",
                                  "failure,cancelled,timed_out,action_required,startup_failure,stale"])
            print(f"Discovering: {workflow_repo}")
            code, output = run_capture(discovery, discovery_file)
            if code != 0:
                operational_failures += 1
                print(f"WARNING: discovery failed for {workflow_repo} (exit {code}): "
                      f"{first_error_line(output)}", file=sys.stderr)
                hint = failure_hint(output, workflow_repo)
                if hint:
                    print(f"  {hint}", file=sys.stderr)
                print(f"  full output: {discovery_file}", file=sys.stderr)
                if args.fail_fast:
                    break
                continue
            matched_runs = extract_runs(output)
            if matched_runs:
                by_conclusion: dict[str, int] = {}
                for run in matched_runs:
                    key = run.conclusion or "in_progress"
                    by_conclusion[key] = by_conclusion.get(key, 0) + 1
                breakdown = ", ".join(
                    f"{count} {name}" for name, count in
                    sorted(by_conclusion.items(), key=lambda kv: (-kv[1], kv[0])))
                print(f"Discovery: {len(matched_runs)} run(s): {breakdown}")
            selected_runs, fallback_runs, matched, skipped_by_age = select_runs(
                matched_runs, args.runs_per_repo, args.max_age_days,
                newest_overall=bool(args.last))
            if not matched:
                print(f"NOTE: no matching runs in the newest {args.limit} runs of "
                      f"{workflow_repo}; if failures are older, raise --limit")
            elif not selected_runs:
                print(f"NOTE: {matched} matching run(s) in {workflow_repo} but all older "
                      f"than {args.max_age_days} days; raise --max-age-days to include them")
            else:
                order_note = ("newest first" if args.last
                              else "newest per scan target first")
                print(f"Runs: matched {matched}, selected {len(selected_runs)} "
                      f"({order_note})"
                      + (f", skipped {skipped_by_age} older than {args.max_age_days}d"
                         if skipped_by_age else ""))
            # Candidates beyond the selection serve as fallback when a selected
            # run's logs are expired, so the quota still yields actionable logs.
            candidates = selected_runs + fallback_runs
            attempts_budget = max(args.runs_per_repo * 3, args.runs_per_repo + 5)
            fetched = 0
            attempts = 0
            expired_runs = 0
            runs_hosted = 0
            runs_selfhosted = 0
            runs_mixed = 0
            mixed_hosted_jobs: set[str] = set()
            failure_categories: dict[str, int] = {}
            runner_inventory = fetch_org_runner_inventory(args, organization)
            if runner_inventory:
                summary = ", ".join(
                    f"{name} ({facts['os']}, {facts['status']}, "
                    f"labels: {facts['labels']})"
                    for name, facts in sorted(runner_inventory.items()))
                print(f"Self-hosted inventory for {organization}: {summary}")
            else:
                print(f"Self-hosted inventory for {organization}: none visible "
                      f"(no org-level runners, or token lacks "
                      f"organization_self_hosted_runners:read)")
            observed_nonhosted_names: set[str] = set()
            payload_labels: set[str] = set()
            stop = False
            for run_meta in candidates:
                if fetched >= args.runs_per_repo or attempts >= attempts_budget:
                    break
                attempts += 1
                run_id = run_meta.run_id
                log = logs_dir / f"{target_name}-sca-{run_id}.log"
                # SCA jobs are not named like SAST pipeline jobs, so fetch the
                # complete run log; this helper does its own extraction.
                command = [args.python_executable, str(args.cli),
                           "logs", "--repo", workflow_repo, "--run-id", run_id]
                if args.verbose:
                    print(f"Fetching run log: {workflow_repo} run {run_id}")
                log_code, log_output = run_capture(command, log)
                jobs_info = fetch_run_jobs(args, workflow_repo, run_id)
                if jobs_info["labels"]:
                    payload_labels.update(jobs_info["labels"])
                if jobs_info["state"] == "github-hosted":
                    runs_hosted += 1
                elif jobs_info["state"] == "self-hosted":
                    runs_selfhosted += 1
                elif jobs_info["state"] == "mixed":
                    runs_mixed += 1
                    mixed_hosted_jobs.update(jobs_info["hosted_jobs"])
                if jobs_info["state"] in ("self-hosted", "mixed"):
                    observed_nonhosted_names.update(
                        name for name in jobs_info["runner_names"]
                        if not name.startswith("GitHub Actions"))
                category = ("OK" if log_code == 0
                            else log_failure_category(log_code, log_output))
                if category == "IN_PROGRESS":
                    # Run not finished: no logs exist yet by design. Skip to
                    # the next candidate without recording a failure.
                    if args.verbose:
                        print(f"NOTE: run {run_id} still in progress, "
                              f"trying next candidate")
                    continue
                if category == "GONE":
                    # Expired retention is data availability, not a tooling
                    # failure: record it, try the next-newest candidate, and do
                    # not flip the helper exit code for it.
                    expired_runs += 1
                    finding = classify(log, organization, workflow_repo, run_meta, log_code)
                    finding.result = "LOGS_UNAVAILABLE"
                    finding.primary_code = "LOGS_UNAVAILABLE"
                    finding.primary_failure = "Run logs expired or deleted (Actions retention)"
                    finding.severity = "info"
                    finding.recommendation = ("Logs are gone from GitHub; lower --max-age-days "
                                              "toward the org's Actions log retention window, "
                                              "or re-trigger the scan for fresh logs.")
                    apply_jobs_info(finding, jobs_info)
                    finding.queue_seconds, finding.jobs_duration_seconds = (
                    compute_timings(run_meta.created_at, jobs_info))
                    findings.append(finding)
                    continue
                if log_code != 0:
                    operational_failures += 1
                    failure_categories[category] = (
                        failure_categories.get(category, 0) + 1)
                    if args.verbose:
                        print(f"WARNING: log fetch failed for {workflow_repo} run "
                              f"{run_id} ({category}, exit {log_code}): "
                              f"{first_error_line(log_output)}", file=sys.stderr)
                        if category == "TRANSIENT":
                            print("  hint: GitHub log backend flaked; the CLI "
                                  "already retried with backoff, re-run later "
                                  "for this run", file=sys.stderr)
                        else:
                            hint = failure_hint(log_output, workflow_repo)
                            if hint:
                                print(f"  {hint}", file=sys.stderr)
                    if category == "AUTH":
                        # Every subsequent fetch will fail identically; bail out
                        # of this repo instead of burning the attempts budget.
                        print(f"  aborting remaining fetches for {workflow_repo}: "
                              f"auth failures repeat", file=sys.stderr)
                        finding = classify(log, organization, workflow_repo,
                                           run_meta, log_code)
                        apply_jobs_info(finding, jobs_info)
                        finding.queue_seconds, finding.jobs_duration_seconds = (
                            compute_timings(run_meta.created_at, jobs_info))
                        findings.append(finding)
                        break
                else:
                    fetched += 1
                finding = classify(log, organization, workflow_repo, run_meta, log_code)
                apply_jobs_info(finding, jobs_info)
                finding.queue_seconds, finding.jobs_duration_seconds = (
                    compute_timings(run_meta.created_at, jobs_info))
                findings.append(finding)
                if log_code != 0 and args.fail_fast:
                    stop = True
                    break
            if failure_categories and not args.verbose:
                breakdown = ", ".join(
                    f"{count} {name}" for name, count in
                    sorted(failure_categories.items(), key=lambda kv: -kv[1]))
                print(f"Log fetch issues in {workflow_repo}: {breakdown} "
                      f"(rerun with --verbose for per-run detail)",
                      file=sys.stderr)
            total_checked = runs_hosted + runs_selfhosted + runs_mixed
            if total_checked:
                print(f"RUNNER CHECK {workflow_repo}: {runs_selfhosted} self-hosted, "
                      f"{runs_mixed} mixed, {runs_hosted} GitHub-hosted of "
                      f"{total_checked} run(s); payload labels seen: "
                      f"{sorted(payload_labels)}")
                impostors = observed_nonhosted_names - set(runner_inventory)
                if impostors and runner_inventory:
                    print(f"  NOT IN YOUR INVENTORY: {sorted(impostors)} "
                          f"classified self-hosted by runner group, but absent "
                          f"from {organization}'s self-hosted runners. These "
                          f"are GitHub-hosted larger runners or "
                          f"enterprise-level runners.")
                if runs_mixed:
                    print(f"  MIXED: jobs on GitHub-hosted while the rest of the "
                          f"run was self-hosted: {sorted(mixed_hosted_jobs)}")
                    if any("build" in job.lower() for job in mixed_hosted_jobs):
                        print("  => build jobs use build_runs_on from "
                              "actions:<scan_type>:build:runs_on, not "
                              "default:runs_on; set that key in this org's "
                              "veracode.yml")
                config = (result_dir / "config-files"
                          / safe_target_name(organization) / "veracode.yml")
                if config.is_file():
                    default_value, lint_warnings = lint_runs_on(
                        config.read_text(encoding="utf-8", errors="replace"))
                    print(f"  CONFIG: default:runs_on parses as "
                          f"{default_value or '(not set)'}")
                    for warning in lint_warnings:
                        print(f"  CONFIG LINT: {warning}")
                    config_labels = [part.strip()
                                     for part in default_value.split(",")
                                     if part.strip()]
                    wants_self = bool(config_labels) and not all(
                        looks_github_hosted(part) for part in config_labels)
                    if wants_self and runs_hosted == total_checked:
                        print("  => PROOF: config asks for self-hosted but no dispatch "
                              "payload contained self-hosted labels. The app reads "
                              "veracode.yml from the veracode repo's DEFAULT branch at "
                              "dispatch time. Verify: (1) the repo's default branch is "
                              "the branch you edited, (2) the file is veracode.yml at "
                              "the repo root, (3) then push a fresh commit to a scanned "
                              "repo and re-check its newest run's labels.")
                    elif not wants_self and not lint_warnings:
                        print("  => fetched config does not request self-hosted; fix "
                              "this org's veracode.yml")
                else:
                    print("  (run with --fetch-configs to cross-check this org's "
                          "veracode.yml against the payload labels)")
            if expired_runs:
                print(f"NOTE: {expired_runs} run(s) in {workflow_repo} had expired logs "
                      f"(Actions retention); fell back to older candidates, "
                      f"fetched {fetched} with logs")
            if stop:
                break

    write_reports(result_dir, findings, args.include_ok)
    config_root = result_dir / "config-files"
    print(f"\nAnalyzed: {len(findings)}")
    if config_root.is_dir():
        print(f"Configs:  {config_root}")
    print(f"Index:    {result_dir / 'index.md'}")
    print(f"Per-org:  {result_dir / 'orgs'}{os.sep}<org>{os.sep}sca-summary.md (.csv, .json)")
    return 1 if operational_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
