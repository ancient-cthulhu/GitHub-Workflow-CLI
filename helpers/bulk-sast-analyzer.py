#!/usr/bin/env python3
"""Bulk Veracode SAST build and scan triage.

Discovers recent Static Code Analysis runs across every organization the
GitHub token can reach (or an explicit target list), uses the GitHub Workflow
CLI to fetch complete run logs, retains build/AutoPackager/upload/prescan/
pipeline-scan/policy-scan jobs, and classifies the real operational failure.

Cleanup failures are tracked but reported separately at the bottom of the
Markdown summary; they never mask the primary SAST failure.
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
from dataclasses import asdict, dataclass
from pathlib import Path

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

PIPELINE_STAGES = tuple(stage for stage in STAGE_ORDER if stage != "collection")

PRIMARY_RESULTS = ("OPERATIONAL_FAILURE", "POLICY_FAILED", "UNCLASSIFIED_SAST_FAILURE")


@dataclass(frozen=True)
class Rule:
    code: str
    stage: str
    title: str
    severity: str
    recommendation: str
    patterns: tuple[str, ...]
    priority: int


# Priority: lower wins. 5-10 exact credential/config/infra signatures,
# 20-40 specific build/dependency errors, 50-70 stage-level failures,
# 80+ generic catch-alls (cancellation, packaging fallbacks).
RULES: tuple[Rule, ...] = (
    # ---- validation -------------------------------------------------------
    Rule("VERACODE_AUTH", "validation", "Veracode API authentication failed", "high",
         "Rotate or correct the Veracode API credentials (VERACODE_API_ID/KEY secrets) and verify permissions, region, and expiration.",
         (r"VERACODE_API_ID.*invalid", r"Invalid credentials", r"authentication failed.*Veracode",
          r"401 Unauthorized.*(?:Veracode|analysiscenter|veracode\.com)",
          r"(?:VERACODE_API_ID|VERACODE_API_KEY).*(?:not set|is empty|missing)"), 5),
    Rule("VERACODE_PERMISSION", "validation", "Veracode API identity lacks required permissions", "high",
         "Grant the API service account the required roles (Upload and Scan, Results) or use an identity that has them.",
         (r"403 Forbidden.*(?:Veracode|analysiscenter|veracode\.com)", r"insufficient permissions.*Veracode",
          r"not authorized to (?:upload|scan|view)"), 5),
    Rule("VERACODE_RATE_LIMIT", "validation", "Veracode API rate limit reached", "medium",
         "Reduce request frequency or parallelism, add backoff between runs, and retry after the limit window.",
         (r"429 Too Many Requests", r"rate limit.*(?:Veracode|analysiscenter)"), 10),
    Rule("INVALID_POLICY", "validation", "Veracode policy validation failed", "high",
         "Correct the policy name or verify the API identity can access the configured policy.",
         (r"invalid policy", r"policy .* not found", r"validatePolicyName.*failed"), 10),
    Rule("APP_PROFILE_NOT_FOUND", "validation", "Veracode application profile not found", "high",
         "Create the application profile, correct the app name/ID input, or grant the API identity access to it.",
         (r"application (?:profile )?.*not found", r"app_id.*not found", r"Could not find application",
          r"No application profile.*matches"), 10),
    Rule("SANDBOX_NOT_FOUND", "validation", "Veracode sandbox not found", "high",
         "Create the sandbox, correct the sandbox name input, or allow auto-creation in the workflow.",
         (r"sandbox.*not found", r"Could not find sandbox"), 10),
    Rule("SCAN_IN_PROGRESS", "validation", "A Veracode scan is already in progress for this application", "medium",
         "Wait for the in-flight scan to finish or delete the incomplete build, then rerun. Consider serializing scans per app.",
         (r"scan is already in progress", r"not in a state where.*(?:new builds|scans)",
          r"app.*is in state.*(?:Pre-?Scan|Scan In Process)", r"A build is already in progress"), 10),
    # ---- build (checkout / source) ----------------------------------------
    Rule("CHECKOUT_AUTH", "build", "Repository checkout or Git authentication failed", "high",
         "Verify repository access, token permissions, organization policy, and the requested ref.",
         (r"fatal: Authentication failed", r"Repository not found", r"couldn't find remote ref",
          r"Permission to .* denied"), 10),
    Rule("SUBMODULE_FAILED", "build", "Git submodule checkout failed", "high",
         "Grant the checkout token access to the submodule repositories or disable submodule checkout.",
         (r"Failed to recurse into submodule", r"fatal: clone of .* into submodule",
          r"No url found for submodule"), 10),
    Rule("GIT_LFS_FAILED", "build", "Git LFS object retrieval failed", "high",
         "Verify LFS is enabled for the repository, LFS quota is available, and the token can read LFS objects.",
         (r"smudge filter lfs failed", r"Error downloading object", r"batch response: .*(?:401|403|404|rate limit)"), 10),
    # ---- autopackager (dependencies) ---------------------------------------
    Rule("DOTNET_TARGETING_PACK", "autopackager", "Missing .NET Framework targeting pack", "high",
         "Install the required .NET Framework Developer/Targeting Pack on the runner or retarget the application.",
         (r"MSB3644:.*reference assemblies for \.NETFramework,Version=v([0-9.]+) were not found",), 10),
    Rule("NUGET_PRIVATE_FEED", "autopackager", "Private NuGet package or feed unavailable", "high",
         "Configure and authenticate the private NuGet source before AutoPackager runs, then verify restore independently.",
         (r"NU1101: Unable to find package", r"No packages exist with this id in source\(s\)"), 10),
    Rule("NUGET_AUTH", "autopackager", "NuGet feed authentication failed", "high",
         "Correct private NuGet feed credentials and verify the runner can access the service index.",
         (r"NU1301: Unable to load the service index", r"401 \(Unauthorized\).*NuGet",
          r"Response status code does not indicate success: 401"), 10),
    Rule("MAVEN_DEPENDENCY", "autopackager", "Maven dependency resolution failed", "high",
         "Configure the required Maven repository and credentials and verify the Maven build before packaging.",
         (r"Could not resolve dependencies for project", r"Could not find artifact .* in ",
          r"Non-resolvable parent POM"), 10),
    Rule("GRADLE_DEPENDENCY", "autopackager", "Gradle dependency resolution failed", "high",
         "Configure the required Gradle repository and credentials and verify the Gradle build before packaging.",
         (r"Could not resolve all files for configuration", r"Could not resolve .* Required by:",
          r"Could not find .*\.pom"), 10),
    Rule("NODE_DEPENDENCY", "autopackager", "Node package installation failed", "high",
         "Configure the required npm registry and credentials, then verify npm, Yarn, or pnpm installation.",
         (r"npm ERR!", r"yarn error", r"ERR_PNPM_", r"401 Unauthorized.*registry"), 10),
    Rule("PYTHON_DEPENDENCY", "autopackager", "Python dependency installation failed", "high",
         "Configure the required index/credentials for pip and verify the install command outside the workflow.",
         (r"No matching distribution found for", r"Could not find a version that satisfies the requirement",
          r"ERROR: pip's dependency resolver", r"error: subprocess-exited-with-error"), 10),
    Rule("GO_DEPENDENCY", "autopackager", "Go module resolution or build failed", "high",
         "Verify GOPROXY/GOPRIVATE settings, module credentials, and go.sum entries, then rerun the build locally.",
         (r"go: .*unknown revision", r"missing go\.sum entry", r"cannot find package",
          r"go: .*module .* not found"), 10),
    Rule("RUBY_DEPENDENCY", "autopackager", "Ruby gem installation failed", "high",
         "Configure the required gem source/credentials and verify bundle install outside the workflow.",
         (r"Could not find gem", r"Bundler::(?:GemNotFound|HTTPError|PermissionError)",
          r"An error occurred while installing"), 10),
    Rule("PHP_DEPENDENCY", "autopackager", "PHP Composer dependency resolution failed", "high",
         "Configure the required Composer repository/credentials and verify composer install outside the workflow.",
         (r"Your requirements could not be resolved", r"composer.*(?:could not|failed to) (?:find|download)"), 10),
    # ---- autopackager (compilation) ----------------------------------------
    Rule("JAVA_BUILD", "autopackager", "Java build or compilation failed", "high",
         "Run the same Maven or Gradle build outside Veracode and correct the first build error.",
         (r"BUILD FAILURE", r"COMPILATION ERROR", r"Execution failed for task .*compile"), 20),
    Rule("DOTNET_BUILD", "autopackager", ".NET build or publish failed", "high",
         "Run the same dotnet or MSBuild command outside AutoPackager and correct the first compiler or restore error.",
         (r"Build FAILED", r"error CS\d{4}", r"error MSB\d{4}", r"dotnet.*publish.*failed"), 30),
    Rule("TYPESCRIPT_BUILD", "autopackager", "TypeScript compilation failed", "high",
         "Run tsc locally and correct the first compiler error before packaging.",
         (r"error TS\d{4}",), 30),
    Rule("NATIVE_BUILD", "autopackager", "C/C++ or native build failed", "high",
         "Run make or the native toolchain locally and correct the first compile or link error.",
         (r"make: \*\*\* .* Error \d+", r"undefined reference to",
          r"fatal error: .*\.h: No such file or directory"), 30),
    # ---- autopackager (environment) ----------------------------------------
    Rule("TOOLCHAIN_SETUP_FAILED", "autopackager", "Toolchain setup action failed", "high",
         "Verify the requested JDK/Node/.NET/Python version exists for the setup action and the runner can download it.",
         (r"Unable to (?:find|download) (?:Java|Node|\.NET|Python|version)",
          r"Version .* (?:not found|was not found).*(?:setup|tool cache)",
          r"Could not find satisfied version"), 10),
    Rule("DOCKER_PERMISSION", "autopackager", "Docker is unavailable to AutoPackager", "high",
         "Provide approved Docker access to the runner or use the supported rootless/container configuration.",
         (r"permission denied.*docker\.sock", r"Cannot connect to the Docker daemon",
          r"docker: command not found"), 10),
    Rule("DISK_SPACE", "autopackager", "Runner disk space exhausted", "high",
         "Free runner disk space or increase the runner volume.",
         (r"No space left on device", r"ENOSPC", r"not enough space on the disk"), 10),
    Rule("OUT_OF_MEMORY", "autopackager", "Build or AutoPackager ran out of memory", "high",
         "Increase runner memory or reduce build parallelism and package size.",
         (r"OutOfMemory", r"Java heap space", r"exit code 137", r"Killed process .* out of memory"), 10),
    Rule("NETWORK_TLS", "autopackager", "Network, proxy, DNS, or TLS failure", "high",
         "Verify outbound connectivity, proxy settings (including 407 auth), DNS, and enterprise CA trust from the runner.",
         (r"certificate verify failed", r"unable to get local issuer certificate",
          r"PKIX path building failed", r"Could not resolve host", r"Connection timed out",
          r"407 Proxy Authentication Required", r"self.signed certificate in certificate chain"), 20),
    Rule("GITHUB_RATE_LIMIT", "autopackager", "GitHub API rate limit reached", "medium",
         "Wait for the rate-limit window, reduce API-heavy steps, or use a token with higher limits.",
         (r"API rate limit exceeded", r"secondary rate limit"), 15),
    # ---- autopackager (outcome catch-alls) ---------------------------------
    Rule("AUTOPACKAGER_UNSUPPORTED", "autopackager", "AutoPackager could not identify a supported project", "high",
         "Confirm the application type is supported or provide a manual build-and-upload workflow.",
         (r"No supported projects found", r"unsupported TargetFrameworkVersion",
          r"Could not find a supported build configuration"), 60),
    Rule("AUTOPACKAGER_FAILED", "autopackager", "AutoPackager build or publish failed", "high",
         "Inspect the first restore, compiler, or toolchain error and reproduce the build outside AutoPackager.",
         (r"Packaging .* artifacts .* failed", r"Publish failed", r"Packager\(s\).*unsuccessful",
          r"veracode package.*(?:failed|error)"), 80),
    Rule("NO_ARTIFACTS", "autopackager", "No scan artifacts were produced", "high",
         "Inspect the earlier build error and confirm the application produces supported compiled artifacts.",
         (r"no artifacts identified", r"No artifacts were produced",
          r"No files were found with the provided path"), 90),
    # ---- artifact handling --------------------------------------------------
    Rule("ARTIFACT_TRANSFER_FAILED", "artifact", "Workflow artifact upload/download failed", "high",
         "Retry the run; if persistent, check artifact size limits, retention, and runner connectivity to GitHub.",
         (r"Unable to download artifact", r"Artifact not found",
          r"Failed to (?:upload|download) artifact(?!.*Veracode)"), 20),
    # ---- upload -------------------------------------------------------------
    Rule("ARCHIVE_TOO_LARGE", "upload", "Scan archive exceeds Veracode size limits", "high",
         "Reduce the package size (exclude third-party binaries, debug symbols, test data) per Veracode packaging guidance.",
         (r"exceeds the maximum.*size", r"file size limit.*exceeded", r"upload.*too large"), 10),
    Rule("VERACODE_UNAVAILABLE", "upload", "Veracode platform unavailable or server error", "medium",
         "Check Veracode status, then retry. Persistent 5xx responses warrant a Veracode support ticket.",
         (r"50[0-4] .*(?:Veracode|analysiscenter|veracode\.com)", r"Service Unavailable.*Veracode",
          r"Veracode Platform is (?:currently )?unavailable"), 15),
    Rule("UPLOAD_FAILED", "upload", "Artifact upload to Veracode failed", "high",
         "Inspect the upload response, API permissions, application profile, archive format, network path, and file limits.",
         (r"Failed to upload.*Veracode", r"Unable to upload.*Veracode", r"upload.*failed"), 20),
    # ---- prescan ------------------------------------------------------------
    Rule("NO_MODULES", "prescan", "Prescan found no scannable modules", "high",
         "Verify the uploaded archive contains supported compiled modules.",
         (r"no modules.*selected", r"no modules.*found", r"No modules were detected"), 10),
    Rule("PRESCAN_MODULE_ERRORS", "prescan", "Prescan reported module errors", "high",
         "Fix the reported module issues (missing debug info, unsupported architecture, missing dependencies) per Veracode packaging guidance.",
         (r"missing debug (?:info|information|symbols)", r"unsupported (?:architecture|platform|file type)",
          r"Duplicate module", r"missing supporting files"), 10),
    Rule("PRESCAN_FAILED", "prescan", "Veracode prescan failed", "high",
         "Review prescan module errors, unsupported binaries, duplicate modules, and packaging guidance.",
         (r"prescan.*failed", r"pre-scan.*failed", r"prescan.*error"), 20),
    # ---- pipeline scan ------------------------------------------------------
    Rule("BASELINE_FILE_ERROR", "pipeline_scan", "Pipeline scan baseline file problem", "medium",
         "Verify the baseline file path, format, and that it was generated by a compatible pipeline-scan version.",
         (r"baseline file.*(?:not found|invalid|could not)", r"Unable to (?:read|parse) baseline"), 10),
    Rule("SCAN_TIMEOUT", "pipeline_scan", "SAST scan timed out", "high",
         "Review scan status, package size, workflow timeout, and Veracode service health.",
         (r"scan.*timed out", r"Timed out waiting for.*scan", r"timeout.*results"), 10),
    Rule("PIPELINE_FINDINGS_GATE", "pipeline_scan", "Pipeline scan completed and failed on findings", "medium",
         "This is the security gate working: triage the reported flaws, remediate or baseline them. The scanner itself succeeded.",
         (r"fail_on_severity", r"FAILURE: Found \d+ issues?", r"Found \d+ issues? of (?:Very High|High|Medium)"), 30),
    Rule("PIPELINE_SCAN_FAILED", "pipeline_scan", "Pipeline scan failed operationally", "high",
         "Inspect the first pipeline-scan error, confirm artifact validity and API access, and retry.",
         (r"pipeline scan.*failed", r"Pipeline Scan.*error", r"pipeline_scan.*exit code [1-9]"), 40),
    # ---- policy scan --------------------------------------------------------
    Rule("POLICY_SCAN_FAILED", "policy_scan", "Policy scan failed operationally", "high",
         "Inspect the first policy-scan or results-retrieval error and verify API access and scan completion.",
         (r"policy scan.*failed", r"failed to retrieve.*results", r"Unable to get.*results"), 20),
    Rule("POLICY_FAILED", "policy_scan", "SAST completed but failed policy", "medium",
         "This is the security gate working: review and remediate or mitigate the Veracode policy violations. The scanner completed successfully.",
         (r"policy status.*did not pass", r"policy compliance status.*fail", r"Did Not Pass",
          r"policy.*failed due to flaws"), 40),
    # ---- workflow/runner level (generic signals, late priority) -------------
    Rule("WORKFLOW_INVALID", "validation", "Workflow file is invalid", "high",
         "Fix the workflow YAML: the run failed before any job could start.",
         (r"Invalid workflow file", r"workflow is not valid",
          r"error parsing called workflow"), 10),
    Rule("RUNNER_LOST", "results", "Runner lost communication or was shut down", "medium",
         "Rerun; if recurring, investigate self-hosted runner stability, spot-instance eviction, or resource exhaustion.",
         (r"lost communication with the server", r"runner has received a shutdown signal",
          r"The self-hosted runner .* (?:lost|is offline)"), 50),
    Rule("JOB_TIMEOUT", "results", "Job exceeded its maximum execution time", "medium",
         "Increase the job timeout or reduce work per job; check for hangs waiting on Veracode results.",
         (r"has exceeded the maximum execution time", r"exceeded the timeout"), 50),
    Rule("VERACODE_WRAPPER_EXCEPTION", "results", "Veracode API wrapper threw an exception", "high",
         "Inspect the Java exception from the Veracode wrapper; verify wrapper version, inputs, and API access.",
         (r"com\.veracode\..*Exception", r"Exception in thread .*veracode"), 45),
    Rule("CONCURRENCY_CANCELED", "results", "Run was canceled (concurrency, newer run, or manual)", "low",
         "Usually benign: a newer commit or concurrency group superseded this run. Confirm the latest run for the ref succeeded.",
         (r"Canceling since a higher priority waiting request", r"The (?:run|operation) was cancell?ed",
          r"scan.*cancell?ed", r"build status.*cancell?ed"), 85),
)


CLEANUP_SUDO_PATTERNS = (
    r"sudo: .*incorrect password attempts", r"sudo: a password is required",
    r"no tty present and no askpass program",
)
CLEANUP_GENERIC_PATTERNS = (
    r"##\[error\]", r"Process completed with exit code [1-9]",
)



@dataclass
class RunnerInfo:
    runner_image: str = ""
    runner_os: str = ""
    runner_name: str = ""
    runner_type: str = "unknown"


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
    result: str
    failure_stage: str
    primary_code: str
    primary_failure: str
    severity: str
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
    parser = argparse.ArgumentParser(
        description="Bulk Veracode SAST build and scan triage",
        epilog=("Without --targets, every organization the token can reach is "
                "discovered via the CLI's 'orgs' command and processed."),
    )
    parser.add_argument(
        "--targets", type=Path,
        help=("Optional target file with one org/repo or organization per line. "
              "An organization-only entry processes every repository in that "
              "organization. Omit to auto-discover all accessible organizations."),
    )
    parser.add_argument("--workflow-repo", "--repo", dest="workflow_repo", default="veracode",
                        help=("Name of the central repository that hosts the Veracode workflows "
                              "in each organization (default: veracode). Bare organization targets "
                              "map to <org>/<workflow-repo>."))
    parser.add_argument("--limit", type=positive_int, default=200,
                        help="Maximum workflow runs to list per repository during discovery")
    parser.add_argument("--runs-per-repo", "--runs-per-org", dest="runs_per_repo",
                        type=positive_int, default=10,
                        help="Maximum runs to fetch logs for, per repository")
    parser.add_argument("--failed-only", action=argparse.BooleanOptionalAction, default=True,
                        help="Only analyze failed/cancelled/timed-out runs (default: on)")
    parser.add_argument("--cli", type=Path, default=Path("github-workflow-cli.py"),
                        help="Path to the GitHub Workflow CLI")
    parser.add_argument("--python", dest="python_executable", default=sys.executable)
    parser.add_argument("--output-dir", type=Path, default=Path("workflow-output"))
    parser.add_argument("--analyze-dir", type=Path,
                        help="Re-analyze previously collected logs instead of fetching")
    parser.add_argument("--include-ok", action="store_true",
                        help="Also report runs where no SAST failure was observed")
    parser.add_argument("--fetch-configs", action=argparse.BooleanOptionalAction, default=False,
                        help=("Opt in to also save each org's workflow config files (default files: "
                              "veracode.yml and repo_list.yml) under config-files/<org>/ in the "
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


def extract_csv_column(output: str, column: str) -> list[str]:
    """Extract a named column from the CLI's CSV output."""
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

def logs_unavailable(output: str) -> bool:
    """True when the failure is expired/deleted run logs, not a real error.

    GitHub deletes run logs after the org's Actions retention window; gh then
    reports "log not found" (API: HTTP 410 Gone). This is a data-availability
    condition, not a tooling failure, and gets fallback handling.
    """
    return bool(re.search(r"log not found|HTTP 410|\bGone\b|logs?(?: have)? expired",
                          output, re.I))




def extract_runs(output: str) -> list[RunMeta]:
    """Parse discovery output (CSV preferred, table/URL fallback) into run metadata."""
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
        header = False
        for line in output.splitlines():
            columns = [column.strip() for column in line.split("|")]
            normalized = [column.lower() for column in columns]
            if "number" in normalized and "id" in normalized and "name" in normalized:
                header = True
                continue
            if header and len(columns) >= 3 and columns[1].isdigit() and columns[1] not in seen:
                seen.add(columns[1])
                runs.append(RunMeta(
                    run_id=columns[1],
                    conclusion=columns[4] if len(columns) > 4 else "",
                    created_at=columns[5] if len(columns) > 5 else "",
                    branch=columns[8] if len(columns) > 8 else "",
                ))
    if not runs:
        for run_id in re.findall(r"/actions/runs/(\d{6,20})", output):
            if run_id not in seen:
                seen.add(run_id)
                runs.append(RunMeta(run_id=run_id))
    return runs


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


def select_runs(runs: list[RunMeta], maximum: int, max_age_days: int) -> tuple[list[RunMeta], int, int]:
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
        r"No matching distribution found for\s+([^\s]+)",
        r"Could not find gem\s+'?([^'\s]+)",
        r"Could not resolve\s+([^\s]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, text, re.I)
        if match:
            return match.group(1).rstrip(".")
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


def classify_cleanup(cleanup_text: str, fallback_text: str) -> tuple[str, str]:
    """Return (cleanup_code, evidence). Cleanup problems never become primary."""
    scope = cleanup_text or fallback_text
    evidence = matching_line(scope, CLEANUP_SUDO_PATTERNS)
    if evidence:
        return "CLEANUP_SUDO_FAILED", evidence
    if cleanup_text:
        evidence = matching_line(cleanup_text, CLEANUP_GENERIC_PATTERNS)
        if evidence:
            return "CLEANUP_FAILED", evidence
    return "", ""


def run_url_for(workflow_repo: str, run_id: str) -> str:
    if "/" in workflow_repo and run_id.isdigit():
        return f"https://github.com/{workflow_repo}/actions/runs/{run_id}"
    return ""


def classify(path: Path, organization: str, workflow_repo: str, run_meta: RunMeta,
             manifest: Path | None, collection_exit_code: int = 0) -> Finding:
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    metadata = load_manifest(manifest)
    sast_jobs = list(metadata.get("sast_jobs") or infer_sast_jobs(text))
    cleanup_jobs = list(metadata.get("cleanup_jobs") or infer_cleanup_jobs(text))
    sast_text = select_job_lines(text, sast_jobs) if sast_jobs else ""
    cleanup_text = select_job_lines(text, cleanup_jobs) if cleanup_jobs else ""
    actionable_sast = bool(sast_jobs and sast_text.strip())
    cleanup_code, cleanup_evidence = classify_cleanup(cleanup_text, text)
    runner = detect_runner(text)

    # Critical: primary SAST rules are evaluated only against SAST job lines.
    matches = [(rule, matching_line(sast_text, rule.patterns)) for rule in RULES
               if any(re.search(pattern, sast_text, re.I | re.M) for pattern in rule.patterns)]

    if matches:
        primary, evidence = sorted(matches, key=lambda item: item[0].priority)[0]
        codes = ";".join(rule.code for rule, _ in sorted(matches, key=lambda item: item[0].priority))
        result = "POLICY_FAILED" if primary.code in ("POLICY_FAILED", "PIPELINE_FINDINGS_GATE") \
            else "OPERATIONAL_FAILURE"
    elif collection_exit_code != 0:
        primary = Rule("LOG_COLLECTION_FAILED", "collection", "GitHub run log collection failed", "high",
                       "Inspect the gh error, permissions, run ID, and log retention.", (), 999)
        evidence = next((line.strip() for line in text.splitlines() if line.startswith("Error:")), "Log collection failed")
        codes = primary.code
        result = "COLLECTION_FAILED"
    elif actionable_sast:
        evidence = first_sast_error(sast_text)
        error_job = line_job_name(evidence)
        if evidence:
            stage = infer_failure_stage(error_job, evidence)
            primary = Rule("UNCLASSIFIED_SAST_FAILURE", stage, "Actionable SAST job has an unclassified failure", "medium",
                           "Inspect this SAST-job evidence and add a reusable classifier rule for it.", (), 999)
            result = "UNCLASSIFIED_SAST_FAILURE"
        else:
            primary = Rule("SAST_NO_FAILURE_OBSERVED", "results", "SAST jobs were present but no SAST error was observed", "info",
                           "The workflow likely failed outside SAST (for example cleanup or registration).", (), 999)
            result = "SAST_NO_FAILURE_OBSERVED"
        codes = primary.code
    elif cleanup_jobs:
        primary = Rule("NO_ACTIONABLE_SAST_LOGS", "collection", "Run has cleanup but no build or scan jobs", "info",
                       "Record cleanup separately and inspect another run for the same target.", (), 999)
        evidence = cleanup_evidence or "Cleanup job was present; no SAST jobs were present."
        codes = primary.code
        result = "CLEANUP_ONLY"
    else:
        primary = Rule("NO_ACTIONABLE_SAST_LOGS", "collection", "No recognized SAST jobs were present", "info",
                       "Review workflow job names or another run for the same target.", (), 999)
        evidence = "No recognized SAST jobs were present."
        codes = primary.code
        result = "NO_ACTIONABLE_JOBS"

    failing_job = (failing_job_for(sast_text, primary.patterns) if primary.patterns
                   else line_job_name(evidence))
    effective_stage = primary.stage
    # Generic run-level rules (runner lost, timeout, cancel) land in "results";
    # pin the stage to where the failing job actually sat when we can tell.
    if primary.stage == "results" and failing_job:
        effective_stage = infer_failure_stage(failing_job, evidence)

    statuses = default_statuses(effective_stage)
    # Refine successful validation and completed policy states from direct signals.
    if re.search(r"VERACODE_API_ID and VERACODE_API_KEY is valid", sast_text, re.I):
        statuses["validation"] = "SUCCEEDED"
    if primary.code in ("POLICY_FAILED", "PIPELINE_FINDINGS_GATE"):
        statuses["pipeline_scan"] = "COMPLETED"
        statuses["policy_scan"] = "FAILED_POLICY"
    elif re.search(r"policy.*pass|passed policy", sast_text, re.I):
        statuses["policy_scan"] = "PASSED"

    return Finding(
        organization=organization,
        workflow_repository=workflow_repo,
        source_repository=source_repository(sast_text or text, organization),
        run_id=run_meta.run_id,
        run_url=run_url_for(workflow_repo, run_meta.run_id),
        branch=run_meta.branch,
        created_at=run_meta.created_at,
        conclusion=run_meta.conclusion,
        runner_image=runner.runner_image,
        runner_os=runner.runner_os,
        runner_name=runner.runner_name,
        runner_type=runner.runner_type,
        result=result,
        failure_stage=effective_stage,
        primary_code=primary.code,
        primary_failure=primary.title,
        severity=primary.severity,
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
        failing_job=failing_job,
        evidence=evidence,
        missing_package=detect_missing_package(sast_text),
        actionable_sast=actionable_sast,
        cleanup_status="FAILED" if cleanup_code else ("PRESENT" if cleanup_jobs else "NOT_DETECTED"),
        cleanup_code=cleanup_code,
        cleanup_evidence=cleanup_evidence,
        sast_jobs=";".join(sast_jobs),
        cleanup_jobs=";".join(cleanup_jobs),
        log_file=str(path),
        manifest_file=str(manifest) if manifest else "",
        collection_exit_code=collection_exit_code,
    )


def pipeline_progress(row: Finding) -> str:
    """Compact one-line stage progression, e.g. validation:ok -> upload:FAILED."""
    labels = {
        "REACHED": "reached", "SUCCEEDED": "ok", "COMPLETED": "ok", "PASSED": "ok",
        "FAILED": "FAILED", "FAILED_POLICY": "FAILED_POLICY", "NOT_STARTED": None,
    }
    stage_status = {
        "validation": row.validation_status, "build": row.build_status,
        "autopackager": row.autopackager_status, "artifact": row.artifact_status,
        "upload": row.upload_status, "prescan": row.prescan_status,
        "pipeline_scan": row.pipeline_scan_status, "policy_scan": row.policy_scan_status,
    }
    parts: list[str] = []
    for stage, status in stage_status.items():
        label = labels.get(status, status)
        if label is None:
            continue
        parts.append(f"{stage}:{label}")
    return " -> ".join(parts) if parts else "no stage reached"


def finding_link(row: Finding) -> str:
    label = f"{row.workflow_repository} run {row.run_id}"
    return f"[{label}]({row.run_url})" if row.run_url else label


def is_reportable(row: Finding, include_ok: bool) -> bool:
    if include_ok:
        return True
    return not (row.result == "SAST_NO_FAILURE_OBSERVED" and not row.cleanup_code)


def write_markdown(directory: Path, rows: list[Finding], scope: str = "") -> None:
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    primary_rows = [r for r in rows if r.result in PRIMARY_RESULTS]
    secondary_rows = [r for r in rows if r.result not in PRIMARY_RESULTS]
    title = f"# Veracode SAST triage: {scope}" if scope else "# Bulk Veracode SAST triage"
    lines = [
        title,
        "",
        f"Generated: {generated}",
        f"Runs analyzed: {len(rows)}",
        f"Primary SAST failures: {len(primary_rows)}",
        f"Secondary or non-actionable runs: {len(secondary_rows)}",
        "",
        "## Failure breakdown",
        "",
    ]
    counts: dict[str, int] = {}
    titles: dict[str, str] = {}
    for row in primary_rows:
        counts[row.primary_code] = counts.get(row.primary_code, 0) + 1
        titles.setdefault(row.primary_code, row.primary_failure)
    if counts:
        for code, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
            lines.append(f"- **{count}** `{code}`: {titles[code]}")
    else:
        lines.append("- No primary SAST failures classified.")
    lines.append("")

    runner_counts: dict[str, int] = {}
    for row in rows:
        runner_counts[runner_display(row)] = runner_counts.get(runner_display(row), 0) + 1
    lines.extend(["## Runner breakdown", ""])
    for label, count in sorted(runner_counts.items(), key=lambda item: (-item[1], item[0])):
        lines.append(f"- **{count}** on `{label}`")
    lines.append("")

    lines.extend(["## Findings by cause", ""])
    if not primary_rows:
        lines.extend(["No primary findings.", ""])
    for code, _ in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        group = sorted((r for r in primary_rows if r.primary_code == code),
                       key=lambda r: (r.organization, r.source_repository, r.run_id))
        sample = group[0]
        lines.extend([
            f"### `{code}`: {sample.primary_failure} ({len(group)} run{'s' if len(group) != 1 else ''})",
            "",
            f"**Action:** {sample.recommendation}",
            "",
        ])
        for row in group:
            detail = [f"- {finding_link(row)}"]
            meta_bits = [bit for bit in (
                f"branch `{row.branch}`" if row.branch else "",
                row.created_at,
            ) if bit]
            if meta_bits:
                detail.append(f"  - When/where: {', '.join(meta_bits)}")
            if row.source_repository not in ("unknown", row.workflow_repository):
                detail.append(f"  - Source repository: `{row.source_repository}`")
            detail.append(f"  - Failed at: `{row.failure_stage}`"
                          + (f" in job `{row.failing_job}`" if row.failing_job else ""))
            detail.append(f"  - Runner: `{runner_display(row)}`")
            detail.append(f"  - Progress: {pipeline_progress(row)}")
            if row.missing_package:
                detail.append(f"  - Missing package: `{row.missing_package}`")
            detail.append(f"  - Evidence: `{row.evidence}`" if row.evidence
                          else "  - Evidence: no known signature")
            if row.all_codes and ";" in row.all_codes:
                detail.append(f"  - Other signals: `{row.all_codes}`")
            detail.append(f"  - Local log: `{row.log_file}`")
            lines.extend(detail)
            lines.append("")

    # Secondary section: cleanup failures and non-actionable runs, at the bottom.
    cleanup_failures = [r for r in rows if r.cleanup_code]
    other_secondary = [r for r in secondary_rows if not r.cleanup_code]
    lines.extend([
        "## Secondary issues",
        "",
        "Cleanup failures are real workflow failures but are not scan blockers;",
        "they are tracked here so they never mask the primary SAST cause.",
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
    lines.extend([f"### Non-actionable or collection-limited runs ({len(other_secondary)})", ""])
    if other_secondary:
        for row in sorted(other_secondary, key=lambda r: (r.organization, r.source_repository, r.run_id)):
            lines.append(f"- {finding_link(row)}: `{row.result}` ({row.primary_failure})")
    else:
        lines.append("- None.")
    lines.append("")
    (directory / "sast-summary.md").write_text("\n".join(lines), encoding="utf-8")


def write_org_reports(org_dir: Path, organization: str, rows: list[Finding]) -> None:
    org_dir.mkdir(parents=True, exist_ok=True)
    fields = list(Finding.__dataclass_fields__)
    with (org_dir / "sast-findings.csv").open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(asdict(row) for row in rows)
    (org_dir / "sast-findings.json").write_text(
        json.dumps([asdict(row) for row in rows], indent=2), encoding="utf-8")
    write_markdown(org_dir, rows, scope=organization)


def write_index(directory: Path, by_org: dict[str, list[Finding]]) -> None:
    """Fleet index: one row per org with counts and a link to its report."""
    generated = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "# Veracode SAST triage index",
        "",
        f"Generated: {generated}",
        f"Organizations: {len(by_org)}",
        "",
        "| Org | Runs | Primary failures | Top cause | Report |",
        "|:--|:--|:--|:--|:--|",
    ]
    for organization in sorted(by_org):
        rows = by_org[organization]
        primary = [r for r in rows if r.result in PRIMARY_RESULTS]
        cause_counts: dict[str, int] = {}
        for row in primary:
            cause_counts[row.primary_code] = cause_counts.get(row.primary_code, 0) + 1
        top_cause = max(cause_counts.items(), key=lambda item: item[1])[0] if cause_counts else "none"
        folder = safe_target_name(organization)
        lines.append(f"| {organization} | {len(rows)} | {len(primary)} | `{top_cause}` "
                     f"| [sast-summary.md](orgs/{folder}/sast-summary.md) |")
    lines.append("")
    (directory / "index.md").write_text("\n".join(lines), encoding="utf-8")


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
    match = re.match(r"(.+?)-sast-(\d+)\.log$", path.name)
    return (match.group(1), match.group(2)) if match else ("unknown", "unknown")



DEFAULT_CONFIG_FILES = ("veracode.yml", "repo_list.yml")


def fetch_config_files(args: argparse.Namespace, result_dir: Path,
                       workflow_repo: str, fetched_orgs: set[str]) -> None:
    """Save the org's workflow config files under config-files/<org>/.

    Fetches each configured file (default: veracode.yml and repo_list.yml)
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
    """Ask the CLI which organizations the single token can reach."""
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
            findings.append(classify(path, organization, f"{organization}/{args.workflow_repo}",
                                     RunMeta(run_id=run_id),
                                     manifest if manifest.is_file() else None))
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
            # Explicit org/repo targets are used as-is. A bare organization
            # maps directly to its central workflow repository (the Veracode
            # workflows run only there and scan the org's other repositories
            # as sources), so there is no need to enumerate every repo.
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
            discovery_file = logs_dir / f"{target_name}-sast-discovery.log"
            discovery = [args.python_executable, str(args.cli),
                         "workflows", "--repo", workflow_repo, "--limit", str(args.limit),
                         "--name", SAST_WORKFLOW_NAME, "--csv"]
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
            selected_runs, fallback_runs, matched, skipped_by_age = select_runs(
                matched_runs, args.runs_per_repo, args.max_age_days)
            if not matched:
                print(f"NOTE: no matching runs in the newest {args.limit} runs of "
                      f"{workflow_repo}; if failures are older, raise --limit")
            elif not selected_runs:
                print(f"NOTE: {matched} matching run(s) in {workflow_repo} but all older "
                      f"than {args.max_age_days} days; raise --max-age-days to include them")
            else:
                print(f"Runs: matched {matched}, selected {len(selected_runs)} "
                      f"(newest per scan target first)"
                      + (f", skipped {skipped_by_age} older than {args.max_age_days}d"
                         if skipped_by_age else ""))
            # Candidates beyond the selection serve as fallback when a selected
            # run's logs are expired, so the quota still yields actionable logs.
            candidates = selected_runs + fallback_runs
            attempts_budget = max(args.runs_per_repo * 3, args.runs_per_repo + 5)
            fetched = 0
            attempts = 0
            expired_runs = 0
            stop = False
            for run_meta in candidates:
                if fetched >= args.runs_per_repo or attempts >= attempts_budget:
                    break
                attempts += 1
                run_id = run_meta.run_id
                log = logs_dir / f"{target_name}-sast-{run_id}.log"
                manifest = logs_dir / f"{target_name}-sast-{run_id}-jobs.json"
                command = [args.python_executable, str(args.cli),
                           "logs", "--repo", workflow_repo, "--run-id", run_id,
                           "--relevant-only", "--manifest", str(manifest)]
                print(f"Fetching build and scan steps: {workflow_repo} run {run_id}")
                log_code, log_output = run_capture(command, log)
                if log_code != 0 and logs_unavailable(log_output):
                    # Expired retention is data availability, not a tooling
                    # failure: record it, try the next-newest candidate, and do
                    # not flip the helper exit code for it.
                    expired_runs += 1
                    finding = classify(log, organization, workflow_repo, run_meta,
                                       None, log_code)
                    finding.result = "LOGS_UNAVAILABLE"
                    finding.primary_code = "LOGS_UNAVAILABLE"
                    finding.primary_failure = "Run logs expired or deleted (Actions retention)"
                    finding.severity = "info"
                    finding.recommendation = ("Logs are gone from GitHub; lower --max-age-days "
                                              "toward the org's Actions log retention window, "
                                              "or re-trigger the scan for fresh logs.")
                    findings.append(finding)
                    continue
                if log_code != 0:
                    operational_failures += 1
                    print(f"WARNING: log fetch failed for {workflow_repo} run {run_id} "
                          f"(exit {log_code}): {first_error_line(log_output)}", file=sys.stderr)
                    hint = failure_hint(log_output, workflow_repo)
                    if hint:
                        print(f"  {hint}", file=sys.stderr)
                else:
                    fetched += 1
                findings.append(classify(log, organization, workflow_repo, run_meta,
                                         manifest if manifest.is_file() else None, log_code))
                if log_code != 0 and args.fail_fast:
                    stop = True
                    break
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
    print(f"Per-org:  {result_dir / 'orgs'}{os.sep}<org>{os.sep}sast-summary.md (.csv, .json)")
    return 1 if operational_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
