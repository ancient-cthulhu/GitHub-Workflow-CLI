#!/usr/bin/env python3
"""
GitHub Workflow CLI - Query and remediate GitHub Actions workflows, repos, issues,
and protection settings. One GitHub token (GITHUB_TOKEN, or GH_TOKEN if unset)
authenticates every command; whatever orgs it is authorized for is what the CLI
can reach. Use the `orgs` command to see the token's reach.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import random
import re
import time
from pathlib import Path
import signal
import subprocess
import sys
from dataclasses import dataclass
import tempfile

try:
    from ruamel.yaml import YAML
except ImportError:  # Optional: only repo-write-file --operation merge needs it.
    YAML = None

try:
    from enable_debug import protection_ops
except ImportError:  # Optional: only branch-protection/rulesets commands need it.
    protection_ops = None

TOKEN_ENV_VARS = ("GITHUB_TOKEN", "GH_TOKEN")
GITHUB_API_BASE = "https://api.github.com"

SUBPROCESS_TIMEOUT = 600  # 10 minutes

# GitHub logs can contain UTF-8 BOM and characters that Windows cp1252 cannot
# encode. Keep redirected output and diagnostics UTF-8-safe.
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        _stream.reconfigure(encoding="utf-8", errors="replace")


def load_env_file(path: str = ".env") -> None:
    """Load KEY=VALUE pairs from a .env file without overriding existing env vars."""
    if not os.path.isfile(path):
        return

    try:
        with open(path, encoding="utf-8") as fh:
            for raw_line in fh:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if "=" not in line:
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    continue

                if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                    value = value[1:-1]

                os.environ.setdefault(key, value)
    except OSError as exc:
        print(f"Warning: Could not read {path}: {exc}", file=sys.stderr)


def get_github_token() -> str:
    """Retrieve the GitHub token from GITHUB_TOKEN, or GH_TOKEN if unset."""
    for env_name in TOKEN_ENV_VARS:
        token = os.environ.get(env_name, "").strip()
        if token:
            return token
    raise SystemExit(
        "Error: No GitHub token found. Set GITHUB_TOKEN (or GH_TOKEN) in the "
        "environment or a local .env file."
    )


def require_protection_ops() -> None:
    """Fail clearly when a protection command is used without enable_debug."""
    if protection_ops is None:
        raise SystemExit(
            "Error: This command requires the internal 'enable_debug' module "
            "(protection_ops), which is not importable in this environment."
        )


def build_gh_env(token: str | None = None) -> dict[str, str]:
    """Construct subprocess environment with GitHub token."""
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
        env["GITHUB_TOKEN"] = token
    return env


def run_gh_command(cmd: list[str], env: dict[str, str]) -> dict | list:
    """Execute a gh CLI command and return parsed JSON output."""
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"gh command failed with code {result.returncode}: {result.stderr}"
            )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"gh command timed out after {SUBPROCESS_TIMEOUT} seconds")
    except OSError as exc:
        raise RuntimeError(f"Unable to run gh: {exc}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse gh output as JSON: {exc}")


def run_git_command(cmd: list[str], env: dict[str, str]) -> str:
    """Execute a git command and return its stdout."""
    try:
        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"git command failed with code {result.returncode}: {result.stderr}"
            )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git command timed out after {SUBPROCESS_TIMEOUT} seconds")
    except OSError as exc:
        raise RuntimeError(f"Unable to run git: {exc}")


@dataclass
class Repo:
    name: str
    url: str
    is_private: bool
    description: str | None
    is_archived: bool = False


@dataclass
class WorkflowRun:
    number: int
    run_id: int
    name: str
    status: str
    conclusion: str | None
    created_at: str
    started_at: str
    updated_at: str
    head_branch: str


@dataclass
class Issue:
    number: int
    title: str
    state: str
    created_at: str
    updated_at: str
    author: str


@dataclass
class RepoContent:
    name: str
    type: str
    size: int
    path: str
    last_updated: str = ""


@dataclass
class IssueDetail:
    number: int
    title: str
    state: str
    body: str
    author: str
    created_at: str
    updated_at: str


@dataclass
class IssueComment:
    author: str
    body: str
    created_at: str


@dataclass
class InstalledApp:
    name: str
    app_id: int
    created_at: str
    updated_at: str
    permissions: str


@dataclass
class RepoBranch:
    name: str
    is_default: bool
    is_protected: bool
    commit_sha: str


@dataclass
class RepoCommit:
    sha: str
    author: str
    date: str
    message: str
    url: str


@dataclass
class RepoActionsPermissions:
    repo: str
    enabled: bool
    allowed_actions: str
    selected_actions_url: str | None = None


def format_table(headers: list[str], rows: list[list]) -> str:
    """Format data as a human-readable table."""
    if not rows:
        return "(no results)"

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    lines = []

    header_line = " | ".join(
        h.ljust(col_widths[i]) for i, h in enumerate(headers)
    )
    lines.append(header_line)
    lines.append("-" * len(header_line))

    for row in rows:
        row_line = " | ".join(
            str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)
        )
        lines.append(row_line)

    return "\n".join(lines)


def format_csv(headers: list[str], rows: list[list]) -> str:
    """Format data as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    writer.writerows(rows)
    return output.getvalue()


def cmd_repos(
    org: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List repositories in an organization."""
    env = build_gh_env(token)

    try:
        data = run_gh_command(
            [
                "gh",
                "repo",
                "list",
                org,
                "--json",
                "name,url,isPrivate,description,isArchived",
                "--limit",
                "10000",
            ],
            env=env,
        )

        if not isinstance(data, list):
            print("Error: Unexpected response format from gh repo list", file=sys.stderr)
            return 1

        repos = []
        for item in data:
            if item.get("isArchived", False):
                continue
            name = item.get("name", "")
            if name_filter and name_filter.lower() not in name.lower():
                continue
            repos.append(
                Repo(
                    name=name,
                    url=item.get("url", ""),
                    is_private=item.get("isPrivate", False),
                    description=item.get("description"),
                    is_archived=item.get("isArchived", False),
                )
            )

        if output_format == "csv":
            headers = ["name", "url", "private", "description"]
            rows = [
                [r.name, r.url, "yes" if r.is_private else "no", r.description or ""]
                for r in repos
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["name", "url", "private", "description"]
            rows = [
                [r.name, r.url, "yes" if r.is_private else "no", r.description or ""]
                for r in repos
            ]
            print(format_table(headers, rows))

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_workflows(
    repo: str,
    token: str,
    status: str | None = None,
    conclusion: str | None = None,
    name_filter: str | None = None,
    name_filter_break: bool | None = None,
    limit: int = 100,
    output_format: str = "table",
) -> int:
    """List workflow runs in a repository."""
    env = build_gh_env(token)

    try:
        # Note: gh doesn't support multiple conclusions in one query, so we filter locally
        # if conclusion is specified
        # Parse comma-separated conclusions if provided
        allowed_conclusions = set()
        if conclusion:
            allowed_conclusions = set(c.strip() for c in conclusion.split(","))

        data = []

        page = 1
        pagination_size = 100
        query_params = [
            f"per_page={pagination_size}", "sort=created", "order=desc"
        ]

        total_fetched = 0
        while True:
            if total_fetched >= limit:
                break
            query_path = f"/repos/{repo}/actions/runs?{"&".join(query_params)}&page={page}"
            cmd = [
                "gh", "api", query_path
            ]
            paged_data = run_gh_command(cmd, env=env)
            if not isinstance(paged_data, dict):
                print(f"Error: Unexpected response format from \"{" ".join(cmd)}\"", file=sys.stderr)
                return 1

            workflow_runs = paged_data.get("workflow_runs", [])
            if not isinstance(workflow_runs, list):
                print(f"Error: Unexpected workflow_runs format from \"{" ".join(cmd)}\"", file=sys.stderr)
                return 1

            if not workflow_runs:
                break

            for item in workflow_runs:
                name = item.get("name", "")
                if name_filter and name_filter.lower() not in name.lower():
                    continue
                item_conclusion = item.get("conclusion")
                # Filter by conclusion if specified
                if allowed_conclusions and item_conclusion not in allowed_conclusions:
                    continue
                
                run = WorkflowRun(
                        number=item.get("run_number", 0),
                        run_id=item.get("id", 0),
                        name=name,
                        status=item.get("status", ""),
                        conclusion=item_conclusion,
                        created_at=item.get("created_at", ""),
                        started_at=item.get("run_started_at", ""),
                        updated_at=item.get("updated_at", ""),
                        head_branch=item.get("head_branch", ""),
                    )
                
                data.append(run)

            if name_filter and name_filter_break and data:
                break

            page = page + 1
            total_fetched += len(workflow_runs)

        if output_format == "csv":
            headers = ["number", "id", "name", "status", "conclusion", "created", "started", "updated", "branch"]
            rows = [
                [
                    r.number,
                    r.run_id,
                    r.name,
                    r.status,
                    r.conclusion or "",
                    r.created_at,
                    r.started_at,
                    r.updated_at,
                    r.head_branch,
                ]
                for r in data
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["number", "id", "name", "status", "conclusion", "created", "started", "updated", "branch"]
            rows = [
                [
                    r.number,
                    r.run_id,
                    r.name,
                    r.status,
                    r.conclusion or "",
                    r.created_at,
                    r.started_at,
                    r.updated_at,
                    r.head_branch,
                ]
                for r in data
            ]
            print(format_table(headers, rows))

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_run_view(
    run_id: int,
    token: str,
    repo: str,
) -> int:
    """View details for a specific workflow run."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "run",
            "view",
            str(run_id),
            "--repo",
            repo,
            "--json",
            "number,databaseId,name,status,conclusion,createdAt,updatedAt,headBranch,workflowName,displayTitle",
        ]

        data = run_gh_command(cmd, env=env)

        if not isinstance(data, dict):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1

        print(f"Run #{data.get('number', 'N/A')}: {data.get('name', 'N/A')}")
        print(f"Workflow: {data.get('workflowName', 'N/A')}")
        print(f"Display Title: {data.get('displayTitle', 'N/A')}")
        print(f"Status: {data.get('status', 'N/A')}")
        print(f"Conclusion: {data.get('conclusion', 'N/A') or 'N/A'}")
        print(f"Run ID: {data.get('databaseId', 'N/A')}")
        print(f"Branch: {data.get('headBranch', 'N/A')}")
        print(f"Created: {data.get('createdAt', 'N/A')}")
        print(f"Updated: {data.get('updatedAt', 'N/A')}")

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


# Matched against each "/"-separated segment of the gh job column so that
# reusable-workflow names like "Static Code Analysis / scan" and jobs that do
# not begin with the token (e.g. "SAST Scan") are still recognized.
SAST_RELEVANT_JOB_PATTERNS = (
    r"^validations?\b",
    r"^build\b",
    r"^packager?\b",
    r"^artifact\b",
    r"^upload\b",
    r"^pre.?scan\b",
    r"^pipeline.?scan\b",
    r"^policy.?scan\b",
    r"^scan\b",
    r"^results?\b",
    r"\bstatic.?(?:code.?)?analysis\b",
    r"\bsast\b",
    r"\bveracode\b",
    r"\bsecurity.?scan\b",
    r"\bcode.?analysis\b",
    r"\banaly[sz]e\b",
)

SAST_EXCLUDED_JOB_PATTERNS = (
    r"^cleanup\b",
    r"^register\b",
)


def job_name_segments(job_name: str) -> list[str]:
    """Split a gh job column into "/"-separated segments (reusable workflows)."""
    return [segment.strip() for segment in job_name.split("/") if segment.strip()]


def is_sast_job(job_name: str) -> bool:
    return any(
        re.search(pattern, segment, re.I)
        for segment in job_name_segments(job_name)
        for pattern in SAST_RELEVANT_JOB_PATTERNS
    )


def is_excluded_job(job_name: str) -> bool:
    return any(
        re.search(pattern, segment, re.I)
        for segment in job_name_segments(job_name)
        for pattern in SAST_EXCLUDED_JOB_PATTERNS
    )


# Log-fetch failure categories, mapped to distinct process exit codes by
# cmd_logs so bulk callers can branch without parsing prose.
LOG_ERROR_EXIT_CODES = {
    "GONE": 4,          # HTTP 410 / log not found: permanent, use another run
    "IN_PROGRESS": 5,   # run not finished yet: skip, do not count as failure
    "TRANSIENT": 6,     # 5xx / network / timeout: retries exhausted
    "AUTH": 7,          # 401/403: fix token, retrying is pointless
    "NOT_FOUND": 8,     # 404: bad repo or run id
}


class GhLogError(RuntimeError):
    """gh log fetch failure with a machine-usable category."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category


def classify_gh_log_error(stderr: str) -> str:
    """Map gh stderr to a failure category. Order matters: most specific first."""
    if re.search(r"HTTP 410|\blog not found\b|\bGone\b", stderr, re.I):
        return "GONE"
    if re.search(r"still in progress|has not (?:yet )?completed", stderr, re.I):
        return "IN_PROGRESS"
    if re.search(r"HTTP 40[13]|Unauthorized|Forbidden|Bad credentials|"
                 r"rate limit", stderr, re.I):
        return "AUTH"
    if re.search(r"HTTP 404|Not Found", stderr, re.I):
        return "NOT_FOUND"
    # 5xx from the logs endpoint, blob fetch failures from
    # results-receiver.actions.githubusercontent.com, connection resets, and
    # gh's "more than 25 job logs missing" fallback error are all transient.
    if re.search(r"HTTP 5\d\d|failed to get run log|connection (?:reset|refused)|"
                 r"timed? ?out|TLS|EOF|temporary failure|missing.*job logs",
                 stderr, re.I):
        return "TRANSIENT"
    return "UNKNOWN"


def run_gh_log_command(
    cmd: list[str],
    env: dict[str, str],
    max_attempts: int = 3,
    backoff_base: float = 2.0,
) -> str:
    """Run gh with bounded retry on transient failures only.

    Permanent conditions (410 Gone, auth, 404, run in progress) fail
    immediately with a category so callers can pick the right fallback.
    """
    last_error = "unknown failure"
    for attempt in range(1, max_attempts + 1):
        try:
            result = subprocess.run(
                cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            category, last_error = "TRANSIENT", (
                f"gh command timed out after {SUBPROCESS_TIMEOUT} seconds"
            )
        except OSError as exc:
            raise GhLogError("UNKNOWN", f"Unable to run gh: {exc}") from exc
        else:
            if result.returncode == 0:
                return result.stdout.decode("utf-8-sig", errors="replace")
            stderr = result.stderr.decode("utf-8-sig", errors="replace").strip()
            category = classify_gh_log_error(stderr)
            last_error = (
                f"gh command failed with code {result.returncode}: {stderr}"
            )
        if category != "TRANSIENT":
            raise GhLogError(category, last_error)
        if attempt < max_attempts:
            delay = backoff_base ** attempt + random.uniform(0, 1)
            print(f"Transient log fetch failure (attempt {attempt}/{max_attempts}), "
                  f"retrying in {delay:.1f}s: {last_error[:200]}", file=sys.stderr)
            time.sleep(delay)
    raise GhLogError(
        "TRANSIENT", f"{last_error} (after {max_attempts} attempts)"
    )


def workflow_log_job_name(line: str) -> str:
    """Return the job name from the first tab-delimited gh run log column."""
    if "\t" not in line:
        return ""
    return line.split("\t", 1)[0].strip().lstrip("\ufeff")


def filter_sast_workflow_logs(
    logs: str,
    relevant_only: bool = False,
    exclude_cleanup: bool = False,
) -> tuple[str, dict]:
    """Split gh combined logs by job category without conflating cleanup/SAST."""
    all_jobs: list[str] = []
    sast_jobs: list[str] = []
    cleanup_jobs: list[str] = []
    other_jobs: list[str] = []
    sast_lines: list[str] = []
    cleanup_lines: list[str] = []
    other_lines: list[str] = []

    for raw_line in logs.splitlines():
        line = raw_line.lstrip("\ufeff")
        job_name = workflow_log_job_name(line)
        if not job_name:
            continue
        if job_name not in all_jobs:
            all_jobs.append(job_name)
        is_cleanup = any(
            re.search(r"^cleanup\b", segment, re.I)
            for segment in job_name_segments(job_name)
        )
        is_sast = not is_excluded_job(job_name) and is_sast_job(job_name)
        if is_cleanup:
            cleanup_lines.append(line)
            if job_name not in cleanup_jobs:
                cleanup_jobs.append(job_name)
        elif is_sast:
            sast_lines.append(line)
            if job_name not in sast_jobs:
                sast_jobs.append(job_name)
        else:
            other_lines.append(line)
            if job_name not in other_jobs:
                other_jobs.append(job_name)

    # With --relevant-only, emit SAST and (unless explicitly excluded) cleanup.
    # Cleanup is included for secondary reporting but never listed as a SAST job.
    if relevant_only:
        output_lines = list(sast_lines)
        if not exclude_cleanup:
            output_lines.extend(cleanup_lines)
    elif exclude_cleanup:
        output_lines = sast_lines + other_lines
    else:
        return logs, {
            "all_jobs": all_jobs, "sast_jobs": sast_jobs,
            "cleanup_jobs": cleanup_jobs, "other_jobs": other_jobs,
            "sast_line_count": len(sast_lines),
            "cleanup_line_count": len(cleanup_lines),
        }

    # Never convert a successful download into a collection failure.
    # Prefer the unrecognized (other) job lines over cleanup so a scan job
    # with an unanticipated name is preserved instead of silently dropped.
    if not output_lines:
        output_lines = other_lines or cleanup_lines
    elif relevant_only and not sast_lines and other_lines:
        # Only cleanup matched but other jobs exist: keep them for triage.
        output_lines = other_lines + output_lines
    filtered = "\n".join(output_lines)
    if filtered:
        filtered += "\n"
    return filtered, {
        "all_jobs": all_jobs, "sast_jobs": sast_jobs,
        "cleanup_jobs": cleanup_jobs, "other_jobs": other_jobs,
        "sast_line_count": len(sast_lines),
        "cleanup_line_count": len(cleanup_lines),
    }


def fetch_logs_via_api(
    token: str,
    repo: str,
    run_id: int,
    relevant_only: bool = False,
    exclude_cleanup: bool = False,
) -> tuple[str, dict]:
    """Fetch the complete run once and preserve SAST/cleanup as separate sets."""
    env = build_gh_env(token)
    full_logs = run_gh_log_command(
        ["gh", "run", "view", str(run_id), "--log", "--repo", repo], env
    )
    filtered, details = filter_sast_workflow_logs(
        full_logs, relevant_only=relevant_only, exclude_cleanup=exclude_cleanup
    )
    manifest = {
        "repository": repo,
        "run_id": run_id,
        "collection_status": "SUCCESS",
        "sast_log_status": (
            "ACTIONABLE_SAST" if details["sast_jobs"]
            else "CLEANUP_ONLY" if details["cleanup_jobs"]
            else "NO_RELEVANT_JOBS"
        ),
        **details,
        "relevant_only": relevant_only,
        "exclude_cleanup": exclude_cleanup,
    }
    return filtered or full_logs, manifest

def cmd_logs(
    run_id: int,
    token: str,
    repo: str,
    relevant_only: bool = False,
    exclude_cleanup: bool = False,
    manifest_path: str | None = None,
) -> int:
    """Fetch complete run logs and optionally retain only SAST pipeline jobs."""
    try:
        logs, manifest = fetch_logs_via_api(
            token,
            repo,
            run_id,
            relevant_only=relevant_only,
            exclude_cleanup=exclude_cleanup,
        )
        print(logs, end="")
        if manifest_path:
            destination = Path(manifest_path)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                json.dumps(manifest, indent=2),
                encoding="utf-8",
            )
        return 0
    except GhLogError as exc:
        # Structured marker plus category exit code; bulk helpers key on both.
        print(f"Error[{exc.category}]: {exc}", file=sys.stderr)
        return LOG_ERROR_EXIT_CODES.get(exc.category, 1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_run_jobs(
    run_id: int,
    token: str,
    repo: str,
) -> int:
    """List each job's requested labels and resolved runner as CSV.

    The labels column is the literal runs-on the job asked for, i.e. exactly
    what the Veracode dispatch payload contained; runner_name/runner_group is
    where GitHub actually placed the job. Jobs metadata outlives log
    retention, so this remains provable after logs expire.
    """
    env = build_gh_env(token)
    try:
        data = run_gh_command(
            ["gh", "api",
             f"repos/{repo}/actions/runs/{run_id}/jobs?per_page=100"],
            env=env,
        )
        jobs = data.get("jobs", []) if isinstance(data, dict) else []
        writer = csv.writer(sys.stdout)
        writer.writerow(["job_id", "name", "labels", "runner_name",
                         "runner_group", "status", "conclusion",
                         "started_at", "completed_at"])
        for job in jobs:
            writer.writerow([
                job.get("id", ""),
                job.get("name", ""),
                ";".join(job.get("labels") or []),
                job.get("runner_name") or "",
                job.get("runner_group_name") or "",
                job.get("status", ""),
                job.get("conclusion") or "",
                job.get("started_at") or "",
                job.get("completed_at") or "",
            ])
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_org_runners(
    org: str,
    token: str,
) -> int:
    """List the org's SELF-HOSTED runner inventory as CSV.

    The authoritative answer to "is this runner actually mine": any runner
    name observed on a job but absent from this list is a GitHub-hosted
    larger runner or an enterprise-level runner, not an org self-hosted one.
    """
    env = build_gh_env(token)
    try:
        data = run_gh_command(
            ["gh", "api", f"orgs/{org}/actions/runners?per_page=100"],
            env=env,
        )
        runners = data.get("runners", []) if isinstance(data, dict) else []
        writer = csv.writer(sys.stdout)
        writer.writerow(["id", "name", "os", "status", "busy", "labels"])
        for runner in runners:
            writer.writerow([
                runner.get("id", ""),
                runner.get("name", ""),
                runner.get("os", ""),
                runner.get("status", ""),
                runner.get("busy", ""),
                ";".join(label.get("name", "")
                         for label in runner.get("labels", [])),
            ])
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_runner_groups(
    org: str,
    token: str,
) -> int:
    """Enumerate the org's runner groups and every runner inside them (CSV).

    Joins three endpoints: runner-groups (group metadata incl. visibility and
    enterprise inheritance), each group's self-hosted runners (incl.
    enterprise-shared ones visible through the group), and the org's
    GitHub-hosted larger runners, which report their runner_group_id and are
    joined to group names here. source column: self-hosted | hosted-larger.
    This answers "what is actually in my runner groups" in one call.
    """
    env = build_gh_env(token)
    writer = csv.writer(sys.stdout)
    writer.writerow(["group_id", "group_name", "visibility", "inherited",
                     "source", "runner_id", "runner_name", "os_or_platform",
                     "status", "busy", "labels_or_image"])
    try:
        data = run_gh_command(
            ["gh", "api", f"orgs/{org}/actions/runner-groups?per_page=100"],
            env=env,
        )
        groups = data.get("runner_groups", []) if isinstance(data, dict) else []
        group_names = {int(g["id"]): g.get("name", "") for g in groups
                       if g.get("id") is not None}
        for group in groups:
            gid = group.get("id", "")
            gname = group.get("name", "")
            gvis = group.get("visibility", "")
            ginherited = group.get("inherited", "")
            rows_written = 0
            try:
                runners_data = run_gh_command(
                    ["gh", "api",
                     f"orgs/{org}/actions/runner-groups/{gid}/runners"
                     f"?per_page=100"],
                    env=env,
                )
                for runner in (runners_data.get("runners", [])
                               if isinstance(runners_data, dict) else []):
                    writer.writerow([
                        gid, gname, gvis, ginherited, "self-hosted",
                        runner.get("id", ""), runner.get("name", ""),
                        runner.get("os", ""), runner.get("status", ""),
                        runner.get("busy", ""),
                        ";".join(label.get("name", "")
                                 for label in runner.get("labels", [])),
                    ])
                    rows_written += 1
            except Exception as exc:
                print(f"Warning: could not list runners for group {gid} "
                      f"({gname}): {exc}", file=sys.stderr)
            if rows_written == 0:
                writer.writerow([gid, gname, gvis, ginherited, "empty",
                                 "", "", "", "", "", ""])
        # GitHub-hosted larger runners (endpoint absent on some plans: warn,
        # do not fail)
        try:
            hosted = run_gh_command(
                ["gh", "api", f"orgs/{org}/actions/hosted-runners?per_page=100"],
                env=env,
            )
            for runner in (hosted.get("runners", [])
                           if isinstance(hosted, dict) else []):
                gid = runner.get("runner_group_id", "")
                image = runner.get("image") or {}
                size = runner.get("machine_size_details") or {}
                writer.writerow([
                    gid,
                    group_names.get(gid, f"(group {gid})") if gid else "",
                    "", "", "hosted-larger",
                    runner.get("id", ""), runner.get("name", ""),
                    runner.get("platform", ""), runner.get("status", ""), "",
                    f"image={image.get('id', '')};"
                    f"size={size.get('id', '')}",
                ])
        except Exception as exc:
            print(f"Warning: hosted larger runners not listable for {org}: "
                  f"{exc}", file=sys.stderr)
        return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_issues(
    repo: str,
    token: str,
    state: str | None = None,
    limit: int = 10000,
    output_format: str = "table",
    show_tree: bool = False,
) -> int:
    """List issues in a repository."""
    env = build_gh_env(token)

    try:
        check_cmd = [
            "gh",
            "repo",
            "view",
            repo,
            "--json",
            "hasIssuesEnabled",
        ]

        result_check = subprocess.run(
            check_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result_check.returncode != 0:
            print(f"Error checking repo: {result_check.stderr}", file=sys.stderr)
            return 1

        try:
            repo_data = json.loads(result_check.stdout)
            issues_enabled = repo_data.get("hasIssuesEnabled", False)
        except json.JSONDecodeError:
            print("Error: Could not parse repo status", file=sys.stderr)
            return 1

        issues_were_disabled = not issues_enabled

        if issues_were_disabled:
            print(f"Issues are disabled on {repo}. Enabling temporarily...", file=sys.stderr)
            enable_cmd = [
                "gh",
                "repo",
                "edit",
                repo,
                "--enable-issues",
            ]

            result_enable = subprocess.run(
                enable_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result_enable.returncode != 0:
                print(f"Error enabling issues: {result_enable.stderr}", file=sys.stderr)
                return 1
            print("Issues enabled.", file=sys.stderr)

        cmd = [
            "gh",
            "issue",
            "list",
            "--repo",
            repo,
            "--json",
            "number,title,state,createdAt,updatedAt,author",
            "--limit",
            str(limit),
        ]

        if state:
            cmd.extend(["--state", state])

        data = run_gh_command(cmd, env=env)

        if not isinstance(data, list):
            print("Error: Unexpected response format from gh issue list", file=sys.stderr)
            return 1

        issues = []
        for item in data:
            author_data = item.get("author", {})
            author_name = author_data.get("login", "unknown") if isinstance(author_data, dict) else str(author_data)
            issues.append(
                Issue(
                    number=item.get("number", 0),
                    title=item.get("title", ""),
                    state=item.get("state", ""),
                    created_at=item.get("createdAt", ""),
                    updated_at=item.get("updatedAt", ""),
                    author=author_name,
                )
            )

        if show_tree:
            print(build_issue_tree(issues, repo, env))
        elif output_format == "csv":
            headers = ["number", "title", "state", "created", "updated", "author"]
            rows = [
                [
                    i.number,
                    i.title,
                    i.state,
                    i.created_at,
                    i.updated_at,
                    i.author,
                ]
                for i in issues
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["number", "title", "state", "created", "updated", "author"]
            rows = [
                [
                    i.number,
                    i.title,
                    i.state,
                    i.created_at,
                    i.updated_at,
                    i.author,
                ]
                for i in issues
            ]
            print(format_table(headers, rows))

        if issues_were_disabled:
            print("Disabling issues again...", file=sys.stderr)
            disable_cmd = [
                "gh",
                "api",
                f"repos/{repo}",
                "-X",
                "PATCH",
                "-f",
                "has_issues=false",
            ]

            result_disable = subprocess.run(
                disable_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result_disable.returncode != 0:
                print(f"Warning: Could not disable issues: {result_disable.stderr}", file=sys.stderr)
            else:
                print("Issues disabled.", file=sys.stderr)

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        if issues_were_disabled:
            print("Attempting to disable issues...", file=sys.stderr)
            disable_cmd = [
                "gh",
                "api",
                f"repos/{repo}",
                "-X",
                "PATCH",
                "-f",
                "has_issues=false",
            ]

            result_disable = subprocess.run(
                disable_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )
        return 1


def cmd_org_apps(
    org: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List GitHub apps installed in an organization."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "api",
            f"orgs/{org}/installations",
            "--jq",
            "[.installations[] | {name: .app_slug, app_id: .app_id, created_at: .created_at, updated_at: .updated_at, permissions: (.permissions | keys | join(\", \"))}]",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1

        if not isinstance(data, list):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1

        apps = []
        for item in data:
            name = item.get("name", "")
            if name_filter and name_filter.lower() not in name.lower():
                continue
            apps.append(
                InstalledApp(
                    name=name,
                    app_id=item.get("app_id", 0),
                    created_at=item.get("created_at", ""),
                    updated_at=item.get("updated_at", ""),
                    permissions=item.get("permissions", ""),
                )
            )

        if output_format == "csv":
            headers = ["name", "app_id", "created_at", "updated_at", "permissions"]
            rows = [
                [
                    a.name,
                    a.app_id,
                    a.created_at,
                    a.updated_at,
                    a.permissions,
                ]
                for a in apps
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["name", "app_id", "created_at", "updated_at", "permissions"]
            rows = [
                [
                    a.name,
                    a.app_id,
                    a.created_at,
                    a.updated_at,
                    a.permissions,
                ]
                for a in apps
            ]
            print(format_table(headers, rows))

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_token_info(
    token: str,
) -> int:
    """Display information about the GitHub token being used."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "api",
            "user",
            "--jq",
            "{login: .login, name: .name, email: .email, id: .id, type: .type, company: .company, location: .location}",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        try:
            user_data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1

        print("Token Information:")
        print(f"  User: {user_data.get('login', 'N/A')}")
        print(f"  Name: {user_data.get('name', 'N/A')}")
        print(f"  Email: {user_data.get('email', 'N/A')}")
        print(f"  ID: {user_data.get('id', 'N/A')}")
        print(f"  Type: {user_data.get('type', 'N/A')}")
        if user_data.get('company'):
            print(f"  Company: {user_data.get('company')}")
        if user_data.get('location'):
            print(f"  Location: {user_data.get('location')}")
        print()

        print("Token Scopes:")
        cmd_status = [
            "gh",
            "auth",
            "status",
        ]

        result_status = subprocess.run(
            cmd_status,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result_status.returncode == 0:
            print(result_status.stdout)
        else:
            print("  (Unable to retrieve scopes)")
            if result_status.stderr:
                print(f"  {result_status.stderr}", file=sys.stderr)

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_orgs(
    token: str,
    output_format: str = "table",
) -> int:
    """List every organization the token can reach and print a scope verdict.

    Tries /user/orgs first (classic PATs with read:org). Falls back to
    /user/memberships/orgs for tokens where /user/orgs returns nothing.
    """
    env = build_gh_env(token)
    orgs: list[dict] = []

    try:
        data = run_gh_command(
            ["gh", "api", "user/orgs", "--paginate"], env=env
        )
        if isinstance(data, list):
            orgs = [item for item in data if isinstance(item, dict)]
    except RuntimeError:
        orgs = []

    if not orgs:
        try:
            data = run_gh_command(
                ["gh", "api", "user/memberships/orgs", "--paginate"], env=env
            )
            if isinstance(data, list):
                orgs = [
                    item.get("organization")
                    for item in data
                    if isinstance(item, dict) and isinstance(item.get("organization"), dict)
                ]
        except RuntimeError as exc:
            print(f"Error: unable to list organizations: {exc}", file=sys.stderr)
            return 1

    rows = []
    seen: set[str] = set()
    for item in orgs:
        login = (item.get("login") or "").strip()
        if not login or login in seen:
            continue
        seen.add(login)
        rows.append([login, item.get("url", ""), item.get("description") or ""])

    headers = ["org", "url", "description"]
    if output_format == "csv":
        print(format_csv(headers, rows), end="")
    else:
        print(format_table(headers, rows))

    count = len(rows)
    verdict = (
        "No organizations reachable (user-scoped token?)" if count == 0
        else f"Single-org token: {rows[0][0]}" if count == 1
        else f"Multi-org token: {count} organizations"
    )
    # Keep CSV stdout machine-parseable; verdict goes to stderr in that mode.
    print(verdict, file=sys.stderr if output_format == "csv" else sys.stdout)
    return 0


def cmd_org_actions_permissions(
    org: str,
    token: str,
) -> int:
    """View GitHub Actions permissions settings for an organization."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "api",
            f"orgs/{org}/actions/permissions",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1

        print(f"GitHub Actions Permissions for {org}:")
        print()
        print("Enabled Repositories:")
        enabled_repos = data.get("enabled_repositories", "N/A")
        print(f"  {enabled_repos}")
        print()
        print("Allowed Actions:")
        allowed_actions = data.get("allowed_actions", "N/A")
        print(f"  {allowed_actions}")
        print()
        print("Full Response:")
        print(json.dumps(data, indent=2))

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_repo_actions_permissions(
    repo: str,
    token: str,
    output_format: str = "table",
    enable: bool | None = None,
    disable: bool | None = None,
) -> int:
    """View or update GitHub Actions permissions settings for a repository."""
    env = build_gh_env(token)

    try:
        # Update permissions if enable/disable flags are set
        if enable or disable:
            enabled_value = enable if enable else not disable
            payload = {"enabled": enabled_value}
            cmd = [
                "gh",
                "api",
                f"repos/{repo}/actions/permissions",
                "-X",
                "PUT",
                "--input",
                "-",
            ]

            result = subprocess.run(
                cmd,
                env=env,
                input=json.dumps(payload),
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1

            print(f"Successfully updated Actions permissions for {repo}")
            print(f"Actions are now: {'enabled' if enabled_value else 'disabled'}")
            print()
        else:
            # Query current permissions
            cmd = [
                "gh",
                "api",
                f"repos/{repo}/actions/permissions",
            ]

            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
                return 1

            enabled = data.get("enabled", False)
            allowed_actions = data.get("allowed_actions", "N/A")
            selected_actions_url = data.get("selected_actions_url")

            if output_format == "csv":
                headers = ["repo", "enabled", "allowed_actions", "selected_actions_url"]
                rows = [
                    [
                        repo,
                        "yes" if enabled else "no",
                        str(allowed_actions),
                        selected_actions_url or "",
                    ]
                ]
                output = format_csv(headers, rows)
                print(output, end="")
            else:
                print(f"GitHub Actions Permissions for {repo}:")
                print()
                print(f"Enabled: {'yes' if enabled else 'no'}")
                print(f"Allowed Actions: {allowed_actions}")
                if selected_actions_url:
                    print(f"Selected Actions URL: {selected_actions_url}")
                print()
                print("Full Response:")
                print(json.dumps(data, indent=2))

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1
    

def cmd_org_rulesets(
    org: str,
    token: str,
    ruleset_id: str | None = None,
    modify_ruleset_enforcement: str | None = None
) -> int:
    """View GitHub org rulesets for an organization."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "api",
            f"orgs/{org}/rulesets",
        ]

        if ruleset_id:
            cmd = [
                "gh",
                "api",
                f"orgs/{org}/rulesets/{ruleset_id}",
            ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1
        
        if ruleset_id and modify_ruleset_enforcement:
            data["enforcement"] = modify_ruleset_enforcement

            cmd = [
                "gh",
                "api",
                f"orgs/{org}/rulesets/{ruleset_id}",
                "-X", "PUT",
                "--input", "-",
            ]

            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
                input=json.dumps(data, separators=(',',':'))
            )

            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
                return 1
            
            # print(json.dumps(data, indent=2))
            print(f"Success: Updated {org} ruleset id {ruleset_id} with enforcement {modify_ruleset_enforcement}")
            
            return 0
            
            
        print(f"GitHub Rulesets for {org}:")
        print()
        print(json.dumps(data, indent=2))

        if not ruleset_id:
            headers = ["id", "name", "target", "enforcement"]
            rows = [
                [
                    c.get("id"),
                    c.get("name"),
                    c.get("target"),
                    c.get("enforcement"),
                ]
                for c in data
            ]
            print(format_table(headers, rows))

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_org_app_view(
    org: str,
    app_name: str,
    token: str,
) -> int:
    """View settings for a specific GitHub app installed in an organization."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "api",
            f"orgs/{org}/installations",
            "--jq",
            f".installations[] | select(.app_slug == \"{app_name}\")",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        if not result.stdout.strip():
            print(f"Error: App '{app_name}' not found in organization '{org}'", file=sys.stderr)
            return 1

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1

        print(f"GitHub App: {data.get('app_slug', 'N/A')}")
        print(f"App ID: {data.get('app_id', 'N/A')}")
        print(f"Installation ID: {data.get('id', 'N/A')}")
        print(f"Created: {data.get('created_at', 'N/A')}")
        print(f"Updated: {data.get('updated_at', 'N/A')}")
        print()

        if data.get("suspended_at"):
            print("Status: SUSPENDED")
            print(f"  Suspended at: {data.get('suspended_at', 'N/A')}")
            print(f"  Suspended by: {data.get('suspended_by', 'N/A')}")
            print()
        else:
            print("Status: ACTIVE")
            print()
        print("Permissions:")
        permissions = data.get("permissions", {})
        if isinstance(permissions, dict):
            for perm, level in sorted(permissions.items()):
                print(f"  {perm}: {level}")
        else:
            print(f"  {permissions}")
        print()
        print("Repository Selection:")
        repo_selection = data.get("repository_selection", "N/A")
        print(f"  {repo_selection}")

        if repo_selection == "all":
            print("  (App has access to all repositories in the organization)")
        elif repo_selection == "selected":
            print("  (App has access to selected repositories only)")

        if data.get("single_file_name"):
            print(f"  Single file path: {data.get('single_file_name')}")
        print()

        events = data.get("events", [])
        if events:
            print("Subscribed Events:")
            for event in sorted(events):
                print(f"  {event}")

        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_issue_create(
    repo: str,
    token: str,
    title: str,
    body: str | None = None,
    assignee: str | None = None,
    labels: str | None = None,
) -> int:
    """Create a new issue on a repository."""
    env = build_gh_env(token)

    try:
        check_cmd = [
            "gh",
            "repo",
            "view",
            repo,
            "--json",
            "hasIssuesEnabled",
        ]

        result_check = subprocess.run(
            check_cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result_check.returncode != 0:
            print(f"Error checking repo: {result_check.stderr}", file=sys.stderr)
            return 1

        try:
            repo_data = json.loads(result_check.stdout)
            issues_enabled = repo_data.get("hasIssuesEnabled", False)
        except json.JSONDecodeError:
            print("Error: Could not parse repo status", file=sys.stderr)
            return 1

        issues_were_disabled = not issues_enabled

        if issues_were_disabled:
            print(f"Issues are disabled on {repo}. Enabling temporarily...")
            enable_cmd = [
                "gh",
                "repo",
                "edit",
                repo,
                "--enable-issues",
            ]

            result_enable = subprocess.run(
                enable_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result_enable.returncode != 0:
                print(f"Error enabling issues: {result_enable.stderr}", file=sys.stderr)
                return 1
            print("Issues enabled.")

        cmd = [
            "gh",
            "issue",
            "create",
            "--repo",
            repo,
            "--title",
            title,
        ]

        if body:
            cmd.extend(["--body", body])
        if assignee:
            cmd.extend(["--assignee", assignee])
        if labels:
            cmd.extend(["--label", labels])

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if issues_were_disabled:
            print("Disabling issues again...")
            disable_cmd = [
                "gh",
                "api",
                f"repos/{repo}",
                "-X",
                "PATCH",
                "-f",
                "has_issues=false",
            ]

            result_disable = subprocess.run(
                disable_cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result_disable.returncode != 0:
                print(f"Warning: Could not disable issues: {result_disable.stderr}", file=sys.stderr)
            else:
                print("Issues disabled.")

        if result.returncode != 0:
            stderr_msg = result.stderr.strip() if result.stderr else "Unknown error"
            print(f"Error creating issue: {stderr_msg}", file=sys.stderr)
            if result.stdout:
                print(f"Output: {result.stdout}", file=sys.stderr)
            return 1

        output = result.stdout.strip()
        if output:
            print(f"Issue created successfully: {output}")
        else:
            print("Warning: Issue may not have been created - no URL returned", file=sys.stderr)
            print("This often indicates you've hit GitHub's secondary rate limit.", file=sys.stderr)
            print("Please wait a few minutes and try again.", file=sys.stderr)
            if result.stderr:
                print(f"Additional info: {result.stderr}", file=sys.stderr)
            return 1
        return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_issue_view(
    repo: str,
    issue_number: int,
    token: str,
) -> int:
    """View full contents of a specific issue."""
    env = build_gh_env(token)

    try:
        cmd = [
            "gh",
            "issue",
            "view",
            str(issue_number),
            "--repo",
            repo,
            "--json",
            "number,title,state,body,author,createdAt,updatedAt",
        ]

        data = run_gh_command(cmd, env=env)

        if not isinstance(data, dict):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1

        author_data = data.get("author", {})
        author_name = author_data.get("login", "unknown") if isinstance(author_data, dict) else str(author_data)

        issue = IssueDetail(
            number=data.get("number", 0),
            title=data.get("title", ""),
            state=data.get("state", ""),
            body=data.get("body", ""),
            author=author_name,
            created_at=data.get("createdAt", ""),
            updated_at=data.get("updatedAt", ""),
        )

        print(f"Issue #{issue.number}: {issue.title}")
        print(f"State: {issue.state}")
        print(f"Author: {issue.author}")
        print(f"Created: {issue.created_at}")
        print(f"Updated: {issue.updated_at}")
        print()
        print("=" * 80)
        print(issue.body)
        print("=" * 80)

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def fetch_issue_comments(
    repo: str, issue_number: int, env: dict[str, str]
) -> list[IssueComment]:
    """Fetch comments for a specific issue."""
    try:
        cmd = [
            "gh",
            "issue",
            "view",
            str(issue_number),
            "--repo",
            repo,
            "--json",
            "comments",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            return []

        data = json.loads(result.stdout)
        comments_data = data.get("comments", [])

        comments = []
        for comment in comments_data:
            author_data = comment.get("author", {})
            author_name = (
                author_data.get("login", "unknown")
                if isinstance(author_data, dict)
                else str(author_data)
            )
            comments.append(
                IssueComment(
                    author=author_name,
                    body=comment.get("body", ""),
                    created_at=comment.get("createdAt", ""),
                )
            )
        return comments
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def build_issue_tree(
    issues: list[Issue], repo: str, env: dict[str, str], max_depth: int = 5
) -> str:
    """Build a tree representation of issues with their comments (most recent up to max_depth issues)."""
    recent_issues = sorted(issues, key=lambda x: x.number, reverse=True)[:max_depth]
    lines = []
    for i, issue in enumerate(recent_issues):
        is_last_issue = i == len(recent_issues) - 1
        current_prefix = "└── " if is_last_issue else "├── "
        lines.append(
            current_prefix
            + f"#{issue.number}: {issue.title} [{issue.state}]"
        )

        comments = fetch_issue_comments(repo, issue.number, env)
        if comments:
            next_prefix = "    " if is_last_issue else "│   "
            for j, comment in enumerate(comments):
                is_last_comment = j == len(comments) - 1
                comment_prefix = "└── " if is_last_comment else "├── "
                comment_line = (
                    f"{next_prefix}{comment_prefix}"
                    f"{comment.author} ({comment.created_at}): "
                    f"{comment.body[:80]}{'...' if len(comment.body) > 80 else ''}"
                )
                lines.append(comment_line)

    if len(issues) > max_depth:
        lines.append(f"└── ... and {len(issues) - max_depth} more issues")

    return "\n".join(lines)


def build_tree(items: list, prefix: str = "", is_last: bool = True) -> str:
    """Build a tree representation of repository contents."""
    lines = []
    for i, item in enumerate(items):
        is_last_item = i == len(items) - 1
        current_prefix = "└── " if is_last_item else "├── "
        lines.append(prefix + current_prefix + item["name"] + ("/" if item["type"] == "dir" else ""))

        if item.get("children"):
            next_prefix = prefix + ("    " if is_last_item else "│   ")
            lines.append(build_tree(item["children"], next_prefix, is_last_item))

    return "\n".join(filter(None, lines))


def fetch_tree_contents(
    repo: str, path: str, env: dict, token: str
) -> dict | None:
    """Recursively fetch repository contents as a tree."""
    try:
        cmd = [
            "gh",
            "api",
            f"repos/{repo}/contents/{path}" if path else f"repos/{repo}/contents",
            "--jq",
            "[.[] | {name: .name, type: .type, path: .path}]",
        ]

        result = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            check=False,
        )

        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            if "429" in error_msg or "too many requests" in error_msg.lower():
                print(f"Debug: Rate limited on {repo}{f'/{path}' if path else ''}: {error_msg}", file=sys.stderr)
            elif "404" in error_msg or "not found" in error_msg.lower():
                print(f"Debug: Not found {repo}{f'/{path}' if path else ''}: {error_msg}", file=sys.stderr)
            else:
                print(f"Debug: API error on {repo}{f'/{path}' if path else ''}: {error_msg}", file=sys.stderr)
            return None

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return None

        tree_items = []
        for item in data:
            tree_item = {
                "name": item.get("name", ""),
                "type": item.get("type", ""),
                "path": item.get("path", ""),
            }

            if item.get("type") == "dir":
                tree_item["children"] = fetch_tree_contents(
                    repo, item.get("path", ""), env, token
                )

            tree_items.append(tree_item)

        return tree_items

    except subprocess.TimeoutExpired:
        return None


def cmd_contents(
    repo: str,
    token: str,
    path: str | None = None,
    show_tree: bool = False,
    output_format: str = "table",
) -> int:
    """List contents of a repository or fetch a specific file."""
    env = build_gh_env(token)

    try:
        if show_tree:
            tree_data = fetch_tree_contents(repo, "", env, token)
            if tree_data is None:
                # Try to get more details about the failure
                check_cmd = [
                    "gh",
                    "api",
                    f"repos/{repo}",
                    "--jq",
                    "{name: .name, is_archived: .archived, visibility: .visibility}",
                ]
                check_result = subprocess.run(
                    check_cmd,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=SUBPROCESS_TIMEOUT,
                    check=False,
                )
                if check_result.returncode == 0:
                    try:
                        repo_info = json.loads(check_result.stdout)
                        print(f"Error: Could not fetch repository contents for {repo}", file=sys.stderr)
                        print(f"       Repo exists (name: {repo_info.get('name')}, archived: {repo_info.get('is_archived')}, visibility: {repo_info.get('visibility')})", file=sys.stderr)
                        print(f"       Check rate limits: gh api rate_limit", file=sys.stderr)
                    except json.JSONDecodeError:
                        pass
                else:
                    error_msg = check_result.stderr.strip() if check_result.stderr else "Unknown error"
                    print(f"Error: Could not fetch repository contents for {repo}", file=sys.stderr)
                    if "404" in error_msg:
                        print(f"       Repository not found or not accessible", file=sys.stderr)
                    elif "401" in error_msg:
                        print(f"       Authentication failed - check your GitHub token", file=sys.stderr)
                    elif "429" in error_msg or "too many requests" in error_msg.lower():
                        print(f"       Rate limited - wait a few minutes and retry", file=sys.stderr)
                        print(f"       Check quota: gh api rate_limit", file=sys.stderr)
                    else:
                        print(f"       Details: {error_msg}", file=sys.stderr)
                return 1

            tree_data.sort(key=lambda x: (x["type"] != "dir", x["name"]))
            print(repo)
            print(build_tree(tree_data))
            return 0

        if path:
            cmd = [
                "gh",
                "api",
                f"repos/{repo}/contents/{path}",
            ]

            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
                return 1

            if isinstance(data, dict) and data.get("type") == "file":
                content = data.get("content", "")
                encoding = data.get("encoding", "utf-8")
                if encoding == "base64":
                    try:
                        content = base64.b64decode(content).decode("utf-8")
                    except Exception as exc:
                        print(f"Error: Failed to decode file content: {exc}", file=sys.stderr)
                        return 1
                print(content, end="")
                return 0

            # GitHub returns a list for directory paths; support listing those contents.
            if isinstance(data, list):
                contents = []
                for item in data:
                    contents.append(
                        RepoContent(
                            name=item.get("name", ""),
                            type=item.get("type", ""),
                            size=item.get("size", 0),
                            path=item.get("path", ""),
                        )
                    )

                contents.sort(key=lambda x: (x.type != "dir", x.name))

                if output_format == "csv":
                    headers = ["name", "type", "size", "path"]
                    rows = [
                        [
                            c.name,
                            c.type,
                            c.size,
                            c.path,
                        ]
                        for c in contents
                    ]
                    output = format_csv(headers, rows)
                    print(output, end="")
                else:
                    headers = ["name", "type", "size", "path"]
                    rows = [
                        [
                            c.name,
                            c.type,
                            c.size,
                            c.path,
                        ]
                        for c in contents
                    ]
                    print(format_table(headers, rows))

                return 0

            print("Error: Unexpected response format", file=sys.stderr)
            return 1

        else:
            cmd = [
                "gh",
                "api",
                f"repos/{repo}/contents",
                "--jq",
                "[.[] | {name: .name, type: .type, size: .size, path: .path}]",
            ]

            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
                check=False,
            )

            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1

            try:
                data = json.loads(result.stdout)
            except json.JSONDecodeError as exc:
                print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
                return 1

            if not isinstance(data, list):
                print("Error: Unexpected response format", file=sys.stderr)
                return 1

            contents = []
            for item in data:
                # Get commit date for this specific file
                last_updated = ""
                file_path = item.get("path", "")
                if file_path:
                    try:
                        commit_cmd = [
                            "gh",
                            "api",
                            f"repos/{repo}/commits?path={file_path}&per_page=1",
                            "--jq",
                            ".[0].commit.committer.date",
                        ]
                        commit_result = subprocess.run(
                            commit_cmd,
                            env=env,
                            capture_output=True,
                            text=True,
                            timeout=30,
                            check=False,
                        )
                        if commit_result.returncode == 0 and commit_result.stdout.strip():
                            date_str = commit_result.stdout.strip().strip('"')
                            # Format as just date and time without timezone
                            if "T" in date_str:
                                last_updated = date_str.replace("T", " ")[:16]
                    except Exception:
                        pass

                contents.append(
                    RepoContent(
                        name=item.get("name", ""),
                        type=item.get("type", ""),
                        size=item.get("size", 0),
                        path=item.get("path", ""),
                        last_updated=last_updated,
                    )
                )

            contents.sort(key=lambda x: (x.type != "dir", x.name))

            if output_format == "csv":
                headers = ["name", "type", "size", "path", "last_updated"]
                rows = [
                    [
                        c.name,
                        c.type,
                        c.size,
                        c.path,
                        c.last_updated,
                    ]
                    for c in contents
                ]
                output = format_csv(headers, rows)
                print(output, end="")
            else:
                headers = ["name", "type", "size", "path", "last_updated"]
                rows = [
                    [
                        c.name,
                        c.type,
                        c.size,
                        c.path,
                        c.last_updated,
                    ]
                    for c in contents
                ]
                print(format_table(headers, rows))

            return 0

    except subprocess.TimeoutExpired:
        print(
            f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
            file=sys.stderr,
        )
        return 1


def cmd_repo_branches(
    repo: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List branches for a repository and identify the default branch."""
    env = build_gh_env(token)

    try:
        repo_data = run_gh_command(
            [
                "gh",
                "api",
                f"repos/{repo}",
            ],
            env=env,
        )

        if not isinstance(repo_data, dict):
            print("Error: Unexpected response format from gh api repos", file=sys.stderr)
            return 1

        default_branch = str(repo_data.get("default_branch", "")).strip()
        if not default_branch:
            print(f"Error: Could not determine default branch for {repo}", file=sys.stderr)
            return 1

        branches: list[RepoBranch] = []
        page = 1
        per_page = 100

        while True:
            page_data = run_gh_command(
                [
                    "gh",
                    "api",
                    f"repos/{repo}/branches?per_page={per_page}&page={page}",
                ],
                env=env,
            )

            if not isinstance(page_data, list):
                print(
                    "Error: Unexpected response format from gh api branches",
                    file=sys.stderr,
                )
                return 1

            for item in page_data:
                name = str(item.get("name", ""))
                if not name:
                    continue
                if name_filter and name_filter.lower() not in name.lower():
                    continue

                commit = item.get("commit", {})
                commit_sha = ""
                if isinstance(commit, dict):
                    commit_sha = str(commit.get("sha", ""))

                branches.append(
                    RepoBranch(
                        name=name,
                        is_default=(name == default_branch),
                        is_protected=bool(item.get("protected", False)),
                        commit_sha=commit_sha,
                    )
                )

            if len(page_data) < per_page:
                break
            page += 1

        branches.sort(key=lambda b: (not b.is_default, b.name.lower()))

        if output_format == "csv":
            headers = ["name", "default", "protected", "commit_sha"]
            rows = [
                [
                    b.name,
                    "yes" if b.is_default else "no",
                    "yes" if b.is_protected else "no",
                    b.commit_sha,
                ]
                for b in branches
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["name", "default", "protected", "commit_sha"]
            rows = [
                [
                    b.name,
                    "yes" if b.is_default else "no",
                    "yes" if b.is_protected else "no",
                    b.commit_sha,
                ]
                for b in branches
            ]
            print(format_table(headers, rows))

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_repo_commits(
    repo: str,
    branch: str,
    token: str,
    limit: int = 10,
    verbose: bool = False,
    output_format: str = "table",
) -> int:
    """List commits for a repository branch.

    Default mode shows top-level commit info for recent commits.
    Verbose mode shows deeper commit details (full SHA and full message).
    """
    env = build_gh_env(token)

    try:
        fetch_limit = limit
        if fetch_limit < 1:
            print("Error: --limit must be >= 1", file=sys.stderr)
            return 1

        commits: list[RepoCommit] = []
        page = 1
        per_page = 100

        while len(commits) < fetch_limit:
            page_data = run_gh_command(
                [
                    "gh",
                    "api",
                    f"repos/{repo}/commits?sha={branch}&per_page={per_page}&page={page}",
                ],
                env=env,
            )

            if not isinstance(page_data, list):
                print(
                    "Error: Unexpected response format from gh api commits",
                    file=sys.stderr,
                )
                return 1

            if not page_data:
                break

            for item in page_data:
                commit_data = item.get("commit", {})
                author_data = commit_data.get("author", {}) if isinstance(commit_data, dict) else {}
                message = ""
                if isinstance(commit_data, dict):
                    raw_message = str(commit_data.get("message", ""))
                    message = raw_message if verbose else raw_message.splitlines()[0]

                commits.append(
                    RepoCommit(
                        sha=str(item.get("sha", "")),
                        author=str(author_data.get("name", "")) if isinstance(author_data, dict) else "",
                        date=str(author_data.get("date", "")) if isinstance(author_data, dict) else "",
                        message=message,
                        url=str(item.get("html_url", "")),
                    )
                )

                if len(commits) >= fetch_limit:
                    break

            if len(page_data) < per_page:
                break
            page += 1

        if output_format == "csv":
            headers = ["sha", "author", "date", "message", "url"]
            rows = [
                [
                    c.sha,
                    c.author,
                    c.date,
                    c.message,
                    c.url,
                ]
                for c in commits
            ]
            output = format_csv(headers, rows)
            print(output, end="")
        else:
            headers = ["sha", "author", "date", "message", "url"]
            rows = [
                [
                    c.sha if verbose else c.sha[:12],
                    c.author,
                    c.date,
                    c.message.replace("\n", " | ") if verbose else c.message,
                    c.url,
                ]
                for c in commits
            ]
            print(format_table(headers, rows))

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_repo_branch_protection(
    repo: str,
    branch: str,
    token: str,
    operation: str,
) -> int:
    """Disable, restore, or inspect branch protection for a repository branch."""
    require_protection_ops()
    env = build_gh_env(token)

    try:
        parts = repo.split("/")
        if len(parts) != 2:
            print(f"Invalid repo format: {repo}", file=sys.stderr)
            return 1
        org, repo = parts
 
        metadata = f"org: {org}, repo: {repo}, branch: {branch}"

        if operation == "disable":
            protection_ops.disable_branch_protection(GITHUB_API_BASE, org, repo, branch, token, org)
        
        if operation == "restore":
            cached_protection = protection_ops.get_latest_protection_for_branch(org, org, repo, branch)
            if not cached_protection:
                print(f"Invalid cached protection for {metadata}", file=sys.stderr)
                return 1
            
            protection_data = protection_ops.transform_branch_protection_cache(cached_protection)
            if not protection_data:
                print(f"Invalid protection data object for {metadata}")
                return 1
            
            protection_ops.restore_branch_protection(GITHUB_API_BASE, org, repo, branch, token, protection_data)
        
        if operation == "current":
            current_protection = protection_ops.get_branch_protection(GITHUB_API_BASE, org, repo, branch, token)
            if not current_protection:
                print(f"Invalid protection data object for {metadata}", file=sys.stderr)
                return 1
            print(json.dumps(current_protection, indent=2))
        
        if operation == "cached":
            cached_protection = protection_ops.get_latest_protection_for_branch(org, org, repo, branch)
            if not cached_protection:
                print(f"Invalid cached protection for {metadata}", file=sys.stderr)
                return 1
            print(json.dumps(cached_protection.to_dict(), indent=2))

        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    

def cmd_repo_revert_commit(
    repo: str,
    branch: str,
    sha: str,
    token: str
) -> int:
    """List commits for a repository branch.

    Default mode shows top-level commit info for recent commits.
    Verbose mode shows deeper commit details (full SHA and full message).
    """
    env = build_gh_env(token)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_AUTHOR_EMAIL"] = "veracode@users.noreply.github.com"
    env["GIT_AUTHOR_NAME"] = "veracode-workflow-rollout-helper"

    try:
        temp_git_worktree = tempfile.mkdtemp(prefix=f"veracode-revert-")
        git_url = f"https://x-access-token:{token}@github.com/{repo}.git"

        cmd = [
            "git", "-c", "credential.helper=", "clone",
            "--branch", branch,
            "--single-branch",
            "--depth", "15", git_url, temp_git_worktree
        ]
        data = run_git_command(cmd, env=env)
        if not isinstance(data, str):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1
        print(f"cloned repository with repo: {repo}, branch: {branch}, directory: {temp_git_worktree}")

        cmd = [
            "git", "-C", temp_git_worktree, "config", "credential.helper", '""'
        ]
        data = run_git_command(cmd, env=env)
        if not isinstance(data, str):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1
        print(f"unset credential helper for command: {cmd}")

        cmd = [
            "git", "-C", temp_git_worktree, "revert", "--no-edit", sha
        ]
        data = run_git_command(cmd, env=env)
        if not isinstance(data, str):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1
        print(f"reverted commit with: {cmd}")

        cmd = [
            "git", "-C", temp_git_worktree, "push", "origin", branch
        ]
        data = run_git_command(cmd, env=env)
        if not isinstance(data, str):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1
        print(f"pushed changes with cmd: {cmd}")

        return 0
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if YAML is not None:
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.default_flow_style = False
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 2**32
else:
    yaml = None


def merge_lists_by_name(source_list: list, destination_list: list) -> None:
    """
    Merge source list into destination list, matching items by 'name' key.
    For items with 'name' key: find matching destination item and merge it (recursive).
    For items without 'name' key: replace destination list entirely.
    Modifies destination_list in place.
    """
    # Check if list items are dicts with 'name' keys
    if not source_list or not all(isinstance(item, dict) for item in source_list):
        # Source list is empty or contains non-dict items; replace entirely
        destination_list.clear()
        destination_list.extend(source_list)
        return

    if not all('name' in item for item in source_list):
        # Not all source items have 'name' key; replace entirely
        destination_list.clear()
        destination_list.extend(source_list)
        return

    # Merge by name: source items update/append to destination
    for source_item in source_list:
        source_name = source_item.get('name')
        # Find matching destination item by name
        dest_item = None
        for item in destination_list:
            if isinstance(item, dict) and item.get('name') == source_name:
                dest_item = item
                break

        if dest_item is not None:
            # Found matching item; merge source into destination (recursive)
            merge_yaml_dicts(source_item, dest_item)
        else:
            # No matching item; append source item to destination
            destination_list.append(source_item)


def merge_yaml_dicts(source: dict, destination: dict) -> None:
    """
    Recursively merge source keys into destination, updating values where keys match.
    For lists of dicts with 'name' keys, merge by name instead of replacing.
    Modifies destination in place.
    Note: Multi-line comments on replaced scalar values may be lost due to ruamel.yaml limitations.
    """
    for key, value in source.items():
        if key in destination:
            if isinstance(value, dict) and isinstance(destination[key], dict):
                merge_yaml_dicts(value, destination[key])
            elif isinstance(value, list) and isinstance(destination[key], list):
                merge_lists_by_name(value, destination[key])
            else:
                destination[key] = value
        else:
            destination[key] = value


def obj_to_yml_str(obj, options=None) -> str:
    if not options: options = {}
    string_stream = io.StringIO()
    yaml.dump(obj, string_stream, **options)
    output_str = string_stream.getvalue()
    string_stream.close()
    return output_str


def upsert_yaml_keys(source_content: str, remote_content: str) -> str:
    if yaml is None:
        raise RuntimeError(
            "The 'ruamel.yaml' package is required for --operation merge."
        )
    source_file_yml = yaml.load(source_content)
    remote_file_yml = yaml.load(remote_content)
    merge_yaml_dicts(source_file_yml, remote_file_yml) # remote file contains merged content

    result = obj_to_yml_str(remote_file_yml)
    return result


def cmd_repo_write_file(
    repo: str,
    branch: str,
    destination_file_path: str,
    operation: str,
    token: str,
    source_file_path: str | None = None,
    commit_message: str | None = None,
) -> int:
    """Write, merge, or delete a file in a repository via GitHub API.

    Operations:
    - overwrite: Replace file with provided content
    - merge: Merge YAML content with existing file
    - delete: Remove the file from the repository
    """
    env = build_gh_env(token)

    org_rulesets_disabled = None
    repo_rulesets_disabled = None
    branch_protection_disabled = None
    encountered_error = False

    require_protection_ops()
    parts = repo.split("/")
    if len(parts) != 2:
        print(f"Invalid repo format: {repo}", file=sys.stderr)
        return 1
    org, repo_name = parts

    try:
        api_endpoint = f"repos/{org}/{repo_name}/contents/{destination_file_path}"

        get_cmd = [
            "gh", "api", "-X", "GET", api_endpoint
        ]
        try:
            get_data = run_gh_command(get_cmd, env=env)
        except RuntimeError as exc:
            # A missing file is expected when creating it for the first time.
            if "404" not in str(exc):
                raise
            get_data = {}
        if not isinstance(get_data, dict):
            raise ValueError(f"Error: Unexpected response format from \"{" ".join(get_cmd)}\"")
        get_sha = get_data.get("sha")

        try:
            if not cmd_repo_branch_protection(repo, branch, token, "disable"): 
                branch_protection_disabled = True
            print(f"{repo}@{branch}: branch protection disabled: {branch_protection_disabled}")
        except Exception as e:
            print(f"{repo}@{branch}: failed to disable branch protection: {e}")
        repo_rulesets_disabled = protection_ops.disable_repository_rulesets(GITHUB_API_BASE, org, repo_name, token, None)
        if repo_rulesets_disabled:
            print(f"{repo}: repository rulesets disabled: {repo_rulesets_disabled}")
        org_rulesets_disabled = protection_ops.disable_org_rulesets(GITHUB_API_BASE, org, token, None)
        if org_rulesets_disabled:
            print(f"{org}: org rulesets disabled: {org_rulesets_disabled}")

        if operation == "delete":
            if not get_sha:
                raise ValueError(f"Could not retrieve SHA for operation: {operation}")
            
            delete_cmd = [
                "gh", "api", "-X", "DELETE", api_endpoint,
                "-f", f"message={commit_message or f'Delete {destination_file_path}'}",
                "-f", f"sha={get_sha}",
                "-f", f"branch={branch}",
            ]
            data = run_gh_command(delete_cmd, env=env)
            if not isinstance(data, dict):
                raise ValueError(f"Error: Unexpected response format from \"{" ".join(delete_cmd)}\"")
            
            print(f"Deleted file: {destination_file_path}")

        if operation in ("overwrite", "merge"):
            if not source_file_path:
                raise ValueError(f"Error: --source-file is required for {operation} operation")
            
            source_path = Path(source_file_path)
            if not source_path.exists():
                raise ValueError(f"Error: file {source_path} does not exist")

            merged_content = source_path.read_text()
            action_label = "Updated" if get_sha else "Created"

            if operation == "merge" and get_sha:
                existing_content = base64.b64decode(get_data.get("content", "")).decode("utf-8")
                merged_content = upsert_yaml_keys(source_content=merged_content, remote_content=existing_content)

            encoded_content = base64.b64encode(merged_content.encode("utf-8")).decode("utf-8")
            put_cmd = [
                "gh", "api", "-X", "PUT", api_endpoint,
                "-f", f"message={commit_message or f'{action_label} {destination_file_path}'}",
                "-f", f"content={encoded_content}",
                "-f", f"branch={branch}",
            ]
            if get_sha:
                put_cmd.extend(["-f", f"sha={get_sha}"])

            data = run_gh_command(put_cmd, env=env)
            if not isinstance(data, dict):
                raise ValueError(f"Error: Unexpected response format from \"{" ".join(put_cmd)}\"")

            print(f"{action_label} file: {destination_file_path}")

            return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        encountered_error = True
        # return 1
    finally:
        if branch_protection_disabled: 
            cmd_repo_branch_protection(repo, branch, token, "restore")
            print(f"{repo}@{branch}: branch protection restored")
        if repo_rulesets_disabled:
            protection_ops.restore_repository_rulesets(GITHUB_API_BASE, org, repo_name, token, repo_rulesets_disabled, None)
            print(f"{repo}: repository rulesets restored")
        if org_rulesets_disabled:
            protection_ops.restore_org_rulesets(GITHUB_API_BASE, org, token, org_rulesets_disabled, None)
            print(f"{org}: org rulesets restored")

    if encountered_error:
            return 1
    
    return 0


def _handle_termination_signal(signum: int, frame) -> None:
    """Convert termination signals into SystemExit so finally blocks run.

    repo-write-file disables branch protection and rulesets and restores them
    in finally; a raw signal death would leave protections off. Only SIGKILL
    or a host crash can bypass this.
    """
    raise SystemExit(128 + signum)


def install_signal_handlers() -> None:
    for name in ("SIGTERM", "SIGINT", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _handle_termination_signal)
        except (ValueError, OSError):
            pass


def main() -> int:
    """Main entry point."""
    install_signal_handlers()
    load_env_file()

    parser = argparse.ArgumentParser(
        description="GitHub Workflow CLI - Query workflows and logs"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    org_actions_perms_parser = subparsers.add_parser("org-actions-permissions", help="View GitHub Actions permissions for an organization")
    org_actions_perms_parser.add_argument(
        "--org", required=True, help="Organization name"
    )

    token_info_parser = subparsers.add_parser("token-info", help="Show information about the GitHub token being used")

    orgs_parser = subparsers.add_parser("orgs", help="List organizations the token can access, with a single/multi-org verdict")
    orgs_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    org_app_view_parser = subparsers.add_parser("org-app", help="View settings for a GitHub app installed in an organization")
    org_app_view_parser.add_argument(
        "--org", required=True, help="Organization name"
    )
    org_app_view_parser.add_argument(
        "--name", required=True, help="App name (e.g., veracode-workflow-app, slack)"
    )

    org_apps_parser = subparsers.add_parser("org-apps", help="List GitHub apps installed in an organization")
    org_apps_parser.add_argument(
        "--org", required=True, help="Organization name"
    )
    org_apps_parser.add_argument(
        "--name",
        help="Filter by app name (case-insensitive substring match)",
    )
    org_apps_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    org_rulesets_parser = subparsers.add_parser("org-rulesets")
    org_rulesets_parser.add_argument(
        "--org", required=True, help="Organization name"
    )
    org_rulesets_parser.add_argument(
        "--ruleset-id", help="Ruleset ID to look at a specific ruleset"   
    )
    org_rulesets_parser.add_argument(
        "--modify-ruleset-enforcement", help="Update ruleset enforcement state",
        choices=['active', 'disabled', 'evaluate']
    )

    repos_parser = subparsers.add_parser("repos", help="List repositories")
    repos_parser.add_argument(
        "--org", required=True, help="Organization name"
    )
    repos_parser.add_argument(
        "--name",
        help="Filter by repository name (case-insensitive substring match)",
    )
    repos_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    workflows_parser = subparsers.add_parser("workflows", help="List workflow runs")
    workflows_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    workflows_parser.add_argument(
        "--status",
        choices=["queued", "in_progress", "completed"],
        help="Filter by status",
    )
    workflows_parser.add_argument(
        "--conclusion",
        help="Filter by conclusion (comma-separated: success,failure,cancelled,skipped)",
    )
    workflows_parser.add_argument(
        "--name",
        help="Filter by workflow name (case-insensitive substring match)",
    )
    workflows_parser.add_argument(
        "--name-break",
        help="Exit pagination on name match",
        action=argparse.BooleanOptionalAction
    )
    workflows_parser.add_argument(
        "--limit", type=int, default=10000, help="Maximum number of runs to list (default: 10000, fetches all)"
    )
    workflows_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    run_parser = subparsers.add_parser("run", help="View details of a specific workflow run")
    run_parser.add_argument(
        "--id", type=int, required=True, help="Workflow run ID (use the 'id' column from workflows output)"
    )
    run_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )

    groups_parser = subparsers.add_parser(
        "runner-groups",
        help="List runner groups and every runner in them, incl. hosted larger runners (CSV)")
    groups_parser.add_argument(
        "--org", required=True, help="Organization login"
    )
    runners_parser = subparsers.add_parser(
        "runners", help="List the org's self-hosted runner inventory (CSV)")
    runners_parser.add_argument(
        "--org", required=True, help="Organization login"
    )
    jobs_parser = subparsers.add_parser(
        "jobs", help="List a run's jobs with requested labels and resolved runner (CSV)")
    jobs_parser.add_argument(
        "--run-id", type=int, required=True, help="Workflow run ID"
    )
    jobs_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    logs_parser = subparsers.add_parser("logs", help="Fetch workflow logs")
    logs_parser.add_argument(
        "--run-id", type=int, required=True, help="Workflow run ID (use the 'id' column from workflows output)"
    )
    logs_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    logs_parser.add_argument(
        "--relevant-only",
        action="store_true",
        help="Keep validation, build, AutoPackager, upload, prescan, scan, policy, and results jobs.",
    )
    logs_parser.add_argument(
        "--exclude-cleanup",
        action="store_true",
        help="Exclude cleanup and check-run registration jobs.",
    )
    logs_parser.add_argument(
        "--manifest",
        help="Write discovered and selected job names to a JSON manifest.",
    )

    issues_parser = subparsers.add_parser("issues", help="List issues")
    issues_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    issues_parser.add_argument(
        "--state",
        choices=["open", "closed"],
        help="Filter by state",
    )
    issues_parser.add_argument(
        "--limit", type=int, default=10000, help="Maximum number of issues to list (default: 10000, fetches all)"
    )
    issues_parser.add_argument(
        "--tree",
        action="store_true",
        help="Show issues as a tree with comments",
    )
    issues_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    issue_create_parser = subparsers.add_parser("issue-create", help="Create a new issue")
    issue_create_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    issue_create_parser.add_argument(
        "--title", required=True, help="Issue title"
    )
    issue_create_parser.add_argument(
        "--body", help="Issue body/description"
    )
    issue_create_parser.add_argument(
        "--assignee", help="Username to assign the issue to"
    )
    issue_create_parser.add_argument(
        "--labels", help="Comma-separated list of labels"
    )

    issue_view_parser = subparsers.add_parser("issue", help="View a specific issue")
    issue_view_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    issue_view_parser.add_argument(
        "--number", type=int, required=True, help="Issue number"
    )

    contents_parser = subparsers.add_parser("contents", help="List contents of repo root or fetch a file")
    contents_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    contents_parser.add_argument(
        "--path", help="File path to fetch (e.g., README.md, src/main.py)"
    )
    contents_parser.add_argument(
        "--tree",
        action="store_true",
        help="Show full tree of all files and directories",
    )
    contents_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV (only for directory listing)",
    )

    repo_branches_parser = subparsers.add_parser("repo-branches", help="List repository branches")
    repo_branches_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_branches_parser.add_argument(
        "--name",
        help="Filter by branch name (case-insensitive substring match)",
    )
    repo_branches_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    repo_commits_parser = subparsers.add_parser("repo-commits", help="List commit history for a branch")
    repo_commits_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_commits_parser.add_argument(
        "--branch", required=True, help="Branch name (e.g., main, develop, release/v1)"
    )
    repo_commits_parser.add_argument(
        "--limit", type=int, default=10, help="Maximum number of commits to list (default: 10)"
    )
    repo_commits_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show verbose commit details (full SHA and full commit message/body).",
    )
    repo_commits_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    repo_actions_perms_parser = subparsers.add_parser("repo-actions-permissions", aliases=["rap"], help="View or update GitHub Actions permissions for a repository")
    repo_actions_perms_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_actions_perms_parser.add_argument(
        "--enable",
        action="store_true",
        help="Enable GitHub Actions for the repository",
    )
    repo_actions_perms_parser.add_argument(
        "--disable",
        action="store_true",
        help="Disable GitHub Actions for the repository",
    )
    repo_actions_perms_parser.add_argument(
        "--csv",
        dest="output_format",
        action="store_const",
        const="csv",
        default="table",
        help="Output as CSV",
    )

    repo_branch_protection_parser = subparsers.add_parser("repo-branch-protection", help="Manage branch protection")
    repo_branch_protection_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_branch_protection_parser.add_argument(
        "--branch", required=True, help="Branch name"
    )
    repo_branch_protection_parser.add_argument(
        "--operation", required=True, help="Branch protection operation (disable/restore)",
        choices=["disable", "restore", "current", "cached"]
    )

    repo_write_file_parser = subparsers.add_parser("repo-write-file", help="Write, merge, or delete a file in a repository")
    repo_write_file_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_write_file_parser.add_argument(
        "--branch", required=True, help="Branch name"
    )
    repo_write_file_parser.add_argument(
        "--destination-file", required=True, help="File path (relative to repo root)"
    )
    repo_write_file_parser.add_argument(
        "--operation", required=True, help="File operation",
        choices=["merge", "overwrite", "delete"]
    )
    repo_write_file_parser.add_argument(
        "--source-file", help="File content (required for merge/overwrite, not needed for delete)"
    )
    repo_write_file_parser.add_argument(
        "--message", help="Custom commit message"
    )

    repo_revert_commit_parser = subparsers.add_parser("repo-revert-commit", help="Revert repo commit")
    repo_revert_commit_parser.add_argument(
        "--repo", required=True, help="Repository (org/repo format)"
    )
    repo_revert_commit_parser.add_argument(
        "--branch", required=True, help="Branch (main/master/develop/etc.)"
    )
    repo_revert_commit_parser.add_argument(
        "--sha", required=True, help="Commit SHA"
    )

    args = parser.parse_args()

    try:
        token = get_github_token()
    except SystemExit as exc:
        print(exc, file=sys.stderr)
        return 1

    if args.command == "org-actions-permissions":
        return cmd_org_actions_permissions(
            args.org,
            token,
        )
    elif args.command == "repos":
        return cmd_repos(
            args.org,
            token,
            name_filter=args.name,
            output_format=args.output_format,
        )
    elif args.command == "token-info":
        return cmd_token_info(
            token,
        )
    elif args.command == "orgs":
        return cmd_orgs(
            token,
            output_format=args.output_format,
        )
    elif args.command == "org-app":
        return cmd_org_app_view(
            args.org,
            args.name,
            token,
        )
    elif args.command == "org-apps":
        return cmd_org_apps(
            args.org,
            token,
            name_filter=args.name,
            output_format=args.output_format,
        )
    elif args.command == "workflows":
        return cmd_workflows(
            args.repo,
            token,
            status=args.status,
            conclusion=args.conclusion,
            name_filter=args.name,
            limit=args.limit,
            output_format=args.output_format,
            name_filter_break=args.name_break
        )
    elif args.command == "run":
        return cmd_run_view(
            args.id,
            token,
            repo=args.repo,
        )
    elif args.command == "runner-groups":
        return cmd_runner_groups(
            args.org,
            token,
        )
    elif args.command == "runners":
        return cmd_org_runners(
            args.org,
            token,
        )
    elif args.command == "jobs":
        return cmd_run_jobs(
            args.run_id,
            token,
            repo=args.repo,
        )
    elif args.command == "logs":
        return cmd_logs(
            args.run_id,
            token,
            repo=args.repo,
            relevant_only=args.relevant_only,
            exclude_cleanup=args.exclude_cleanup,
            manifest_path=args.manifest,
        )
    elif args.command == "issues":
        return cmd_issues(
            args.repo,
            token,
            state=args.state,
            limit=args.limit,
            output_format=args.output_format,
            show_tree=args.tree,
        )
    elif args.command == "issue-create":
        return cmd_issue_create(
            args.repo,
            token,
            title=args.title,
            body=args.body,
            assignee=args.assignee,
            labels=args.labels,
        )
    elif args.command == "issue":
        return cmd_issue_view(
            args.repo,
            args.number,
            token,
        )
    elif args.command == "contents":
        return cmd_contents(
            args.repo,
            token,
            path=args.path,
            show_tree=args.tree,
            output_format=args.output_format,
        )
    elif args.command == "repo-branches":
        return cmd_repo_branches(
            args.repo,
            token,
            name_filter=args.name,
            output_format=args.output_format,
        )
    elif args.command == "repo-commits":
        return cmd_repo_commits(
            args.repo,
            args.branch,
            token,
            limit=args.limit,
            verbose=args.verbose,
            output_format=args.output_format,
        )
    elif args.command == "repo-branch-protection":
        return cmd_repo_branch_protection(
            args.repo,
            args.branch,
            token,
            args.operation
        )
    elif args.command == "repo-write-file":
        return cmd_repo_write_file(
            args.repo,
            args.branch,
            destination_file_path=args.destination_file,
            operation=args.operation,
            source_file_path=args.source_file,
            token=token,
            commit_message=args.message,
        )
    elif args.command == "repo-revert-commit":
        return cmd_repo_revert_commit(
            args.repo,
            args.branch,
            args.sha,
            token
        )
    elif args.command == "org-rulesets":
        return cmd_org_rulesets(
            args.org,
            token,
            args.ruleset_id,
            args.modify_ruleset_enforcement,
        )
    elif args.command in ("repo-actions-permissions", "rap"):
        return cmd_repo_actions_permissions(
            args.repo,
            token,
            output_format=args.output_format,
            enable=args.enable,
            disable=args.disable,
        )
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
