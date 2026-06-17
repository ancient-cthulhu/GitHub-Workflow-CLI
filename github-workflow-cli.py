#!/usr/bin/env python3
"""
GitHub Workflow CLI - Query and remediate GitHub workflows, repos, and settings.

Supports listing repos, workflow runs, logs, issues, contents, branches,
commits, app/permission/ruleset inspection, and bulk file write/merge/delete
plus branch-protection and commit-revert helpers used by the Veracode
workflow integration to remediate at scale.

Requires Python 3.12+ (uses PEP 701 nested-quote f-strings) and the `gh` and
`git` CLIs on PATH.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

from enable_debug import protection_ops
from ruamel.yaml import YAML

try:
    import requests
except ImportError:
    requests = None

GITHUB_API_BASE = "https://api.github.com"

# A single GitHub token authenticates every command (tenant-wide token or a
# personal access token). The token's own access determines which orgs and
# repos are reachable. Checked in order.
TOKEN_ENV_VARS = ("GITHUB_TOKEN", "GH_TOKEN")

SUBPROCESS_TIMEOUT = 600  # 10 minutes


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _run(
    cmd: list[str],
    env: dict[str, str],
    *,
    input: str | None = None,
    timeout: int = SUBPROCESS_TIMEOUT,
) -> subprocess.CompletedProcess:
    """Run a subprocess capturing text output. Never raises on non-zero exit."""
    return subprocess.run(
        cmd,
        env=env,
        input=input,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def emit(headers: list[str], rows: list[list], output_format: str) -> None:
    """Print rows as CSV or as a human-readable table."""
    if output_format == "csv":
        print(format_csv(headers, rows), end="")
    else:
        print(format_table(headers, rows))


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


def get_token() -> str:
    """Retrieve the GitHub token from the environment (GITHUB_TOKEN or GH_TOKEN)."""
    for env_name in TOKEN_ENV_VARS:
        token = os.environ.get(env_name)
        if token:
            return token
    raise SystemExit(
        f"No GitHub token found. Set one of {', '.join(TOKEN_ENV_VARS)} "
        f"(in the environment or a local .env file)."
    )


def build_gh_env(token: str | None = None) -> dict[str, str]:
    """Construct subprocess environment with GitHub token."""
    env = os.environ.copy()
    if token:
        env["GH_TOKEN"] = token
        env["GITHUB_TOKEN"] = token
    return env


def build_git_auth_env(token: str) -> dict[str, str]:
    """Environment for git over HTTPS to github.com that does not leak the token.

    The token is injected as an http.extraheader through GIT_CONFIG_* env vars
    (git 2.31+), so it appears in neither the process arguments (ps) nor a
    persisted .git/config remote URL. Clones/pushes use a bare https URL.
    """
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "http.https://github.com/.extraheader"
    env["GIT_CONFIG_VALUE_0"] = f"AUTHORIZATION: basic {basic}"
    return env


def run_gh_command(cmd: list[str], env: dict[str, str]) -> dict | list:
    """Execute a gh CLI command and return parsed JSON output."""
    try:
        result = _run(cmd, env)
        if result.returncode != 0:
            raise RuntimeError(
                f"gh command failed with code {result.returncode}: {result.stderr}"
            )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"gh command timed out after {SUBPROCESS_TIMEOUT} seconds")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse gh output as JSON: {exc}")


def run_git_command(cmd: list[str], env: dict[str, str]) -> str:
    """Execute a git CLI command and return its stdout."""
    try:
        result = _run(cmd, env)
        if result.returncode != 0:
            raise RuntimeError(
                f"git command failed with code {result.returncode}: {result.stderr}"
            )
        return result.stdout
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git command timed out after {SUBPROCESS_TIMEOUT} seconds")


# --------------------------------------------------------------------------- #
# Data models
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Formatting
# --------------------------------------------------------------------------- #
def format_table(headers: list[str], rows: list[list]) -> str:
    """Format data as a human-readable table."""
    if not rows:
        return "(no results)"

    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    lines = []
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
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


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_repos(
    org: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List repositories in an organization (archived repos are skipped)."""
    env = build_gh_env(token)

    try:
        data = run_gh_command(
            [
                "gh", "repo", "list", org,
                "--json", "name,url,isPrivate,description,isArchived",
                "--limit", "10000",
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

        headers = ["name", "url", "private", "description"]
        rows = [
            [r.name, r.url, "yes" if r.is_private else "no", r.description or ""]
            for r in repos
        ]
        emit(headers, rows, output_format)
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
        # gh doesn't support multiple conclusions in one query, so filter locally.
        allowed_conclusions = set()
        if conclusion:
            allowed_conclusions = set(c.strip() for c in conclusion.split(","))

        data: list[WorkflowRun] = []

        page = 1
        pagination_size = 100
        query_params = [f"per_page={pagination_size}", "sort=created", "order=desc"]
        if status:  # server-side status filter (queued|in_progress|completed)
            query_params.append(f"status={status}")

        total_fetched = 0
        while True:
            if total_fetched >= limit:
                break
            query_path = f"/repos/{repo}/actions/runs?{"&".join(query_params)}&page={page}"
            cmd = ["gh", "api", query_path]
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
                if allowed_conclusions and item_conclusion not in allowed_conclusions:
                    continue

                data.append(
                    WorkflowRun(
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
                )

            if name_filter and name_filter_break and data:
                break

            page += 1
            total_fetched += len(workflow_runs)

        headers = ["number", "id", "name", "status", "conclusion",
                   "created", "started", "updated", "branch"]
        rows = [
            [r.number, r.run_id, r.name, r.status, r.conclusion or "",
             r.created_at, r.started_at, r.updated_at, r.head_branch]
            for r in data
        ]
        emit(headers, rows, output_format)
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
        data = run_gh_command(
            [
                "gh", "run", "view", str(run_id), "--repo", repo, "--json",
                "number,databaseId,name,status,conclusion,createdAt,updatedAt,"
                "headBranch,workflowName,displayTitle",
            ],
            env=env,
        )

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


def fetch_logs_via_api(token: str, repo: str, run_id: int) -> str:
    """Fetch workflow logs via the GitHub API, one job at a time.

    The gh CLI truncates very large logs; fetching per-job from the API avoids
    that. Each job's log archive is downloaded in full (not streamed), so peak
    memory scales with the largest single job log.
    """
    if not requests:
        raise RuntimeError(
            "requests library not available. Install with: pip install requests"
        )

    if "/" not in repo:
        raise ValueError(f"Invalid repo format: {repo}")
    owner, repo_name = repo.split("/", 1)

    jobs_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/actions/runs/{run_id}/jobs"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }

    try:
        response = requests.get(jobs_url, headers=headers, timeout=60)
        response.raise_for_status()
        jobs_data = response.json()
    except Exception as e:
        raise RuntimeError(f"Failed to fetch jobs: {e}")

    all_logs = []
    for job in jobs_data.get("jobs", []):
        job_id = job.get("id")
        if not job_id:
            continue

        logs_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo_name}/actions/jobs/{job_id}/logs"
        try:
            response = requests.get(logs_url, headers=headers, timeout=60, allow_redirects=True)
            response.raise_for_status()
            job_name = job.get("name", f"Job {job_id}")
            all_logs.append(f"=== {job_name} ===\n{response.text}\n")
        except Exception as e:
            print(f"Warning: Failed to fetch logs for job {job_id}: {e}", file=sys.stderr)
            continue

    return "".join(all_logs)


def cmd_logs(
    run_id: int,
    token: str,
    repo: str,
) -> int:
    """Fetch logs for a specific workflow run (API first, gh CLI fallback)."""
    try:
        logs = fetch_logs_via_api(token, repo, run_id)
        print(logs, end="")
        return 0
    except Exception as e:
        print(f"Warning: API method failed ({e}), falling back to gh CLI", file=sys.stderr)
        env = build_gh_env(token)
        try:
            result = _run(
                ["gh", "run", "view", str(run_id), "--log", "--repo", repo], env
            )
            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1
            print(result.stdout, end="")
            return 0
        except subprocess.TimeoutExpired:
            print(
                f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds",
                file=sys.stderr,
            )
            return 1


def _set_repo_issues(repo: str, env: dict[str, str], enabled: bool) -> None:
    """Toggle the repository's issues feature on/off (best effort)."""
    if enabled:
        _run(["gh", "repo", "edit", repo, "--enable-issues"], env)
    else:
        _run(
            ["gh", "api", f"repos/{repo}", "-X", "PATCH", "-f", "has_issues=false"],
            env,
        )


def cmd_issues(
    repo: str,
    token: str,
    state: str | None = None,
    limit: int = 10000,
    output_format: str = "table",
    show_tree: bool = False,
) -> int:
    """List issues in a repository (temporarily enables issues if disabled)."""
    env = build_gh_env(token)
    issues_were_disabled = False

    try:
        result_check = _run(
            ["gh", "repo", "view", repo, "--json", "hasIssuesEnabled"], env
        )
        if result_check.returncode != 0:
            print(f"Error checking repo: {result_check.stderr}", file=sys.stderr)
            return 1

        try:
            issues_enabled = json.loads(result_check.stdout).get("hasIssuesEnabled", False)
        except json.JSONDecodeError:
            print("Error: Could not parse repo status", file=sys.stderr)
            return 1

        issues_were_disabled = not issues_enabled
        if issues_were_disabled:
            print(f"Issues are disabled on {repo}. Enabling temporarily...", file=sys.stderr)
            _set_repo_issues(repo, env, enabled=True)
            print("Issues enabled.", file=sys.stderr)

        cmd = [
            "gh", "issue", "list", "--repo", repo,
            "--json", "number,title,state,createdAt,updatedAt,author",
            "--limit", str(limit),
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
            author_name = (
                author_data.get("login", "unknown")
                if isinstance(author_data, dict) else str(author_data)
            )
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
        else:
            headers = ["number", "title", "state", "created", "updated", "author"]
            rows = [
                [i.number, i.title, i.state, i.created_at, i.updated_at, i.author]
                for i in issues
            ]
            emit(headers, rows, output_format)

        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        if issues_were_disabled:
            print("Disabling issues again...", file=sys.stderr)
            _set_repo_issues(repo, env, enabled=False)
            print("Issues disabled.", file=sys.stderr)


def cmd_org_apps(
    org: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List GitHub apps installed in an organization."""
    env = build_gh_env(token)

    try:
        result = _run(
            [
                "gh", "api", f"orgs/{org}/installations", "--jq",
                "[.installations[] | {name: .app_slug, app_id: .app_id, "
                "created_at: .created_at, updated_at: .updated_at, "
                "permissions: (.permissions | keys | join(\", \"))}]",
            ],
            env,
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

        headers = ["name", "app_id", "created_at", "updated_at", "permissions"]
        rows = [
            [a.name, a.app_id, a.created_at, a.updated_at, a.permissions]
            for a in apps
        ]
        emit(headers, rows, output_format)
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def cmd_token_info(
    token: str,
) -> int:
    """Display information about the GitHub token being used."""
    env = build_gh_env(token)

    try:
        result = _run(
            [
                "gh", "api", "user", "--jq",
                "{login: .login, name: .name, email: .email, id: .id, "
                "type: .type, company: .company, location: .location}",
            ],
            env,
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
        if user_data.get("company"):
            print(f"  Company: {user_data.get('company')}")
        if user_data.get("location"):
            print(f"  Location: {user_data.get('location')}")
        print()

        print("Token Scopes:")
        result_status = _run(["gh", "auth", "status"], env)
        if result_status.returncode == 0:
            print(result_status.stdout)
        else:
            print("  (Unable to retrieve scopes)")
            if result_status.stderr:
                print(f"  {result_status.stderr}", file=sys.stderr)
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def _list_token_orgs(token: str, env: dict[str, str]) -> tuple[list[str] | None, str]:
    """Return (orgs, source) reachable by the token.

    Tries /user/orgs first (PAT, fine-grained, OAuth). If that is not available
    (e.g. an app installation token has no user context) it infers the org(s)
    from the installation's repository owners. Returns (None, "") on failure.
    """
    result = _run(["gh", "api", "--paginate", "user/orgs", "--jq", ".[].login"], env)
    if result.returncode == 0:
        orgs = sorted({line.strip() for line in result.stdout.splitlines() if line.strip()})
        return orgs, "user"

    inst = _run(
        ["gh", "api", "--paginate", "installation/repositories",
         "--jq", ".repositories[].owner.login"],
        env,
    )
    if inst.returncode == 0:
        orgs = sorted({line.strip() for line in inst.stdout.splitlines() if line.strip()})
        return orgs, "installation"

    print("Error: could not list organizations for this token.", file=sys.stderr)
    print(f"  user/orgs: {result.stderr.strip()}", file=sys.stderr)
    print(f"  installation/repositories: {inst.stderr.strip()}", file=sys.stderr)
    print(
        "  A classic PAT needs the 'read:org' or 'user' scope; a fine-grained PAT "
        "needs organization access.",
        file=sys.stderr,
    )
    return None, ""


def cmd_orgs(
    token: str,
    output_format: str = "table",
) -> int:
    """List the organizations the token can reach and report single vs multi-org."""
    env = build_gh_env(token)

    try:
        orgs, source = _list_token_orgs(token, env)
        if orgs is None:
            return 1

        emit(["org"], [[o] for o in orgs], output_format)

        if output_format != "csv":
            count = len(orgs)
            if count == 0:
                print("\nNo organizations are visible to this token.")
            elif count == 1:
                print(f"\nSingle-org token: 1 organization ({orgs[0]}).")
            else:
                print(f"\nMulti-org token: {count} organizations.")
            if source == "installation":
                print("(Inferred from installation repository owners; this is an "
                      "app installation token.)")
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def cmd_org_actions_permissions(
    org: str,
    token: str,
) -> int:
    """View GitHub Actions permissions settings for an organization."""
    env = build_gh_env(token)

    try:
        result = _run(["gh", "api", f"orgs/{org}/actions/permissions"], env)
        if result.returncode != 0:
            print(f"Error: {result.stderr}", file=sys.stderr)
            return 1

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            print(f"Error: Failed to parse response as JSON: {exc}", file=sys.stderr)
            return 1

        print(f"GitHub Actions Permissions for {org}:\n")
        print("Enabled Repositories:")
        print(f"  {data.get('enabled_repositories', 'N/A')}\n")
        print("Allowed Actions:")
        print(f"  {data.get('allowed_actions', 'N/A')}\n")
        print("Full Response:")
        print(json.dumps(data, indent=2))
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
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
        if enable or disable:
            enabled_value = enable if enable else not disable
            result = _run(
                ["gh", "api", f"repos/{repo}/actions/permissions",
                 "-X", "PUT", "--input", "-"],
                env,
                input=json.dumps({"enabled": enabled_value}),
            )
            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1
            print(f"Successfully updated Actions permissions for {repo}")
            print(f"Actions are now: {'enabled' if enabled_value else 'disabled'}\n")
            return 0

        result = _run(["gh", "api", f"repos/{repo}/actions/permissions"], env)
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
            rows = [[repo, "yes" if enabled else "no", str(allowed_actions),
                     selected_actions_url or ""]]
            emit(headers, rows, output_format)
        else:
            print(f"GitHub Actions Permissions for {repo}:\n")
            print(f"Enabled: {'yes' if enabled else 'no'}")
            print(f"Allowed Actions: {allowed_actions}")
            if selected_actions_url:
                print(f"Selected Actions URL: {selected_actions_url}")
            print("\nFull Response:")
            print(json.dumps(data, indent=2))
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def cmd_org_rulesets(
    org: str,
    token: str,
    ruleset_id: str | None = None,
    modify_ruleset_enforcement: str | None = None,
) -> int:
    """View or modify GitHub org rulesets for an organization."""
    env = build_gh_env(token)

    try:
        path = f"orgs/{org}/rulesets/{ruleset_id}" if ruleset_id else f"orgs/{org}/rulesets"
        result = _run(["gh", "api", path], env)
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
            result = _run(
                ["gh", "api", f"orgs/{org}/rulesets/{ruleset_id}", "-X", "PUT", "--input", "-"],
                env,
                input=json.dumps(data, separators=(",", ":")),
            )
            if result.returncode != 0:
                print(f"Error: {result.stderr}", file=sys.stderr)
                return 1
            print(
                f"Success: Updated {org} ruleset id {ruleset_id} "
                f"with enforcement {modify_ruleset_enforcement}"
            )
            return 0

        print(f"GitHub Rulesets for {org}:\n")
        print(json.dumps(data, indent=2))

        if not ruleset_id:
            headers = ["id", "name", "target", "enforcement"]
            rows = [
                [c.get("id"), c.get("name"), c.get("target"), c.get("enforcement")]
                for c in data
            ]
            print(format_table(headers, rows))
        return 0

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def cmd_org_app_view(
    org: str,
    app_name: str,
    token: str,
) -> int:
    """View settings for a specific GitHub app installed in an organization."""
    env = build_gh_env(token)

    try:
        result = _run(
            ["gh", "api", f"orgs/{org}/installations", "--jq",
             f".installations[] | select(.app_slug == \"{app_name}\")"],
            env,
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
        print(f"Updated: {data.get('updated_at', 'N/A')}\n")

        if data.get("suspended_at"):
            print("Status: SUSPENDED")
            print(f"  Suspended at: {data.get('suspended_at', 'N/A')}")
            print(f"  Suspended by: {data.get('suspended_by', 'N/A')}\n")
        else:
            print("Status: ACTIVE\n")

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
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def cmd_issue_create(
    repo: str,
    token: str,
    title: str,
    body: str | None = None,
    assignee: str | None = None,
    labels: str | None = None,
) -> int:
    """Create a new issue on a repository (temporarily enables issues if disabled)."""
    env = build_gh_env(token)
    issues_were_disabled = False

    try:
        result_check = _run(
            ["gh", "repo", "view", repo, "--json", "hasIssuesEnabled"], env
        )
        if result_check.returncode != 0:
            print(f"Error checking repo: {result_check.stderr}", file=sys.stderr)
            return 1

        try:
            issues_enabled = json.loads(result_check.stdout).get("hasIssuesEnabled", False)
        except json.JSONDecodeError:
            print("Error: Could not parse repo status", file=sys.stderr)
            return 1

        issues_were_disabled = not issues_enabled
        if issues_were_disabled:
            print(f"Issues are disabled on {repo}. Enabling temporarily...")
            _set_repo_issues(repo, env, enabled=True)
            print("Issues enabled.")

        cmd = ["gh", "issue", "create", "--repo", repo, "--title", title]
        if body:
            cmd.extend(["--body", body])
        if assignee:
            cmd.extend(["--assignee", assignee])
        if labels:
            cmd.extend(["--label", labels])

        result = _run(cmd, env)
        if result.returncode != 0:
            stderr_msg = result.stderr.strip() if result.stderr else "Unknown error"
            print(f"Error creating issue: {stderr_msg}", file=sys.stderr)
            if result.stdout:
                print(f"Output: {result.stdout}", file=sys.stderr)
            return 1

        output = result.stdout.strip()
        if output:
            print(f"Issue created successfully: {output}")
            return 0

        print("Warning: Issue may not have been created - no URL returned", file=sys.stderr)
        print("This often indicates you've hit GitHub's secondary rate limit.", file=sys.stderr)
        print("Please wait a few minutes and try again.", file=sys.stderr)
        if result.stderr:
            print(f"Additional info: {result.stderr}", file=sys.stderr)
        return 1

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1
    finally:
        if issues_were_disabled:
            print("Disabling issues again...")
            _set_repo_issues(repo, env, enabled=False)
            print("Issues disabled.")


def cmd_issue_view(
    repo: str,
    issue_number: int,
    token: str,
) -> int:
    """View full contents of a specific issue."""
    env = build_gh_env(token)

    try:
        data = run_gh_command(
            ["gh", "issue", "view", str(issue_number), "--repo", repo,
             "--json", "number,title,state,body,author,createdAt,updatedAt"],
            env=env,
        )
        if not isinstance(data, dict):
            print("Error: Unexpected response format", file=sys.stderr)
            return 1

        author_data = data.get("author", {})
        author_name = (
            author_data.get("login", "unknown")
            if isinstance(author_data, dict) else str(author_data)
        )

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
        print(f"Updated: {issue.updated_at}\n")
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
        result = _run(
            ["gh", "issue", "view", str(issue_number), "--repo", repo, "--json", "comments"],
            env,
        )
        if result.returncode != 0:
            return []

        comments_data = json.loads(result.stdout).get("comments", [])
        comments = []
        for comment in comments_data:
            author_data = comment.get("author", {})
            author_name = (
                author_data.get("login", "unknown")
                if isinstance(author_data, dict) else str(author_data)
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
    """Tree of the most recent issues (up to max_depth) with their comments."""
    recent_issues = sorted(issues, key=lambda x: x.number, reverse=True)[:max_depth]
    lines = []
    for i, issue in enumerate(recent_issues):
        is_last_issue = i == len(recent_issues) - 1
        current_prefix = "└── " if is_last_issue else "├── "
        lines.append(current_prefix + f"#{issue.number}: {issue.title} [{issue.state}]")

        comments = fetch_issue_comments(repo, issue.number, env)
        if comments:
            next_prefix = "    " if is_last_issue else "│   "
            for j, comment in enumerate(comments):
                is_last_comment = j == len(comments) - 1
                comment_prefix = "└── " if is_last_comment else "├── "
                lines.append(
                    f"{next_prefix}{comment_prefix}"
                    f"{comment.author} ({comment.created_at}): "
                    f"{comment.body[:80]}{'...' if len(comment.body) > 80 else ''}"
                )

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


def fetch_tree_contents(repo: str, path: str, env: dict, token: str) -> list | None:
    """Recursively fetch repository contents as a tree."""
    try:
        api_path = f"repos/{repo}/contents/{path}" if path else f"repos/{repo}/contents"
        result = _run(
            ["gh", "api", api_path, "--jq",
             "[.[] | {name: .name, type: .type, path: .path}]"],
            env,
        )
        if result.returncode != 0:
            error_msg = result.stderr.strip() if result.stderr else "Unknown error"
            loc = f"{repo}{f'/{path}' if path else ''}"
            if "429" in error_msg or "too many requests" in error_msg.lower():
                print(f"Debug: Rate limited on {loc}: {error_msg}", file=sys.stderr)
            elif "404" in error_msg or "not found" in error_msg.lower():
                print(f"Debug: Not found {loc}: {error_msg}", file=sys.stderr)
            else:
                print(f"Debug: API error on {loc}: {error_msg}", file=sys.stderr)
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
                tree_item["children"] = fetch_tree_contents(repo, item.get("path", ""), env, token)
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
    with_dates: bool = False,
) -> int:
    """List contents of a repository or fetch a specific file."""
    env = build_gh_env(token)

    try:
        if show_tree:
            tree_data = fetch_tree_contents(repo, "", env, token)
            if tree_data is None:
                _diagnose_contents_failure(repo, env)
                return 1
            tree_data.sort(key=lambda x: (x["type"] != "dir", x["name"]))
            print(repo)
            print(build_tree(tree_data))
            return 0

        if path:
            return _contents_path(repo, path, env, output_format)

        return _contents_root(repo, env, output_format, with_dates=with_dates)

    except subprocess.TimeoutExpired:
        print(f"Error: gh command timed out after {SUBPROCESS_TIMEOUT} seconds", file=sys.stderr)
        return 1


def _diagnose_contents_failure(repo: str, env: dict[str, str]) -> None:
    """Emit a more actionable error when a tree fetch fails."""
    check_result = _run(
        ["gh", "api", f"repos/{repo}", "--jq",
         "{name: .name, is_archived: .archived, visibility: .visibility}"],
        env,
    )
    if check_result.returncode == 0:
        try:
            repo_info = json.loads(check_result.stdout)
            print(f"Error: Could not fetch repository contents for {repo}", file=sys.stderr)
            print(
                f"       Repo exists (name: {repo_info.get('name')}, "
                f"archived: {repo_info.get('is_archived')}, "
                f"visibility: {repo_info.get('visibility')})",
                file=sys.stderr,
            )
            print("       Check rate limits: gh api rate_limit", file=sys.stderr)
            return
        except json.JSONDecodeError:
            pass

    error_msg = check_result.stderr.strip() if check_result.stderr else "Unknown error"
    print(f"Error: Could not fetch repository contents for {repo}", file=sys.stderr)
    if "404" in error_msg:
        print("       Repository not found or not accessible", file=sys.stderr)
    elif "401" in error_msg:
        print("       Authentication failed - check your GitHub token", file=sys.stderr)
    elif "429" in error_msg or "too many requests" in error_msg.lower():
        print("       Rate limited - wait a few minutes and retry", file=sys.stderr)
        print("       Check quota: gh api rate_limit", file=sys.stderr)
    else:
        print(f"       Details: {error_msg}", file=sys.stderr)


def _contents_path(repo: str, path: str, env: dict[str, str], output_format: str) -> int:
    """Fetch a single file's contents or list a sub-directory."""
    result = _run(["gh", "api", f"repos/{repo}/contents/{path}"], env)
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
        if data.get("encoding", "utf-8") == "base64":
            try:
                content = base64.b64decode(content).decode("utf-8")
            except Exception as exc:
                print(f"Error: Failed to decode file content: {exc}", file=sys.stderr)
                return 1
        print(content, end="")
        return 0

    if isinstance(data, list):
        contents = [
            RepoContent(
                name=item.get("name", ""),
                type=item.get("type", ""),
                size=item.get("size", 0),
                path=item.get("path", ""),
            )
            for item in data
        ]
        contents.sort(key=lambda x: (x.type != "dir", x.name))
        headers = ["name", "type", "size", "path"]
        rows = [[c.name, c.type, c.size, c.path] for c in contents]
        emit(headers, rows, output_format)
        return 0

    print("Error: Unexpected response format", file=sys.stderr)
    return 1


def _contents_root(repo: str, env: dict[str, str], output_format: str, with_dates: bool = False) -> int:
    """List the repository root.

    By default this is a single API call. With with_dates=True it also resolves
    each file's last-commit date, which costs one commits API call per file
    (N+1) and is slow and rate-limit heavy on large repos.
    """
    result = _run(
        ["gh", "api", f"repos/{repo}/contents", "--jq",
         "[.[] | {name: .name, type: .type, size: .size, path: .path}]"],
        env,
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
        last_updated = ""
        file_path = item.get("path", "")
        if with_dates and file_path:
            try:
                commit_result = _run(
                    ["gh", "api", f"repos/{repo}/commits?path={file_path}&per_page=1",
                     "--jq", ".[0].commit.committer.date"],
                    env,
                    timeout=30,
                )
                if commit_result.returncode == 0 and commit_result.stdout.strip():
                    date_str = commit_result.stdout.strip().strip('"')
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
    if with_dates:
        headers = ["name", "type", "size", "path", "last_updated"]
        rows = [[c.name, c.type, c.size, c.path, c.last_updated] for c in contents]
    else:
        headers = ["name", "type", "size", "path"]
        rows = [[c.name, c.type, c.size, c.path] for c in contents]
    emit(headers, rows, output_format)
    return 0


def cmd_repo_branches(
    repo: str,
    token: str,
    name_filter: str | None = None,
    output_format: str = "table",
) -> int:
    """List branches for a repository and identify the default branch."""
    env = build_gh_env(token)

    try:
        repo_data = run_gh_command(["gh", "api", f"repos/{repo}"], env=env)
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
                ["gh", "api", f"repos/{repo}/branches?per_page={per_page}&page={page}"],
                env=env,
            )
            if not isinstance(page_data, list):
                print("Error: Unexpected response format from gh api branches", file=sys.stderr)
                return 1

            for item in page_data:
                name = str(item.get("name", ""))
                if not name:
                    continue
                if name_filter and name_filter.lower() not in name.lower():
                    continue
                commit = item.get("commit", {})
                commit_sha = str(commit.get("sha", "")) if isinstance(commit, dict) else ""
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
        headers = ["name", "default", "protected", "commit_sha"]
        rows = [
            [b.name, "yes" if b.is_default else "no",
             "yes" if b.is_protected else "no", b.commit_sha]
            for b in branches
        ]
        emit(headers, rows, output_format)
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

    Default mode shows top-level commit info for recent commits; verbose mode
    shows full SHA and full multi-line commit message.
    """
    env = build_gh_env(token)

    try:
        if limit < 1:
            print("Error: --limit must be >= 1", file=sys.stderr)
            return 1

        commits: list[RepoCommit] = []
        page = 1
        per_page = 100
        while len(commits) < limit:
            page_data = run_gh_command(
                ["gh", "api",
                 f"repos/{repo}/commits?sha={branch}&per_page={per_page}&page={page}"],
                env=env,
            )
            if not isinstance(page_data, list):
                print("Error: Unexpected response format from gh api commits", file=sys.stderr)
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
                if len(commits) >= limit:
                    break

            if len(page_data) < per_page:
                break
            page += 1

        headers = ["sha", "author", "date", "message", "url"]
        if output_format == "csv":
            rows = [[c.sha, c.author, c.date, c.message, c.url] for c in commits]
        else:
            rows = [
                [c.sha if verbose else c.sha[:12], c.author, c.date,
                 c.message.replace("\n", " | ") if verbose else c.message, c.url]
                for c in commits
            ]
        emit(headers, rows, output_format)
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
    """Inspect or change branch protection: disable / restore / current / cached."""
    try:
        parts = repo.split("/")
        if len(parts) != 2:
            print(f"Invalid repo format: {repo}", file=sys.stderr)
            return 1
        org, repo_name = parts
        metadata = f"org: {org}, repo: {repo_name}, branch: {branch}"

        if operation == "disable":
            protection_ops.disable_branch_protection(
                GITHUB_API_BASE, org, repo_name, branch, token, org
            )

        elif operation == "restore":
            cached_protection = protection_ops.get_latest_protection_for_branch(
                org, org, repo_name, branch
            )
            if not cached_protection:
                print(f"Invalid cached protection for {metadata}", file=sys.stderr)
                return 1
            protection_data = protection_ops.transform_branch_protection_cache(cached_protection)
            if not protection_data:
                print(f"Invalid protection data object for {metadata}", file=sys.stderr)
                return 1
            protection_ops.restore_branch_protection(
                GITHUB_API_BASE, org, repo_name, branch, token, protection_data
            )

        elif operation == "current":
            current_protection = protection_ops.get_branch_protection(
                GITHUB_API_BASE, org, repo_name, branch, token
            )
            if not current_protection:
                print(f"Invalid protection data object for {metadata}", file=sys.stderr)
                return 1
            print(json.dumps(current_protection, indent=2))

        elif operation == "cached":
            cached_protection = protection_ops.get_latest_protection_for_branch(
                org, org, repo_name, branch
            )
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
    token: str,
) -> int:
    """Clone a branch shallowly, git-revert a commit, and push the revert."""
    env = build_git_auth_env(token)
    env["GIT_AUTHOR_EMAIL"] = "veracode@users.noreply.github.com"
    env["GIT_AUTHOR_NAME"] = "veracode-workflow-rollout-helper"
    # git revert creates a commit, which needs a committer identity too.
    env["GIT_COMMITTER_EMAIL"] = env["GIT_AUTHOR_EMAIL"]
    env["GIT_COMMITTER_NAME"] = env["GIT_AUTHOR_NAME"]

    temp_git_worktree = tempfile.mkdtemp(prefix="veracode-revert-")
    try:
        # Bare URL: auth is supplied via http.extraheader from the environment,
        # so the token is never written into .git/config or the process args.
        git_url = f"https://github.com/{repo}.git"
        run_git_command(
            ["git", "clone", "--branch", branch,
             "--single-branch", "--depth", "15", git_url, temp_git_worktree],
            env,
        )
        print(f"cloned repository with repo: {repo}, branch: {branch}, directory: {temp_git_worktree}")

        run_git_command(
            ["git", "-C", temp_git_worktree, "revert", "--no-edit", sha], env
        )
        print(f"reverted commit {sha}")

        run_git_command(
            ["git", "-C", temp_git_worktree, "push", "origin", branch], env
        )
        print("pushed revert to origin")
        return 0

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        shutil.rmtree(temp_git_worktree, ignore_errors=True)


# --------------------------------------------------------------------------- #
# YAML merge support (repo-write-file --operation merge)
# --------------------------------------------------------------------------- #
yaml = YAML()
yaml.preserve_quotes = True
yaml.default_flow_style = False
yaml.indent(mapping=2, sequence=4, offset=2)
yaml.width = 2**32


def merge_lists_by_name(source_list: list, destination_list: list) -> None:
    """Merge source list into destination, matching dict items by their 'name' key.

    Items without a 'name' key, or non-dict lists, replace the destination list
    entirely. Modifies destination_list in place.
    """
    if not source_list or not all(isinstance(item, dict) for item in source_list):
        destination_list.clear()
        destination_list.extend(source_list)
        return

    if not all("name" in item for item in source_list):
        destination_list.clear()
        destination_list.extend(source_list)
        return

    for source_item in source_list:
        source_name = source_item.get("name")
        dest_item = next(
            (item for item in destination_list
             if isinstance(item, dict) and item.get("name") == source_name),
            None,
        )
        if dest_item is not None:
            merge_yaml_dicts(source_item, dest_item)
        else:
            destination_list.append(source_item)


def merge_yaml_dicts(source: dict, destination: dict) -> None:
    """Recursively merge source keys into destination, in place.

    Lists of dicts with 'name' keys are merged by name rather than replaced.
    Note: multi-line comments on replaced scalars may be lost (ruamel limitation).
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
    if not options:
        options = {}
    string_stream = io.StringIO()
    yaml.dump(obj, string_stream, **options)
    output_str = string_stream.getvalue()
    string_stream.close()
    return output_str


def upsert_yaml_keys(source_content: str, remote_content: str) -> str:
    source_file_yml = yaml.load(source_content)
    remote_file_yml = yaml.load(remote_content)
    merge_yaml_dicts(source_file_yml, remote_file_yml)  # remote holds merged content
    return obj_to_yml_str(remote_file_yml)


def _is_not_found(stderr: str) -> bool:
    """True if a gh api error indicates the resource does not exist (HTTP 404)."""
    s = (stderr or "").lower()
    return "404" in s or "not found" in s


def _install_termination_guard() -> dict:
    """Convert SIGTERM/SIGHUP into KeyboardInterrupt so finally blocks still run.

    Returns the previous handlers for later restoration. No-op off the main
    thread, where signal.signal is not allowed. SIGINT already raises
    KeyboardInterrupt by default; SIGKILL cannot be intercepted.
    """
    def _raise(signum, _frame):
        raise KeyboardInterrupt(f"received signal {signum}")

    handlers: dict = {}
    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            handlers[sig] = signal.signal(sig, _raise)
        except (ValueError, OSError):
            pass
    return handlers


def _restore_handlers(handlers: dict) -> None:
    for sig, handler in handlers.items():
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass


def cmd_repo_write_file(
    repo: str,
    branch: str,
    destination_file_path: str,
    operation: str,
    token: str,
    source_file_path: str | None = None,
    commit_message: str | None = None,
) -> int:
    """Write, merge, or delete a file in a repository via the GitHub API.

    Operations:
      overwrite - create the file, or replace it if it already exists
      merge     - merge YAML content into the existing file (or create it)
      delete    - remove the file

    Branch protection and repo/org rulesets are disabled around the write and
    restored in the finally block. SIGTERM/SIGINT/SIGHUP during the window is
    converted into an exception so the restore still runs; only an unblockable
    hard kill (SIGKILL) can leave protections off.
    """
    env = build_gh_env(token)

    org_rulesets_disabled = None
    repo_rulesets_disabled = None
    branch_protection_disabled = None
    encountered_error = False

    parts = repo.split("/")
    if len(parts) != 2:
        print(f"Invalid repo format: {repo}", file=sys.stderr)
        return 1
    org, repo_name = parts

    prev_handlers = _install_termination_guard()
    try:
        try:
            api_endpoint = f"repos/{org}/{repo_name}/contents/{destination_file_path}"

            get_result = _run(["gh", "api", "-X", "GET", api_endpoint], env)
            if get_result.returncode == 0:
                try:
                    get_data = json.loads(get_result.stdout)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"Could not parse contents response: {exc}")
                if not isinstance(get_data, dict):
                    raise ValueError("Unexpected response format from contents GET")
                get_sha = get_data.get("sha")
            elif _is_not_found(get_result.stderr):
                get_data, get_sha = {}, None  # file does not exist yet -> create
            else:
                raise ValueError(
                    f"Failed to read {destination_file_path}: {get_result.stderr.strip()}"
                )

            try:
                if not cmd_repo_branch_protection(repo, branch, token, "disable"):
                    branch_protection_disabled = True
                print(f"{repo}@{branch}: branch protection disabled: {branch_protection_disabled}")
            except Exception as e:
                print(f"{repo}@{branch}: failed to disable branch protection: {e}")

            repo_rulesets_disabled = protection_ops.disable_repository_rulesets(
                GITHUB_API_BASE, org, repo_name, token, None
            )
            if repo_rulesets_disabled:
                print(f"{repo}: repository rulesets disabled: {repo_rulesets_disabled}")
            org_rulesets_disabled = protection_ops.disable_org_rulesets(
                GITHUB_API_BASE, org, token, None
            )
            if org_rulesets_disabled:
                print(f"{org}: org rulesets disabled: {org_rulesets_disabled}")

            if operation == "delete":
                if not get_sha:
                    raise ValueError(f"Cannot delete {destination_file_path}: file does not exist")
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

            elif operation in ("overwrite", "merge"):
                if not source_file_path:
                    raise ValueError(f"Error: --source-file is required for {operation} operation")
                source_path = Path(source_file_path)
                if not source_path.exists():
                    raise ValueError(f"Error: file {source_path} does not exist")

                source_content = source_path.read_text()
                if get_sha:
                    existing_content = base64.b64decode(get_data.get("content", "")).decode("utf-8")
                    final_content = (
                        upsert_yaml_keys(source_content=source_content, remote_content=existing_content)
                        if operation == "merge" else source_content
                    )
                    action_label = "Updated"
                else:
                    final_content = source_content  # new file: nothing to merge into
                    action_label = "Created"

                encoded_content = base64.b64encode(final_content.encode("utf-8")).decode("utf-8")
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

        except Exception as exc:
            print(f"Error: {exc}", file=sys.stderr)
            encountered_error = True
        finally:
            if branch_protection_disabled:
                cmd_repo_branch_protection(repo, branch, token, "restore")
                print(f"{repo}@{branch}: branch protection restored")
            if repo_rulesets_disabled:
                protection_ops.restore_repository_rulesets(
                    GITHUB_API_BASE, org, repo_name, token, repo_rulesets_disabled, None
                )
                print(f"{repo}: repository rulesets restored")
            if org_rulesets_disabled:
                protection_ops.restore_org_rulesets(
                    GITHUB_API_BASE, org, token, org_rulesets_disabled, None
                )
                print(f"{org}: org rulesets restored")
    except KeyboardInterrupt:
        print("Interrupted: protections were restored before exit.", file=sys.stderr)
        encountered_error = True
    finally:
        _restore_handlers(prev_handlers)

    return 1 if encountered_error else 0


# --------------------------------------------------------------------------- #
# Argument parsing / dispatch
# --------------------------------------------------------------------------- #
def _add_csv_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--csv", dest="output_format", action="store_const",
        const="csv", default="table", help="Output as CSV",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="GitHub Workflow CLI - Query workflows and logs"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    p = subparsers.add_parser("org-actions-permissions", help="View Actions permissions for an org")
    p.add_argument("--org", required=True, help="Organization name")

    subparsers.add_parser("token-info", help="Show info about the GitHub token being used")

    p = subparsers.add_parser("orgs", help="List orgs the token can reach (single vs multi-org check)")
    _add_csv_flag(p)

    p = subparsers.add_parser("org-app", help="View settings for a GitHub app in an org")
    p.add_argument("--org", required=True, help="Organization name")
    p.add_argument("--name", required=True, help="App name (e.g., veracode-workflow-app, slack)")

    p = subparsers.add_parser("org-apps", help="List GitHub apps installed in an org")
    p.add_argument("--org", required=True, help="Organization name")
    p.add_argument("--name", help="Filter by app name (case-insensitive substring)")
    _add_csv_flag(p)

    p = subparsers.add_parser("org-rulesets", help="View or modify org rulesets")
    p.add_argument("--org", required=True, help="Organization name")
    p.add_argument("--ruleset-id", help="Ruleset ID to view a specific ruleset")
    p.add_argument("--modify-ruleset-enforcement", help="Update ruleset enforcement state",
                   choices=["active", "disabled", "evaluate"])

    p = subparsers.add_parser("repos", help="List repositories")
    p.add_argument("--org", required=True, help="Organization name")
    p.add_argument("--name", help="Filter by repository name (case-insensitive substring)")
    _add_csv_flag(p)

    p = subparsers.add_parser("workflows", help="List workflow runs")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--status", choices=["queued", "in_progress", "completed"], help="Filter by status")
    p.add_argument("--conclusion", help="Filter by conclusion (comma-separated: success,failure,cancelled,skipped)")
    p.add_argument("--name", help="Filter by workflow name (case-insensitive substring)")
    p.add_argument("--name-break", help="Exit pagination on name match", action=argparse.BooleanOptionalAction)
    p.add_argument("--limit", type=int, default=10000, help="Maximum number of runs to list (default: 10000)")
    _add_csv_flag(p)

    p = subparsers.add_parser("run", help="View details of a specific workflow run")
    p.add_argument("--id", type=int, required=True, help="Workflow run ID (the 'id' column from workflows)")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")

    p = subparsers.add_parser("logs", help="Fetch workflow logs")
    p.add_argument("--run-id", type=int, required=True, help="Workflow run ID (the 'id' column from workflows)")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")

    p = subparsers.add_parser("issues", help="List issues")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--state", choices=["open", "closed"], help="Filter by state")
    p.add_argument("--limit", type=int, default=10000, help="Maximum number of issues to list (default: 10000)")
    p.add_argument("--tree", action="store_true", help="Show issues as a tree with comments")
    _add_csv_flag(p)

    p = subparsers.add_parser("issue-create", help="Create a new issue")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--title", required=True, help="Issue title")
    p.add_argument("--body", help="Issue body/description")
    p.add_argument("--assignee", help="Username to assign the issue to")
    p.add_argument("--labels", help="Comma-separated list of labels")

    p = subparsers.add_parser("issue", help="View a specific issue")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--number", type=int, required=True, help="Issue number")

    p = subparsers.add_parser("contents", help="List repo contents or fetch a file")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--path", help="File path to fetch (e.g., README.md, src/main.py)")
    p.add_argument("--tree", action="store_true", help="Show full tree of all files and directories")
    p.add_argument("--with-dates", action="store_true",
                   help="Add a last-commit date per file (one extra API call per file; slow on large repos)")
    _add_csv_flag(p)

    p = subparsers.add_parser("repo-branches", help="List repository branches")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--name", help="Filter by branch name (case-insensitive substring)")
    _add_csv_flag(p)

    p = subparsers.add_parser("repo-commits", help="List commit history for a branch")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--branch", required=True, help="Branch name (e.g., main, develop, release/v1)")
    p.add_argument("--limit", type=int, default=10, help="Maximum number of commits to list (default: 10)")
    p.add_argument("--verbose", action="store_true", help="Show full SHA and full commit message/body")
    _add_csv_flag(p)

    p = subparsers.add_parser("repo-actions-permissions", aliases=["rap"],
                              help="View or update Actions permissions for a repo")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--enable", action="store_true", help="Enable GitHub Actions for the repository")
    p.add_argument("--disable", action="store_true", help="Disable GitHub Actions for the repository")
    _add_csv_flag(p)

    p = subparsers.add_parser("repo-branch-protection", help="Manage branch protection")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--branch", required=True, help="Branch name")
    p.add_argument("--operation", required=True, help="Branch protection operation",
                   choices=["disable", "restore", "current", "cached"])

    p = subparsers.add_parser("repo-write-file", help="Write, merge, or delete a file in a repo")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--branch", required=True, help="Branch name")
    p.add_argument("--destination-file", required=True, help="File path (relative to repo root)")
    p.add_argument("--operation", required=True, help="File operation", choices=["merge", "overwrite", "delete"])
    p.add_argument("--source-file", help="Local file content (required for merge/overwrite)")
    p.add_argument("--message", help="Custom commit message")

    p = subparsers.add_parser("repo-revert-commit", help="Revert a repo commit")
    p.add_argument("--repo", required=True, help="Repository (org/repo format)")
    p.add_argument("--branch", required=True, help="Branch (main/master/develop/etc.)")
    p.add_argument("--sha", required=True, help="Commit SHA")

    return parser


def main() -> int:
    """Main entry point."""
    load_env_file()
    args = build_parser().parse_args()

    try:
        token = get_token()
    except (ValueError, SystemExit) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if args.command == "org-actions-permissions":
        return cmd_org_actions_permissions(args.org, token)
    if args.command == "repos":
        return cmd_repos(args.org, token, name_filter=args.name, output_format=args.output_format)
    if args.command == "token-info":
        return cmd_token_info(token)
    if args.command == "orgs":
        return cmd_orgs(token, output_format=args.output_format)
    if args.command == "org-app":
        return cmd_org_app_view(args.org, args.name, token)
    if args.command == "org-apps":
        return cmd_org_apps(args.org, token, name_filter=args.name, output_format=args.output_format)
    if args.command == "workflows":
        return cmd_workflows(
            args.repo, token, status=args.status, conclusion=args.conclusion,
            name_filter=args.name, limit=args.limit, output_format=args.output_format,
            name_filter_break=args.name_break,
        )
    if args.command == "run":
        return cmd_run_view(args.id, token, repo=args.repo)
    if args.command == "logs":
        return cmd_logs(args.run_id, token, repo=args.repo)
    if args.command == "issues":
        return cmd_issues(
            args.repo, token, state=args.state, limit=args.limit,
            output_format=args.output_format, show_tree=args.tree,
        )
    if args.command == "issue-create":
        return cmd_issue_create(
            args.repo, token, title=args.title, body=args.body,
            assignee=args.assignee, labels=args.labels,
        )
    if args.command == "issue":
        return cmd_issue_view(args.repo, args.number, token)
    if args.command == "contents":
        return cmd_contents(
            args.repo, token, path=args.path,
            show_tree=args.tree, output_format=args.output_format,
            with_dates=args.with_dates,
        )
    if args.command == "repo-branches":
        return cmd_repo_branches(args.repo, token, name_filter=args.name, output_format=args.output_format)
    if args.command == "repo-commits":
        return cmd_repo_commits(
            args.repo, args.branch, token,
            limit=args.limit, verbose=args.verbose, output_format=args.output_format,
        )
    if args.command == "repo-branch-protection":
        return cmd_repo_branch_protection(args.repo, args.branch, token, args.operation)
    if args.command == "repo-write-file":
        return cmd_repo_write_file(
            args.repo, args.branch, destination_file_path=args.destination_file,
            operation=args.operation, source_file_path=args.source_file, token=token,
            commit_message=args.message,
        )
    if args.command == "repo-revert-commit":
        return cmd_repo_revert_commit(args.repo, args.branch, args.sha, token)
    if args.command == "org-rulesets":
        return cmd_org_rulesets(args.org, token, args.ruleset_id, args.modify_ruleset_enforcement)
    if args.command in ("repo-actions-permissions", "rap"):
        return cmd_repo_actions_permissions(
            args.repo, token, output_format=args.output_format,
            enable=args.enable, disable=args.disable,
        )

    print(f"Unknown command: {args.command}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
