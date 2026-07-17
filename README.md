# GitHub Workflow CLI and Veracode Triage Helpers

Operator tooling for running and fixing the Veracode workflow integration
across GitHub organizations. The CLI wraps `gh` and the GitHub REST API for
querying and remediating workflows, repos, issues, and protection settings.
The helpers drive the CLI to produce fleet-wide, root-cause triage reports for
SAST and SCA runs.

| Path | What it is |
|:--|:--|
| `github-workflow-cli.py` | Single-file CLI. Read and mutate commands for orgs, repos, workflow runs, logs, issues, contents, branches, commits, Actions permissions, rulesets, and branch protection. |
| `helpers/bulk-sast-analyzer.py` | Bulk triage for "Static Code Analysis" runs. Classifies root causes and writes Markdown, CSV, and JSON reports. |
| `helpers/bulk-sca-analyzer.py` | Bulk triage for agent-based "Software Composition Analysis" runs. Separates operational failures from severity gate failures and extracts scan intelligence. |

## Quick start

```bash
export GITHUB_TOKEN=ghp_xxx
python github-workflow-cli.py token-info      # who am I, which scopes
python github-workflow-cli.py orgs            # which orgs the token covers
python helpers/bulk-sast-analyzer.py          # SAST triage, all reachable orgs
python helpers/bulk-sca-analyzer.py           # SCA triage, all reachable orgs
```

## Requirements

| Requirement | Needed for | Notes |
|:--|:--|:--|
| Python 3.12+ | Everything | Uses PEP 701 nested-quote f-strings. |
| `gh` on PATH | Everything | All GitHub access goes through `gh`. |
| `git` 2.31+ on PATH | `repo-revert-commit` | Env-injected auth requires 2.31+. |
| `ruamel.yaml` | `repo-write-file --operation merge` only | Optional import; every other command runs without it. |
| Internal `enable_debug` module (`protection_ops`) | Branch protection, rulesets, `repo-write-file` | Optional import; read commands never need it. Missing module produces a clear error only when those commands are invoked. |

## Authentication

One token authenticates every command and helper, read from `GITHUB_TOKEN`,
then `GH_TOKEN` if that is unset. A local `.env` file is loaded without
overriding variables already set in the environment. The token can be a
tenant-wide installation/admin token or a personal access token; whatever it
is authorized for is what the tooling can reach.

`orgs` answers whether a token is scoped to one org or several: it lists every
reachable org and prints a Single-org / Multi-org verdict (sent to stderr in
`--csv` mode so pipes stay machine-parseable). It falls back to membership
listing when `/user/orgs` returns nothing.

## CLI command reference

All list commands print a table by default and CSV with `--csv`. CSV column
order is fixed; the bulk recipes below rely on it.

### Read commands

| Command | Purpose | Key flags |
|:--|:--|:--|
| `orgs` | List every org the token reaches, with a scope verdict | `--csv` |
| `token-info` | Authenticated user and token scopes. Run first when anything returns 403/404 | |
| `repos --org ORG` | Non-archived repos in an org | `--name SUBSTR`, `--csv` |
| `workflows --repo ORG/REPO` | Workflow runs. `--status` filters server-side; `--conclusion` and `--name` filter locally. `--name-break` stops paginating once a page matched, which makes org-wide discovery fast | `--status`, `--conclusion a,b`, `--name SUBSTR`, `--name-break`, `--limit N`, `--csv` |
| `run --repo ORG/REPO --id RUN_ID` | Metadata for one run | |
| `logs --repo ORG/REPO --run-id RUN_ID` | Complete per-job run log, no `gh` truncation | `--relevant-only`, `--exclude-cleanup`, `--manifest FILE` |
| `issues --repo ORG/REPO` | List issues | `--state`, `--tree`, `--csv` |
| `issue --repo ORG/REPO --number N` | One issue with comments | |
| `contents --repo ORG/REPO` | Repo tree or file contents | `--path P`, `--tree`, `--with-dates`, `--csv` |
| `repo-branches --repo ORG/REPO` | Branches with default/protected flags | `--name SUBSTR`, `--csv` |
| `repo-commits --repo ORG/REPO --branch B` | Commit history | `--limit N`, `--verbose`, `--csv` |
| `org-apps --org ORG` | GitHub apps installed in the org | `--name SUBSTR`, `--csv` |
| `org-app --org ORG --name APP` | One app's settings | |
| `org-actions-permissions --org ORG` | Org-level Actions permissions | |
| `repo-actions-permissions --repo ORG/REPO` | Repo-level Actions permissions (alias `rap`) | `--csv` |
| `org-rulesets --org ORG` | Org rulesets | `--ruleset-id ID` |

Notes on `logs`: `--relevant-only` keeps the Veracode SAST pipeline jobs
(Validations, build, package, artifact, upload, prescan, scan, policy,
results) plus cleanup; `--exclude-cleanup` drops cleanup and registration
jobs; `--manifest` writes the discovered job names (`sast_jobs`,
`cleanup_jobs`, line counts) to JSON so downstream tooling never re-derives
them. For SCA runs fetch the full log without `--relevant-only`; SCA job names
do not match the SAST pipeline patterns.

### Mutate commands

| Command | Purpose | Key flags |
|:--|:--|:--|
| `repo-write-file --repo ORG/REPO --branch B --destination-file PATH --operation merge or overwrite or delete` | Write, YAML-merge, or delete a file via the API. `overwrite` creates the file if absent. `merge` deep-merges YAML; lists of dicts merge by `name` key (requires `ruamel.yaml`) | `--source-file LOCAL`, `--message MSG` |
| `repo-revert-commit --repo ORG/REPO --branch B --sha SHA` | Clone shallow, revert, push | |
| `repo-branch-protection --repo ORG/REPO --branch B --operation ...` | `disable`, `restore` (from cache), `current`, `cached` | |
| `repo-actions-permissions --repo ORG/REPO --enable or --disable` | Toggle Actions on a repo | |
| `org-rulesets --org ORG --ruleset-id ID --modify-ruleset-enforcement ...` | Set ruleset enforcement: `active`, `disabled`, `evaluate` | |
| `issue-create --repo ORG/REPO --title T` | Create an issue (also the scan trigger mechanism) | `--body B`, `--assignee U`, `--labels a,b` |

### Exit codes

| Code | Meaning |
|:--|:--|
| 0 | Success |
| 1 | Command error (API failure, invalid input, missing optional module) |
| 2 | Usage error (argparse) |

## Bulk recipes

Fleet-wide shell recipes using only `--csv` output and standard shell. Set
once:

```bash
CLI="python github-workflow-cli.py"
ORG=my-org
export GITHUB_TOKEN=ghp_xxx
repos=$($CLI repos --org "$ORG" --csv | tail -n +2 | cut -d, -f1)
```

### 1. Org-wide Veracode failure report

All Veracode workflow runs happen in the org's central `veracode` repository;
the run name carries the scanned source repo (for example `Software
Composition Analysis - verademo`). One query per org is enough. The workflows
CSV is `number,id,name,status,conclusion,...`, so the run id is column 2.

```bash
$CLI workflows --repo "$ORG/veracode" \
     --conclusion failure,cancelled,timed_out --limit 200 --csv \
  > veracode-failures.csv
```

Filter to one scan type with `--name "Static Code Analysis"` or
`--name "Software Composition Analysis"`. For classified root-cause reports
instead of raw CSVs, use the helpers below; this recipe is the manual path.

### 2. Pull logs for every failed run

```bash
mkdir -p logs
tail -n +2 veracode-failures.csv | while IFS=, read -r num id rest; do
  $CLI logs --repo "$ORG/veracode" --run-id "$id" > "logs/${id}.log" 2>&1
done
```

### 3. Bulk-update the scan workflow (YAML merge)

Put only the keys you want to change in a local snippet, for example
`veracode-update.yml`:

```yaml
jobs:
  veracode:
    steps:
      - name: Veracode Scan
        with:
          fail_build: true
```

`--operation merge` recurses into maps and merges list items by their `name`
key, so existing steps and local edits are preserved. Detect each repo's
default branch first (branches CSV is `name,default,protected,commit_sha`):

```bash
for r in $repos; do
  def=$($CLI repo-branches --repo "$ORG/$r" --csv \
        | awk -F, '$2=="yes"{print $1; exit}')
  $CLI repo-write-file --repo "$ORG/$r" --branch "$def" \
       --destination-file .github/workflows/veracode.yml \
       --operation merge --source-file veracode-update.yml \
       --message "chore: update Veracode scan workflow" \
    || echo "$r" >> write-failures.txt
  sleep 2
done
```

Use `--operation overwrite --source-file veracode.yml` to force a known-good
file (it also creates the file if the repo does not have one yet), or
`--operation delete` (no source file) to offboard a repo.

### 4. Bulk revert a bad rollout commit

The rollout helper commits as `veracode-workflow-rollout-helper`. The commits
CSV is `sha,author,date,message,url`, so match on author (column 2, safe from
commas in the message) to find the SHA, then revert it.

```bash
for r in $repos; do
  def=$($CLI repo-branches --repo "$ORG/$r" --csv | awk -F, '$2=="yes"{print $1; exit}')
  sha=$($CLI repo-commits --repo "$ORG/$r" --branch "$def" --limit 20 --csv \
        | awk -F, '$2=="veracode-workflow-rollout-helper"{print $1; exit}')
  [ -n "$sha" ] && $CLI repo-revert-commit --repo "$ORG/$r" --branch "$def" --sha "$sha"
  sleep 2
done
```

### 5. Trigger a SAST scan on every repo

The Veracode workflow integration starts a static scan when an issue with the
agreed title is opened:

```bash
for r in $repos; do
  $CLI issue-create --repo "$ORG/$r" \
       --title "Veracode Baseline Scans" \
       --body "Veracode Static Scan" \
    || echo "$r" >> scan-trigger-failures.txt
  sleep 2
done
```

### 6. Fleet gating audit

Confirm scans actually gate merges. Actions-permissions CSV is
`repo,enabled,...` (enabled is column 2); branches CSV gives default and
protected.

```bash
echo "repo,actions_enabled,default_branch,branch_protected" > gating-audit.csv
for r in $repos; do
  en=$($CLI repo-actions-permissions --repo "$ORG/$r" --csv | tail -n +2 | cut -d, -f2)
  bl=$($CLI repo-branches --repo "$ORG/$r" --csv | awk -F, '$2=="yes"{print $1","$3; exit}')
  echo "$r,$en,$bl" >> gating-audit.csv
done
```

### 7. Run across multiple orgs

```bash
for ORG in $($CLI orgs --csv | tail -n +2 | cut -d, -f1); do
  echo "=== $ORG ==="
  # ... run a recipe here with $ORG ...
done
```

Tips: list before you mutate, append per-repo failures to a log and keep going
(`|| echo "$r" >> failures.txt`), add a `sleep` in loops, and check headroom
with `gh api rate_limit`.

## Triage helpers

Both helpers share one operating model: the Veracode workflows run only in
each organization's central workflow repository (default name `veracode`) and
scan the org's other repositories as sources, so a bare organization target
maps straight to `<org>/veracode`. No fleet-wide repo enumeration happens; one
discovery query per org.

### Shared flags

| Flag | Default | Purpose |
|:--|:--|:--|
| `--targets FILE` | auto-discover | One target per line, `org` or `org/repo`; `#` comments allowed. A bare `org` maps to `<org>/<workflow-repo>`. Without the flag, every org the token reaches is discovered via `orgs --csv`. |
| `--workflow-repo NAME` (alias `--repo`) | `veracode` | Central workflow repository name inside each org. Also labels logs re-analyzed with `--analyze-dir`. |
| `--limit N` | 200 | Workflow runs listed per repository during discovery, newest first. The central repo's run list is shared by all Veracode workflows, so keep this comfortably larger than `--runs-per-repo`. |
| `--last N` | | Sets `--no-failed-only` `--include-ok` `--max-age-days 0` `--runs-per-repo N` in one shot. |
| `--runs-per-repo N` | 10 | Runs whose logs are fetched and classified, per repository, chosen by the selection policy below. |
| `--max-age-days N` | 30 | Ignore matched runs older than this (0 disables). Keeps triage on current, re-triggerable failures instead of stale history. Runs with a missing timestamp are kept, never silently dropped. |
| `--failed-only` / `--no-failed-only` | on | Restrict discovery to `failure,cancelled,timed_out,action_required,startup_failure,stale`. `startup_failure` catches invalid workflow files that never start a job. Gate failures mark the run failed, so they are always included. |
| `--cli PATH` | `github-workflow-cli.py` | Path to the CLI. |
| `--python PATH` | current interpreter | Interpreter used to invoke the CLI. |
| `--output-dir DIR` | `workflow-output` | A timestamped `sast-bulk-*` or `sca-bulk-*` folder is created per invocation. Reports are written per org, never as one aggregate: `index.md` at the root plus `orgs/<org>/` folders each containing that org's summary, CSV, JSON, and raw run logs, plus `config-files/<org>/` when `--fetch-configs` is set. |
| `--analyze-dir DIR` | | Skip fetching; re-classify previously collected `*-sast-NNN.log` or `*-sca-NNN.log` files. No token needed. Ideal when iterating on rules. |
| `--include-ok` | off | Also report runs with no observed failure (SAST) or clean gate passes (SCA). |
| `--fetch-configs` | off | Opt in to also save each org's workflow config files from the workflow repo root under `config-files/<org>/` in the output folder. Missing files produce a note, never a failure. |
| `--config-file NAME` | `veracode.yml`, `repo-list.yml` | Config file to fetch; repeatable. Overrides the default list when given. Saved flat by base name inside the org folder. |
| `--fail-fast` | off | Stop on the first collection error instead of continuing. |

Helper exit codes: 0 all collection succeeded, 1 at least one discovery or log
fetch failed (findings are still written), 2 usage or environment error.

### Output layout (per org, not one big report)

Reports are generated per organization so each org's failures can be reviewed
and fixed in isolation, with a fleet `index.md` for navigation:

```
workflow-output/sast-bulk-<timestamp>/
  index.md                      # one row per org: runs, failures, top cause, link
  config-files/                 # only with --fetch-configs
    <org>/veracode.yml          # plus repo-list.yml when present
  orgs/
    <org>/
      sast-summary.md           # that org's triage report (sca-summary.md for SCA)
      sast-findings.csv
      sast-findings.json
      logs/                     # raw discovery and per-run logs for that org
```

Each `orgs/<org>/` folder is self-contained: the report, the machine outputs,
and the raw logs the classifications were derived from, so a single org folder
can be zipped and handed to that org's owners.

### Run selection (freshness guarantees)

Getting the latest, most actionable runs is the core of the helpers, so the
selection chain is defensive end to end:

| Layer | Guarantee |
|:--|:--|
| API ordering | Discovery requests `sort=created&order=desc` explicitly; newest-first is an API parameter, not an assumption. |
| Defensive re-sort | The helper re-sorts matched runs by created time, then run id, so it never depends on upstream output ordering. |
| Age gate | Runs older than `--max-age-days` (default 30) are dropped and counted, keeping the report about current, re-triggerable failures. Missing timestamps never cause a silent drop. |
| Coverage pass | Run names encode the scan target (`Software Composition Analysis - verademo`), so the newest run per distinct name is selected first: every still-failing target gets its latest failure into the quota before any target gets a second one. A single flapping repo cannot starve the rest. |
| Backfill pass | Remaining quota is filled with the next-newest runs overall, giving recent failure history for flapping targets. |
| Visibility | Every discovery prints `Runs: matched M, selected N, skipped K older than Xd`, plus explicit notes when nothing matched in the window (raise `--limit`) or everything matched was too old (raise `--max-age-days`). |

The helpers deliberately do not use the CLI's `--name-break` during discovery:
combined with a conclusion filter it stops at the first page containing any
match, which can skip a target whose latest failure sits one page deeper.

### Troubleshooting discovery failures

Discovery warnings always include the exit code, the first error line, a
targeted hint, and the path to the full discovery log. The common systematic
cases (every org failing the same way) are:

| Symptom in the warning | Cause | Fix |
|:--|:--|:--|
| `HTTP 404` / `Not Found` | The central workflow repo is not named `veracode` in your orgs | Set `--workflow-repo NAME`; find the name with `repos --org ORG --csv` |
| `HTTP 401` / `Bad credentials` | Token missing or invalid in the helper's shell | Export `GITHUB_TOKEN` in the same shell; verify with `token-info` |
| `HTTP 403` / rate limit | Scope, SSO authorization, or rate limiting | Authorize the token for SSO orgs; check `gh api rate_limit` |
| `Unable to run gh` | `gh` not on PATH for the helper's environment | Install `gh` or fix PATH |

### Runner detection

Both helpers detect the runner each run used from the Set up job block and
report it per finding, in a "Runner breakdown" section, and as columns in the
CSV/JSON.

| Field | Example | Notes |
|:--|:--|:--|
| `runner_image` | `ubuntu-24.04`, `windows-2022` | GitHub-hosted image. The logs contain the resolved image, not the literal `default:runs_on` label, so `windows-latest` appears as its current image. Multiple images in one run are joined with `;`. |
| `runner_os` | `linux`, `windows`, `macos` | Derived from the image or the Operating System block. |
| `runner_name` | `corp-linux-runner-7` | Self-hosted runner name; hosted runners leave this empty. |
| `runner_type` | `github-hosted`, `self-hosted`, `unknown` | Hosted detected via the provisioner markers; `unknown` when the log has no Set up job block. |

This makes failure classes that correlate with a runner choice jump out, for
example .NET targeting pack failures appearing only on one image after a
`default:runs_on` change.

### bulk-sast-analyzer.py

Triage for "Static Code Analysis" runs. Fetches only the SAST pipeline jobs
(`logs --relevant-only --manifest`) and classifies the root cause against a
signature rule set covering, among others:

| Category | Example codes |
|:--|:--|
| Veracode config | `VERACODE_AUTH`, `VERACODE_PERMISSION`, `INVALID_POLICY`, `APP_PROFILE_NOT_FOUND`, `SANDBOX_NOT_FOUND`, `SCAN_IN_PROGRESS` |
| Source access | `CHECKOUT_AUTH`, `SUBMODULE_FAILED`, `GIT_LFS_FAILED` |
| Dependency resolution | `NUGET_PRIVATE_FEED`, `NUGET_AUTH`, `MAVEN_DEPENDENCY`, `GRADLE_DEPENDENCY`, `NODE_DEPENDENCY`, `PYTHON_DEPENDENCY`, `GO_DEPENDENCY`, `RUBY_DEPENDENCY`, `PHP_DEPENDENCY` |
| Build and environment | `JAVA_BUILD`, `DOTNET_BUILD`, `DOTNET_TARGETING_PACK`, `TYPESCRIPT_BUILD`, `NATIVE_BUILD`, `TOOLCHAIN_SETUP_FAILED`, `DOCKER_PERMISSION`, `DISK_SPACE`, `OUT_OF_MEMORY`, `NETWORK_TLS` |
| Packaging and scan | `AUTOPACKAGER_UNSUPPORTED`, `AUTOPACKAGER_FAILED`, `NO_ARTIFACTS`, `UPLOAD_FAILED`, `ARCHIVE_TOO_LARGE`, `NO_MODULES`, `PRESCAN_MODULE_ERRORS`, `SCAN_TIMEOUT`, `PIPELINE_SCAN_FAILED`, `POLICY_SCAN_FAILED` |
| Gates working as intended | `POLICY_FAILED`, `PIPELINE_FINDINGS_GATE` |
| Workflow and runner | `WORKFLOW_INVALID`, `RUNNER_LOST`, `JOB_TIMEOUT`, `CONCURRENCY_CANCELED` |

Specific signatures always beat generic ones (priority ordering), so a
cancellation line never masks the real dependency error underneath it.

| Output (per org unless noted) | Contents |
|:--|:--|
| `index.md` (root) | Fleet index: runs, primary failure count, top cause, and a link per org. |
| `orgs/<org>/sast-summary.md` | That org's findings grouped by cause with run link, branch, timestamp, failing job, runner, pipeline progress, evidence line, and the concrete remediation. Cleanup failures sit in a "Secondary issues" section at the bottom and never mask the primary SAST cause. |
| `orgs/<org>/sast-findings.csv` / `.json` | Full field set per run, including stage statuses, runner fields, and log paths. |
| `orgs/<org>/logs/` | Raw discovery and per-run logs for that org, so classifications are auditable in place. |
| `config-files/<org>/` (with `--fetch-configs`) | Each org's `veracode.yml` and `repo-list.yml` (or the `--config-file` list) fetched from the workflow repo root. Cross-reference `default:runs_on` and thresholds against the failures in the same run folder. |

```bash
python helpers/bulk-sast-analyzer.py                         # all reachable orgs
python helpers/bulk-sast-analyzer.py --targets targets.txt   # explicit list
python helpers/bulk-sast-analyzer.py --analyze-dir logs/     # offline re-run
```

Unclassified failures surface as `UNCLASSIFIED_SAST_FAILURE` with their
evidence line; add a `Rule` entry for any recurring one so the classifier
keeps improving.

### bulk-sca-analyzer.py

Triage for agent-based "Software Composition Analysis" runs (run names look
like `Software Composition Analysis - <source repo>`). SCA differs from SAST
in one important way: a failed run is very often a successful scan that the
severity gate blocked, which is the control working, not an error. The report
is split accordingly.

| Section | What it contains |
|:--|:--|
| Operational failures | Grouped by cause: `SRCCLR_AUTH`, `SRCCLR_FORBIDDEN`, `AGENT_DOWNLOAD_FAILED`, `NO_SUPPORTED_PROJECTS`, `LOCKFILE_MISSING`, per-ecosystem graph resolution, `OUT_OF_MEMORY`, `DISK_SPACE`, `NETWORK_TLS`, fail-closed gate plumbing (`GATE_SCRIPT_MISSING`, `RESULTS_FILE_MISSING`), `RUNNER_LOST`, `CONCURRENCY_CANCELED`. |
| Severity gate failures | Scan intelligence extracted from the run log so remediation starts without opening the platform: threshold, findings at or above it, severity split (critical/high/medium/low), vulnerable vs total libraries with direct/transitive split, package managers, analysis time, the platform scan URL, and Update Advisor quick wins (library, safe version, breaking or not). |
| Secondary issues | Cleanup failures and non-actionable, passed, or collection-limited runs. |

It fetches the complete run log (no `--relevant-only`; SCA job names do not
match the SAST pipeline patterns) and writes the same per-org layout as the
SAST helper: a fleet `index.md` (with operational and gate failure counts per
org) plus `orgs/<org>/` folders containing `sca-summary.md`,
`sca-findings.csv`, `sca-findings.json`, and the raw logs, plus
`config-files/<org>/` when `--fetch-configs` is set. That puts the
resolved gate threshold from the logs and the configured
`break_build_severity_threshold` from `veracode.yml` side by side in one
output folder.

```bash
python helpers/bulk-sca-analyzer.py                          # all reachable orgs
python helpers/bulk-sca-analyzer.py --targets targets.txt --runs-per-repo 5
python helpers/bulk-sca-analyzer.py --analyze-dir logs/ --include-ok
```

If any org disables build-breaking on findings (`breakBuildOnPolicyFindings:
false`), those gate outcomes conclude success; sweep them with
`--no-failed-only --include-ok`. Unclassified failures surface as
`UNCLASSIFIED_SCA_FAILURE` with their evidence line; add a `Rule` entry for
any recurring one.

## Safety and limitations

| Area | Behavior |
|:--|:--|
| Protection windows | `repo-write-file` disables branch protection and repo/org rulesets for the duration of the write and restores them in a `finally` block. SIGTERM, SIGINT, and SIGHUP convert to a clean shutdown so the restore still runs; only an unblockable hard kill (SIGKILL) or host crash can leave protections off. The org ruleset toggle affects the whole org, so prefer a narrow blast radius and spot-check with `repo-branch-protection --operation current` afterward. |
| Multi-org cache partitioning | The `protection_ops` backup cache is keyed by org/repo/branch (org is passed as the namespace), so a token spanning multiple orgs is partitioned correctly. This depends on `protection_ops` honoring that namespace; confirm it on your build. |
| Token hygiene | `repo-revert-commit` authenticates with a bare clone URL and an `http.extraheader` injected via the environment (`GIT_CONFIG_*`, git 2.31+), so the token is never written into argv or the temp clone's `.git/config`. The temp dir is removed in a `finally` block. |
| Sensitive output | `logs` and `contents` print raw output that may contain build secrets. Treat report folders and fetched logs as sensitive artifacts. |
| API cost | `contents` is a single API call by default; `--with-dates` adds one call per file (N+1), so use it only on small repos or specific paths. Helper discovery is at most `ceil(--limit / 100)` paginated calls per org thanks to the central-repo model (two pages at the default 200). |
| Runner labels | Run logs contain the resolved runner image, not the literal `default:runs_on` label. The configured label is in the org's `veracode.yml`, which the helpers save under `config-files/<org>/` when run with `--fetch-configs`. |
