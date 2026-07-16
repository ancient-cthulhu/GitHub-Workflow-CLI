# GitHub Workflow CLI

A single-file CLI for querying and remediating GitHub Actions workflows, repos,
issues, and protection settings. It wraps the `gh` CLI and the GitHub REST API,
and is the operator surface for troubleshooting and bulk-fixing the Veracode
workflow integration. Target any org or repo per command with `--org` / `--repo`.

## Requirements

* Python 3.12+ (uses PEP 701 nested-quote f-strings).
* `gh` and `git` on `PATH` (git 2.31+, for env-injected auth in
  `repo-revert-commit`).
* Python package `ruamel.yaml` (only for `repo-write-file --operation merge`)
  and the internal `enable_debug` module providing `protection_ops` (only for
  branch-protection, ruleset, and `repo-write-file` commands). Both are optional
  imports; every read command works without them.

## Authentication

One GitHub token authenticates every command, read from `GITHUB_TOKEN`, or
`GH_TOKEN` if that is unset. It can be a tenant-wide token (org or enterprise
installation/admin token) or a personal access token; whatever it is authorized
for is what the CLI can reach. A local `.env` file is also loaded, without
overriding variables already set in the environment.

```bash
export GITHUB_TOKEN=ghp_xxx
python github-workflow-cli.py token-info     # user + scopes
python github-workflow-cli.py orgs           # which orgs the token covers
```

`orgs` answers whether a token is scoped to one org or several. It lists every
reachable org and prints a `Single-org` / `Multi-org` verdict.

## Commands

Read:

* `orgs [--csv]` lists every organization the token can reach and prints a
  Single-org / Multi-org verdict (verdict goes to stderr in CSV mode so pipes
  stay clean). Falls back to membership listing for tokens where `/user/orgs`
  returns nothing.
* `token-info` shows the authenticated user and token scopes. Run this first
  when anything returns 403/404.
* `repos --org ORG [--name SUBSTR] [--csv]` lists non-archived repos.
* `workflows --repo ORG/REPO [--status queued|in_progress|completed]
  [--conclusion a,b] [--name SUBSTR] [--name-break] [--limit N] [--csv]`.
  `--status` filters server-side; `--conclusion` and `--name` filter locally.
  `--name-break` stops paginating once a page produced name matches, which is
  what makes org-wide discovery fast.
* `run --repo ORG/REPO --id RUN_ID` shows one run's metadata.
* `logs --repo ORG/REPO --run-id RUN_ID [--relevant-only] [--exclude-cleanup]
  [--manifest FILE]` prints the complete per-job run log with no `gh` CLI
  truncation. `--relevant-only` keeps the Veracode SAST pipeline jobs
  (Validations/build/package/artifact/upload/prescan/scan/policy/results) plus
  cleanup; `--exclude-cleanup` drops cleanup and registration jobs; `--manifest`
  writes the discovered job names (`sast_jobs`, `cleanup_jobs`, counts) to a
  JSON file so downstream tooling never has to re-derive them. For SCA runs
  fetch the full log without `--relevant-only` (the SCA job names do not match
  the SAST pipeline patterns).
* `issues --repo ORG/REPO [--state ...] [--tree] [--csv]`,
  `issue --repo ORG/REPO --number N`.
* `contents --repo ORG/REPO [--path P] [--tree] [--with-dates] [--csv]`.
* `repo-branches --repo ORG/REPO [--name SUBSTR] [--csv]`,
  `repo-commits --repo ORG/REPO --branch B [--limit N] [--verbose] [--csv]`.
* `org-apps --org ORG [--name SUBSTR] [--csv]`, `org-app --org ORG --name APP`,
  `org-actions-permissions --org ORG`,
  `repo-actions-permissions --repo ORG/REPO` (alias `rap`),
  `org-rulesets --org ORG [--ruleset-id ID]`.

Mutate:

* `repo-write-file --repo ORG/REPO --branch B --destination-file PATH --operation merge|overwrite|delete [--source-file LOCAL] [--message MSG]`.
  `overwrite` creates the file if it does not exist yet; `merge` requires
  `ruamel.yaml` and deep-merges YAML (lists of dicts merge by `name` key).
* `repo-revert-commit --repo ORG/REPO --branch B --sha SHA`.
* `repo-branch-protection --repo ORG/REPO --branch B --operation disable|restore|current|cached`.
* `repo-actions-permissions --repo ORG/REPO --enable|--disable`.
* `org-rulesets --org ORG --ruleset-id ID --modify-ruleset-enforcement active|disabled|evaluate`.
* `issue-create --repo ORG/REPO --title T [--body B] [--assignee U] [--labels a,b]`.

All list commands print a table by default and CSV with `--csv`. CSV column order
is fixed, which is what the bulk recipes below rely on. Exit codes: 0 success,
1 command error, 2 usage error. Mutating commands that require the internal
`enable_debug` module fail with a clear error when it is absent; read commands
never need it.

## Bulk operations

These recipes run fleet-wide. They use only `--csv` output and standard shell, so
they are safe to adapt. Run them in `bash`. Set these once:

```bash
CLI="python github-workflow-cli.py"
ORG=my-org
export GITHUB_TOKEN=ghp_xxx
```

A reusable list of repo names for the org (CSV column 1 is `name`):

```bash
$CLI repos --org "$ORG" --csv > repos.csv
repos=$(tail -n +2 repos.csv | cut -d, -f1)
```

### 1. Org-wide Veracode failure report

All Veracode workflow runs happen in the org's central `veracode` repository
(the run name carries the scanned source repo, e.g. `Software Composition
Analysis - verademo`), so one query per org is enough. The workflows CSV is
`number,id,name,status,conclusion,...`, so the run id is column 2.

```bash
$CLI workflows --repo "$ORG/veracode" \
     --conclusion failure,cancelled,timed_out --limit 200 --csv \
  > veracode-failures.csv
```

Filter to one scan type with `--name "Static Code Analysis"` or
`--name "Software Composition Analysis"`. For classified root-cause reports
instead of raw CSVs, use the helpers below; this recipe is the manual path.

### 2. Pull logs for every failed run

`veracode-failures.csv` columns are `number,id,name,...`, so read the first two
fields and write one log file per run.

```bash
mkdir -p logs
tail -n +2 veracode-failures.csv | while IFS=, read -r num id rest; do
  $CLI logs --repo "$ORG/veracode" --run-id "$id" > "logs/${id}.log" 2>&1
done
```

### 3. Bulk-update the scan workflow (YAML merge)

Put just the keys you want to change in a local snippet, for example
`veracode-update.yml`:

```yaml
jobs:
  veracode:
    steps:
      - name: Veracode Scan
        with:
          fail_build: true
```

`--operation merge` recurses into maps and merges list items by their `name` key,
so existing steps and local edits are preserved. This detects each repo's default
branch first (branches CSV is `name,default,protected,commit_sha`):

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

Use `--operation overwrite --source-file veracode.yml` to force a known-good file
(it also creates the file if the repo does not have one yet), or
`--operation delete` (no source file) to offboard a repo.

### 4. Bulk revert a bad rollout commit

The rollout helper commits as `veracode-workflow-rollout-helper`. The commits CSV
is `sha,author,date,message,url`, so match on author (column 2, safe from commas
in the message) to find the SHA, then revert it.

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
agreed title is opened. Create it on every repo in the org:

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

Confirm scans actually gate merges. Actions-permissions CSV is `repo,enabled,...`
(enabled is column 2); branches CSV gives default and protected.

```bash
echo "repo,actions_enabled,default_branch,branch_protected" > gating-audit.csv
for r in $repos; do
  en=$($CLI repo-actions-permissions --repo "$ORG/$r" --csv | tail -n +2 | cut -d, -f2)
  bl=$($CLI repo-branches --repo "$ORG/$r" --csv | awk -F, '$2=="yes"{print $1","$3; exit}')
  echo "$r,$en,$bl" >> gating-audit.csv
done
```

### 7. Run across multiple orgs

If the token spans several orgs, loop over `orgs` (CSV column 1 is `org`) and
nest any recipe above:

```bash
for ORG in $($CLI orgs --csv | tail -n +2 | cut -d, -f1); do
  echo "=== $ORG ==="
  $CLI repos --org "$ORG" --csv > "repos-$ORG.csv"
  # ... run a recipe here with $ORG ...
done
```

Tips: list before you mutate, append per-repo failures to a log and keep going
(`|| echo "$r" >> failures.txt`), add a `sleep` in loops, and check headroom with
`gh api rate_limit`.

## Safety and limitations

* `repo-write-file` disables branch protection and repo/org rulesets for the
  duration of the write and restores them in a `finally` block. SIGTERM, SIGINT,
  and SIGHUP are converted to a clean shutdown so the restore still runs; only an
  unblockable hard kill (SIGKILL) or host crash can leave protections off. The
  org ruleset toggle affects the whole org, so prefer a narrow blast radius and
  spot-check with `repo-branch-protection --operation current` afterward.
* The `protection_ops` backup cache is keyed by org/repo/branch (org is passed as
  the namespace), so a token spanning multiple orgs is partitioned correctly.
  This depends on `protection_ops` honoring that namespace; confirm it on your
  build.
* `repo-revert-commit` authenticates with a bare clone URL and an
  `http.extraheader` injected via the environment (`GIT_CONFIG_*`, git 2.31+), so
  the token is never written into argv or the temp clone's `.git/config`. The
  temp dir is removed in a `finally` block.
* `logs` and `contents` print raw output that may contain build secrets. Treat
  the output as sensitive.
* `contents` is a single API call by default. `--with-dates` adds a last-commit
  date per file, which costs one API call per file (N+1); use it only on small
  repos or specific paths.

## Helpers

Both helpers live in `helpers/` and drive the CLI as a subprocess. They share
one operating model: the Veracode workflows run only in each organization's
central workflow repository (default name `veracode`) and scan the org's other
repositories as sources, so a bare organization target maps straight to
`<org>/veracode`. No fleet-wide repo enumeration happens.

Shared flags (both helpers):

* `--targets FILE`: one target per line, `org` or `org/repo`, `#` comments
  allowed. A bare `org` maps to `<org>/<workflow-repo>`. Omit the flag entirely
  to auto-discover every organization the token reaches (via `orgs --csv`).
* `--workflow-repo NAME` (alias `--repo`, default `veracode`): the central
  workflow repository name inside each org. Also used to label logs re-analyzed
  with `--analyze-dir`.
* `--limit N` (default 50): workflow runs listed per repository during
  discovery (pagination stops early thanks to `--name-break`).
* `--runs-per-repo N` (default 10): runs whose logs are fetched and classified,
  per repository.
* `--failed-only` / `--no-failed-only` (default on): restrict discovery to
  `failure,cancelled,timed_out,action_required` conclusions. Gate failures mark
  the run as failed, so they are always included.
* `--cli PATH` (default `github-workflow-cli.py`): path to the CLI.
* `--python PATH`: interpreter used to invoke the CLI (defaults to the current
  one).
* `--output-dir DIR` (default `workflow-output`): a timestamped
  `sast-bulk-*` / `sca-bulk-*` folder is created per invocation containing the
  raw discovery logs, per-run logs, and the three reports.
* `--analyze-dir DIR`: skip fetching and re-classify previously collected
  `*-sast-NNN.log` / `*-sca-NNN.log` files. Useful when iterating on the rule
  set; no token needed.
* `--include-ok`: also report runs with no observed failure (SAST) or clean
  gate passes (SCA).
* `--fail-fast`: stop on the first collection error instead of continuing.

Exit codes: 0 all collection succeeded, 1 at least one discovery/log fetch
failed (findings are still written), 2 usage or environment error.

### bulk-sast-analyzer.py

Triage for "Static Code Analysis" runs. Fetches only the SAST pipeline jobs
(`logs --relevant-only --manifest`), classifies the root cause against a
signature rule set (Veracode credentials/profile/sandbox, private feeds and
dependency resolution per ecosystem, compiler failures, Docker/disk/memory,
TLS/proxy/DNS, prescan module errors, scan timeouts, policy gates, runner loss,
cancellations), and writes:

* `sast-summary.md`: findings grouped by cause with run link, branch,
  timestamp, failing job, pipeline progress, evidence line, and the concrete
  remediation. Cleanup failures are real failures but not scan blockers, so
  they are reported in a "Secondary issues" section at the bottom and never
  mask the primary SAST cause.
* `sast-findings.csv` / `sast-findings.json`: full field set per run.

```bash
export GITHUB_TOKEN=ghp_xxx
python helpers/bulk-sast-analyzer.py                         # all reachable orgs
python helpers/bulk-sast-analyzer.py --targets targets.txt   # explicit list
python helpers/bulk-sast-analyzer.py --analyze-dir logs/     # offline re-run
```

Unclassified failures surface as `UNCLASSIFIED_SAST_FAILURE` with their
evidence line; add a `Rule` entry for any recurring one.

### bulk-sca-analyzer.py

Triage for agent-based "Software Composition Analysis" runs (run names look
like `Software Composition Analysis - <source repo>`). SCA is different from
SAST in one important way: a failed run is very often a successful scan that
the severity gate blocked, which is the control working, not an error. The
helper therefore splits its report:

* Operational failures grouped by cause: `SRCCLR_API_TOKEN` problems, agent
  download/bootstrap, no supported projects, missing lockfiles, dependency
  graph resolution per ecosystem, OOM/disk/network, fail-closed gate plumbing
  (`GATE_SCRIPT_MISSING`, `RESULTS_FILE_MISSING`), runner loss, cancellations.
* Severity gate failures with the scan intelligence extracted from the run
  log: threshold, findings at or above it, severity split
  (critical/high/medium/low), vulnerable vs total libraries (direct and
  transitive), package managers, analysis time, the platform scan URL, and the
  Update Advisor quick wins (library, safe version, breaking or not) so
  remediation can start without opening the platform.
* Clean passes counted, listed with `--include-ok`.

It fetches the complete run log (no `--relevant-only`; SCA job names do not
match the SAST pipeline patterns) and writes `sca-summary.md`,
`sca-findings.csv`, and `sca-findings.json` with the same layout conventions as
the SAST helper, including the cleanup section at the bottom.

```bash
python helpers/bulk-sca-analyzer.py                          # all reachable orgs
python helpers/bulk-sca-analyzer.py --targets targets.txt --runs-per-repo 5
python helpers/bulk-sca-analyzer.py --analyze-dir logs/ --include-ok
```

Unclassified failures surface as `UNCLASSIFIED_SCA_FAILURE` with their
evidence line; add a `Rule` entry for any recurring one.
