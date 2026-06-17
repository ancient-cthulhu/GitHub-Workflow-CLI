# GitHub Workflow CLI

A single-file CLI for querying and remediating GitHub Actions workflows, repos,
issues, and protection settings. It wraps the `gh` CLI and the GitHub REST API,
and is the operator surface for troubleshooting and bulk-fixing the Veracode
workflow integration. Target any org or repo per command with `--org` / `--repo`.

## Requirements

* Python 3.12+ (uses PEP 701 nested-quote f-strings).
* `gh` and `git` on `PATH` (git 2.31+, for env-injected auth in
  `repo-revert-commit`).
* Python packages `requests` and `ruamel.yaml`, plus the internal `enable_debug`
  module providing `protection_ops`.

## Authentication

One GitHub token authenticates every command, read from `GITHUB_TOKEN`, or
`GH_TOKEN` if that is unset. It can be a tenant-wide token (org or enterprise
installation/admin token) or a personal access token; whatever it is authorized
for is what the CLI can reach. A local `.env` file is also loaded, without
overriding variables already set in the environment.

```bash
export GITHUB_TOKEN=ghp_xxx
python gh_workflow_cli.py token-info     # user + scopes
python gh_workflow_cli.py orgs           # which orgs the token covers
```

`orgs` answers whether a token is scoped to one org or several. It lists every
reachable org and prints a `Single-org` / `Multi-org` verdict.

## Commands

Read:

* `repos --org ORG [--name SUBSTR] [--csv]` lists non-archived repos.
* `workflows --repo ORG/REPO [--status ...] [--conclusion a,b] [--name SUBSTR] [--name-break] [--limit N] [--csv]`.
  `--status` filters server-side; `--conclusion` and `--name` filter locally.
* `run --repo ORG/REPO --id RUN_ID`, `logs --repo ORG/REPO --run-id RUN_ID`
  (full per-job logs, no `gh` CLI truncation).
* `issues --repo ORG/REPO [--state ...] [--tree] [--csv]`,
  `issue --repo ORG/REPO --number N`.
* `contents --repo ORG/REPO [--path P] [--tree] [--with-dates] [--csv]`.
* `repo-branches`, `repo-commits --branch B [--verbose]`.
* `token-info`, `orgs`.
* `org-apps`, `org-app --name APP`, `org-actions-permissions`,
  `repo-actions-permissions` (alias `rap`), `org-rulesets [--ruleset-id ID]`.

Mutate:

* `repo-write-file --repo ORG/REPO --branch B --destination-file PATH --operation merge|overwrite|delete [--source-file LOCAL] [--message MSG]`.
* `repo-revert-commit --repo ORG/REPO --branch B --sha SHA`.
* `repo-branch-protection --repo ORG/REPO --branch B --operation disable|restore|current|cached`.
* `repo-actions-permissions --repo ORG/REPO --enable|--disable`.
* `org-rulesets --org ORG --ruleset-id ID --modify-ruleset-enforcement active|disabled|evaluate`.
* `issue-create --repo ORG/REPO --title T [--body B] [--assignee U] [--labels a,b]`.

All list commands print a table by default and CSV with `--csv`. CSV column order
is fixed, which is what the bulk recipes below rely on.

## Bulk operations

These recipes run fleet-wide. They use only `--csv` output and standard shell, so
they are safe to adapt. Run them in `bash`. Set these once:

```bash
CLI="python gh_workflow_cli.py"
ORG=my-org
export GITHUB_TOKEN=ghp_xxx
```

A reusable list of repo names for the org (CSV column 1 is `name`):

```bash
$CLI repos --org "$ORG" --csv > repos.csv
repos=$(tail -n +2 repos.csv | cut -d, -f1)
```

### 1. Org-wide Veracode failure report

Collect recent failed/cancelled Veracode runs across every repo into one CSV,
tagged with the repo name. The workflows CSV is
`number,id,name,status,conclusion,...`, so the run id is column 2.

```bash
echo "repo,run_number,run_id,name,status,conclusion" > veracode-failures.csv
for r in $repos; do
  $CLI workflows --repo "$ORG/$r" --name veracode \
       --conclusion failure,cancelled --limit 50 --csv \
    | tail -n +2 | sed "s#^#$r,#" >> veracode-failures.csv
  sleep 1   # be gentle with rate limits
done
```

### 2. Pull logs for every failed run

`veracode-failures.csv` rows start `repo,number,run_id,...`, so read the first
three fields and write one log file per run.

```bash
mkdir -p logs
tail -n +2 veracode-failures.csv | while IFS=, read -r repo num id rest; do
  $CLI logs --repo "$ORG/$repo" --run-id "$id" > "logs/${repo}-${id}.log" 2>&1
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
for ORG in $($CLI orgs --csv | tail -n +2); do
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
