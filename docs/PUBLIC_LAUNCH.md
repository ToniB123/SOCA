# Public launch checklist

The repository is intentionally sanitized from its first commit: the live,
host-tuned `netstat_baseline_rules.yaml`, runtime logs/findings/caches, and
`CODE_REVIEW.md` are gitignored. Run this checklist before changing the GitHub
repository from private to public.

## 1. Scan the working tree

```powershell
python scripts/check_sensitive_data.py --tree
```

Fix every finding. Do not use `git add -f` for a local-only file.

## 2. Scan the staged content and the history

```powershell
python scripts/check_sensitive_data.py --staged
git log --all --stat --oneline
git log --all -p -- netstat_baseline_rules.yaml CODE_REVIEW.md
```

The last command must produce no output. Review the history for logs, `*.jsonl`,
`*.log`, caches, allow-list files, `.env` files, keys, emails, machine names,
personal paths, and private IPs.

## 3. If anything sensitive was ever committed

Ignoring a file does not remove it from history. Either:

- rewrite the history with `git filter-repo` (or BFG) and force-push to a
  private remote, then verify the history again; or
- start a fresh public repository from the current sanitized tree and do not
  reuse the old history.

Do not make the old repository public until the history is clean.

## 4. Clean-clone test

Copy only the tracked files into a temporary directory, then:

```powershell
Copy-Item netstat_baseline_rules.example.yaml netstat_baseline_rules.yaml
uv run ruff check .
uv run python -m unittest
```

Confirm the app starts, the dashboard loads, and tests pass without the live
tuned baseline or any runtime artifact.

## 5. Documentation review

- `README.md` and `IMPLEMENTATION_GUIDE.md` contain no host-specific examples,
  personal identifiers, or observed network statistics.
- The README quickstart tells users to copy the example baseline and tune it
  before running.
- `docs/PUBLIC_LAUNCH.md` and `SECURITY.md` (if present) explain that all data
  is local and that logs/findings must never be committed.

## 6. Repository settings

- Create the GitHub repository as **private** first.
- Add the remote only after this checklist passes:
  `git remote add origin https://github.com/<account>/<repo>.git`.
- Push, inspect the public/private view, then flip visibility if desired.
- Enable secret scanning/push protection in GitHub if available.
