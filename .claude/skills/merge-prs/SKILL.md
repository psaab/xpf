---
name: merge-prs
description: Merge all open PRs (or specific ones) and close their associated issues
user_invocable: true
---

# Merge Open PRs and Close Associated Issues

Merge open pull requests and automatically close any issues they reference via "Fixes #N".

## Usage

- `/merge-prs` — merge ALL open PRs
- `/merge-prs 123 456 789` — merge specific PR numbers

## Steps

1. List open PRs (or use the provided numbers).
2. Merge each PR with `--merge` strategy.
3. For any that fail with merge conflicts, rebase on master and retry.
4. Extract "Fixes #N" references from each merged PR body.
5. Close the associated issues.
6. Report results.

## Implementation

```bash
# Get PR list — either from args or all open
if [ -n "$ARGS" ]; then
  PRS="$ARGS"
else
  PRS=$(gh pr list --state open --json number -q '.[].number' | sort -n)
fi

if [ -z "$PRS" ]; then
  echo "No open PRs to merge."
  exit 0
fi

MERGED=""
FAILED=""
ISSUES_CLOSED=""

for pr in $PRS; do
  if gh pr merge $pr --merge 2>/dev/null; then
    MERGED="$MERGED $pr"
    
    # Extract and close associated issues
    FIXES=$(gh pr view $pr --json body -q '.body' 2>/dev/null | grep -oP '[Ff]ixes #\d+' | grep -oP '\d+')
    for issue in $FIXES; do
      gh issue close $issue --reason completed --comment "Fixed by PR #$pr (merged)." 2>/dev/null && \
        ISSUES_CLOSED="$ISSUES_CLOSED #$issue"
    done
  else
    # Try rebase and retry
    BRANCH=$(gh pr view $pr --json headRefName -q '.headRefName' 2>/dev/null)
    if [ -n "$BRANCH" ]; then
      git fetch origin $BRANCH 2>/dev/null
      git checkout $BRANCH 2>/dev/null
      if git merge origin/master --no-edit 2>/dev/null; then
        git push 2>/dev/null
        git checkout master 2>/dev/null
        sleep 3
        if gh pr merge $pr --merge 2>/dev/null; then
          MERGED="$MERGED $pr"
          FIXES=$(gh pr view $pr --json body -q '.body' 2>/dev/null | grep -oP '[Ff]ixes #\d+' | grep -oP '\d+')
          for issue in $FIXES; do
            gh issue close $issue --reason completed --comment "Fixed by PR #$pr (merged)." 2>/dev/null && \
              ISSUES_CLOSED="$ISSUES_CLOSED #$issue"
          done
        else
          FAILED="$FAILED $pr"
        fi
      else
        # Conflicts, including stale root `_Log.md` edits, take the abort path;
        # that log is closed and must never be forced with `--theirs` or union.
        git merge --abort 2>/dev/null
        git checkout master 2>/dev/null
        FAILED="$FAILED $pr"
      fi
    else
      FAILED="$FAILED $pr"
    fi
  fi
done

git checkout master 2>/dev/null
git pull origin master 2>/dev/null

echo ""
echo "=== Results ==="
[ -n "$MERGED" ] && echo "Merged:$MERGED"
[ -n "$FAILED" ] && echo "Failed:$FAILED (need manual rebase)"
[ -n "$ISSUES_CLOSED" ] && echo "Issues closed:$ISSUES_CLOSED"
[ -z "$MERGED" ] && [ -z "$FAILED" ] && echo "Nothing to do."
```
