# Curbi Check

Replay your Curbi regressions on every pull request. When an agent reply's verdict changes (a wrong price that used to be caught now passes, or a clean reply now fails), the job fails and one PR comment shows which case changed and why.

```yaml
# .github/workflows/curbi.yml
on: pull_request
permissions: { contents: read, pull-requests: write }
jobs:
  curbi:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Curbi-Inc/curbi-check-action@v1
```

Put regressions in a `curbi/` folder. Each is a `curbi.regression` JSON file. You can make one three ways:

- **Claude or ChatGPT:** ask the [Curbi connector](https://curbi.io/connect/) to "turn this failed reply into a regression" (`export_regression`), and save the result as `curbi/<name>.json`.
- **The web:** check a reply on [curbi.io/check](https://curbi.io/check/) and choose **Download this regression test**.
- **By hand:** see [`example/curbi/first-check.json`](example/curbi/first-check.json).

## Inputs

| Input | Default | |
|---|---|---|
| `path` | `curbi` | A file, or a folder searched recursively. Other JSON files there are ignored. |
| `api-key` | none | A Curbi API key (`ck_live_…`) from a repository secret. Without one, checks use the free, rate-limited tier. |
| `api` | `https://api.curbi.io/v1/check` | HTTPS Check API endpoint; HTTP is accepted only for loopback testing. Redirects are refused. |
| `comment` | `true` | Post one PR comment and update it on each run. |
| `github-token` | `github.token` | Used only for that comment. |

Outputs: `cases` and `failed`.

## What it sends and what it means

- **What it sends:** each regression's policy, replies and records go to the Check API. Keep secrets and real customer data out of committed regressions.
- **Errors fail the job:** a network error, an API error or a malformed file fails the job. A run never passes without a verdict.
- **Fork PRs:** they get a read-only token, so the comment is skipped. The job summary still shows the results.
- **What a pass means:** a pass means no configured rule fired. It is not general truth and grants no permission.

Requests are split at both 50 cases and 64 KiB of serialized UTF-8 JSON, including policy overhead. A single policy/case that cannot fit fails before it is sent. Case IDs must be unique, nonempty strings of at most 60 characters; omitted IDs use their index. Expected rules must be unique nonempty strings; a passing case uses an empty rules array.

Only regular files are read. Symlinks are refused; on Actions, fixture paths must remain inside `GITHUB_WORKSPACE`, including every directory component. Limits are 1 MiB per file, 16 MiB across fixtures, 256 JSON files, 4,096 directory entries, 16 directory levels and 10,000 cases per run. API responses are streamed with a 1 MiB limit and must return exactly one well-formed result per requested ID. Oversized, missing, duplicate and inconsistent results fail the job.

Untrusted report text is rendered literally, including Markdown links and images. Reports are capped at 60,000 characters; case counts remain complete. GitHub comment requests have a three-second timeout, and comment failures do not change the check outcome. Updates target only comments from `github-actions[bot]` with the Curbi marker; a custom user token may create comments but does not make arbitrary existing comments eligible for update.

MIT licensed. No dependencies.
