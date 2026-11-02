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
| `api` | `https://api.curbi.io/v1/check` | The Check API endpoint. |
| `comment` | `true` | Post one PR comment and update it on each run. |
| `github-token` | `github.token` | Used only for that comment. |

Outputs: `cases` and `failed`.

## What it sends and what it means

- **What it sends:** each regression's policy, replies and records go to the Check API. Keep secrets and real customer data out of committed regressions.
- **Errors fail the job:** a network error, an API error or a malformed file fails the job. A run never passes without a verdict.
- **Fork PRs:** they get a read-only token, so the comment is skipped. The job summary still shows the results.
- **What a pass means:** a pass means no configured rule fired. It is not general truth and grants no permission.

MIT licensed. No dependencies.
