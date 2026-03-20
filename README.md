# Security Health Check

Static security analysis for JavaScript and TypeScript apps — secrets, auth vulnerabilities, dependency risks, code quality, and CSP. Get a **0–100 health score** with actionable diagnostics posted to your PRs.

Inspired by [React Doctor](https://github.com/millionco/react-doctor), but focused on frontend and Node.js security.

## How it works

Security Health Check runs five checks on your codebase and produces a weighted composite score:

1. **Security & Secrets** (35%) — Hardcoded API keys, tokens, JWTs, `eval()`, XSS sinks, localStorage misuse
2. **Auth Patterns** (25%) — Client-side role checks, unverified JWTs, hardcoded `isAdmin`, unprotected routes
3. **Dependencies** (20%) — `npm audit` vulnerabilities, known-risky packages, deprecated libraries
4. **Code Quality** (10%) — Empty catch blocks, `@ts-ignore`, debugger statements, unimplemented stubs
5. **CSP Audit** (10%) — Missing or misconfigured Content-Security-Policy meta tags

Results are posted as a collapsible PR comment with per-check scores, severity-tagged findings, and detected good practices.

## GitHub Actions

Add to your workflow (e.g. `.github/workflows/security-health-check.yml`):

```yaml
name: Security Health Check

on:
  pull_request:
    branches: [main]

jobs:
  security-health-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write
      issues: write
    steps:
      - uses: actions/checkout@v4
      - uses: OWNER/security-health-check@v1
        with:
          app-path: .
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

Replace `OWNER` with your GitHub username or org.

### Minimal integration

```yaml
- uses: actions/checkout@v4
- uses: OWNER/security-health-check@v1
  with:
    app-path: .
    github-token: ${{ secrets.GITHUB_TOKEN }}
```

### With custom threshold

```yaml
- uses: actions/checkout@v4
- uses: OWNER/security-health-check@v1
  with:
    app-path: apps/frontend
    github-token: ${{ secrets.GITHUB_TOKEN }}
    threshold: "80"
```

### Gate on score output

```yaml
- uses: actions/checkout@v4
- uses: OWNER/security-health-check@v1
  id: security
  with:
    app-path: .
    github-token: ${{ secrets.GITHUB_TOKEN }}

- name: Fail if score too low
  if: steps.security.outputs.score < '70'
  run: exit 1
```

## Inputs

| Input | Default | Description |
| ----- | ------- | ----------- |
| `app-path` | _(required)_ | Path to the JS/TS app relative to repo root (e.g. `apps/frontend`) |
| `github-token` | _(required)_ | GitHub token for posting PR comments |
| `threshold` | `70` | Minimum passing score (0–100) |
| `post-comment` | `true` | Post results as a PR comment |
| `node-version` | `20` | Node.js version to use |

## Outputs

| Output | Description |
| ------ | ----------- |
| `score` | Health score from 0–100 |
| `has-findings` | Whether any check reported issues (`true`/`false`) |

## CLI usage

The tool also works as a standalone CLI:

```bash
npm install -g security-health-check
security-health-check --dir ./my-app --threshold 70 --json report.json
```

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--dir <path>` | `.` | Root directory to scan |
| `--threshold <n>` | `70` | Minimum passing score |
| `--json <path>` | — | Write JSON report to file |
| `--no-fail` | `false` | Exit 0 regardless of score |

## Publishing to the Marketplace

1. Create a **public** repository with `action.yml` at the root
2. Create a release (e.g. tag `v1`) and select **Publish this Action to the GitHub Marketplace**
3. Accept the [GitHub Marketplace Developer Agreement](https://docs.github.com/en/actions/sharing-automations/creating-actions/publishing-actions-in-github-marketplace) if prompted

See [GitHub's publishing docs](https://docs.github.com/en/actions/sharing-automations/creating-actions/publishing-actions-in-github-marketplace) for details.

## License

MIT License — see [LICENSE](LICENSE).
