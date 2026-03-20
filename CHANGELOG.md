# Changelog

## [1.0.0] - 2026-03-20

### Added
- Initial release as a GitHub Action
- Security & Secrets check (hardcoded keys, tokens, JWTs, XSS sinks, eval)
- Auth Patterns check (client-side roles, unverified JWTs, unprotected routes)
- Dependency vulnerability check (npm audit, risky packages)
- Code Quality check (empty catch blocks, ts-ignore, debugger statements)
- CSP Audit check (missing/misconfigured Content-Security-Policy)
- Weighted 0–100 health score with PR comment output
- CLI usage via `security-health-check` bin
- JSON report output via `--json` flag
