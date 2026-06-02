# GitHub repository setup — post-push checklist

Done at v0.3.0 publication (2026-06-02). Documented so the operator (or a future contributor) can verify or replicate the configuration.

## Repository features ✅ (configured via `gh api`)

| Feature | Status | How |
|---|---|---|
| Public visibility | ✅ on | initial creation |
| Issues | ✅ enabled | `gh api repos/.../{owner}/{repo} -X PATCH -F has_issues=true` |
| Discussions | ✅ enabled | same PATCH `-F has_discussions=true` |
| Wiki | ❌ disabled | (we prefer docs in-repo) |
| Topics | ✅ set | `mcp`, `model-context-protocol`, `microsoft-outlook`, `microsoft-graph`, `oauth`, `security-hardened`, `typescript`, `nfadp`, `ixtria` |
| Description | ✅ set | "Security-hardened MCP server for Microsoft Outlook (Mail + Calendar). Client-agnostic. Audit-trail + egress allowlist + OAuth proxy hardening. Apache-2.0, by Ixtria." |

## Security features ✅ (configured via `gh api`)

| Feature | Status | How |
|---|---|---|
| Dependabot security updates | ✅ enabled | `gh api repos/.../automated-security-fixes -X PUT` |
| Vulnerability alerts | ✅ enabled | `gh api repos/.../vulnerability-alerts -X PUT` |
| Secret scanning | ✅ enabled | `gh api repos/.../{owner}/{repo} -X PATCH -f 'security_and_analysis[secret_scanning][status]=enabled'` |
| Secret scanning push protection | ✅ enabled | same PATCH with `secret_scanning_push_protection` |
| Code scanning (CodeQL) | ✅ enabled via workflow | `.github/workflows/security.yml` job `codeql` |
| Semgrep SARIF upload | ✅ enabled via workflow | same workflow |
| TruffleHog secret scan | ✅ enabled via workflow | same workflow (replaced gitleaks which now requires paid license) |
| OSV-Scanner | ✅ enabled via workflow | same workflow |
| License compliance | ✅ enabled via workflow | same workflow |

## Branch protection (TO ACTIVATE via UI — not done at v0.3.0)

For solo-maintainer Jimmy, **branch protection is optional** at first but **strongly recommended** before accepting external contributions. Configure once via GitHub UI :

1. Open https://github.com/Ixtria/outlook-mcp-hardened/settings/branches
2. Click "Add branch ruleset" or "Add classic branch protection rule"
3. Pattern : `main`
4. Recommended rules :
   - ✅ Require a pull request before merging
   - ✅ Require approvals (1 minimum)
   - ✅ Dismiss stale pull request approvals when new commits are pushed
   - ✅ Require status checks to pass before merging
     - Required checks : `CI / lint-typecheck-test (20.x)`, `CI / lint-typecheck-test (22.x)`, `CI / npm-audit`, `Security / codeql`, `Security / semgrep`, `Security / osv-scanner`, `Security / trufflehog`, `Security / license-check`
   - ✅ Require branches to be up to date before merging
   - ✅ Require conversation resolution before merging
   - ✅ Require signed commits (optional, hardens supply chain)
   - ✅ Restrict who can push to matching branches (yourself only initially)
   - ❌ Do not allow bypassing the above settings (admin enforcement)

CLI alternative (one-shot) :

```bash
gh api repos/Ixtria/outlook-mcp-hardened/branches/main/protection -X PUT --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      {"context": "CI / lint-typecheck-test (20.x)"},
      {"context": "CI / lint-typecheck-test (22.x)"},
      {"context": "CI / npm-audit"},
      {"context": "Security / CodeQL (JS/TS SAST)"},
      {"context": "Security / Semgrep (OWASP + TS rulepacks)"},
      {"context": "Security / OSV-Scanner (deps vuln scan)"},
      {"context": "Security / TruffleHog (secret scan)"},
      {"context": "Security / License compliance"}
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true,
  "required_linear_history": false
}
JSON
```

## CodeQL configuration (alerts review)

After the first `Security / CodeQL` job completes successfully :

1. Open https://github.com/Ixtria/outlook-mcp-hardened/security/code-scanning
2. Review any alerts surfaced by the `security-and-quality` query suite
3. Triage : fix, suppress with justification, or open issue tracker entry

## Dependabot configuration

Already configured via `.github/dependabot.yml` :

- Weekly Monday 06:00 Europe/Zurich
- npm + github-actions ecosystems
- Security updates : all severities (priorité)
- Version updates : minor/patch grouped, majors individual
- `commander` major pinned (v12 breaks our CLI parsing)

## Releases

| Tag | URL |
|---|---|
| v0.1.0 | https://github.com/Ixtria/outlook-mcp-hardened/releases/tag/v0.1.0 |
| v0.2.0 | https://github.com/Ixtria/outlook-mcp-hardened/releases/tag/v0.2.0 |
| v0.3.0 (current latest) | https://github.com/Ixtria/outlook-mcp-hardened/releases/tag/v0.3.0 |

## npm publication (not done at v0.3.0)

The package is **not yet published to npm**. Before publication, decide :

1. Should this go on the public npm registry, or only as a GitHub-hosted package ?
2. Who owns the `@ixtria` scope on npm ? Must be configured first.
3. Set up `npm publish` via GitHub Actions on tag push (with NPM_TOKEN secret).

Suggested workflow (`.github/workflows/publish.yml`) :

```yaml
name: Publish to npm
on:
  release:
    types: [published]
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write  # OIDC trusted publishing (no NPM_TOKEN needed)
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          registry-url: 'https://registry.npmjs.org'
      - run: npm ci
      - run: npm run build
      - run: npm publish --provenance --access public
```

OIDC trusted publishing requires npm account → GitHub repo association (npm UI). Once configured, no token storage needed.
