<!--
  PR template for @ixtria/outlook-mcp-hardened.
  Keep sections short and factual. Delete inline HTML comments before submitting.
-->

## Overview

<!-- One or two sentences: what does this PR change, and why now? -->

## Related tickets

<!--
  Link every ticket / issue / ADR / cross-review finding this PR touches.
  Examples:
    - Closes #123
    - Refs TICKETS.md § GOV-04
    - Implements ADR-0004 Rule 3
    - Fixes cross-review finding BLOCKER-N1-07
-->

- Closes #
- Refs

## Testing

<!--
  Discipline ADR-0004 Rule 3: tests must observe behavior, not grep source.
  A test that greps `SERVER_TS.toContain('PKCE')` proves nothing and is REJECTED in review.
-->

- [ ] Added / updated **behavioral** tests (spawn server, mock req/res, assert observable effect).
- [ ] **No** `SOURCE.toContain(...)`, no regex over `fs.readFileSync`, no AST-grep asserting the source string exists.
- [ ] `npm run verify` passes locally (`generate + lint + format:check + build + test`).
- [ ] If touching OAuth / egress / audit: cross-review N0 + N1 attached in comment (per ADR-0001).

## Discipline ADR-0004

<!--
  These four gates are non-negotiable on `main`. See docs/adr/0004-discipline-de-maintenance.md.
-->

- [ ] **Rule 1 — Deps scanners bloquants** : no new runtime dep added without justification in the PR body below; `npm audit --audit-level=moderate` green.
- [ ] **Rule 2 — `--max-warnings 0`** : lint passes at zero warnings; every new `// eslint-disable...` carries an inline `// justif: <reason>` on the same or preceding line.
- [ ] **Rule 3 — Behavioral tests only** : re-confirming the checkbox from the Testing section above (yes, on purpose — this is the gate that regresses most often).
- [ ] **Rule 4 — Dependabot SLA** : if this PR merges a Dependabot bump, it's within the 7-day window; if it defers, a ticket is opened with rationale.

## Threat Model impact

<!--
  Per ADR-0004 anti-pattern list: no architecture change without a TM clause.
  Choose one:
    - TM: unchanged           (bugfix / doc / test / refactor with no surface change)
    - TM: to-update           (this PR shifts a surface; TM update tracked in ticket #___)
    - TM: superseded          (this PR is itself the TM update; docs/threat-model/ diff below)
-->

- **TM:** unchanged | to-update | superseded  <!-- pick one, delete the others -->
- If `to-update` or `superseded`, link the threat-model diff or ticket:

## Deployment / operational notes

<!--
  Optional. Fill only if operators must do something at upgrade time:
  new env var, migration, changed default, revoked deprecated flag, new CLI arg, etc.
  Put "None" if there is nothing operational to note.
-->

None.

## Reviewer checklist (informational)

- [ ] Diff is minimal and focused; unrelated cleanups split into a separate PR.
- [ ] Upstream files (non-security/) modified only via chirurgical `// HARDENED:` markers.
- [ ] No secret, token, or PII in code / config / test fixtures / commit messages.
- [ ] User-facing changes documented in `CHANGELOG.md` (or noted as internal-only).
