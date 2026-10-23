# Changelog

## 0.25.1

- Updated minimum dependency versions for FastAPI, Uvicorn, Pydantic, Playwright, and setuptools.
- Merged the first Dependabot maintenance updates.

## 0.25.0

- Added a `/review` workbench that deduplicates findings by fingerprint across scans.
- Added status, severity, and target filters plus high-risk and expiry summaries.
- Added accepted-risk expiry warnings for expired and soon-to-expire decisions.
- Added navigation from the dashboard and sidebar.
- Hardened review-state lookups for large histories.

## 0.24.0

- Added CLI commands for target baselines: `baseline set`, `show`, and `clear`.
- Added a real scan end-to-end CI fixture: passive scan, safe scan, baseline, and diff gates.
- CI uploads the real scan HTML/JSON reports as an artifact.
- Hardened CI actions and permissions.
- Added weekly Dependabot updates for Python and GitHub Actions.

## 0.23.1

- CI now enforces a 75% pytest coverage threshold.
- Added a wheel install smoke test, including package template data.
- Added a deterministic baseline fixture that exercises `diff --baseline --fail-on new_confirmed` in CI.
- Added `scripts/ci_gate_fixture.py` for local gate verification.

## 0.23.0

- Added per-target scan baselines with a `/trends` view.
- Diff defaults to the stored target baseline when one exists.
- Added a cross-scan trend table with new/fixed/untested/reviewed-out and review counts.
- Added `vulnscan diff --baseline` and `--fail-on` for CI regression gates.
- Added schema version 3 for the baseline table.

## 0.22.0

- Added an indexed fingerprint column to findings with an additive schema migration.
- Added `PRAGMA user_version` migrations and automatic fingerprint backfills.
- Added a cross-scan fingerprint history page with occurrences, scans, severity and review timeline.
- Review states now record the reviewed severity and evidence hash.
- Accepted risk supports an expiry date; expired risk is reopened automatically.
- Severity escalation and false-positive evidence changes reopen reviews with a `system` event.
- HTML/JSON reports include fingerprint, expiry and review history.

## 0.21.0

- Review status is now stored by finding fingerprint and shared across scans.
- Existing per-finding reviews and events are backfilled once into the new state tables.
- `false_positive` and `accepted_risk` now require a review note.
- Diff uses cross-scan review state and keeps reviewed-out findings out of regressions.
- Review history, filters, bulk updates, dashboard counts, and reports use the shared state.

## 0.20.0

- Added finding review filters and bulk review updates.
- Added append-only finding review history and JSON report history.
- Added dashboard counts by review status.
- Diff now separates confirmed/new/needs-review/reviewed-out findings.

## 0.19.0

- Added finding review status: needs review, confirmed, false positive, accepted risk.
- Added review notes and reviewer metadata to HTML/JSON reports.
- Added per-check API outcome details to the endpoint result matrix.
- Added GitHub Actions CI and an opt-in Playwright GUI smoke test.
- Preserved existing scan data; finding reviews use a new `finding_reviews` table.

## 0.18.0

- Added BFLA read-only checks and BOLA/BFLA authorization matrix.
- Shared rate limiter, request budget, and live request statistics across clients.
- Added form-login session recovery.
- Added BOLA GET allow-all acknowledgement.

## 0.17.0

- Added API/BOLA coverage diff and separated untested findings from fixed findings.
- Added explicit BOLA all-GET acknowledgement.
- Added per-endpoint BOLA results and JSON shape comparison.

## 0.16.0

- Added BOLA result matrix, GET allowlist, and BOLA diff.
- Added API test budget and per-endpoint result matrix.

## 0.15.0

- Added read-only BOLA/IDOR dual-account checks.
- Added configurable API/BOLA test budgets.
- Added per-endpoint API checks matrix.

## 0.14.0

- Added spec fingerprint drift detection, scope-aware external `$ref`, and session validity checks.

## 0.13.0

- Added host-aware allowlists, explicit all-POST acknowledgement, and API scope reporting.

## 0.12.0

- Added authenticated OpenAPI preview, request manifests, and import warning statistics.

## 0.11.0

- Added OpenAPI URL redirects/3.1 support, POST preview, allowlist, and boolean SQLi retries.
