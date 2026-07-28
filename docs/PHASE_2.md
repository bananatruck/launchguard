# Phase 2: Security normalization and planning

Phase 2 adds trusted scanner orchestration, scanner-neutral findings, reviewed
execution plans, and a deterministic readiness policy. It deliberately stops
before sandboxed execution, AI remediation, and publication. Nothing in Phase 2
runs repository code.

## Architecture

Phase 2 extends `launchguard-core` with five modules:

- `scanner` runs trusted scanner binaries without a shell, bounds their output,
  normalizes their reports, and records their versions.
- `finding` defines the scanner-neutral `Finding` record and its fingerprint.
- `artifact` stores raw reports in a content-addressed, user-private directory.
- `plan` generates content-addressed `ExecutionPlan` records from reviewed
  templates.
- `readiness` calculates weighted scores with no model involvement.
- `degradation` records capabilities that did not complete.

`launchguard-cli` gains a `plan` command, scanner selection on `audit`, and
`schema` output for every new record.

## Public records

| Record | Schema | Emitted by |
| --- | --- | --- |
| `Finding` | [`finding-v1`](../schemas/finding-v1.schema.json) | Scanner normalization |
| `ExecutionPlan` | [`execution-plan-v1`](../schemas/execution-plan-v1.schema.json) | `PlanGenerator` |
| `ReadinessAssessment` | [`readiness-assessment-v1`](../schemas/readiness-assessment-v1.schema.json) | `ReadinessEngine` |
| `Degradation` | [`degradation-v1`](../schemas/degradation-v1.schema.json) | Any incomplete capability |

Readers reject unknown schema versions. `launchguard schema <record>` prints
each contract.

## Scanner contract

Trivy runs as `trivy filesystem --format json --quiet --scanners
vuln,secret,misconfig`. OSV-Scanner runs as `osv-scanner scan source --format
json --verbosity error --recursive`. Neither command is built as a string or
interpreted by a shell, and neither receives repository-controlled arguments.

Scanner processes are bounded by a 5-minute wall-clock deadline, 100 MiB of
accepted JSON, and 1 MiB of retained diagnostics. Exceeding a bound terminates
the process and records a degradation.

Scanner exit statuses are interpreted, not assumed:

| Scanner | Status | Meaning |
| --- | --- | --- |
| Trivy | `0` | Completed. A report with no `Results` key is a clean scan. |
| OSV-Scanner | `0` | Completed with no vulnerability match. |
| OSV-Scanner | `1` | Completed with at least one vulnerability match. |
| OSV-Scanner | `128` | Completed with no package manifests to match. |
| Either | other | Failure. Coverage is degraded, the run continues. |

Both scanners reach the network: Trivy downloads its vulnerability database and
OSV-Scanner queries the upstream OSV service. This is scanner infrastructure
traffic, not project execution, and it is separate from the default-deny
network policy that a future sandbox applies to project commands.

### Path normalization

Trivy reports paths relative to the scan root. OSV-Scanner echoes the absolute
path it was given. Public records use repository-relative paths, so both are
rewritten against the repository root before a fingerprint is computed. Without
this, the same CVE seen by both scanners produces two fingerprints and never
merges, and host paths leak into published records.

### Fingerprints and merging

A fingerprint is the SHA-256 of the category, uppercased vulnerability
identifier, lowercased package name, installed version, normalized path, and
start line. Findings sharing a fingerprint merge into one record that:

- retains every contributing scanner,
- keeps the highest reported severity and confidence,
- applies the more restrictive preview and publication block,
- retains every contributing raw report digest.

Merging is order-independent: scanning Trivy first or OSV-Scanner first
produces identical output.

### Raw report retention

Raw reports are written to `<artifact-directory>/sha256/<digest>.json` with
mode `0600` inside a `0700` directory, using an atomic no-clobber rename.
Identical reports deduplicate to one file. Raw reports may contain matched
secret text, so only their digest, size, media type, and relative path appear
in findings, history, or reports.

## Execution plans

A plan is generated only for an unambiguous `detected` profile. Every command
is an executable plus an argument array; no plan may contain `sh`, `bash`, or
`-c`. Each command carries a stage, working directory, accepted exit codes, a
network requirement, and its own deadline.

Every plan declares `approval_state: requires_approval`, a default-deny network
policy with the exact registry destinations its install step needs, CPU, memory,
PID, and wall-clock ceilings, environment variable names only, expected outputs,
and health checks. The digest is a SHA-256 over every field except itself, so
changing any command, limit, or network rule invalidates prior approval.

Phase 2 generates plans. It never executes one.

## Deterministic readiness

`ReadinessEngine` scores four dimensions from weighted checks defined in
`readiness.rs` and versioned by `READINESS_POLICY_VERSION`. Model text cannot
reach a score, because no model participates in Phase 2 at all.

A run blocks preview when any finding blocks preview, classification is not
unambiguous, no plan exists, or scanner coverage is incomplete. Publication is
blocked whenever preview is blocked or any finding blocks publication.

`findings_digest` hashes the security content of the merged findings and
deliberately excludes `raw_artifact_digests`. Trivy embeds a per-run report
identifier and timestamp, so the raw report digest legitimately differs between
two runs over an unchanged project. Hashing it would mean no assessment ever
reproduces. Provenance stays on each finding; it just does not enter the digest.

## Degraded coverage

A missing, failing, or timed-out scanner does not end an audit. The run
completes, records a typed `Degradation`, and reports reduced coverage
explicitly. The same applies when a detected project has no reviewed template.

Degradations are visible in three places: a structured warning on standard
error, a `degradations` array in JSON output, and a "Coverage degradations"
section in Markdown. Because `security.scanner_coverage` fails without both
scanners, a degraded run cannot present itself as a clean scan.

Diagnostic text in a degradation is untrusted scanner output. It is collapsed
to one line and truncated to 512 bytes.

## History

The SQLite database uses schema version 2 and stores the complete audit record:
profile, findings, plan, readiness assessment, degradations, scanner
provenance, and artifact references. `plan_digest`, `findings_digest`, and
`reproduction_digest` are also stored as columns for direct inspection.

Version 1 databases are migrated in place by adding the new columns; existing
rows remain readable and report empty Phase 2 sections. Content-addressed
records are re-validated before storage, so a plan or assessment whose digest
does not reproduce is never persisted.

`launchguard status <run-id>` replays the whole stored record rather than the
profile alone.

## Evaluation

The Phase 2 gate is measured over the same 40-fixture corpus as Phase 1, using
real Trivy and OSV-Scanner binaries. The integration gate requires:

- At least 90% of supported fixtures produce a plan that validates against the
  bundled `ExecutionPlan` schema.
- Every generated assessment validates against the bundled schema.
- Plans and assessments reproduce their digests and are byte-identical across
  repeated generation.
- Ambiguous profiles receive no plan.

See the [Phase 2 evaluation report](evaluation/phase-2.md) for measured results,
tool versions, and limitations.

## Known limitations

- Coverage depends entirely on what the configured scanners support. Trivy did
  not parse `bun.lock` in the evaluated version while OSV-Scanner did, so the
  two scanners can return disjoint findings for the same project. Absence of a
  finding is never evidence that no issue exists.
- Severity is taken from the scanner. `LaunchGuard` never raises or lowers it,
  and merged findings keep the highest reported value rather than adjudicating
  a disagreement.
- Secret findings are reported as metadata only. `LaunchGuard` does not verify
  that a matched credential is live, so a secret finding is a signal to rotate,
  not proof of compromise.
- The vulnerability data behind a run changes over time. Two audits of the same
  revision on different days can legitimately differ; the assessment records
  which scanner and database version produced it.
- Plans are descriptive. No command, mount, limit, or health check in a Phase 2
  plan has been executed or validated against a real runtime.
- Registry destinations in the network policy are reviewed defaults, not a
  measurement of what a given project actually contacts.
- Readiness scores describe evidence collected so far. A high score on a run
  with no scanners means the deterministic checks passed, not that the project
  is secure or deployable.
- Private repositories, authenticated registries, and non-GitHub sources remain
  out of scope.
