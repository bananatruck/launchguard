# LaunchGuard Product Specification

## 1. Document status

This document is the normative pre-implementation contract for LaunchGuard v1.
The words **must**, **must not**, **should**, and **may** describe requirements
with decreasing strength.

When implementation behavior conflicts with this document, the conflict must
be resolved explicitly in a versioned specification change.

## 2. Product objective

LaunchGuard turns a local checkout or GitHub repository into a deterministic
audit, isolated preview, and reviewable deployment pull request.

The system must:

1. Detect a supported project from repository evidence.
2. Produce a read-only security and deployment-readiness audit.
3. Show the exact proposed commands, mounts, limits, and network policy.
4. Execute an approved plan in a restricted OCI environment.
5. Verify builds, tests, health checks, and generated artifacts.
6. Optionally use a local model to explain failures and propose bounded fixes.
7. Re-run deterministic verification after every proposed change.
8. Publish only after a separate user approval.

The system must not claim that scanner output or model output proves a project
secure.

## 3. V1 scope

### 3.1 Supported project types

| Project type | Detection evidence | Required v1 output |
| --- | --- | --- |
| React/Vite | `package.json`, Vite dependency or config | Static build plan and Pages configuration |
| Next.js | `package.json`, Next dependency | Static or server classification and matching plan |
| FastAPI | `pyproject.toml` or requirements plus FastAPI import | Container plan, health configuration, Render blueprint |
| Rust Axum | `Cargo.toml` plus Axum dependency | Container plan, health configuration, Render blueprint |

If evidence is ambiguous, LaunchGuard must report `needs_confirmation` and
present the competing classifications. AI may explain the ambiguity but may
not silently select a runtime.

### 3.2 Supported outputs

- Readiness report in JSON and Markdown.
- Normalized security findings.
- Proposed execution plan.
- Local preview URL and health result.
- Unified diff for generated or repaired files.
- Dockerfile, `.dockerignore`, environment template, and provider manifest
  where applicable.
- Auditable deployment record.
- User-approved Git branch and pull request.

### 3.3 Non-goals

- Direct cloud provisioning in v1.
- Kubernetes or Terraform generation.
- Automatic database migration against non-ephemeral data.
- Arbitrary monorepo orchestration.
- CAPTCHA, authentication, or policy bypass.
- Running deliberately hostile code with a formal isolation guarantee.
- Replacing a security review or penetration test.

## 4. Operating modes

### 4.1 Audit

Audit is read-only. It may inspect repository content, parse manifests, and run
scanners that do not execute project code. It must not run package lifecycle
scripts, build commands, tests, or project binaries.

Audit completes without AI when Ollama is unavailable.

### 4.2 Plan

Plan generates the proposed build, test, preview, resource, mount, and network
policy. Every executable step must have an origin:

- A reviewed framework template.
- An explicit project script.
- A user-provided command.
- An AI proposal accepted by the policy engine and visibly marked as
  model-generated.

Plan itself performs no project execution.

### 4.3 Preview

Preview requires approval of the complete execution plan. It stages a copy of
the selected Git revision, creates a restricted container or VM-backed
container, executes approved commands, starts the application, runs health
checks, captures logs, and tears down runtime resources on completion.

Package-registry access is a separate policy item and is disabled by default.

### 4.4 Repair

Repair operates only in a temporary Git worktree. A repair attempt consists of:

1. Structured diagnosis.
2. Proposed unified diff.
3. Policy validation.
4. Patch application to the temporary worktree.
5. Rebuild, test, rescan, and health verification.

LaunchGuard may perform at most three repair attempts per run. It must stop
early if the same failure signature occurs twice without material progress.

### 4.5 Pull request

Pull-request mode presents the final diff, findings delta, test results,
generated files, and requested GitHub permissions. It requires explicit
approval before creating a branch, pushing, or opening a pull request.

### 4.6 Deploy

Deploy is reserved for a later specification. V1 adapters generate and
validate deployment configuration but do not create cloud resources.

## 5. Planned interfaces

### 5.1 CLI

```text
launchguard audit <path-or-url> [--format json|markdown]
launchguard plan <path-or-url>
launchguard preview <path-or-url> [--approve-plan <digest>]
launchguard repair <run-id> [--approve-plan <digest>]
launchguard pr <run-id> [--repository <owner/name>]
launchguard status <run-id>
```

Commands must emit machine-readable progress events when `--format json` is
selected. Interactive approval must never be inferred from a non-interactive
environment.

### 5.2 Local service

The future Tauri application and CLI daemon mode will use a loopback-only local
service. It must bind to `127.0.0.1` or `::1`, select an available port, and
require a per-session bearer token.

Progress is streamed as typed events; raw scanner and model output is retained
as referenced artifacts rather than embedded in every event.

### 5.3 Core types

The Rust engine will serialize public records using versioned JSON schemas.

```text
ProjectProfile
- schema_version
- source
- revision
- status
- components[]
- framework
- runtime
- package_manager
- deployment_kind
- build_command
- test_commands[]
- start_command
- output_directory
- detected_ports[]
- required_services[]
- environment_variables[]
- confidence
- candidates[]
- evidence[]

Finding
- schema_version
- fingerprint
- scanner
- category
- severity
- confidence
- file
- line
- vulnerability_id
- summary
- recommended_fix
- blocks_preview
- blocks_publication

ExecutionPlan
- schema_version
- digest
- revision
- commands[]
- mounts[]
- resource_limits
- network_policy
- environment_allowlist[]
- expected_outputs[]
- health_checks[]
- approval_state

RemediationProposal
- schema_version
- diagnosis
- confidence
- evidence_refs[]
- patch
- verification_steps[]
- model
- prompt_template_version

ReadinessScore
- schema_version
- build
- security
- deployment
- operations
- checks[]
- calculated_at

DeploymentRecord
- schema_version
- revision
- plan_digest
- tool_versions[]
- scanner_database_versions[]
- commands[]
- artifact_digests[]
- findings_summary
- test_results[]
- generated_files[]
- target
- timestamp
- rollback_identifier
```

Unknown schema versions must be rejected rather than guessed.

## 6. Detection and scoring

Detection must be evidence-based. A model may propose missing information only
after deterministic detectors return incomplete or conflicting results.

Readiness scores are calculated in Rust from versioned weighted checks. Model
text never changes a score. A blocked critical check caps the relevant score
and must remain visible even if the aggregate score is high.

Initial checks include:

- Build and tests succeed.
- No unacknowledged critical vulnerabilities.
- No verified secret finding.
- Required environment variables are documented.
- Container runs as non-root.
- Health check succeeds.
- Application binds to the configured interface and port.
- Generated deployment manifest validates.
- Logs are available from the preview.

Weights and score caps must be documented beside the implementation before the
score is released publicly.

## 7. Scanner contract

V1 uses:

- Trivy for filesystem, dependency, secret, license, configuration, image, and
  SBOM analysis where supported.
- OSV-Scanner for ecosystem vulnerability matching and dependency analysis.
- Native read-only checks when they do not invoke project lifecycle scripts.

Scanner adapters must preserve the raw report and normalize findings using
stable fingerprints. A merged finding must retain every contributing scanner.

Semgrep support is optional until the selected rules and intended distribution
are confirmed compatible with their licenses. LaunchGuard must not silently
download rule sets with incompatible product-use terms.

## 8. AI contract

Ollama is the default local inference adapter. The model is user-configurable
and must not be bundled until its redistribution and commercial-use license is
verified.

AI may:

- Explain findings and logs.
- Rank remediation candidates without changing scanner severity.
- Identify likely build-failure causes.
- Propose a bounded unified diff.
- Draft deployment files from reviewed templates.
- Summarize verification and pull-request content.

AI must not:

- Execute an arbitrary shell string.
- Lower or suppress a scanner finding.
- Calculate readiness scores.
- Grant approval.
- Request or read unrestricted host environment variables.
- Access credentials.
- Change files outside the temporary worktree.
- Publish or deploy.
- Declare the repository secure.

Every model response used for automation must match a versioned JSON schema.
Invalid output is rejected once, retried with a correction prompt once, and
then surfaced as a non-fatal AI failure.

## 9. Data and auditability

Run state is stored locally in SQLite. Repository content and raw logs remain
local unless the user explicitly publishes a diff or report.

Secrets must be redacted before logs or source excerpts enter a model prompt.
The system must record:

- Input revision.
- Plan digest and approval.
- Tool, rule, model, and template versions.
- Commands and exit status.
- Network grants.
- Findings before and after repair.
- Patch digests.
- Artifact and image digests.
- Publication approval and result.

Run history must be deletable without affecting the original repository.

## 10. Failure behavior

- Missing optional scanner: continue with a degraded-coverage warning.
- Missing required runtime: stop before approval and provide installation
  guidance.
- Ollama unavailable: continue deterministically without AI remediation.
- Timeout or resource limit: stop the process tree, preserve logs, and mark the
  plan failed.
- Network denial: report the requested destination; never enable access
  automatically.
- Failed cleanup: surface affected container, volume, and worktree identifiers.
- Scanner disagreement: preserve both findings and apply the more restrictive
  deployment block until reviewed.
- Provider validation failure: retain local artifacts and do not publish.

## 11. V1 acceptance criteria

- Correctly classify at least 95% of a labeled supported-stack corpus.
- Produce schema-valid plans for at least 90% of the corpus.
- Preview at least 80% of supported projects in the evaluation corpus.
- Prevent every isolation fixture from reading blocked host paths, credentials,
  metadata endpoints, and unapproved network destinations.
- Never apply a model patch outside a temporary worktree.
- Produce identical readiness scores for identical deterministic inputs.
- Complete the core workflow with no paid model API.
- Require an auditable approval before every trust-boundary transition.

Targets are goals until measured. Published results must include corpus,
hardware, tool versions, failure definitions, and raw aggregate counts.

## 12. References

- [Tauri](https://tauri.app/)
- [Podman](https://podman.io/)
- [Trivy](https://www.trivy.dev/)
- [OSV-Scanner](https://google.github.io/osv-scanner/)
- [Ollama local API](https://docs.ollama.com/api/introduction)
- [Cloudflare Pages limits](https://developers.cloudflare.com/pages/platform/limits/)
- [Render free-service limitations](https://render.com/docs/free)
