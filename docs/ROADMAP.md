# LaunchGuard Roadmap

Roadmap items are capability gates, not calendar promises. A phase is complete
only when its acceptance criteria and safety requirements are measured.

## Phase 0: Specification foundation

- Publish the product, security, system, and cost contracts.
- Establish normative terminology and v1 non-goals.
- Validate Markdown and internal links in CI.
- Record architecture decisions before introducing executable code.

**Exit criteria:** documentation CI passes and every trust-boundary transition
has a documented approval rule.

## Phase 1: Read-only Rust engine

**Status: complete.** See the
[Phase 1 evaluation report](evaluation/phase-1.md).

- Create a Rust workspace with engine and CLI crates.
- Implement repository acquisition without executing project code.
- Detect React/Vite, Next.js, FastAPI, and Rust/Axum projects.
- Emit versioned `ProjectProfile` JSON with evidence and confidence.
- Add SQLite run history and structured tracing.

**Exit criteria:** at least 95% classification accuracy on a labeled supported
corpus, with ambiguous cases reported rather than guessed.

## Phase 2: Security normalization and planning

**Status: next.**

- Add Trivy and OSV-Scanner adapters.
- Preserve raw reports and normalize stable `Finding` records.
- Generate content-addressed `ExecutionPlan` records from reviewed templates.
- Implement deterministic readiness checks without a model.

**Exit criteria:** schema-valid plans for at least 90% of the supported corpus
and deterministic score reproduction.

## Phase 3: Cross-platform isolated preview

- Implement the OCI runtime trait.
- Support native rootless Podman on Linux.
- Support Podman Machine on macOS and Windows.
- Enforce mounts, capabilities, limits, timeouts, and network policy.
- Stream logs and run health checks.

**Exit criteria:** all isolation fixtures fail closed on every supported
platform and at least 80% of corpus projects preview successfully.

## Phase 4: Local AI and bounded repair

- Add an Ollama-compatible local adapter.
- Implement redaction and source-labeled retrieval.
- Validate structured diagnoses and unified diffs.
- Apply proposals only in temporary Git worktrees.
- Rebuild, test, and rescan for at most three attempts.

**Exit criteria:** no model output crosses a policy boundary, every accepted
patch has deterministic verification, and remediation success is measured
against a fixed failure corpus.

## Phase 5: Tauri desktop application

- Build a cross-platform Tauri interface over the existing engine.
- Present project evidence, findings, plans, diffs, and progress events.
- Add accessible approval dialogs for execution, network, and publication.
- Package unsigned development builds for Linux, macOS, and Windows.

**Exit criteria:** CLI and desktop produce equivalent engine records for the
same revision and policy.

## Phase 6: Deployment pull requests

- Generate Docker, environment, Cloudflare Pages, and Render files.
- Validate generated artifacts locally.
- Add scoped GitHub authentication and permission previews.
- Create branches and pull requests only after explicit approval.
- Include the reproducibility record in pull-request output.

**Exit criteria:** generated configurations validate for the supported corpus,
publication never occurs without an approval event, and rollback instructions
are present.

## Later candidates

- PostgreSQL and migration detection.
- Multi-service Compose generation.
- Semgrep integration with license-compatible rule selection.
- SBOM attestations and signed provenance.
- Additional container runtimes.
- Provider cost estimation.
- GitHub Actions generation.
- Plugin SDK.
- Kubernetes and Terraform adapters.
- Direct deployment under a separately reviewed specification.

## Evaluation reports

Each milestone report must publish the corpus definition, revisions, hardware,
tool versions, raw aggregate counts, failure taxonomy, and limitations.
Targets must remain labeled as targets until achieved.
