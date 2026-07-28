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

**Status: complete.** See the
[Phase 2 evaluation report](evaluation/phase-2.md).

- Add Trivy and OSV-Scanner adapters.
- Preserve raw reports and normalize stable `Finding` records.
- Generate content-addressed `ExecutionPlan` records from reviewed templates.
- Implement deterministic readiness checks without a model.

**Exit criteria:** schema-valid plans for at least 90% of the supported corpus
and deterministic score reproduction.

## Delivery tracks

From Phase 3 onward the engine exposes two tracks. Provider build systems
compile from source, so local execution verifies a deployment but is not
required to produce one.

| Track | Requires | Reaches |
| --- | --- | --- |
| A: deploy | The `launchguard` binary only | Detect, scan, plan, generate configuration, open a pull request, live URL |
| B: verify | Track A plus a container runtime | Everything in Track A, plus a locally proven build, test, and health check before publication |

Track A must remain complete without a container runtime, a local model, or a
Rust toolchain. Missing capability reduces the readiness score and is reported
as a degradation; it never removes the path to a deployment.

## Phase 3: Distribution and capability discovery

**Status: next.**

- Publish checksummed prebuilt binaries and a one-line install script for
  Linux, macOS, and Windows.
- Add `launchguard doctor` to probe the host and publish a `CapabilityReport`.
- Add `launchguard setup` to fetch pinned, checksum-verified scanner binaries
  into a local data directory.
- Route work by measured capability instead of gating on prerequisites.

**Exit criteria:** a user with no Rust toolchain, no scanners, and no container
runtime reaches a readiness report on all three platforms, and every probe
result is a typed record rather than console text.

## Phase 4: Deployment intent and configuration generation

**Status: implemented, pending real-project validation.** Measured 40/40
schema-valid configurations over the supported corpus. That corpus is synthetic,
so the number reflects template and adapter correctness rather than real-world
provider coverage.

- Add the versioned `DeploymentIntent` record and `launchguard target`.
- Implement provider adapters for Cloudflare Pages, Netlify, and Render.
- Generate Dockerfiles, `.dockerignore`, environment templates, and provider
  manifests from reviewed templates.
- Validate every generated artifact locally without contacting a provider.
- Surface live free-tier limits and cost from official provider documentation.

**Exit criteria:** schema-valid deployment configuration for at least 90% of
the supported corpus, validated locally, with no artifact asserting a cost or
limit that is not sourced from current provider documentation.

## Phase 5: Guided deployment and pull requests

**Status: publication implemented, guided flow pending.** `launchguard pr`
plans and opens an approval-gated pull request. The `ship` wizard and the
`summary` artifact remain, and device-flow sign-in needs a registered
`LaunchGuard` OAuth application before it can replace a supplied token.

- Add the `launchguard ship` guided flow with a non-interactive equivalent.
- Add GitHub device-flow authentication with scoped permission previews.
- Split publication gating into hard block, overridable soft block, and clear.
- Record every override and unverified deployment in the pull-request body.
- Guarantee idempotency so a repeated run never opens a duplicate request.
- Emit a local deployment summary artifact from the `DeploymentRecord`.

**Exit criteria:** a real repository reaches a live URL through a user-approved
pull request, publication never occurs without an approval event, rollback
instructions are present, and no credential is requested before publication.

## Phase 6: Isolated preview and verification

- Implement the OCI runtime trait with Podman, Docker, and absent backends.
- Support native rootless Podman on Linux.
- Support Podman Machine on macOS and Windows.
- Enforce mounts, capabilities, limits, timeouts, and network policy.
- Stream logs and run health checks.
- Require a passing preview before publication whenever a runtime is present,
  subject to a recorded override.

**Exit criteria:** all isolation fixtures fail closed on every supported
platform and backend, and at least 80% of corpus projects preview successfully.

## Phase 7: Local AI and bounded repair

- Add a pluggable inference adapter covering local, user-supplied hosted, and
  absent backends, defaulting to Ollama.
- Implement redaction and source-labeled retrieval.
- Validate structured diagnoses and unified diffs.
- Apply proposals only in temporary Git worktrees.
- Rebuild, test, and rescan for at most three attempts.

**Exit criteria:** no model output crosses a policy boundary, every accepted
patch has deterministic verification, no adapter transmits repository content
without an explicit per-session grant, and remediation success is measured
against a fixed failure corpus.

## Phase 8: Tauri desktop application

- Build a cross-platform Tauri interface over the existing engine.
- Present project evidence, findings, plans, diffs, and progress events.
- Add accessible approval dialogs for execution, network, and publication.
- Package unsigned development builds for Linux, macOS, and Windows.

**Exit criteria:** CLI and desktop produce equivalent engine records for the
same revision and policy.

## Later candidates

- Vercel adapter, once non-commercial Hobby-tier terms can be surfaced clearly
  enough that a user cannot deploy a commercial project by accident.
- Fly.io and other always-on server providers.
- Signed and notarized distribution for macOS and Windows.
- Shareable deployment summaries published to external platforms.
- PostgreSQL and migration detection.
- Multi-service Compose generation.
- Semgrep integration with license-compatible rule selection.
- SBOM attestations and signed provenance.
- Provider cost estimation.
- GitHub Actions generation.
- Plugin SDK.
- Kubernetes and Terraform adapters.
- Direct deployment under a separately reviewed specification.

## Evaluation reports

Each milestone report must publish the corpus definition, revisions, hardware,
tool versions, raw aggregate counts, failure taxonomy, and limitations.
Targets must remain labeled as targets until achieved.
