# LaunchGuard

[![Documentation](https://github.com/bananatruck/launchguard/actions/workflows/docs.yml/badge.svg)](https://github.com/bananatruck/launchguard/actions/workflows/docs.yml)
[![Rust](https://github.com/bananatruck/launchguard/actions/workflows/rust.yml/badge.svg)](https://github.com/bananatruck/launchguard/actions/workflows/rust.yml)

**A local-first deployment intelligence platform for unfinished software
projects.**

> [!IMPORTANT]
> Phases 1 and 2 audit and plan only. LaunchGuard reports what trusted scanners
> found and what it proposes to run. It does not build, test, install, repair,
> or deploy repository code, and it never claims a project is secure.

LaunchGuard inspects a local repository or GitHub URL, determines how the
project is built, normalizes security findings, tests it in an isolated
environment, uses optional local AI to diagnose failures, and generates a
reviewable deployment pull request.

![The LaunchGuard pipeline, stage by stage, showing what each one requires](docs/assets/pipeline.svg)

LaunchGuard is not an unattended production deployment service. Its most
privileged outcome is a user-approved pull request containing tested
deployment configuration.

## How it works

Every stage produces a typed, versioned record, and nothing that changes the
world happens without an approval bound to a content digest.

![Terminal session showing launchguard ship guiding a project to a pull request](docs/assets/terminal.svg)

Credentials are requested once, at publication, and never before. Everything up
to that point runs unauthenticated on any machine.

## Two ways to run it

![Track A deploys with only the binary; Track B adds local verification with a container runtime](docs/assets/tracks.svg)

Provider build systems compile from source, so a local sandbox verifies a
deployment rather than being required to produce one. Track A therefore reaches
a live URL with nothing installed but the binary. Track B adds a container
runtime and proves the build before anything is published.

## Product principles

- **Deterministic evidence first.** Manifests, scanners, tests, and health
  checks are authoritative. AI is an explanation and remediation layer.
- **Local and free by default.** Core analysis, local inference, and preview do
  not require a paid API or subscription.
- **Constrained autonomy.** The engine may iterate inside an approved sandbox,
  but it cannot approve commands, credentials, publication, or paid resources.
- **No unknown code on the host.** Builds execute through a rootless OCI
  runtime using a staged workspace and explicit resource policy.
- **Everything is reviewable.** Commands, generated files, findings, model
  proposals, and verification results are included in an audit record.

## V1 capability

The first working release is designed for Linux, macOS, and Windows and
supports:

- React/Vite static applications.
- Next.js applications with explicit static or server classification.
- FastAPI services.
- Rust Axum services.
- Trivy and OSV-Scanner findings normalized into one schema.
- Rootless Podman on Linux and Podman Machine on macOS and Windows.
- Optional local inference through Ollama.
- Local preview, health checks, bounded repair attempts, and GitHub pull
  request generation.
- Cloudflare Pages and Render configuration generation.

Direct infrastructure provisioning, Kubernetes, Terraform, arbitrary
monorepos, and guaranteed execution of deliberately hostile code are not v1
features.

## Planned architecture

```mermaid
flowchart LR
    UI[Tauri desktop] --> Engine[Rust engine]
    CLI[CLI] --> Engine
    Engine --> Detect[Project detector]
    Engine --> Policy[Policy engine]
    Engine --> Scan[Scanner adapters]
    Engine --> AI[Local AI adapter]
    Policy --> Runtime[OCI runtime adapter]
    Runtime --> Linux[Rootless Podman]
    Runtime --> VM[Podman Machine]
    Engine --> Git[Temporary Git worktree]
    Git --> PR[Reviewed pull request]
```

The Rust engine is interface-agnostic. Tauri and the CLI consume the same
typed events and operations rather than implementing separate workflows.

## Quick start

Once a release is published, no toolchain is needed:

```bash
curl -fsSL https://raw.githubusercontent.com/bananatruck/launchguard/main/install.sh | sh
launchguard doctor
launchguard setup
launchguard audit ./path/to/project
```

The installer verifies the published SHA-256 before installing and refuses to
continue on a mismatch. Binaries are unsigned, so macOS and Windows may warn on
first run. Read [`install.sh`](install.sh) before piping it to a shell — it is
deliberately short enough to audit.

### From source

Building requires Rust 1.97.1. The repository pins the toolchain and commits its
dependency lockfile. Trivy and OSV-Scanner are optional; a missing scanner
degrades coverage instead of failing the run.

```bash
cargo build --locked
cargo run --locked -- doctor
cargo run --locked -- setup
cargo run --locked -- audit ./path/to/project --format json
cargo run --locked -- audit ./path/to/project --scanner trivy --scanner osv-scanner
cargo run --locked -- audit https://github.com/owner/public-repository
cargo run --locked -- plan ./path/to/project --format markdown
cargo run --locked -- history
cargo run --locked -- status <run-id> --format markdown
cargo run --locked -- schema execution-plan
```

The `doctor` command probes this host and reports which delivery tracks it can
run. It never blocks, installs, or changes anything, and it succeeds even when
nothing is installed — a missing capability is an outcome to report, not a
reason to refuse work.

The `setup` command installs the scanners this host is missing, from versions
and SHA-256 digests compiled into the release. Verification happens before a
binary is made executable, a mismatch aborts and keeps nothing, and everything
lands in a private directory without needing elevation. A container runtime and
a model server are documented rather than installed, because both need
elevation or very large downloads.

The `audit` command:

- Accepts a local directory or root URL for a public GitHub repository.
- Detects React/Vite, Next.js, FastAPI, and Rust/Axum.
- Reports competing supported classifications as `needs_confirmation`.
- Runs the trusted scanners you select, without a shell and with bounded output.
- Normalizes findings into one schema with stable, scanner-neutral fingerprints.
- Keeps raw scanner reports in a private, content-addressed local store.
- Generates a content-addressed execution plan that requires approval.
- Scores readiness deterministically, with no model involved.
- Records the whole run in SQLite unless `--no-history` is used.
- Writes structured diagnostics to standard error, preserving JSON on standard
  output.

The `plan` command generates and prints a reviewed execution plan without
running scanners or project code.

Set `LAUNCHGUARD_DATABASE` or pass `--database` to choose the history file, and
`LAUNCHGUARD_TRIVY` or `LAUNCHGUARD_OSV_SCANNER` to pin scanner executables.
Only environment variable names are collected; values from `.env` files are
never read.

See the [Phase 1](docs/PHASE_1.md) and [Phase 2](docs/PHASE_2.md)
implementation guides for detector contracts, scanner behavior, plan templates,
scoring, limits, and known limitations.

## Autonomy boundary

| Operation | Automatic | Approval required |
| --- | --- | --- |
| Read-only detection and scanning | Yes | No |
| Generate a command plan | Yes | No |
| Execute commands in a restricted preview | After plan approval | Once per plan |
| Retry verified repairs | Up to three attempts | Covered by approved plan |
| Enable package-registry network access | No | Yes |
| Modify the original checkout | No | Yes |
| Push a branch or open a pull request | No | Yes |
| Read credentials or provision infrastructure | No | Always |

Publication is gated in three levels, so that missing evidence and confirmed
danger are never treated the same way.

![Publication gating: hard block, overridable soft block, and clear](docs/assets/gating.svg)

See the full [product specification](docs/SPECIFICATION.md) and
[security model](docs/SECURITY_MODEL.md).

## What “free” means

LaunchGuard is intended to have zero mandatory software, inference, API, or
hosting spend for local audit and preview. This does not include hardware,
electricity, domains, code-signing certificates, paid cloud resources, or
provider usage beyond free-tier limits.

Users supply their own provider accounts and credentials. A deployment adapter
must display cost and free-tier limitations; it may never label an unknown
provider operation as free.

The detailed contract is in
[System requirements and cost model](docs/SYSTEM_REQUIREMENTS.md).

## Documentation

- [Product specification](docs/SPECIFICATION.md)
- [Security model](docs/SECURITY_MODEL.md)
- [System requirements and cost model](docs/SYSTEM_REQUIREMENTS.md)
- [Roadmap](docs/ROADMAP.md)
- [Phase 1 implementation](docs/PHASE_1.md)
- [Phase 2 implementation](docs/PHASE_2.md)
- [Phase 3 design](docs/PHASE_3.md)
- [ProjectProfile v1 JSON Schema](schemas/project-profile-v1.schema.json)
- [Finding v1 JSON Schema](schemas/finding-v1.schema.json)
- [ExecutionPlan v1 JSON Schema](schemas/execution-plan-v1.schema.json)
- [ReadinessAssessment v1 JSON Schema](schemas/readiness-assessment-v1.schema.json)
- [Degradation v1 JSON Schema](schemas/degradation-v1.schema.json)
- [CapabilityReport v1 JSON Schema](schemas/capability-report-v1.schema.json)
- [ProvisionedTool v1 JSON Schema](schemas/provisioned-tool-v1.schema.json)
- [Contributing](CONTRIBUTING.md)

## Status

Phases 1 and 2 are complete.

Phase 1 classified 40 of 40 supported fixtures correctly and failed closed on
all seven safety fixtures. See the
[Phase 1 evaluation report](docs/evaluation/phase-1.md).

Phase 2 produced a schema-valid execution plan for 40 of 40 supported fixtures
with Trivy 0.72.0 and OSV-Scanner 2.4.0 running for real, reproduced every plan
and assessment digest across repeated runs, and refused to plan an ambiguous
project. See the [Phase 2 evaluation report](docs/evaluation/phase-2.md) for
the environment, raw counts, smoke checks, the four defects that real scanner
runs exposed, and limitations.

Phase 3 distribution and capability discovery is next. See the
[Phase 3 design](docs/PHASE_3.md).

The roadmap was reordered after Phase 2: the deployment path now precedes
isolated preview, because provider build systems compile from source, so local
execution verifies a deployment rather than being required to produce one.
Gating the whole product on the heaviest prerequisite would have made the
deterministic security work unreachable for most users.

No LaunchGuard release has yet executed a project command.

## License

LaunchGuard is licensed under the [MIT License](LICENSE). Third-party scanners,
rules, local models, container runtimes, and deployment providers retain their
own licenses and terms.
