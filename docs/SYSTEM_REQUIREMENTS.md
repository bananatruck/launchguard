# System Requirements and Cost Model

## Support promise

LaunchGuard v1 targets 64-bit Linux, macOS, and Windows desktop systems.
Interface portability does not mean identical execution backends:

- Linux uses native rootless Podman, or Docker when Podman is absent.
- macOS uses a Podman Machine Linux VM, or Docker Desktop.
- Windows uses a Podman Machine Linux VM with supported Windows
  virtualization, or Docker Desktop.

Podman remains the preferred backend because rootless operation is the default
rather than an option. Docker is a supported backend, not a later candidate,
because far more users already have it installed and excluding them would
contradict the accessibility goal.

The runtime adapter also has an absent backend. A host with no container runtime
runs the deployment track without local verification, as described in the
[roadmap delivery tracks](ROADMAP.md).

## Distribution

LaunchGuard publishes checksummed prebuilt binaries. A Rust toolchain is
required only to build from source, never to use a release.

Binaries are unsigned in v1. Apple notarization and Windows code signing are
recorded below as costs outside the free contract.

## Hardware profiles

| Profile | CPU | Memory | Free storage | Local model | Intended workload |
| --- | --- | --- | --- | --- | --- |
| Minimum | 4 modern 64-bit cores | 8 GiB | 20 GiB | Optional 3B-class Q4 | Audit and small previews |
| Recommended | 8 cores | 16 GiB | 50 GiB | 7–8B-class Q4 | Full v1 workflow |
| Heavy | 12+ cores | 32 GiB | 100 GiB | 12–14B-class Q4 | Larger repos and parallel evaluation |

GPU acceleration is optional. Approximately 8 GiB of compatible VRAM is a
useful recommended target for a 7–8B quantized coding model, but model-specific
requirements take precedence.

LaunchGuard must detect insufficient disk space and memory before starting a
preview. It should serialize the model and build workload on constrained
machines rather than overcommitting memory.

## Platform requirements

### Linux

- Maintained 64-bit distribution.
- Kernel support for user namespaces and cgroups v2.
- Rootless Podman and subordinate UID/GID configuration.
- Tauri system webview and build prerequisites when using the desktop app.
- Ollama only when local AI is enabled.

### macOS

- Maintained macOS release on Apple Silicon or supported Intel hardware.
- Hardware virtualization.
- Podman CLI and a running Podman Machine.
- Tauri/WebKit build prerequisites for source builds.
- Ollama only when local AI is enabled.

Unsigned local development is free. Broad trusted distribution may require
Apple signing and notarization through the paid Apple Developer Program.

### Windows

- Maintained 64-bit Windows 10 or Windows 11 release supported by the selected
  Podman version.
- Hardware virtualization enabled.
- Podman CLI/Desktop and a running Podman Machine.
- WebView2 and Tauri build prerequisites.
- Ollama only when local AI is enabled.

Trusted public distribution may require a separately obtained code-signing
certificate.

## Required external tools

The engine must detect tools and record versions rather than assuming they are
installed.

| Tool | Required | Auto-provisioned | Purpose |
| --- | --- | --- | --- |
| Git | Yes | No | Revision pinning and temporary worktrees |
| Podman or Docker | Preview and Repair | No | OCI execution |
| Trivy | Audit | Yes | Security, secret, configuration, image, and SBOM scans |
| OSV-Scanner | Audit | Yes | Ecosystem vulnerability analysis |
| Ollama | No | No | Local explanation and remediation proposals |
| GitHub account | Pull request only | No | User-approved publication |

Only tools distributed as checksum-verified static binaries that install without
elevation are auto-provisioned. A container runtime and a model server are
documented, never installed silently.

Missing Ollama reduces capability but must not block deterministic Audit, Plan,
or Preview. A missing container runtime removes local verification but must not
block Audit, Plan, deployment intent, or publication.

Publication requires no separately installed GitHub tooling. Authentication uses
the device-authorization flow against the GitHub API.

## Local AI profile

LaunchGuard communicates with an Ollama-compatible loopback endpoint. The
default endpoint is configurable and must never silently switch to a cloud
provider.

The user selects the model. LaunchGuard records its name and digest when
available and warns when the model license is unknown. A model must not be
bundled with LaunchGuard until redistribution and intended-use terms have been
reviewed.

To fit within the recommended profile:

- Retrieve relevant files instead of sending the entire repository.
- Redact secrets before context construction.
- Bound prompt and response sizes.
- Unload or pause inference during memory-heavy builds when supported.
- Cache deterministic retrieval, not model conclusions.
- Fall back to scanner- and template-based guidance when inference fails.

## Definition of free

LaunchGuard operates no server, database, or hosted inference of its own. There
is no LaunchGuard account and no LaunchGuard backend to pay for, which is what
makes a permanently free tier sustainable rather than promotional. Any future
change that introduces a hosted component must be treated as a change to this
contract.

The complete deployment track — capability discovery, provisioning, audit,
planning, deployment intent, configuration generation, and a published pull
request producing a live static site — costs nothing beyond hardware and
internet access. A container runtime and a local model add verification and
repair; neither is required to reach a deployment.

“Free” means the local core workflow has no mandatory subscription,
per-request model charge, or hosted backend:

- Rust, Tauri, React, SQLite, Podman, Trivy, OSV-Scanner, and the Ollama local
  API can be used without a LaunchGuard subscription.
- Public repositories can use standard GitHub-hosted Actions without consuming
  private-repository minute quotas.
- Deployment adapters may target provider free tiers.

“Free” does not mean zero total cost. Users remain responsible for:

- Computer hardware, storage, electricity, and internet access.
- Model-specific licenses and resource requirements.
- Domains and certificates not supplied by a provider.
- Apple or Windows trusted-distribution signing.
- Private CI usage beyond included quotas.
- Cloud usage beyond provider free-tier limits.
- Persistent databases and always-on production services.

## Provider limitations

Provider facts change over time. Adapters must query or link current official
documentation and show limitations before publication.

V1 ships three adapters: Cloudflare Pages and Netlify for static output, and
Render for server output.

As of the specification date:

- Cloudflare Pages has a free-plan build and project allowance suitable for
  portfolio previews, not unlimited multi-tenant deployment.
- Netlify has a free-plan bandwidth and build-minute allowance.
- Render free web services sleep when idle and use ephemeral local filesystems;
  free PostgreSQL is temporary.
- GitHub Actions is free on standard hosted runners for public repositories;
  private repositories use account quotas.

Static output has a genuinely free steady state. Server output does not: the
honest free option sleeps when idle, and avoiding that costs a few dollars per
month per always-on service. An adapter must present that tradeoff before
publication rather than after the first cold start.

Vercel is deliberately excluded from v1. Its Hobby tier restricts commercial
use, which is an unsafe default for a tool whose user may not know whether their
project counts. It is a later candidate, contingent on surfacing that restriction
clearly enough that a user cannot accept it unknowingly.

LaunchGuard must not encode “free forever” into a readiness decision.

## Performance expectations

No performance number is a product claim until measured. Evaluation reports
must name:

- Host hardware and operating system.
- Container runtime and VM configuration.
- Model and quantization.
- Scanner and database versions.
- Repository corpus and revision.
- Whether dependency caches were warm.
- Time spent in detection, scanning, build, inference, and verification.

The engine should expose resource and timing measurements needed to reproduce
those reports.

## Official references

- [Tauri prerequisites](https://tauri.app/start/prerequisites/)
- [Podman](https://podman.io/)
- [Ollama local API](https://docs.ollama.com/api/introduction)
- [GitHub Actions billing](https://docs.github.com/en/actions/concepts/billing-and-usage)
- [Cloudflare Pages limits](https://developers.cloudflare.com/pages/platform/limits/)
- [Render free-service limitations](https://render.com/docs/free)
- [Apple Developer Program](https://developer.apple.com/programs/whats-included/)
