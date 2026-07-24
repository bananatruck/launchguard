# System Requirements and Cost Model

## Support promise

LaunchGuard v1 targets 64-bit Linux, macOS, and Windows desktop systems.
Interface portability does not mean identical execution backends:

- Linux uses native rootless Podman.
- macOS uses a Podman Machine Linux VM.
- Windows uses a Podman Machine Linux VM with supported Windows
  virtualization.

Docker support may be added through the runtime adapter, but it is not the
required v1 backend.

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

| Tool | Required | Purpose |
| --- | --- | --- |
| Git | Yes | Revision pinning and temporary worktrees |
| Podman | Preview and Repair | Rootless OCI execution |
| Trivy | Audit | Security, secret, configuration, image, and SBOM scans |
| OSV-Scanner | Audit | Ecosystem vulnerability analysis |
| Ollama | No | Local explanation and remediation proposals |
| GitHub CLI or API token | Pull request only | User-approved publication |

Missing Ollama reduces capability but must not block deterministic Audit, Plan,
or Preview.

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

As of the specification date:

- Cloudflare Pages has a free-plan build and project allowance suitable for
  portfolio previews, not unlimited multi-tenant deployment.
- Render free web services sleep when idle and use ephemeral local filesystems;
  free PostgreSQL is temporary.
- GitHub Actions is free on standard hosted runners for public repositories;
  private repositories use account quotas.

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
