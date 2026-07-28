# Phase 3: Distribution and capability discovery

Phase 3 makes LaunchGuard reachable. Phases 1 and 2 produce useful records but
require a Rust toolchain to build and manually installed scanners to run, which
places six prerequisites between a new user and any result. Phase 3 reduces
that to one download and routes all later work by measured host capability.

Phase 3 executes no repository code and contacts no deployment provider.

## Objective

A user with no Rust toolchain, no scanners, and no container runtime should
reach a readiness report on Linux, macOS, or Windows without reading
documentation first.

This reorders the roadmap deliberately. Isolated preview moved after the
deployment path because provider build systems compile from source: local
execution raises confidence in a deployment but is not required to produce one.
Shipping preview first would have gated the entire product on the single
heaviest prerequisite.

## Distribution

Releases publish prebuilt binaries for:

| Platform | Target triple |
| --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-gnu` |
| Linux ARM64 | `aarch64-unknown-linux-gnu` |
| macOS Apple Silicon | `aarch64-apple-darwin` |
| macOS Intel | `x86_64-apple-darwin` |
| Windows x86-64 | `x86_64-pc-windows-msvc` |

Every artifact publishes a SHA-256 checksum. The install script verifies the
checksum before moving a binary into place and refuses to continue on a
mismatch.

Binaries are unsigned in v1. Signed and notarized distribution requires a paid
Apple Developer Program membership and a Windows code-signing certificate, both
of which are recorded in
[System requirements and cost model](SYSTEM_REQUIREMENTS.md) as user or
maintainer costs outside the free contract. The install script must state that
binaries are unsigned rather than instructing users to bypass a security
warning.

LaunchGuard does not self-update. An update is an explicit user action, because
silent replacement of a binary that later requests credentials is a supply-chain
risk disproportionate to the convenience.

## Capability discovery

`launchguard doctor` probes the host and emits a versioned `CapabilityReport`.
It never blocks, never installs, and never mutates the host.

Probed capabilities:

| Capability | Detected by | Required for |
| --- | --- | --- |
| Git | Executable and version | Revision pinning and worktrees |
| Container runtime | Podman, then Docker | Track B preview |
| Trivy | Executable and version | Vulnerability, secret, and configuration findings |
| OSV-Scanner | Executable and version | Ecosystem vulnerability findings |
| Local inference | Ollama loopback endpoint | Explanation and repair |
| Disk and memory | Platform query | Preview admission control |

Each probe records the executable path, reported version, and outcome. A probe
that fails records why. Version parsing reuses the approach already proven in
`ScannerRunner::provenance`, which executes only a tool's own version
subcommand and never touches repository content.

The report names the tracks the host can currently run and the specific missing
capability blocking any track it cannot. Capability is measured, never assumed
from the operating system.

## Provisioning

`launchguard setup` fetches missing tools that can be safely obtained without a
system package manager.

| Tool | Auto-provisioned | Reason |
| --- | --- | --- |
| Trivy | Yes | Single static binary, published checksums |
| OSV-Scanner | Yes | Single static binary, published checksums |
| Container runtime | No | System-level installation, requires elevation |
| Ollama | No | System service and large model downloads |
| Git | No | Expected system tooling |

Provisioned binaries are pinned to an exact version compiled into the release,
downloaded over HTTPS, verified against an expected SHA-256 before use, and
written to a user-private data directory with an atomic no-clobber rename. This
is the procedure already used for raw scanner reports in `ArtifactStore`, and
the same reasoning applies: content addressing plus restrictive permissions.

A checksum mismatch is a hard failure. Setup never falls back to an unverified
download and never executes an installer script fetched at runtime.

For tools it cannot provision, `setup` prints the official installation command
for the detected platform and exits successfully. Refusing to run because
Podman is absent would defeat the purpose of the phase.

## Capability-routed execution

Existing commands consult the capability report instead of assuming tools
exist. The degradation machinery added in Phase 2 already carries this: a
missing scanner records a typed `Degradation`, completes the run, and prevents
`security.scanner_coverage` from passing, so a degraded run cannot present
itself as a clean scan.

Phase 3 extends that vocabulary with capability-derived degradation kinds and
threads the capability report through `RunRecord`, so a stored run states which
capabilities were present when it was produced. A run audited without a
container runtime must remain distinguishable from one that was fully verified,
years later, from history alone.

## Public records

| Record | Schema | Emitted by |
| --- | --- | --- |
| `CapabilityReport` | `capability-report-v1` | `doctor` and every capability-routed command |
| `ProvisionedTool` | `provisioned-tool-v1` | `setup` |

Both follow the established contract: an explicit `schema_version`, rejection of
unknown versions, and no absolute host paths in published fields. Path handling
reuses the relativization added in Phase 2 after real scanner output leaked
absolute paths into public records.

## Security considerations

Phase 3 introduces the first capability that downloads and executes third-party
binaries, which is a genuine expansion of the trust boundary and is recorded in
the [security model](SECURITY_MODEL.md).

Controls:

- Versions and checksums are compiled into the release, not fetched at runtime.
- Downloads use HTTPS with a bounded size, a request timeout, and a redirect
  limit, matching the existing repository acquisition bounds.
- Verification precedes execution. A mismatch aborts and retains nothing.
- Provisioned binaries live in a user-private directory, never a system path.
- `setup` requires no elevation. A tool needing elevation is not provisioned.
- Probing runs only a tool's own version subcommand, with no repository input.
- No credential is requested, read, or stored in this phase.

The install script itself is the weakest link, because a user pipes it from the
network. It must be short enough to read, verify checksums, pin a release, and
work when downloaded and inspected before execution.

## Exit criteria

- Checksummed binaries publish for all five targets, and the install script
  verifies them on Linux, macOS, and Windows.
- A host with no Rust toolchain, no scanners, and no container runtime produces
  a readiness report using only the released binary.
- `doctor` correctly reports every capability present and absent across a
  documented probe matrix, including a host with Docker but not Podman.
- `setup` provisions both scanners from a clean host and fails closed on an
  induced checksum mismatch.
- Stored runs record the capabilities present when they were produced.
- No command in this phase requests a credential or executes repository code.

## Non-goals

- Container runtime installation, which requires elevation.
- Model downloads, which are large and license-encumbered.
- Signed or notarized distribution.
- Self-update.
- Any provider or GitHub contact.
- Any execution of repository code, which begins in Phase 6.
