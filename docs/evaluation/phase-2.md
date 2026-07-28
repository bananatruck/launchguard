# Phase 2 evaluation report

## Result

Phase 2 passed its roadmap gate on 2026-07-27.

| Gate | Required | Measured |
| --- | ---: | ---: |
| Schema-valid plans over the supported corpus | At least 90% | 40/40, 100% |
| Deterministic score reproduction | Identical digests | Identical across repeated runs |
| Ambiguous classification receives no plan | Fail closed | 1/1 refused |
| Both scanners complete on the corpus | Not gated | 40/40 |
| Locked workspace tests | Pass | 39/39 passed |
| Clippy | No warnings | Passed with `-D warnings` |
| Formatting | Clean | `cargo fmt --all --check` passed |
| RustSec audit | No known vulnerability | 0 vulnerabilities across 264 locked dependencies |

The plan-coverage figure counts only plans that validated against the bundled
`ExecutionPlan` v1 JSON Schema, which is what the roadmap gate asks for. A plan
that generated but failed schema validation would not have been counted.

This is a detector and template contract result over a synthetic corpus plus
two public repositories. It is not a claim about population-level accuracy,
scanner recall, or real-world deployment readiness.

## Evaluated revision

- Branch: `agent/phase-2-scanning-and-planning`
- Corpus schema: `1.0`
- Profile schema: `1.0`
- Finding, `ExecutionPlan`, `ReadinessAssessment`, and `Degradation` schemas:
  `1.0`
- Readiness policy: `2026-07-26.1`
- Reviewed template release: `2026-07-26.1`
- Supported corpus:
  [`phase1.json`](../../crates/launchguard-core/tests/corpus/phase1.json)

The corpus is the same 40 labeled fixtures used in Phase 1: 10 each for
React/Vite, Next.js, FastAPI, and Rust/Axum, plus seven fail-closed safety
fixtures.

## Environment

- Date: 2026-07-27
- Host: Linux 7.0.12-arch1-1, x86-64
- CPU: AMD Ryzen 9 8945HS, 8 cores and 16 threads
- Memory: 14 GiB available to the host
- Base container: `rust:1.97.1-bookworm`
- Base container digest:
  `sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa`
- `rustc`: 1.97.1, commit `8bab26f4f`
- Cargo: 1.97.1, commit `c980f4866`
- Cargo Audit: 0.22.2
- RustSec advisory database:
  `0bfde9d6a469ae503f8a6147c2dd552856cd5999`, 1170 advisories

Scanners were installed into the pinned base image and verified by checksum:

| Scanner | Version | Artifact | SHA-256 |
| --- | --- | --- | --- |
| Trivy | 0.72.0 | `trivy_0.72.0_Linux-64bit.tar.gz` | `bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea` |
| OSV-Scanner | 2.4.0 | `osv-scanner_linux_amd64` | `15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0` |

Trivy vulnerability database schema version 2, built `2026-07-27T19:20:18Z`.
OSV-Scanner matches against the upstream OSV service and reports no local
database version, so none is recorded.

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo audit
cargo build --locked --release
launchguard audit <path> --scanner trivy --scanner osv-scanner --format json
```

## Corpus results

Every supported fixture was audited with both scanners enabled.

| Measure | Count |
| --- | ---: |
| Fixtures audited | 40 |
| Audits exiting 0 | 40 |
| Schema-valid plans generated | 40 |
| Runs where both scanners completed | 40 |
| Runs reporting any degradation | 0 |
| Runs blocking preview | 1 |
| Findings reported across the corpus | 34 |
| Distinct plan digests | 37 |

Mean wall clock was 2.25 s per audit and the slowest fixture took 12.25 s,
which included the one-time Trivy database download.

Three fixtures share a plan digest with another fixture. That is expected: a
content-addressed plan is identical when the framework, package manager,
commands, limits, and revision are identical, and the corpus contains
detector-focused variants that differ only in evidence placement.

One fixture blocks preview: `fastapi-requirements-root`, whose pinned
`h11 0.9.0` carries the critical CVE-2025-43859. Its eight other findings, up
to high severity, block publication but not preview, which is the documented
policy. The remaining 39 fixtures completed both scanners with no blocking
finding.

## Real scanner behavior

A deliberately vulnerable fixture pinned `lodash@4.17.11`, `react@17.0.2`, and
`vite@2.9.12` with a synthetic GitHub personal access token in source.

| Measure | Result |
| --- | ---: |
| Findings after merge | 26 |
| Findings confirmed by both scanners | 23 |
| Duplicate vulnerability identifiers | 0 |
| Absolute host paths in public records | 0 |
| Secret detected | 1, critical, `src/main.ts:1` |
| Security score | 35% |
| Preview and publication | Both blocked |

The secret was retained as metadata only; the matched token text appears in no
finding, report, or history record.

## Determinism

Two consecutive audits of the same fixture with both scanners produced:

- identical plan digest
  `fc31038d58447501fb8e26ea53daffe690c915aedc03e8af837e02574aed5177`,
- identical findings digest
  `09b2ee65526208666b981a3554c203af5aa927f2cd4a437a334c96704ee9a8c0`,
- identical reproduction digest
  `9d39e5bf0761992da62646068556e2bc87c65df4389bdd4aff30f6ebef578848`,
- identical scores,
- and different raw artifact digests.

The last point is expected and is why the assessment digest excludes raw report
provenance: Trivy embeds a fresh report identifier and timestamp in every run,
so byte-identical raw reports are not achievable, while the normalized security
content is.

## Public repository smoke checks

Two public repositories were audited through the same acquisition path as the
CLI, with both scanners enabled.

| Repository | Resolved revision | Result |
| --- | --- | --- |
| `allaboutapps/react-starter` | `ff2ed47a42f7c84f99529bbb832bc78917d3b3c4` | `detected` React/Vite with pnpm; 97 findings, 49 confirmed by both scanners; preview blocked by 3 critical findings |
| `tiangolo/full-stack-fastapi-template` | `c9e70d65c74f7adda417fc8de0757207ff77514c` | `needs_confirmation`; no plan generated; 37 findings; preview blocked |

The React/Vite revision matches the one recorded in the
[Phase 1 report](phase-1.md), so the two phases describe the same snapshot.

The FastAPI template is a multi-component repository. Phase 2 preserved the
Phase 1 fail-closed behavior: competing classifications were retained, no
framework was selected, and no plan was generated, while scanning still
completed and reported findings.

That repository also produced disjoint scanner output: OSV-Scanner reported 30
vulnerabilities from `bun.lock` while Trivy reported 7 Dockerfile
misconfigurations and no dependency findings, because the evaluated Trivy
version does not parse `bun.lock`. No finding merged across scanners there.
This is a genuine coverage difference, not a normalization failure, and it is
the clearest argument in this evaluation for running both scanners.

These checks were not added to CI because external repositories, upstream
advisory data, and rate limits are nondeterministic.

## Non-execution

A fixture defining `preinstall`, `install`, `postinstall`, `build`, and `test`
scripts that each create a sentinel file was audited with both scanners. The
audit completed, classified the project, generated a plan, and produced
findings. The sentinel file was not created.

## Defects found and fixed during evaluation

Running real scanner binaries, rather than only checked-in fixtures, exposed
four defects that the fixture-based tests had not:

1. **Cross-scanner findings never merged.** OSV-Scanner reports absolute paths
   while Trivy reports scan-root-relative paths, and the fingerprint hashes the
   path. The vulnerable fixture produced 49 findings with 23 duplicated CVE
   identifiers and 0 merged records. Paths are now normalized against the
   repository root before fingerprinting, giving 26 findings, 23 of them
   confirmed by both scanners, and 0 duplicates. This also removed absolute
   host paths from public records. The checked-in OSV fixture used a relative
   path, which no real OSV-Scanner run emits, so the existing merge test passed
   while production behavior was broken; the fixture now matches real output.
2. **A clean Trivy scan was treated as a malformed report.** Trivy omits the
   `Results` key entirely when it finds nothing, and normalization required it.
   Every clean project was recorded as a rejected report: 39 of 40 corpus
   fixtures. An absent `Results` is now a clean scan, while a present
   non-array still fails closed.
3. **OSV-Scanner exit code 128 was treated as a failure.** That status means
   no package manifests were found, which is a completed scan of an empty
   ecosystem. It affected 34 of 40 corpus fixtures. It is now accepted as a
   completed scan with zero findings.
4. **Assessments did not reproduce.** `findings_digest` hashed
   `raw_artifact_digests`, and Trivy embeds a per-run report identifier and
   timestamp, so the digest changed on every run over unchanged inputs. The
   digest now covers the normalized security content only.

Before these fixes the corpus produced 39 degraded runs out of 40; after them,
zero. Each fix has a regression test named for the behavior it protects.

## Failure taxonomy

No supported corpus case failed. Fail-closed behavior was preserved:

- Ambiguous classification produced no plan and an explicit error.
- A profile with no reviewed template records a `plan_unavailable` degradation
  instead of ending the audit.
- A missing scanner executable records `scanner_unavailable`, completes the
  audit, leaves `completed_scanners` empty, and blocks preview. Verified end to
  end: with Trivy absent and OSV-Scanner present, the run still normalized 23
  findings, scored security at 30%, and blocked both preview and publication.
- An unknown Trivy schema version is rejected rather than guessed.
- A plan or assessment whose digest does not reproduce is never persisted.

## Limitations

- The supported corpus is synthetic and was designed from the documented
  detector and template contracts. It tests regressions and failure behavior,
  not population-level generalization.
- Only two public repositories were audited, and only one of them classified.
- Corpus fixtures declare dependencies without real resolved lockfile content,
  so they exercise the scanner pipeline rather than scanner recall. The 34
  corpus findings are not a meaningful vulnerability measurement.
- Scanner recall and precision were not evaluated. No labeled vulnerability
  ground truth was used, so this report makes no claim about what the scanners
  missed.
- Results are tied to the Trivy database built on 2026-07-27 and to OSV data
  retrieved the same day. Re-running later will legitimately differ.
- Linux only. macOS and Windows jobs are configured in CI but cannot be
  reported as observed here.
- Trivy license scanning is not enabled, so the `License` finding category is
  normalized but never populated in this evaluation.
- Phase 2 performs no build, test, container execution, or health check. A
  generated plan has never been run.
- A passing readiness score is not a security or deployment-readiness claim.
