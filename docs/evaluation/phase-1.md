# Phase 1 evaluation report

## Result

Phase 1 passed its roadmap gate on 2026-07-26.

| Gate | Required | Measured |
| --- | ---: | ---: |
| Supported classification accuracy | At least 95% | 40/40, 100% |
| Ambiguous classification behavior | No silent selection | 1/1 reported `needs_confirmation` with both candidates |
| Incomplete or unsupported evidence | Fail closed | 6/6 reported `unsupported` |
| Locked workspace tests | Pass | 15/15 passed |
| Clippy | No warnings | Passed with `-D warnings` |
| RustSec audit | No known vulnerability | 0 vulnerabilities across 221 locked dependencies |

The accuracy result satisfies the Phase 1 exit criterion. It is a detector
contract result over a synthetic corpus, not a claim of 100% accuracy on
arbitrary real repositories.

## Evaluated revision

- Branch: `agent/phase-1-read-only-engine`
- Implementation revision: `b1bca41827b6a3a9f1f886903925e3d4987c6061`
- Corpus schema: `1.0`
- Profile schema: `1.0`
- Supported corpus:
  [`phase1.json`](../../crates/launchguard-core/tests/corpus/phase1.json)

The corpus contains 10 labeled fixtures for each supported classification:
React/Vite, Next.js, FastAPI, and Rust/Axum. Seven separate safety fixtures
cover competing classifications, missing required evidence, an unsupported
Node framework, and Axum appearing only as a development or build dependency.

## Environment

- Date: 2026-07-26
- Host: Linux 7.0.12, x86-64
- CPU: AMD Ryzen 9 8945HS, 8 cores and 16 threads
- Memory: 14 GiB available to the host
- Container: `rust:1.97.1-bookworm`
- Container digest:
  `sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa`
- `rustc`: 1.97.1, commit `8bab26f4f68e0e26f0bb7960be334d5b520ea452`
- Cargo: 1.97.1, commit `c980f4866`
- Cargo Audit: 0.22.2
- RustSec advisory database:
  `29638ff054fdbb83d2844240f7ef7e576cb52629`

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
cargo audit
```

All commands ran inside the pinned Rust container. The locked test run passed
11 engine unit tests, 2 CLI end-to-end tests, and 2 corpus integration tests.

The CLI test includes package lifecycle and build scripts that would create a
sentinel file if executed. The audit completed, saved and reloaded SQLite
history, emitted valid JSON, and did not create the sentinel.

## Public repository smoke checks

Two public GitHub snapshots were inspected manually through the same archive
acquisition path as the CLI:

| Repository | Resolved revision | Result |
| --- | --- | --- |
| `bananatruck/launchguard` | `f7c39c9718088b44801cedadebd7d0e008fb1abc` | `unsupported`, expected for the documentation-only remote revision |
| `allaboutapps/react-starter` | `ff2ed47a42f7c84f99529bbb832bc78917d3b3c4` | `detected` as React/Vite with pnpm |

These smoke checks confirm exact-revision resolution and one real supported
classification. They were not added to CI because external repositories and
GitHub rate limits are nondeterministic.

## Failure taxonomy

No supported corpus cases failed. Safety cases produced the intended outcomes:

- A repository containing separate Vite and FastAPI components retained both
  candidates and required confirmation.
- FastAPI dependency-only and import-only cases remained unsupported.
- React without Next.js or Vite evidence remained unsupported.
- Express remained unsupported.
- Axum in only `dev-dependencies` or `build-dependencies` remained
  unsupported.

Hardening tests also verify rejection of archive path traversal, omission of
archive links, strict commit identifiers, URL segment encoding, ignored
computed environment prefixes, schema history round trips, and non-execution
through the CLI.

## Limitations

- The supported corpus is synthetic and was designed from the documented
  detector contracts. It tests regressions and failure behavior, not
  population-level generalization.
- Only two public repositories were used as manual smoke checks.
- Local testing occurred on Linux. macOS and Windows test jobs are configured
  but cannot be reported as observed until the branch is published and CI
  completes.
- Detection stops at depth 8 and intentionally ignores files larger than
  1 MiB and generated dependency or build directories.
- Arbitrary monorepos are not selected automatically.
- Local working-tree dirtiness is not included in the revision field.
- Phase 1 performs no vulnerability scanning of the selected repository,
  build verification, readiness scoring, or project execution.

Phase 2 must preserve these failure semantics while adding raw scanner artifact
retention, normalized findings, and deterministic execution-plan generation.
