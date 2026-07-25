# Phase 1: Read-only Rust engine

Phase 1 implements deterministic repository acquisition and project
classification. It deliberately stops before security scanner orchestration,
command planning, sandboxed execution, AI remediation, and publication.

## Architecture

The workspace has two crates:

- `launchguard-core` owns acquisition, bounded file indexing, evidence-based
  detection, public records, and SQLite history.
- `launchguard-cli` owns argument parsing, JSON and Markdown presentation,
  structured tracing setup, and the `audit`, `history`, `status`, and `schema`
  commands.

The CLI and future interfaces consume the same engine types. Detector output
uses the checked-in
[`ProjectProfile` v1 JSON Schema](../schemas/project-profile-v1.schema.json).
Readers reject unknown schema versions.

## Acquisition contract

Local inputs are canonicalized and inspected in place without mutation. The
engine reads `.git/HEAD` and loose or packed refs to identify a local commit
without invoking Git.

Public GitHub inputs must have this shape:

```text
https://github.com/<owner>/<repository>[.git]
```

The engine resolves the default branch through the GitHub API, downloads an
archive for the exact commit, and extracts it into a temporary directory.
Acquisition:

- Does not use a shell or execute Git hooks.
- Does not invoke project scripts, package managers, tests, or binaries.
- Rejects archive path traversal.
- Skips symlinks, hard links, devices, and other non-file entries.
- Limits redirects to 5 and an HTTP request to 1 minute.
- Limits the compressed archive to 100 MiB.
- Limits extracted content to 250 MiB and 20,000 entries.

Phase 1 supports public GitHub repositories only. Authentication and private
repository access require a separate credential-handling specification.

## Inspection bounds

The file index does not follow symlinks. It considers at most:

- 8 directory levels.
- 20,000 files.
- 1 MiB per detector input.

It skips `.git`, `.hg`, `.svn`, `.next`, `.venv`, `build`, `dist`,
`node_modules`, `target`, and virtual-environment directories. Only manifests,
lockfiles, framework configuration, environment templates, and supported
source extensions are read.

Actual `.env` files are excluded. Only variable names, explicit port numbers,
and source locations are retained.

## Evidence contracts

| Classification | Required evidence |
| --- | --- |
| React/Vite | `package.json` and either a Vite dependency or direct Vite configuration |
| Next.js | `package.json` and a Next.js dependency |
| FastAPI | Python dependency manifest containing FastAPI and a Python source import |
| Rust/Axum | `Cargo.toml` containing an Axum dependency |

Each candidate receives facts with repository-relative paths and deterministic
weights. A candidate meeting its complete contract currently has confidence
`1.0`; confidence does not represent a security probability.

Exactly one candidate produces `detected`. More than one candidate produces
`needs_confirmation`, retains every candidate, and leaves the selected
framework empty. No qualifying candidate produces `unsupported`.

Next.js configuration containing `output: "export"` or `output: 'export'` is
classified as static. Other Next.js projects are classified as server
applications.

## History and observability

History is stored in a local SQLite database using WAL mode. Each immutable run
contains a UUIDv7 identifier, UTC timestamp, source, revision, status, schema
version, and complete profile JSON.

Tracing is written to standard error. `--log-format json` emits structured
tracing without contaminating machine-readable reports on standard output.
History contains environment variable names but no values or credentials.

## Evaluation

The checked-in corpus contains 10 labeled variants for each supported
framework and separate ambiguity or incomplete-evidence fixtures. The
integration gate requires:

- Exactly 40 supported cases remain published.
- At least 95% of supported cases are classified correctly.
- Ambiguity preserves at least two candidates and does not select a framework.
- Incomplete evidence is reported as unsupported.

This is a synthetic detector contract corpus. It verifies implementation
behavior but does not by itself establish real-world generalization. A Phase 1
completion report records the measured result, tool versions, and this
limitation.

## Known limitations

- Arbitrary monorepo orchestration is out of scope. Multiple detected
  components require confirmation.
- GitHub subpaths, branch selectors, GitLab, and private repositories are not
  accepted.
- Local revisions do not currently record whether a working tree is dirty.
- Package manager conflicts are not yet a separate ambiguity category.
- Build and start commands are descriptive profile hints; Phase 1 never
  executes them.
- Source-pattern extraction is intentionally conservative and may miss
  computed environment variable names or ports.
- A successful classification is not a security, build-readiness, or
  deployment-readiness claim.
