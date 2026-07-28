# Contributing to LaunchGuard

LaunchGuard is specification-first and now includes its Phase 1 and Phase 2
Rust implementation. Contributions should make behavior safer, clearer, or more
measurable.

## Documentation changes

Before proposing a change:

1. Identify whether it changes product behavior, a trust boundary, a public
   interface, or only explanatory wording.
2. Update every affected document so terminology remains consistent.
3. Include failure behavior and acceptance criteria for new capabilities.
4. Distinguish measured results from targets.
5. Link current official documentation for pricing, licensing, or provider
   limitations.

Pull requests that broaden AI authority, network access, credential access, or
direct deployment must include corresponding changes to the security model.

## Code changes

- Keep the Rust engine independent of Tauri and CLI presentation logic.
- Prefer typed commands and schemas over unstructured shell or model output.
- Add tests for every policy and failure path.
- Preserve raw tool evidence while redacting secrets from user-facing output.
- Do not weaken a deterministic check based on model output.
- Update the labeled corpus and evaluation report when detector behavior
  changes.

Before opening a pull request:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features --locked
```

Rust 1.97.1 is pinned in `rust-toolchain.toml`. The workspace must remain
buildable with `Cargo.lock`; dependency changes should explain their security
and portability implications.

## Security reports

Use GitHub private security advisories for vulnerabilities. Do not publish
credentials, private source, active exploit payloads, or sensitive logs in an
issue.

## Local documentation checks

The repository CI runs Markdown style checks and validates internal links with
Markdownlint CLI2 and Lychee. Rust CI also runs formatting, Clippy, and tests
on Linux, macOS, and Windows.
