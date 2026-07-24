# Contributing to LaunchGuard

LaunchGuard is specification-first. Contributions should make behavior safer,
clearer, or more measurable.

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

## Future code changes

Once executable code exists:

- Keep the Rust engine independent of Tauri and CLI presentation logic.
- Prefer typed commands and schemas over unstructured shell or model output.
- Add tests for every policy and failure path.
- Preserve raw tool evidence while redacting secrets from user-facing output.
- Do not weaken a deterministic check based on model output.

## Security reports

Use GitHub private security advisories for vulnerabilities. Do not publish
credentials, private source, active exploit payloads, or sensitive logs in an
issue.

## Local documentation checks

The repository CI runs Markdown style checks and validates internal links.
Equivalent local commands will be documented when the first contributor
toolchain is added.
