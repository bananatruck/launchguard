//! Contract tests for scanner report normalization and protected artifacts.

use std::{fs, path::Path};

use launchguard_core::{
    ArtifactStore, FindingCategory, ScannerKind, Severity, merge_findings, normalize_osv,
    normalize_trivy,
};

const TRIVY_REPORT: &[u8] = include_bytes!("scanner/trivy.json");
const OSV_REPORT: &[u8] = include_bytes!("scanner/osv.json");

/// The root both fixture reports were produced against.
const ROOT: &str = "/tmp/launchguard-fixture";

fn root() -> &'static Path {
    Path::new(ROOT)
}

#[test]
fn normalizes_reports_without_leaking_secret_values() {
    let trivy = normalize_trivy(TRIVY_REPORT, root()).expect("Trivy fixture should normalize");
    assert_eq!(trivy.len(), 3);
    let secret = trivy
        .iter()
        .find(|finding| finding.category == FindingCategory::Secret)
        .expect("secret should be retained as metadata");
    assert_eq!(secret.severity, Severity::Critical);
    assert!(secret.blocks_preview);
    assert!(secret.blocks_publication);

    let serialized = serde_json::to_string(&trivy).expect("findings should serialize");
    assert!(!serialized.contains("SUPER_SECRET_DO_NOT_EXPOSE"));
    assert!(!serialized.contains("const key"));
}

#[test]
fn merges_overlapping_scanner_findings_deterministically() {
    let trivy = normalize_trivy(TRIVY_REPORT, root()).expect("Trivy fixture should normalize");
    let osv = normalize_osv(OSV_REPORT, root()).expect("OSV fixture should normalize");
    let forward = merge_findings(trivy.clone().into_iter().chain(osv.clone()).collect());
    let reverse = merge_findings(osv.into_iter().chain(trivy).collect());
    assert_eq!(forward, reverse);

    let vulnerability = forward
        .iter()
        .find(|finding| finding.category == FindingCategory::Vulnerability)
        .expect("overlapping vulnerability should remain");
    assert_eq!(
        vulnerability.scanners,
        vec![ScannerKind::Trivy, ScannerKind::OsvScanner]
    );
    assert_eq!(
        vulnerability.vulnerability_id.as_deref(),
        Some("CVE-2024-12345")
    );
}

#[test]
fn raw_reports_are_content_addressed_and_not_embedded_in_metadata() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let store = ArtifactStore::new(temporary.path());
    let first = store
        .put_report(ScannerKind::Trivy, TRIVY_REPORT)
        .expect("artifact should persist");
    let second = store
        .put_report(ScannerKind::Trivy, TRIVY_REPORT)
        .expect("duplicate artifact should resolve");

    assert_eq!(first, second);
    assert_eq!(first.digest.len(), 64);
    assert_eq!(
        fs::read(store.resolve(&first)).expect("stored report should be readable"),
        TRIVY_REPORT
    );
    let metadata = serde_json::to_string(&first).expect("metadata should serialize");
    assert!(!metadata.contains("SUPER_SECRET_DO_NOT_EXPOSE"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(store.resolve(&first))
            .expect("artifact metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn rejects_unknown_trivy_schema() {
    let error = normalize_trivy(br#"{"SchemaVersion":3,"Results":[]}"#, root())
        .expect_err("unknown schema should fail closed");
    assert!(error.to_string().contains("SchemaVersion 2"));
}

/// Regression: Trivy omits `Results` entirely for a scan with no findings.
/// Rejecting that report turned every clean project into a failed scanner.
#[test]
fn a_trivy_report_with_no_findings_is_a_clean_scan_not_a_malformed_report() {
    let clean = br#"{"SchemaVersion":2,"Trivy":{"Version":"0.72.0"},"ArtifactName":"/tmp/x","ArtifactType":"filesystem"}"#;
    let findings = normalize_trivy(clean, root()).expect("a clean Trivy report must normalize");
    assert!(findings.is_empty());

    let error = normalize_trivy(br#"{"SchemaVersion":2,"Results":{}}"#, root())
        .expect_err("a non-array Results must still fail closed");
    assert!(error.to_string().contains("Results is not an array"));
}

/// Regression: real OSV-Scanner reports the absolute path it was given while
/// Trivy reports a scan-root-relative path. Before paths were normalized, the
/// same CVE produced two fingerprints and never merged.
#[test]
fn the_same_vulnerability_merges_across_absolute_and_relative_scanner_paths() {
    let trivy = normalize_trivy(TRIVY_REPORT, root()).expect("Trivy fixture should normalize");
    let osv = normalize_osv(OSV_REPORT, root()).expect("OSV fixture should normalize");
    let merged = merge_findings(trivy.into_iter().chain(osv).collect());

    let shared: Vec<_> = merged
        .iter()
        .filter(|finding| finding.vulnerability_id.as_deref() == Some("CVE-2024-12345"))
        .collect();
    assert_eq!(
        shared.len(),
        1,
        "the shared CVE must merge into exactly one finding"
    );
    assert_eq!(
        shared[0].scanners,
        vec![ScannerKind::Trivy, ScannerKind::OsvScanner]
    );
    assert_eq!(
        shared[0]
            .location
            .as_ref()
            .expect("merged location")
            .path
            .as_str(),
        "package-lock.json"
    );
    assert!(
        merged.iter().all(|finding| !finding
            .location
            .as_ref()
            .is_some_and(|location| location.path.starts_with('/'))),
        "public records must not contain absolute host paths"
    );
}
