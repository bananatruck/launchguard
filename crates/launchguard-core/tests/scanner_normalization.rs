//! Contract tests for scanner report normalization and protected artifacts.

use std::fs;

use launchguard_core::{
    ArtifactStore, FindingCategory, ScannerKind, Severity, merge_findings, normalize_osv,
    normalize_trivy,
};

const TRIVY_REPORT: &[u8] = include_bytes!("scanner/trivy.json");
const OSV_REPORT: &[u8] = include_bytes!("scanner/osv.json");

#[test]
fn normalizes_reports_without_leaking_secret_values() {
    let trivy = normalize_trivy(TRIVY_REPORT).expect("Trivy fixture should normalize");
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
    let trivy = normalize_trivy(TRIVY_REPORT).expect("Trivy fixture should normalize");
    let osv = normalize_osv(OSV_REPORT).expect("OSV fixture should normalize");
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
    let error = normalize_trivy(br#"{"SchemaVersion":3,"Results":[]}"#)
        .expect_err("unknown schema should fail closed");
    assert!(error.to_string().contains("SchemaVersion 2"));
}
