//! JSON Schema validation for every public Phase 2 record.

use std::fs;

use launchguard_core::{
    CAPABILITY_REPORT_SCHEMA_JSON, CapabilityProbe, DetectionEngine, EXECUTION_PLAN_SCHEMA_JSON,
    FINDING_SCHEMA_JSON, PlanGenerator, ProbeConfig, READINESS_SCHEMA_JSON, ReadinessEngine,
    RepositoryAcquirer, ScannerKind, normalize_trivy,
};

#[tokio::test]
async fn generated_phase_two_records_validate_against_bundled_schemas() {
    let fixture = tempfile::tempdir().expect("create fixture");
    fs::create_dir_all(fixture.path().join("src")).expect("create source directory");
    fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies":{"react":"latest","vite":"latest"},"scripts":{"build":"vite build"}}"#,
    )
    .expect("write package manifest");
    fs::write(fixture.path().join("package-lock.json"), "{}").expect("write lockfile");
    fs::write(fixture.path().join("src/main.tsx"), "export default {};").expect("write source");

    let repository = RepositoryAcquirer::new()
        .expect("create acquirer")
        .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
        .await
        .expect("acquire fixture");
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .expect("inspect fixture");
    let plan = PlanGenerator.generate(&profile).expect("generate plan");
    let findings = normalize_trivy(include_bytes!("scanner/trivy.json"), fixture.path())
        .expect("normalize security fixture");
    let assessment = ReadinessEngine
        .assess(
            &profile,
            &findings,
            &[ScannerKind::Trivy, ScannerKind::OsvScanner],
            Some(&plan),
        )
        .expect("calculate readiness");

    validate(FINDING_SCHEMA_JSON, &findings[0]);
    validate(EXECUTION_PLAN_SCHEMA_JSON, &plan);
    validate(READINESS_SCHEMA_JSON, &assessment);
}

#[tokio::test]
async fn capability_reports_validate_against_the_bundled_schema() {
    // A host with nothing installed still produces a schema-valid report.
    let empty = ProbeConfig {
        git_executable: "/nonexistent/git".into(),
        podman_executable: "/nonexistent/podman".into(),
        docker_executable: "/nonexistent/docker".into(),
        trivy_executable: "/nonexistent/trivy".into(),
        osv_executable: "/nonexistent/osv-scanner".into(),
        inference_endpoint: "http://127.0.0.1:1".to_owned(),
    };
    let report = CapabilityProbe::new(empty)
        .detect()
        .await
        .expect("probe an empty host");
    validate(CAPABILITY_REPORT_SCHEMA_JSON, &report);

    // So does whatever this machine actually has.
    let measured = CapabilityProbe::default()
        .detect()
        .await
        .expect("probe this host");
    validate(CAPABILITY_REPORT_SCHEMA_JSON, &measured);
}

fn validate<T: serde::Serialize>(schema: &str, instance: &T) {
    let schema: serde_json::Value = serde_json::from_str(schema).expect("parse bundled schema");
    let instance = serde_json::to_value(instance).expect("serialize public record");
    let validator = jsonschema::validator_for(&schema).expect("compile bundled schema");
    if let Err(error) = validator.validate(&instance) {
        panic!("public record failed bundled schema: {error}");
    }
}
