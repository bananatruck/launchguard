//! JSON Schema validation for every public Phase 2 record.

use std::fs;

use launchguard_core::{
    DetectionEngine, EXECUTION_PLAN_SCHEMA_JSON, FINDING_SCHEMA_JSON, PlanGenerator,
    READINESS_SCHEMA_JSON, ReadinessEngine, RepositoryAcquirer, ScannerKind, normalize_trivy,
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
    let findings =
        normalize_trivy(include_bytes!("scanner/trivy.json")).expect("normalize security fixture");
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

fn validate<T: serde::Serialize>(schema: &str, instance: &T) {
    let schema: serde_json::Value = serde_json::from_str(schema).expect("parse bundled schema");
    let instance = serde_json::to_value(instance).expect("serialize public record");
    let validator = jsonschema::validator_for(&schema).expect("compile bundled schema");
    if let Err(error) = validator.validate(&instance) {
        panic!("public record failed bundled schema: {error}");
    }
}
