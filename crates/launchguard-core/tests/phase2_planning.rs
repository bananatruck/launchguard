//! Phase 2 execution-plan coverage and deterministic-readiness gates.

use std::{collections::BTreeMap, fs, path::Path};

use launchguard_core::{
    ApprovalState, DetectionEngine, DetectionStatus, EXECUTION_PLAN_SCHEMA_JSON, Framework,
    PlanGenerator, READINESS_SCHEMA_JSON, ReadinessEngine, RepositoryAcquirer, normalize_trivy,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    supported: Vec<SupportedCase>,
    safety: Vec<SafetyCase>,
}

#[derive(Debug, Deserialize)]
struct SupportedCase {
    id: String,
    expected: Framework,
    files: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct SafetyCase {
    id: String,
    expected_status: DetectionStatus,
    files: BTreeMap<String, String>,
}

fn load_corpus() -> Corpus {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/phase1.json");
    let content = fs::read_to_string(path).expect("read published corpus");
    serde_json::from_str(&content).expect("parse published corpus")
}

fn materialize(files: &BTreeMap<String, String>) -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("create fixture directory");
    for (relative_path, content) in files {
        let path = directory.path().join(relative_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(path, content).expect("write fixture file");
    }
    directory
}

/// Compile the bundled schemas once for the whole corpus sweep.
fn validators() -> (jsonschema::Validator, jsonschema::Validator) {
    let compile = |schema: &str| {
        let schema: serde_json::Value = serde_json::from_str(schema).expect("parse bundled schema");
        jsonschema::validator_for(&schema).expect("compile bundled schema")
    };
    (
        compile(EXECUTION_PLAN_SCHEMA_JSON),
        compile(READINESS_SCHEMA_JSON),
    )
}

#[tokio::test]
async fn reviewed_plans_cover_at_least_ninety_percent_of_supported_corpus() {
    let corpus = load_corpus();
    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let detector = DetectionEngine::default();
    let planner = PlanGenerator;
    let readiness = ReadinessEngine;
    let (plan_schema, readiness_schema) = validators();
    let mut plan_successes = 0_usize;
    let mut failures = Vec::new();

    for case in &corpus.supported {
        let fixture = materialize(&case.files);
        let repository = acquirer
            .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
            .await
            .expect("acquire fixture");
        let profile = detector.inspect(&repository).expect("inspect fixture");
        assert_eq!(profile.framework, Some(case.expected), "{}", case.id);

        match planner.generate(&profile) {
            Ok(plan) => {
                // The roadmap gate is schema-valid plans, so a plan that
                // generates but does not validate is not counted as a success.
                let serialized = serde_json::to_value(&plan).expect("serialize plan");
                if let Err(error) = plan_schema.validate(&serialized) {
                    failures.push(format!("{}: plan failed bundled schema: {error}", case.id));
                    continue;
                }
                plan_successes += 1;
                assert_eq!(plan.approval_state, ApprovalState::RequiresApproval);
                assert!(plan.network_policy.default_deny);
                assert!(!plan.commands.is_empty());
                assert!(
                    plan.commands.iter().all(|command| {
                        command.executable != "sh"
                            && command.executable != "bash"
                            && !command.arguments.iter().any(|argument| argument == "-c")
                    }),
                    "{} contains a shell interpreter",
                    case.id
                );
                plan.validate_digest()
                    .expect("plan digest should reproduce");
                let duplicate = planner.generate(&profile).expect("regenerate plan");
                assert_eq!(plan, duplicate, "{} plan is not deterministic", case.id);

                let first = readiness
                    .assess(&profile, &[], &[], Some(&plan))
                    .expect("score plan");
                let second = readiness
                    .assess(&profile, &[], &[], Some(&duplicate))
                    .expect("reproduce score");
                assert_eq!(first, second, "{} score is not deterministic", case.id);
                first
                    .validate_digest()
                    .expect("assessment digest should reproduce");
                let assessment = serde_json::to_value(&first).expect("serialize assessment");
                if let Err(error) = readiness_schema.validate(&assessment) {
                    panic!("{}: assessment failed bundled schema: {error}", case.id);
                }
            }
            Err(error) => failures.push(format!("{}: {error}", case.id)),
        }
    }

    let percentage = plan_successes * 100 / corpus.supported.len();
    assert!(
        percentage >= 90,
        "only {plan_successes}/{} fixtures produced a schema-valid plan:\n{}",
        corpus.supported.len(),
        failures.join("\n")
    );
    eprintln!(
        "Phase 2 schema-valid plan coverage: {plan_successes}/{} ({percentage}%)",
        corpus.supported.len()
    );
}

#[tokio::test]
async fn ambiguous_profiles_cannot_receive_execution_plans() {
    let corpus = load_corpus();
    let case = corpus
        .safety
        .iter()
        .find(|case| case.expected_status == DetectionStatus::NeedsConfirmation)
        .expect("ambiguity fixture");
    let fixture = materialize(&case.files);
    let repository = RepositoryAcquirer::new()
        .expect("create acquirer")
        .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
        .await
        .expect("acquire fixture");
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .expect("inspect fixture");
    let error = PlanGenerator
        .generate(&profile)
        .expect_err("ambiguous profile must fail closed");
    assert!(
        error.to_string().contains("requires confirmation"),
        "{}: {error}",
        case.id
    );
}

#[tokio::test]
async fn deterministic_policy_blocks_critical_secret_fixture() {
    let corpus = load_corpus();
    let case = &corpus.supported[0];
    let fixture = materialize(&case.files);
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
        .assess(&profile, &findings, &[], Some(&plan))
        .expect("assess fixture");

    assert!(assessment.blocks_preview);
    assert!(assessment.blocks_publication);
    assert!(assessment.scores.security.percentage < 50);
}

/// Regression: Trivy embeds a per-run report identifier and timestamp, so the
/// stored raw report has a different digest on every run. That provenance must
/// not leak into the assessment digest, or no assessment ever reproduces.
#[tokio::test]
async fn assessments_reproduce_when_only_raw_report_provenance_differs() {
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

    let first = normalize_trivy(include_bytes!("scanner/trivy.json"), fixture.path())
        .expect("normalize security fixture");
    let mut second = first.clone();
    for finding in &mut second {
        finding.raw_artifact_digests = vec![format!("{:064x}", 1)];
    }
    assert_ne!(
        first[0].raw_artifact_digests, second[0].raw_artifact_digests,
        "the two runs must differ only in raw report provenance"
    );

    let scanners = [launchguard_core::ScannerKind::Trivy];
    let left = ReadinessEngine
        .assess(&profile, &first, &scanners, Some(&plan))
        .expect("assess first run");
    let right = ReadinessEngine
        .assess(&profile, &second, &scanners, Some(&plan))
        .expect("assess second run");

    assert_eq!(left.findings_digest, right.findings_digest);
    assert_eq!(left.reproduction_digest, right.reproduction_digest);
    assert_eq!(left.scores, right.scores);
}
