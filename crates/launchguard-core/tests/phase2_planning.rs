//! Phase 2 execution-plan coverage and deterministic-readiness gates.

use std::{collections::BTreeMap, fs, path::Path};

use launchguard_core::{
    ApprovalState, DetectionEngine, DetectionStatus, Framework, PlanGenerator, ReadinessEngine,
    RepositoryAcquirer, normalize_trivy,
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

#[tokio::test]
async fn reviewed_plans_cover_at_least_ninety_percent_of_supported_corpus() {
    let corpus = load_corpus();
    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let detector = DetectionEngine::default();
    let planner = PlanGenerator;
    let readiness = ReadinessEngine;
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
            }
            Err(error) => failures.push(format!("{}: {error}", case.id)),
        }
    }

    let percentage = plan_successes * 100 / corpus.supported.len();
    assert!(
        percentage >= 90,
        "only {plan_successes}/{} fixtures planned:\n{}",
        corpus.supported.len(),
        failures.join("\n")
    );
    eprintln!(
        "Phase 2 reviewed plan coverage: {plan_successes}/{} ({percentage}%)",
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
    let findings =
        normalize_trivy(include_bytes!("scanner/trivy.json")).expect("normalize security fixture");
    let assessment = ReadinessEngine
        .assess(&profile, &findings, &[], Some(&plan))
        .expect("assess fixture");

    assert!(assessment.blocks_preview);
    assert!(assessment.blocks_publication);
    assert!(assessment.scores.security.percentage < 50);
}
