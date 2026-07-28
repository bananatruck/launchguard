//! Phase 5 publication gates.
//!
//! These assert the properties that make publication safe to automate: a
//! refused decision cannot produce a plan, an override is always visible in the
//! pull request, secrets never reach it, and a repeated run targets the same
//! branch instead of opening a second request.

use std::{collections::BTreeMap, fs, path::Path};

use launchguard_core::{
    DetectionEngine, GateLevel, IntentGenerator, PULL_REQUEST_PLAN_SCHEMA_JSON, PlanGenerator,
    PreviewOutcome, Provider, PublicationContext, PublicationGate, PullRequestPlanner,
    ReadinessEngine, RepositoryAcquirer, ScannerKind, generate_configuration, normalize_trivy,
};

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("create fixture");
    let files: BTreeMap<&str, &str> = BTreeMap::from([
        (
            "package.json",
            r#"{"dependencies":{"react":"latest","vite":"latest"},"scripts":{"build":"vite build"}}"#,
        ),
        ("package-lock.json", "{}"),
        (
            "src/main.ts",
            "export default { url: import.meta.env.VITE_API_URL, key: import.meta.env.VITE_API_KEY };",
        ),
    ]);
    for (relative, contents) in files {
        let path = directory.path().join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, contents).expect("write fixture");
    }
    directory
}

struct Harness {
    profile: launchguard_core::ProjectProfile,
    intent: launchguard_core::DeploymentIntent,
    files: Vec<launchguard_core::GeneratedFile>,
    readiness: launchguard_core::ReadinessAssessment,
    findings: Vec<launchguard_core::Finding>,
}

async fn harness(scanners: &[ScannerKind], with_findings: bool) -> Harness {
    let directory = fixture();
    let repository = RepositoryAcquirer::new()
        .expect("acquirer")
        .acquire(directory.path().to_str().expect("UTF-8 path"))
        .await
        .expect("acquire");
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .expect("inspect");
    let intent = IntentGenerator
        .generate(&profile, Provider::CloudflarePages, None)
        .expect("intent");
    let files = generate_configuration(&intent).expect("configuration");
    let findings = if with_findings {
        normalize_trivy(include_bytes!("scanner/trivy.json"), directory.path()).expect("normalize")
    } else {
        Vec::new()
    };
    // A run reaching publication has an execution plan; without one the gate
    // raises no_execution_plan, which is correct but not what these exercise.
    let execution_plan = PlanGenerator.generate(&profile).expect("execution plan");
    let readiness = ReadinessEngine
        .assess(&profile, &findings, scanners, Some(&execution_plan))
        .expect("assess");
    Harness {
        profile,
        intent,
        files,
        readiness,
        findings,
    }
}

fn context<'a>(
    harness: &'a Harness,
    decision: &'a launchguard_core::PublicationDecision,
) -> PublicationContext<'a> {
    PublicationContext {
        repository: "octocat/example",
        base_branch: "main",
        private_repository: false,
        profile: &harness.profile,
        intent: &harness.intent,
        files: &harness.files,
        readiness: &harness.readiness,
        findings: &harness.findings,
        provenance: &[],
        decision,
    }
}

fn both() -> Vec<ScannerKind> {
    vec![ScannerKind::Trivy, ScannerKind::OsvScanner]
}

#[tokio::test]
async fn a_hard_blocked_run_cannot_produce_a_pull_request_plan() {
    // The Trivy fixture carries a critical secret.
    let harness = harness(&both(), true).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::Passed,
        )
        .expect("evaluate");
    assert_eq!(decision.level, GateLevel::HardBlock);

    let error = PullRequestPlanner
        .plan(&context(&harness, &decision))
        .expect_err("a hard block must refuse to plan");
    assert!(error.to_string().contains("hard_block"), "{error}");
}

#[tokio::test]
async fn a_soft_blocked_run_needs_an_override_and_records_it() {
    let harness = harness(&[ScannerKind::Trivy], false).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::NotAttempted,
        )
        .expect("evaluate");
    assert_eq!(decision.level, GateLevel::SoftBlock);

    // Without the override there is no plan at all.
    assert!(
        PullRequestPlanner
            .plan(&context(&harness, &decision))
            .is_err()
    );

    let accepted = decision.accept_override().expect("override");
    let plan = PullRequestPlanner
        .plan(&context(&harness, &accepted))
        .expect("plan after override");

    // The reviewer must be told what was skipped, in the body itself.
    assert!(plan.body.contains("Accepted without verification"));
    for code in &accepted.overridden_codes {
        assert!(
            plan.body.contains(code.as_str()),
            "the body must name skipped check {code}"
        );
    }
    plan.validate_digest().expect("digest reproduces");
}

#[tokio::test]
async fn a_repeated_run_targets_one_branch_so_it_cannot_duplicate_a_request() {
    let harness = harness(&both(), false).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::Passed,
        )
        .expect("evaluate");
    assert_eq!(decision.level, GateLevel::Clear);

    let first = PullRequestPlanner
        .plan(&context(&harness, &decision))
        .expect("plan");
    let second = PullRequestPlanner
        .plan(&context(&harness, &decision))
        .expect("replan");

    assert_eq!(first, second, "planning must be deterministic");
    assert!(first.head_branch.starts_with("launchguard/deploy-"));
    assert!(
        first.head_branch.contains(&harness.intent.digest[..12]),
        "the branch must derive from the intent digest"
    );
}

#[tokio::test]
async fn a_plan_never_carries_a_secret_value_and_states_its_permissions() {
    let harness = harness(&both(), false).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::Passed,
        )
        .expect("evaluate");
    let plan = PullRequestPlanner
        .plan(&context(&harness, &decision))
        .expect("plan");

    // VITE_API_KEY is credential-shaped, so it is named but never assigned.
    assert!(
        harness
            .intent
            .secret_variable_names
            .contains(&"VITE_API_KEY".to_owned()),
        "the fixture must exercise a secret-shaped name"
    );
    for secret in &harness.intent.secret_variable_names {
        let assigned = format!("{secret}=");
        for file in &plan.files {
            if let Some(index) = file.contents.find(&assigned) {
                let rest = &file.contents[index + assigned.len()..];
                assert!(
                    rest.lines().next().unwrap_or_default().trim().is_empty(),
                    "{secret} must never be assigned a value"
                );
            }
        }
    }

    // The narrowest scope that can open a pull request on a public repository.
    assert_eq!(plan.requested_scopes.len(), 1);
    assert_eq!(plan.requested_scopes[0].scope, "public_repo");
    assert!(!plan.requested_scopes[0].permits.is_empty());

    // A private repository needs a broader grant, and must say so.
    let mut private = context(&harness, &decision);
    private.private_repository = true;
    let private_plan = PullRequestPlanner.plan(&private).expect("plan");
    assert_eq!(private_plan.requested_scopes[0].scope, "repo");
    assert!(
        private_plan.requested_scopes[0].permits.contains("private"),
        "a broader grant must explain what else it exposes"
    );
}

#[tokio::test]
async fn a_plan_validates_against_the_bundled_schema() {
    let harness = harness(&both(), false).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::Passed,
        )
        .expect("evaluate");
    let plan = PullRequestPlanner
        .plan(&context(&harness, &decision))
        .expect("plan");

    let schema: serde_json::Value =
        serde_json::from_str(PULL_REQUEST_PLAN_SCHEMA_JSON).expect("parse schema");
    let validator = jsonschema::validator_for(&schema).expect("compile schema");
    let instance = serde_json::to_value(&plan).expect("serialize plan");
    if let Err(error) = validator.validate(&instance) {
        panic!("plan failed bundled schema: {error}");
    }

    // The body carries the reproducibility record a reviewer needs.
    assert!(plan.body.contains(&harness.intent.digest));
    assert!(plan.body.contains("Rollback"));
    assert!(plan.body.contains("has not executed this project's code"));
}

#[tokio::test]
async fn a_malformed_repository_is_refused() {
    let harness = harness(&both(), false).await;
    let decision = PublicationGate
        .evaluate(
            &harness.readiness,
            &harness.findings,
            None,
            PreviewOutcome::Passed,
        )
        .expect("evaluate");
    for repository in ["", "no-slash", "too/many/slashes", "/leading", "trailing/"] {
        let mut broken = context(&harness, &decision);
        broken.repository = repository;
        assert!(
            PullRequestPlanner.plan(&broken).is_err(),
            "{repository} must be refused"
        );
    }
}

#[test]
fn the_corpus_path_is_stable() {
    // Guards the fixture the other tests include.
    assert!(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/scanner/trivy.json")
            .is_file()
    );
}
