//! Phase 4 deployment-configuration coverage and safety gates.
//!
//! The gate is schema-valid configuration for the supported corpus. The corpus
//! is synthetic, so this measures template and adapter correctness rather than
//! real-world provider coverage.

use std::{collections::BTreeMap, fs, path::Path};

use launchguard_core::{
    ApprovalState, DEPLOYMENT_INTENT_SCHEMA_JSON, DeploymentKind, DetectionEngine, DetectionStatus,
    Framework, GENERATED_FILE_SCHEMA_JSON, IntentGenerator, Provider, RepositoryAcquirer,
    generate_configuration,
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
    serde_json::from_str(&fs::read_to_string(path).expect("read corpus")).expect("parse corpus")
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

fn validator(schema: &str) -> jsonschema::Validator {
    let schema: serde_json::Value = serde_json::from_str(schema).expect("parse bundled schema");
    jsonschema::validator_for(&schema).expect("compile bundled schema")
}

#[tokio::test]
async fn deployment_configuration_covers_the_supported_corpus() {
    let corpus = load_corpus();
    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let detector = DetectionEngine::default();
    let intent_schema = validator(DEPLOYMENT_INTENT_SCHEMA_JSON);
    let file_schema = validator(GENERATED_FILE_SCHEMA_JSON);

    let mut configured = 0_usize;
    let mut failures = Vec::new();

    for case in &corpus.supported {
        let fixture = materialize(&case.files);
        let repository = acquirer
            .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
            .await
            .expect("acquire fixture");
        let profile = detector.inspect(&repository).expect("inspect fixture");

        let candidates = match IntentGenerator.candidates(&profile) {
            Ok(candidates) => candidates,
            Err(error) => {
                failures.push(format!("{}: no candidate provider: {error}", case.id));
                continue;
            }
        };
        assert!(!candidates.is_empty(), "{}", case.id);

        // Every candidate must serve the detected deployment behavior.
        let kind = profile.deployment_kind.expect("detected deployment kind");
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.provider.deployment_kind() == kind),
            "{} proposed a provider for the wrong deployment kind",
            case.id
        );

        let provider = candidates[0].provider;
        match IntentGenerator.generate(&profile, provider, None) {
            Ok(intent) => {
                intent.validate_digest().expect("intent digest reproduces");
                assert_eq!(intent.approval_state, ApprovalState::RequiresApproval);
                let serialized = serde_json::to_value(&intent).expect("serialize intent");
                if let Err(error) = intent_schema.validate(&serialized) {
                    failures.push(format!("{}: intent failed schema: {error}", case.id));
                    continue;
                }

                let files = match generate_configuration(&intent) {
                    Ok(files) => files,
                    Err(error) => {
                        failures.push(format!("{}: generation failed: {error}", case.id));
                        continue;
                    }
                };
                let mut schema_valid = true;
                for file in &files {
                    let value = serde_json::to_value(file).expect("serialize file");
                    if let Err(error) = file_schema.validate(&value) {
                        failures.push(format!("{}: {} failed schema: {error}", case.id, file.path));
                        schema_valid = false;
                    }
                }
                if !schema_valid {
                    continue;
                }

                // Generation is deterministic, so a digest can bind an approval.
                let repeat = generate_configuration(&intent).expect("regenerate");
                assert_eq!(files, repeat, "{} generation is not deterministic", case.id);

                configured += 1;
            }
            Err(error) => failures.push(format!("{}: {error}", case.id)),
        }
    }

    let percentage = configured * 100 / corpus.supported.len();
    assert!(
        percentage >= 90,
        "only {configured}/{} fixtures produced schema-valid configuration:\n{}",
        corpus.supported.len(),
        failures.join("\n")
    );
    eprintln!(
        "Phase 4 schema-valid configuration coverage: {configured}/{} ({percentage}%)",
        corpus.supported.len()
    );
}

#[tokio::test]
async fn an_ambiguous_project_receives_no_deployment_target() {
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

    let error = IntentGenerator
        .candidates(&profile)
        .expect_err("ambiguous profile must fail closed");
    assert!(
        error.to_string().contains("requires confirmation"),
        "{error}"
    );

    // Naming a provider explicitly must not bypass the ambiguity gate.
    assert!(
        IntentGenerator
            .generate(&profile, Provider::CloudflarePages, None)
            .is_err(),
        "{}: an explicit provider must not override classification",
        case.id
    );
}

#[tokio::test]
async fn a_provider_cannot_serve_the_wrong_deployment_kind() {
    let corpus = load_corpus();
    let case = corpus
        .supported
        .iter()
        .find(|case| case.expected == Framework::ReactVite)
        .expect("static fixture");
    let fixture = materialize(&case.files);
    let repository = RepositoryAcquirer::new()
        .expect("create acquirer")
        .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
        .await
        .expect("acquire fixture");
    let profile = DetectionEngine::default()
        .inspect(&repository)
        .expect("inspect fixture");
    assert_eq!(profile.deployment_kind, Some(DeploymentKind::Static));

    // Render hosts long-running services; a static bundle is not one.
    let error = IntentGenerator
        .generate(&profile, Provider::Render, None)
        .expect_err("a static project must not target a server provider");
    assert!(error.to_string().contains("Server"), "{error}");
}

#[tokio::test]
async fn generated_artifacts_never_carry_an_environment_value() {
    let corpus = load_corpus();
    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let detector = DetectionEngine::default();

    for case in &corpus.supported {
        let fixture = materialize(&case.files);
        let repository = acquirer
            .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
            .await
            .expect("acquire fixture");
        let profile = detector.inspect(&repository).expect("inspect fixture");
        let Ok(candidates) = IntentGenerator.candidates(&profile) else {
            continue;
        };
        let Ok(intent) = IntentGenerator.generate(&profile, candidates[0].provider, None) else {
            continue;
        };
        let Ok(files) = generate_configuration(&intent) else {
            continue;
        };

        for file in &files {
            // Paths stay inside the repository.
            assert!(
                !file.path.starts_with('/') && !file.path.contains(".."),
                "{}: {} escapes the repository",
                case.id,
                file.path
            );
            // A secret is never assigned a value anywhere. Non-secret names may
            // legitimately carry an engine-derived value such as the service
            // port in a Dockerfile ENV line; those come from detector evidence,
            // never from reading a .env file, which the engine does not do.
            for name in &intent.secret_variable_names {
                if let Some(index) = file.contents.find(&format!("{name}=")) {
                    let rest = &file.contents[index + name.len() + 1..];
                    let value = rest.lines().next().unwrap_or_default().trim();
                    assert!(
                        value.is_empty(),
                        "{}: {} assigned a value to secret {name}",
                        case.id,
                        file.path
                    );
                }
            }

            // The environment template is placeholders only, for every name,
            // because it is the artifact a user commits to their repository.
            if file.path.ends_with(".env.example") {
                for line in file.contents.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let (name, value) = line.split_once('=').unwrap_or((line, "x"));
                    assert!(
                        value.trim().is_empty(),
                        "{}: .env.example assigned a value to {name}",
                        case.id
                    );
                }
            }
        }
    }
}
