//! Phase 1 detector accuracy and fail-closed behavior over the published corpus.

use std::{collections::BTreeMap, fs, path::Path};

use launchguard_core::{
    DetectionEngine, DetectionStatus, Framework, PROJECT_PROFILE_SCHEMA_VERSION, RepositoryAcquirer,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Corpus {
    schema_version: String,
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
    let content = fs::read_to_string(path).expect("read Phase 1 corpus");
    serde_json::from_str(&content).expect("parse Phase 1 corpus")
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
async fn supported_corpus_exceeds_phase_one_accuracy_gate() {
    let corpus = load_corpus();
    assert_eq!(corpus.schema_version, PROJECT_PROFILE_SCHEMA_VERSION);
    assert_eq!(
        corpus.supported.len(),
        40,
        "the published Phase 1 corpus must retain 40 supported cases"
    );

    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let engine = DetectionEngine::default();
    let mut correct = 0_usize;
    let mut failures = Vec::new();

    for case in &corpus.supported {
        let fixture = materialize(&case.files);
        let repository = acquirer
            .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
            .await
            .expect("acquire local fixture");
        let profile = engine.inspect(&repository).expect("inspect fixture");
        if profile.status == DetectionStatus::Detected && profile.framework == Some(case.expected) {
            correct += 1;
        } else {
            failures.push(format!(
                "{}: expected {:?}, received status {:?} and framework {:?}",
                case.id, case.expected, profile.status, profile.framework
            ));
        }
    }

    let correct_count = u32::try_from(correct).expect("corpus count fits u32");
    let total_count = u32::try_from(corpus.supported.len()).expect("corpus count fits u32");
    let accuracy = f64::from(correct_count) / f64::from(total_count);
    assert!(
        accuracy >= 0.95,
        "Phase 1 accuracy {:.1}% is below 95%:\n{}",
        accuracy * 100.0,
        failures.join("\n")
    );
    eprintln!(
        "Phase 1 supported classification accuracy: {correct}/{} ({:.1}%)",
        corpus.supported.len(),
        accuracy * 100.0
    );
}

#[tokio::test]
async fn ambiguity_and_incomplete_evidence_fail_closed() {
    let corpus = load_corpus();
    let acquirer = RepositoryAcquirer::new().expect("create acquirer");
    let engine = DetectionEngine::default();

    for case in &corpus.safety {
        let fixture = materialize(&case.files);
        let repository = acquirer
            .acquire(fixture.path().to_str().expect("UTF-8 fixture path"))
            .await
            .expect("acquire local fixture");
        let profile = engine.inspect(&repository).expect("inspect fixture");
        assert_eq!(
            profile.status, case.expected_status,
            "{} did not fail closed",
            case.id
        );
        if profile.status == DetectionStatus::NeedsConfirmation {
            assert!(
                profile.candidates.len() >= 2,
                "{} did not preserve competing classifications",
                case.id
            );
            assert!(
                profile.framework.is_none(),
                "{} silently selected a framework",
                case.id
            );
        }
    }
}
