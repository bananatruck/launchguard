//! End-to-end tests for the read-only CLI and local history.

use std::{fs, process::Command};

#[test]
fn audit_is_machine_readable_persisted_and_non_executing() {
    let fixture = tempfile::tempdir().expect("create fixture");
    fs::create_dir_all(fixture.path().join("src")).expect("create source directory");
    fs::write(
        fixture.path().join("package.json"),
        r#"{
            "dependencies": {"react": "latest", "vite": "latest"},
            "scripts": {
                "preinstall": "touch project-code-ran",
                "build": "touch project-code-ran"
            }
        }"#,
    )
    .expect("write package manifest");
    fs::write(fixture.path().join("package-lock.json"), "{}").expect("write lockfile");
    fs::write(
        fixture.path().join("src/main.ts"),
        "console.log(import.meta.env.VITE_API_URL);",
    )
    .expect("write source");

    let state = tempfile::tempdir().expect("create state directory");
    let database = state.path().join("history.sqlite3");
    let audit = Command::new(env!("CARGO_BIN_EXE_launchguard"))
        .arg("--database")
        .arg(&database)
        .arg("audit")
        .arg(fixture.path())
        .arg("--format")
        .arg("json")
        .output()
        .expect("run audit");
    assert!(
        audit.status.success(),
        "audit failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let output: serde_json::Value =
        serde_json::from_slice(&audit.stdout).expect("parse audit JSON");
    assert_eq!(output["profile"]["framework"], "react_vite");
    assert_eq!(output["profile"]["status"], "detected");
    assert!(!fixture.path().join("project-code-ran").exists());

    let run_id = output["run_id"].as_str().expect("run id");
    let status = Command::new(env!("CARGO_BIN_EXE_launchguard"))
        .arg("--database")
        .arg(&database)
        .arg("status")
        .arg(run_id)
        .arg("--format")
        .arg("json")
        .output()
        .expect("load status");
    assert!(
        status.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stored: serde_json::Value =
        serde_json::from_slice(&status.stdout).expect("parse stored run");
    assert_eq!(stored["run_id"], run_id);
    assert_eq!(stored["profile"]["framework"], "react_vite");

    // History schema 2 replays the whole audit, not just the profile.
    assert_eq!(stored["plan"]["digest"], output["plan"]["digest"]);
    assert_eq!(
        stored["readiness"]["reproduction_digest"],
        output["readiness"]["reproduction_digest"]
    );
    assert!(stored["readiness"]["reproduction_digest"].is_string());
}

#[test]
fn a_missing_scanner_degrades_coverage_instead_of_failing_the_audit() {
    let fixture = tempfile::tempdir().expect("create fixture");
    fs::create_dir_all(fixture.path().join("src")).expect("create source directory");
    fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies": {"react": "latest", "vite": "latest"}, "scripts": {"build": "vite build"}}"#,
    )
    .expect("write package manifest");
    fs::write(fixture.path().join("package-lock.json"), "{}").expect("write lockfile");
    fs::write(fixture.path().join("src/main.ts"), "export default {};").expect("write source");

    let absent = fixture.path().join("no-such-scanner");
    let audit = Command::new(env!("CARGO_BIN_EXE_launchguard"))
        .arg("audit")
        .arg(fixture.path())
        .arg("--format")
        .arg("json")
        .arg("--no-history")
        .arg("--scanner")
        .arg("trivy")
        .arg("--trivy-executable")
        .arg(&absent)
        .output()
        .expect("run audit");
    assert!(
        audit.status.success(),
        "a missing scanner must not fail the audit: {}",
        String::from_utf8_lossy(&audit.stderr)
    );

    let output: serde_json::Value =
        serde_json::from_slice(&audit.stdout).expect("parse audit JSON");
    let degradations = output["degradations"]
        .as_array()
        .expect("degradations are reported");
    assert_eq!(degradations.len(), 1);
    assert_eq!(degradations[0]["kind"], "scanner_unavailable");
    assert_eq!(degradations[0]["subject"], "trivy");

    // Reduced coverage stays visible instead of reading as a clean scan.
    assert_eq!(output["profile"]["status"], "detected");
    assert!(output["plan"]["digest"].is_string());
    assert_eq!(
        output["readiness"]["completed_scanners"],
        serde_json::json!([])
    );
    assert_eq!(output["readiness"]["blocks_preview"], true);
    assert_eq!(output["readiness"]["blocks_publication"], true);
}

/// `doctor` must succeed on any host and report a self-consistent result.
///
/// Assertions here are invariants rather than facts about the machine, because
/// a CI runner may legitimately have Docker or Git installed. The
/// nothing-is-installed case is covered deterministically by the engine unit
/// test, which injects paths that cannot resolve on any platform.
#[test]
fn doctor_reports_capability_without_blocking_or_requiring_anything() {
    let output = Command::new(env!("CARGO_BIN_EXE_launchguard"))
        .arg("doctor")
        .arg("--format")
        .arg("json")
        .output()
        .expect("run doctor");
    assert!(
        output.status.success(),
        "doctor must succeed on any host: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse capability JSON");
    assert_eq!(report["schema_version"], "1.0");
    assert!(report["platform"]["os"].is_string());
    assert!(report["platform"]["architecture"].is_string());

    let capabilities = report["capabilities"].as_array().expect("capabilities");
    assert_eq!(capabilities.len(), 5);
    assert!(
        capabilities
            .iter()
            .all(|capability| capability["status"] == "present" || capability["status"] == "absent")
    );

    // Track A depends on nothing beyond this binary, so it is always offered.
    let tracks = report["available_tracks"]
        .as_array()
        .expect("available tracks");
    assert!(tracks.iter().any(|track| track == "deploy"));

    // Verification is offered exactly when a container runtime was found, and
    // the report names the blocker exactly when it was not.
    let runtime_present = capabilities.iter().any(|capability| {
        capability["kind"] == "container_runtime" && capability["status"] == "present"
    });
    let verify_offered = tracks.iter().any(|track| track == "verify");
    assert_eq!(verify_offered, runtime_present);
    assert_eq!(
        report["blocking_capability"].is_null(),
        runtime_present,
        "a blocking capability must be named exactly when verification is unavailable"
    );
}

#[test]
fn schema_command_emits_the_versioned_contract() {
    let output = Command::new(env!("CARGO_BIN_EXE_launchguard"))
        .arg("schema")
        .output()
        .expect("print schema");
    assert!(output.status.success());
    let schema: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse JSON Schema");
    assert_eq!(schema["properties"]["schema_version"]["const"], "1.0");
    assert!(
        schema["required"]
            .as_array()
            .expect("required fields")
            .iter()
            .any(|field| field == "evidence")
    );
}

#[test]
fn plan_is_typed_approval_gated_and_deterministic() {
    let fixture = tempfile::tempdir().expect("create fixture");
    fs::create_dir_all(fixture.path().join("src")).expect("create source directory");
    fs::write(
        fixture.path().join("package.json"),
        r#"{
            "dependencies": {"react": "latest", "vite": "latest"},
            "scripts": {"build": "vite build", "preinstall": "touch project-code-ran"}
        }"#,
    )
    .expect("write package manifest");
    fs::write(fixture.path().join("package-lock.json"), "{}").expect("write lockfile");
    fs::write(fixture.path().join("src/main.ts"), "export default {};").expect("write source");

    let execute = || {
        Command::new(env!("CARGO_BIN_EXE_launchguard"))
            .arg("plan")
            .arg(fixture.path())
            .arg("--format")
            .arg("json")
            .output()
            .expect("generate plan")
    };
    let first = execute();
    let second = execute();
    assert!(
        first.status.success(),
        "plan failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(first.stdout, second.stdout);

    let output: serde_json::Value = serde_json::from_slice(&first.stdout).expect("parse plan JSON");
    assert_eq!(output["plan"]["approval_state"], "requires_approval");
    assert_eq!(output["plan"]["network_policy"]["default_deny"], true);
    assert_eq!(output["readiness"]["blocks_preview"], true);
    assert!(
        output["plan"]["commands"]
            .as_array()
            .expect("typed commands")
            .iter()
            .all(|command| command["executable"] != "sh" && command["executable"] != "bash")
    );
    assert!(!fixture.path().join("project-code-ran").exists());
}

#[test]
fn phase_two_schema_commands_emit_expected_contracts() {
    for (record, title) in [
        ("finding", "LaunchGuard Finding v1"),
        ("execution-plan", "LaunchGuard ExecutionPlan v1"),
        ("readiness-assessment", "LaunchGuard ReadinessAssessment v1"),
        ("degradation", "LaunchGuard Degradation v1"),
        ("capability-report", "LaunchGuard CapabilityReport v1"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_launchguard"))
            .arg("schema")
            .arg(record)
            .output()
            .expect("print schema");
        assert!(
            output.status.success(),
            "{record}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let schema: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("parse JSON Schema");
        assert_eq!(schema["title"], title);
        assert_eq!(schema["properties"]["schema_version"]["const"], "1.0");
    }
}
