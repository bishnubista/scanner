//! SARIF 2.1.0 output generation for the SAFE-MCP scanner.
//!
//! This module converts scanner findings into the SARIF (Static Analysis Results
//! Interchange Format) for integration with GitHub Code Scanning and other tools.

use engine::{aggregation::Finding, entrypoint::AnalyzeOutput, Technique};
use serde_sarif::sarif;

/// SARIF schema URL for version 2.1.0
const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";

/// Tool information URI
const TOOL_INFO_URI: &str = "https://github.com/anthropics/safe-mcp";

/// Convert internal severity to SARIF result level.
///
/// Maps scanner severity levels (P0-P3 or high/medium/low) to SARIF levels.
pub fn map_severity_to_level(severity: &str) -> sarif::ResultLevel {
    match severity.to_lowercase().as_str() {
        "p0" | "critical" | "high" => sarif::ResultLevel::Error,
        "p1" | "medium" => sarif::ResultLevel::Warning,
        "p2" | "low" => sarif::ResultLevel::Note,
        "p3" | "info" => sarif::ResultLevel::Note,
        _ => sarif::ResultLevel::Warning, // Default to warning for unknown
    }
}

/// Convert internal severity to security-severity score (1.0-9.0).
///
/// This score is used by GitHub Code Scanning for severity classification.
pub fn map_severity_to_score(severity: &str) -> f64 {
    match severity.to_lowercase().as_str() {
        "p0" | "critical" | "high" => 9.0,
        "p1" | "medium" => 6.0,
        "p2" | "low" => 3.0,
        "p3" | "info" => 1.0,
        _ => 6.0, // Default to medium
    }
}

/// Build a SARIF reporting descriptor (rule) from a Technique.
fn technique_to_rule(technique: &Technique) -> sarif::ReportingDescriptor {
    let short_desc = sarif::MultiformatMessageString::builder()
        .text(&technique.name)
        .build();

    let full_desc = sarif::MultiformatMessageString::builder()
        .text(&technique.summary)
        .build();

    let help = sarif::MultiformatMessageString::builder()
        .text(&technique.description)
        .build();

    let level = map_severity_to_level(&technique.severity);

    let config = sarif::ReportingConfiguration::builder()
        .level(serde_json::to_value(level).unwrap_or(serde_json::Value::Null))
        .build();

    // Build properties with security-severity score
    let mut properties = sarif::PropertyBag::default();
    properties.additional_properties.insert(
        "security-severity".to_string(),
        serde_json::json!(map_severity_to_score(&technique.severity)),
    );
    properties.additional_properties.insert(
        "tags".to_string(),
        serde_json::json!(["security", "safe-mcp"]),
    );

    sarif::ReportingDescriptor::builder()
        .id(&technique.id)
        .name(&technique.name)
        .short_description(short_desc)
        .full_description(full_desc)
        .help(help)
        .help_uri(format!("{}/techniques/{}", TOOL_INFO_URI, technique.id))
        .default_configuration(config)
        .properties(properties)
        .build()
}

/// Build a SARIF result from a Finding.
fn finding_to_result(finding: &Finding, technique_id: &str, rule_index: i64) -> sarif::Result {
    // Build artifact location
    let artifact_location = sarif::ArtifactLocation::builder()
        .uri(&finding.file)
        .build();

    // Build region with line numbers and optional code snippet
    let region = if !finding.evidence.is_empty() {
        let snippet = sarif::ArtifactContent::builder()
            .text(&finding.evidence)
            .build();
        sarif::Region::builder()
            .start_line(finding.start_line as i64)
            .end_line(finding.end_line as i64)
            .snippet(snippet)
            .build()
    } else {
        sarif::Region::builder()
            .start_line(finding.start_line as i64)
            .end_line(finding.end_line as i64)
            .build()
    };

    // Build physical location
    let physical_location = sarif::PhysicalLocation::builder()
        .artifact_location(artifact_location)
        .region(region)
        .build();

    // Build location
    let location = sarif::Location::builder()
        .physical_location(physical_location)
        .build();

    // Build message
    let message = sarif::Message::builder()
        .text(&finding.observation)
        .build();

    // Build properties with additional metadata
    let mut properties = sarif::PropertyBag::default();
    if !finding.model_support.is_empty() {
        properties.additional_properties.insert(
            "modelSupport".to_string(),
            serde_json::json!(finding.model_support),
        );
    }
    if !finding.unknown_mitigations.is_empty() {
        properties.additional_properties.insert(
            "mitigations".to_string(),
            serde_json::json!(finding.unknown_mitigations),
        );
    }
    properties.additional_properties.insert(
        "chunkId".to_string(),
        serde_json::json!(finding.chunk_id),
    );

    // Map severity
    let level = map_severity_to_level(&finding.severity);

    sarif::Result::builder()
        .rule_id(technique_id)
        .rule_index(rule_index)
        .level(level)
        .message(message)
        .locations(vec![location])
        .properties(properties)
        .build()
}

/// Build a complete SARIF document from scanner output.
///
/// # Arguments
///
/// * `output` - The analysis output containing findings
/// * `technique` - The technique that was scanned (for rule metadata)
/// * `technique_id` - The technique ID used in the scan
///
/// # Returns
///
/// A SARIF 2.1.0 compliant document ready for serialization.
pub fn build_sarif(output: &AnalyzeOutput, technique: &Technique, technique_id: &str) -> sarif::Sarif {
    // Build the rule for this technique
    let rule = technique_to_rule(technique);

    // Build results from findings
    let results: Vec<sarif::Result> = output
        .analysis
        .findings
        .iter()
        .map(|f| finding_to_result(f, technique_id, 0))
        .collect();

    // Build tool component (driver)
    let driver = sarif::ToolComponent::builder()
        .name("safe-mcp-scan")
        .version(env!("CARGO_PKG_VERSION"))
        .semantic_version(env!("CARGO_PKG_VERSION"))
        .information_uri(TOOL_INFO_URI)
        .rules(vec![rule])
        .build();

    // Build tool
    let tool = sarif::Tool::builder().driver(driver).build();

    // Build automation details for deduplication
    let automation_id = format!(
        "{}/{}",
        technique_id, output.analysis.meta.scanned_at_utc
    );
    let automation_details = sarif::RunAutomationDetails::builder()
        .id(automation_id)
        .build();

    // Build invocation with scan metadata
    let mut invocation_properties = sarif::PropertyBag::default();
    invocation_properties.additional_properties.insert(
        "filesScanned".to_string(),
        serde_json::json!(output.analysis.meta.files_scanned),
    );
    invocation_properties.additional_properties.insert(
        "chunksAnalyzed".to_string(),
        serde_json::json!(output.analysis.meta.chunks_analyzed),
    );

    let invocation = sarif::Invocation::builder()
        .execution_successful(true)
        .properties(invocation_properties)
        .build();

    // Build the run
    let run = sarif::Run::builder()
        .tool(tool)
        .results(results)
        .automation_details(automation_details)
        .invocations(vec![invocation])
        .build();

    // Build the SARIF document
    sarif::Sarif::builder()
        .version(sarif::Version::V2_1_0.to_string())
        .schema(SARIF_SCHEMA)
        .runs(vec![run])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine::status::{AnalysisMeta, AnalysisResult, AnalysisStatus};

    fn mock_technique() -> Technique {
        Technique {
            id: "SAFE-T1001".to_string(),
            name: "Hidden Instruction Injection".to_string(),
            severity: "P1".to_string(),
            summary: "An attacker injects hidden instructions into tool responses".to_string(),
            description: "Detailed description of the technique".to_string(),
            mitigations: vec![],
            code_signals: vec![],
            languages: vec!["rust".to_string()],
            output_schema: engine::OutputSchema {
                requires_mitigations: true,
                allowed_status_values: vec!["pass".into(), "fail".into()],
            },
        }
    }

    fn mock_finding() -> Finding {
        Finding {
            chunk_id: "src/lib.rs:1-50".to_string(),
            file: "src/lib.rs".to_string(),
            start_line: 10,
            end_line: 20,
            severity: "medium".to_string(),
            observation: "Potential hidden instruction injection vector".to_string(),
            evidence: "let response = fetch_external_data();".to_string(),
            model_support: vec!["gpt-4o-mini".to_string()],
            unknown_mitigations: vec!["SAFE-M-1".to_string()],
        }
    }

    fn mock_output() -> AnalyzeOutput {
        AnalyzeOutput {
            analysis: AnalysisResult {
                status: AnalysisStatus::Fail,
                findings: vec![mock_finding()],
                summary: "SAFE-T1001: 1 finding detected".to_string(),
                model_support: vec!["gpt-4o-mini".to_string()],
                meta: AnalysisMeta {
                    scanned_at_utc: "2025-01-01T00:00:00Z".to_string(),
                    files_scanned: 10,
                    chunks_analyzed: 5,
                },
            },
            missing_techniques: vec![],
            extra_techniques: vec![],
            mitigation_titles: vec![],
            readme_path: "safe-mcp/techniques/SAFE-T1001/README.md".to_string(),
        }
    }

    #[test]
    fn test_severity_mapping_p0() {
        assert!(matches!(
            map_severity_to_level("P0"),
            sarif::ResultLevel::Error
        ));
        assert!(matches!(
            map_severity_to_level("critical"),
            sarif::ResultLevel::Error
        ));
        assert!(matches!(
            map_severity_to_level("high"),
            sarif::ResultLevel::Error
        ));
        assert_eq!(map_severity_to_score("P0"), 9.0);
    }

    #[test]
    fn test_severity_mapping_p1() {
        assert!(matches!(
            map_severity_to_level("P1"),
            sarif::ResultLevel::Warning
        ));
        assert!(matches!(
            map_severity_to_level("medium"),
            sarif::ResultLevel::Warning
        ));
        assert_eq!(map_severity_to_score("P1"), 6.0);
    }

    #[test]
    fn test_severity_mapping_p2() {
        assert!(matches!(
            map_severity_to_level("P2"),
            sarif::ResultLevel::Note
        ));
        assert!(matches!(
            map_severity_to_level("low"),
            sarif::ResultLevel::Note
        ));
        assert_eq!(map_severity_to_score("P2"), 3.0);
    }

    #[test]
    fn test_sarif_output_structure() {
        let output = mock_output();
        let technique = mock_technique();
        let sarif_doc = build_sarif(&output, &technique, "SAFE-T1001");

        // Serialize to JSON and verify structure
        let json = serde_json::to_string_pretty(&sarif_doc).expect("serialization should work");

        // Verify required SARIF fields
        assert!(json.contains("\"version\":\"2.1.0\""));
        assert!(json.contains("\"$schema\""));
        assert!(json.contains("safe-mcp-scan"));
        assert!(json.contains("SAFE-T1001"));
    }

    #[test]
    fn test_sarif_contains_findings() {
        let output = mock_output();
        let technique = mock_technique();
        let sarif_doc = build_sarif(&output, &technique, "SAFE-T1001");

        let json = serde_json::to_string(&sarif_doc).expect("serialization");

        // Verify findings are included
        assert!(json.contains("src/lib.rs"));
        assert!(json.contains("Potential hidden instruction injection"));
        assert!(json.contains("gpt-4o-mini"));
    }

    #[test]
    fn test_sarif_empty_findings() {
        let mut output = mock_output();
        output.analysis.findings = vec![];

        let technique = mock_technique();
        let sarif_doc = build_sarif(&output, &technique, "SAFE-T1001");

        let json = serde_json::to_string(&sarif_doc).expect("serialization");

        // Should still have valid structure with empty results
        assert!(json.contains("\"results\":[]"));
    }
}
