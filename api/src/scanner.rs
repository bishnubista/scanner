//! Scanner module - wraps the engine to perform scans
//!
//! This module handles:
//! 1. Cloning repositories to temp directories
//! 2. Running technique detection via the engine (in parallel)
//! 3. Returning findings in API format

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use futures::future::join_all;
use tempfile::TempDir;
use tracing::{info, warn};

use crate::Finding;

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Clone)]
pub struct ScannerConfig {
    pub openai_api_key: Option<String>,
    pub anthropic_api_key: Option<String>,
    pub techniques_dir: PathBuf,
    pub schema_path: PathBuf,
    pub safe_mcp_path: PathBuf,
    pub provider: String,
    pub model_name: Option<String>,
}

impl ScannerConfig {
    pub fn is_configured(&self) -> bool {
        match self.provider.as_str() {
            "openai" => self.openai_api_key.is_some(),
            "anthropic" => self.anthropic_api_key.is_some(),
            "local" => true,
            _ => false,
        }
    }
}

// ============================================================================
// SCAN RESULT
// ============================================================================

pub struct ScanResult {
    pub findings: Vec<Finding>,
    pub techniques_checked: usize,
    pub files_scanned: usize,
}

// ============================================================================
// SCANNER IMPLEMENTATION
// ============================================================================

pub async fn run_scan(
    config: &ScannerConfig,
    repository_url: &str,
    commit_sha: &str,
    techniques: Option<&[String]>,
    changed_files: Option<&[String]>,
    github_token: Option<&str>,
) -> Result<ScanResult, Box<dyn std::error::Error + Send + Sync>> {
    // Create temp directory for cloning
    let temp_dir = TempDir::new()?;
    let repo_path = temp_dir.path().join("repo");

    info!(
        repository_url = %repository_url,
        commit_sha = %commit_sha,
        has_token = github_token.is_some(),
        "Cloning repository"
    );

    // Clone the repository
    clone_repository(repository_url, commit_sha, &repo_path, github_token).await?;

    // Get list of techniques to check
    let technique_ids = if let Some(t) = techniques {
        t.to_vec()
    } else {
        // Default: check all priority techniques
        get_default_techniques(config)?
    };

    info!(
        techniques_count = technique_ids.len(),
        "Running technique scans in parallel"
    );

    // Log config paths for debugging
    info!(
        techniques_dir = %config.techniques_dir.display(),
        schema_path = %config.schema_path.display(),
        safe_mcp_path = %config.safe_mcp_path.display(),
        provider = %config.provider,
        "Scanner configuration"
    );

    // Wrap config and repo_path in Arc for sharing across tasks
    let config = Arc::new(config.clone());
    let repo_path = Arc::new(repo_path);
    let changed_files: Option<Arc<[String]>> = changed_files.map(|f| f.to_vec().into());

    // Spawn all technique scans in parallel
    let scan_futures: Vec<_> = technique_ids
        .iter()
        .map(|technique_id| {
            let config = Arc::clone(&config);
            let repo_path = Arc::clone(&repo_path);
            let technique_id = technique_id.clone();
            let changed_files = changed_files.clone();

            async move {
                let cf_slice: Option<&[String]> = changed_files.as_deref();
                let result = scan_technique(&config, &repo_path, &technique_id, cf_slice).await;
                (technique_id, result)
            }
        })
        .collect();

    // Wait for all scans to complete
    let results = join_all(scan_futures).await;

    // Aggregate results
    let mut all_findings = Vec::new();
    let mut files_scanned = 0;
    let mut techniques_succeeded = 0;
    let mut techniques_failed = 0;

    for (technique_id, result) in results {
        match result {
            Ok(scan_result) => {
                info!(
                    technique_id = %technique_id,
                    findings_count = scan_result.findings.len(),
                    files_scanned = scan_result.files_scanned,
                    "Technique scan completed"
                );
                all_findings.extend(scan_result.findings);
                files_scanned = files_scanned.max(scan_result.files_scanned);
                techniques_succeeded += 1;
            }
            Err(e) => {
                warn!(
                    technique_id = %technique_id,
                    error = %e,
                    "Failed to scan technique, continuing with others"
                );
                techniques_failed += 1;
            }
        }
    }

    info!(
        total_findings = all_findings.len(),
        files_scanned = files_scanned,
        techniques_succeeded = techniques_succeeded,
        techniques_failed = techniques_failed,
        "Scan summary"
    );

    // Temp dir is automatically cleaned up when dropped
    Ok(ScanResult {
        findings: all_findings,
        techniques_checked: technique_ids.len(),
        files_scanned,
    })
}

async fn clone_repository(
    url: &str,
    commit_sha: &str,
    dest: &PathBuf,
    github_token: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build clone URL with token if provided (for private repos)
    let clone_url = if let Some(token) = github_token {
        inject_token_into_url(url, token)
    } else {
        url.to_string()
    };

    // Clone with depth 1 for efficiency
    let output = Command::new("git")
        .args(["clone", "--depth", "1", &clone_url, dest.to_str().unwrap()])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Git clone failed: {}", stderr).into());
    }

    // Checkout specific commit if not HEAD
    if commit_sha != "HEAD" && !commit_sha.is_empty() {
        // Fetch the specific commit (use authenticated URL if we have a token)
        let fetch_output = Command::new("git")
            .current_dir(dest)
            .args(["fetch", "--depth", "1", "origin", commit_sha])
            .output()?;

        if fetch_output.status.success() {
            // Checkout the commit
            let checkout_output = Command::new("git")
                .current_dir(dest)
                .args(["checkout", commit_sha])
                .output()?;

            if !checkout_output.status.success() {
                warn!(
                    commit_sha = %commit_sha,
                    "Could not checkout specific commit, using default branch"
                );
            }
        }
    }

    Ok(())
}

/// Inject GitHub token into HTTPS URL for authenticated access.
/// Converts: https://github.com/owner/repo.git
/// To:       https://x-access-token:TOKEN@github.com/owner/repo.git
fn inject_token_into_url(url: &str, token: &str) -> String {
    if url.starts_with("https://github.com") {
        url.replace("https://github.com", &format!("https://x-access-token:{}@github.com", token))
    } else if url.starts_with("https://") {
        // Generic HTTPS URL - insert token after https://
        url.replace("https://", &format!("https://x-access-token:{}@", token))
    } else {
        // Non-HTTPS URL (e.g., SSH), return as-is
        url.to_string()
    }
}

fn get_default_techniques(config: &ScannerConfig) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // Load technique files from the techniques directory
    let outcome = engine::load_techniques(&config.techniques_dir);

    if !outcome.errors.is_empty() {
        for err in &outcome.errors {
            warn!("Technique load error: {:?}", err);
        }
    }

    let ids: Vec<String> = outcome.techniques.iter().map(|t| t.id.clone()).collect();

    if ids.is_empty() {
        // Fallback to well-known technique IDs if no files found
        warn!("No technique files found, using hardcoded defaults");
        return Ok(vec![
            "SAFE-T1001".to_string(),
            "SAFE-T1002".to_string(),
            "SAFE-T1101".to_string(),
            "SAFE-T1201".to_string(),
            "SAFE-T1301".to_string(),
            "SAFE-T1401".to_string(),
            "SAFE-T1501".to_string(),
            "SAFE-T1601".to_string(),
            "SAFE-T1701".to_string(),
            "SAFE-T1801".to_string(),
        ]);
    }

    Ok(ids)
}

struct TechniqueScanResult {
    findings: Vec<Finding>,
    files_scanned: usize,
}

async fn scan_technique(
    config: &ScannerConfig,
    repo_path: &PathBuf,
    technique_id: &str,
    _changed_files: Option<&[String]>,
) -> Result<TechniqueScanResult, Box<dyn std::error::Error + Send + Sync>> {
    // Load the technique spec
    let validation = engine::validate_techniques(&config.techniques_dir, &config.schema_path)?;

    let technique = validation
        .techniques
        .iter()
        .find(|t| t.id == technique_id)
        .ok_or_else(|| format!("Technique {} not found", technique_id))?;

    // Run the analysis based on provider
    let safe_mcp_techniques = config.safe_mcp_path.join("techniques");
    let mitigations_dir = config.safe_mcp_path.join("mitigations");
    let prioritized_path = safe_mcp_techniques.join("prioritized-techniques.md");
    let readme_path = config.safe_mcp_path.join("README.md");

    let result = match config.provider.as_str() {
        "openai" => {
            let key = config
                .openai_api_key
                .as_ref()
                .ok_or("OPENAI_API_KEY not configured")?;
            let model_name = config
                .model_name
                .clone()
                .unwrap_or_else(|| "gpt-4o-mini".to_string());
            let model = engine::adapters::openai::OpenAIModel::new(model_name, key.clone());
            engine::entrypoint::analyze_technique(
                &model,
                technique_id,
                repo_path,
                &config.techniques_dir,
                &config.schema_path,
                &mitigations_dir,
                &safe_mcp_techniques,
                &prioritized_path,
                &readme_path,
                engine::chunk::ScopeKind::FullRepo,
                200,
                None,
            )
            .await?
        }
        "anthropic" => {
            let key = config
                .anthropic_api_key
                .as_ref()
                .ok_or("ANTHROPIC_API_KEY not configured")?;
            let model_name = config
                .model_name
                .clone()
                .unwrap_or_else(|| "claude-3-5-sonnet-20240620".to_string());
            let model = engine::adapters::anthropic::AnthropicModel::new(model_name, key.clone());
            engine::entrypoint::analyze_technique(
                &model,
                technique_id,
                repo_path,
                &config.techniques_dir,
                &config.schema_path,
                &mitigations_dir,
                &safe_mcp_techniques,
                &prioritized_path,
                &readme_path,
                engine::chunk::ScopeKind::FullRepo,
                200,
                None,
            )
            .await?
        }
        _ => {
            let model = engine::adapters::local::LocalModel::default();
            engine::entrypoint::analyze_technique(
                &model,
                technique_id,
                repo_path,
                &config.techniques_dir,
                &config.schema_path,
                &mitigations_dir,
                &safe_mcp_techniques,
                &prioritized_path,
                &readme_path,
                engine::chunk::ScopeKind::FullRepo,
                200,
                None,
            )
            .await?
        }
    };

    // Convert engine findings to API findings
    let findings: Vec<Finding> = result
        .analysis
        .findings
        .iter()
        .map(|f| Finding {
            technique_id: technique_id.to_string(),
            technique_name: technique.name.clone(),
            severity: technique.severity.clone(),
            file_path: f.file.clone(),
            start_line: f.start_line,
            end_line: Some(f.end_line),
            code_snippet: if f.evidence.is_empty() {
                None
            } else {
                Some(f.evidence.clone())
            },
            title: f.observation.clone(),
            description: format!(
                "{}\n\nEvidence: {}",
                technique.description,
                f.evidence
            ),
            recommendation: technique.mitigations.first().map(|m| m.description.clone()),
        })
        .collect();

    Ok(TechniqueScanResult {
        findings,
        files_scanned: result.analysis.meta.files_scanned,
    })
}
