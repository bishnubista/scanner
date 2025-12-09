//! SAFE-MCP Scanner HTTP API
//!
//! A simple HTTP API that wraps the scanner CLI functionality.
//!
//! Endpoints:
//! - GET  /health     - Health check
//! - POST /v1/scan    - Trigger a scan on a repository

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use uuid::Uuid;

mod scanner;

// ============================================================================
// CONFIGURATION
// ============================================================================

#[derive(Clone)]
struct AppState {
    scanner_config: scanner::ScannerConfig,
}

fn get_env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

// ============================================================================
// REQUEST/RESPONSE TYPES
// ============================================================================

#[derive(Debug, Deserialize)]
struct ScanRequest {
    repository_url: String,
    commit_sha: String,
    #[serde(default)]
    techniques: Option<Vec<String>>,
    #[serde(default)]
    changed_files: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct ScanResponse {
    success: bool,
    scan_id: String,
    findings: Vec<Finding>,
    scanner_version: String,
    duration_ms: u64,
    techniques_checked: usize,
    files_scanned: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Finding {
    technique_id: String,
    technique_name: String,
    severity: String,
    file_path: String,
    start_line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_snippet: Option<String>,
    title: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    recommendation: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

// ============================================================================
// HANDLERS
// ============================================================================

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let configured = state.scanner_config.is_configured();

    Json(HealthResponse {
        status: if configured { "ok".to_string() } else { "degraded".to_string() },
        version: env!("CARGO_PKG_VERSION").to_string(),
        message: if !configured {
            Some("Scanner not fully configured - check OPENAI_API_KEY or ANTHROPIC_API_KEY".to_string())
        } else {
            None
        },
    })
}

async fn scan_handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanResponse>, (StatusCode, Json<ErrorResponse>)> {
    let scan_id = Uuid::new_v4().to_string();
    let start_time = std::time::Instant::now();

    info!(
        scan_id = %scan_id,
        repository_url = %request.repository_url,
        commit_sha = %request.commit_sha,
        "Starting scan"
    );

    // Run the scan
    match scanner::run_scan(&state.scanner_config, &request.repository_url, &request.commit_sha, request.techniques.as_deref(), request.changed_files.as_deref()).await {
        Ok(result) => {
            let duration_ms = start_time.elapsed().as_millis() as u64;

            info!(
                scan_id = %scan_id,
                findings_count = result.findings.len(),
                duration_ms = duration_ms,
                "Scan completed"
            );

            Ok(Json(ScanResponse {
                success: true,
                scan_id,
                findings: result.findings,
                scanner_version: env!("CARGO_PKG_VERSION").to_string(),
                duration_ms,
                techniques_checked: result.techniques_checked,
                files_scanned: result.files_scanned,
                error: None,
            }))
        }
        Err(e) => {
            let duration_ms = start_time.elapsed().as_millis() as u64;

            error!(
                scan_id = %scan_id,
                error = %e,
                duration_ms = duration_ms,
                "Scan failed"
            );

            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    success: false,
                    error: e.to_string(),
                }),
            ))
        }
    }
}

// ============================================================================
// MAIN
// ============================================================================

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "scanner_api=info,tower_http=info".into()),
        )
        .json()
        .init();

    // Load configuration
    let scanner_config = scanner::ScannerConfig {
        openai_api_key: std::env::var("OPENAI_API_KEY").ok(),
        anthropic_api_key: std::env::var("ANTHROPIC_API_KEY").ok(),
        techniques_dir: PathBuf::from(get_env("TECHNIQUES_DIR", "/app/techniques")),
        schema_path: PathBuf::from(get_env("SCHEMA_PATH", "/app/schemas/technique.schema.json")),
        safe_mcp_path: PathBuf::from(get_env("SAFE_MCP_PATH", "/app/safe-mcp")),
        provider: get_env("LLM_PROVIDER", "openai"),
        model_name: std::env::var("MODEL_NAME").ok(),
    };

    let state = Arc::new(AppState { scanner_config });

    // Build router
    let app = Router::new()
        .route("/health", get(health_handler))
        .route("/v1/scan", post(scan_handler))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start server
    let port: u16 = get_env("PORT", "8080").parse().unwrap_or(8080);
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    info!("Starting scanner API on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}
