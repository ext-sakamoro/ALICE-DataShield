use axum::{extract::State, response::Json, routing::{get, post}, Router};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

struct AppState { start_time: Instant, stats: Mutex<Stats> }
struct Stats { total_scans: u64, total_classifications: u64, total_alerts: u64, data_sources_monitored: u64 }

#[derive(Serialize)]
struct Health { status: String, version: String, uptime_secs: u64, total_ops: u64 }

#[derive(Deserialize)]
struct ScanRequest { data_source: String, source_type: Option<String>, deep_scan: Option<bool> }
#[derive(Serialize)]
struct ScanResponse { scan_id: String, data_source: String, files_scanned: u64, sensitive_files: u64, classifications: Vec<Classification>, posture_score: f64, elapsed_ms: u64 }
#[derive(Serialize)]
struct Classification { path: String, category: String, confidence: f64, pii_types: Vec<String> }

#[derive(Deserialize)]
struct PostureRequest { scope: Option<String> }
#[derive(Serialize)]
struct PostureResponse { posture_id: String, overall_score: f64, risk_level: String, findings: Vec<Finding>, recommendations: Vec<String> }
#[derive(Serialize)]
struct Finding { category: String, severity: String, count: u32, description: String }

#[derive(Deserialize)]
struct EncryptAuditRequest { data_source: String }
#[derive(Serialize)]
struct EncryptAuditResponse { audit_id: String, data_source: String, encrypted_at_rest: bool, encrypted_in_transit: bool, key_rotation_days: u32, compliance: Vec<String>, recommendations: Vec<String> }

#[derive(Serialize)]
struct StatsResponse { total_scans: u64, total_classifications: u64, total_alerts: u64, data_sources_monitored: u64 }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "alice_datashield_engine=info".into())).init();
    let state = Arc::new(AppState { start_time: Instant::now(), stats: Mutex::new(Stats { total_scans: 0, total_classifications: 0, total_alerts: 0, data_sources_monitored: 0 }) });
    let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/datashield/scan", post(scan_data))
        .route("/api/v1/datashield/posture", post(check_posture))
        .route("/api/v1/datashield/encrypt-audit", post(encrypt_audit))
        .route("/api/v1/datashield/stats", get(stats))
        .layer(cors).layer(TraceLayer::new_for_http()).with_state(state);
    let addr = std::env::var("DATASHIELD_ADDR").unwrap_or_else(|_| "0.0.0.0:8081".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    tracing::info!("DataShield Engine on {addr}");
    axum::serve(listener, app).await.unwrap();
}

async fn health(State(s): State<Arc<AppState>>) -> Json<Health> {
    let st = s.stats.lock().unwrap();
    Json(Health { status: "ok".into(), version: env!("CARGO_PKG_VERSION").into(), uptime_secs: s.start_time.elapsed().as_secs(), total_ops: st.total_scans + st.total_classifications })
}

async fn scan_data(State(s): State<Arc<AppState>>, Json(req): Json<ScanRequest>) -> Json<ScanResponse> {
    let start = Instant::now();
    let mut st = s.stats.lock().unwrap(); st.total_scans += 1; st.total_classifications += 3; st.data_sources_monitored += 1;
    Json(ScanResponse { scan_id: uuid::Uuid::new_v4().to_string(), data_source: req.data_source, files_scanned: 1250, sensitive_files: 47,
        classifications: vec![
            Classification { path: "users/emails.csv".into(), category: "PII".into(), confidence: 0.98, pii_types: vec!["email".into(), "name".into()] },
            Classification { path: "payments/cards.json".into(), category: "PCI".into(), confidence: 0.95, pii_types: vec!["credit_card".into()] },
            Classification { path: "health/records.db".into(), category: "PHI".into(), confidence: 0.92, pii_types: vec!["medical_record".into()] },
        ], posture_score: 72.5, elapsed_ms: start.elapsed().as_millis() as u64 })
}

async fn check_posture(State(s): State<Arc<AppState>>, Json(_req): Json<PostureRequest>) -> Json<PostureResponse> {
    let st = s.stats.lock().unwrap();
    Json(PostureResponse { posture_id: uuid::Uuid::new_v4().to_string(), overall_score: 72.5, risk_level: "medium".into(),
        findings: vec![
            Finding { category: "Encryption".into(), severity: "high".into(), count: 3, description: "3 data stores lack encryption at rest".into() },
            Finding { category: "Access Control".into(), severity: "medium".into(), count: 12, description: "12 overprivileged service accounts".into() },
            Finding { category: "Data Retention".into(), severity: "low".into(), count: 5, description: "5 datasets exceed retention policy".into() },
        ], recommendations: vec!["Enable encryption at rest for all S3 buckets".into(), "Rotate service account keys older than 90 days".into(), "Archive datasets older than retention policy".into()],
    })
}

async fn encrypt_audit(State(s): State<Arc<AppState>>, Json(req): Json<EncryptAuditRequest>) -> Json<EncryptAuditResponse> {
    let mut st = s.stats.lock().unwrap(); st.total_alerts += 1;
    Json(EncryptAuditResponse { audit_id: uuid::Uuid::new_v4().to_string(), data_source: req.data_source,
        encrypted_at_rest: true, encrypted_in_transit: true, key_rotation_days: 45,
        compliance: vec!["GDPR Art.32".into(), "HIPAA 164.312(a)".into(), "SOC2 CC6.1".into()],
        recommendations: vec!["Key rotation exceeds 30-day best practice. Consider automating rotation.".into()] })
}

async fn stats(State(s): State<Arc<AppState>>) -> Json<StatsResponse> {
    let st = s.stats.lock().unwrap();
    Json(StatsResponse { total_scans: st.total_scans, total_classifications: st.total_classifications, total_alerts: st.total_alerts, data_sources_monitored: st.data_sources_monitored })
}
