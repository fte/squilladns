mod zone;

use std::convert::Infallible;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use serde::Deserialize;
use tokio::net::TcpListener;

type HyperBytes = Full<Bytes>;

const VERSION: &str = "0.1.0";
const ZONES_DIR: &str = "zones/575.be";

// ---------------------------------------------------------------------------
// Helpers de réponse
// ---------------------------------------------------------------------------

fn json_response(status: StatusCode, body: impl Into<Bytes>) -> Response<HyperBytes> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(body.into()))
        .unwrap()
}

fn _bad_request(body: impl Into<Bytes>) -> Response<HyperBytes> {
    json_response(StatusCode::BAD_REQUEST, body)
}

fn unauthorized(body: impl Into<Bytes>) -> Response<HyperBytes> {
    json_response(StatusCode::UNAUTHORIZED, body)
}

fn not_found(body: impl Into<Bytes>) -> Response<HyperBytes> {
    json_response(StatusCode::NOT_FOUND, body)
}

fn internal_error(body: impl Into<Bytes>) -> Response<HyperBytes> {
    json_response(StatusCode::INTERNAL_SERVER_ERROR, body)
}

// ---------------------------------------------------------------------------
// Génération d'un token hex aléatoire
// ---------------------------------------------------------------------------

fn generate_token() -> String {
    use std::fmt::Write;
    let bytes: [u8; 32] = std::array::from_fn(|_| rand::random::<u8>());
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        write!(s, "{:02x}", b).ok();
        s
    })
}

fn write_token(path: &Path, secret: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("failed to create token dir: {}", e);
        });
    }
    fs::write(path, secret).unwrap_or_else(|e| {
        eprintln!("failed to write token: {}", e);
    });
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| {
        eprintln!("failed to set permissions: {}", e);
    });
}

// ---------------------------------------------------------------------------
// État partagé
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    token_path: PathBuf,
}

// ---------------------------------------------------------------------------
// Handler principal
// ---------------------------------------------------------------------------

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<HyperBytes>, Infallible> {
    let method = req.method().to_string();
    let path = req.uri().path().to_lowercase();

    // Extraction du header Authorization
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    // Lecture du body
    let _body_bytes = req
        .into_body()
        .collect()
        .await
        .map(|b| b.to_bytes())
        .unwrap_or_default();

    // Vérification du token pour les endpoints protégés
    if matches!(path.as_str(), "/sync" | "/zones" | "/token") {
        if auth.is_empty() {
            return Ok(unauthorized(
                serde_json::json!({ "error": "unauthorized" }).to_string(),
            ));
        }

        if !state.token_path.exists() {
            return Ok(internal_error(
                serde_json::json!({ "error": "token not found" }).to_string(),
            ));
        }

        let stored = fs::read_to_string(&state.token_path).unwrap_or_default();
        let bearer = auth.trim_start_matches("Bearer ").trim();
        if stored.trim() != bearer {
            return Ok(unauthorized(
                serde_json::json!({ "error": "invalid token" }).to_string(),
            ));
        }
    }

    let resp = match (method.as_str(), path.as_str()) {
        ("GET", "/health") => json_response(
            StatusCode::OK,
            serde_json::json!({
                "status": "ok",
                "version": VERSION,
                "zones_dir": ZONES_DIR,
            })
            .to_string(),
        ),

        ("GET", "/zones") => json_response(
            StatusCode::OK,
            serde_json::json!({ "zones": serde_json::Value::Array(vec![]) }).to_string(),
        ),

        ("POST", "/token") => {
            let secret = generate_token();
            write_token(&state.token_path, &secret);
            json_response(
                StatusCode::CREATED,
                serde_json::json!({
                    "created": true,
                    "token": secret,
                })
                .to_string(),
            )
        }

        ("POST", "/sync") => json_response(
            StatusCode::OK,
            serde_json::json!({
                "serial": "0",
                "status": "synced",
                "zone": "",
            })
            .to_string(),
        ),

        _ => not_found(serde_json::json!({ "error": "not_found" }).to_string()),
    };

    Ok(resp)
}

// ---------------------------------------------------------------------------
// Structs de désérialisation (utilisées par zone.rs)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct Record {
    #[serde(alias = "type")]
    pub r#type: String,
    pub name: String,
    pub value: String,
}

#[derive(Deserialize)]
struct ZonePayload {
    records: Vec<Record>,
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // Résolution du chemin du token
    let token_env = std::env::var("API_TOKEN").unwrap_or_default();
    let token_path = PathBuf::from(
        std::env::var("API_TOKEN_PATH")
            .unwrap_or_else(|_| "/app/.api-token".to_string()),
    );

    // Écriture initiale du token depuis la variable d'env, ou génération si absent
    if !token_env.is_empty() {
        write_token(&token_path, &token_env);
    } else if !token_path.exists() {
        let secret = generate_token();
        tracing::warn!("no API_TOKEN set — generated token: {}", secret);
        write_token(&token_path, &secret);
    }

    let state = Arc::new(AppState {
        token_path: token_path.clone(),
    });

    let addr = std::env::var("API_ADDR").unwrap_or_else(|_| "0.0.0.0:8085".to_string());
    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("failed to bind to {}: {}", addr, e);
        std::process::exit(1);
    });

    tracing::info!("squilladns {} listening on {}", VERSION, addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };

        tracing::debug!("connection from {}", peer);

        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(
                    hyper_util::rt::TokioIo::new(stream),
                    service_fn(move |req| handle_request(req, Arc::clone(&state))),
                )
                .await
            {
                eprintln!("connection error: {}", e);
            }
        });
    }
}
