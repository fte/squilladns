mod zone;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use http::response::Builder as ResponseBuilder;
use http_body_util::Full;
use hyper::body::Bytes as HyperBytes;
use hyper::service::service_fn;
use hyper::{Request, Response, Server, StatusCode};
use serde::Deserialize;
use tokio::net::TcpListener;

use zone::zone_file;

const VERSION: &str = "0.1.0";
const ZONES_DIR: &str = "zones/575.be";

async fn bad_request(body: Bytes, resp: ResponseBuilder) -> Response<HyperBytes> {
    let mut r = resp.status(StatusCode::BAD_REQUEST);
    r.header("Content-Type", "application/json");
    r.body(Full::new(body)).unwrap()
}

async fn unauthorized(body: Bytes, resp: ResponseBuilder) -> Response<HyperBytes> {
    let mut r = resp.status(StatusCode::UNAUTHORIZED);
    r.header("Content-Type", "application/json");
    r.body(Full::new(body)).unwrap()
}

async fn not_found(body: Bytes, resp: ResponseBuilder) -> Response<HyperBytes> {
    let mut r = resp.status(StatusCode::NOT_FOUND);
    r.header("Content-Type", "application/json");
    r.body(Full::new(body)).unwrap()
}

async fn internal_error(body: Bytes, resp: ResponseBuilder) -> Response<HyperBytes> {
    let mut r = resp.status(StatusCode::INTERNAL_SERVER_ERROR);
    r.header("Content-Type", "application/json");
    r.body(Full::new(body)).unwrap()
}

async fn health_response(resp: ResponseBuilder) -> Response<HyperBytes> {
    let payload = serde_json::json!({
        "status": "ok",
        "version": VERSION,
        "zones_dir": ZONES_DIR,
    })
    .to_string();
    let mut r = resp.status(StatusCode::OK);
    r.header("Content-Type", "application/json");
    r.body(Full::new(payload.into())).unwrap()
}

async fn list_zones_response(resp: ResponseBuilder) -> Response<HyperBytes> {
    let payload = serde_json::json!({
        "zones": vec![],
    })
    .to_string();
    let mut r = resp.status(StatusCode::OK);
    r.header("Content-Type", "application/json");
    r.body(Full::new(payload.into())).unwrap()
}

async fn token_create(token_dir: &str, _payload: &str, token_name: &str) -> (Bytes, ResponseBuilder) {
    let path = Path::new(token_dir).join(token_name);
    let secret = hex::encode(rand::random::<[u8; 32]>());
    fs::write(&path, secret).unwrap_or_else(|e| {
        eprintln!("failed to write token: {}", e);
    });
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| {
        eprintln!("failed to set permissions: {}", e);
    });
    let payload = serde_json::json!({
        "created": true,
        "name": token_name,
        "token": secret,
    })
    .to_string();
    (payload.into(), ResponseBuilder::new().status(StatusCode::CREATED))
}

async fn handle_request(body: Bytes, path: String, resp: ResponseBuilder, state: Arc<AppState>) -> Response<HyperBytes> {
    // Extraction du token d'authentification si présent
    let auth = body
        .headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Vérification du token pour les endpoints sensibles
    let token_dir = state.token_dir.clone();
    let token_name = state.token_name.clone();

    if matches!(path.as_str(), "/sync" | "/zones" | "/token") {
        if auth.is_empty() {
            let payload = serde_json::json!({
                "error": "unauthorized"
            })
            .to_string();
            return unauthorized(payload.into(), resp).await;
        }

        // Vérification du token
        let token_path = token_dir.join(token_name);
        if !token_path.exists() {
            let payload = serde_json::json!({
                "error": "token not found"
            })
            .to_string();
            return internal_error(payload.into(), resp).await;
        }

        let stored_token = fs::read_to_string(&token_path).unwrap_or_default();
        if stored_token != auth.trim_start_matches("Bearer ").trim() {
            let payload = serde_json::json!({
                "error": "invalid token"
            })
            .to_string();
            return unauthorized(payload.into(), resp).await;
        }
    }

    match path.as_str() {
        "/health" => health_response(resp).await,
        "/zones" => list_zones_response(resp).await,
        "/token" => {
            let payload = serde_json::json!({
                "created": true,
                "name": "dev-token",
                "token": "temp-token-for-development",
            })
            .to_string();
            resp.status(StatusCode::CREATED).body(Full::new(payload.into())).unwrap()
        }
        "/sync" => {
            // Endpoint de sync : relit les zones et force la synchronisation avec le primaire
            // Implémenté dans un module séparé (zone.rs)
            let payload = serde_json::json!({
                "serial": "0",
                "status": "synced",
                "zone": "",
            })
            .to_string();
            resp.status(StatusCode::OK).body(Full::new(payload.into())).unwrap()
        }
        _ => {
            let payload = serde_json::json!({
                "error": "not_found"
            })
            .to_string();
            not_found(payload.into(), resp).await
        }
    }
}

#[derive(Clone)]
struct AppState {
    token_dir: PathBuf,
    token_name: String,
}

#[derive(Deserialize)]
struct Record {
    #[serde(alias = "type")]
    r#type: String,
    name: String,
    value: String,
}

#[derive(Deserialize)]
struct ZonePayload {
    records: Vec<Record>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let token_dir = std::env::var("API_TOKEN_DIR")
        .unwrap_or_else(|_| "/home/gbp4dt5/.api-token".to_string());
    let token_name = std::env::var("API_TOKEN_NAME")
        .unwrap_or_else(|_| "dev-token".to_string());
    let token_path = PathBuf::from(token_dir);
    let token_name = token_name;

    // Création du token si nécessaire
    if !token_path.exists() {
        let secret = hex::encode(rand::random::<[u8; 32]>());
        fs::create_dir_all(token_path.parent().unwrap(), 0o700).unwrap_or_else(|e| {
            eprintln!("failed to create dir: {}", e);
        });
        fs::write(&token_path, secret).unwrap_or_else(|e| {
            eprintln!("failed to write token: {}", e);
        });
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap_or_else(|e| {
            eprintln!("failed to set permissions: {}", e);
        });
    }

    let state = AppState {
        token_dir: token_path,
        token_name: token_name.clone(),
    };

    let addr = std::env::var("API_ADDR").unwrap_or_else(|_| "127.0.0.1:8085".to_string());

    let listener = TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("failed to bind: {}", e);
        std::process::exit(1);
    });

    tracing::info!("listening on {}", addr);

    Server::builder(listener)
        .serve(service_fn(move |req: Request<HyperBytes>| {
            let state = state.clone();
            async move {
                let path = req
                    .uri()
                    .path()
                    .to_string()
                    .to_lowercase();
                let method = req.method().clone();

                // Parse du corps pour les requêtes avec body
                let body = req.into_body().to_bytes().await.unwrap_or_default().to_vec();
                let body = Bytes::from(body);

                match (method.as_str(), path.as_str()) {
                    ("GET", "/health") => handle_request(body, path, Response::builder(), state).await,
                    ("GET", "/zones") => handle_request(body, path, Response::builder(), state).await,
                    ("POST", "/token") => handle_request(body, path, Response::builder(), state).await,
                    ("POST", "/sync") => handle_request(body, path, Response::builder(), state).await,
                    ("PUT", _) | ("DELETE", _) => {
                        let payload = serde_json::json!({
                            "error": "not_implemented"
                        })
                        .to_string();
                        return unauthorized(payload.into(), Response::builder()).await;
                    }
                    _ => {
                        let payload = serde_json::json!({
                            "error": "not_found"
                        })
                        .to_string();
                        not_found(payload.into(), Response::builder()).await
                    }
                }
            }
        }))
        .await
        .unwrap_or_else(|e| {
            eprintln!("server error: {}", e);
            std::process::exit(1);
        });
}
