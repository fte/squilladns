mod validation;
mod zone;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use validation::{validate_zone_payload, ProblemDetails, ValidationErrorCode};

const VERSION: &str = "0.1.0";
const ZONES_DIR: &str = "zones/example.invalid";

// ---------------------------------------------------------------------------
// OpenAPI spec
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    info(
        title = "SquillaDNS API",
        version = "0.1.0",
        description = "DNS zone management API"
    ),
    paths(handle_health, handle_list_zones, handle_token, handle_sync,),
    components(schemas(
        HealthResponse,
        ZonesResponse,
        TokenResponse,
        SyncResponse,
        ErrorResponse,
        ProblemDetails,
        ValidationErrorCode,
        Record,
        ZonePayload,
    ))
)]
struct ApiDoc;

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
struct HealthResponse {
    status: String,
    version: String,
    zones_dir: String,
}

#[derive(Serialize, ToSchema)]
struct ZonesResponse {
    zones: Vec<String>,
}

#[derive(Serialize, ToSchema)]
struct TokenResponse {
    created: bool,
    token: String,
}

#[derive(Serialize, ToSchema)]
struct SyncResponse {
    status: String,
    zone: String,
    serial: String,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct Record {
    #[serde(rename = "type")]
    pub record_type: String,
    pub name: String,
    pub value: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ZonePayload {
    pub records: Vec<Record>,
}

// ---------------------------------------------------------------------------
// État partagé
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    token_path: PathBuf,
}

type SharedState = Arc<AppState>;

// ---------------------------------------------------------------------------
// Middleware d'authentification (extracteur manuel)
// ---------------------------------------------------------------------------

fn check_auth(
    headers: &HeaderMap,
    token_path: &Path,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let auth = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if auth.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "missing authorization header".into(),
            }),
        ));
    }

    let stored = fs::read_to_string(token_path).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "token not configured".into(),
            }),
        )
    })?;
    let bearer = auth.strip_prefix("Bearer ").unwrap_or(auth).trim();

    if stored.trim() != bearer {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid token".into(),
            }),
        ));
    }

    Ok(())
}

fn problem(
    status: StatusCode,
    title: &str,
    detail: &str,
    instance: &str,
) -> axum::response::Response {
    let body = ProblemDetails::new(status.as_u16(), title)
        .with_detail(detail)
        .with_instance(instance);
    (status, Json(body)).into_response()
}

fn validation_problem(
    errors: &[validation::ValidationError],
    instance: &str,
) -> axum::response::Response {
    let body = validation::validation_errors_to_problem_details(errors, Some(instance));
    let status = StatusCode::from_u16(body.status).unwrap_or(StatusCode::BAD_REQUEST);
    (status, Json(body)).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Redirige la racine vers la documentation Swagger
async fn handle_root() -> Redirect {
    Redirect::permanent("/docs/")
}

/// Vérifie l'état du service
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service opérationnel", body = HealthResponse)
    )
)]
async fn handle_health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        version: VERSION.into(),
        zones_dir: ZONES_DIR.into(),
    })
}

/// Liste les zones DNS disponibles
#[utoipa::path(
    get,
    path = "/zones",
    responses(
        (status = 200, description = "Liste des zones", body = ZonesResponse),
        (status = 401, description = "Non autorisé", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_list_zones(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    if let Err(error) = check_auth(&headers, &state.token_path) {
        return error.into_response();
    }

    Json(ZonesResponse { zones: vec![] }).into_response()
}

/// Valide et écrit le fichier de zone DNS
#[utoipa::path(
    post,
    path = "/sync",
    request_body = ZonePayload,
    responses(
        (status = 200, description = "Zone synchronisée", body = SyncResponse),
        (status = 400, description = "Payload invalide", body = ProblemDetails),
        (status = 401, description = "Non autorisé", body = ErrorResponse),
        (status = 422, description = "Zone invalide", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_sync(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Json(payload): Json<ZonePayload>,
) -> impl IntoResponse {
    if let Err(error) = check_auth(&headers, &state.token_path) {
        return error.into_response();
    }

    if let Err(errors) = validate_zone_payload(&payload) {
        return validation_problem(&errors, "/sync");
    }

    let zone_name = "default";
    let serial = zone::compute_serial(None);
    let zone_file =
        match zone::generate_zone_file(zone_name, &payload.records, serial, &zone::zones_dir()) {
            Ok(path) => path,
            Err(error) => {
                return problem(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal Server Error",
                    &error,
                    "/sync",
                );
            }
        };

    if let Err(error) = validation::validate_zone_file_with_named_checkzone(zone_name, &zone_file) {
        return validation_problem(&[error], "/sync");
    }

    Json(SyncResponse {
        status: "synced".into(),
        zone: zone_name.into(),
        serial: serial.to_string(),
    })
    .into_response()
}

/// Génère ou renouvelle le token d'API
#[utoipa::path(
    post,
    path = "/token",
    responses(
        (status = 201, description = "Token créé", body = TokenResponse),
        (status = 401, description = "Authentification requise", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_token(headers: HeaderMap, State(state): State<SharedState>) -> impl IntoResponse {
    if let Err(error) = check_auth(&headers, &state.token_path) {
        return error.into_response();
    }

    let secret = generate_token();
    write_token(&state.token_path, &secret);

    (
        StatusCode::CREATED,
        Json(TokenResponse {
            created: true,
            token: secret,
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

/// Construit la couche CORS.
///
/// `CORS_ALLOWED_ORIGINS` accepte une liste séparée par des virgules
/// (ex. `http://localhost:8904,null`) ou `*` pour tout autoriser.
/// Par défaut : tout autoriser, pratique pour les clients `file://` (Origin: null)
/// et les serveurs statiques locaux sur un port quelconque.
fn cors_layer() -> CorsLayer {
    let raw = std::env::var("CORS_ALLOWED_ORIGINS").unwrap_or_default();
    let listed: Vec<HeaderValue> = raw
        .split(',')
        .map(str::trim)
        .filter(|origin| !origin.is_empty())
        .filter_map(|origin| HeaderValue::from_str(origin).ok())
        .collect();

    let layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
        .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE, header::ACCEPT])
        .expose_headers([header::CONTENT_TYPE])
        .max_age(std::time::Duration::from_secs(3600));

    if raw.contains('*') || listed.is_empty() {
        layer.allow_origin(Any)
    } else {
        layer.allow_origin(listed)
    }
}

// ---------------------------------------------------------------------------
// Token utils
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
        fs::create_dir_all(parent).unwrap_or_else(|e| eprintln!("token dir: {}", e));
    }
    fs::write(path, secret).unwrap_or_else(|e| eprintln!("token write: {}", e));
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| eprintln!("token chmod: {}", e));
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let token_env = std::env::var("API_TOKEN").unwrap_or_default();
    let token_path = PathBuf::from(
        std::env::var("API_TOKEN_PATH").unwrap_or_else(|_| "/app/.api-token".to_string()),
    );

    if !token_env.is_empty() {
        write_token(&token_path, &token_env);
    } else if !token_path.exists() {
        let secret = generate_token();
        tracing::warn!("no API_TOKEN set — generated token: {}", secret);
        write_token(&token_path, &secret);
    }

    let state = Arc::new(AppState { token_path });

    let app = Router::new()
        .merge(SwaggerUi::new("/docs").url("/docs/openapi.json", ApiDoc::openapi()))
        .route("/", get(handle_root))
        .route("/health", get(handle_health))
        .route("/zones", get(handle_list_zones))
        .route("/token", post(handle_token))
        .route("/sync", post(handle_sync))
        .layer(cors_layer())
        .with_state(state);

    let addr = std::env::var("API_ADDR").unwrap_or_else(|_| "0.0.0.0:8085".to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("bind {}: {}", addr, e);
            std::process::exit(1);
        });

    tracing::info!(
        "squilladns {} on {} — docs: http://{}/docs",
        VERSION,
        addr,
        addr
    );

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("server error: {}", e);
        std::process::exit(1);
    });
}
