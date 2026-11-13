mod auth;
mod zone;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use auth::resolve_user;

const VERSION: &str = "0.1.0";
const ZONES_DIR: &str = "zones/575.be";

// ---------------------------------------------------------------------------
// OpenAPI spec
// ---------------------------------------------------------------------------

#[derive(OpenApi)]
#[openapi(
    info(
        title = "SquillaDNS API",
        version = "0.1.0",
        description = "DNS zone management API.\n\n\
            ## Authentification (optionnelle)\n\
            Sans token : accès public, toutes les zones sont visibles et modifiables.\n\
            Avec `Authorization: Bearer <token>` : les zones de l'utilisateur sont \
            isolées et invisibles aux autres.\n\n\
            Providers supportés : Google, GitHub, Microsoft.\n\
            Mode sandbox : `SANDBOX_USER=alice` (dev local, pas de provider requis)."
    ),
    paths(
        handle_health,
        handle_me,
        handle_list_zones,
        handle_sync,
        handle_token,
    ),
    components(schemas(
        HealthResponse,
        MeResponse,
        ZonesResponse,
        TokenResponse,
        SyncResponse,
        ErrorResponse,
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
    auth_mode: String,
}

#[derive(Serialize, ToSchema)]
struct MeResponse {
    authenticated: bool,
    id: Option<String>,
    email: Option<String>,
    provider: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct ZonesResponse {
    zones: Vec<String>,
    /// "public" ou "private:<user_id>"
    scope: String,
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
    scope: String,
}

#[derive(Serialize, ToSchema)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize, Serialize, ToSchema, Clone)]
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
// Helpers
// ---------------------------------------------------------------------------

fn auth_mode() -> String {
    if let Ok(u) = std::env::var("SANDBOX_USER") {
        if !u.is_empty() {
            return format!("sandbox({})", u);
        }
    }
    if std::env::var("AUTH_PROVIDER").is_ok() {
        return format!("provider({})", std::env::var("AUTH_PROVIDER").unwrap());
    }
    "public".into()
}

fn err(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// État du service et mode d'authentification actif
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
        auth_mode: auth_mode(),
    })
}

/// Retourne l'identité de l'appelant courant
///
/// - Anonyme si pas de token
/// - Identifié si token valide auprès d'un provider (Google, GitHub, Microsoft)
/// - Toujours identifié en mode sandbox
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Identité résolue (peut être anonyme)", body = MeResponse)
    ),
    security(("bearer_token" = []))
)]
async fn handle_me(headers: HeaderMap) -> impl IntoResponse {
    match resolve_user(&headers).await {
        Some(user) => Json(MeResponse {
            authenticated: true,
            id: Some(user.id),
            email: user.email,
            provider: Some(user.provider),
        }),
        None => Json(MeResponse {
            authenticated: false,
            id: None,
            email: None,
            provider: None,
        }),
    }
}

/// Liste les zones DNS
///
/// - **Anonyme** : retourne toutes les zones publiques
/// - **Authentifié** : retourne uniquement les zones de cet utilisateur
#[utoipa::path(
    get,
    path = "/zones",
    responses(
        (status = 200, description = "Liste des zones", body = ZonesResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_list_zones(
    headers: HeaderMap,
    State(_state): State<SharedState>,
) -> impl IntoResponse {
    let user = resolve_user(&headers).await;

    let (zones, scope) = match &user {
        Some(u) => {
            // TODO: filtrer les zones depuis le stockage par u.id
            tracing::info!("list zones for user {}", u.id);
            (vec![], format!("private:{}", u.id))
        }
        None => {
            // TODO: retourner toutes les zones publiques
            tracing::info!("list zones — public");
            (vec![], "public".into())
        }
    };

    Json(ZonesResponse { zones, scope }).into_response()
}

/// Synchronise / écrit une zone DNS
///
/// - **Anonyme** : écrit dans le namespace public (partagé)
/// - **Authentifié** : écrit dans le namespace de l'utilisateur
#[utoipa::path(
    post,
    path = "/sync",
    request_body = ZonePayload,
    responses(
        (status = 200, description = "Zone synchronisée", body = SyncResponse),
        (status = 400, description = "Payload invalide", body = ErrorResponse),
        (status = 500, description = "Erreur interne", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_sync(
    headers: HeaderMap,
    State(_state): State<SharedState>,
    Json(payload): Json<ZonePayload>,
) -> impl IntoResponse {
    let user = resolve_user(&headers).await;

    // Le nom de zone inclut le namespace : "public" ou "user:<id>"
    let namespace = match &user {
        Some(u) => format!("user-{}", u.id),
        None => "public".into(),
    };

    let zone_name = format!("{}-default", namespace);
    let serial = zone::compute_serial(None);
    let zone_dir = zone::zones_dir();

    match zone::generate_zone_file(&zone_name, &payload.records, serial, &zone_dir) {
        Ok(_) => Json(SyncResponse {
            status: "synced".into(),
            zone: zone_name,
            serial: serial.to_string(),
            scope: match &user {
                Some(u) => format!("private:{}", u.id),
                None => "public".into(),
            },
        })
        .into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, &e),
    }
}

/// Génère ou renouvelle le token d'API interne
///
/// Cet endpoint est protégé — nécessite un utilisateur authentifié.
#[utoipa::path(
    post,
    path = "/token",
    responses(
        (status = 201, description = "Token créé", body = TokenResponse),
        (status = 401, description = "Authentification requise", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_token(
    headers: HeaderMap,
    State(state): State<SharedState>,
) -> impl IntoResponse {
    // /token est le seul endpoint qui exige une auth
    let Some(_user) = resolve_user(&headers).await else {
        return err(StatusCode::UNAUTHORIZED, "authentication required");
    };

    let secret = generate_token();
    write_token(&state.token_path, &secret);

    (
        StatusCode::CREATED,
        Json(TokenResponse { created: true, token: secret }),
    )
        .into_response()
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
        .route("/health",    get(handle_health))
        .route("/auth/me",   get(handle_me))
        .route("/zones",     get(handle_list_zones))
        .route("/sync",      post(handle_sync))
        .route("/token",     post(handle_token))
        .with_state(state);

    let addr = std::env::var("API_ADDR").unwrap_or_else(|_| "0.0.0.0:8085".to_string());
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap_or_else(|e| {
        eprintln!("bind {}: {}", addr, e);
        std::process::exit(1);
    });

    tracing::info!(
        "squilladns {} on {} — mode: {} — docs: http://{}/docs",
        VERSION, addr, auth_mode(), addr
    );

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("server error: {}", e);
        std::process::exit(1);
    });
}
