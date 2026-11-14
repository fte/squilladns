mod auth;
mod validation;
mod zone;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use axum::{
    body::Bytes,
    extract::{Extension, Path as UrlPath, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::{Any, CorsLayer};
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

use auth::{resolve_user, AuthUser};
use validation::{validate_zone_payload, ProblemDetails, ValidationErrorCode};

const VERSION: &str = "0.1.0";

const HEADER_SERVER_TIMING: HeaderName = HeaderName::from_static("server-timing");
const HEADER_RESPONSE_TIME: HeaderName = HeaderName::from_static("x-response-time");
const HEADER_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");
const HEADER_TIMING_ALLOW_ORIGIN: HeaderName = HeaderName::from_static("timing-allow-origin");

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
            Mode sandbox : `SANDBOX_USER=alice` (dev local, pas de provider requis).\n\
            Un token généré par `POST /token` est aussi accepté comme Bearer (provider `token`)."
    ),
    paths(
        handle_health,
        handle_me,
        handle_list_zones,
        handle_put_zone,
        handle_delete_zone,
        handle_sync,
        handle_token,
    ),
    components(schemas(
        HealthResponse,
        MeResponse,
        ZonesResponse,
        TokenResponse,
        TokenRequest,
        SyncResponse,
        SyncQuery,
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

#[derive(Deserialize, ToSchema)]
pub struct TokenRequest {
    /// Libellé libre du token (informatif)
    pub name: Option<String>,
}

#[derive(Serialize, ToSchema)]
struct SyncResponse {
    /// "created", "updated", "synced" ou "reloaded"
    status: String,
    zone: String,
    serial: String,
    scope: String,
}

#[derive(Deserialize, ToSchema)]
pub struct SyncQuery {
    /// Nom de la zone (obligatoire si aucun body JSON)
    pub zone: Option<String>,
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
// Mesure des temps de réponse (`Server-Timing`)
// ---------------------------------------------------------------------------

/// Sous-mesures accumulées pendant une requête (auth, disque, `named-checkzone`,
/// `rndc`…), transformées en en-tête `Server-Timing` par le middleware.
#[derive(Clone, Default)]
struct Timings(Arc<Mutex<Vec<(&'static str, f64)>>>);

impl Timings {
    /// Enregistre une étape en millisecondes.
    fn record(&self, step: &'static str, elapsed: std::time::Duration) {
        if let Ok(mut steps) = self.0.lock() {
            steps.push((step, elapsed.as_secs_f64() * 1000.0));
        }
    }

    /// `app;dur=12.4;desc="handler", write;dur=1.2;desc="zone file write"`
    fn header_value(&self, total_ms: f64) -> String {
        let mut parts = vec![format!("app;dur={:.1};desc=\"handler\"", total_ms)];

        if let Ok(steps) = self.0.lock() {
            for (name, dur) in steps.iter() {
                parts.push(format!("{};dur={:.1};desc=\"{}\"", name, dur, step_label(name)));
            }
        }

        parts.join(", ")
    }
}

fn step_label(step: &str) -> &str {
    match step {
        "auth" => "authentication",
        "validate" => "payload validation",
        "list" => "list zones",
        "write" => "zone file write",
        "checkzone" => "named-checkzone",
        "rndc" => "rndc reload",
        "delete" => "delete zone",
        "token" => "token generation",
        other => other,
    }
}

/// Exécute `f` en enregistrant sa durée.
fn timed<T>(timings: &Timings, step: &'static str, f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let value = f();
    timings.record(step, start.elapsed());
    value
}

/// Variante asynchrone (résolution de token auprès d'un provider = I/O réseau).
async fn timed_async<T, F>(timings: &Timings, step: &'static str, future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    let value = future.await;
    timings.record(step, start.elapsed());
    value
}

/// Reprend l'identifiant de corrélation du client s'il est plausible,
/// sinon en génère un (8 octets hex).
fn request_id(headers: &HeaderMap) -> String {
    headers
        .get(&HEADER_REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|id| !id.is_empty() && id.len() <= 128 && id.chars().all(|c| c.is_ascii_graphic()))
        .map(str::to_string)
        .unwrap_or_else(|| {
            let bytes: [u8; 8] = std::array::from_fn(|_| rand::random::<u8>());
            bytes.iter().map(|byte| format!("{:02x}", byte)).collect()
        })
}

/// Middleware : mesure la durée totale et publie les en-têtes de timing.
///
/// Il doit rester sous `CorsLayer` pour que les `expose_headers` s'appliquent.
async fn server_timing(mut request: Request, next: Next) -> Response {
    let start = Instant::now();
    let timings = Timings::default();
    request.extensions_mut().insert(timings.clone());
    let request_id = request_id(request.headers());

    let mut response = next.run(request).await;
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;

    let headers = response.headers_mut();

    if let Ok(value) = HeaderValue::from_str(&timings.header_value(total_ms)) {
        headers.insert(HEADER_SERVER_TIMING, value);
    }
    if let Ok(value) = HeaderValue::from_str(&format!("{:.1}ms", total_ms)) {
        headers.insert(HEADER_RESPONSE_TIME, value);
    }
    if let Ok(value) = HeaderValue::from_str(&request_id) {
        headers.insert(HEADER_REQUEST_ID, value);
    }
    headers.insert(HEADER_TIMING_ALLOW_ORIGIN, HeaderValue::from_static("*"));

    response
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn auth_mode() -> String {
    if let Ok(user) = std::env::var("SANDBOX_USER") {
        if !user.is_empty() {
            return format!("sandbox({})", user);
        }
    }
    if let Ok(provider) = std::env::var("AUTH_PROVIDER") {
        if !provider.is_empty() {
            return format!("provider({})", provider);
        }
    }
    "public".into()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .map(|value| value.trim_start_matches("Bearer ").trim())
}

/// Résout l'appelant : token interne d'abord (pas d'appel réseau), puis
/// sandbox / provider OAuth via `auth::resolve_user`. `None` = anonyme.
async fn resolve_caller(headers: &HeaderMap, token_path: &Path) -> Option<AuthUser> {
    if let Some(bearer) = bearer_token(headers) {
        if !bearer.is_empty() && token_matches(token_path, bearer) {
            return Some(AuthUser {
                id: "api-token".into(),
                email: None,
                provider: "token".into(),
            });
        }
    }

    resolve_user(headers).await
}

fn scope_of(user: &Option<AuthUser>) -> String {
    match user {
        Some(user) => format!("private:{}", user.id),
        None => "public".into(),
    }
}

/// Répertoire de travail du scope : `public/` ou `user-<id>/`.
fn scope_dir(user: &Option<AuthUser>) -> String {
    match user {
        Some(user) => format!("user-{}", sanitize_id(&user.id)),
        None => "public".into(),
    }
}

fn sanitize_id(id: &str) -> String {
    let cleaned: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();

    if cleaned.is_empty() {
        "anonymous".into()
    } else {
        cleaned
    }
}

fn zone_root(user: &Option<AuthUser>) -> PathBuf {
    zone::zones_dir().join(scope_dir(user))
}

fn list_zones(root: &Path) -> Result<Vec<String>, String> {
    let mut zones = Vec::new();

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(zones),
        Err(error) => return Err(format!("read {}: {}", root.display(), error)),
    };

    for entry in entries.flatten() {
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        if !is_dir {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.path().join(format!("{}.zone", name)).is_file() {
            zones.push(name);
        }
    }

    zones.sort();
    Ok(zones)
}

fn err(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(ErrorResponse { error: msg.into() })).into_response()
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

/// Normalise un nom de zone pour le système de fichiers (sans point final).
fn normalized_zone_name(raw: &str) -> Result<String, validation::ValidationError> {
    validation::validate_zone_name(raw).map(|zone| zone.trim_end_matches('.').to_string())
}

static NAMED_CHECKZONE: OnceLock<bool> = OnceLock::new();

/// Valide le fichier de zone avec `named-checkzone` quand le binaire existe.
fn check_zone_file(
    zone_name: &str,
    zone_file: &Path,
) -> Result<(), validation::ValidationError> {
    let available = *NAMED_CHECKZONE
        .get_or_init(|| Command::new("named-checkzone").arg("-v").output().is_ok());

    if !available {
        tracing::warn!("named-checkzone introuvable — validation du fichier de zone ignorée");
        return Ok(());
    }

    validation::validate_zone_file_with_named_checkzone(zone_name, zone_file)
}

/// Recharge la zone dans BIND9 si `rndc` est disponible.
fn rndc_reload(zone_name: &str) -> bool {
    match Command::new("rndc").args(["reload", zone_name]).output() {
        Ok(output) if output.status.success() => {
            tracing::info!("rndc reload {}: ok", zone_name);
            true
        }
        Ok(output) => {
            tracing::warn!(
                "rndc reload {}: {}",
                zone_name,
                String::from_utf8_lossy(&output.stderr).trim()
            );
            false
        }
        Err(error) => {
            tracing::debug!("rndc indisponible: {}", error);
            false
        }
    }
}

/// Annule une écriture de zone refusée par `named-checkzone`.
///
/// Si la zone existait, l'ancien contenu est restauré ; sinon le répertoire
/// fraîchement créé est supprimé pour ne pas laisser de fichier invalide.
fn restore_zone(root: &Path, zone_name: &str, zone_file: &Path, previous: Option<String>) {
    match previous {
        Some(content) => {
            if let Err(error) = fs::write(zone_file, content) {
                tracing::error!("restauration de {} impossible: {}", zone_file.display(), error);
            }
        }
        None => {
            let _ = fs::remove_dir_all(root.join(zone_name));
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Redirige la racine vers la documentation Swagger
async fn handle_root() -> Redirect {
    Redirect::permanent("/docs/")
}

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
        zones_dir: zone::zones_dir().display().to_string(),
        auth_mode: auth_mode(),
    })
}

/// Retourne l'identité de l'appelant courant
///
/// - Anonyme si pas de token
/// - Identifié si token valide (provider OAuth ou token interne)
/// - Toujours identifié en mode sandbox
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Identité résolue (peut être anonyme)", body = MeResponse)
    ),
    security(("bearer_token" = []))
)]
async fn handle_me(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
) -> impl IntoResponse {
    match timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await
    {
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
    .into_response()
}

/// Liste les zones du scope courant
///
/// - **Anonyme** : zones publiques
/// - **Authentifié** : zones de l'utilisateur uniquement
#[utoipa::path(
    get,
    path = "/zones",
    responses(
        (status = 200, description = "Liste des zones", body = ZonesResponse),
        (status = 500, description = "Erreur interne", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_list_zones(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
) -> impl IntoResponse {
    let user = timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await;
    let root = zone_root(&user);

    match timed(&timings, "list", || list_zones(&root)) {
        Ok(zones) => Json(ZonesResponse {
            zones,
            scope: scope_of(&user),
        })
        .into_response(),
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            &error,
            "/zones",
        ),
    }
}

/// Installe ou remplace une zone
///
/// Le serial BIND9 est calculé automatiquement : `max(jours UTC, serial + 1)`.
#[utoipa::path(
    put,
    path = "/zones/{name}",
    params(("name" = String, Path, description = "Nom de la zone (ex. alpha.test)")),
    request_body = ZonePayload,
    responses(
        (status = 201, description = "Zone créée", body = SyncResponse),
        (status = 200, description = "Zone mise à jour", body = SyncResponse),
        (status = 400, description = "Nom de zone invalide", body = ProblemDetails),
        (status = 422, description = "Zone invalide", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_put_zone(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
    UrlPath(name): UrlPath<String>,
    Json(payload): Json<ZonePayload>,
) -> impl IntoResponse {
    let instance = format!("/zones/{}", name);
    let user = timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await;

    let zone_name = match normalized_zone_name(&name) {
        Ok(zone_name) => zone_name,
        Err(error) => return validation_problem(&[error], &instance),
    };

    if let Err(errors) = timed(&timings, "validate", || validate_zone_payload(&payload)) {
        return validation_problem(&errors, &instance);
    }

    let root = zone_root(&user);
    let zone_file = zone::zone_file_path(&root, &zone_name);
    let created = !zone_file.exists();
    let previous = fs::read_to_string(&zone_file).ok();
    let serial = zone::compute_serial(zone::read_serial(&zone_file));

    let written = match timed(&timings, "write", || {
        zone::generate_zone_file(&zone_name, &payload.records, serial, &root)
    }) {
        Ok(path) => path,
        Err(error) => {
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                &error,
                &instance,
            );
        }
    };

    if let Err(error) = timed(&timings, "checkzone", || {
        check_zone_file(&zone_name, &written)
    }) {
        restore_zone(&root, &zone_name, &zone_file, previous);
        return validation_problem(&[error], &instance);
    }

    let (code, status) = if created {
        (StatusCode::CREATED, "created")
    } else {
        (StatusCode::OK, "updated")
    };

    (
        code,
        Json(SyncResponse {
            status: status.into(),
            zone: zone_name,
            serial: serial.to_string(),
            scope: scope_of(&user),
        }),
    )
        .into_response()
}

/// Supprime définitivement une zone
#[utoipa::path(
    delete,
    path = "/zones/{name}",
    params(("name" = String, Path, description = "Nom de la zone (ex. alpha.test)")),
    responses(
        (status = 204, description = "Zone supprimée"),
        (status = 404, description = "Zone introuvable", body = ErrorResponse),
        (status = 400, description = "Nom invalide", body = ProblemDetails),
        (status = 422, description = "Nom invalide", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_delete_zone(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
    UrlPath(name): UrlPath<String>,
) -> impl IntoResponse {
    let instance = format!("/zones/{}", name);
    let user = timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await;

    let zone_name = match normalized_zone_name(&name) {
        Ok(zone_name) => zone_name,
        Err(error) => return validation_problem(&[error], &instance),
    };

    let zone_path = zone_root(&user).join(&zone_name);
    if !zone_path.is_dir() {
        return err(StatusCode::NOT_FOUND, "zone not found");
    }

    match timed(&timings, "delete", || fs::remove_dir_all(&zone_path)) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            &format!("failed to delete {}: {}", zone_path.display(), error),
            &instance,
        ),
    }
}

/// Écrit et/ou recharge une zone dans BIND9
///
/// - Body JSON `{ "records": [...] }` : (ré)écrit la zone, puis `rndc reload`.
/// - Query `?zone=<name>` seul : recharge la zone existante.
#[utoipa::path(
    post,
    path = "/sync",
    params(("zone" = Option<String>, Query, description = "Nom de la zone à recharger")),
    request_body = ZonePayload,
    responses(
        (status = 200, description = "Zone synchronisée", body = SyncResponse),
        (status = 400, description = "Requête invalide", body = ErrorResponse),
        (status = 404, description = "Zone introuvable", body = ErrorResponse),
        (status = 422, description = "Zone invalide", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_sync(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
    Query(query): Query<SyncQuery>,
    body: Bytes,
) -> impl IntoResponse {
    const INSTANCE: &str = "/sync";

    let user = timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await;

    let payload = if body.is_empty() {
        None
    } else {
        match serde_json::from_slice::<ZonePayload>(&body) {
            Ok(payload) => Some(payload),
            Err(error) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid JSON body: {}", error),
                );
            }
        }
    };

    if payload.is_none() && query.zone.is_none() {
        return err(
            StatusCode::BAD_REQUEST,
            "missing zone parameter or JSON body",
        );
    }

    let zone_name = match normalized_zone_name(query.zone.as_deref().unwrap_or("default")) {
        Ok(zone_name) => zone_name,
        Err(error) => return validation_problem(&[error], INSTANCE),
    };

    let root = zone_root(&user);
    let zone_file = zone::zone_file_path(&root, &zone_name);

    let serial = match payload {
        Some(payload) => {
            if let Err(errors) = timed(&timings, "validate", || validate_zone_payload(&payload)) {
                return validation_problem(&errors, INSTANCE);
            }

            let serial = zone::compute_serial(zone::read_serial(&zone_file));
            let previous = fs::read_to_string(&zone_file).ok();
            let written = match timed(&timings, "write", || {
                zone::generate_zone_file(&zone_name, &payload.records, serial, &root)
            }) {
                Ok(path) => path,
                Err(error) => {
                    return problem(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Server Error",
                        &error,
                        INSTANCE,
                    );
                }
            };

            if let Err(error) = timed(&timings, "checkzone", || {
                check_zone_file(&zone_name, &written)
            }) {
                restore_zone(&root, &zone_name, &zone_file, previous);
                return validation_problem(&[error], INSTANCE);
            }

            serial
        }
        None => match zone::read_serial(&zone_file) {
            Some(serial) => serial,
            None => {
                return err(
                    StatusCode::NOT_FOUND,
                    &format!("zone {} not found", zone_name),
                );
            }
        },
    };

    let reloaded = timed(&timings, "rndc", || rndc_reload(&zone_name));

    Json(SyncResponse {
        status: if reloaded { "reloaded" } else { "synced" }.into(),
        zone: zone_name,
        serial: serial.to_string(),
        scope: scope_of(&user),
    })
    .into_response()
}

/// Génère ou renouvelle le token d'API interne
///
/// Cet endpoint est protégé — nécessite un utilisateur authentifié.
#[utoipa::path(
    post,
    path = "/token",
    request_body = TokenRequest,
    responses(
        (status = 201, description = "Token créé", body = TokenResponse),
        (status = 400, description = "Body invalide", body = ErrorResponse),
        (status = 401, description = "Authentification requise", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_token(
    headers: HeaderMap,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
    body: Bytes,
) -> impl IntoResponse {
    let Some(user) = timed_async(
        &timings,
        "auth",
        resolve_caller(&headers, &state.token_path),
    )
    .await
    else {
        return err(StatusCode::UNAUTHORIZED, "authentication required");
    };

    if !body.is_empty() {
        match serde_json::from_slice::<TokenRequest>(&body) {
            Ok(request) => {
                if let Some(name) = request.name {
                    tracing::info!(
                        "token requested by {} ({}) as '{}'",
                        user.id,
                        user.provider,
                        name
                    );
                }
            }
            Err(error) => {
                return err(
                    StatusCode::BAD_REQUEST,
                    &format!("invalid JSON body: {}", error),
                );
            }
        }
    }

    let secret = timed(&timings, "token", generate_token);
    append_token(&state.token_path, &secret);

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
        // Sans ces expositions, le navigateur masque les en-têtes de timing
        // et `performance.*.serverTiming` reste vide.
        .expose_headers([
            header::CONTENT_TYPE,
            HEADER_SERVER_TIMING.clone(),
            HEADER_RESPONSE_TIME.clone(),
            HEADER_REQUEST_ID.clone(),
            HEADER_TIMING_ALLOW_ORIGIN.clone(),
        ])
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

/// Écrit le token de bootstrap (API_TOKEN) et applique les permissions 0600.
fn write_token(path: &Path, secret: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| eprintln!("token dir: {}", e));
    }
    fs::write(path, format!("{}\n", secret.trim()))
        .unwrap_or_else(|e| eprintln!("token write: {}", e));
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| eprintln!("token chmod: {}", e));
}

/// Ajoute un token sans invalider les précédents (un token par ligne).
fn append_token(path: &Path, secret: &str) {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| eprintln!("token dir: {}", e));
    }

    let result = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut file| {
            file.write_all(format!("{}\n", secret.trim()).as_bytes())?;
            file.flush()
        });

    if let Err(error) = result {
        eprintln!("token append: {}", error);
    }

    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

/// Vrai si le bearer correspond à une ligne du fichier de tokens.
fn token_matches(path: &Path, bearer: &str) -> bool {
    let content = fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .map(str::trim)
        .any(|line| !line.is_empty() && line == bearer)
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
        .route("/auth/me", get(handle_me))
        .route("/zones", get(handle_list_zones))
        .route(
            "/zones/:name",
            put(handle_put_zone).delete(handle_delete_zone),
        )
        .route("/sync", post(handle_sync))
        .route("/token", post(handle_token))
        .layer(middleware::from_fn(server_timing))
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
        "squilladns {} on {} — mode: {} — docs: http://{}/docs",
        VERSION,
        addr,
        auth_mode(),
        addr
    );

    axum::serve(listener, app).await.unwrap_or_else(|e| {
        eprintln!("server error: {}", e);
        std::process::exit(1);
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn server_timing_lists_total_then_steps() {
        let timings = Timings::default();
        timings.record("write", Duration::from_millis(2));
        timings.record("checkzone", Duration::from_micros(1500));

        assert_eq!(
            timings.header_value(12.44),
            "app;dur=12.4;desc=\"handler\", \
             write;dur=2.0;desc=\"zone file write\", \
             checkzone;dur=1.5;desc=\"named-checkzone\""
        );
    }

    #[test]
    fn server_timing_without_steps_has_only_app() {
        assert_eq!(
            Timings::default().header_value(0.42),
            "app;dur=0.4;desc=\"handler\""
        );
    }

    #[test]
    fn request_id_reuses_client_value_and_rejects_junk() {
        let mut headers = HeaderMap::new();
        assert_eq!(request_id(&headers).len(), 16, "id généré = 8 octets hex");

        headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("abc-123"));
        assert_eq!(request_id(&headers), "abc-123");

        headers.insert(HEADER_REQUEST_ID, HeaderValue::from_static("bad id"));
        assert_eq!(
            request_id(&headers).len(),
            16,
            "un id avec espace est remplacé"
        );
    }
}
