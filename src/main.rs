mod auth;
mod validation;
mod zone;

use squilladns::request_limits::{
    body_limit, parse_max_request_body_bytes, ENV_MAX_REQUEST_BODY_BYTES,
};

use std::fs;
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

use auth::{AuthError, AuthUser, JwtConfig, TokenStore};
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
            Sans header `Authorization` : accès public, scope `public`.\n\
            Avec `Authorization: Bearer <token>` : les zones du porteur sont isolées \
            dans son propre tenant et invisibles aux autres.\n\n\
            Deux mécanismes, aucun provider contacté par l'API :\n\
            - **JWT EdDSA** signé par le BFF (ou HS256 historique) après un SSO (GitHub, Azure, Google…). \
            Claims requis : `iss`, `sub`, `preferred_username`, `exp`, `aud` (`squilladns` par défaut).\n\
            `POST /token` échange ce JWT contre un token API et un slug public ; \
            l'identifiant interne reste privé et stable pour retrouver les zones.\n\
            - **Token API** `sqi_…` (fichier `API_TOKEN_PATH`), rattaché au tenant du porteur.\n\n\
            Un credential présent mais invalide renvoie `401` (`problem+json`) : \
            il n'y a jamais de repli silencieux vers le scope public.\n\
            Mode sandbox : `SANDBOX_USER=alice` (dev local, auth court-circuitée)."
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
    /// Slug public stable basé sur le login SSO.
    slug: Option<String>,
    email: Option<String>,
    /// `jwt`, `token` ou `sandbox`.
    provider: Option<String>,
    /// `public` ou `private`.
    scope: String,
}

#[derive(Serialize, ToSchema)]
struct ZonesResponse {
    zones: Vec<String>,
    /// `public` (anonyme) ou `private` (authentifié)
    scope: String,
}

#[derive(Serialize, ToSchema)]
struct TokenResponse {
    created: bool,
    token: String,
    /// Slug public permettant au client de retrouver le compte et ses zones.
    slug: String,
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

/// État partagé.
///
/// `tokens` et `jwt` sont les deux seuls mécanismes d'auth : aucun provider
/// n'est contacté, donc aucune I/O réseau dans `resolve_caller`.
struct AppState {
    tokens: Mutex<TokenStore>,
    jwt: Option<JwtConfig>,
    /// Identité imposée par `SANDBOX_USER` (mode dev).
    sandbox: Option<AuthUser>,
}

/// Résultat d'authentification calculé une seule fois par le middleware,
/// partagé avec les handlers et les logs d'accès.
#[derive(Clone)]
struct CallerResolution(Result<Option<AuthUser>, AuthError>);

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
                parts.push(format!(
                    "{};dur={:.1};desc=\"{}\"",
                    name,
                    dur,
                    step_label(name)
                ));
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
async fn server_timing(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let timings = Timings::default();
    request.extensions_mut().insert(timings.clone());
    let request_id = request_id(request.headers());
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let bearer = bearer_token(request.headers()).map(str::to_owned);
    let caller = CallerResolution(timed(&timings, "auth", || {
        resolve_caller(request.headers(), &state)
    }));
    request.extensions_mut().insert(caller.clone());
    let resolved_user = caller.0.as_ref().ok().and_then(Option::as_ref);
    // Claims are decoded only after the shared auth result verified this JWT.
    let jwt = if resolved_user
        .as_ref()
        .is_some_and(|user| user.provider == "jwt")
    {
        bearer.as_deref().and_then(auth::jwt_log_fields)
    } else {
        None
    };
    let auth_kind = match (bearer.as_deref(), &caller.0) {
        (None, Ok(Some(user))) if user.provider == "sandbox" => "sandbox",
        (None, _) => "anonymous",
        (Some(_), Ok(Some(user))) if user.provider == "sandbox" => "sandbox",
        (Some(token), Ok(Some(user))) if token.starts_with("sqi_") && user.provider == "token" => {
            "api_token"
        }
        (Some(_), Ok(Some(user))) if user.provider == "jwt" => "jwt",
        (Some(_), _) => "invalid_bearer",
    };

    let mut response = next.run(request).await;
    let total_ms = start.elapsed().as_secs_f64() * 1000.0;
    tracing::info!(
        target: "squilladns::access",
        request_id = %request_id, method = %method, path = %path,
        status = response.status().as_u16(), duration_ms = total_ms,
        auth_kind, jwt_claims_verified = jwt.is_some(),
        jwt_alg = ?jwt.as_ref().and_then(|j| j.alg.as_deref()),
        jwt_kid = ?jwt.as_ref().and_then(|j| j.kid.as_deref()),
        jwt_iss = ?jwt.as_ref().and_then(|j| j.iss.as_deref()),
        jwt_sub = ?jwt.as_ref().and_then(|j| j.sub.as_deref()),
        jwt_aud = ?jwt.as_ref().and_then(|j| j.aud.as_deref()),
        jwt_exp = ?jwt.as_ref().and_then(|j| j.exp),
        jwt_preferred_username = ?jwt.as_ref().and_then(|j| j.preferred_username.as_deref()),
        "http access"
    );

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

/// Décrit les mécanismes actifs, pour `/health` et les logs de démarrage.
fn auth_mode(state: &AppState) -> String {
    if state.sandbox.is_some() {
        return "sandbox".into();
    }

    let mut parts: Vec<&str> = Vec::new();
    if state.jwt.is_some() {
        parts.push("jwt");
    }
    if !state
        .tokens
        .lock()
        .map(|store| store.is_empty())
        .unwrap_or(true)
    {
        parts.push("token");
    }

    if parts.is_empty() {
        "public".into()
    } else {
        parts.join("+")
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()
        .map(|value| value.trim_start_matches("Bearer ").trim())
}

/// Résout l'appelant, sans aucun appel réseau.
///
/// - sandbox configuré → toujours cet utilisateur ;
/// - pas de header → anonyme (`Ok(None)`), scope `public` ;
/// - token API connu → tenant du token ;
/// - JWT valide → tenant dérivé du `sub` ;
/// - credential présent mais invalide → `Err`, et **jamais** de repli anonyme
///   (sinon un JWT expiré écrirait silencieusement dans le scope public).
fn resolve_caller(headers: &HeaderMap, state: &AppState) -> Result<Option<AuthUser>, AuthError> {
    if let Some(ref sandbox) = state.sandbox {
        return Ok(Some(sandbox.clone()));
    }

    let Some(bearer) = bearer_token(headers) else {
        return Ok(None);
    };

    if bearer.is_empty() {
        return Err(AuthError::InvalidToken);
    }

    if let Some((tenant, slug)) = state
        .tokens
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .resolve(bearer)
    {
        return Ok(Some(AuthUser {
            email: None,
            provider: "token".into(),
            tenant,
            legacy_tenant: None,
            slug,
        }));
    }

    if let Some(ref jwt) = state.jwt {
        if jwt_shape(bearer) {
            return jwt.verify(bearer).map(Some);
        }
    }

    Err(AuthError::InvalidToken)
}

/// Un JWT a exactement deux points ; évite de parser n'importe quoi.
fn jwt_shape(token: &str) -> bool {
    token.len() <= 8192 && token.bytes().filter(|byte| *byte == b'.').count() == 2
}

/// Étiquette de scope renvoyée au client. Volontairement sans identifiant :
/// un tenant ne doit pas fuiter dans les réponses ni dans les logs.
fn scope_of(user: &Option<AuthUser>) -> String {
    match user {
        Some(_) => "private".into(),
        None => "public".into(),
    }
}

/// Répertoire de travail : `public/` ou `tenants/<tenant>/`.
///
/// Le tenant est un hachage opaque : plus de collision entre deux identités
/// (`a@b.com` et `a_b.com` tombaient auparavant dans le même `user-a_b.com`).
fn zone_root(user: &Option<AuthUser>) -> PathBuf {
    match user {
        Some(user) => {
            let root = zone::zones_dir();
            let current = auth::tenant_dir(&root, &user.tenant);
            if let Some(legacy) = user.legacy_tenant.as_deref() {
                let previous = auth::tenant_dir(&root, legacy);
                if !current.exists() && previous.exists() {
                    if let Some(parent) = current.parent() {
                        let _ = fs::create_dir_all(parent);
                    }
                    if let Err(error) = fs::rename(&previous, &current) {
                        tracing::warn!("migration du dossier utilisateur impossible: {}", error);
                    }
                }
            }
            current
        }
        None => zone::zones_dir().join("public"),
    }
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

/// Erreur d'authentification au format `problem+json`, avec un `type` stable
/// (`https://squilladns.dev/errors/auth_*`) que le client peut traiter par code.
fn auth_problem(error: AuthError, instance: &str) -> axum::response::Response {
    let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::UNAUTHORIZED);
    let body = ProblemDetails::new(status.as_u16(), error.title())
        .with_type(&format!("https://squilladns.dev/errors/{}", error.code()))
        .with_detail(error.detail())
        .with_instance(instance);

    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
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
fn check_zone_file(zone_name: &str, zone_file: &Path) -> Result<(), validation::ValidationError> {
    let available =
        *NAMED_CHECKZONE.get_or_init(|| Command::new("named-checkzone").arg("-v").output().is_ok());

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
                tracing::error!(
                    "restauration de {} impossible: {}",
                    zone_file.display(),
                    error
                );
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
async fn handle_health(State(state): State<SharedState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".into(),
        version: VERSION.into(),
        zones_dir: zone::zones_dir().display().to_string(),
        auth_mode: auth_mode(&state),
    })
}

/// Retourne l'identité de l'appelant courant
///
/// - Anonyme sans header `Authorization`
/// - Identifié par un token API ou un JWT valide
/// - Toujours identifié en mode sandbox
/// - `401` si un credential est fourni mais invalide
#[utoipa::path(
    get,
    path = "/auth/me",
    responses(
        (status = 200, description = "Identité résolue (peut être anonyme)", body = MeResponse),
        (status = 401, description = "Credential fourni mais invalide", body = ProblemDetails)
    ),
    security(("bearer_token" = []))
)]
async fn handle_me(Extension(caller): Extension<CallerResolution>) -> impl IntoResponse {
    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, "/auth/me"),
    };

    let scope = scope_of(&user);

    match user {
        Some(user) => Json(MeResponse {
            authenticated: true,
            slug: Some(user.slug),
            email: user.email,
            provider: Some(user.provider),
            scope,
        }),
        None => Json(MeResponse {
            authenticated: false,
            slug: None,
            email: None,
            provider: None,
            scope: scope_of(&None),
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
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
) -> impl IntoResponse {
    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, "/zones"),
    };
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
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
    UrlPath(name): UrlPath<String>,
    Json(payload): Json<ZonePayload>,
) -> impl IntoResponse {
    let instance = format!("/zones/{}", name);
    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, &instance),
    };

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
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
    UrlPath(name): UrlPath<String>,
) -> impl IntoResponse {
    let instance = format!("/zones/{}", name);
    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, &instance),
    };

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
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
    Query(query): Query<SyncQuery>,
    body: Bytes,
) -> impl IntoResponse {
    const INSTANCE: &str = "/sync";

    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, INSTANCE),
    };

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

/// Génère un token d'API rattaché au tenant de l'appelant
///
/// Le token créé ouvre le **même scope** que l'appelant (utile pour passer d'un
/// JWT de front à un token de script), et n'invalide aucun token existant.
#[utoipa::path(
    post,
    path = "/token",
    request_body = TokenRequest,
    responses(
        (status = 201, description = "Token créé", body = TokenResponse),
        (status = 400, description = "Body invalide", body = ErrorResponse),
        (status = 401, description = "Authentification requise ou invalide", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_token(
    Extension(caller): Extension<CallerResolution>,
    State(state): State<SharedState>,
    Extension(timings): Extension<Timings>,
    body: Bytes,
) -> impl IntoResponse {
    let user = match caller.0 {
        Ok(Some(user)) => user,
        Ok(None) => return auth_problem(AuthError::Required, "/token"),
        Err(error) => return auth_problem(error, "/token"),
    };

    if !body.is_empty() {
        match serde_json::from_slice::<TokenRequest>(&body) {
            Ok(request) => {
                if let Some(name) = request.name {
                    tracing::info!(
                        "token requested by {} ({}) as '{}'",
                        user.slug,
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

    let secret = timed(&timings, "token", auth::mint_token);
    let stored = state
        .tokens
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .add(&user.tenant, &user.slug, &secret);

    if !stored {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "token store is not writable",
            "/token",
        );
    }

    (
        StatusCode::CREATED,
        Json(TokenResponse {
            created: true,
            token: secret,
            slug: user.slug,
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
// main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    // `tracing-subscriber` est compilé avec `env-filter` : sans RUST_LOG,
    // `fmt::init()` installait un filtre vide et n'affichait plus rien.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let max_request_body_bytes = match parse_max_request_body_bytes(
        std::env::var(ENV_MAX_REQUEST_BODY_BYTES).ok().as_deref(),
    ) {
        Ok(limit) => limit,
        Err(error) => {
            eprintln!("request limit config: {}", error);
            std::process::exit(1);
        }
    };

    let token_env = std::env::var("API_TOKEN").unwrap_or_default();
    let token_path = PathBuf::from(
        std::env::var("API_TOKEN_PATH").unwrap_or_else(|_| ".state/tokens".to_string()),
    );

    // Le token bootstrap a son propre tenant ; les tokens /token héritent du porteur.
    let tokens = TokenStore::load(token_path, &token_env);

    // JWT : configuration optionnelle, mais refusée au démarrage si invalide.
    let jwt = match JwtConfig::from_env() {
        Ok(config) => config,
        Err(error) => {
            eprintln!("auth config: {}", error);
            std::process::exit(1);
        }
    };

    let sandbox = auth::sandbox_user();
    if let Some(ref sandbox) = sandbox {
        tracing::warn!(
            "sandbox mode — toute authentification est court-circuitée, utilisateur: {}",
            sandbox.slug
        );
    }

    let state = Arc::new(AppState {
        tokens: Mutex::new(tokens),
        jwt,
        sandbox,
    });

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
        .layer(body_limit(max_request_body_bytes))
        .layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            server_timing,
        ))
        .layer(cors_layer())
        .with_state(Arc::clone(&state));

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
        auth_mode(&state),
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
