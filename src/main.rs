mod auth;
mod validation;
mod zone;

use squilladns::bind::{self, RndcClient, RndcError};
use squilladns::request_limits::{
    body_limit, run_limited, run_limited_by, BlockingWorkError, RequestLimits,
};

use std::collections::HashMap;
use std::fs;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
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
use validation::{ProblemDetails, ValidationErrorCode};

const VERSION: &str = "0.1.0";
const DEFAULT_ZONE_LIST_LIMIT: usize = 100;
const MAX_ZONE_LIST_LIMIT: usize = 500;

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
        ZoneListQuery,
        TokenResponse,
        TokenRequest,
        SyncResponse,
        DeleteResponse,
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
    /// Offset à utiliser pour récupérer la page suivante.
    next_offset: Option<usize>,
    /// `public` (anonyme) ou `private` (authentifié)
    scope: String,
}

#[derive(Deserialize, ToSchema)]
struct ZoneListQuery {
    /// Nombre maximal de zones dans la réponse (1 à 500, défaut 100).
    limit: Option<usize>,
    /// Nombre de zones à ignorer avant la page retournée.
    offset: Option<usize>,
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
    /// Le fichier de zone est publié sur disque.
    persisted: bool,
    /// Résultat du rechargement demandé ; absent si aucun reload n'a été demandé.
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    /// Code machine lisible si la zone a été persistée mais pas activée.
    #[serde(skip_serializing_if = "Option::is_none")]
    activation_error: Option<String>,
    zone: String,
    serial: String,
    scope: String,
}

#[derive(Serialize, ToSchema)]
struct DeleteResponse {
    status: String,
    persisted: bool,
    /// Résultat de la désactivation BIND, absent si le mode dynamique est désactivé.
    #[serde(skip_serializing_if = "Option::is_none")]
    active: Option<bool>,
    zone: String,
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
    tokens: Arc<Mutex<TokenStore>>,
    token_updates: Arc<tokio::sync::Mutex<()>>,
    jwt: Option<JwtConfig>,
    request_limits: RequestLimits,
    validation_slots: Arc<tokio::sync::Semaphore>,
    io_slots: Arc<tokio::sync::Semaphore>,
    rndc: RndcClient,
    publications: PublicationQueue,
    zone_locks: ZoneLocks,
    /// Identité imposée par `SANDBOX_USER` (mode dev).
    sandbox: Option<AuthUser>,
}

#[derive(Clone, Default)]
struct ZoneLocks(Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>);

impl ZoneLocks {
    async fn lock(&self, key: String) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.0.lock().expect("zone lock map poisoned");
            locks.retain(|_, lock| lock.strong_count() > 0);
            if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
                lock
            } else {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(key, Arc::downgrade(&lock));
                lock
            }
        };
        lock.lock_owned().await
    }
}

async fn lock_zone(
    state: &AppState,
    key: String,
    timings: &Timings,
) -> tokio::sync::OwnedMutexGuard<()> {
    let start = Instant::now();
    let guard = state.zone_locks.lock(key).await;
    timings.record("lock", start.elapsed());
    guard
}

struct PublicationRequest {
    root: PathBuf,
    zone_name: String,
    tenant: String,
    queued_at: Instant,
    timings: Timings,
    reply: tokio::sync::oneshot::Sender<Result<(), PublicationError>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct PublicationBatchKey {
    tenant: String,
    zone_name: String,
}

impl PublicationBatchKey {
    fn new(tenant: &str, zone_name: &str) -> Self {
        Self {
            tenant: tenant.to_string(),
            zone_name: zone_name.to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PublicationError {
    Saturated,
    WorkerFailed,
    Ownership,
    ZoneFile,
    StatePersistence,
    Rndc(RndcError),
}

impl PublicationError {
    fn code(self) -> &'static str {
        match self {
            Self::Saturated => "publication_capacity_exhausted",
            Self::WorkerFailed => "publication_worker_failed",
            Self::Ownership => "zone_ownership_unavailable",
            Self::ZoneFile => "zone_file_unavailable",
            Self::StatePersistence => "publication_state_persistence_failed",
            Self::Rndc(RndcError::Unavailable) => "rndc_unavailable",
            Self::Rndc(RndcError::TimedOut) => "rndc_timeout",
            Self::Rndc(RndcError::SpawnFailed) => "rndc_spawn_failed",
            Self::Rndc(RndcError::CommandFailed(_)) => "rndc_command_failed",
        }
    }
}

fn verify_publication_owner(
    owners_dir: &Path,
    zone_name: &str,
    tenant: &str,
) -> Result<bind::OwnerState, PublicationError> {
    match bind::read_zone_owner(owners_dir, zone_name) {
        Ok(Some(owner)) if owner.tenant == tenant => Ok(owner.state),
        Ok(_) => Err(PublicationError::Ownership),
        Err(_) => Err(PublicationError::Ownership),
    }
}

fn activate_owned_zone(
    rndc: &RndcClient,
    owners_dir: &Path,
    zone_name: &str,
    tenant: &str,
    zone_file: &str,
    previous_state: bind::OwnerState,
    timings: &[Timings],
) -> Result<(), PublicationError> {
    bind::set_zone_owner_state(owners_dir, zone_name, tenant, bind::OwnerState::Activating)
        .map_err(|_| PublicationError::StatePersistence)?;

    let rndc_start = Instant::now();
    let activation = rndc.activate_zone(
        zone_name,
        zone_file,
        previous_state != bind::OwnerState::Inactive,
    );
    let rndc_elapsed = rndc_start.elapsed();
    for timing in timings {
        timing.record("rndc", rndc_elapsed);
    }
    activation.map_err(PublicationError::Rndc)?;

    bind::set_zone_owner_state(owners_dir, zone_name, tenant, bind::OwnerState::Active)
        .map_err(|_| PublicationError::StatePersistence)
}

#[derive(Clone)]
struct PublicationQueue {
    sender: tokio::sync::mpsc::Sender<PublicationRequest>,
}

impl PublicationQueue {
    fn new(rndc: RndcClient, io_slots: Arc<tokio::sync::Semaphore>, zone_locks: ZoneLocks) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<PublicationRequest>(256);
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut batches: HashMap<PublicationBatchKey, Vec<PublicationRequest>> =
                    HashMap::new();
                batches
                    .entry(PublicationBatchKey::new(&first.tenant, &first.zone_name))
                    .or_default()
                    .push(first);

                let debounce = tokio::time::sleep(std::time::Duration::from_millis(40));
                tokio::pin!(debounce);
                loop {
                    tokio::select! {
                        _ = &mut debounce => break,
                        request = receiver.recv() => match request {
                            Some(request) => batches.entry(PublicationBatchKey::new(&request.tenant, &request.zone_name)).or_default().push(request),
                            None => break,
                        }
                    }
                }

                for (key, requests) in batches {
                    let last = requests.last().expect("nonempty publication batch");
                    let root = last.root.clone();
                    let tenant = key.tenant;
                    let zone_name = key.zone_name;
                    let request_timings: Vec<_> = requests
                        .iter()
                        .map(|request| (request.timings.clone(), request.queued_at))
                        .collect();
                    let request_id = request_timings
                        .first()
                        .map(|(timings, _)| timings.request_id())
                        .unwrap_or_else(|| "unknown".into());
                    let rndc = rndc.clone();
                    let locks = zone_locks.clone();
                    let lock = locks.lock(zone_lock_key(&zone_name)).await;
                    let result = run_limited(Arc::clone(&io_slots), move || {
                        let _zone_guard = lock;
                        for (timings, queued_at) in &request_timings {
                            timings.record(
                                "queue",
                                Instant::now().saturating_duration_since(*queued_at),
                            );
                        }
                        let owners_dir = zone_owners_dir();
                        let owner_state = match verify_publication_owner(
                            &owners_dir,
                            &zone_name,
                            &tenant,
                        ) {
                            Ok(state) => state,
                            Err(error) => {
                                tracing::warn!(request_id = %request_id, zone = %zone_name, "publication rejected by zone ownership");
                                return Err(error);
                            }
                        };
                        let zone_file = zone::zone_file_path(&root, &zone_name);
                        let canonical_file = match fs::canonicalize(zone_file) {
                            Ok(path) => path,
                            Err(_) => return Err(PublicationError::ZoneFile),
                        };
                        let Some(canonical_file) = canonical_file.to_str() else {
                            return Err(PublicationError::ZoneFile);
                        };
                        let activation = activate_owned_zone(
                            &rndc,
                            &owners_dir,
                            &zone_name,
                            &tenant,
                            canonical_file,
                            owner_state,
                            &request_timings
                                .iter()
                                .map(|(timings, _)| timings.clone())
                                .collect::<Vec<_>>(),
                        );
                        if let Err(error) = activation {
                            if let PublicationError::Rndc(error) = error {
                            tracing::warn!(request_id = %request_id, zone = %zone_name, error = ?error, "BIND activation failed");
                            } else {
                                tracing::error!(request_id = %request_id, zone = %zone_name, code = error.code(), "BIND activation state update failed");
                            }
                            return Err(error);
                        }
                        Ok(())
                    })
                    .await
                    .map_err(|error| match error {
                        BlockingWorkError::Saturated => PublicationError::Saturated,
                        BlockingWorkError::WorkerFailed => PublicationError::WorkerFailed,
                    })
                    .and_then(|result| result);

                    for request in requests {
                        let _ = request.reply.send(result);
                    }
                }
            }
        });
        Self { sender }
    }

    async fn publish(
        &self,
        root: PathBuf,
        zone_name: String,
        tenant: String,
        timings: Timings,
    ) -> Result<(), PublicationError> {
        let (reply, response) = tokio::sync::oneshot::channel();
        let request = PublicationRequest {
            root,
            zone_name,
            tenant,
            queued_at: Instant::now(),
            timings,
            reply,
        };
        if self.sender.try_send(request).is_err() {
            return Err(PublicationError::Saturated);
        }
        response
            .await
            .unwrap_or(Err(PublicationError::WorkerFailed))
    }
}

fn zone_lock_key(zone_name: &str) -> String {
    zone::zones_dir()
        .join(".zone-locks")
        .join(zone_name)
        .to_string_lossy()
        .into_owned()
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
struct Timings {
    entries: Arc<Mutex<Vec<(&'static str, f64, Option<String>)>>>,
    request_id: Arc<Mutex<Option<String>>>,
}

impl Timings {
    /// Enregistre une étape en millisecondes.
    fn record(&self, step: &'static str, elapsed: std::time::Duration) {
        if let Ok(mut steps) = self.entries.lock() {
            steps.push((step, elapsed.as_secs_f64() * 1000.0, None));
        }
    }

    fn record_detail(&self, step: &'static str, detail: String) {
        if let Ok(mut steps) = self.entries.lock() {
            steps.push((step, 0.0, Some(detail)));
        }
    }

    /// `app;dur=12.4;desc="handler", write;dur=1.2;desc="zone file write"`
    fn header_value(&self, total_ms: f64) -> String {
        let mut parts = vec![format!("app;dur={:.1};desc=\"handler\"", total_ms)];

        if let Ok(steps) = self.entries.lock() {
            for (name, dur, detail) in steps.iter() {
                let desc = detail.as_deref().unwrap_or_else(|| step_label(name));
                parts.push(format!("{};dur={:.1};desc=\"{}\"", name, dur, desc));
            }
        }

        parts.join(", ")
    }

    fn set_request_id(&self, request_id: String) {
        if let Ok(mut stored) = self.request_id.lock() {
            *stored = Some(request_id);
        }
    }

    fn request_id(&self) -> String {
        self.request_id
            .lock()
            .ok()
            .and_then(|stored| stored.clone())
            .unwrap_or_else(|| "unknown".into())
    }
}

fn step_label(step: &str) -> &str {
    match step {
        "auth" => "authentication",
        "validate" => "payload validation",
        "list" => "list zones",
        "write" => "zone file write",
        "filesystem" => "filesystem work",
        "checkzone" => "named-checkzone",
        "rndc" => "rndc reload",
        "publish" => "BIND publication",
        "queue" => "publication queue wait",
        "lock" => "zone lock wait",
        "payload" => "request payload",
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

async fn timed_async<T>(
    timings: &Timings,
    step: &'static str,
    future: impl Future<Output = T>,
) -> T {
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
async fn server_timing(
    State(state): State<SharedState>,
    mut request: Request,
    next: Next,
) -> Response {
    let start = Instant::now();
    let timings = Timings::default();
    request.extensions_mut().insert(timings.clone());
    let request_id = request_id(request.headers());
    timings.set_request_id(request_id.clone());
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
    zone_root_under(&zone::zones_dir(), user)
}

fn zone_root_under(zones_dir: &Path, user: &Option<AuthUser>) -> PathBuf {
    match user {
        Some(user) => auth::tenant_dir(zones_dir, &user.tenant),
        None => zones_dir.join("public"),
    }
}

/// Migration de l'ancien répertoire tenant. À appeler depuis le pool I/O.
fn migrate_legacy_zone_root(user: &Option<AuthUser>, current: &Path) {
    let Some(user) = user else { return };
    let Some(legacy) = user.legacy_tenant.as_deref() else {
        return;
    };
    let previous = auth::tenant_dir(&zone::zones_dir(), legacy);
    if !current.exists() && previous.exists() {
        if let Some(parent) = current.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Err(error) = fs::rename(&previous, current) {
            tracing::warn!("migration du dossier utilisateur impossible: {}", error);
        }
    }
}

fn list_zones(
    root: &Path,
    offset: usize,
    limit: usize,
) -> Result<(Vec<String>, Option<usize>), String> {
    let mut zones = Vec::new();

    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok((zones, None)),
        Err(error) => return Err(format!("could not read zones directory: {}", error)),
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
    let mut page: Vec<_> = zones.into_iter().skip(offset).take(limit + 1).collect();
    let has_more = page.len() > limit;
    if has_more {
        page.pop();
    }
    let next_offset = has_more.then(|| offset.saturating_add(limit));
    Ok((page, next_offset))
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
    let code = match status {
        StatusCode::BAD_REQUEST => "bad_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::UNPROCESSABLE_ENTITY => "validation_failed",
        StatusCode::SERVICE_UNAVAILABLE => "service_unavailable",
        _ => "internal_error",
    };
    problem_with_code(status, title, code, detail, instance)
}

fn problem_with_code(
    status: StatusCode,
    title: &str,
    code: &str,
    detail: &str,
    instance: &str,
) -> axum::response::Response {
    let body = ProblemDetails::new(status.as_u16(), title)
        .with_detail(detail)
        .with_instance(instance)
        .with_extension("code", serde_json::Value::String(code.into()));
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

enum ZonePayloadError {
    InvalidJson(String),
    InvalidRecords(Vec<validation::ValidationError>),
    Saturated,
    WorkerFailed,
}

async fn parse_and_validate_zone_payload(
    body: Bytes,
    limits: RequestLimits,
    slots: Arc<tokio::sync::Semaphore>,
) -> Result<Vec<validation::ValidatedRecord>, ZonePayloadError> {
    let result = run_limited(slots, move || {
        let payload = serde_json::from_slice::<ZonePayload>(&body)
            .map_err(|error| ZonePayloadError::InvalidJson(error.to_string()))?;
        validation::validate_zone_payload_with_limits(&payload, &limits)
            .map_err(ZonePayloadError::InvalidRecords)
    })
    .await
    .map_err(|error| match error {
        BlockingWorkError::Saturated => ZonePayloadError::Saturated,
        BlockingWorkError::WorkerFailed => ZonePayloadError::WorkerFailed,
    })?;
    result
}

fn zone_payload_error_response(error: ZonePayloadError, instance: &str) -> Response {
    match error {
        ZonePayloadError::InvalidJson(error) => err(
            StatusCode::BAD_REQUEST,
            &format!("invalid JSON body: {}", error),
        ),
        ZonePayloadError::InvalidRecords(errors) => validation_problem(&errors, instance),
        ZonePayloadError::Saturated => problem_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "validation_capacity_exhausted",
            "zone validation capacity is currently exhausted",
            instance,
        ),
        ZonePayloadError::WorkerFailed => problem_with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "validation_worker_failed",
            "zone validation worker failed",
            instance,
        ),
    }
}

/// Normalise un nom de zone pour le système de fichiers (sans point final).
fn normalized_zone_name(raw: &str) -> Result<String, validation::ValidationError> {
    validation::validate_zone_name(raw).map(|zone| zone.trim_end_matches('.').to_string())
}

/// Valide le fichier de zone avec `named-checkzone` quand le binaire existe.
fn check_zone_file(zone_name: &str, zone_file: &Path) -> Result<(), validation::ValidationError> {
    validation::validate_zone_file_with_named_checkzone(zone_name, zone_file)
}

#[derive(Debug)]
enum ZoneWriteError {
    Io(String),
    Validation(validation::ValidationError),
    OwnerConflict,
    OwnerIo,
}

struct ZoneWriteOutcome {
    created: bool,
    serial: i32,
}

fn write_zone_transaction_timed(
    root: &Path,
    zone_name: &str,
    records: &[validation::ValidatedRecord],
    timings: &Timings,
) -> Result<(bool, i32), ZoneWriteError> {
    let start = Instant::now();
    let mut checkzone_elapsed = std::time::Duration::ZERO;
    let result = write_zone_transaction_with(root, zone_name, records, |name, path| {
        let checkzone_start = Instant::now();
        let result = check_zone_file(name, path);
        checkzone_elapsed = checkzone_start.elapsed();
        result
    });
    timings.record("checkzone", checkzone_elapsed);
    timings.record(
        "filesystem",
        start.elapsed().saturating_sub(checkzone_elapsed),
    );
    result
}

fn write_zone_transaction_with(
    root: &Path,
    zone_name: &str,
    records: &[validation::ValidatedRecord],
    validate: impl FnOnce(&str, &Path) -> Result<(), validation::ValidationError>,
) -> Result<(bool, i32), ZoneWriteError> {
    let zone_file = zone::zone_file_path(root, zone_name);
    let (created, existing_serial) = match fs::read_to_string(&zone_file) {
        Ok(content) => (false, zone::serial_from_contents(&content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (true, None),
        Err(error) => {
            return Err(ZoneWriteError::Io(format!(
                "failed to read current zone: {}",
                error
            )))
        }
    };
    let serial = zone::compute_serial(existing_serial);
    let contents = zone::render_zone_file(zone_name, records, serial);
    let prepared =
        zone::prepare_zone_file(zone_name, &contents, root).map_err(ZoneWriteError::Io)?;
    validate(zone_name, prepared.path()).map_err(ZoneWriteError::Validation)?;
    prepared.publish().map_err(ZoneWriteError::Io)?;
    Ok((created, serial))
}

fn zone_owner_id(user: &Option<AuthUser>) -> String {
    user.as_ref()
        .map(|user| user.tenant.clone())
        .unwrap_or_else(|| "public".into())
}

fn zone_owners_dir() -> PathBuf {
    zone::zones_dir().join(".bind-owners")
}

fn write_zone_work(
    root: &Path,
    zone_name: &str,
    records: &[validation::ValidatedRecord],
    tenant: &str,
    timings: &Timings,
) -> Result<ZoneWriteOutcome, ZoneWriteError> {
    write_zone_work_with_owners(
        root,
        zone_name,
        records,
        tenant,
        timings,
        &zone_owners_dir(),
    )
}

fn write_zone_work_with_owners(
    root: &Path,
    zone_name: &str,
    records: &[validation::ValidatedRecord],
    tenant: &str,
    timings: &Timings,
    owners_dir: &Path,
) -> Result<ZoneWriteOutcome, ZoneWriteError> {
    let claim =
        bind::claim_zone_owner(owners_dir, zone_name, tenant).map_err(|error| match error {
            bind::OwnerError::Conflict => ZoneWriteError::OwnerConflict,
            bind::OwnerError::Io => ZoneWriteError::OwnerIo,
        })?;

    let (created, serial) = match write_zone_transaction_timed(root, zone_name, records, timings) {
        Ok(result) => result,
        Err(error) => {
            if claim.created {
                if let Err(release_error) = bind::release_zone_owner(owners_dir, zone_name, tenant)
                {
                    tracing::warn!(request_id = %timings.request_id(), error = ?release_error, "could not release failed zone claim");
                }
            }
            return Err(error);
        }
    };

    Ok(ZoneWriteOutcome { created, serial })
}

enum ZoneSyncError {
    Zone(ZoneWriteError),
    NotFound,
}

fn sync_existing_zone_work(
    root: &Path,
    zone_name: &str,
    tenant: &str,
    timings: &Timings,
) -> Result<i32, ZoneSyncError> {
    let filesystem_start = Instant::now();
    let zone_file = zone::zone_file_path(root, zone_name);
    let contents = match fs::read_to_string(&zone_file) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(ZoneSyncError::NotFound)
        }
        Err(error) => {
            return Err(ZoneSyncError::Zone(ZoneWriteError::Io(format!(
                "failed to read current zone: {}",
                error
            ))))
        }
    };
    let serial = zone::serial_from_contents(&contents).ok_or(ZoneSyncError::NotFound)?;

    let owners_dir = zone_owners_dir();
    bind::claim_zone_owner(&owners_dir, zone_name, tenant).map_err(|error| {
        ZoneSyncError::Zone(match error {
            bind::OwnerError::Conflict => ZoneWriteError::OwnerConflict,
            bind::OwnerError::Io => ZoneWriteError::OwnerIo,
        })
    })?;
    timings.record("filesystem", filesystem_start.elapsed());
    Ok(serial)
}

enum ZoneDeleteError {
    NotFound,
    OwnerConflict,
    OwnerIo,
    Bind(RndcError),
    Io(std::io::Error),
}

fn delete_zone_work(
    root: &Path,
    zone_name: &str,
    tenant: &str,
    rndc: &RndcClient,
    timings: &Timings,
) -> Result<Option<bool>, ZoneDeleteError> {
    delete_zone_work_with_owners(root, zone_name, tenant, rndc, timings, &zone_owners_dir())
}

fn delete_zone_work_with_owners(
    root: &Path,
    zone_name: &str,
    tenant: &str,
    rndc: &RndcClient,
    timings: &Timings,
    owners_dir: &Path,
) -> Result<Option<bool>, ZoneDeleteError> {
    let filesystem_start = Instant::now();
    let zone_path = root.join(zone_name);
    if !zone_path.is_dir() {
        return Err(ZoneDeleteError::NotFound);
    }

    let claim =
        bind::claim_zone_owner(owners_dir, zone_name, tenant).map_err(|error| match error {
            bind::OwnerError::Conflict => ZoneDeleteError::OwnerConflict,
            bind::OwnerError::Io => ZoneDeleteError::OwnerIo,
        })?;
    if claim.state != bind::OwnerState::Inactive {
        let rndc_start = Instant::now();
        let deletion = rndc.delete_zone(zone_name);
        timings.record("rndc", rndc_start.elapsed());
        deletion.map_err(|error| {
            tracing::warn!(request_id = %timings.request_id(), zone = %zone_name, error = ?error, "BIND deletion failed");
            ZoneDeleteError::Bind(error)
        })?;
        bind::set_zone_owner_state(owners_dir, zone_name, tenant, bind::OwnerState::Inactive)
            .map_err(|_| ZoneDeleteError::OwnerIo)?;
    }
    fs::remove_dir_all(&zone_path).map_err(ZoneDeleteError::Io)?;
    bind::release_zone_owner(owners_dir, zone_name, tenant)
        .map_err(|_| ZoneDeleteError::OwnerIo)?;
    timings.record(
        "filesystem",
        Instant::now().saturating_duration_since(filesystem_start),
    );

    Ok(Some(false))
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
    params(
        ("limit" = Option<usize>, Query, description = "Nombre de zones (1 à 500, défaut 100)"),
        ("offset" = Option<usize>, Query, description = "Décalage de pagination")
    ),
    responses(
        (status = 200, description = "Liste des zones", body = ZonesResponse),
        (status = 503, description = "Capacité I/O momentanément saturée", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ErrorResponse),
    ),
    security(("bearer_token" = []))
)]
async fn handle_list_zones(
    State(state): State<SharedState>,
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
    Query(query): Query<ZoneListQuery>,
) -> impl IntoResponse {
    let user = match caller.0 {
        Ok(user) => user,
        Err(error) => return auth_problem(error, "/zones"),
    };
    let limit = query.limit.unwrap_or(DEFAULT_ZONE_LIST_LIMIT);
    if !(1..=MAX_ZONE_LIST_LIMIT).contains(&limit) {
        return problem(
            StatusCode::BAD_REQUEST,
            "Bad Request",
            "limit must be between 1 and 500",
            "/zones",
        );
    }
    let offset = query.offset.unwrap_or(0);
    let root = zone_root(&user);
    let user_for_work = user.clone();

    let result = timed_async(
        &timings,
        "list",
        run_limited(Arc::clone(&state.io_slots), move || {
            migrate_legacy_zone_root(&user_for_work, &root);
            list_zones(&root, offset, limit)
        }),
    )
    .await;
    match result {
        Err(BlockingWorkError::Saturated) => {
            return problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                "capacity_exhausted",
                "I/O capacity is exhausted",
                "/zones",
            )
        }
        Err(BlockingWorkError::WorkerFailed) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "worker_failed",
                "I/O worker failed",
                "/zones",
            )
        }
        Ok(Err(error)) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "filesystem_error",
                &error,
                "/zones",
            )
        }
        Ok(Ok((zones, next_offset))) => Json(ZonesResponse {
            zones,
            next_offset,
            scope: scope_of(&user),
        })
        .into_response(),
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
        (status = 503, description = "Capacité saturée ou validation BIND expirée", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_put_zone(
    State(state): State<SharedState>,
    Extension(caller): Extension<CallerResolution>,
    Extension(timings): Extension<Timings>,
    UrlPath(name): UrlPath<String>,
    body: Bytes,
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

    let payload_bytes = body.len();
    let payload_result = timed_async(
        &timings,
        "validate",
        parse_and_validate_zone_payload(
            body,
            state.request_limits,
            Arc::clone(&state.validation_slots),
        ),
    )
    .await;
    let payload = match payload_result {
        Ok(payload) => payload,
        Err(error) => return zone_payload_error_response(error, &instance),
    };
    timings.record_detail(
        "payload",
        format!("bytes={};records={}", payload_bytes, payload.len()),
    );

    let root = zone_root(&user);
    let zone_guard = lock_zone(&state, zone_lock_key(&zone_name), &timings).await;
    let user_for_work = user.clone();
    let name_for_work = zone_name.clone();
    let tenant = zone_owner_id(&user);
    let tenant_for_work = tenant.clone();
    let root_for_work = root.clone();
    let timings_for_work = timings.clone();
    let write_result = timed_async(
        &timings,
        "write",
        run_limited_by(
            vec![
                Arc::clone(&state.io_slots),
                Arc::clone(&state.validation_slots),
            ],
            move || {
                let _zone_guard = zone_guard;
                migrate_legacy_zone_root(&user_for_work, &root_for_work);
                write_zone_work(
                    &root_for_work,
                    &name_for_work,
                    &payload,
                    &tenant_for_work,
                    &timings_for_work,
                )
            },
        ),
    )
    .await;
    let outcome = match write_result {
        Err(BlockingWorkError::Saturated) => {
            return problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                "capacity_exhausted",
                "I/O capacity is exhausted",
                &instance,
            )
        }
        Err(BlockingWorkError::WorkerFailed) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "worker_failed",
                "I/O worker failed",
                &instance,
            )
        }
        Ok(Err(ZoneWriteError::Io(error))) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "filesystem_error",
                &error,
                &instance,
            )
        }
        Ok(Err(ZoneWriteError::Validation(error))) => {
            return validation_problem(&[error], &instance)
        }
        Ok(Err(ZoneWriteError::OwnerConflict)) => {
            return problem(
                StatusCode::CONFLICT,
                "Conflict",
                "zone name is owned by another tenant",
                &instance,
            )
        }
        Ok(Err(ZoneWriteError::OwnerIo)) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "ownership_error",
                "zone ownership could not be read or updated",
                &instance,
            )
        }
        Ok(Ok(result)) => result,
    };

    let (code, status) = if outcome.created {
        (StatusCode::CREATED, "created")
    } else {
        (StatusCode::OK, "updated")
    };
    let activation = timed_async(
        &timings,
        "publish",
        state
            .publications
            .publish(root, zone_name.clone(), tenant, timings.clone()),
    )
    .await;

    (
        code,
        Json(SyncResponse {
            status: status.into(),
            persisted: true,
            active: Some(activation.is_ok()),
            activation_error: activation.err().map(|error| error.code().to_string()),
            zone: zone_name,
            serial: outcome.serial.to_string(),
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
        (status = 200, description = "Zone supprimée", body = DeleteResponse),
        (status = 404, description = "Zone introuvable", body = ErrorResponse),
        (status = 409, description = "Zone appartenant à un autre tenant", body = ProblemDetails),
        (status = 503, description = "Capacité I/O momentanément saturée", body = ProblemDetails),
        (status = 400, description = "Nom invalide", body = ProblemDetails),
        (status = 422, description = "Nom invalide", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_delete_zone(
    State(state): State<SharedState>,
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

    let root = zone_root(&user);
    let zone_guard = lock_zone(&state, zone_lock_key(&zone_name), &timings).await;
    let user_for_work = user.clone();
    let name_for_work = zone_name.clone();
    let tenant = zone_owner_id(&user);
    let rndc = state.rndc.clone();
    let timings_for_work = timings.clone();
    let deletion = timed_async(
        &timings,
        "delete",
        run_limited(Arc::clone(&state.io_slots), move || {
            let _zone_guard = zone_guard;
            migrate_legacy_zone_root(&user_for_work, &root);
            delete_zone_work(&root, &name_for_work, &tenant, &rndc, &timings_for_work)
        }),
    )
    .await;
    match deletion {
        Err(BlockingWorkError::Saturated) => problem_with_code(
            StatusCode::SERVICE_UNAVAILABLE,
            "Service Unavailable",
            "capacity_exhausted",
            "I/O capacity is exhausted",
            &instance,
        ),
        Err(BlockingWorkError::WorkerFailed) => problem_with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "worker_failed",
            "I/O worker failed",
            &instance,
        ),
        Ok(Ok(active)) => Json(DeleteResponse {
            status: "deleted".into(),
            persisted: true,
            active,
            zone: zone_name,
            scope: scope_of(&user),
        })
        .into_response(),
        Ok(Err(ZoneDeleteError::NotFound)) => err(StatusCode::NOT_FOUND, "zone not found"),
        Ok(Err(ZoneDeleteError::OwnerConflict)) => problem(
            StatusCode::CONFLICT,
            "Conflict",
            "zone name is owned by another tenant",
            &instance,
        ),
        Ok(Err(ZoneDeleteError::OwnerIo)) => problem_with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "ownership_error",
            "zone ownership could not be read or updated",
            &instance,
        ),
        Ok(Err(ZoneDeleteError::Bind(error))) => {
            let code = PublicationError::Rndc(error).code();
            problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                code,
                "BIND could not remove the zone; zone files remain available for retry",
                &instance,
            )
        }
        Ok(Err(ZoneDeleteError::Io(error))) => problem_with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "filesystem_error",
            &format!("failed to delete zone: {}", error),
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
        (status = 503, description = "Capacité saturée ou validation BIND expirée", body = ProblemDetails),
        (status = 500, description = "Erreur interne", body = ProblemDetails),
    ),
    security(("bearer_token" = []))
)]
async fn handle_sync(
    State(state): State<SharedState>,
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

    let payload_bytes = body.len();
    let payload = if body.is_empty() {
        None
    } else {
        match timed_async(
            &timings,
            "validate",
            parse_and_validate_zone_payload(
                body,
                state.request_limits,
                Arc::clone(&state.validation_slots),
            ),
        )
        .await
        {
            Ok(payload) => Some(payload),
            Err(error) => return zone_payload_error_response(error, INSTANCE),
        }
    };
    if let Some(records) = &payload {
        timings.record_detail(
            "payload",
            format!("bytes={};records={}", payload_bytes, records.len()),
        );
    }

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
    let zone_guard = lock_zone(&state, zone_lock_key(&zone_name), &timings).await;
    let user_for_work = user.clone();
    let name_for_work = zone_name.clone();
    let tenant = zone_owner_id(&user);
    let root_for_work = root.clone();
    let tenant_for_work = tenant.clone();
    let timings_for_work = timings.clone();
    let serial_result = timed_async(
        &timings,
        "write",
        run_limited_by(
            vec![
                Arc::clone(&state.io_slots),
                Arc::clone(&state.validation_slots),
            ],
            move || {
                let _zone_guard = zone_guard;
                migrate_legacy_zone_root(&user_for_work, &root_for_work);
                match payload {
                    Some(records) => write_zone_work(
                        &root_for_work,
                        &name_for_work,
                        &records,
                        &tenant_for_work,
                        &timings_for_work,
                    )
                    .map(|outcome| Some(outcome.serial))
                    .map_err(ZoneSyncError::Zone),
                    None => sync_existing_zone_work(
                        &root_for_work,
                        &name_for_work,
                        &tenant_for_work,
                        &timings_for_work,
                    )
                    .map(Some),
                }
            },
        ),
    )
    .await;
    let serial = match serial_result {
        Err(BlockingWorkError::Saturated) => {
            return problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                "capacity_exhausted",
                "I/O capacity is exhausted",
                INSTANCE,
            )
        }
        Err(BlockingWorkError::WorkerFailed) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "worker_failed",
                "I/O worker failed",
                INSTANCE,
            )
        }
        Ok(Err(ZoneSyncError::Zone(ZoneWriteError::Io(error)))) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "filesystem_error",
                &error,
                INSTANCE,
            )
        }
        Ok(Err(ZoneSyncError::Zone(ZoneWriteError::Validation(error)))) => {
            return validation_problem(&[error], INSTANCE)
        }
        Ok(Err(ZoneSyncError::Zone(ZoneWriteError::OwnerConflict))) => {
            return problem(
                StatusCode::CONFLICT,
                "Conflict",
                "zone name is owned by another tenant",
                INSTANCE,
            )
        }
        Ok(Err(ZoneSyncError::Zone(ZoneWriteError::OwnerIo))) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "ownership_error",
                "zone ownership could not be read or updated",
                INSTANCE,
            )
        }
        Ok(Err(ZoneSyncError::NotFound)) => {
            return err(
                StatusCode::NOT_FOUND,
                &format!("zone {} not found", zone_name),
            )
        }
        Ok(Ok(Some(result))) => result,
        Ok(Ok(None)) => {
            return err(
                StatusCode::NOT_FOUND,
                &format!("zone {} not found", zone_name),
            )
        }
    };

    let activation = timed_async(
        &timings,
        "publish",
        state
            .publications
            .publish(root, zone_name.clone(), tenant, timings.clone()),
    )
    .await;

    Json(SyncResponse {
        status: if activation.is_ok() {
            "reloaded"
        } else {
            "persisted"
        }
        .into(),
        persisted: true,
        active: Some(activation.is_ok()),
        activation_error: activation.err().map(|error| error.code().to_string()),
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
        (status = 503, description = "Capacité I/O momentanément saturée", body = ProblemDetails),
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
    let update_guard = Arc::clone(&state.token_updates).lock_owned().await;
    let shared_tokens = Arc::clone(&state.tokens);
    let tenant = user.tenant.clone();
    let slug = user.slug.clone();
    let secret_for_work = secret.clone();
    let update = timed_async(
        &timings,
        "token",
        run_limited(Arc::clone(&state.io_slots), move || {
            let _update_guard = update_guard;
            let mut token_store = shared_tokens
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let stored = token_store.add(&tenant, &slug, &secret_for_work);
            if stored {
                *shared_tokens
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = token_store;
            }
            stored
        }),
    )
    .await;
    let stored = match update {
        Err(BlockingWorkError::Saturated) => {
            return problem_with_code(
                StatusCode::SERVICE_UNAVAILABLE,
                "Service Unavailable",
                "capacity_exhausted",
                "I/O capacity is exhausted",
                "/token",
            )
        }
        Err(BlockingWorkError::WorkerFailed) => {
            return problem_with_code(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal Server Error",
                "worker_failed",
                "I/O worker failed",
                "/token",
            )
        }
        Ok(result) => result,
    };
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
        .allow_headers([
            header::AUTHORIZATION,
            header::CONTENT_TYPE,
            header::ACCEPT,
            HEADER_REQUEST_ID.clone(),
        ])
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

    if let Err(error) = validation::configure_checkzone_timeout_from_env() {
        eprintln!("checkzone config: {}", error);
        std::process::exit(1);
    }

    let request_limits = match RequestLimits::from_env() {
        Ok(limits) => limits,
        Err(error) => {
            eprintln!("request limits config: {}", error);
            std::process::exit(1);
        }
    };

    let rndc = match RndcClient::from_env() {
        Ok(client) => client,
        Err(error) => {
            eprintln!("rndc config: {}", error);
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

    let io_slots = Arc::new(tokio::sync::Semaphore::new(request_limits.max_parallel_io));
    let zone_locks = ZoneLocks::default();
    let publications =
        PublicationQueue::new(rndc.clone(), Arc::clone(&io_slots), zone_locks.clone());
    let state = Arc::new(AppState {
        tokens: Arc::new(Mutex::new(tokens)),
        token_updates: Arc::new(tokio::sync::Mutex::new(())),
        jwt,
        request_limits,
        validation_slots: Arc::new(tokio::sync::Semaphore::new(
            request_limits.max_parallel_validations,
        )),
        io_slots,
        rndc,
        publications,
        zone_locks,
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
        .layer(body_limit(request_limits.max_request_body_bytes))
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
    use tower::ServiceExt;

    fn temp_test_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("squilladns-{}-{}", name, std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn test_state(request_limits: RequestLimits) -> (SharedState, PathBuf) {
        let state_dir = temp_test_dir(&format!("app-state-{}", rand::random::<u64>()));
        let tokens = TokenStore::load(state_dir.join("tokens"), "test-bootstrap-token");
        let io_slots = Arc::new(tokio::sync::Semaphore::new(request_limits.max_parallel_io));
        let zone_locks = ZoneLocks::default();
        let rndc =
            RndcClient::new(state_dir.join("unused-rndc"), None, Duration::from_secs(1)).unwrap();
        let publications =
            PublicationQueue::new(rndc.clone(), Arc::clone(&io_slots), zone_locks.clone());
        (
            Arc::new(AppState {
                tokens: Arc::new(Mutex::new(tokens)),
                token_updates: Arc::new(tokio::sync::Mutex::new(())),
                jwt: None,
                request_limits,
                validation_slots: Arc::new(tokio::sync::Semaphore::new(
                    request_limits.max_parallel_validations,
                )),
                io_slots,
                rndc,
                publications,
                zone_locks,
                sandbox: None,
            }),
            state_dir,
        )
    }

    #[test]
    fn zone_listing_is_sorted_and_paged_with_a_bounded_page() {
        let root = std::env::temp_dir().join(format!("squilladns-list-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        for name in ["c.test", "a.test", "b.test"] {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{}.zone", name)), "zone file").unwrap();
        }

        let (first, next_offset) = list_zones(&root, 0, 2).unwrap();
        assert_eq!(first, ["a.test", "b.test"]);
        assert_eq!(next_offset, Some(2));

        let (last, next_offset) = list_zones(&root, 2, 2).unwrap();
        assert_eq!(last, ["c.test"]);
        assert_eq!(next_offset, None);
        assert!(list_zones(&root, 100, 2).unwrap().0.is_empty());

        let _ = fs::remove_dir_all(root);
    }

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
    fn server_timing_exposes_lock_process_and_payload_metrics() {
        let timings = Timings::default();
        timings.record("lock", Duration::from_millis(2));
        timings.record("rndc", Duration::from_millis(4));
        timings.record_detail("payload", "bytes=128;records=3".into());
        let header = timings.header_value(12.0);
        assert!(header.contains("lock;dur=2.0;desc=\"zone lock wait\""));
        assert!(header.contains("rndc;dur=4.0;desc=\"rndc reload\""));
        assert!(header.contains("payload;dur=0.0;desc=\"bytes=128;records=3\""));
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

    #[test]
    fn publication_batches_are_isolated_by_tenant_and_zone() {
        let tenant_a = PublicationBatchKey::new("tenant-a", "example.test");
        let same_owner = PublicationBatchKey::new("tenant-a", "example.test");
        let tenant_b = PublicationBatchKey::new("tenant-b", "example.test");
        let other_zone = PublicationBatchKey::new("tenant-a", "other.test");

        assert_eq!(tenant_a, same_owner);
        assert_ne!(tenant_a, tenant_b);
        assert_ne!(tenant_a, other_zone);
    }

    #[tokio::test]
    async fn cors_allows_clients_to_send_and_read_request_ids() {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(cors_layer());
        let preflight = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::OPTIONS)
                    .uri("/")
                    .header(header::ORIGIN, "https://client.example")
                    .header(header::ACCESS_CONTROL_REQUEST_METHOD, "GET")
                    .header(header::ACCESS_CONTROL_REQUEST_HEADERS, "x-request-id")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(preflight.status(), StatusCode::OK);
        assert!(preflight
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("x-request-id"));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::ORIGIN, "https://client.example")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(response
            .headers()
            .get(header::ACCESS_CONTROL_EXPOSE_HEADERS)
            .unwrap()
            .to_str()
            .unwrap()
            .to_ascii_lowercase()
            .contains("x-request-id"));
    }

    #[test]
    fn sync_response_separates_persistence_from_activation() {
        let put_response = SyncResponse {
            status: "created".into(),
            persisted: true,
            active: None,
            activation_error: None,
            zone: "example.test".into(),
            serial: "1".into(),
            scope: "public".into(),
        };
        let put_json = serde_json::to_value(put_response).unwrap();
        assert_eq!(put_json["persisted"], true);
        assert!(put_json.get("active").is_none());

        let sync_response = SyncResponse {
            status: "synced".into(),
            persisted: true,
            active: Some(false),
            activation_error: Some("rndc_timeout".into()),
            zone: "example.test".into(),
            serial: "2".into(),
            scope: "public".into(),
        };
        let sync_json = serde_json::to_value(sync_response).unwrap();
        assert_eq!(sync_json["persisted"], true);
        assert_eq!(sync_json["active"], false);
        assert_eq!(sync_json["activation_error"], "rndc_timeout");
    }

    #[tokio::test]
    async fn problem_details_include_a_stable_machine_error_code() {
        let response = problem_with_code(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error",
            "filesystem_error",
            "zone storage failed",
            "/zones/example.test",
        );
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["code"], "filesystem_error");
        assert_eq!(body["detail"], "zone storage failed");
        assert!(!body.to_string().contains("/private/"));
    }

    #[tokio::test]
    async fn invalid_payload_is_rejected_without_acquiring_io_capacity() {
        let mut limits = RequestLimits::default();
        limits.max_records_per_zone = 1;
        let (state, state_dir) = test_state(limits);
        let payload = Bytes::from(
            r#"{"records":[{"type":"A","name":"one","value":"192.0.2.1"},{"type":"A","name":"two","value":"192.0.2.2"}]}"#,
        );
        let response = handle_put_zone(
            State(Arc::clone(&state)),
            Extension(CallerResolution(Ok(None))),
            Extension(Timings::default()),
            UrlPath("example.test".into()),
            payload,
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(state.io_slots.available_permits(), limits.max_parallel_io);
        let _ = fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn health_remains_responsive_when_all_io_slots_are_occupied() {
        let limits = RequestLimits::default();
        let (state, state_dir) = test_state(limits);
        let mut permits = Vec::new();
        for _ in 0..limits.max_parallel_io {
            permits.push(Arc::clone(&state.io_slots).acquire_owned().await.unwrap());
        }

        let response = tokio::time::timeout(
            Duration::from_millis(100),
            handle_health(State(Arc::clone(&state))),
        )
        .await
        .expect("health should not wait for filesystem or process capacity")
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        drop(permits);
        let _ = fs::remove_dir_all(state_dir);
    }

    #[tokio::test]
    async fn concurrent_same_zone_writes_get_distinct_serials_and_complete_files() {
        let root = temp_test_dir("same-zone-writes");
        let locks = ZoneLocks::default();
        let records = vec![validation::validate_record(&Record {
            record_type: "A".into(),
            name: "www".into(),
            value: "192.0.2.8".into(),
        })
        .unwrap()];

        let run_write =
            |locks: ZoneLocks, root: PathBuf, records: Vec<validation::ValidatedRecord>| {
                tokio::spawn(async move {
                    let _guard = locks.lock("shared-zone".into()).await;
                    tokio::task::spawn_blocking(move || {
                        write_zone_transaction_timed(
                            &root,
                            "example.test",
                            &records,
                            &Timings::default(),
                        )
                    })
                    .await
                    .unwrap()
                })
            };
        let first = run_write(locks.clone(), root.clone(), records.clone());
        let second = run_write(locks, root.clone(), records);
        let (first, second) = tokio::join!(first, second);
        let first_serial = first.unwrap().unwrap().1;
        let second_serial = second.unwrap().unwrap().1;
        assert_ne!(first_serial, second_serial);

        let zone_file = zone::zone_file_path(&root, "example.test");
        let contents = fs::read_to_string(&zone_file).unwrap();
        assert_eq!(
            zone::serial_from_contents(&contents),
            Some(first_serial.max(second_serial))
        );
        assert_eq!(contents.matches("www 3600 IN A").count(), 1);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_supported_rr_is_rendered_once_with_its_typed_value() {
        let input = [
            ("A", "www", "192.0.2.9"),
            ("AAAA", "v6", "2001:db8::9"),
            ("CNAME", "alias", "www.example.test."),
            ("MX", "@", "10 mail.example.test."),
            ("NS", "@", "ns.example.test."),
            ("TXT", "txt", "hello"),
            ("SRV", "_sip._tcp", "0 5 5060 sip.example.test."),
            ("CAA", "@", "0 issue \"letsencrypt.org\""),
        ];
        let records: Vec<_> = input
            .iter()
            .map(|(record_type, name, value)| {
                validation::validate_record(&Record {
                    record_type: (*record_type).into(),
                    name: (*name).into(),
                    value: (*value).into(),
                })
                .unwrap()
            })
            .collect();

        let rendered = zone::render_zone_file("example.test", &records, 42);
        let root = temp_test_dir("typed-rr-file");
        let zone_file = zone::prepare_zone_file("example.test", &rendered, &root)
            .unwrap()
            .publish()
            .unwrap();
        let contents = fs::read_to_string(zone_file).unwrap();
        for (record_type, _, _) in input {
            assert_eq!(
                contents
                    .lines()
                    .filter(|line| line.contains(&format!(" IN {} ", record_type)))
                    .count(),
                1,
                "expected exactly one {} record",
                record_type
            );
        }
        assert!(contents.contains("www 3600 IN A 192.0.2.9"));
        assert!(contents.contains("v6 3600 IN AAAA 2001:db8::9"));
        assert!(contents.contains("alias 3600 IN CNAME www.example.test."));
        assert!(contents.contains("@ 3600 IN MX 10 mail.example.test."));
        assert!(contents.contains("@ 3600 IN NS ns.example.test."));
        assert!(contents.contains("txt 3600 IN TXT \"hello\""));
        assert!(contents.contains("_sip._tcp 3600 IN SRV 0 5 5060 sip.example.test."));
        assert!(contents.contains("@ 3600 IN CAA 0 issue \"letsencrypt.org\""));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rndc_activation_failure_keeps_a_recoverable_pending_owner_state() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_test_dir("activation-failure");
        let owners = root.join("owners");
        let zone_file = root.join("example.test.zone");
        let rndc_script = root.join("rndc-fails");
        fs::write(&zone_file, "zone contents").unwrap();
        fs::write(&rndc_script, "#!/bin/sh\nexit 7\n").unwrap();
        let mut permissions = fs::metadata(&rndc_script).unwrap().permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&rndc_script, permissions).unwrap();
        bind::claim_zone_owner(&owners, "example.test", "tenant-a").unwrap();
        let rndc = RndcClient::new(rndc_script, None, Duration::from_secs(1)).unwrap();

        assert_eq!(
            activate_owned_zone(
                &rndc,
                &owners,
                "example.test",
                "tenant-a",
                zone_file.to_str().unwrap(),
                bind::OwnerState::Inactive,
                &[],
            ),
            Err(PublicationError::Rndc(RndcError::CommandFailed(Some(7))))
        );
        assert_eq!(
            bind::read_zone_owner(&owners, "example.test")
                .unwrap()
                .unwrap()
                .state,
            bind::OwnerState::Activating
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tenant_cannot_overwrite_or_delete_another_tenants_global_zone_name() {
        let base = temp_test_dir("cross-tenant-zone");
        let tenant_a_root = base.join("tenant-a");
        let tenant_b_root = base.join("tenant-b");
        let owners = base.join("owners");
        let tenant_b_zone = zone::zone_file_path(&tenant_b_root, "example.test");
        fs::create_dir_all(tenant_b_zone.parent().unwrap()).unwrap();
        fs::write(&tenant_b_zone, "tenant-b sentinel").unwrap();
        let records = vec![validation::validate_record(&Record {
            record_type: "A".into(),
            name: "www".into(),
            value: "192.0.2.10".into(),
        })
        .unwrap()];
        write_zone_work_with_owners(
            &tenant_a_root,
            "example.test",
            &records,
            "tenant-a",
            &Timings::default(),
            &owners,
        )
        .unwrap();
        assert_eq!(
            verify_publication_owner(&owners, "example.test", "tenant-b"),
            Err(PublicationError::Ownership)
        );

        let before = fs::read_to_string(&tenant_b_zone).unwrap();
        assert!(matches!(
            write_zone_work_with_owners(
                &tenant_b_root,
                "example.test",
                &records,
                "tenant-b",
                &Timings::default(),
                &owners,
            ),
            Err(ZoneWriteError::OwnerConflict)
        ));
        let rndc = RndcClient::new(base.join("no-rndc"), None, Duration::from_secs(1)).unwrap();
        assert!(matches!(
            delete_zone_work_with_owners(
                &tenant_b_root,
                "example.test",
                "tenant-b",
                &rndc,
                &Timings::default(),
                &owners,
            ),
            Err(ZoneDeleteError::OwnerConflict)
        ));
        assert_eq!(fs::read_to_string(&tenant_b_zone).unwrap(), before);
        assert!(fs::read_to_string(zone::zone_file_path(&tenant_a_root, "example.test")).is_ok());
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn tenant_roots_keep_zone_listings_separate() {
        let base = temp_test_dir("tenant-list-roots");
        let user_a = Some(AuthUser {
            email: None,
            provider: "token".into(),
            tenant: "tenant-a".into(),
            legacy_tenant: None,
            slug: "alice".into(),
        });
        let user_b = Some(AuthUser {
            email: None,
            provider: "token".into(),
            tenant: "tenant-b".into(),
            legacy_tenant: None,
            slug: "bob".into(),
        });
        let root_a = zone_root_under(&base, &user_a);
        let root_b = zone_root_under(&base, &user_b);
        for (root, name) in [(&root_a, "a.example.test"), (&root_b, "b.example.test")] {
            let dir = root.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{}.zone", name)), "zone").unwrap();
        }
        assert_eq!(list_zones(&root_a, 0, 10).unwrap().0, ["a.example.test"]);
        assert_eq!(list_zones(&root_b, 0, 10).unwrap().0, ["b.example.test"]);
        let _ = fs::remove_dir_all(base);
    }

    #[test]
    fn rejected_temporary_zone_keeps_previous_file_and_cleans_candidate() {
        let root =
            std::env::temp_dir().join(format!("squilladns-write-reject-{}", std::process::id()));
        let target = zone::zone_file_path(&root, "example.test");
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::write(&target, "previous zone contents\n").unwrap();
        let records = vec![validation::validate_record(&Record {
            record_type: "A".into(),
            name: "www".into(),
            value: "192.0.2.10".into(),
        })
        .unwrap()];

        let result =
            write_zone_transaction_with(&root, "example.test", &records, |_zone, candidate| {
                assert_ne!(candidate, target);
                assert!(candidate.exists());
                Err(validation::ValidationError::new(
                    validation::ValidationErrorCode::ZoneValidationFailed,
                    "test rejection",
                ))
            });

        assert!(matches!(result, Err(ZoneWriteError::Validation(_))));
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "previous zone contents\n"
        );
        let remaining: Vec<_> = std::fs::read_dir(target.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(remaining, vec![target.file_name().unwrap()]);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn zone_locks_serialize_same_key_and_allow_different_keys() {
        let locks = Arc::new(ZoneLocks::default());
        let first = locks.lock("tenant-a/alpha.test".into()).await;
        let (sent, mut received) = tokio::sync::oneshot::channel();
        let other_locks = Arc::clone(&locks);
        let waiting = tokio::spawn(async move {
            let _guard = other_locks.lock("tenant-a/alpha.test".into()).await;
            let _ = sent.send(());
        });

        tokio::task::yield_now().await;
        assert!(
            received.try_recv().is_err(),
            "same zone must wait for its lock"
        );
        drop(first);
        received.await.unwrap();
        waiting.await.unwrap();

        let _a = locks.lock("tenant-a/alpha.test".into()).await;
        let _b = locks.lock("tenant-b/alpha.test".into()).await;
    }
}
