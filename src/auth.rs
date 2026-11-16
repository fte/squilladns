//! Résolution de l'identité d'un appelant.
//!
//! Deux mécanismes, tous deux **hors ligne** (aucun appel réseau, aucun provider
//! contacté par l'API) :
//!
//! 1. **JWT HS256** émis par le client (front/BFF) après un SSO quelconque
//!    (GitHub, Azure, Google…). Le provider est du ressort du client, l'API ne
//!    vérifie qu'une signature et des claims.
//! 2. **Token API statique** (fichier `API_TOKEN_PATH`), pour les scripts et le
//!    CI. Le token bootstrap a son propre tenant ; les tokens créés par `/token`
//!    héritent du tenant du porteur afin de retrouver les mêmes zones.
//!
//! Un mode **sandbox** (`SANDBOX_USER=alice`) court-circuite tout : l'appelant
//! devient cet utilisateur fictif, ce qui permet de travailler sans aucun token.
//!
//! L'identifiant interne de l'utilisateur combine une forme lisible de l'émetteur
//! et du sujet avec un suffixe anti-collision. Il ne sort jamais dans les réponses
//! API ; seul le login normalisé (slug) est exposé au client.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// Longueur maximale d'un `sub` JWT accepté (caractères).
const MAX_SUBJECT_LEN: usize = 128;

/// Clé HMAC minimale : 256 bits, comme le bloc de SHA-256.
const MIN_SECRET_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Identité
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Email si le JWT en transporte un.
    pub email: Option<String>,
    /// `sandbox`, `token` ou `jwt`.
    pub provider: String,
    /// Identifiant interne lisible, utilisé comme nom de répertoire et jamais exposé.
    pub tenant: String,
    /// Ancien identifiant opaque, migré au premier accès si son dossier existe.
    pub legacy_tenant: Option<String>,
    /// Login SSO normalisé, exposable au client.
    pub slug: String,
}

/// Calcule un tenant stable et non devinable à partir d'une identité.
///
/// Le résultat ne dépend pas du secret : ce n'est pas un credential, seulement
/// une clé de rangement. Il est encodé en base64url sans padding (22 car.), donc
/// utilisable tel quel comme nom de répertoire (pas de `/`, `.` ni espace).
pub fn tenant_id(kind: &str, provider: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"squilladns/tenant/v1\0");
    hasher.update(kind.as_bytes());
    hasher.update(b"\0");
    hasher.update(provider.as_bytes());
    hasher.update(b"\0");
    hasher.update(subject.as_bytes());

    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&digest[..16])
}

/// Identifiant lisible interne, stable par émetteur et sujet. Il reste côté API.
fn internal_user_id(issuer: &str, subject: &str) -> String {
    let readable_issuer = readable_part(issuer).chars().take(15).collect::<String>();
    let readable_subject = readable_part(subject).chars().take(15).collect::<String>();
    let readable = format!("{}-{}", readable_issuer, readable_subject);
    // Hash the original claims so normalization/truncation cannot merge accounts.
    let digest = Sha256::digest(format!("{}\0{}", issuer, subject).as_bytes());
    let readable: String = readable.trim_matches('-').chars().take(32).collect();
    format!("user-{}-{}", readable, URL_SAFE_NO_PAD.encode(&digest[..5]))
}

fn readable_part(value: &str) -> String {
    let value = value.to_ascii_lowercase();
    let mut out = String::new();
    let mut separator = false;
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            separator = false;
        } else if !separator && !out.is_empty() {
            out.push('-');
            separator = true;
        }
    }
    out.trim_matches('-').chars().take(40).collect()
}

/// Login public stable utilisé comme slug dans le client.
fn public_slug(value: &str) -> Option<String> {
    let slug = readable_part(value);
    if slug.is_empty() || slug.len() > 48 {
        None
    } else {
        Some(slug)
    }
}

/// Vrai si la chaîne peut servir de nom de répertoire sans échappement.
fn is_valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty()
        && tenant.len() <= 64
        && tenant
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

// ---------------------------------------------------------------------------
// Erreurs
// ---------------------------------------------------------------------------

/// Catalogue fermé des erreurs d'authentification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Header `Authorization` absent alors que la route l'exige.
    Required,
    /// Token inconnu, JWT malformé, mauvaise signature ou mauvais `alg`.
    InvalidToken,
    /// JWT dont `exp` (ou `nbf`) est dépassé.
    ExpiredToken,
}

impl AuthError {
    pub fn status(self) -> u16 {
        401
    }

    /// Code stable, utilisé dans `type: https://squilladns.dev/errors/<code>`.
    pub fn code(self) -> &'static str {
        match self {
            Self::Required => "auth_required",
            Self::InvalidToken => "auth_invalid_token",
            Self::ExpiredToken => "auth_expired",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Self::Required => "Authentication Required",
            Self::InvalidToken => "Invalid Token",
            Self::ExpiredToken => "Expired Token",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            Self::Required => "This endpoint requires a Bearer token.",
            Self::InvalidToken => {
                "The Bearer token is unknown, malformed or has an invalid signature."
            }
            Self::ExpiredToken => "The Bearer token has expired; request a new one.",
        }
    }
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

/// `SANDBOX_USER=alice` → identité fictive, sans aucune vérification.
///
/// Volontairement prioritaire sur `Authorization` : c'est un mode de dev.
pub fn sandbox_user() -> Option<AuthUser> {
    let name = std::env::var("SANDBOX_USER").ok()?;
    let name = name.trim();
    if name.is_empty() {
        return None;
    }

    let id = name.to_string();

    Some(AuthUser {
        tenant: internal_user_id("sandbox", &id),
        legacy_tenant: None,
        slug: public_slug(&id).unwrap_or_else(|| "sandbox-user".into()),
        email: Some(format!("{}@sandbox.local", id)),
        provider: "sandbox".into(),
    })
}

// ---------------------------------------------------------------------------
// JWT (HS256 legacy, EdDSA BFF)
// ---------------------------------------------------------------------------

/// Valeurs figées : ce projet n'a qu'un émetteur et une seule API.
/// Deux réglages de plus seraient deux occasions de se tromper.
const DEFAULT_JWT_AUDIENCE: &str = "squilladns";
const BFF_ISSUER: &str = "https://a.575.be/bff";
const BFF_KID: &str = "bff-2026-01";
const CLOCK_LEEWAY_SECS: i64 = 60;

pub struct JwtConfig {
    verifier: JwtVerifier,
    audience: String,
}

enum JwtVerifier {
    Hs256(Vec<u8>),
    Ed25519([u8; 32]),
}

impl JwtConfig {
    /// Clé publique Ed25519 prioritaire ; HS256 reste disponible pour compatibilité.
    pub fn from_env() -> Result<Option<Self>, String> {
        let audience =
            non_empty_env("BFF_API_AUDIENCE").unwrap_or_else(|| DEFAULT_JWT_AUDIENCE.to_string());
        if let Some(public_key) = non_empty_env("JWT_ED25519_PUBLIC_KEY") {
            let bytes = decode_b64(&public_key)
                .ok_or_else(|| "JWT_ED25519_PUBLIC_KEY doit être en base64url".to_string())?;
            let key: [u8; 32] = bytes.try_into().map_err(|_| {
                "JWT_ED25519_PUBLIC_KEY doit contenir une clé Ed25519 brute de 32 octets"
                    .to_string()
            })?;
            return Ok(Some(Self {
                verifier: JwtVerifier::Ed25519(key),
                audience,
            }));
        }
        let Some(secret) = non_empty_env("JWT_SECRET") else {
            return Ok(None);
        };
        if secret.len() < MIN_SECRET_LEN {
            return Err(format!(
                "JWT_SECRET trop court ({} octets, minimum {})",
                secret.len(),
                MIN_SECRET_LEN
            ));
        }
        Ok(Some(Self {
            verifier: JwtVerifier::Hs256(secret.into_bytes()),
            audience,
        }))
    }

    /// Vérifie signature + claims et retourne l'identité correspondante.
    pub fn verify(&self, token: &str) -> Result<AuthUser, AuthError> {
        let mut parts = token.split('.');
        let (header_b64, claims_b64, signature_b64) =
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some(header), Some(claims), Some(signature), None) => (header, claims, signature),
                _ => return Err(AuthError::InvalidToken),
            };

        let header: JwtHeader = decode_json(header_b64).ok_or(AuthError::InvalidToken)?;

        // Épingle l'algorithme : jamais `none`, jamais de confusion HS/RS.
        if header
            .typ
            .as_deref()
            .is_some_and(|typ| !typ.eq_ignore_ascii_case("JWT"))
        {
            return Err(AuthError::InvalidToken);
        }

        let signature = decode_b64(signature_b64).ok_or(AuthError::InvalidToken)?;
        let signing_input = format!("{}.{}", header_b64, claims_b64);
        match (&self.verifier, header.alg.as_str()) {
            (JwtVerifier::Hs256(secret), "HS256") => {
                let expected = hmac_sha256(secret, signing_input.as_bytes());
                if !ct_eq(&signature, &expected) {
                    return Err(AuthError::InvalidToken);
                }
            }
            (JwtVerifier::Ed25519(public_key), "EdDSA")
                if header.kid.as_deref() == Some(BFF_KID) =>
            {
                ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key)
                    .verify(signing_input.as_bytes(), &signature)
                    .map_err(|_| AuthError::InvalidToken)?;
            }
            _ => return Err(AuthError::InvalidToken),
        }

        let claims: JwtClaims = decode_json(claims_b64).ok_or(AuthError::InvalidToken)?;
        let now = unix_now();

        let Some(exp) = claims.exp else {
            return Err(AuthError::InvalidToken);
        };
        if now > exp.saturating_add(CLOCK_LEEWAY_SECS) {
            return Err(AuthError::ExpiredToken);
        }
        if let Some(nbf) = claims.nbf {
            if now.saturating_add(CLOCK_LEEWAY_SECS) < nbf {
                return Err(AuthError::InvalidToken);
            }
        }

        if !audience_matches(claims.aud.as_ref(), &self.audience) {
            return Err(AuthError::InvalidToken);
        }
        if matches!(&self.verifier, JwtVerifier::Ed25519(_))
            && claims.iss.as_deref() != Some(BFF_ISSUER)
        {
            return Err(AuthError::InvalidToken);
        }
        let subject = claims.sub.trim();
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_LEN
            || !subject
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '@' | ':'))
        {
            return Err(AuthError::InvalidToken);
        }

        let issuer = claims.iss.as_deref().unwrap_or("sso");
        let slug = claims
            .preferred_username
            .as_deref()
            .and_then(public_slug)
            .ok_or(AuthError::InvalidToken)?;
        let tenant = internal_user_id(issuer, subject);
        let legacy_tenant = tenant_id("jwt", claims.iss.as_deref().unwrap_or("-"), subject);
        Ok(AuthUser {
            tenant,
            legacy_tenant: Some(legacy_tenant),
            slug,
            email: claims.email,
            provider: "jwt".into(),
        })
    }
}

#[derive(Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
    #[serde(default)]
    typ: Option<String>,
}

/// Claims décodés pour les logs d'accès ; non authentifiés jusqu'à validation de signature.
#[derive(Debug, Default)]
pub struct JwtLogFields {
    pub alg: Option<String>,
    pub kid: Option<String>,
    pub iss: Option<String>,
    pub sub: Option<String>,
    pub aud: Option<String>,
    pub exp: Option<i64>,
    pub preferred_username: Option<String>,
}

pub fn jwt_log_fields(token: &str) -> Option<JwtLogFields> {
    if token.len() > 8192 {
        return None;
    }
    let mut parts = token.split('.');
    let (header, claims) = (parts.next()?, parts.next()?);
    if parts.next().is_none() || parts.next().is_some() {
        return None;
    }
    let header: JwtHeader = decode_json(header)?;
    let claims: JwtClaims = decode_json(claims)?;
    let aud = match claims.aud.as_ref() {
        None => None,
        Some(serde_json::Value::String(s)) => Some(log_value(s)),
        Some(serde_json::Value::Array(a)) => Some(
            a.iter()
                .filter_map(|v| v.as_str())
                .collect::<Vec<_>>()
                .join(",")
                .chars()
                .take(256)
                .collect(),
        ),
        _ => None,
    };
    Some(JwtLogFields {
        alg: Some(log_value(&header.alg)),
        kid: header.kid.as_deref().map(log_value),
        iss: claims.iss.as_deref().map(log_value),
        sub: Some(log_value(&claims.sub)),
        aud,
        exp: claims.exp,
        preferred_username: claims.preferred_username.as_deref().map(log_value),
    })
}

fn log_value(value: &str) -> String {
    value.chars().take(256).collect()
}

#[derive(Deserialize)]
struct JwtClaims {
    sub: String,
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    nbf: Option<i64>,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    preferred_username: Option<String>,
}

fn audience_matches(aud: Option<&serde_json::Value>, expected: &str) -> bool {
    match aud {
        Some(serde_json::Value::String(value)) => value == expected,
        Some(serde_json::Value::Array(values)) => {
            values.iter().any(|value| value.as_str() == Some(expected))
        }
        _ => false,
    }
}

fn decode_b64(value: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(value))
        .ok()
}

fn decode_json<T: for<'de> Deserialize<'de>>(value: &str) -> Option<T> {
    serde_json::from_slice(&decode_b64(value)?).ok()
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Tokens API
// ---------------------------------------------------------------------------

/// Un token et le tenant auquel il donne accès.
#[derive(Debug, Clone)]
struct TokenEntry {
    tenant: String,
    slug: String,
    token: String,
}

/// Fichier de tokens : une ligne `<tenant>\t<slug>\t<token>`.
/// Les anciens formats à deux champs et token seul sont migrés au chargement.
pub struct TokenStore {
    path: PathBuf,
    entries: Vec<TokenEntry>,
}

impl TokenStore {
    /// Charge le fichier, migre les anciennes lignes et garantit qu'un token de
    /// bootstrap existe (`API_TOKEN`), sans jamais écraser les tokens existants.
    pub fn load(path: PathBuf, bootstrap: &str) -> Self {
        let mut store = Self {
            path,
            entries: Vec::new(),
        };

        let mut dirty = false;

        for line in fs::read_to_string(&store.path).unwrap_or_default().lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let fields: Vec<&str> = line.split_whitespace().collect();

            match fields.as_slice() {
                [tenant, slug, token] if is_valid_tenant(tenant) && public_slug(slug).is_some() => {
                    store.push(tenant, slug, token);
                }
                [tenant, token] if is_valid_tenant(tenant) => {
                    store.push(
                        tenant,
                        &format!("api-{}", &tenant[..tenant.len().min(8)]),
                        token,
                    );
                    dirty = true;
                }
                // Ancien format : la ligne entière est le token. On lui donne un
                // tenant aléatoire (jamais un hash du token : ce serait exposer
                // un dérivé du secret).
                _ => {
                    let tenant = random_tenant();
                    store.push(&tenant, &format!("api-{}", &tenant[..8]), line);
                    dirty = true;
                }
            }
        }

        let bootstrap = bootstrap.trim();
        if !bootstrap.is_empty() && !store.contains(bootstrap) {
            // Tenant déterministe : le même `API_TOKEN` retombe sur le même
            // scope même si le fichier de tokens est perdu (conteneur recréé).
            let tenant = tenant_id("token", "bootstrap", bootstrap);
            store.push(&tenant, &format!("api-{}", &tenant[..8]), bootstrap);
            dirty = true;
        }

        if store.entries.is_empty() {
            let token = mint_token();
            let tenant = random_tenant();
            store.push(&tenant, &format!("api-{}", &tenant[..8]), &token);
            dirty = true;
            eprintln!("no API_TOKEN set — generated token: {}", token);
        }

        if dirty {
            if let Err(error) = store.persist() {
                eprintln!("token store write ({}): {}", store.path.display(), error);
            }
        }

        store
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Tenant associé à un token, en temps constant sur les tokens connus.
    pub fn resolve(&self, bearer: &str) -> Option<(String, String)> {
        self.entries
            .iter()
            .find(|entry| ct_eq(entry.token.as_bytes(), bearer.as_bytes()))
            .map(|entry| (entry.tenant.clone(), entry.slug.clone()))
    }

    /// Ajoute un token pour un tenant existant (ou nouveau) et persiste.
    pub fn add(&mut self, tenant: &str, slug: &str, token: &str) -> bool {
        let Some(slug) = public_slug(slug) else {
            return false;
        };
        if !is_valid_tenant(tenant) || token.is_empty() || self.contains(token) {
            return false;
        }

        self.push(tenant, &slug, token);
        if let Err(error) = self.persist() {
            self.entries.pop();
            eprintln!("token store write ({}): {}", self.path.display(), error);
            return false;
        }

        true
    }

    fn contains(&self, token: &str) -> bool {
        self.entries.iter().any(|entry| entry.token == token)
    }

    fn push(&mut self, tenant: &str, slug: &str, token: &str) {
        self.entries.push(TokenEntry {
            tenant: tenant.to_string(),
            slug: slug.to_string(),
            token: token.to_string(),
        });
    }

    fn persist(&self) -> std::io::Result<()> {
        let content: String = self
            .entries
            .iter()
            .map(|entry| format!("{}\t{}\t{}\n", entry.tenant, entry.slug, entry.token))
            .collect();

        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Écriture atomique : fichier temporaire + rename, permissions 0600.
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_else(|| "tokens".into());
        let tmp = self.path.with_file_name(format!(".{}.tmp", file_name));

        fs::write(&tmp, content)?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, &self.path)?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))?;

        Ok(())
    }
}

/// Token neuf : `sqi_` + 32 octets hexadécimaux.
pub fn mint_token() -> String {
    use std::fmt::Write;

    let bytes: [u8; 32] = std::array::from_fn(|_| rand::random::<u8>());
    let hex = bytes
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            write!(acc, "{:02x}", byte).ok();
            acc
        });

    format!("sqi_{}", hex)
}

fn random_tenant() -> String {
    let bytes: [u8; 16] = std::array::from_fn(|_| rand::random::<u8>());
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn tenant_dir(root: &Path, tenant: &str) -> PathBuf {
    root.join("tenants").join(tenant)
}

// ---------------------------------------------------------------------------
// Crypto minimale (SHA-256 + HMAC, comparaison temps constant)
// ---------------------------------------------------------------------------

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];

    if key.len() > 64 {
        block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = [0x36u8; 64];
    let mut outer_pad = [0x5cu8; 64];
    for i in 0..64 {
        inner_pad[i] ^= block[i];
        outer_pad[i] ^= block[i];
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);

    outer.finalize().into()
}

fn ct_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }

    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }

    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config(secret: &[u8]) -> JwtConfig {
        JwtConfig {
            verifier: JwtVerifier::Hs256(secret.to_vec()),
            audience: DEFAULT_JWT_AUDIENCE.to_string(),
        }
    }

    fn sign(secret: &[u8], claims: serde_json::Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let signing_input = format!("{}.{}", header, payload);
        let signature = hmac_sha256(secret, signing_input.as_bytes());

        format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
    }

    fn valid_claims() -> serde_json::Value {
        serde_json::json!({
            "sub": "gh-42",
            "preferred_username": "Alice",
            "aud": "squilladns",
            "exp": unix_now() + 300,
            "email": "alice@example.com"
        })
    }

    /// Simule le JWT normalisé et signé par le BFF après authentification SSO.
    /// Les providers réels n'émettent pas le JWT SquillaDNS directement.
    fn sso_claims(issuer: &str, subject: &str, login: &str) -> serde_json::Value {
        serde_json::json!({
            "iss": issuer,
            "sub": subject,
            "preferred_username": login,
            "aud": "squilladns",
            "exp": unix_now() + 300
        })
    }

    #[test]
    fn tenant_ids_are_distinct_even_when_legacy_sanitizing_collided() {
        // Ancien bug : `a@b.com` et `a_b.com` finissaient dans `user-a_b.com`.
        assert_ne!(
            tenant_id("jwt", "https://issuer", "a@b.com"),
            tenant_id("jwt", "https://issuer", "a_b.com")
        );
        // Même sujet, provider différent → tenants différents.
        assert_ne!(
            tenant_id("jwt", "github", "42"),
            tenant_id("jwt", "azure", "42")
        );
    }

    #[test]
    fn tenant_id_is_stable_and_filename_safe() {
        let first = tenant_id("token", "token", "abc");
        assert_eq!(first, tenant_id("token", "token", "abc"));
        assert!(is_valid_tenant(&first));
        assert_eq!(first.len(), 22);
        assert!(!first.contains('/'));
        assert!(!first.contains('.'));
    }

    #[test]
    fn readable_internal_ids_do_not_collide_after_normalization() {
        assert_ne!(
            internal_user_id("github", "a@b"),
            internal_user_id("github", "a-b")
        );
        assert_eq!(
            internal_user_id("github", "583231"),
            internal_user_id("github", "583231")
        );
    }

    #[test]
    fn jwt_roundtrip_yields_tenant_and_email() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let user = config(secret)
            .verify(&sign(secret, valid_claims()))
            .unwrap();

        assert_eq!(user.provider, "jwt");
        assert!(user.tenant.starts_with("user-sso-gh-42-"));
        assert_eq!(user.slug, "alice");
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn normalized_sso_jwts_work_for_github_google_and_other_providers() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let scenarios = [
            ("github", "583231", "OctoCat", "octocat"),
            (
                "google",
                "109876543210987654321",
                "Alice.Example",
                "alice-example",
            ),
            (
                "https://login.example.test/tenant-a",
                "user:external-42",
                "Mina_Dev",
                "mina-dev",
            ),
        ];

        for (issuer, subject, login, expected_slug) in scenarios {
            let user = config(secret)
                .verify(&sign(secret, sso_claims(issuer, subject, login)))
                .expect("BFF JWT normalisé accepté quel que soit le SSO");

            assert_eq!(user.provider, "jwt");
            assert_eq!(user.slug, expected_slug);
            assert!(user.tenant.starts_with("user-"));
            assert!(is_valid_tenant(&user.tenant));
        }
    }

    #[test]
    fn sso_identity_is_stable_across_login_changes_and_isolated_by_issuer() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let github = config(secret)
            .verify(&sign(secret, sso_claims("github", "583231", "octocat")))
            .unwrap();
        let renamed_github = config(secret)
            .verify(&sign(
                secret,
                sso_claims("github", "583231", "octocat-renamed"),
            ))
            .unwrap();
        let google = config(secret)
            .verify(&sign(secret, sso_claims("google", "583231", "octocat")))
            .unwrap();

        assert_eq!(github.tenant, renamed_github.tenant);
        assert_ne!(github.slug, renamed_github.slug);
        assert_ne!(github.tenant, google.tenant);
    }

    #[test]
    fn sso_jwt_requires_a_usable_login_for_the_public_slug() {
        let secret = b"0123456789abcdef0123456789abcdef";
        for login in ["", " !!! "] {
            assert_eq!(
                config(secret)
                    .verify(&sign(secret, sso_claims("github", "583231", login)))
                    .unwrap_err(),
                AuthError::InvalidToken
            );
        }

        let mut claims = sso_claims("github", "583231", "octocat");
        claims.as_object_mut().unwrap().remove("preferred_username");
        assert_eq!(
            config(secret).verify(&sign(secret, claims)).unwrap_err(),
            AuthError::InvalidToken
        );
    }

    #[test]
    fn token_created_for_sso_identity_keeps_its_slug_and_zones_tenant() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let user = config(secret)
            .verify(&sign(secret, sso_claims("github", "583231", "octocat")))
            .unwrap();
        let path = temp_store_path("sso-token");
        let mut store = TokenStore::load(path.clone(), "");
        let token = mint_token();

        assert!(store.add(&user.tenant, &user.slug, &token));
        drop(store);

        let reloaded = TokenStore::load(path.clone(), "");
        assert_eq!(reloaded.resolve(&token), Some((user.tenant, user.slug)));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn jwt_rejects_expired_token() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let mut claims = valid_claims();
        claims["exp"] = serde_json::json!(unix_now() - 3600);

        assert_eq!(
            config(secret).verify(&sign(secret, claims)).unwrap_err(),
            AuthError::ExpiredToken
        );
    }

    #[test]
    fn jwt_rejects_tampered_signature() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let token = sign(secret, valid_claims());

        // 1. signature altérée
        let mut tampered = token.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            config(secret).verify(&tampered).unwrap_err(),
            AuthError::InvalidToken
        );

        // 2. payload réécrit, signature d'origine conservée
        let parts: Vec<&str> = token.split('.').collect();
        let (header, signature) = (parts[0], parts[2]);
        let mut claims = valid_claims();
        claims["sub"] = serde_json::json!("gh-43");
        let forged = format!(
            "{}.{}.{}",
            header,
            URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()),
            signature
        );

        assert_eq!(
            config(secret).verify(&forged).unwrap_err(),
            AuthError::InvalidToken
        );
    }

    #[test]
    fn jwt_rejects_wrong_audience_and_missing_exp() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let mut claims = valid_claims();
        claims["aud"] = serde_json::json!("another-api");
        assert_eq!(
            config(secret).verify(&sign(secret, claims)).unwrap_err(),
            AuthError::InvalidToken
        );

        let secret = b"0123456789abcdef0123456789abcdef";
        let mut claims = valid_claims();
        claims.as_object_mut().unwrap().remove("exp");
        assert_eq!(
            config(secret).verify(&sign(secret, claims)).unwrap_err(),
            AuthError::InvalidToken
        );
    }

    #[test]
    fn jwt_rejects_alg_none_and_alg_hs512() {
        let secret = b"0123456789abcdef0123456789abcdef";

        for alg in ["none", "HS512", "RS256"] {
            let header =
                URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg).as_bytes());
            let payload = URL_SAFE_NO_PAD.encode(valid_claims().to_string().as_bytes());
            let token = format!("{}.{}.", header, payload);

            assert_eq!(
                config(secret).verify(&token).unwrap_err(),
                AuthError::InvalidToken,
                "alg {} doit être refusé",
                alg
            );
        }
    }

    fn temp_store_path(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("squilladns-test-{}-{}", name, random_tenant()));
        fs::create_dir_all(&dir).unwrap();
        dir.join("tokens")
    }

    #[test]
    fn token_store_gives_one_tenant_per_token() {
        let path = temp_store_path("per-token");
        fs::write(&path, "token-one\ntoken-two\n").unwrap();

        let store = TokenStore::load(path.clone(), "");
        let first = store.resolve("token-one").unwrap();
        let second = store.resolve("token-two").unwrap();

        assert_ne!(
            first.0, second.0,
            "deux tokens = deux tenants (bug initial)"
        );
        assert!(store.resolve("unknown").is_none());

        // Le fichier migré doit être relu à l'identique.
        let reloaded = TokenStore::load(path.clone(), "");
        assert_eq!(reloaded.resolve("token-one").unwrap(), first);
        assert_eq!(reloaded.resolve("token-two").unwrap(), second);

        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(&format!("{}\t", first.0)));
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn token_store_adds_bootstrap_without_erasing_existing_tokens() {
        let path = temp_store_path("bootstrap");
        fs::write(&path, "existing\n").unwrap();

        let store = TokenStore::load(path.clone(), "bootstrap-token");

        assert!(store.resolve("existing").is_some());
        assert!(store.resolve("bootstrap-token").is_some());
        assert_ne!(
            store.resolve("existing").unwrap().0,
            store.resolve("bootstrap-token").unwrap().0
        );

        let content = fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 2);
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn bootstrap_tenant_survives_a_lost_token_file() {
        let path = temp_store_path("bootstrap-lost");
        let first = TokenStore::load(path.clone(), "bootstrap-token")
            .resolve("bootstrap-token")
            .unwrap()
            .0;

        fs::remove_file(&path).unwrap();

        let second = TokenStore::load(path.clone(), "bootstrap-token")
            .resolve("bootstrap-token")
            .unwrap()
            .0;

        assert_eq!(
            first, second,
            "recréer le conteneur ne doit pas changer de tenant"
        );
        let _ = fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn token_store_mints_prefix_token() {
        let token = mint_token();
        assert!(token.starts_with("sqi_"));
        assert_eq!(token.len(), 4 + 64);
    }
}
