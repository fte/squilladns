/// Résolution de l'identité d'un appelant.
///
/// Trois modes, évalués dans l'ordre :
///
/// 1. `SANDBOX_USER` défini  → tout le monde devient cet utilisateur fictif (dev local)
/// 2. Header `Authorization: Bearer <token>` présent → vérifié auprès du provider OAuth2
/// 3. Pas de header → anonyme (API publique, accès non filtré)

use axum::http::HeaderMap;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Type représentant un utilisateur identifié
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AuthUser {
    /// Identifiant stable fourni par le provider (sub Google, id GitHub, oid Azure…)
    pub id: String,
    /// Email si fourni par le provider, sinon None
    pub email: Option<String>,
    /// Nom du provider ayant validé le token
    pub provider: String,
}

// ---------------------------------------------------------------------------
// Endpoints userinfo des providers supportés
// ---------------------------------------------------------------------------

/// Chaque provider expose un endpoint userinfo standard OAuth2/OIDC.
/// Ton API ne fait que appeler cet URL avec le token du client —
/// aucune clé, aucune crypto de ton côté.
const PROVIDERS: &[(&str, &str)] = &[
    ("google", "https://www.googleapis.com/oauth2/v3/userinfo"),
    ("github", "https://api.github.com/user"),
    ("microsoft", "https://graph.microsoft.com/oidc/userinfo"),
];

// ---------------------------------------------------------------------------
// Réponse userinfo normalisée
// ---------------------------------------------------------------------------

#[derive(Deserialize, Debug)]
struct UserinfoResponse {
    // Google / OIDC standard
    sub: Option<String>,
    email: Option<String>,
    // GitHub (pas de sub, utilise id)
    id: Option<serde_json::Value>,
    login: Option<String>,
}

impl UserinfoResponse {
    /// Extrait un identifiant stable quel que soit le provider
    fn stable_id(&self) -> Option<String> {
        // OIDC standard (Google, Microsoft)
        if let Some(sub) = &self.sub {
            return Some(sub.clone());
        }
        // GitHub retourne un entier "id"
        if let Some(id) = &self.id {
            return Some(id.to_string());
        }
        None
    }

    fn display_name(&self) -> Option<String> {
        self.email.clone().or_else(|| self.login.clone())
    }
}

// ---------------------------------------------------------------------------
// Résolution principale
// ---------------------------------------------------------------------------

/// Tente de résoudre l'identité de l'appelant.
/// Retourne `None` si anonyme ou token invalide.
pub async fn resolve_user(headers: &HeaderMap) -> Option<AuthUser> {
    // ── Mode sandbox ────────────────────────────────────────────────────────
    // SANDBOX_USER=alice  →  tous les appels sont vus comme "alice"
    // Utile pour le dev local sans OAuth configuré.
    if let Ok(sandbox) = std::env::var("SANDBOX_USER") {
        if !sandbox.is_empty() {
            tracing::debug!("sandbox mode — user: {}", sandbox);
            return Some(AuthUser {
                id: sandbox.clone(),
                email: Some(format!("{}@sandbox.local", sandbox)),
                provider: "sandbox".into(),
            });
        }
    }

    // ── Mode provider OAuth2 ─────────────────────────────────────────────────
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let t = v.trim_start_matches("Bearer ").trim();
            if t.is_empty() { None } else { Some(t.to_string()) }
        })?;

    verify_with_provider(&token).await
}

/// Essaie les providers dans l'ordre jusqu'à ce que l'un d'eux valide le token.
async fn verify_with_provider(token: &str) -> Option<AuthUser> {
    // Client HTTP réutilisable (pas de session, pas de cookie)
    let client = reqwest::Client::builder()
        .user_agent("squilladns/0.1")
        .build()
        .ok()?;

    // Provider forcé via env var (optionnel, accélère la validation)
    let forced = std::env::var("AUTH_PROVIDER").ok();

    for (name, url) in PROVIDERS {
        if let Some(ref p) = forced {
            if p != name {
                continue;
            }
        }

        tracing::debug!("trying provider {} at {}", name, url);

        let resp = client
            .get(*url)
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                match r.json::<UserinfoResponse>().await {
                    Ok(info) => {
                        if let Some(id) = info.stable_id() {
                            tracing::debug!("authenticated via {} — id: {}", name, id);
                            return Some(AuthUser {
                                id,
                                email: info.display_name(),
                                provider: name.to_string(),
                            });
                        }
                    }
                    Err(e) => tracing::debug!("provider {} parse error: {}", name, e),
                }
            }
            Ok(r) => tracing::debug!("provider {} returned {}", name, r.status()),
            Err(e) => tracing::debug!("provider {} unreachable: {}", name, e),
        }
    }

    None
}
