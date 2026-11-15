# Auth côté client

Ce document décrit **uniquement** ce que le client doit faire. L'API ne connaît
aucun provider OAuth : elle vérifie une signature et des claims, rien de plus.

```text
navigateur                front / BFF                         API squilladns
    │                         │                                    │
    │ clic "GitHub"           │                                    │
    ├────────────────────────►│ OAuth GitHub                       │
    │                         │ récupère id + login                │
    │                         │ signe un JWT HS256                 │
    │                         │                                    │
    │                         ├── POST /token + JWT ──────────────►│
    │                         │◄── { token: sqi_…, slug: login } ──┤
    │◄── token + slug ────────┤                                    │
    │                         │                                    │
    ├── GET /zones + token API ───────────────────────────────────►│
    │                         │       tenant interne → zones       │
```

Le token GitHub ne quitte jamais le BFF. Le JWT sert à obtenir un token API via
`POST /token`. La réponse contient le token à conserver côté client et le slug
public du compte. Les appels suivants utilisent ce token ; l’API le rattache au
même identifiant interne et aux mêmes zones. Le slug permet au client de
retrouver/afficher le compte sans exposer cet identifiant interne.


---

## 1. Ce que l'API attend

### JWT (option A, recommandé)

`Authorization: Bearer <jwt>`, signature **HS256**, secret partagé avec le BFF.

| Claim | Requis | Règle |
|-------|--------|-------|
| `sub` | oui | 1–128 caractères `[A-Za-z0-9._@:-]`. Identifiant stable, privé côté API. |
| `exp` | oui | Timestamp Unix. Tolérance d'horloge : 60 s. |
| `aud` | oui | Doit valoir `squilladns` (constante côté API). |
| `iss` | non | Identifie l'émetteur ; contribue à l'identifiant interne. |
| `preferred_username` | oui | Login SSO lisible ; l’API le normalise en slug public. |
| `email` | non | Affiché par `GET /auth/me`. |

Règles dures côté API : `alg` doit être exactement `HS256` (`none`, `HS512`,
`RS256` sont rejetés), signature comparée en temps constant, et **aucun repli
anonyme** : un JWT invalide renvoie `401`.

`sub` doit être **stable par utilisateur** : `String(user.id)` du provider suffit
(`12345` pour GitHub). L'API génère un identifiant interne lisible à partir de
l'émetteur et du `sub`, avec un suffixe anti-collision. Il reste privé à l'API.
Le client ne reçoit que `preferred_username` normalisé en `slug`, notamment dans
la réponse de `POST /token`.

### Token API

`POST /token` accepte le JWT du SSO et renvoie `{created, token, slug}`.
Le token créé reste rattaché au compte et à ses zones. Plusieurs tokens créés
pour le même utilisateur partagent donc ses zones. Le token bootstrap
`API_TOKEN`, lui, a son propre tenant.

### Sandbox

`SANDBOX_USER=alice` côté API : n'importe quel appel, **même sans header**,
devient `alice` (`provider: "sandbox"`). C'est le mode à utiliser pour développer
le front avant d'avoir un provider :

```bash
make up SANDBOX_USER=alice
curl http://localhost:8085/auth/me
# {"authenticated":true,"slug":"alice","provider":"sandbox","scope":"private"}
```

---

## 2. Erreurs

Toujours du `problem+json` (RFC 9457). Le champ stable à traiter est `type` :
`https://squilladns.dev/errors/<code>`.

| `type` (suffixe) | HTTP | Cause | Que fait le front |
|------------------|------|-------|-------------------|
| `auth_required` | 401 | aucun header sur une route qui l'exige | renvoyer vers le bouton SSO |
| `auth_invalid_token` | 401 | token inconnu, JWT malformé/mauvaise signature/mauvais `alg` | purger le token stocké, revoir l'utilisateur |
| `auth_expired` | 401 | `exp` dépassé | redemander un JWT (ou relancer le SSO) |
| — (validation) | 400/422 | payload de zone invalide | afficher `detail` + `errors[]` |

```json
{
  "type": "https://squilladns.dev/errors/auth_expired",
  "title": "Expired Token",
  "status": 401,
  "detail": "The Bearer token has expired; request a new one.",
  "instance": "/zones"
}
```

Règle côté front : sur `401`, supprimer le token et proposer le bouton SSO. Ne
jamais réessayer en boucle.

---

## 3. BFF minimal (Node 18+, zéro dépendance)

Un seul fichier, `bff.js`. Il fait le flux GitHub et signe le JWT.

```js
// bff.js — node bff.js
import http from 'node:http';
import crypto from 'node:crypto';

const {
  PORT = 8904,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  JWT_SECRET,                       // même valeur que côté API
  JWT_AUDIENCE = 'squilladns',      // constante côté API
  JWT_TTL = '900',                  // 15 min
  API_URL = 'http://localhost:8085',
  PUBLIC_URL = 'http://localhost:8904',
} = process.env;

if (!GITHUB_CLIENT_ID || !GITHUB_CLIENT_SECRET || !JWT_SECRET) {
  console.error('GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET et JWT_SECRET sont requis');
  process.exit(1);
}

const b64 = (value) => Buffer.from(value).toString('base64url');

function signJwt(claims) {
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64(JSON.stringify(claims));
  const data = `${header}.${payload}`;
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${signature}`;
}

// state -> expiration (anti-CSRF, usage unique, 10 min)
const pending = new Map();

const reply = (res, status, body) => {
  res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(body));
};

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, PUBLIC_URL);

  // 1. Redirection vers GitHub
  if (url.pathname === '/auth/github') {
    const state = crypto.randomBytes(32).toString('base64url');
    pending.set(state, Date.now() + 10 * 60 * 1000);

    const authorize = new URL('https://github.com/login/oauth/authorize');
    authorize.searchParams.set('client_id', GITHUB_CLIENT_ID);
    authorize.searchParams.set('redirect_uri', `${PUBLIC_URL}/auth/github/callback`);
    authorize.searchParams.set('scope', 'read:user user:email');
    authorize.searchParams.set('state', state);
    authorize.searchParams.set('allow_signup', 'false');

    res.writeHead(302, { Location: authorize.toString() }).end();
    return;
  }

  // 2. Retour de GitHub
  if (url.pathname === '/auth/github/callback') {
    const { code, state, error } = Object.fromEntries(url.searchParams);

    if (error) return reply(res, 401, { code: 'auth_provider_denied' });

    const expiresAt = pending.get(state);
    pending.delete(state);
    if (!code || !expiresAt || expiresAt < Date.now()) {
      return reply(res, 400, { code: 'auth_state_invalid' });
    }

    // 2a. Échange du code (le client_secret reste ici)
    const tokenResponse = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: GITHUB_CLIENT_ID,
        client_secret: GITHUB_CLIENT_SECRET,
        code,
        redirect_uri: `${PUBLIC_URL}/auth/github/callback`,
      }),
    }).then((response) => response.json());

    if (!tokenResponse.access_token) {
      console.error('github token exchange:', tokenResponse);
      return reply(res, 502, { code: 'auth_code_exchange_failed' });
    }

    // 2b. Identité + email vérifié
    const headers = {
      Authorization: `Bearer ${tokenResponse.access_token}`,
      Accept: 'application/vnd.github+json',
      'User-Agent': 'squilladns-bff',
    };

    const [profile, emails] = await Promise.all([
      fetch('https://api.github.com/user', { headers }).then((r) => r.json()),
      fetch('https://api.github.com/user/emails', { headers }).then((r) => r.json()),
    ]);

    const primary = Array.isArray(emails)
      ? emails.find((entry) => entry.primary && entry.verified)
      : undefined;

    // 2c. JWT court, utilisé uniquement pour appeler /token côté serveur
    const jwt = signJwt({
      sub: String(profile.id),
      preferred_username: profile.login,
      iss: 'github',
      email: primary?.email ?? null,
      aud: JWT_AUDIENCE,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + Number(JWT_TTL),
    });

    // 2d. Échange du JWT contre le token API et le slug public
    const exchange = await fetch(`${API_URL}/token`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${jwt}`, Accept: 'application/json' },
    });
    if (!exchange.ok) {
      console.error('API token exchange:', exchange.status);
      return reply(res, 502, { code: 'api_token_exchange_failed' });
    }
    const { token: apiToken, slug } = await exchange.json();
    if (typeof apiToken !== 'string' || typeof slug !== 'string') {
      return reply(res, 502, { code: 'api_token_response_invalid' });
    }

    // 2e. Page de retour : le JWT reste côté serveur ; le client reçoit token API + slug
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(`<!doctype html><meta charset="utf-8"><script>
      sessionStorage.setItem('sqd_token', ${JSON.stringify(apiToken)});
      sessionStorage.setItem('sqd_login', ${JSON.stringify(slug)});
      location.replace('/');
    </script>`);
    return;
  }

  // 3. Statique
  reply(res, 404, { code: 'not_found' });
});

server.listen(PORT, () => console.log(`BFF prêt sur ${PUBLIC_URL}`));
```

Démarrage :

```bash
export GITHUB_CLIENT_ID=… GITHUB_CLIENT_SECRET=… \
       JWT_SECRET="$(openssl rand -hex 32)"
make up JWT_SECRET="$JWT_SECRET"          # côté API
export API_URL=http://localhost:8085
node bff.js                                # côté front
```

Déclare `http://localhost:8904/auth/github/callback` comme *Authorization
callback URL* dans l'OAuth App GitHub (les URLs `localhost` sont acceptées).

---

## 4. Les boutons

HTML/CSS/JS sans framework. Le bouton est un simple lien : GitHub exige une
navigation haut de page, pas un `fetch`.

```html
<!-- index.html -->
<!doctype html>
<meta charset="utf-8">
<title>SquillaDNS</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 3rem auto; max-width: 40rem; }
  .sso { display: flex; flex-direction: column; gap: .5rem; margin: 1.5rem 0; }
  .sso a, .sso button {
    display: flex; align-items: center; gap: .6rem;
    padding: .65rem .9rem; border-radius: .5rem;
    border: 1px solid #8884; background: #8881;
    color: inherit; font: inherit; text-decoration: none; cursor: pointer;
  }
  .sso a:hover, .sso button:hover { background: #8882; }
  .sso :disabled { opacity: .5; cursor: not-allowed; }
  .sso svg { width: 18px; height: 18px; fill: currentColor; }
  .error { color: #c33; }
</style>

<div id="out"></div>

<div class="sso" id="sso">
  <a href="/auth/github" data-provider="github">
    <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.4 7.4 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A7.995 7.995 0 0 0 16 8c0-4.42-3.58-8-8-8Z"/></svg>
    Se connecter avec GitHub
  </a>
  <button disabled title="Bientôt disponible">Microsoft / Azure</button>
  <button disabled title="Bientôt disponible">Google</button>
</div>
<button id="logout" hidden>Se déconnecter</button>
<pre id="zones"></pre>
```

```js
// app.js
const API = 'http://localhost:8085';

const token = () => sessionStorage.getItem('sqd_token');
const forget = () => {
  sessionStorage.removeItem('sqd_token');
  sessionStorage.removeItem('sqd_login');
  location.reload();
};

// Codes d'erreur de l'API -> message affiché
const MESSAGES = {
  auth_required: 'Session absente, reconnecte-toi.',
  auth_invalid_token: 'Session invalide, reconnecte-toi.',
  auth_expired: 'Session expirée, reconnecte-toi.',
};

async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { 'Content-Type': 'application/json' } : {}),
      ...(token() ? { Authorization: `Bearer ${token()}` } : {}),
      ...options.headers,
    },
  });

  if (response.status === 401) {
    const problem = await response.json().catch(() => ({}));
    const code = (problem.type || '').split('/').pop();
    document.getElementById('out').innerHTML =
      `<p class="error">${MESSAGES[code] ?? 'Authentification refusée.'}</p>`;
    forget();
    throw new Error(code);
  }

  if (response.status === 204) return null;
  if (!response.ok) throw new Error((await response.json()).detail ?? response.statusText);
  return response.json();
}

async function refresh() {
  const anonymous = document.getElementById('sso');
  const logout = document.getElementById('logout');

  if (!token()) {
    anonymous.hidden = false;
    logout.hidden = true;
    return;
  }

  anonymous.hidden = true;
  logout.hidden = false;

  const me = await api('/auth/me');
  const zones = await api('/zones');
  document.getElementById('zones').textContent =
    `${me.slug} (${me.provider})\n` +
    (zones.zones.length ? zones.zones.join('\n') : 'aucune zone');
}

document.getElementById('logout').addEventListener('click', forget);
refresh();
```

Si le front et l'API ne sont pas sur la même origine, autorise l'origine côté API :

```bash
make up JWT_SECRET=… CORS_ALLOWED_ORIGINS=http://localhost:8904
```

Pour éviter complètement le CORS *et* l'exposition du JWT au JavaScript, fais
transiter les appels par le BFF (`/api/*` → API avec le header) et garde une
session cookie côté BFF. C'est un proxy de 20 lignes ; le reste du front ne
change pas.

---

## 5. Cas des scripts et du CI

Un token API suffit, aucun JWT :

```bash
TOKEN="$(curl -s -X POST http://localhost:8085/token \
  -H "Authorization: Bearer $API_TOKEN" | jq -r .token)"

curl -s http://localhost:8085/zones -H "Authorization: Bearer $TOKEN"
```

`POST /token` rattache le nouveau token au **même tenant** que le porteur : les
zones créées depuis le front sont visibles depuis le script, et inversement.
Deux tokens bootstrap différents, eux, ont deux tenants distincts.

---

## 6. Checklist

- [ ] `client_secret` uniquement dans le BFF, jamais dans le navigateur
- [ ] `state` aléatoire (32 octets), usage unique, TTL 10 min, vérifié au retour
- [ ] `redirect_uri` identique à celle déclarée chez le provider
- [ ] `JWT_SECRET` ≥ 32 octets, identique côté BFF et côté API, hors du dépôt
- [ ] TTL du JWT court (5–15 min) et renouvellement silencieux côté BFF
- [ ] `sub` stable par utilisateur (jamais l'email : il change)
- [ ] sur `401` : purge + bouton SSO, pas de retry en boucle
- [ ] `Cache-Control: no-store` sur les réponses du BFF
- [ ] HTTPS en production (les cookies et les `redirect_uri` en dépendent)
- [ ] `CORS_ALLOWED_ORIGINS` restreint à l'origine du front
