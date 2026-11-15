# squilladns

<p align="center">
  <img src="squilladns.jpeg" alt="squilladns mascot" width="480">
</p>

SquillaDNS est une API REST légère écrite en Rust pour gérer des zones DNS BIND9 depuis un service HTTP. Le projet a pour objectif de fournir un point d'entrée simple pour provisionner, synchroniser et exposer des enregistrements DNS sans devoir manipuler directement des fichiers de zone sur un serveur distant.

Le nom vient de la squille, un crustacé rapide et très observateur, ce qui rappelle un nameserver capable de lire toutes les formes d'enregistrements et de répondre vite.

## Statut du projet

- Version actuelle : `0.1.0`
- Type : prototype / base technique de production orientée service
- Focus actuel : API REST protégée par token, validation DNS, génération de fichiers de zone et conteneurisation Docker

## Fonctionnalités principales

### Gestion de zones DNS

- Créer / remplacer une zone via `PUT /zones/{name}`, la supprimer via `DELETE /zones/{name}`
- Synchroniser les enregistrements reçus par l'API vers un fichier de zone sur disque
- Générer un SOA automatiquement (mname/rname dérivés de la zone) et ajouter un NS d'apex par défaut si aucun n'est fourni
- Valider les enregistrements et le fichier final avec `named-checkzone` (ignoré si le binaire est absent)
- Restaurer le fichier précédent si la validation finale échoue
- Générer des fichiers `*.zone` destinés à être consommés par BIND9
- Recharger une zone avec `rndc reload` quand `rndc` est disponible
- Isoler les zones par scope : `public/` pour les appels anonymes, `tenants/<tenant>/` pour les appels authentifiés
- Lister les zones du scope courant via `GET /zones`
- Serial incrémental relu depuis le fichier de zone existant (`max(jour UTC, serial + 1)`)

### Types d'enregistrements supportés

Les enregistrements fournis par le client peuvent être :

- `A`
- `AAAA`
- `CNAME`
- `MX`
- `NS`
- `TXT`
- `SRV`
- `CAA`

Le SOA est généré automatiquement ; il ne fait pas partie des types acceptés dans le payload.

### Calcul de serial BIND9

- Le helper de serial applique `max(jour UTC depuis epoch, serial existant + 1)`
- Le serial existant est relu dans la ligne SOA du fichier de zone avant réécriture

### Authentification et sécurité

Deux mécanismes, aucun appel réseau : l'API ne contacte **jamais** un provider OAuth.

- Auth optionnelle : sans header `Authorization`, l'appelant est anonyme et travaille dans le scope `public`
- Avec `Authorization: Bearer <token>`, les zones sont isolées dans le tenant du porteur (`scope: "private"`)
- **Token API** : `sqi_…`, stocké dans `API_TOKEN_PATH` ; les tokens créés par `POST /token` héritent du compte SSO appelant et partagent ses zones
- **JWT HS256** : émis par le client après un SSO GitHub/Azure/Google. Claims requis : `sub`, `preferred_username`, `exp`, `aud` (défaut `squilladns`). Voir [AUTH.md](./AUTH.md)
- Un credential présent mais invalide renvoie `401` en `problem+json` (`auth_invalid_token`, `auth_expired`, `auth_required`) — jamais de repli silencieux vers le scope public
- L'API range les zones sous un identifiant interne lisible et stable, jamais renvoyé au client ; le client reçoit seulement le slug du login SSO
- Mode sandbox pour le dev local : `SANDBOX_USER=alice` (auth court-circuitée, avertissement au démarrage)
- `POST /token` crée un token rattaché au tenant de l'appelant, sans invalider les précédents
- Conservation des tokens dans `API_TOKEN_PATH`, écriture atomique, permissions Unix `0600`
- CORS configurable via `CORS_ALLOWED_ORIGINS` (ouvert par défaut, y compris `Origin: null` des fichiers locaux)
- Documentation OpenAPI / Swagger incluse

Les spécifications côté client (flux SSO, boutons, gestion des erreurs) sont dans **[AUTH.md](./AUTH.md)**.

### Déploiement et exploitation

- Service HTTP via `axum` + `tokio`
- Exécution en conteneur Docker
- Support Docker Compose pour un déploiement rapide
- Logs structurés via `tracing`
- API documentée via Swagger UI sur `/docs`
- Mesure des temps de réponse exposée par en-têtes (`Server-Timing`, `X-Response-Time`, `X-Request-Id`)

### Mesure des temps de réponse

Chaque réponse porte les en-têtes suivants (hors préflight `OPTIONS`, traité par `CorsLayer`) :

```http
Server-Timing: app;dur=382.2;desc="handler", auth;dur=0.1;desc="authentication", validate;dur=0.1;desc="payload validation", write;dur=0.4;desc="zone file write", checkzone;dur=381.5;desc="named-checkzone"
X-Response-Time: 382.2ms
X-Request-Id: d2bd65cb097acb3f
Timing-Allow-Origin: *
Access-Control-Expose-Headers: content-type,server-timing,x-response-time,x-request-id,timing-allow-origin
```

- `app` couvre la requête entière (middleware → réponse prête) ;
- les étapes mesurent le travail réel : résolution d'auth (dont appels provider), validation du payload, écriture du fichier de zone, `named-checkzone`, `rndc reload`, suppression, génération de token ;
- les étapes sont cumulées dans l'ordre d'exécution, jamais après l'envoi du corps ;
- `X-Request-Id` est repris tel quel s'il est fourni par le client (sinon 8 octets hex générés) ;
- `Access-Control-Expose-Headers` est géré par `CorsLayer::expose_headers`, pas écrasé à la main.

Côté navigateur, `performance.getEntriesByType("resource")[i].serverTiming` expose directement `app`, `checkzone`, etc. ; `Timing-Allow-Origin: *` débloque les temps réseau (DNS, TCP, TLS, TTFB) et `X-Response-Time` reste lisible en XHR.

## Stack technique

- HTTP : `axum`, `tokio`, `tower`
- DNS / zone generation : `hickory-*`
- Serialization : `serde`, `serde_json`
- Logging : `tracing`, `tracing-subscriber`
- OpenAPI : `utoipa`, `utoipa-swagger-ui`
- Conteneurisation : Docker, Docker Compose

## Points d'entrée API

| Méthode | Chemin | Description | Auth |
|---------|--------|-------------|------|
| GET | `/` | Redirection vers Swagger UI | — |
| GET | `/health` | Vérifie l'état du service et le mode d'auth | — |
| GET | `/auth/me` | Identité résolue de l'appelant (`slug`, `scope`) | Optionnelle |
| GET | `/zones` | Liste les zones du scope courant | Optionnelle |
| PUT | `/zones/{name}` | Crée (`201`) ou remplace (`200`) une zone | Optionnelle |
| DELETE | `/zones/{name}` | Supprime une zone (`204` / `404`) | Optionnelle |
| POST | `/sync` | Écrit une zone (body JSON) et/ou recharge (`?zone=`) | Optionnelle |
| POST | `/token` | Crée un token pour le tenant de l'appelant | Requise |
| GET | `/docs` | Interface Swagger UI | — |

Le body JSON des routes d'écriture est de la forme :

```json
{
  "records": [
    {"type": "A", "name": "@", "value": "1.2.3.4"},
    {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.example ~all"}
  ]
}
```

`POST /sync` accepte deux usages : avec le body ci-dessus pour (ré)écrire la zone (`?zone=<nom>`, sinon `default`), ou avec le seul paramètre `?zone=<nom>` pour recharger une zone déjà présente sur disque.

## Démarrage rapide

### Avec Docker Compose

```bash
export API_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
curl http://127.0.0.1:8085/health
```

Définis un token aléatoire avant de démarrer ; ne conserve pas le token d'exemple fourni par les configurations de développement.

### Avec Makefile

```bash
make up
make logs
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `API_ADDR` | `0.0.0.0:8085` | Adresse d'écoute du service |
| `API_TOKEN` | vide | Token racine. Vide : un token est généré au démarrage, écrit dans `API_TOKEN_PATH` et affiché une fois dans les logs |
| `API_TOKEN_PATH` | `.state/tokens` | Fichier de tokens (`<tenant>\t<slug>\t<token>` par ligne, `0600`, migré automatiquement) |
| `ZONES_DIR` | `zones/example.invalid` | Répertoire racine des zones (`<ZONES_DIR>/public/` ou `<ZONES_DIR>/tenants/<tenant>/`) |
| `CORS_ALLOWED_ORIGINS` | `*` | Origines CORS autorisées, séparées par des virgules (`null` pour `file://`) |
| `JWT_SECRET` | vide | Secret HS256 (≥ 32 octets) partagé avec le front. Sans lui, les JWT sont refusés (`401`) |
| `SANDBOX_USER` | vide | Mode dev : tout appelant devient cet utilisateur, auth court-circuitée |

Les anciens répertoires tenant basés sur un haché sont déplacés automatiquement au
premier appel JWT authentifié. Les répertoires `user-*` du schéma antérieur ne
sont pas migrés automatiquement ; sauvegarde-les avant une migration manuelle.

## Exemple de consommation

### Vérifier l'état du service

```bash
curl http://127.0.0.1:8085/health
```

### Synchroniser une zone

```bash
# Écrire la zone (créée si absente)
curl -X PUT http://127.0.0.1:8085/zones/example.invalid \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "records": [
      {"type": "A", "name": "@", "value": "217.128.154.10"},
      {"type": "MX", "name": "@", "value": "10 mail.example.invalid."},
      {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.google.com ~all"}
    ]
  }'

# Recharger dans BIND9 (rndc reload si disponible)
curl -X POST "http://127.0.0.1:8085/sync?zone=example.invalid" \
  -H "Authorization: Bearer <token>"
```

### Lister et supprimer

```bash
curl http://127.0.0.1:8085/zones
curl -X DELETE http://127.0.0.1:8085/zones/example.invalid \
  -H "Authorization: Bearer <token>"
```

### Générer un token API

```bash
# Échanger le JWT SSO contre un token API et récupérer le slug client
curl -X POST http://127.0.0.1:8085/token \
  -H "Authorization: Bearer <jwt-sso>"

# {"created":true,"token":"sqi_…","slug":"alice"}

# Lister les zones de ce compte avec le token API reçu
curl http://127.0.0.1:8085/zones \
  -H "Authorization: Bearer sqi_…"
```

## Structure du dépôt

```text
.
├── src/
│   ├── main.rs
│   ├── auth.rs
│   ├── validation.rs
│   └── zone.rs
├── zones/
│   └── example.invalid/
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── Cargo.toml
├── README.md
├── AUTH.md
├── ROADMAP.md
└── squilladns.jpeg
```

## Installation et déploiement

Pour la procédure d'installation, le déploiement en Docker et les recommandations de production, voir [INSTALL.md](./INSTALL.md).

## Roadmap

La roadmap détaillée est disponible dans [ROADMAP.md](./ROADMAP.md).

## Licence

MIT
