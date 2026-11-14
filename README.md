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
- Isoler les zones par scope : `public/` pour les appels anonymes, `user-<id>/` pour les appels authentifiés
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

- Auth optionnelle : sans token, l'appelant est anonyme et travaille dans le scope `public`
- Avec `Authorization: Bearer <token>`, les zones sont isolées par utilisateur (`private:<id>`)
- Tokens acceptés : token interne (fichier `API_TOKEN_PATH`), ou token OAuth Google / GitHub / Microsoft vérifié via l'endpoint userinfo du provider
- Mode sandbox pour le dev local : `SANDBOX_USER=alice` (aucun provider requis)
- `POST /token` ajoute un token interne au fichier sans invalider les précédents
- Conservation du token dans `API_TOKEN_PATH`, avec permissions Unix `0600`
- CORS configurable via `CORS_ALLOWED_ORIGINS` (ouvert par défaut, y compris `Origin: null` des fichiers locaux)
- Documentation OpenAPI / Swagger incluse

### Déploiement et exploitation

- Service HTTP via `axum` + `tokio`
- Exécution en conteneur Docker
- Support Docker Compose pour un déploiement rapide
- Logs structurés via `tracing`
- API documentée via Swagger UI sur `/docs`

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
| GET | `/auth/me` | Identité résolue de l'appelant | Optionnelle |
| GET | `/zones` | Liste les zones du scope courant | Optionnelle |
| PUT | `/zones/{name}` | Crée (`201`) ou remplace (`200`) une zone | Optionnelle |
| DELETE | `/zones/{name}` | Supprime une zone (`204` / `404`) | Optionnelle |
| POST | `/sync` | Écrit une zone (body JSON) et/ou recharge (`?zone=`) | Optionnelle |
| POST | `/token` | Ajoute un token interne au fichier | Requise |
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
| `API_TOKEN` | vide | Token interne de bootstrap (réécrit au démarrage) |
| `API_TOKEN_PATH` | `/app/.api-token` | Fichier de tokens internes (un par ligne, `0600`) |
| `ZONES_DIR` | `zones/example.invalid` | Répertoire racine des zones (`<ZONES_DIR>/<scope>/<zone>/`) |
| `CORS_ALLOWED_ORIGINS` | `*` | Origines CORS autorisées, séparées par des virgules (`null` pour `file://`) |
| `SANDBOX_USER` | vide | Mode dev : tout appelant devient cet utilisateur |
| `AUTH_PROVIDER` | vide | Force la vérification sur un seul provider (`google`, `github`, `microsoft`) |

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

### Générer un token interne

```bash
curl -X POST http://127.0.0.1:8085/token \
  -H "Authorization: Bearer <token>"
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
├── ROADMAP.md
└── squilladns.jpeg
```

## Installation et déploiement

Pour la procédure d'installation, le déploiement en Docker et les recommandations de production, voir [INSTALL.md](./INSTALL.md).

## Roadmap

La roadmap détaillée est disponible dans [ROADMAP.md](./ROADMAP.md).

## Licence

MIT
