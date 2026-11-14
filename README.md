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

- Synchroniser les enregistrements reçus par l'API vers un fichier de zone sur disque
- Générer un SOA automatiquement et ajouter un NS d'apex par défaut si aucun n'est fourni
- Valider les enregistrements et le fichier final avec `named-checkzone`
- Générer des fichiers `*.zone` destinés à être consommés par BIND9
- Préparer un layout de travail par domaine (`zones/example.invalid/...`)
- La liste de zones est exposée par `/zones`, mais son implémentation est encore à compléter

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
- La route `/sync` ne relit pas encore le serial du fichier existant et appelle actuellement ce helper sans serial précédent

### Authentification et sécurité

- Authentification Bearer par token partagé configuré avec `API_TOKEN` ou généré au démarrage
- Conservation du token dans `API_TOKEN_PATH`, avec permissions Unix `0600`
- Protection des routes `/zones`, `/sync` et `/token`
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
| GET | `/health` | Vérifie l'état du service | — |
| GET | `/zones` | Liste des zones (implémentation à compléter) | Requise |
| POST | `/sync` | Valide et écrit le fichier de zone `default` | Requise |
| POST | `/token` | Génère un nouveau token interne | Requise |
| GET | `/docs` | Interface Swagger UI | — |

La route `/sync` accepte un payload JSON de type :

```json
{
  "records": [
    {"type": "A", "name": "@", "value": "1.2.3.4"},
    {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.example ~all"}
  ]
}
```

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
| `API_TOKEN` | vide | Token interne préconfiguré si fourni |
| `API_TOKEN_PATH` | `/app/.api-token` | Emplacement du fichier de token |
| `ZONES_DIR` | `zones/example.invalid` | Répertoire racine des zones |

## Exemple de consommation

### Vérifier l'état du service

```bash
curl http://127.0.0.1:8085/health
```

### Synchroniser une zone

```bash
curl -X POST http://127.0.0.1:8085/sync \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "records": [
      {"type": "A", "name": "@", "value": "217.128.154.10"},
      {"type": "MX", "name": "@", "value": "10 mail.example.invalid."},
      {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.google.com ~all"}
    ]
  }'
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
