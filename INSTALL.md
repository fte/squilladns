# Installation et déploiement SquillaDNS

## Objectif

Ce document décrit les étapes de déploiement de SquillaDNS en environnement local, Docker, et production légère. Il complète le [README.md](./README.md) en se concentrant sur l'installation, la configuration, l'exploitation et les bonnes pratiques de mise en service.

## Prérequis

- Rust 1.70+ (si compilation locale)
- Docker 24+ ou Docker Compose v2
- `named-checkzone` (fourni par `bind9-utils` dans l'image Docker du projet)
- Accessibilité réseau sur le port `8085`
- Un stockage persistant pour les fichiers de zone si le service doit survivre à un reboot
- Un secret d'API / token si l'API est exposée à des clients non-trustés

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `API_ADDR` | `0.0.0.0:8085` | Adresse d'écoute du service |
| `API_TOKEN` | vide | Token interne généré ou injecté pour sécuriser les endpoints sensibles |
| `API_TOKEN_PATH` | `/app/.api-token` | Emplacement du fichier local contenant le token |
| `ZONES_DIR` | `zones/example.invalid` | Répertoire racine des zones gérées par le service |

## Modes d'installation

### 1. Déploiement local via Cargo

```bash
cargo build --release
API_ADDR=0.0.0.0:8085 \
API_TOKEN="$(openssl rand -hex 32)" \
ZONES_DIR=./zones/example.invalid \
./target/release/squilladns
```

Puis vérifier :

```bash
curl -fsS http://127.0.0.1:8085/health
```

### 2. Déploiement via Docker Compose

Le projet fournit un `docker-compose.yml`. Définis `API_TOKEN` avant le démarrage :

```bash
export API_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
```

Sans cette variable, la configuration Compose de développement peut utiliser un token de démonstration. Ne l'expose jamais sur un réseau non fiable.

Le service écoute sur :

```bash
http://127.0.0.1:8085
```

Vérification :

```bash
curl -fsS http://127.0.0.1:8085/health
```

### 3. Déploiement via Makefile

```bash
make up API_TOKEN="$(openssl rand -hex 32)"
```

Les cibles utiles :

```bash
make build
make logs
make down
make restart
make ps
```

## Sécurité et tokens

Le service autorise un mode de sécurité avec token interne. Au démarrage, si `API_TOKEN` est absent et qu'aucun fichier de token n'est présent, SquillaDNS en crée un automatiquement et l'écrit sur `API_TOKEN_PATH` avec permissions `0600`.

Exemple de lancement sécurisé :

```bash
export API_TOKEN="$(openssl rand -hex 32)"
export API_ADDR="0.0.0.0:8085"
export ZONES_DIR="./zones/example.invalid"
docker compose up -d
```

Le fichier `.api-token` est stocké en clair avec des permissions Unix restrictives (`0600`) ; il n'est pas chiffré. Protège le volume et ne publie jamais ce fichier :

```bash
ls -l /app/.api-token
```

## Gestion des zones

Les zones sont générées dans le répertoire configuré par `ZONES_DIR`.

Exemple de structure :

```text
zones/
└── example.invalid/
    └── default/
        └── default.zone
```

Le fichier de zone est écrit au format BIND9 standard. Le SOA et, si nécessaire, le NS d'apex sont générés automatiquement. Les enregistrements pris en charge sont :

- SOA
- A / AAAA
- MX / NS
- TXT / CAA
- CNAME
- SRV

## Authentification

Les routes `/zones`, `/sync` et `/token` requièrent un token Bearer partagé. Configure-le avec `API_TOKEN` ou utilise le token généré au démarrage et conservé dans `API_TOKEN_PATH`.

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8085/zones
```

Le token généré automatiquement est affiché dans les logs de démarrage : protège ces logs comme un secret.

## Surveillance et exploitation

### Vérification de santé

```bash
curl -fsS http://127.0.0.1:8085/health
```

### Swagger / docs API

```text
http://127.0.0.1:8085/docs
```

### Logs

```bash
docker compose logs -f
```

ou

```bash
make logs
```

### Redémarrage

```bash
docker compose restart
```

ou

```bash
make restart
```

## Production légère : recommandations

Pour un usage quasi-production, les recommandations suivantes sont pertinentes :

- exposer le service derrière un reverse proxy (Nginx / Caddy)
- utiliser un secret manager ou un environnement d'orchestration pour `API_TOKEN`
- monter un volume persistant sur `ZONES_DIR`
- limiter les accès réseau au service DNS administratif
- activer les logs structurés et la collecte centralisée
- utiliser un monitoring de santé avec alerting sur `/health`
- ne pas laisser de token en clair dans un dépôt Git

## Exemple de stack de production légère

```yaml
services:
  squilladns:
    image: ghcr.io/fte/squilladns:latest
    restart: unless-stopped
    ports:
      - "127.0.0.1:8085:8085"
    environment:
      - API_ADDR=0.0.0.0:8085
      - API_TOKEN=${API_TOKEN}
      - ZONES_DIR=/data/zones
    volumes:
      - ./data/zones:/data/zones
```

## Exemples d'appels

### Endpoint de santé

```bash
curl http://127.0.0.1:8085/health
```

### Génération d'un token

```bash
curl -X POST http://127.0.0.1:8085/token \
  -H "Authorization: Bearer <token>"
```

### Synchronisation d'une zone

```bash
curl -X POST http://127.0.0.1:8085/sync \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <token>" \
  -d '{
    "records": [
      {"type": "A", "name": "@", "value": "203.0.113.10"},
      {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.example.com ~all"}
    ]
  }'
```

## Nettoyage

Pour supprimer le service et ses ressources Docker locales :

```bash
make down
```

ou :

```bash
docker compose down
```

## Points d'amélioration recommandés

- validation stricte des entrées DNS
- persistance utilisateur / multi-tenant
- gestion des ACL et de l'autorisation par zone
- intégration avec un service BIND9 opéré via reload/restart
- métriques Prometheus / OpenTelemetry
- test automatisé de génération de fichier zone

## Conclusion

SquillaDNS est déjà un service exploitable comme base technique pour la gestion d'une zone DNS via API, mais il doit encore évoluer vers un modèle plus robuste pour le multi-tenancy, la validation et la production. L'installation est volontairement simple pour rendre le projet facile à tester et à déployer sans dépendre d'un écosystème lourd.
