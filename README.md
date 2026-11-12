# squilladns

<p align="center">
  <img src="squilladns.jpeg" alt="squilladns mascot" width="480">
</p>

API REST légère en Rust pour gérer les zones d'un DNS primaire BIND9.

Nommé d'après la *squille* (*Squilla mantis*), crustacé à la frappe ultrarapide (~23 ms) et à la vision multispectrale — comme un nameserver qui voit tous les types d'enregistrements et répond sans latence.

## Fonctionnalités

- Installer, modifier, supprimer des zones BIND9
- Types d'enregistrements : A, AAAA, CNAME, MX, NS, SOA, TXT, SRV, CAA
- Serial calculé en mémoire : `max(date UTC, serial + 1)`
- Authentification par Bearer token (fichier `.api-token`, mode 600)
- Déployable en Docker / Docker Compose

## Stack

- **HTTP** : `hyper` 1.12 + `tokio`
- **DNS** : `hickory-dns` 0.25 (`hickory-server`, `hickory-client`, `hickory-proto`)
- **Sérialisation** : `serde` / `serde_json`
- **Logs** : `tracing` / `tracing-subscriber`

## Endpoints

| Méthode | Chemin | Description | Auth |
|---------|--------|-------------|------|
| GET | `/health` | État de santé | — |
| GET | `/zones` | Lister les zones | — |
| POST | `/token` | Créer un token | — |
| POST | `/sync` | Sync une zone (`?zone=<name>`) | Bearer |
| PUT | `/zones/<name>` | Installer/modifier une zone | Bearer |
| DELETE | `/zones/<name>` | Supprimer une zone | Bearer |

## Démarrage rapide

```bash
# Build et lancement
docker compose up -d

# Vérifier
curl http://127.0.0.1:8085/health
```

## Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `API_TOKEN` | — | Bearer token requis pour les endpoints d'écriture |
| `API_ADDR` | `127.0.0.1:8085` | Adresse d'écoute |
| `ZONES_DIR` | `zones/575.be` | Dossier racine des zones |

## Exemple : installer une zone

```bash
curl -X PUT http://127.0.0.1:8085/zones/www \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "records": [
      {"type": "A",   "name": "@", "value": "217.128.154.10"},
      {"type": "MX",  "name": "@", "value": "10 mail.575.be."},
      {"type": "TXT", "name": "@", "value": "v=spf1 include:_spf.google.com ~all"}
    ]
  }'
```

## Intégration dans un dépôt de config

Le dépôt de configuration (ex. `vps/zones/575.be/a/`) référence l'image publiée :

```yaml
# docker-compose.yml
services:
  squilladns:
    image: ghcr.io/fte/squilladns:latest
    ports:
      - "8085:8085"
    environment:
      - API_TOKEN=${API_TOKEN}
    restart: unless-stopped
```

## Licence

MIT
