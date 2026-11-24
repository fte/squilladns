# Installation et exploitation

## Prérequis

- Docker Compose v2, ou Rust 1.70+ pour l’exécution locale.
- Port 8085 disponible.
- Un volume persistant pour les zones et l’état des tokens.

L’image inclut named-checkzone. rndc n’est actif que si l’environnement le
configure ; l’API ne remplace pas la déclaration des zones dans named.conf.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| API_ADDR | 0.0.0.0:8085 | Adresse d’écoute |
| API_TOKEN | vide | Token bootstrap ; vide = génération au démarrage |
| API_TOKEN_PATH | .state/tokens | Stockage local des tokens, permissions 0600 |
| ZONES_DIR | zones/example.invalid | Racine des fichiers de zones |
| MAX_REQUEST_BODY_BYTES | 1048576 | Taille maximale du corps HTTP accepté (1 Mio) |
| MAX_RECORDS_PER_ZONE | 10000 | Nombre maximal de RR dans un payload de zone |
| MAX_RECORD_NAME_BYTES | 253 | Longueur maximale du nom propriétaire d’un RR, en octets |
| MAX_RECORD_VALUE_BYTES | 4096 | Longueur maximale de la valeur d’un RR, en octets |
| MAX_PARALLEL_VALIDATIONS | 4 | Nombre maximal de parsing/validations de zones simultanés |
| JWT_SECRET | vide | Secret HS256 historique, minimum 32 octets |
| JWT_ED25519_PUBLIC_KEY | vide | Clé publique Ed25519 BFF en base64url (32 octets) ; prioritaire sur JWT_SECRET |
| BFF_API_AUDIENCE | squilladns | Audience attendue dans le JWT signé par le BFF |
| CORS_ALLOWED_ORIGINS | * | Origines séparées par des virgules ; null autorise file:// |
| SANDBOX_USER | vide | Identité de développement, auth désactivée |
| RUST_LOG | info | Filtre tracing ; inclut les logs d'accès HTTP |

Sans API_TOKEN, le secret généré est écrit dans API_TOKEN_PATH et affiché une
fois dans les logs. Le fichier contient les credentials en clair ; protège le
volume et les logs.

## Docker Compose

~~~sh
export API_TOKEN="$(openssl rand -hex 32)" # recommandé pour un déploiement stable
docker compose up --build -d
curl -fsS http://127.0.0.1:8085/health
docker compose logs
~~~

Compose persiste zones et tokens via ./zones et ./.state. Omettre API_TOKEN
est possible : le fichier d’état conserve le token généré entre les redémarrages.

Opérations usuelles :

~~~sh
docker compose logs -f
docker compose restart
docker compose down
~~~

## Exécution locale

~~~sh
export API_TOKEN="$(openssl rand -hex 32)"
export ZONES_DIR=./zones/example.invalid
cargo run --release
~~~

Le mode sandbox est réservé au développement local :

~~~sh
SANDBOX_USER=alice cargo run
~~~

## Authentification

Le flux SSO et les claims JWT sont spécifiés dans [AUTH.md](AUTH.md).
Pour un appel script, utiliser un token API dans Authorization: Bearer <token>.
Une authentification absente ouvre le scope public ; un credential invalide
renvoie 401.

## Stockage et migration

Les zones sont écrites sous ZONES_DIR/public ou ZONES_DIR/tenants/<id-interne>.
L’identifiant interne n’est pas exposé par l’API. Les anciens répertoires de
tenant hashés sont déplacés au premier appel JWT. Les répertoires user-* de
versions antérieures nécessitent une migration manuelle.

Le fichier API_TOKEN_PATH accepte les anciens formats et les migre au chargement.

## Vérification

- Santé : GET http://127.0.0.1:8085/health
- Swagger : http://127.0.0.1:8085/docs
- Cibles Makefile : voir make help ; certaines opérations nécessitent Docker.

En production, limite l’accès réseau à l’API, utilise un secret manager et
monte des volumes persistants. Restreins CORS aux origines réellement utilisées.
