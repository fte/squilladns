# Installation et exploitation

## Prérequis

- Docker Compose v2, ou Rust 1.70+ pour l’exécution locale.
- Port 8085 disponible.
- Un volume persistant pour les zones et l’état des tokens.

L’image inclut `named-checkzone` et `rndc`. La publication utilise les zones
dynamiques BIND (`rndc addzone`/`delzone`) : activez `allow-new-zones yes` dans
`named.conf`, donnez à BIND un stockage persistant pour son fichier `.nzf`/`.nzd`
et montez `ZONES_DIR` au même chemin absolu dans l’API et dans BIND. Les noms
DNS sont globaux : le premier tenant qui crée une zone en devient propriétaire.

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| API_ADDR | 0.0.0.0:8085 | Adresse d’écoute |
| API_TOKEN | vide | Token bootstrap ; vide = génération au démarrage |
| API_TOKEN_PATH | /var/lib/squilladns/state/tokens dans l’image | Stockage des tokens, permissions 0600 |
| ZONES_DIR | /var/lib/squilladns/zones dans l’image | Racine des fichiers de zones |
| MAX_REQUEST_BODY_BYTES | 1048576 | Taille maximale du corps HTTP accepté (1 Mio) |
| MAX_RECORDS_PER_ZONE | 10000 | Nombre maximal de RR dans un payload de zone |
| MAX_RECORD_NAME_BYTES | 253 | Longueur maximale du nom propriétaire d’un RR, en octets |
| MAX_RECORD_VALUE_BYTES | 4096 | Longueur maximale de la valeur d’un RR, en octets |
| MAX_PARALLEL_VALIDATIONS | 4 | Nombre maximal de validations/sérialisations CPU simultanées |
| MAX_PARALLEL_IO | 4 | Nombre maximal d’opérations disque et processus BIND simultanés |
| RNDC_BIN | rndc | Chemin ou nom de l’exécutable `rndc` |
| RNDC_CONF | vide | Fichier `rndc.conf` optionnel; monter en lecture seule avec mode 0600 |
| RNDC_TIMEOUT_SECS | 5 | Délai maximal d’un appel `rndc` (1 à 60 secondes) |
| CHECKZONE_TIMEOUT_SECS | 5 | Délai maximal de `named-checkzone` (1 à 60 secondes) |
| JWT_SECRET | vide | Secret HS256 historique, minimum 32 octets |
| JWT_ED25519_PUBLIC_KEY | vide | Clé publique Ed25519 BFF en base64url (32 octets) ; prioritaire sur JWT_SECRET |
| BFF_API_AUDIENCE | squilladns | Audience attendue dans le JWT signé par le BFF |
| CORS_ALLOWED_ORIGINS | * | Origines séparées par des virgules ; null autorise file:// |
| SANDBOX_USER | vide | Identité de développement, auth désactivée |
| RUST_LOG | info | Filtre tracing ; inclut les logs d'accès HTTP |

Sans API_TOKEN, le secret généré est écrit dans API_TOKEN_PATH et affiché une
fois dans les logs. Le fichier contient les credentials en clair ; protège le
volume et les logs.

Le répertoire `.bind-owners` sous `ZONES_DIR` conserve les propriétaires des
noms entre redémarrages. Ne le supprimez pas séparément des zones. Un échec
`rndc` laisse la zone persistée mais inactive ; renvoyez PUT ou POST `/sync`
pour réessayer.

Les réponses PUT/SYNC exposent `activation_error` lorsque BIND n’a pas confirmé
la publication, avec un code stable tel que `rndc_timeout` ou
`publication_capacity_exhausted`. `Server-Timing` détaille la validation,
l’attente du verrou, le filesystem, `named-checkzone`, la file de publication,
`rndc` et la taille/count du payload. Les logs d’accès incluent le
`X-Request-ID`; les en-têtes Server-Timing sont exposés en CORS.

## Docker Compose

~~~sh
export API_TOKEN="$(openssl rand -hex 32)" # recommandé pour un déploiement stable
docker compose up --build -d
curl -fsS http://127.0.0.1:8085/health
docker compose logs
~~~

Compose et `make up` persistent zones et tokens sous
`./var/lib/squilladns/{zones,state}` par défaut. Sur le VPS, définissez
`DATA_DIR=/var/lib/squilladns` pour conserver les données dans le chemin système
usuel. Créez les deux répertoires avec des droits adaptés à l’UID/GID utilisés
par le conteneur. Si BIND tourne sur l’hôte, il doit aussi accéder au répertoire
des zones ; configurez un groupe partagé. Pour `rndc`, placez éventuellement le
fichier de configuration dans `state/rndc.conf` et réglez
`RNDC_CONF=/var/lib/squilladns/state/rndc.conf`. Omettre API_TOKEN est possible :
le fichier d’état conserve le token généré entre les redémarrages.

Opérations usuelles :

~~~sh
docker compose logs -f
docker compose restart
docker compose down
~~~

## Exécution locale

~~~sh
export API_TOKEN="$(openssl rand -hex 32)"
export ZONES_DIR=./var/lib/squilladns/zones
cargo run --release
~~~

Le mode sandbox est réservé au développement local :

~~~sh
SANDBOX_USER=alice cargo run
~~~

### Développement local avec BIND 9

`make dev-up` démarre l’API et BIND 9 dans le même conteneur Debian Trixie.
Les chemins sont ceux de l’installation de production : zones et tokens sous
`/var/lib/squilladns`, configuration BIND sous `/etc/bind` et état dynamique
BIND sous `/var/cache/bind`. Les données sont conservées côté hôte dans
`DATA_DIR` (par défaut `./var/lib/squilladns`).

~~~sh
make dev-up
make shell
# Dans le shell :
rndc -c /etc/bind/squilladns-rndc.conf status
dig @127.0.0.1 example.test A +norecurse
# Depuis l’hôte, DNS est exposé sur 127.0.0.1:1053 :
dig @127.0.0.1 -p 1053 example.test A +norecurse
~~~

L’interface cliente locale peut appeler l’API sur `http://localhost:8085`.
`make dev-logs`, `make dev-ps` et `make dev-down` pilotent ce conteneur. Le
secret RNDC de cette image est réservé au développement ; l’image production
ne contient pas le serveur `named`.

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

Le test E2E opt-in `SPEC-AC-08` démarre une instance BIND isolée, vérifie la
création, la mise à jour, la persistance après redémarrage et la suppression
d’une zone via l’API. Il nécessite `named` et `rndc` disponibles dans le
`PATH` ; `BIND_NAMED_BIN` et `BIND_RNDC_BIN` permettent d’indiquer leurs chemins.
Lancer avec :

~~~sh
cargo test --test bind_e2e -- --ignored --nocapture
~~~

Avec le moteur de conteneurs détecté par Makefile (Apple Container prioritaire,
Docker Compose sinon), lancer `make test-bind-e2e`. La cible construit une image
de test séparée basée sur Debian Trixie avec BIND 9.

En production, limite l’accès réseau à l’API, utilise un secret manager et
monte des volumes persistants. Restreins CORS aux origines réellement utilisées.
