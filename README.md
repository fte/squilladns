# SquillaDNS

API Rust pour gérer des zones BIND9 via HTTP. État du projet : MVP 0.1.x.

- [Installation et configuration](INSTALL.md)
- [Contrat SSO et tokens](AUTH.md)
- [Travail restant](ROADMAP.md)
- OpenAPI / Swagger : /docs

## Contrat fonctionnel

- Zones stockées en fichiers sous ZONES_DIR, séparées en public et tenants.
- PUT /zones/{name} remplace une zone ; DELETE la supprime ; GET /zones la liste.
- SOA généré automatiquement ; NS apex ajouté si absent.
- Types acceptés : A, AAAA, CNAME, MX, NS, TXT, SRV, CAA.
- Serial : max(serial existant + 1, date UTC).
- named-checkzone et rndc sont utilisés lorsqu’ils sont disponibles.
- Écriture restaurée si la validation finale échoue.
- Un bearer invalide renvoie 401 ; il ne bascule jamais vers le scope public.
- JWT EdDSA du BFF (HS256 historique) ou token API ; POST /token émet un token lié au même tenant.
  Le client reçoit le slug, jamais l’identifiant interne.

## Routes

| Méthode | Route | Auth | Résultat |
|---|---|---|---|
| GET | /health | — | État et mode d’auth |
| GET | /auth/me | Optionnelle | Slug, fournisseur, scope |
| GET | /zones | Optionnelle | Zones du scope |
| PUT | /zones/{name} | Optionnelle | Création ou remplacement |
| DELETE | /zones/{name} | Optionnelle | Suppression |
| POST | /sync?zone={name} | Optionnelle | Écriture et/ou reload |
| POST | /token | Requise | Token API et slug |
| GET | /docs | — | Swagger UI |

Les routes d’écriture reçoivent un objet JSON avec records :

~~~json
{
  "records": [
    {"type": "A", "name": "@", "value": "192.0.2.10"},
    {"type": "TXT", "name": "@", "value": "v=spf1 -all"}
  ]
}
~~~

POST /sync accepte ce body pour écrire la zone, ou seulement zone en query
pour recharger une zone existante.

## Démarrage

~~~sh
export API_TOKEN="$(openssl rand -hex 32)"
docker compose up --build -d
curl -fsS http://127.0.0.1:8085/health
~~~

Si API_TOKEN est omis, l’API en génère un, le journalise au démarrage et le
conserve dans .state/tokens. Voir [INSTALL.md](INSTALL.md) pour les volumes,
variables d’environnement et le déploiement.

## Implémentation

Rust, axum/tokio, Hickory, serde, utoipa. Les réponses exposent Server-Timing,
X-Response-Time et X-Request-Id. Les choix d’exploitation et les écarts connus
sont dans [ROADMAP.md](ROADMAP.md).
