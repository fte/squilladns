# Authentification

## Modèle

L’API ne contacte pas les fournisseurs SSO. Le BFF valide le retour OAuth/OIDC,
normalise l’identité et signe un JWT HS256 avec JWT_SECRET. L’API vérifie la
signature, exp, aud et les claims requis.

Flux :

1. L’utilisateur s’authentifie chez GitHub, Google ou un autre fournisseur.
2. Le BFF émet le JWT SquillaDNS.
3. Le BFF appelle POST /token avec Authorization: Bearer <jwt>.
4. L’API renvoie {created, token, slug}. Le client utilise ce token API pour
   les appels suivants.

Le JWT reste côté BFF dans le flux recommandé. Le token API est rattaché au
même tenant et donne accès aux mêmes zones. Le slug est un identifiant public
pour l’interface ; l’autorisation dépend du bearer, pas du slug.

## Claims JWT

~~~json
{
  "iss": "github",
  "sub": "583231",
  "preferred_username": "octocat",
  "email": "octocat@example.com",
  "aud": "squilladns",
  "exp": 1800000000
}
~~~

| Claim | Requis | Contrat |
|---|---|---|
| iss | Non | Identifiant du fournisseur ; à renseigner pour isoler plusieurs SSO |
| sub | Oui | Identifiant stable du compte chez ce fournisseur, 1–128 caractères |
| preferred_username | Oui | Login lisible, normalisé en slug |
| aud | Oui | squilladns |
| exp | Oui | Timestamp Unix ; tolérance d’horloge de 60 secondes |
| email | Non | Donnée de profil renvoyée par /auth/me |

Le BFF adapte les claims propres à chaque fournisseur à ce contrat commun.
Exemples : ID numérique + login pour GitHub ; sub + nom d’utilisateur ou email
normalisé pour Google ; subject stable + login pour tout autre SSO. L’API ne
contient pas de code spécifique à un fournisseur.

JWT_SECRET doit faire au moins 32 octets et être identique côté BFF et API.
L’API accepte uniquement HS256, rejette les JWT incomplets et ne retombe jamais
en mode anonyme après une erreur d’auth. Le BFF est responsable de valider
l’identité fournie par le fournisseur avant de signer.

## Échange et appels API

~~~sh
curl -X POST http://127.0.0.1:8085/token \
  -H "Authorization: Bearer <jwt-sso>"

# Réponse : {"created":true,"token":"sqi_…","slug":"octocat"}

curl http://127.0.0.1:8085/zones \
  -H "Authorization: Bearer <token-api>"
~~~

GET /auth/me renvoie authenticated, slug, email, provider et scope. L’identifiant
interne est conservé côté API ; les fichiers de zones sont rangés par tenant.

Le token bootstrap API_TOKEN a son propre tenant. Les tokens créés par POST
/token héritent du tenant de l’appelant et ne révoquent pas les précédents.
Le fichier API_TOKEN_PATH persiste les tokens avec permissions Unix 0600.

## Erreurs

Les erreurs d’authentification sont des réponses 401 problem+json. Le client
traite le suffixe du champ type.

| Code | Cause |
|---|---|
| auth_required | Route protégée sans bearer |
| auth_invalid_token | Token inconnu, signature ou claims invalides |
| auth_expired | exp dépassé |

Sur 401, le client supprime le token et relance le parcours SSO. Ne boucle pas
sur une nouvelle tentative.

## Développement

SANDBOX_USER=alice court-circuite l’authentification pour l’utilisateur alice.
Ne l’active pas sur une instance exposée. Voir [INSTALL.md](INSTALL.md) pour
CORS et configuration d’exécution.
