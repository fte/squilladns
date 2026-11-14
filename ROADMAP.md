# Roadmap SquillaDNS

## Vision

SquillaDNS a pour objectif de devenir un service DNS léger et fiable pour gérer des zones BIND9 via API. Le projet part d'une base technique fonctionnelle en Rust et vise progressivement vers une plateforme plus sûre, plus multi-tenant, plus observable et plus proche d'un usage réel en production.

## État actuel

Version actuelle : `0.1.0`

Implémenté :

- API HTTP en Rust avec `axum`
- Génération de fichiers de zone BIND9
- Support de plusieurs types d'enregistrements
- Calcul de serial BIND9
- Authentification Bearer par token partagé (`API_TOKEN` / `API_TOKEN_PATH`)
- Validation des payloads DNS et contrôle final des fichiers avec `named-checkzone`
- Documentation OpenAPI / Swagger
- Conteneurisation Docker / Docker Compose

À compléter avant la version 1.0 :

- persistance réelle des zones par utilisateur / namespace
- extension de la validation aux cas DNS avancés et couverture de tests supplémentaire
- gestion des suppressions, collisions, ACLs et permissions
- intégration DNS réelle avec BIND9 ou service de résolution
- observabilité, logs structurés, métriques, alerting
- sécurité / hardening de production

## Roadmap des livraisons

### Phase 1 — Fondations stables (terminée / en cours)

Objectif : poser le socle fonctionnel et documenté du produit.

Livrables :

- service HTTP démarrable en conteneur
- génération de zone par payload JSON
- types d'enregistrements core
- serial BIND9 automatique
- authentification Bearer par token API
- validation DNS des types d'enregistrements pris en charge
- docs Swagger

### Phase 2 — Multi-tenancy et persistance

Objectif : faire passer l'API d'un prototype de génération de fichiers à un service exploitable par plusieurs utilisateurs ou namespaces.

À livrer :

- stockage des zones par namespace public / utilisateur
- isolation des données entre comptes
- récupération/lecture des zones existantes
- gestion de fichiers de zone dans un arborescence durable
- validation des appels et des payloads

### Phase 3 — Intégration DNS / runtime opérateur

Objectif : rendre le service vraiment utile en environnement DNS.

À livrer :

- intégration avec BIND9 ou un runtime DNS compatible
- reload/notify automatique lors de modifications de zones
- contrôle fin sur les fichiers générés
- support de zones dynamiques et de sous-domaines
- tests de cohérence sur les fichiers générés

### Phase 4 — Production hardening

Objectif : sécuriser le service pour un usage réel dans un environnement partagé.

À livrer :

- validation stricte de tous les enregistrements
- gestion des erreurs avec codes HTTP explicites
- journaux structurés et corrélation de traces
- métriques `/metrics` et intégration Prometheus
- limites de taux et protections contre abus
- politique de secrets et clés API sécurisées

### Phase 5 — Opérations et qualité

Objectif : transformer l'outil en composant fiable et maintenable.

À livrer :

- CI/CD Rust avec tests automatisés
- lint et format
- tests de non-régression sur les formats de zone
- back-ups de zones et restauration
- procédures de déploiement et de rollback

## Priorités de développement

1. Clarifier la persistance des zones et le modèle de données
2. Sécuriser l'API avant tout usage partagé
3. Ajouter les contrôles de validation DNS
4. Connecter le service à un runtime DNS réel
5. Mettre en place les métriques et alertes

## Feuille de route indicative

| Période | Cible | Niveau |
|---------|-------|--------|
| 0.1.x | Stabiliser base API + docs | Actuel |
| 0.2.x | Multi-tenancy + persistance | Next |
| 0.3.x | Intégration BIND9 + reloads | À venir |
| 0.4.x | Hardening + observabilité | À venir |
| 1.0 | Production-ready | Objectif final |

## Hypothèses de conception

- Le service reste léger et centralisé, sans dépendre d'une base de données lourde au départ
- L'API reste facile à déployer dans un environnement Docker ou VM
- La génération de zones doit rester lisible, explicite et testable
- Le système doit évoluer vers un modèle multi-utilisateur sans réécrire complètement le cœur

## Notes

La roadmap ci-dessus est volontairement pragmatique : elle ne décrit pas un produit fini, mais la route la plus logique pour faire passer SquillaDNS d'un prototype technique à un composant DNS utilisable en équipe ou en environnement de production légère.
