# Roadmap

## État

MVP 0.1.x : API, génération de zones BIND9, stockage fichier, séparation public /
tenant, JWT HS256, tokens API, OpenAPI. named-checkzone est conditionnel ;
rndc reload est une intégration optionnelle. Les zones sont persistées sur disque,
sans base de données.

## À faire

### Priorité 1 — Runtime DNS

- Définir le contrat d’exploitation BIND9 : zones déclarées, reload/notify,
  erreurs et état de propagation.
- Couvrir l’intégration par tests avec un named réel ; préciser les limites
  actuelles du reload opportuniste.

### Priorité 2 — Exploitation

- Sauvegarde et restauration des zones, avec procédures de rollback.
- CI : tests, formatage, lint et publication reproductible.
- Métriques et alertes ; Server-Timing et request ID existent déjà.

### Priorité 3 — Sécurité multi-tenant

- ACL par zone, limites de débit et politique de révocation des tokens.
- Revue de sécurité de la configuration CORS, des secrets et des permissions.
- Étendre les tests de validation DNS et les cas de concurrence sur les fichiers.

## Hors périmètre actuel

Base SQL, gestion complète du plan de contrôle BIND9 et disponibilité multi-instance.
