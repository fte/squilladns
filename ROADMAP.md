# Roadmap

## État

MVP 0.1.x : API, génération de zones BIND9, stockage fichier, séparation public /
tenant, JWT HS256, tokens API, OpenAPI. named-checkzone est conditionnel ;
rndc reload est une intégration optionnelle. Les zones sont persistées sur disque,
sans base de données.

La spécification du runtime, des limites, de la validation RR et de la
publication BIND est dans [SPEC-runtime-validation.md](SPEC-runtime-validation.md).
Les limites d’entrée, la validation et sérialisation RR typées, le remplacement
complet des RR, les verrous par zone et le remplacement atomique des fichiers
sont implémentés. La validation `named-checkzone` reste postérieure à l’écriture ;
la publication après validation préalable est encore à faire.

## À faire

### Priorité 1 — Runtime DNS

Ordre d’implémentation proposé ; les identifiants renvoient à
[SPEC-runtime-validation.md](SPEC-runtime-validation.md) :

1. **Décisions préalables** — `SPEC-DEC-01..05` : valeurs par défaut des
   limites, catalogue et format des RR, validation Hickory, source de vérité
   BIND et contrat HTTP de publication.
2. **Bornes et sécurité RR** — `SPEC-IN-01..04` et `SPEC-RR-01..05` terminées :
   plafonds, validation et sérialisation typées, catalogue explicite,
   protection contre l’injection et conflits CNAME. `named-checkzone` reste le
   contrôle final de cohérence avec BIND.
3. **Intégrité des écritures** — `SPEC-IO-04` terminé : verrou par tenant/zone
   partagé par PUT, sync et DELETE ; remplacement du fichier par renommage
   atomique. À faire : valider le fichier temporaire avec `named-checkzone`
   avant publication et définir complètement les échecs (`SPEC-WRITE-*`).
4. **Travail bloquant et quotas** — `SPEC-IO-01..03`, `SPEC-IO-05..06`,
   `SPEC-OBS-02` : filesystem, calcul et processus hors des workers HTTP, avec
   concurrence bornée.
5. **Publication BIND** — `SPEC-BIND-*` : création, modification, suppression,
   reload, délais et état `persisted`/`active`, puis coalescence des reloads.
6. **Listing et observabilité** — `SPEC-LIST-*`, `SPEC-OBS-*` : pagination ou
   index selon le besoin, timings, erreurs et métriques.
7. **Vérification** — `SPEC-T-*`, `SPEC-AC-*` : tests unitaires et de
   concurrence, puis tests d’intégration contre un BIND réel.

Branche suggérée pour le chantier complet : `feat/runtime-hardening`. Pour des
changements plus petits et relisibles, séparer en `feat/rr-validation`,
`feat/atomic-zone-writes`, puis `feat/bind-publisher`.

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
