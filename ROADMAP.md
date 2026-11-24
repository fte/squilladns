# Roadmap

## État

MVP 0.1.x : API, génération de zones BIND9, stockage fichier, séparation public /
tenant, JWT HS256, tokens API, OpenAPI. Les zones sont persistées sur disque,
sans base de données ; BIND reçoit les zones dynamiques via `rndc`.

La spécification du runtime, des limites, de la validation RR et de la
publication BIND est dans [SPEC-runtime-validation.md](SPEC-runtime-validation.md).
Les limites d’entrée, la validation RR typée, les verrous par zone, les quotas
bornés I/O/CPU, la validation temporaire, et la publication dynamique BIND avec
propriété globale des noms sont implémentés.

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
   partagé par PUT, sync et DELETE ; remplacement atomique du fichier. `SPEC-WRITE-06..09`
   terminées : vérification `named-checkzone` sur le temporaire avant publication,
   nettoyage en cas d’échec et résultats de persistance/activation distincts.
4. **Travail bloquant et quotas** — `SPEC-IO-01..06` et `SPEC-OBS-02`
   terminées. Les tests couvrent le rejet à saturation, la libération des
   quotas et la conservation des permis quand une requête est annulée.
5. **Publication BIND** — `SPEC-BIND-01..08` implémentées sur
   `feat/bind-publisher` : zones dynamiques, réservation du nom au premier
   tenant, activation/suppression bornées et coalescence des publications.
6. **Listing et observabilité** — `SPEC-LIST-01` et `04` terminées sur
   `feat/list-zone-pagination` : listing sans lecture des fichiers de zone,
   pagination par offset, limite par page. `SPEC-LIST-02..03` restent
   conditionnelles à un besoin d’index ; `SPEC-OBS-01`, `03..05` restent à faire.
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
