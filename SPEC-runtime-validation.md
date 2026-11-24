# Spécification — runtime, validation DNS et publication

Statut : spécification approuvée ; l’avancement ci-dessous distingue les exigences
implémentées de celles qui restent à faire.

Avancement : `SPEC-IN-01..04`, `SPEC-RR-01..05`, `SPEC-IO-01..06` et
`SPEC-OBS-02` sont terminées. `SPEC-WRITE-06..09` sont également terminées :
la validation BIND porte sur un fichier temporaire, et la réponse expose
séparément la persistance et l’activation. Les opérations disque/processus passent par un
pool bloquant borné via `MAX_PARALLEL_IO`; parsing, validation, sérialisation
de zone et `named-checkzone` prennent aussi le quota CPU
`MAX_PARALLEL_VALIDATIONS`.

## Objectifs

- **SPEC-OBJ-01** Garder les workers Tokio disponibles pendant les accès disque, les validations
  lentes et les appels aux outils BIND.
- **SPEC-OBJ-02** Borner les ressources CPU, mémoire, disque et processus consommées par une
  requête, y compris lorsque plusieurs requêtes arrivent en même temps.
- **SPEC-OBJ-03** Rejeter les RR invalides ou ambigus avant publication et empêcher toute
  injection de syntaxe dans les fichiers de zone ou la configuration BIND.
- **SPEC-OBJ-04** Garantir que le contenu servi par BIND correspond à une version validée et
  complète de la zone.
- **SPEC-OBJ-05** Isoler les opérations par tenant et ne jamais accepter l’identifiant interne
  du tenant ou un chemin de fichier fourni par le client.

## Hors périmètre

- Remplacer le stockage fichier par une base de données.
- Construire un plan de contrôle BIND multi-instance ou haute disponibilité.
- Promettre une propagation DNS instantanée ou une disponibilité du serveur DNS
  à partir du seul succès de l’API.

## Contrat d’entrée et limites

1. **SPEC-IN-01 [x]** Les routes qui acceptent un payload de zone appliquent une limite explicite
   de taille du corps HTTP et renvoient `413 Payload Too Large` en cas de
   dépassement. La limite est configurable au démarrage, avec un défaut
   documenté et raisonnable pour une API de gestion.
2. **SPEC-IN-02 [x]** La validation impose également des maxima configurables pour le nombre de
   RR par zone, la longueur des noms, et la longueur des champs textuels. Le
   rejet est une erreur client structurée, sans écriture partielle.
3. **SPEC-IN-03 [x]** Le parse JSON et la validation ne doivent pas traiter un contenu non borné.
   Le nombre de validations concurrentes est limité.
4. **SPEC-IN-04 [x]** Les opérations de remplacement demeurent explicites : un payload complet
   remplace la zone. Une modification incrémentale n’est pas implicite.

## Contrat RR et validation

1. **SPEC-RR-01 [x]** Chaque RR est validé selon son type. Les noms sont parsés comme noms DNS ;
   les adresses IP comme adresses IP ; les champs structurés (MX, SRV, CAA,
   etc.) ont un schéma dédié.
2. **SPEC-RR-02 [x]** Aucun champ client ne peut injecter une ligne, un commentaire ou une
   directive de zone. Les caractères de contrôle et séparateurs dangereux sont
   rejetés ou échappés selon les règles de présentation DNS du type concerné.
   Les RR sont sérialisés depuis une représentation typée, jamais par
   interpolation de chaînes brutes non validées.
3. **SPEC-RR-03 [x]** Le catalogue de types RR accepté est explicite et documenté. Les types
   inconnus sont refusés par défaut ; un éventuel support RFC 3597 devra être
   une décision explicite, avec validation dédiée.
4. **SPEC-RR-04 [x]** La validation inclut les contraintes entre RR et celles de zone nécessaires
   à la publication, notamment les conflits CNAME et la présence/cohérence des
   enregistrements SOA et NS requis. `named-checkzone` reste le contrôle final
   de compatibilité avec la version de BIND déployée.
5. **SPEC-RR-05 [x]** La normalisation (casse des types, noms absolus/relatifs, valeurs) est
   effectuée une fois à l’entrée. Toute donnée acceptée doit être présente dans
   le fichier généré ou la requête doit échouer.

### Bibliothèques

- Évaluer et réutiliser `hickory-proto` pour les types `Name`, `RData` et le
  parsing des fichiers de zone, après vérification des types RR couverts et de
  la compatibilité avec la version déjà déclarée dans `Cargo.toml`.
- Ne pas ajouter `hickory-server` ou `hickory-client` au seul motif qu’ils sont
  dans le manifeste : le choix du parseur/encodeur doit justifier chaque
  dépendance retenue.
- Le parseur Hickory ne remplace pas `named-checkzone` en production tant que
  BIND est l’autorité de publication. Les deux contrôles ont des rôles
  distincts : validation structurée de l’entrée, puis validation par le serveur
  effectivement utilisé.
- Toute bibliothèque alternative doit être comparée sur la couverture des RR,
  le traitement des noms IDNA/échappés, les règles de zone, la maintenance et la
  capacité à sérialiser sans injection ; aucune nouvelle dépendance n’est
  présumée nécessaire.

## I/O, CPU et concurrence

1. **SPEC-IO-01 [x]** Aucun appel bloquant au filesystem ou à un processus système ne s’exécute
   directement sur un worker Tokio.
2. **SPEC-IO-02 [x]** Les opérations filesystem d’une requête sont regroupées en une unité de
   travail bornée. Elles utilisent `tokio::fs` ou `spawn_blocking` selon le
   besoin ; la sélection ne doit pas créer une tâche bloquante par petit appel
   sans limite de concurrence.
3. **SPEC-IO-03 [x]** Les tâches CPU lourdes (décodage de grands payloads, validation et
   sérialisation) sont bornées séparément du nombre de connexions HTTP.
4. **SPEC-IO-04 [x]** L’accès à une même zone est sérialisé par la clé interne `(tenant, zone)`.
   Des zones distinctes peuvent être traitées en parallèle dans une limite
   globale configurable.
5. **SPEC-IO-05 [x]** La limite de concurrence s’applique aussi aux listings, suppressions
   récursives et validations BIND. Une saturation donne lieu à une attente
   bornée ou une réponse de surcharge documentée, jamais à une croissance
   mémoire non bornée.
6. **SPEC-IO-06 [x]** Les accès au store de tokens et aux métriques ne doivent pas garder un
   verrou partagé pendant une opération disque ou un appel externe.

## Écriture, validation finale et rollback

Pour un remplacement, l’ordre logique est :

1. **SPEC-WRITE-01** Authentifier et résoudre le tenant depuis le credential.
2. **SPEC-WRITE-02** Normaliser et valider complètement le payload et ses limites.
3. **SPEC-WRITE-03** Acquérir le verrou de zone.
4. **SPEC-WRITE-04** Lire le serial courant et construire le nouveau serial.
5. **SPEC-WRITE-05** Générer un fichier temporaire dans le même filesystem que le fichier cible.
6. **SPEC-WRITE-06 [x]** Lancer `named-checkzone` sur le temporaire avec délai maximal et limites de
   sortie (5 secondes ; stdout/stderr redirigés, aucune sortie capturée). Un
   timeout renvoie `503 Service Unavailable`.
7. **SPEC-WRITE-07 [x]** En cas d’échec, supprimer le temporaire et garder l’ancienne zone intacte.
8. **SPEC-WRITE-08 [x]** En cas de succès, publier par renommage atomique, puis libérer le verrou une
   fois l’état disque cohérent.
9. **SPEC-WRITE-09 [x]** Demander la publication/relecture à BIND et retourner distinctement le
   résultat `persisted` et le résultat `active` (absent si aucun reload n’a été demandé).

**SPEC-WRITE-10** Les erreurs de validation et de disque ne doivent jamais exposer des chemins
absolus, secrets ou détails de configuration interne. Un échec de validation ne
doit pas réécrire l’ancienne zone : elle n’a pas été remplacée.

## Intégration BIND et `rndc`

1. **SPEC-BIND-01 [x]** `rndc` est un transport de contrôle ; il ne définit ni l’isolation par
   tenant ni la source de vérité des zones.
2. **SPEC-BIND-02 [x]** L’API résout elle-même le chemin de zone depuis la racine configurée,
   l’identifiant opaque du tenant et le nom DNS validé. Le client ne fournit
   jamais un chemin.
3. **SPEC-BIND-03 [x]** Une zone doit être déclarée dans BIND avant qu’un simple `rndc reload
   <zone>` puisse la recharger. Le déploiement choisit et documente une seule
   source de vérité :
   - configuration générée/revue par un composant dédié puis `rndc reconfig` ;
   - ou zones dynamiques avec `rndc addzone`/`delzone`, `allow-new-zones` et
     persistance BIND configurés explicitement.
4. **SPEC-BIND-04 [x]** La commande est lancée sans shell, avec exécutable contrôlé, arguments
   validés, durée maximale, sorties bornées, et nombre d’appels concurrents
   limité. Tout texte de configuration est construit depuis des valeurs
   validées et correctement échappées.
5. **SPEC-BIND-05 [x]** La configuration de contrôle `rndc` et son secret sont montés/configurés
   avec permissions minimales ; ils ne sont jamais renvoyés par l’API ou ses
   logs.
6. **SPEC-BIND-06 [x]** La création, modification et suppression doivent toutes mettre à jour
   l’état actif BIND. Une suppression retire d’abord la zone du service DNS
   (selon le mécanisme retenu), puis supprime les fichiers sous le verrou. Avant
   une activation, l’état durable est marqué `activating`; il ne devient `active`
   qu’après confirmation de `rndc`. Une suppression traite `activating` comme un
   état potentiellement actif et demande `delzone` avant d’effacer les fichiers.
7. **SPEC-BIND-07 [x]** Les modifications rapprochées peuvent être regroupées dans une file de
   publication. Le coalescing ne doit pas perdre la dernière version d’une zone
   ni annoncer une zone active avant confirmation de BIND.
8. **SPEC-BIND-08 [x]** La réponse API distingue au minimum `persisted` et `active` (ou une
   représentation équivalente). Un échec `rndc` après persistance est
   observable et réessayable ; il ne provoque pas un rollback disque implicite
   qui ferait diverger l’état servi.

Décision retenue : BIND global, noms DNS uniques. Le premier tenant qui réserve
un nom le possède durablement ; les PUT, sync et DELETE des autres tenants
reçoivent un conflit. Les zones sont ajoutées/supprimées avec `rndc addzone` et
`rndc delzone`; `allow-new-zones yes` et la persistance `.nzf`/`.nzd` sont
requises au déploiement.

## Listing et index

- **SPEC-LIST-01 [x]** Le listing ne lit pas les contenus de zone pour obtenir les noms ; le serial n’est pas chargé lors du listing.
- **SPEC-LIST-02** Si le coût de parcours disque devient important, maintenir un index dérivé
  reconstruisible à partir des fichiers. Les fichiers validés restent la
  source de vérité, sauf décision future de migration.
- **SPEC-LIST-03** L’index est isolé par tenant, cohérent après redémarrage et mis à jour sous
  les mêmes règles de sérialisation que les écritures.
- **SPEC-LIST-04 [x]** Une pagination et un plafond de résultats sont requis avant que le nombre de
  zones par tenant puisse croître sans borne.

## Exploitabilité et observabilité

- **SPEC-OBS-01** Délai maximal distinct pour validation BIND et contrôle `rndc`.
- **SPEC-OBS-02 [x]** Concurrence maximale configurable pour I/O, CPU, `named-checkzone` et `rndc`.
- **SPEC-OBS-03** Métriques ou timings pour parsing/validation, attente du verrou, filesystem,
  checkzone, publication BIND et taille/count des payloads.
- **SPEC-OBS-04** Logs structurés corrélés par request ID ; aucune donnée RR sensible, token,
  secret ou chemin absolu n’est journalisé par défaut.
- **SPEC-OBS-05** Les erreurs de surcharge, timeout, échec checkzone, échec BIND et erreur
  filesystem sont distinguables par le client sans révéler l’infrastructure.

## Critères d’acceptation

- **SPEC-AC-01** Un payload dépassant chacune des limites est rejeté avant toute modification
  disque ; les réponses utilisent le contrat d’erreur HTTP documenté.
- **SPEC-AC-02** Les cas de tentative d’injection via TXT, CAA, noms et autres champs textuels
  sont rejetés ou sérialisés sans produire de RR supplémentaire.
- **SPEC-AC-03** Tout RR annoncé comme accepté apparaît exactement dans le fichier publié ;
  les RR non pris en charge sont refusés explicitement.
- **SPEC-AC-04** Des écritures parallèles sur la même zone produisent des serials cohérents,
  aucun fichier partiel et aucun rollback qui écrase une écriture réussie.
- **SPEC-AC-05** Une panne de `named-checkzone` laisse l’ancienne version intacte.
- **SPEC-AC-06** Une panne ou un timeout `rndc` est reflété comme échec d’activation tout en
  conservant un état disque cohérent et réessayable.
- **SPEC-AC-07** Un grand nombre de requêtes disque/processus ne bloque pas les routes légères
  et ne dépasse pas les limites de concurrence configurées.
- **SPEC-AC-08** Les créations et suppressions sont vérifiées contre un BIND réel : nouvelle
  zone publiée, zone modifiée avec le nouveau contenu, zone supprimée et plus
  servie, redémarrage de BIND avec état persistant.
- **SPEC-AC-09** Les opérations d’un tenant ne peuvent ni lister, modifier, supprimer ou
  publier les zones d’un autre tenant, même avec des noms et payloads malformés.

## Décisions à prendre avant l’implémentation

1. **SPEC-DEC-01** Choisir les valeurs par défaut des limites (octets, RR/zone, concurrence,
   délais) et leurs variables de configuration.
2. **SPEC-DEC-02** Choisir la source de vérité BIND : configuration générée/reconfigurée ou
   `rndc addzone`/`delzone` avec `allow-new-zones`.
3. **SPEC-DEC-03** Définir le contrat HTTP de publication partielle : réponse synchrone avec
   état `persisted`/`active`, ou ressource de travail asynchrone avec polling.
4. **SPEC-DEC-04** Définir le catalogue RR et les champs API typés, et décider si un format
   RFC 3597 opaque est nécessaire.
5. **SPEC-DEC-05** Vérifier la version Hickory retenue contre le catalogue RR requis et décider
   quelles dépendances inutilisées seront supprimées.

## Ébauche d’architecture Rust

Cette proposition est un découpage logique, pas une prescription de noms de
fichiers. Les types métier doivent rester indépendants d’Axum et des processus
externes afin d’être testables sans serveur HTTP ni BIND.

```rust
struct Limits {
    max_body_bytes: usize,
    max_records_per_zone: usize,
    max_name_bytes: usize,
    max_text_bytes: usize,
    max_parallel_validation: usize,
    max_parallel_fs: usize,
    max_parallel_checkzone: usize,
    max_parallel_rndc: usize,
    checkzone_timeout: Duration,
    rndc_timeout: Duration,
}

struct TenantId(String); // opaque, internal; never deserialized from request
struct ZoneName(hickory_proto::rr::Name); // validated, canonical form
struct ZoneKey { tenant: TenantId, zone: ZoneName }

enum TypedRData {
    A(std::net::Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Cname(hickory_proto::rr::Name),
    // Add typed variants for the explicitly supported RR catalog.
}

struct ValidatedRecord { owner: RelativeOrApexName, ttl: u32, data: TypedRData }
struct ValidatedZone { name: ZoneName, records: Vec<ValidatedRecord> }
struct PublishState { persisted: bool, active: bool, serial: u32 }

trait ZoneStore: Send + Sync {
    async fn list(&self, tenant: &TenantId, page: Page) -> Result<ZonePage, StoreError>;
    async fn read(&self, key: &ZoneKey) -> Result<Option<StoredZone>, StoreError>;
    async fn commit(&self, key: &ZoneKey, zone: &ValidatedZone)
        -> Result<StoredZone, StoreError>;
    async fn delete(&self, key: &ZoneKey) -> Result<bool, StoreError>;
}

trait ZoneValidator: Send + Sync {
    fn validate_payload(&self, input: ZonePayload, limits: &Limits)
        -> Result<ValidatedZone, Vec<ValidationIssue>>;
    async fn check_with_bind(&self, zone: &ValidatedZone, temp_file: &Path)
        -> Result<(), CheckZoneError>;
}

trait ZonePublisher: Send + Sync {
    async fn ensure_zone(&self, key: &ZoneKey, file: &Path) -> Result<(), PublishError>;
    async fn reload(&self, key: &ZoneKey) -> Result<(), PublishError>;
    async fn remove_zone(&self, key: &ZoneKey) -> Result<(), PublishError>;
}
```

Notes de conception :

- `ZoneStore` utilise soit `tokio::fs`, soit un unique `spawn_blocking` par
  transaction filesystem ; l’implémentation choisie doit respecter
  `SPEC-IO-02` et `SPEC-WRITE-03..08`.
- `ZoneValidator::validate_payload` est synchrone et pur après désérialisation ;
  l’appelant le place derrière le quota CPU (`SPEC-IN-03`, `SPEC-IO-03`).
- `ZonePublisher` encapsule `tokio::process::Command`, timeout et quotas. Le
  handler ne construit pas lui-même de ligne de commande ou de configuration.
- Un service applicatif `ZoneService` orchestre validation, verrou par zone,
  commit et publication. Les handlers Axum convertissent seulement les
  paramètres, authentification, erreurs et résultats HTTP.
- Les erreurs métier (`ValidationIssue`, `StoreError`, `CheckZoneError`,
  `PublishError`) ne contiennent pas de chemin ou secret destiné au client ; une
  couche de présentation les mappe au contrat problem-details.
- Le verrou doit être asynchrone (`tokio::sync::Mutex`) et l’entrée de la map
  de verrous doit avoir une politique de durée de vie afin d’éviter une fuite
  mémoire si le nombre de zones vues au cours de la vie du processus croît sans
  borne.

## Ébauche du plan de tests

Les tests ci-dessous sont à écrire avec l’implémentation. Les tests unitaires
utilisent des fichiers temporaires et des faux `ZonePublisher`/`ZoneValidator` ;
seuls les tests explicitement marqués BIND réel démarrent `named` et `rndc`.

| ID de test | Exigences couvertes | Scénario et résultat attendu |
|---|---|---|
| `SPEC-T-IN-LIMITS` | `SPEC-IN-01..03`, `SPEC-AC-01` | Corps juste sous la limite accepté ; au-dessus rejeté en 413 ; aucun fichier créé/modifié. Même vérification pour count RR, taille owner et champ texte. |
| `SPEC-T-VALIDATION-QUOTA` | `SPEC-IN-03`, `SPEC-IO-03`, `SPEC-AC-07` | Parsing JSON et validation s’exécutent sur le pool bloquant ; si tous les permis sont pris, le travail additionnel est rejeté immédiatement en 503 et ne s’accumule pas en file applicative. |
| `SPEC-T-RR-TYPED` | `SPEC-RR-01`, `03`, `05`, `SPEC-AC-03` | Cas valides par type, type inconnu refusé, type en casse mixte normalisé une fois ; chaque RR accepté figure exactement dans la représentation générée. |
| `SPEC-T-RR-INJECTION` | `SPEC-RR-02`, `SPEC-AC-02` | CR/LF/NUL, guillemets, antislashs, commentaires, `$INCLUDE`, CAA/TXT hostile et noms échappés ne créent jamais de RR additionnel ni de directive. |
| `SPEC-T-RR-TYPED-SERIALIZATION` | `SPEC-RR-01`, `SPEC-RR-02`, `SPEC-RR-05` | Tous les types acceptés sont convertis en variantes typées ; les valeurs TXT/CAA sont encodées en chaîne maître DNS et les noms sont échappés/canoniques avant écriture. |
| `SPEC-T-RR-SEMANTICS` | `SPEC-RR-04` | CNAME en conflit, SOA absent/dupliqué, NS apex absent et cas valides sont acceptés/rejetés selon le contrat documenté. |
| `SPEC-T-STORE-ATOMIC` | `SPEC-WRITE-05..08`, `SPEC-AC-05` | Erreur d’écriture/validation ne change pas l’ancienne zone ; après commit, le fichier est complet et le serial progresse. |
| `SPEC-T-FULL-REPLACE` | `SPEC-IN-04` | Écrire une première liste de RR puis une seconde ne laisse aucun RR de la première liste dans le fichier final. |
| `SPEC-T-SAME-ZONE-RACE` | `SPEC-IO-04`, `SPEC-AC-04` | N commits simultanés sur la même clé n’ont ni serial dupliqué ni fichier partiel ; publication finale correspond au commit ordonné final. |
| `SPEC-T-CROSS-TENANT` | `SPEC-OBJ-05`, `SPEC-BIND-02`, `SPEC-AC-09` | Même nom de zone dans deux tenants reste isolé pour GET/list/PUT/DELETE et la publication. Aucun chemin client ne permet de sortir de la racine. |
| `SPEC-T-PROCESS-TIMEOUT` | `SPEC-BIND-04`, `SPEC-OBS-01`, `SPEC-AC-06` | Faux exécutable qui expire, échoue, émet beaucoup de sortie ou manque ; délai borné, sortie bornée, erreur classée et état persisté cohérent. |
| `SPEC-T-RNDC-ARGS` | `SPEC-BIND-04..05` | Vérifier les arguments exacts du processus sans shell ; noms invalides refusés avant lancement ; aucun secret dans logs/réponses. |
| `SPEC-T-RELOAD-COALESCE` | `SPEC-BIND-07` | Rafale de changements : nombre de reloads borné, toutes les zones finales publiées, échec visible et réessayable. |
| `SPEC-T-LIST-INDEX` | `SPEC-LIST-01..04` | Pagination stable, tenant isolé, index reconstruit après redémarrage ; listing ne lit pas chaque contenu de zone pour ses métadonnées. |
| `SPEC-T-BOUNDED-LOAD` | `SPEC-IO-01..06`, `SPEC-OBS-02`, `SPEC-AC-07` | Instrumenter faux store/processus sous charge : concurrence observée ≤ configuration et endpoint léger répond pendant les opérations lentes. |
| `SPEC-T-BIND-E2E` | `SPEC-BIND-03`, `06`, `08`, `SPEC-AC-08` | Avec BIND de test : création visible, mise à jour visible, suppression non servie, redémarrage conserve l’état attendu ; `persisted` et `active` reflètent les résultats réels. |

Les tests de performance doivent rapporter taille et nombre de RR, débit,
latences p50/p95/p99, utilisation CPU/mémoire et configuration de concurrence.
Ils servent à choisir les valeurs par défaut, pas à imposer un seuil matériel
universel dans les tests unitaires.
