#!/usr/bin/env bash
# restart.sh — (re)démarre squilladns sans root, à placer dans VPS_PATH à côté
# du binaire. Source un éventuel .env local, arrête l'ancien process, relance en
# arrière-plan puis vérifie le contrat de santé /health. Sortie non nulle en cas
# d'échec pour que le workflow de déploiement déclenche son rollback.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"

BIN="$APP_DIR/squilladns"
LOG="$APP_DIR/squilladns.log"
PIDFILE="$APP_DIR/squilladns.pid"
HEALTH_URL="http://127.0.0.1:8085/health"

# Configuration locale (API_TOKEN, ZONES_DIR, API_ADDR, JWT_* ...) si présente.
if [[ -f "$APP_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "$APP_DIR/.env"
  set +a
fi

# Valeurs par défaut alignées sur INSTALL.md (chemins absolus pour être
# indépendants du répertoire de lancement).
: "${API_ADDR:=0.0.0.0:8085}"
: "${API_TOKEN_PATH:=$APP_DIR/.state/tokens}"
: "${ZONES_DIR:=$APP_DIR/zones/example.invalid}"
: "${RUST_LOG:=info}"
export API_ADDR API_TOKEN_PATH ZONES_DIR RUST_LOG
mkdir -p "$(dirname "$API_TOKEN_PATH")" "$ZONES_DIR"

# Arrêt de l'ancien process : PID file fiable, sinon repli sur pkill ciblé.
if [[ -f "$PIDFILE" ]]; then
  oldpid="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [[ -n "${oldpid:-}" ]] && kill -0 "$oldpid" 2>/dev/null; then
    kill "$oldpid" 2>/dev/null || true
    for _ in {1..10}; do kill -0 "$oldpid" 2>/dev/null || break; sleep 0.3; done
    kill -0 "$oldpid" 2>/dev/null && kill -9 "$oldpid" 2>/dev/null || true
  fi
fi
pkill -f "$BIN" 2>/dev/null || true
sleep 0.5

# Démarrage en arrière-plan, détaché du terminal. stdin sur /dev/null pour ne pas
# garder le canal SSH du workflow ouvert ; nohup ignore SIGHUP à la déconnexion.
nohup "$BIN" >> "$LOG" 2>&1 < /dev/null &
newpid=$!
echo "$newpid" > "$PIDFILE"
echo "[restart] squilladns démarré (pid $newpid), logs: $LOG"

# Contrat de santé : HTTP 200 + status == ok, 30 s max.
ready=0
body=""
for _ in {1..30}; do
  body="$(curl -fsS --max-time 3 "$HEALTH_URL" 2>/dev/null || true)"
  if [[ -n "$body" ]] && echo "$body" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" -ne 1 ]]; then
  echo "[restart] ERREUR: /health n'a pas répondu sous 30 s. Dernières lignes de log :" >&2
  tail -n 40 "$LOG" >&2 || true
  exit 1
fi

echo "[restart] Contrat de santé validé : $body"