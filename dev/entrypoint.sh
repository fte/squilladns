#!/bin/bash
set -uo pipefail

# Le répertoire bind-cache est un volume local de développement, créé par
# l'utilisateur hôte. BIND doit pouvoir y persister ses zones rndc (.nzd).
chmod 0777 /var/cache/bind

named -g -c /etc/bind/squilladns-dev.conf -u bind &
named_pid=$!

cleanup() {
    trap - INT TERM
    kill -TERM "$named_pid" 2>/dev/null || true
    if [[ -n "${api_pid:-}" ]]; then
        kill -TERM "$api_pid" 2>/dev/null || true
    fi
    wait "$named_pid" 2>/dev/null || true
    if [[ -n "${api_pid:-}" ]]; then
        wait "$api_pid" 2>/dev/null || true
    fi
}
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

ready=0
for _ in {1..100}; do
    if ! kill -0 "$named_pid" 2>/dev/null; then
        wait "$named_pid"
        exit $?
    fi
    if rndc -c /etc/bind/squilladns-rndc.conf status >/dev/null 2>&1; then
        ready=1
        break
    fi
    sleep 0.1
done

if [[ "$ready" != 1 ]]; then
    echo "BIND failed to become ready for rndc" >&2
    cleanup
    exit 1
fi

setpriv --reuid "${APP_UID:-10001}" --regid "${APP_GID:-10001}" --clear-groups \
    /usr/local/bin/squilladns &
api_pid=$!

set +e
wait -n "$named_pid" "$api_pid"
status=$?
cleanup
exit "$status"
