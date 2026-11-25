# =============================================================================
# SquillaDNS — cibles regroupées par contexte : développement, tests, exploitation
# RUNTIME=auto choisit Apple Container avant Docker/Colima.
# =============================================================================

-include .env

.DEFAULT_GOAL := help

RUNTIME ?= auto
IMAGE := squilladns
DEV_IMAGE := squilladns-dev
E2E_IMAGE := squilladns-bind-e2e
DEV_CONTAINER_NAME := squilladns-dev
CONTAINER_NAME := squilladns
PORT ?= 8085
DNS_PORT ?= 1053
DATA_DIR ?= $(CURDIR)/var/lib/squilladns
ZONES_DIR := $(DATA_DIR)/zones
STATE_DIR := $(DATA_DIR)/state
BIND_CACHE_DIR := $(DATA_DIR)/bind-cache
RUN_UID := $(shell id -u)
RUN_GID := $(shell id -g)

API_TOKEN ?=
MAX_REQUEST_BODY_BYTES ?= 1048576
MAX_RECORDS_PER_ZONE ?= 10000
MAX_RECORD_NAME_BYTES ?= 253
MAX_RECORD_VALUE_BYTES ?= 4096
MAX_PARALLEL_VALIDATIONS ?= 4
MAX_PARALLEL_IO ?= 4
RNDC_BIN ?= rndc
RNDC_CONF ?=
RNDC_TIMEOUT_SECS ?= 5
CHECKZONE_TIMEOUT_SECS ?= 5
RUST_LOG ?= info
JWT_SECRET ?=
JWT_ED25519_PUBLIC_KEY ?=
BFF_API_AUDIENCE ?= squilladns
SANDBOX_USER ?=
CORS_ALLOWED_ORIGINS ?= *

# Détection des moteurs au parse-time.
DOCKER_CLI := $(shell command -v docker >/dev/null 2>&1 && echo yes || echo no)
CONTAINER_CLI := $(shell command -v container >/dev/null 2>&1 && echo yes || echo no)
DOCKER_COMPOSE := $(shell \
	if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
		echo 'docker compose'; \
	elif command -v docker-compose >/dev/null 2>&1; then \
		echo 'docker-compose'; \
	fi)

ifeq ($(RUNTIME),container)
  RUNTIME_EFFECTIVE := container
else ifeq ($(RUNTIME),docker)
  RUNTIME_EFFECTIVE := docker
else ifeq ($(CONTAINER_CLI),yes)
  RUNTIME_EFFECTIVE := container
else ifeq ($(DOCKER_CLI),yes)
  RUNTIME_EFFECTIVE := docker
else
  RUNTIME_EFFECTIVE := none
endif
CONTAINER_ENGINE := $(if $(filter container,$(RUNTIME_EFFECTIVE)),container,docker)

.PHONY: _guard _guard_compose help runtime \
	dev dev-build dev-up dev-down dev-restart dev-logs dev-ps shell \
	test test-bind-e2e test-list test-watch \
	build-bin binary build up down restart logs ps clean fclean

_guard:
	@if [ "$(RUNTIME_EFFECTIVE)" = "none" ]; then \
		printf '\033[1;31m[erreur]\033[0m Aucun moteur de conteneurs détecté.\n'; \
		exit 1; \
	fi

_guard_compose: _guard
	@if [ "$(RUNTIME_EFFECTIVE)" = "docker" ] && [ -z "$(DOCKER_COMPOSE)" ]; then \
		printf '\033[1;31m[erreur]\033[0m Cette cible requiert Docker Compose.\n'; \
		exit 1; \
	fi

help: ## [OPS] Affiche les cibles classées par contexte
	@printf '\n\033[1;1;35mSquillaDNS — Makefile\033[0m\n'
	@printf '\033[1;36m── DEV · conteneur local + BIND 9 ──\033[0m\n'
	@grep -h -E '^[a-zA-Z0-9_-]+:.*## \[DEV\]' $(MAKEFILE_LIST) | sed -E 's/^([^:]+):.*## \[DEV\] /\1\t/' | awk -F '\t' '{printf "  \033[1;36m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\033[1;33m── TESTS ──\033[0m\n'
	@grep -h -E '^[a-zA-Z0-9_-]+:.*## \[TEST\]' $(MAKEFILE_LIST) | sed -E 's/^([^:]+):.*## \[TEST\] /\1\t/' | awk -F '\t' '{printf "  \033[1;33m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\033[1;32m── EXPLOITATION / OUTILS ──\033[0m\n'
	@grep -h -E '^[a-zA-Z0-9_-]+:.*## \[OPS\]' $(MAKEFILE_LIST) | sed -E 's/^([^:]+):.*## \[OPS\] /\1\t/' | awk -F '\t' '{printf "  \033[1;32m%-18s\033[0m %s\n", $$1, $$2}'
	@printf '\n\033[1;35mDétection : Apple Container prioritaire, Docker/Colima ensuite.\033[0m\n'
	@printf 'Exemple VPS : make dev-up DATA_DIR=/var/lib/squilladns\n\n'

runtime: ## [OPS] Affiche le moteur détecté
	@printf 'override=%s effectif=%s AppleContainer=%s Docker=%s Compose=%s\n' "$(RUNTIME)" "$(RUNTIME_EFFECTIVE)" "$(CONTAINER_CLI)" "$(DOCKER_CLI)" "$(DOCKER_COMPOSE)"
	@if [ "$(RUNTIME_EFFECTIVE)" = "container" ]; then container --version; elif [ "$(RUNTIME_EFFECTIVE)" = "docker" ]; then docker --version; fi

# ── DEV : l’API et BIND 9 partagent un conteneur et les chemins de production ─

dev: dev-up ## [DEV] Alias de dev-up

dev-build: _guard ## [DEV] Construit l’image locale API + BIND 9
	$(CONTAINER_ENGINE) build --target dev -t $(DEV_IMAGE) .

dev-up: _guard ## [DEV] Démarre API + BIND 9, ports API 8085 et DNS 1053
	$(CONTAINER_ENGINE) build --target dev -t $(DEV_IMAGE) .
	@mkdir -p "$(ZONES_DIR)" "$(STATE_DIR)" "$(BIND_CACHE_DIR)"
	$(CONTAINER_ENGINE) run --detach \
	  --name $(DEV_CONTAINER_NAME) \
	  --publish $(PORT):8085 \
	  --publish $(DNS_PORT):53/udp \
	  --publish $(DNS_PORT):53/tcp \
	  --volume "$(ZONES_DIR):/var/lib/squilladns/zones" \
	  --volume "$(STATE_DIR):/var/lib/squilladns/state" \
	  --volume "$(BIND_CACHE_DIR):/var/cache/bind" \
	  --env API_ADDR=0.0.0.0:8085 \
	  --env APP_UID=$(RUN_UID) --env APP_GID=$(RUN_GID) \
	  --env ZONES_DIR=/var/lib/squilladns/zones \
	  --env API_TOKEN_PATH=/var/lib/squilladns/state/tokens \
	  --env "API_TOKEN=$(API_TOKEN)" \
	  --env MAX_REQUEST_BODY_BYTES=$(MAX_REQUEST_BODY_BYTES) \
	  --env MAX_RECORDS_PER_ZONE=$(MAX_RECORDS_PER_ZONE) \
	  --env MAX_RECORD_NAME_BYTES=$(MAX_RECORD_NAME_BYTES) \
	  --env MAX_RECORD_VALUE_BYTES=$(MAX_RECORD_VALUE_BYTES) \
	  --env MAX_PARALLEL_VALIDATIONS=$(MAX_PARALLEL_VALIDATIONS) \
	  --env MAX_PARALLEL_IO=$(MAX_PARALLEL_IO) \
	  --env RNDC_CONF=/etc/bind/squilladns-rndc.conf \
	  --env RNDC_TIMEOUT_SECS=$(RNDC_TIMEOUT_SECS) \
	  --env CHECKZONE_TIMEOUT_SECS=$(CHECKZONE_TIMEOUT_SECS) \
	  --env RUST_LOG=$(RUST_LOG) \
	  --env "JWT_SECRET=$(JWT_SECRET)" \
	  --env "JWT_ED25519_PUBLIC_KEY=$(JWT_ED25519_PUBLIC_KEY)" \
	  --env "BFF_API_AUDIENCE=$(BFF_API_AUDIENCE)" \
	  --env "CORS_ALLOWED_ORIGINS=$(CORS_ALLOWED_ORIGINS)" \
	  --env "SANDBOX_USER=$(SANDBOX_USER)" \
	  $(DEV_IMAGE)
	@printf '\033[1;32m✓ API : http://localhost:%s · DNS : 127.0.0.1:%s\033[0m\n' "$(PORT)" "$(DNS_PORT)"

dev-down: _guard ## [DEV] Arrête le conteneur de développement
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container stop $(DEV_CONTAINER_NAME) 2>/dev/null || true; container delete $(DEV_CONTAINER_NAME) 2>/dev/null || true,docker rm -f $(DEV_CONTAINER_NAME) 2>/dev/null || true)

dev-restart: dev-down dev-up ## [DEV] Redémarre API + BIND 9

dev-logs: _guard ## [DEV] Suit les logs API et BIND 9
	$(CONTAINER_ENGINE) logs --follow $(DEV_CONTAINER_NAME)

dev-ps: _guard ## [DEV] Affiche le conteneur de développement
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container list | grep -E 'NAME|$(DEV_CONTAINER_NAME)' || true,docker ps --filter name=$(DEV_CONTAINER_NAME))

shell: _guard ## [DEV] Ouvre un shell dans le conteneur (démarrer avec dev-up)
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container exec --interactive --tty $(DEV_CONTAINER_NAME) /bin/bash,docker exec -it $(DEV_CONTAINER_NAME) /bin/bash)

# ── TESTS ──────────────────────────────────────────────────────────────────

test: ## [TEST] Lance les tests Rust
	cargo test -- --nocapture

test-bind-e2e: _guard ## [TEST] Lance SPEC-AC-08 dans une image avec BIND 9
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container build --target bind-e2e -t $(E2E_IMAGE) . && container run --rm --name $(E2E_IMAGE) $(E2E_IMAGE),docker build --target bind-e2e -t $(E2E_IMAGE) . && docker run --rm --name $(E2E_IMAGE) $(E2E_IMAGE))

test-list: ## [TEST] Liste les tests Rust disponibles
	@printf '\n\033[1;33mTests disponibles\033[0m\n\n'
	@cargo test -- --list 2>&1 | awk '\
	/Running (unittests|tests|doctests)/ { \
	  target = $$0; sub(/^.*Running /, "", target); sub(/ \(.*/, "", target); \
	  current = ++groups; group_names[current] = target; counts[current] = 0; next; \
	} \
	/: test$$/ { \
	  name = $$0; sub(/: test$$/, "", name); \
	  counts[current]++; tests[current, counts[current]] = name; \
	} \
	END { \
	  for (g = 1; g <= groups; g++) if (counts[g] > 0) { \
	    printf "  \033[1;36m%s (%d)\033[0m\n", group_names[g], counts[g]; \
	    for (i = 1; i <= counts[g]; i++) printf "    %s\n", tests[g, i]; \
	  } \
	}'

test-watch: ## [TEST] Relance les tests avec cargo-watch
	@if ! cargo watch --version >/dev/null 2>&1; then \
		printf '\033[1;31m[erreur]\033[0m cargo-watch n’est pas installé. Installe-le avec cargo install cargo-watch.\n'; \
		exit 127; \
	fi
	cargo watch -x test

# ── EXPLOITATION / OUTILS ───────────────────────────────────────────────────

build-bin: ## [OPS] Compile le binaire release Rust
	cargo build --release

binary: build-bin ## [OPS] Alias pour build-bin

build: _guard ## [OPS] Construit l’image API de production (sans BIND serveur)
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container build --target runtime -t $(IMAGE) .,docker build --target runtime -t $(IMAGE) .)

up: _guard_compose ## [OPS] Lance l’API seule via Compose / le moteur détecté
	@mkdir -p "$(ZONES_DIR)" "$(STATE_DIR)"
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container run --detach --name $(CONTAINER_NAME) --user $(RUN_UID):$(RUN_GID) --publish $(PORT):8085 --volume "$(ZONES_DIR):/var/lib/squilladns/zones" --volume "$(STATE_DIR):/var/lib/squilladns/state" --env API_ADDR=0.0.0.0:8085 --env ZONES_DIR=/var/lib/squilladns/zones --env API_TOKEN_PATH=/var/lib/squilladns/state/tokens --env API_TOKEN=$(API_TOKEN) --env RNDC_BIN=$(RNDC_BIN) --env RNDC_CONF=$(RNDC_CONF) --env RUST_LOG=$(RUST_LOG) $(IMAGE),SQUILLADNS_DATA_DIR=$(DATA_DIR) SQUILLADNS_UID=$(RUN_UID) SQUILLADNS_GID=$(RUN_GID) $(DOCKER_COMPOSE) -f docker-compose.yml up -d --build)

down: _guard_compose ## [OPS] Arrête l’API de production
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container stop $(CONTAINER_NAME) 2>/dev/null || true; container delete $(CONTAINER_NAME) 2>/dev/null || true,$(DOCKER_COMPOSE) -f docker-compose.yml down)

restart: down up ## [OPS] Redémarre l’API de production

logs: _guard_compose ## [OPS] Suit les logs de production
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container logs --follow $(CONTAINER_NAME),$(DOCKER_COMPOSE) -f docker-compose.yml logs -f)

ps: _guard_compose ## [OPS] Liste les conteneurs SquillaDNS
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container list | grep -E 'NAME|squilladns' || true,$(DOCKER_COMPOSE) -f docker-compose.yml ps)

clean: dev-down down ## [OPS] Arrête les conteneurs et supprime les images
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container image delete $(IMAGE) 2>/dev/null || true; container image delete $(DEV_IMAGE) 2>/dev/null || true; container image delete $(E2E_IMAGE) 2>/dev/null || true,docker rmi -f $(IMAGE) $(DEV_IMAGE) $(E2E_IMAGE) 2>/dev/null || true)

fclean: clean ## [OPS] Supprime aussi les conteneurs arrêtés et cache Docker
	$(if $(filter container,$(RUNTIME_EFFECTIVE)),container prune 2>/dev/null || true,$(DOCKER_COMPOSE) -f docker-compose.yml down -v --remove-orphans 2>/dev/null || true; docker builder prune -f 2>/dev/null || true)
	@printf '\033[1;32m✓ Nettoyage terminé\033[0m\n'
