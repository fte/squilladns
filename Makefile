# =============================================================================
# Makefile — squilladns
#
# Autodetection du runtime container :
#   - Apple Container  (macOS 26+, CLI `container` — pas de plugin compose)
#   - Docker Desktop / Docker Engine  (avec docker compose v2)
#   - Colima           (via le socket Docker standard)
#
# Surcharge possible :
#   make up RUNTIME=docker
#   make up RUNTIME=container
# =============================================================================

RUNTIME  ?= auto
IMAGE    := squilladns
CONTAINER_NAME := squilladns
PORT     := 8085

# Token par défaut (surchargeable : make up API_TOKEN=montoken)
API_TOKEN ?= change-me-apres-creation

# ---------------------------------------------------------------------------
# Détection des CLIs au parse-time
# ---------------------------------------------------------------------------

DOCKER_CLI    := $(shell command -v docker    >/dev/null 2>&1 && echo yes || echo no)
CONTAINER_CLI := $(shell command -v container >/dev/null 2>&1 && echo yes || echo no)

DOCKER_COMPOSE := $(shell \
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
    echo 'docker compose'; \
  elif command -v docker-compose >/dev/null 2>&1; then \
    echo 'docker-compose'; \
  fi)

# ---------------------------------------------------------------------------
# Résolution du runtime effectif
# ---------------------------------------------------------------------------

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

# ---------------------------------------------------------------------------
# Garde
# ---------------------------------------------------------------------------

.PHONY: _guard
_guard:
	@if [ "$(RUNTIME_EFFECTIVE)" = "none" ]; then \
		printf '\033[1;31m[erreur]\033[0m Aucun runtime container détecté.\n'; \
		printf '  Installe Docker Desktop, Colima, ou Apple Container CLI.\n'; \
		exit 1; \
	fi
	@if [ "$(RUNTIME_EFFECTIVE)" = "docker" ] && [ -z "$(DOCKER_COMPOSE)" ]; then \
		printf '\033[1;31m[erreur]\033[0m Docker CLI trouvé mais pas de compose runner.\n'; \
		printf '  Installe docker-compose ou active le plugin Docker Compose v2.\n'; \
		exit 1; \
	fi

# ---------------------------------------------------------------------------
# Affichage du runtime
# ---------------------------------------------------------------------------

define print_runtime
	@printf '\033[1;36m[runtime]\033[0m %s\n' "$(RUNTIME_EFFECTIVE)"
endef

# ---------------------------------------------------------------------------
# Cibles communes (interface identique quel que soit le runtime)
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: help runtime build up down restart logs ps clean fclean

help: ## Affiche cette aide
	@printf '\n\033[1mSquillaDNS — Makefile\033[0m\n\n'
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[1;33m%-10s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '  Surcharge : make <cible> RUNTIME=docker|container  API_TOKEN=xxx\n\n'

runtime: ## Affiche le runtime détecté
	@printf 'RUNTIME override   : %s\n' "$(RUNTIME)"
	@printf 'RUNTIME_EFFECTIVE  : %s\n' "$(RUNTIME_EFFECTIVE)"
	@printf 'CONTAINER_CLI      : %s\n' "$(CONTAINER_CLI)"
	@printf 'DOCKER_CLI         : %s\n' "$(DOCKER_CLI)"
	@printf 'DOCKER_COMPOSE     : %s\n' "$(DOCKER_COMPOSE)"
	@if [ "$(RUNTIME_EFFECTIVE)" = "container" ]; then \
		container --version 2>/dev/null || true; \
	elif [ "$(RUNTIME_EFFECTIVE)" = "docker" ]; then \
		docker --version 2>/dev/null || true; \
		printf 'Docker context     : %s\n' "$$(docker context show 2>/dev/null)"; \
	fi

# ── build ──────────────────────────────────────────────────────────────────

build: _guard ## Construit l'image (sans démarrer)
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container build -t $(IMAGE) .
else
	$(DOCKER_COMPOSE) -f docker-compose.yml build
endif

# ── up ─────────────────────────────────────────────────────────────────────

up: _guard ## Lance le service en arrière-plan (build auto)
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container build -t $(IMAGE) .
	container run \
	  --detach \
	  --name $(CONTAINER_NAME) \
	  --publish $(PORT):$(PORT) \
	  --env API_TOKEN=$(API_TOKEN) \
	  --restart on-failure \
	  $(IMAGE)
	@printf '\033[1;32m✓ Container démarré : http://localhost:%s\033[0m\n' "$(PORT)"
else
	$(DOCKER_COMPOSE) -f docker-compose.yml up -d --build
endif

# ── down ───────────────────────────────────────────────────────────────────

down: _guard ## Arrête et supprime le container
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container stop $(CONTAINER_NAME)  2>/dev/null || true
	container delete $(CONTAINER_NAME) 2>/dev/null || true
else
	$(DOCKER_COMPOSE) -f docker-compose.yml down
endif

# ── restart ────────────────────────────────────────────────────────────────

restart: down up ## Redémarre le service

# ── logs ───────────────────────────────────────────────────────────────────

logs: _guard ## Suit les logs en temps réel (Ctrl+C pour quitter)
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container logs --follow $(CONTAINER_NAME)
else
	$(DOCKER_COMPOSE) -f docker-compose.yml logs -f
endif

# ── ps ─────────────────────────────────────────────────────────────────────

ps: _guard ## Liste les containers du projet
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container list | grep -E "NAME|$(CONTAINER_NAME)" || container list
else
	$(DOCKER_COMPOSE) -f docker-compose.yml ps
endif

# ── clean ──────────────────────────────────────────────────────────────────

clean: down ## Arrête le container et supprime l'image locale
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container image delete $(IMAGE) 2>/dev/null || true
else
	docker rmi -f $(IMAGE) 2>/dev/null || true
endif

# ── fclean ─────────────────────────────────────────────────────────────────

fclean: down ## Nettoyage complet : container, image, volumes, cache build
	$(call print_runtime)
ifeq ($(RUNTIME_EFFECTIVE),container)
	container image delete $(IMAGE) 2>/dev/null || true
	container prune 2>/dev/null || true
else
	$(DOCKER_COMPOSE) -f docker-compose.yml down -v --remove-orphans 2>/dev/null || true
	docker rmi -f $(IMAGE) 2>/dev/null || true
	docker builder prune -f 2>/dev/null || true
endif
	@printf '\033[1;32m✓ Nettoyage complet terminé\033[0m\n'
