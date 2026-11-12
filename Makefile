# =============================================================================
# Makefile — squilladns
#
# Autodetection du runtime container :
#   - Apple Container  (macOS 26+, CLI `container`)
#   - Docker Desktop / Docker Engine
#   - Colima           (via le socket Docker standard)
#
# Surcharge possible depuis la ligne de commande :
#   make up RUNTIME=docker
#   make up RUNTIME=container
# =============================================================================

RUNTIME  ?= auto
IMAGE    := squilladns
COMPOSE  := docker-compose.yml

# ---------------------------------------------------------------------------
# Détection des CLIs au parse-time (command -v — rapide, sans ping daemon)
# ---------------------------------------------------------------------------

DOCKER_CLI    := $(shell command -v docker    >/dev/null 2>&1 && echo yes || echo no)
CONTAINER_CLI := $(shell command -v container >/dev/null 2>&1 && echo yes || echo no)

# Compose runner : plugin v2 "docker compose" ou binaire standalone "docker-compose"
DOCKER_COMPOSE := $(shell \
  if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then \
    echo 'docker compose'; \
  elif command -v docker-compose >/dev/null 2>&1; then \
    echo 'docker-compose'; \
  fi)

# ---------------------------------------------------------------------------
# Résolution effective du runtime
# ---------------------------------------------------------------------------

ifeq ($(RUNTIME),container)
  RUNTIME_EFFECTIVE := container
else ifeq ($(RUNTIME),docker)
  RUNTIME_EFFECTIVE := docker
else ifeq ($(CONTAINER_CLI),yes)
  # Apple Container CLI trouvé → priorité
  RUNTIME_EFFECTIVE := container
else ifeq ($(DOCKER_CLI),yes)
  # Docker CLI trouvé (Docker Desktop ou Colima)
  RUNTIME_EFFECTIVE := docker
else
  RUNTIME_EFFECTIVE := none
endif

# ---------------------------------------------------------------------------
# Commandes selon le runtime effectif
# ---------------------------------------------------------------------------

ifeq ($(RUNTIME_EFFECTIVE),container)
  DOCKER_BIN     := container
  COMPOSE_BIN    := container compose
else
  DOCKER_BIN     := docker
  COMPOSE_BIN    := $(DOCKER_COMPOSE)
endif

# ---------------------------------------------------------------------------
# Garde : vérifie qu'un runtime est disponible avant chaque cible
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
	@printf '\033[1;36m[runtime]\033[0m %s\n' "$(RUNTIME_EFFECTIVE)  (compose: $(COMPOSE_BIN))"
endef

# ---------------------------------------------------------------------------
# Cibles
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: help runtime build up down restart logs ps clean fclean

help: ## Affiche cette aide
	@printf '\n\033[1mSquillaDNS — Makefile\033[0m\n\n'
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[1;33m%-10s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '  Surcharge du runtime : make <cible> RUNTIME=docker|container\n\n'

runtime: ## Affiche le runtime détecté
	@printf 'RUNTIME override   : %s\n' "$(RUNTIME)"
	@printf 'RUNTIME_EFFECTIVE  : %s\n' "$(RUNTIME_EFFECTIVE)"
	@printf 'CONTAINER_CLI      : %s\n' "$(CONTAINER_CLI)"
	@printf 'DOCKER_CLI         : %s\n' "$(DOCKER_CLI)"
	@printf 'COMPOSE_BIN        : %s\n' "$(COMPOSE_BIN)"
	@if [ "$(RUNTIME_EFFECTIVE)" = "container" ]; then \
		container --version 2>/dev/null || true; \
	elif [ "$(RUNTIME_EFFECTIVE)" = "docker" ]; then \
		docker --version 2>/dev/null || true; \
		printf 'Docker context     : %s\n' "$$(docker context show 2>/dev/null)"; \
	fi

build: _guard ## Construit l'image (sans démarrer)
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) build

up: _guard ## Lance les services en arrière-plan (--build auto)
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) up -d --build

down: _guard ## Arrête et supprime les containers
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) down

restart: down up ## Redémarre les services

logs: _guard ## Suit les logs en temps réel (Ctrl+C pour quitter)
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) logs -f

ps: _guard ## Liste les containers du projet
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) ps

clean: _guard ## Arrête les containers et supprime l'image locale
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) down
	$(DOCKER_BIN) rmi -f $(IMAGE) 2>/dev/null || true

fclean: _guard ## Nettoyage complet : containers, volumes, image, cache build
	$(call print_runtime)
	$(COMPOSE_BIN) -f $(COMPOSE) down -v --remove-orphans 2>/dev/null || true
	$(DOCKER_BIN) rmi -f $(IMAGE) 2>/dev/null || true
	$(DOCKER_BIN) builder prune -f 2>/dev/null || true
	@printf '\033[1;32m✓ Nettoyage complet terminé\033[0m\n'
