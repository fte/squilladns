# =============================================================================
# Makefile — squilladns
# Autodetection du runtime container : Apple Container, Colima, Docker Desktop
# =============================================================================

IMAGE   := squilladns
COMPOSE := docker-compose.yml

# ---------------------------------------------------------------------------
# Autodetection du runtime container
#
# Priorité :
#   1. Apple Container  (commande `container` dispo ET daemon en cours)
#   2. Colima           (colima dispo ET instance en cours : socket actif)
#   3. Docker           (docker dispo, fallback standard)
# ---------------------------------------------------------------------------

# Détection silencieuse — chaque bloc teste existence + disponibilité réelle
define detect_runtime
$(shell \
  if command -v container >/dev/null 2>&1 && container ps >/dev/null 2>&1; then \
    echo "apple"; \
  elif command -v colima >/dev/null 2>&1 && colima status 2>/dev/null | grep -q "running"; then \
    echo "colima"; \
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
    echo "docker"; \
  else \
    echo "none"; \
  fi \
)
endef

RUNTIME := $(call detect_runtime)

# Sélection des commandes selon le runtime détecté
ifeq ($(RUNTIME),apple)
  DOCKER         := container
  DOCKER_COMPOSE := container compose
  RUNTIME_LABEL  := Apple Container
else ifeq ($(RUNTIME),colima)
  DOCKER         := docker
  DOCKER_COMPOSE := docker compose
  RUNTIME_LABEL  := Colima (Docker socket)
else ifeq ($(RUNTIME),docker)
  DOCKER         := docker
  DOCKER_COMPOSE := docker compose
  RUNTIME_LABEL  := Docker Desktop / Docker Engine
else
  DOCKER         := docker
  DOCKER_COMPOSE := docker compose
  RUNTIME_LABEL  := ⚠️  Aucun runtime détecté — vérifie ton daemon
endif

# ---------------------------------------------------------------------------
# Affichage du runtime au démarrage de chaque cible
# ---------------------------------------------------------------------------
define print_runtime
	@printf '\033[1;36m[runtime]\033[0m %s\n' "$(RUNTIME_LABEL)"
endef

# ---------------------------------------------------------------------------
# Cibles
# ---------------------------------------------------------------------------

.DEFAULT_GOAL := help

.PHONY: help runtime build up down restart logs clean fclean ps

## Affiche cette aide
help:
	@printf '\n\033[1mSquillaDNS — Makefile\033[0m\n\n'
	@printf '  \033[1;33mruntime\033[0m   Affiche le runtime container détecté\n'
	@printf '  \033[1;33mbuild\033[0m     Construit l'\''image Docker\n'
	@printf '  \033[1;33mup\033[0m        Lance les services (--build implicite)\n'
	@printf '  \033[1;33mdown\033[0m      Arrête et supprime les containers\n'
	@printf '  \033[1;33mrestart\033[0m   Redémarre les services\n'
	@printf '  \033[1;33mlogs\033[0m      Suit les logs en temps réel\n'
	@printf '  \033[1;33mps\033[0m        Liste les containers du projet\n'
	@printf '  \033[1;33mclean\033[0m     down + suppression de l'\''image locale\n'
	@printf '  \033[1;33mfclean\033[0m    clean + suppression des volumes et du cache build\n'
	@printf '\n'

## Affiche le runtime container détecté
runtime:
	$(call print_runtime)
	@printf '  DOCKER         = %s\n' "$(DOCKER)"
	@printf '  DOCKER_COMPOSE = %s\n' "$(DOCKER_COMPOSE)"

## Construit l'image (sans démarrer)
build:
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) build

## Lance les services en arrière-plan (rebuild auto si nécessaire)
up:
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) up -d --build

## Arrête et supprime les containers (volumes préservés)
down:
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) down

## Redémarre les services
restart: down up

## Suit les logs en temps réel (Ctrl+C pour quitter)
logs:
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) logs -f

## Liste les containers du projet
ps:
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) ps

## Arrête les containers et supprime l'image locale
clean: down
	$(call print_runtime)
	$(DOCKER) rmi -f $(IMAGE) 2>/dev/null || true

## Nettoyage complet : containers, image, volumes, cache build
fclean: down
	$(call print_runtime)
	$(DOCKER_COMPOSE) -f $(COMPOSE) down -v --remove-orphans 2>/dev/null || true
	$(DOCKER) rmi -f $(IMAGE) 2>/dev/null || true
	$(DOCKER) builder prune -f 2>/dev/null || true
	@printf '\033[1;32m✓ Nettoyage complet terminé\033[0m\n'
