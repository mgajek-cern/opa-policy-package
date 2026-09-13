# Task runner for opa-policy-package.
#
#   make up PHASE=4        start that phase's stack
#   make init PHASE=4      run its init script, if it has one
#   make test PHASE=4      run whichever suites that phase has
#   make down PHASE=4      stop it (add clean to wipe volumes)
#   make e2e PHASE=4       up + init + test
#
# Every target takes PHASE=1..6. Override RUCIO_URL / OPA_URL / KEYCLOAK_URL
# to point at a remote stack.

PHASE ?= 6
SHELL := /bin/bash
.DEFAULT_GOAL := help

PKG_1 := phase1-no-opa
PKG_2 := phase2-opa
PKG_3 := phase3-opa
PKG_4 := phase4-opa
PKG_5 := phase5-opa
PKG_6 := phase6-opa
PKG := $(PKG_$(PHASE))

ifeq ($(PKG),)
$(error PHASE=$(PHASE) is not one of 1 2 3 4 5 6)
endif

COMPOSE_FILE := deploy/compose/docker-compose.phase$(PHASE).yml
COMPOSE := docker compose -f $(COMPOSE_FILE)

RUCIO_URL ?= http://localhost
OPA_URL ?= http://localhost:8181
KEYCLOAK_URL ?= http://localhost:8080
PYTEST ?= python3 -m pytest
PYTEST_ARGS ?= -v --tb=short

# wildcard, not a literal path: a phase without a given suite simply has none,
# and the target says so instead of failing on a missing file.
OPA_TEST := $(wildcard tests/test_phase$(PHASE)_opa.py)
RUCIO_TEST := $(wildcard tests/test_phase$(PHASE)_rucio.py)
TRANSFER_TEST := $(wildcard tests/test_phase$(PHASE)_full_transfer.py)
INIT_SCRIPT := $(wildcard scripts/init-phase$(PHASE).sh)

ifeq ($(PHASE),1)
UNIT_TESTS := tests/test_phase1_rules.py tests/test_phase1_permission.py
endif

# Phase 6 drives Rucio from inside the client container: it needs the mounted
# certs and in-network DNS to reach FTS and the storage endpoints.
ifeq ($(PHASE),6)
TEST_CONTAINER := rucio-client
endif

ifdef TEST_CONTAINER
run_tests = $(COMPOSE) exec -T $(TEST_CONTAINER) python3 -m pytest /tests/$(notdir $(1)) $(PYTEST_ARGS)
else
run_tests = RUCIO_URL=$(RUCIO_URL) OPA_URL=$(OPA_URL) KEYCLOAK_URL=$(KEYCLOAK_URL) $(PYTEST) $(1) $(PYTEST_ARGS)
endif

.PHONY: help install install-dev certs up init down clean ps logs shell \
        test test-opa test-rucio test-transfer e2e lint

help: ## List targets
	@echo "PHASE=$(PHASE)  package=phases/$(PKG)"
	@echo
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

install: ## pip install -e the selected phase's package
	python3 -m pip install -e phases/$(PKG)/

install-dev: ## Install test dependencies plus the selected phase
	python3 -m pip install pytest pytest-cov requests urllib3
	$(MAKE) install PHASE=$(PHASE)

certs: ## Generate the CA and host certs (needed before phase 6 comes up)
	cd scripts && ./generate-certs.sh

up: ## Start the phase's stack and wait for healthchecks
ifeq ($(PHASE),1)
	@echo "Phase 1 has no stack — run 'make test PHASE=1'."
else
ifeq ($(PHASE),6)
	@[ -f certs/rucio_ca.pem ] || $(MAKE) certs
endif
	$(COMPOSE) up -d --wait
endif

init: ## Register accounts, identities and (phase 6) RSEs and token exchange
	@if [ -z "$(INIT_SCRIPT)" ]; then \
	  echo "phase $(PHASE): no init script"; \
	else \
	  cd scripts && ./$(notdir $(INIT_SCRIPT)); \
	fi

down: ## Stop the stack, keeping volumes
	$(COMPOSE) down

clean: ## Stop the stack and wipe volumes
	$(COMPOSE) down -v

ps: ## Show container status, including exited ones
	$(COMPOSE) ps -a

logs: ## Tail the stack's logs (SERVICE=rucio to narrow)
	$(COMPOSE) logs -f --tail=200 $(SERVICE)

dump: ## Print container status and recent logs (non-following; for CI)
	-$(COMPOSE) ps -a
	-$(COMPOSE) logs --tail=200

shell: ## Open a shell in a container (SERVICE=rucio)
	$(COMPOSE) exec $(or $(SERVICE),rucio) bash

test-opa: ## Scenario tests against OPA directly
	@if [ -z "$(OPA_TEST)" ]; then \
	  echo "phase $(PHASE): no OPA suite"; \
	else \
	  OPA_URL=$(OPA_URL) $(PYTEST) $(OPA_TEST) $(PYTEST_ARGS); \
	fi

test-rucio: ## Authorisation tests against Rucio's REST API
	@if [ -z "$(RUCIO_TEST)" ]; then \
	  echo "phase $(PHASE): no Rucio suite"; \
	else \
	  $(call run_tests,$(RUCIO_TEST)); \
	fi

test-transfer: ## End-to-end transfer tests (phase 6 only)
	@if [ -z "$(TRANSFER_TEST)" ]; then \
	  echo "phase $(PHASE): no transfer suite"; \
	else \
	  $(call run_tests,$(TRANSFER_TEST)); \
	fi

test: ## Run every suite the phase has, except transfers
ifeq ($(PHASE),1)
	$(PYTEST) $(UNIT_TESTS) $(PYTEST_ARGS)
else
	$(MAKE) test-opa PHASE=$(PHASE)
	$(MAKE) test-rucio PHASE=$(PHASE)
endif

e2e: ## up, init, test
	$(MAKE) up PHASE=$(PHASE)
	$(MAKE) init PHASE=$(PHASE)
	$(MAKE) test PHASE=$(PHASE)

lint: ## Run the pre-commit hooks over the whole tree
	pre-commit run --all-files
