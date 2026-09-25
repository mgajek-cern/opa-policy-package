# Task runner for opa-policy-package.
#
#   make up PHASE=4        start that phase's stack
#   make init PHASE=4      run its init script, if it has one
#   make test PHASE=4      run whichever suites that phase has
#   make down PHASE=4      stop it (add clean to wipe volumes)
#   make e2e PHASE=4       up + init + test
#
# Every target takes PHASE=1..6. Phase 6 also takes AUTHZ_MODE=direct|service
# (default direct). Override RUCIO_URL / OPA_URL / KEYCLOAK_URL to point at a
# remote stack. Run `make help` for the full list of overridable variables.


PHASE ?= 6
AUTHZ_MODE ?= direct
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
ifeq ($(AUTHZ_MODE),service)
	COMPOSE := AUTHZ_MODE=$(AUTHZ_MODE) docker compose -f $(COMPOSE_FILE) --profile service
else
	COMPOSE := AUTHZ_MODE=$(AUTHZ_MODE) docker compose -f $(COMPOSE_FILE)
endif

RUCIO_URL ?= http://localhost
OPA_URL ?= http://localhost:8181
KEYCLOAK_URL ?= http://localhost:8080
PYTEST ?= python3 -m pytest
PYTEST_ARGS ?= -v --tb=short

# wildcard, not a literal path: a phase without a given suite simply has none,
# and the target says so instead of failing on a missing file.
OPA_TEST := $(wildcard tests/test_phase$(PHASE)_opa.py)
ifeq ($(AUTHZ_MODE),service)
	RUCIO_TEST := $(wildcard tests/test_phase$(PHASE)_rucio_authz_service.py)
else
	RUCIO_TEST := $(wildcard tests/test_phase$(PHASE)_rucio.py)
endif
# service mode has no transfer suite yet — see README's Test suites table.
ifeq ($(AUTHZ_MODE),service)
	TRANSFER_TEST :=
else
	TRANSFER_TEST := $(wildcard tests/test_phase$(PHASE)_full_transfer.py)
endif
INIT_SCRIPT := $(wildcard scripts/init-phase$(PHASE).sh)

ifeq ($(PHASE),1)
	UNIT_TESTS := tests/test_phase1_rules.py tests/test_phase1_permission.py
endif

# Phases 6 drive Rucio from inside the client container: they need the mounted
# certs and in-network DNS to reach FTS and the storage endpoints.
ifeq ($(PHASE),6)
	TEST_CONTAINER := rucio-client
endif

ifdef TEST_CONTAINER
	run_tests = $(COMPOSE) exec -T $(TEST_CONTAINER) python3 -m pytest /tests/$(notdir $(1)) $(PYTEST_ARGS)
else
	run_tests = RUCIO_URL=$(RUCIO_URL) OPA_URL=$(OPA_URL) KEYCLOAK_URL=$(KEYCLOAK_URL) $(PYTEST) $(1) $(PYTEST_ARGS)
endif

.PHONY: help
help: ## List targets
	@echo "PHASE=$(PHASE)  AUTHZ_MODE=$(AUTHZ_MODE)  package=phases/$(PKG)"
	@echo
	@echo "Overridable variables:"
	@echo "  PHASE=1..6          (default 6)"
	@echo "  AUTHZ_MODE=direct|service   phase 6 only (default direct)"
	@echo "  RUCIO_URL, OPA_URL, KEYCLOAK_URL   for a remote stack (non-container test runs)"
	@echo
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

.PHONY: install
install: ## pip install -e the selected phase's package
	@if [ ! -f "phases/$(PKG)/pyproject.toml" ] && [ ! -f "phases/$(PKG)/setup.py" ]; then \
	  echo "phase $(PHASE): no package at phases/$(PKG)"; \
	else \
	  python3 -m pip install -e phases/$(PKG)/; \
	fi

.PHONY: install-dev
install-dev: ## Install test dependencies plus the selected phase
	python3 -m pip install pytest pytest-cov requests urllib3
	$(MAKE) install PHASE=$(PHASE)

.PHONY: certs
certs: ## Generate the CA and host certs
	cd scripts && ./generate-certs.sh

.PHONY: up
up: ## Start the phase's stack and wait for healthchecks
ifeq ($(PHASE),1)
	@echo "Phase 1 has no stack — run 'make test PHASE=1'."
else
	$(COMPOSE) up -d --wait
endif

.PHONY: init
init: ## Register accounts, identities and (phase 6) RSEs and token exchange
	@if [ -z "$(INIT_SCRIPT)" ]; then \
	  echo "phase $(PHASE): no init script"; \
	else \
	  cd scripts && ./$(notdir $(INIT_SCRIPT)); \
	fi

.PHONY: down
down: ## Stop the stack, keeping volumes
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and wipe volumes
	$(COMPOSE) down -v

.PHONY: ps
ps: ## Show container status, including exited ones
	$(COMPOSE) ps -a

.PHONY: logs
logs: ## Tail the stack's logs (SERVICE=rucio to narrow)
	$(COMPOSE) logs -f --tail=200 $(SERVICE)

.PHONY: dump
dump: ## Print container status and recent logs (non-following; for CI)
	-$(COMPOSE) ps -a
	-$(COMPOSE) logs --tail=200

.PHONY: shell
shell: ## Open a shell in a container (SERVICE=rucio)
	$(COMPOSE) exec $(or $(SERVICE),rucio) bash

.PHONY: test-opa
test-opa: ## Scenario tests against OPA directly
	@if [ -z "$(OPA_TEST)" ]; then \
	  echo "phase $(PHASE): no OPA suite"; \
	else \
	  OPA_URL=$(OPA_URL) $(PYTEST) $(OPA_TEST) $(PYTEST_ARGS); \
	fi

.PHONY: test-rucio
test-rucio: ## Authorisation tests against Rucio's REST API
	@if [ -z "$(RUCIO_TEST)" ]; then \
	  echo "phase $(PHASE): no Rucio suite"; \
	else \
	  $(call run_tests,$(RUCIO_TEST)); \
	fi

.PHONY: test-transfer
test-transfer: ## End-to-end transfer tests (phase 6, AUTHZ_MODE=direct only)
	@if [ -z "$(TRANSFER_TEST)" ]; then \
	  echo "phase $(PHASE): no transfer suite"; \
	else \
	  $(call run_tests,$(TRANSFER_TEST)); \
	fi

.PHONY: test
test: ## Run every suite the phase has, except transfers
ifeq ($(PHASE),1)
	$(PYTEST) $(UNIT_TESTS) $(PYTEST_ARGS)
else
	$(MAKE) test-opa PHASE=$(PHASE) AUTHZ_MODE=$(AUTHZ_MODE)
	$(MAKE) test-rucio PHASE=$(PHASE) AUTHZ_MODE=$(AUTHZ_MODE)
endif

.PHONY: e2e
e2e: ## up, init, test
	$(MAKE) up PHASE=$(PHASE) AUTHZ_MODE=$(AUTHZ_MODE)
	$(MAKE) init PHASE=$(PHASE) AUTHZ_MODE=$(AUTHZ_MODE)
	$(MAKE) test PHASE=$(PHASE) AUTHZ_MODE=$(AUTHZ_MODE)

.PHONY: lint
lint: ## Run the pre-commit hooks over the whole tree
	pre-commit run --all-files
