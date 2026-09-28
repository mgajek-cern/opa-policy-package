# Authorization Service (design-006). Run from this directory or with -C.
#
# The repository Makefile keeps phase concerns; this one keeps the service.

PY ?= python3
VENV ?= .venv
BIN ?= $(VENV)/bin
SPEC := api/openapi.yaml

# Server stubs scaffolded from the contract
SERVER_STUBS_OUT := src/authz_service/api/generated

# Standalone typed client, for consumers of this API (e.g. Rucio PEPs).
CLIENT_OUT := clients/python

# The [codegen] extra (fastapi-code-generator, openapi-python-client) lives
# in a SEPARATE venv from [dev]: fastapi-code-generator's own
# datamodel-code-generator requirement is newer than the ==0.26.5 pin
# [dev] needs, and one venv can't hold two versions of the same package.
# Both venvs are still driven entirely from this Makefile and pyproject.toml
# — nothing installed outside the repo.
TOOLS_VENV ?= .venv-codegen
TOOLS_BIN ?= $(TOOLS_VENV)/bin
FASTAPI_CODEGEN ?= $(TOOLS_BIN)/fastapi-codegen
OPENAPI_PYTHON_CLIENT ?= $(TOOLS_BIN)/openapi-python-client

COMPOSE := docker compose -f docker/docker-compose.yml

.DEFAULT_GOAL := help

help: ## List targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-24s %s\n", $$1, $$2}'

# Stamp files: the venvs are rebuilt only when missing or when
# pyproject.toml changed, so targets can depend on them cheaply.
$(VENV)/.installed: pyproject.toml
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip setuptools wheel
	$(BIN)/pip install -q -e ".[dev]"
	@touch $@

$(TOOLS_VENV)/.installed: pyproject.toml
	$(PY) -m venv $(TOOLS_VENV)
	$(TOOLS_BIN)/pip install -q --upgrade pip setuptools wheel
	$(TOOLS_BIN)/pip install -q -e ".[codegen]"
	@touch $@

venv: $(VENV)/.installed ## Create or refresh the dev environment

tools: $(TOOLS_VENV)/.installed ## Create or refresh the isolated env for the route/client generators

spec-validate: venv ## Validate the OpenAPI contract
	$(BIN)/python -c "import openapi_spec_validator, sys, yaml; \
	openapi_spec_validator.validate(yaml.safe_load(open('$(SPEC)')))"

generate-server-stubs: tools venv ## Scaffold per-tag server stubs from the contract (reference only, not wired in — see README)
	rm -rf $(SERVER_STUBS_OUT)
	@mkdir -p $(SERVER_STUBS_OUT)
	$(FASTAPI_CODEGEN) --input $(SPEC) --output $(SERVER_STUBS_OUT) \
	  --output-model-type pydantic_v2.BaseModel --python-version 3.12 \
	  --generate-routers --disable-timestamp
	$(BIN)/ruff format -q $(SERVER_STUBS_OUT)

generate-client: tools venv ## Generate a standalone typed Python client from the contract
	rm -rf $(CLIENT_OUT)
	@mkdir -p $(dir $(CLIENT_OUT))
	PATH="$(abspath $(BIN)):$$PATH" $(OPENAPI_PYTHON_CLIENT) generate --path $(SPEC) \
	  --output-path $(CLIENT_OUT) --meta none --overwrite

generate-client-phase6: ## Generate phase6's client via openapi-generator python-legacy (3.9-safe)
	rm -rf /tmp/phase6-spec && mkdir -p /tmp/phase6-spec
	python3 scripts/prepare_phase6_spec.py api/openapi.yaml /tmp/phase6-spec/openapi.yaml
	rm -rf ../../phases/phase6-opa/src/rucio_authz_client
	docker run --rm -v /tmp/phase6-spec:/local \
	  -v $(CURDIR)/../../phases/phase6-opa/src:/out \
	  openapitools/openapi-generator-cli:v6.6.0 generate \
	  -i /local/openapi.yaml -g python-legacy -o /out/rucio_authz_client-gen \
	  --additional-properties=packageName=rucio_authz_client,compatibleWithPythonLegacy=true,library=urllib3
	mv ../../phases/phase6-opa/src/rucio_authz_client-gen/rucio_authz_client \
	   ../../phases/phase6-opa/src/rucio_authz_client
	rm -rf ../../phases/phase6-opa/src/rucio_authz_client-gen
	python3 scripts/patch_phase6_client.py ../../phases/phase6-opa/src/rucio_authz_client

check-generated: generate-server-stubs generate-client ## Regenerate and fail if it differs from what's committed (mutates working tree)
	@git diff --exit-code -- $(SERVER_STUBS_OUT) $(CLIENT_OUT) \
	  || { echo "::error::generated code is stale — run 'make generate-server-stubs generate-client' and commit"; exit 1; }
	@echo "Generated code is up to date."

lint: venv ## ruff and the import contracts
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests
	$(BIN)/lint-imports

typecheck: venv ## mypy
	$(BIN)/mypy

test: venv ## Unit tests, then integration tests (needs Docker)
	$(BIN)/pytest tests/unit tests/integration

coverage: venv ## Tests with coverage report (needs Docker)
	$(BIN)/pytest tests/unit tests/integration \
	  --cov --cov-report=term-missing --cov-report=xml

demo-client: venv ## poke a running instance via the generated client (needs `make run` up)
	$(BIN)/python scripts/demo_client.py

test-token-exchange: ## exercise the realm.json exchange flow and check required claims
	bash scripts/test_token_exchange.sh

run: venv ## Run locally
	$(BIN)/uvicorn authz_service.main:create_app --factory --reload --port 8000

image: ## Build the container image
	docker build -f docker/Dockerfile -t authz-service:dev .

up: ## Start the service's own dev/test compose stack (OPA + Keycloak)
	$(COMPOSE) up -d

up-observability: ## Dev stack plus collector, Tempo, Loki, Prometheus, Grafana
	$(COMPOSE) --profile observability up -d

down: ## Stop the dev/test compose stack, keeping volumes
	$(COMPOSE) --profile observability down

clean: ## Stop the dev/test compose stack and wipe volumes
	$(COMPOSE) --profile observability down -v
