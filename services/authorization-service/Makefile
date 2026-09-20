# Authorization Service (design-006). Run from this directory or with -C.
#
# The repository Makefile keeps phase concerns; this one keeps the service.

PY ?= python3
VENV ?= .venv
BIN ?= $(VENV)/bin
SPEC := api/openapi.yaml

# Models for the Rucio policy package: pinned generator, Python 3.9 target.
SVC_MODELS := src/authz_service/api/generated/models.py

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

.DEFAULT_GOAL := help

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

venv: ## Create the dev environment
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip setuptools wheel
	$(BIN)/pip install -q -e ".[dev]"

tools: ## Create the isolated env for the route/client generators
	$(PY) -m venv $(TOOLS_VENV)
	$(TOOLS_BIN)/pip install -q --upgrade pip setuptools wheel
	$(TOOLS_BIN)/pip install -q -e ".[codegen]"

spec-validate: ## Validate the OpenAPI contract
	$(BIN)/python -c "import openapi_spec_validator, sys, yaml; \
	openapi_spec_validator.validate(yaml.safe_load(open('$(SPEC)')))"

generate-server-stubs: tools ## Scaffold per-tag server stubs from the contract (reference only, not wired in)
	rm -rf $(SERVER_STUBS_OUT)
	@mkdir -p $(SERVER_STUBS_OUT)
	$(FASTAPI_CODEGEN) --input $(SPEC) --output $(SERVER_STUBS_OUT) \
	  --output-model-type pydantic_v2.BaseModel --python-version 3.12 \
	  --generate-routers
	$(BIN)/ruff format -q $(SERVER_STUBS_OUT)

generate-client: tools ## Generate a standalone typed Python client from the contract
	rm -rf $(CLIENT_OUT)
	@mkdir -p $(dir $(CLIENT_OUT))
	$(OPENAPI_PYTHON_CLIENT) generate --path $(SPEC) \
	  --output-path $(CLIENT_OUT) --meta none --overwrite

lint: ## ruff and the import contracts
	$(BIN)/ruff check src tests
	$(BIN)/ruff format --check src tests
	$(BIN)/lint-imports

typecheck: ## mypy
	$(BIN)/mypy

test: ## Unit tests, then integration tests (needs Docker)
	$(BIN)/pytest tests/unit tests/integration

run: ## Run locally
	$(BIN)/uvicorn authz_service.main:create_app --factory --reload --port 8000

image: ## Build the container image
	docker build -t authz-service:dev .
