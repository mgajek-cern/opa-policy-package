# Authorization Service (design-006). Run from this directory or with -C.
#
# The repository Makefile keeps phase concerns; this one keeps the service.

PY ?= python3
VENV ?= .venv
BIN ?= $(VENV)/bin
SPEC := api/openapi.yaml

# Models for the Rucio policy package: pinned generator, Python 3.9 target.
PKG_MODELS ?= ../../phases/phase7-opa/src/rucio_opa_v6_policy/_generated/models.py
SVC_MODELS := src/authz_service/api/generated/models.py

.DEFAULT_GOAL := help

.PHONY: help venv spec-validate generate check-generated lint typecheck test run image

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk -F':.*?## ' '{printf "  %-16s %s\n", $$1, $$2}'

venv: ## Create the dev environment
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q --upgrade pip setuptools wheel
	$(BIN)/pip install -q -e ".[dev]"

spec-validate: ## Validate the OpenAPI contract
	$(BIN)/python -c "import openapi_spec_validator, sys, yaml; \
	openapi_spec_validator.validate(yaml.safe_load(open('$(SPEC)')))"

generate: ## Generate the service and package models from the contract
	@mkdir -p $(dir $(SVC_MODELS)) $(dir $(PKG_MODELS))
	$(BIN)/datamodel-codegen --input $(SPEC) --input-file-type openapi \
	  --output $(SVC_MODELS) --output-model-type pydantic_v2.BaseModel \
	  --target-python-version 3.12 --use-standard-collections --field-constraints
	$(BIN)/datamodel-codegen --input $(SPEC) --input-file-type openapi \
	  --output $(PKG_MODELS) --output-model-type pydantic_v2.BaseModel \
	  --target-python-version 3.9 --use-standard-collections --field-constraints

check-generated: generate ## Fail if the committed models are stale
	git diff --exit-code -- $(SVC_MODELS) $(PKG_MODELS)

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
