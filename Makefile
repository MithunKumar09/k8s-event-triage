PYTHON ?= python3.12
VENV ?= .venv
ifeq ($(OS),Windows_NT)
VPY := $(VENV)/Scripts/python.exe
else
VPY := $(VENV)/bin/python
endif
INPUT ?= test-cases/01-healthy.jsonl
ARGS ?=
PIP_ARGS ?= --index-url https://pypi.org/simple --timeout 120 --retries 3
PYTEST_ARGS ?=
WHEEL ?= $(firstword $(wildcard dist/*.whl))
BENCH_OUTPUT ?= build/benchmark
SOURCE_REVISION ?=

.PHONY: install build test lint typecheck check audit run capture verify-outputs bench docker-build docker-run
install:
	"$(PYTHON)" -m venv "$(VENV)"
	"$(VPY)" -m pip install --require-hashes --only-binary=:all: $(PIP_ARGS) -r requirements-dev.lock
	"$(VPY)" -m pip install --no-deps --no-build-isolation -e .
build:
	"$(VPY)" -m build --wheel --no-isolation
test:
	"$(VPY)" -m pytest $(PYTEST_ARGS)
lint:
	"$(VPY)" -m ruff check .
	"$(VPY)" -m ruff format --check .
typecheck:
	"$(VPY)" -m mypy
check: lint typecheck test
audit:
	"$(VPY)" -m pip_audit --disable-pip --no-deps -r requirements-dev.lock
run:
	"$(VPY)" -m k8s_event_triage "$(INPUT)" $(ARGS)
capture:
	"$(VPY)" scripts/capture_outputs.py --wheel "$(WHEEL)" --source-revision "$(SOURCE_REVISION)" --refresh
verify-outputs:
	"$(VPY)" scripts/capture_outputs.py --wheel "$(WHEEL)" --verify
bench:
	"$(VPY)" scripts/benchmark.py --output "$(BENCH_OUTPUT)"
docker-build:
	docker build -t k8s-event-triage .
docker-run:
	docker run --rm --network none --read-only --mount type=bind,source="$(CURDIR)/test-cases",target=/data,readonly k8s-event-triage /data/01-healthy.jsonl
