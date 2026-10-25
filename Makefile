# PrufGate Makefile

IMAGE_NAME ?= prufgate:latest

.PHONY: help build test self-check lint check review clean

help:
	@echo "PrufGate targets:"
	@echo "  make check       - Run prufgate check on changed files"
	@echo "  make review      - Run the ./prufgate.sh gate on changed files (SARIF + Markdown)"
	@echo "  make self-check  - Run the built-in fixtures of all six engines"
	@echo "  make test        - Run all self-checks and unit test suites"
	@echo "  make lint        - Run Ruff on Python modules and ShellCheck on scripts"
	@echo "  make build       - Build the PrufGate Docker image (local only, never pushed)"
	@echo "  make clean       - Clean temporary raw report artifacts"

check:
	python3 prufgate/cli.py check --changed

review:
	./prufgate.sh fast

self-check:
	python3 prufgate/cli.py --self-check

test:
	python3 prufgate/cli.py --self-check
	python3 -m unittest discover -s tests
	python3 -m compileall -q prufgate

lint:
	@command -v ruff >/dev/null 2>&1 && ruff check --config configs/ruff.toml prufgate/ tests/ || echo "ruff not found, skipping"
	@command -v shellcheck >/dev/null 2>&1 && shellcheck install.sh runners/*.sh prufgate.sh entrypoint.sh bin/prufgate || echo "shellcheck not found, skipping"

build:
	docker build -t $(IMAGE_NAME) -f Dockerfile .

clean:
	rm -rf reports/raw/*
