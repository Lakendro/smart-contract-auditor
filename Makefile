.PHONY: help install test audit clean format lint

help:
	@echo "Smart Contract Auditor - Available Commands"
	@echo "============================================"
	@echo "make install     - Install dependencies"
	@echo "make test        - Run all tests"
	@echo "make audit       - Run audit on example contracts"
	@echo "make clean       - Clean generated files"
	@echo "make format      - Format code with black"
	@echo "make lint        - Run code linting"
	@echo "make coverage    - Run tests with coverage"

install:
	pip install -r requirements.txt
	pip install -e .

test:
	python -m pytest tests/ -v

audit:
	python src/auditor.py examples/VulnerableContract.sol
	python src/auditor.py examples/SecureContract.sol

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".coverage" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "htmlcov" -exec rm -rf {} + 2>/dev/null || true
	rm -rf reports/*.html reports/*.json reports/*.md 2>/dev/null || true

format:
	black src/ tests/
	isort src/ tests/

lint:
	flake8 src/ tests/
	mypy src/

coverage:
	python -m pytest tests/ --cov=src --cov-report=html --cov-report=term

all: install test audit
