.PHONY: install test lint security build deploy docker-build docker-run clean all

install:
	pip install --upgrade pip
	pip install -r requirements.txt

test:
	python3 -m pytest tests/ -v --tb=short

lint:
	python3 -m flake8 app.py modules/ tests/ --max-line-length=120

security:
	python3 -m bandit -r modules/ -c .bandit -q

build:
	python3 -c "import py_compile; py_compile.compile('app.py', doraise=True)" && \
	python3 -c "\
	import sys, os; \
	sys.path.insert(0, os.getcwd()); \
	from modules import vault, network_utils, updater, operators, reports, \
	    recon, scope, audit_log, stealth, forensic, throttle, \
	    notifications, exploits, bruteforce, postexploit, \
	    war_exploit, web, database, wireless, network_attacks, utils; \
	print('All modules imported successfully')"

deploy:
	bash deploy_production.sh

docker-build:
	docker build -t blacksentinel-strike:latest .

docker-run:
	bash deploy_docker_production.sh

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .mypy_cache .ruff_cache htmlcov .coverage

all: lint security test build
