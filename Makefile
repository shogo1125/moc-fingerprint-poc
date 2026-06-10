.PHONY: test build deploy local

test:
	cd lambda && python3 -m venv .venv 2>/dev/null || true
	cd lambda && .venv/bin/pip install -q -r requirements.txt pytest
	cd lambda && .venv/bin/pytest test_local.py -v

build:
	sam build -t infra/template.yaml

deploy:
	./scripts/deploy.sh

local:
	./scripts/local-dev.sh

security-check:
	cd lambda && .venv/bin/python security_check.py
