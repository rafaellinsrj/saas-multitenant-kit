.PHONY: install db migrate test lint run

install:
	python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"

db:
	docker compose up -d --wait db

migrate:
	set -a; . ./.env; set +a; .venv/bin/alembic upgrade head

test:
	.venv/bin/pytest -q

lint:
	.venv/bin/ruff check . && .venv/bin/ruff format --check .

run:
	set -a; . ./.env; set +a; .venv/bin/uvicorn app.main:app --reload
