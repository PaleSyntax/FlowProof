.PHONY: up down test lint demo workflows

up:
	docker compose up --build

down:
	docker compose down --volumes

test:
	cd backend && python -m pytest

lint:
	cd backend && python -m ruff check src tests

demo:
	docker compose run --rm demo

workflows:
	python scripts/validate_workflows.py
