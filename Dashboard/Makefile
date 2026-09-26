.PHONY: install backend test lint docker-build docker-up spacy-model

install:
	python -m pip install -r python_gateway/requirements.txt

spacy-model:
	python -m spacy download en_core_web_sm

backend:
	cd python_gateway && python -m uvicorn app:app --reload --host 127.0.0.1 --port 8000

test:
	python -m pytest python_gateway/tests
	node --test tests/rendered-html.test.mjs

lint:
	python -m ruff check python_gateway
	python -m mypy python_gateway

docker-build:
	docker build -t secure-ai-detection-engine .

docker-up:
	docker compose up --build detection-engine
