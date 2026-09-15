FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN addgroup --system gateway && adduser --system --ingroup gateway gateway

COPY python_gateway/requirements.txt /app/python_gateway/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /app/python_gateway/requirements.txt \
    && python -m spacy download en_core_web_sm

COPY python_gateway /app/python_gateway

USER gateway
WORKDIR /app/python_gateway
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/ready', timeout=3).read()"

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
