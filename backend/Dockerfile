FROM python:3.12.13-slim-bookworm

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY backend/requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY backend/pyproject.toml ./
COPY backend/src ./src
RUN pip install --no-cache-dir --no-build-isolation --no-deps .
COPY backend/alembic.ini ./
COPY backend/migrations ./migrations
COPY specs /app/specs
COPY policies /app/policies
COPY scripts/demo.py /app/scripts/demo.py
COPY scripts/n8n_webhook_smoke.py /app/scripts/n8n_webhook_smoke.py
COPY scripts/scheduler_restart_smoke.py /app/scripts/scheduler_restart_smoke.py

RUN groupadd --system --gid 10001 flowproof \
    && useradd --system --uid 10001 --gid flowproof --home-dir /app --no-create-home flowproof

USER 10001:10001

ARG VERSION=0.6.0
ARG REVISION=unknown
ARG SOURCE=https://github.com/OWNER/FlowProof
LABEL org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.version=$VERSION

CMD ["uvicorn", "flowproof.main:app", "--host", "0.0.0.0", "--port", "8000"]
