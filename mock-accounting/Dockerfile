FROM python:3.12.13-slim-bookworm

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock
COPY app ./app

RUN groupadd --system --gid 10001 flowproof \
    && useradd --system --uid 10001 --gid flowproof --home-dir /app --no-create-home flowproof

USER 10001:10001

ARG VERSION=0.6.0
ARG REVISION=unknown
ARG SOURCE=https://github.com/OWNER/FlowProof
LABEL org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.version=$VERSION

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
