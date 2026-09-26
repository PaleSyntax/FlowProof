FROM node:22.14.0-alpine3.21 AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.31.3-alpine3.24
COPY --chown=101:101 --from=build /app/dist /usr/share/nginx/html
ARG VERSION=0.6.0
ARG REVISION=unknown
ARG SOURCE=https://github.com/OWNER/FlowProof
LABEL org.opencontainers.image.source=$SOURCE \
      org.opencontainers.image.revision=$REVISION \
      org.opencontainers.image.version=$VERSION
EXPOSE 8080
