# syntax=docker/dockerfile:1.7
# --- Build stage ---
FROM golang:1.22-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GO111MODULE=on
# Cache deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
# Copy source
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_TIME
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -X github.com/maggch97/dingtalk-oidc/internal/version.Version=$VERSION -X github.com/maggch97/dingtalk-oidc/internal/version.Commit=$COMMIT -X github.com/maggch97/dingtalk-oidc/internal/version.BuildTime=$BUILD_TIME" -o /out/dingtalk-oidc ./cmd/server

# --- Final stage ---
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=build /out/dingtalk-oidc /app/dingtalk-oidc
EXPOSE 8086
USER nonroot:nonroot
ENV ADDRESS=:8086
LABEL org.opencontainers.image.title="dingtalk-oidc" \
    org.opencontainers.image.source="https://github.com/maggch97/DingTalk_OIDC" \
    org.opencontainers.image.version=$VERSION \
    org.opencontainers.image.revision=$COMMIT
ENTRYPOINT ["/app/dingtalk-oidc"]
