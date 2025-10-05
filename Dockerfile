# syntax=docker/dockerfile:1.7
# --- Build stage ---
FROM golang:1.25-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GO111MODULE=on
# Cache deps
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
# Copy source
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go build -trimpath -ldflags "-s -w -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" -o /out/dingtalk-oidc ./cmd/server

# --- Final stage ---
FROM gcr.io/distroless/static:nonroot
WORKDIR /app
COPY --from=build /out/dingtalk-oidc /app/dingtalk-oidc
EXPOSE 8086
USER nonroot:nonroot
ENV ADDRESS=:8086
ENTRYPOINT ["/app/dingtalk-oidc"]
