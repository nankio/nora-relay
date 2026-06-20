FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o relay ./cmd/relay
# /migrate is a one-off Postgres->SQLite importer, run as a temporary Fly machine
# with the volume mounted (see README). Bundled so it shares the relay's image.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o migrate ./cmd/migrate

FROM scratch
COPY --from=builder /app/relay /relay
COPY --from=builder /app/migrate /migrate
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
EXPOSE 8080
ENTRYPOINT ["/relay"]
