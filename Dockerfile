FROM golang:1.22-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o dls .

FROM scratch
COPY --from=builder /build/dls /dls
VOLUME ["/app/cert", "/app/db"]
EXPOSE 443
ENV DLS_URL=localhost \
    DLS_PORT=443 \
    CERT_DIR=/app/cert \
    DB_DSN=/app/db/db.sqlite
ENTRYPOINT ["/dls"]
