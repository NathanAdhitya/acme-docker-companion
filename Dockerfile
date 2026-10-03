# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/acmed ./cmd/acmed \
 && mkdir -p /out/data

# Test-only image: the product image is distroless and has no shell, but the
# end-to-end stack needs one for the `exec` DNS-01 provider. Built with
# `docker build --target test`.
FROM alpine:3.20 AS test
RUN apk add --no-cache bash curl
COPY --from=build /out/acmed /acmed
ENTRYPOINT ["/acmed"]
CMD ["run"]

# Default (product) image: distroless static, root by default so the manager
# can write into host-owned certificate directories. See README for the
# hardened non-root variant and FILE_UID/FILE_GID/FILE_MODE.
FROM gcr.io/distroless/static-debian12:latest AS final

COPY --from=build /out/acmed /acmed
COPY --from=build --chown=0:0 /out/data /data

WORKDIR /
USER 0:0
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/acmed", "healthcheck"]

ENTRYPOINT ["/acmed"]
CMD ["run"]
