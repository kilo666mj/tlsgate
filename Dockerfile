# Build on the native build platform and cross-compile to the target arch.
# The whole tree is pure Go (CGO disabled), so this needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS build

RUN apk add --no-cache --upgrade ca-certificates

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
	-trimpath \
	-ldflags="-s -w -extldflags '-static' -X main.version=${VERSION}" \
	-o /out/tlsgate .
RUN mkdir -p /data

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/tlsgate /tlsgate
COPY --from=build --chown=65532:65532 /data /var/lib/tlsgate

USER 65532:65532
VOLUME ["/var/lib/tlsgate"]

ENTRYPOINT ["/tlsgate"]
CMD ["serve"]
