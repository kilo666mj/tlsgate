# Build on the native build platform and cross-compile to the target arch.
# The whole tree is pure Go (CGO disabled), so this needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26.4-alpine@sha256:f23e8b227fb4493eabe03bede4d5a32d04092da71962f1fb79b5f7d1e6c2a17f AS build

RUN apk add --no-cache ca-certificates

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

FROM scratch

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/tlsgate /tlsgate

VOLUME ["/var/lib/tlsgate"]

ENTRYPOINT ["/tlsgate"]
CMD ["serve"]
