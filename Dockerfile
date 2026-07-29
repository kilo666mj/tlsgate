# Build on the native build platform and cross-compile to the target arch.
# The whole tree is pure Go (CGO disabled), so this needs no emulation.
FROM --platform=$BUILDPLATFORM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

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
