FROM golang:1 as builder

WORKDIR /src

RUN set -x \
    && apt update \
    && apt install -y upx-ucl

COPY . /src

ARG VERSION=dev

# https://github.com/golang/go/wiki/Modules#how-do-i-use-vendoring-with-modules-is-vendoring-going-away
# go build -mod=vendor
# The -gcflags "all=-N -l" flag helps us get a better debug experience
RUN set -x \
    && export BUILD=$(date -u +%s%N) \
    && export REPO=$(go list -m) \
    && export LDFLAGS="-X ${REPO}/misc.Version=${VERSION} -X ${REPO}/misc.Build=${BUILD}" \
    && export GOGC=off \
    && export CGO_ENABLED=0 \
    && [ -d "./vendor" ] || go mod vendor \
    && go build \
      -v \
      -mod=vendor \
      -trimpath \
      -ldflags "${LDFLAGS} -X main.Build=$(date -u +%s%N) -X main.Prefix=S3_GW" \
      -o /go/bin/neofs-s3 ./cmd/gate \
    && upx -3 /go/bin/neofs-s3

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /go/bin/neofs-s3 /usr/bin/neofs-s3
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Run delve
CMD ["/usr/bin/neofs-s3"]
