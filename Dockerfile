FROM golang:1 as builder

WORKDIR /src

RUN set -x \
    && apt update \
    && apt install -y make

COPY . /src

ARG REPO=github.com/nspcc-dev/neofs-s3-gw
ARG VERSION=dev

RUN set -x && make -o dep # run make without dep dependency

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /src/bin/neofs-s3-gw /bin/neofs-s3-gw
COPY --from=builder /src/bin/neofs-authmate /bin/neofs-authmate
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/bin/neofs-s3-gw"]
