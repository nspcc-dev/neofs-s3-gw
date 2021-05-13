FROM golang:1 as builder

WORKDIR /src

RUN set -x \
    && apt update \
    && apt install -y make

COPY . /src

ARG VERSION=dev

RUN make

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /src/bin/neofs-s3-gw /bin/neofs-s3-gw
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT ["/bin/neofs-s3-gw"]
