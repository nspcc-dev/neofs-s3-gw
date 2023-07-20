FROM golang:1.20 as builder

ARG BUILD=now
ARG REPO=github.com/nspcc-dev/neofs-s3-gw
ARG VERSION=dev

WORKDIR /src
COPY . /src

RUN make

# Executable image
FROM scratch

WORKDIR /

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/bin/neofs-s3-gw /bin/neofs-s3-gw
COPY --from=builder /src/bin/neofs-s3-authmate /bin/neofs-s3-authmate

ENTRYPOINT ["/bin/neofs-s3-gw"]
