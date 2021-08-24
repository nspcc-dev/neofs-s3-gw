
ARG HUB_TAG=latest


FROM nspccdev/neo-go:0.95.4 as neo-go
FROM nspccdev/neofs-aio:0.22.3 as neofs-all

# Executable image
FROM alpine AS neofs-aio
RUN apk add --no-cache \
  bash \
  ca-certificates \
  jq \
  expect \
  iputils

WORKDIR /


COPY ./init-aio.sh /usr/bin/
COPY --from=neo-go /config /config
COPY --from=neo-go /usr/bin/privnet-entrypoint.sh /usr/bin/privnet-entrypoint.sh
COPY --from=neo-go /usr/bin/neo-go /usr/bin/neo-go
COPY --from=neo-go /etc/ssl/certs /etc/ssl/certs
COPY --from=neofs-all /bin/neofs-ir /bin/neofs-ir
COPY --from=neofs-all /bin/neofs-node /bin/neofs-node


ENTRYPOINT ["/usr/bin/init-aio.sh"]
