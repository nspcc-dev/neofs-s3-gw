#!/bin/bash

mkdir -p internal/neofs/services/tree 2>/dev/null

REVISION="d4babb0eb89aff316eca067e219c63a0e2ef349b"

echo "tree service revision ${REVISION}"

FILES=$(curl -s https://github.com/nspcc-dev/neofs-node/tree/${REVISION}/pkg/services/tree | sed -n "s,.*\"/nspcc-dev/neofs-node/blob/${REVISION}/pkg/services/tree/\(.*\.pb\.go\)\".*,\1,p")

for file in $FILES; do
  echo "sync '$file' in tree service"
  curl -s "https://raw.githubusercontent.com/nspcc-dev/neofs-node/${REVISION}/pkg/services/tree/${file}" -o "./internal/neofs/services/tree/${file}"
done
