#!/bin/bash

mkdir -p internal/neofs/services/tree 2>/dev/null

REVISION="1678fe44ed2bdac1c3ae3421d2cc500c2be87a98"

echo "tree service revision ${REVISION}"

FILES=$(curl -s https://github.com/nspcc-dev/neofs-node/tree/${REVISION}/pkg/services/tree | sed -n "s,.*\"/nspcc-dev/neofs-node/blob/${REVISION}/pkg/services/tree/\(.*\.pb\.go\)\".*,\1,p")

for file in $FILES; do
  if [[ $file == *"neofs"* ]]; then
    echo "skip '$file'"
    continue
  else
    echo "sync '$file' in tree service"
  fi
  curl -s "https://raw.githubusercontent.com/nspcc-dev/neofs-node/${REVISION}/pkg/services/tree/${file}" -o "./internal/neofs/services/tree/${file}"
done
