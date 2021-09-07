#!/bin/bash

INPUT_FILE=$1
RESULT_FILE=docs/s3_test_results.md

while read -r line;
do
  RES_LINE=$(echo "$line" | sed -nE '/^s3tests_boto3/p')
  if [ -n "$RES_LINE" ]
  then
    TEST=$(echo "$RES_LINE" | sed -e 's/[[:space:]]*\.\.\..*//')
    RESULT=$(echo "$RES_LINE" | sed -e 's/^.*\.\.\.[[:space:]]*//')

    # beautify trailing spaces
    OLD_RESULT=$(sed -n "s/^.*${TEST}[[:space:]]*|[[:space:]]\(.*\)[[:space:]]|.*|$/\1/p" "$RESULT_FILE")
    OLD_RESULT_LEN=${#OLD_RESULT}
    RESULT_LEN=${#RESULT}
    ADDITIONAL_SPACES=$((OLD_RESULT_LEN - RESULT_LEN))
    ADJUSTED_RESULT=$(printf "%s%*s" "$RESULT" $ADDITIONAL_SPACES '')

    sed -i "/UNSUPPORTED/! s/^\(.*${TEST}[[:space:]]*\)|[[:space:]].*[[:space:]]|\(.*|\)$/\1| ${ADJUSTED_RESULT} |\2/" "$RESULT_FILE"
  fi
done < "$INPUT_FILE"
