#!/bin/bash

INPUT_FILE=$1
if [ -z "$INPUT_FILE" ]; then
  echo "you must provide file with tests results"
  exit 1
fi

STORAGE=$2
if [ "$STORAGE" != "s3gw" ] && [ "$STORAGE" != "minio" ] && [ "$STORAGE" != "aws" ]; then
  echo "you must specify storage type  [s3gw | minio | aws]"
  exit 1
fi

RESULT_FILE=docs/s3_test_results.md

get_adjusted_result () {
  local OLD_RESULT=$1
  local NEW_RESULT=$2
  local OLD_RESULT_LEN=${#OLD_RESULT}
  local NEW_RESULT_LEN=${#NEW_RESULT}
  local ADDITIONAL_SPACES=$((OLD_RESULT_LEN - NEW_RESULT_LEN))
  printf "%s%*s" "$NEW_RESULT" $ADDITIONAL_SPACES ''
}

while read -r line;
do
  RES_LINE=$(echo "$line" | sed -nE '/^s3tests_boto3/p')
  if [ -n "$RES_LINE" ]
  then
    TEST=$(echo "$RES_LINE" | sed -e 's/[[:space:]]*\.\.\..*//')
    RESULT=$(echo "$RES_LINE" | sed -e 's/^.*\.\.\.[[:space:]]*//')

    # beautify trailing spaces
    OLD_RESULT_S3GW=$(sed -n "s/^.*${TEST}[[:space:]]*|[[:space:]]\(.*\)[[:space:]]|.*|.*|$/\1/p" "$RESULT_FILE")
    OLD_RESULT_MINIO=$(sed -n "s/^.*${TEST}[[:space:]]*|.*|[[:space:]]\(.*\)[[:space:]]|.*|$/\1/p" "$RESULT_FILE")
    OLD_RESULT_AWS=$(sed -n "s/^.*${TEST}[[:space:]]*|.*|.*|[[:space:]]\(.*\)[[:space:]]|$/\1/p" "$RESULT_FILE")

    ADJUSTED_RESULT_S3GW=$(get_adjusted_result "$OLD_RESULT_S3GW" "$RESULT")
    ADJUSTED_RESULT_MINIO=$(get_adjusted_result "$OLD_RESULT_MINIO" "$RESULT")
    ADJUSTED_RESULT_AWS=$(get_adjusted_result "$OLD_RESULT_AWS" "$RESULT")

    if [ "$STORAGE" = "s3gw" ]; then
      sed -i "/UNSUPPORTED/! s/^\(.*${TEST}[[:space:]]*\)|[[:space:]].*[[:space:]]|\(.*\)$/\1| ${ADJUSTED_RESULT_S3GW} | ${OLD_RESULT_MINIO} | ${OLD_RESULT_AWS} |\2/" "$RESULT_FILE"
    elif [ "$STORAGE" = "minio" ]; then
      sed -i "/UNSUPPORTED/! s/^\(.*${TEST}[[:space:]]*\)|[[:space:]].*[[:space:]]|\(.*\)$/\1| ${OLD_RESULT_S3GW} | ${ADJUSTED_RESULT_MINIO} | ${OLD_RESULT_AWS} |\2/" "$RESULT_FILE"
    else
      sed -i "/UNSUPPORTED/! s/^\(.*${TEST}[[:space:]]*\)|[[:space:]].*[[:space:]]|\(.*\)$/\1| ${OLD_RESULT_S3GW} | ${OLD_RESULT_MINIO} | ${ADJUSTED_RESULT_AWS} |\2/" "$RESULT_FILE"
    fi

  fi
done < "$INPUT_FILE"
