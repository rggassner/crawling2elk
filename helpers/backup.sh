#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG="$DIR/../config.py"

# Extract config values from config.py
HOST=$(grep 'ELASTICSEARCH_HOST' "$CONFIG" | cut -d'"' -f2)
PORT=$(grep 'ELASTICSEARCH_PORT' "$CONFIG" | grep -o '[0-9]\+')
USER=$(grep 'ELASTICSEARCH_USER' "$CONFIG" | cut -d"'" -f2)
PASSWORD=$(grep 'ELASTICSEARCH_PASSWORD' "$CONFIG" | cut -d"'" -f2)
INDEX=$(grep 'URLS_INDEX' "$CONFIG" | cut -d"'" -f2)

mapping_file="${INDEX}.mapping.json"
data_file="${INDEX}.data.json"

NODE_TLS_REJECT_UNAUTHORIZED=0 elasticdump \
  --input=https://$USER:$PASSWORD@$HOST:$PORT/$INDEX \
  --output="$mapping_file" \
  --type=mapping

xz -ze9 --stdout < "$mapping_file" > "$INDEX.mapping.json.xz"
rm "$mapping_file"

NODE_TLS_REJECT_UNAUTHORIZED=0 elasticdump \
  --input=https://$USER:$PASSWORD@$HOST:$PORT/$INDEX \
  --output="$data_file" \
  --type=data

xz -ze9 --stdout < "$data_file" > "$INDEX.data.json.xz"
rm "$data_file"
