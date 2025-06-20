#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONFIG="$DIR/../config.py"

# Extract config values from config.py
HOST=$(grep 'ELASTICSEARCH_HOST' "$CONFIG" | cut -d'"' -f2)
PORT=$(grep 'ELASTICSEARCH_PORT' "$CONFIG" | grep -o '[0-9]\+')
USER=$(grep 'ELASTICSEARCH_USER' "$CONFIG" | cut -d"'" -f2)
PASSWORD=$(grep 'ELASTICSEARCH_PASSWORD' "$CONFIG" | cut -d"'" -f2)
INDEX=$(grep 'URLS_INDEX' "$CONFIG" | cut -d"'" -f2)

# Append "-restore" to avoid overwriting
RESTORE_INDEX="${INDEX}-restore"

# Decompress mapping and data files
xz -d --stdout "${INDEX}.mapping.json.xz" > "${RESTORE_INDEX}.mapping.json"
xz -d --stdout "${INDEX}.data.json.xz" > "${RESTORE_INDEX}.data.json"

# Restore mapping
NODE_TLS_REJECT_UNAUTHORIZED=0 elasticdump \
  --input="${RESTORE_INDEX}.mapping.json" \
  --output="https://$USER:$PASSWORD@$HOST:$PORT/$RESTORE_INDEX" \
  --type=mapping

# Restore data
NODE_TLS_REJECT_UNAUTHORIZED=0 elasticdump \
  --input="${RESTORE_INDEX}.data.json" \
  --output="https://$USER:$PASSWORD@$HOST:$PORT/$RESTORE_INDEX" \
  --type=data

# Cleanup temp files
rm "${RESTORE_INDEX}.mapping.json"
rm "${RESTORE_INDEX}.data.json"

echo "Successfully restored to index: $RESTORE_INDEX"
