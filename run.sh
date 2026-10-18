#!/bin/bash
set -e

# Resolve install directory (where this script lives)
APP_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${HLE_DATA_DIR:-/var/lib/hle}"

# Read API key from config file if not set via environment variable
if [ -z "${HLE_API_KEY}" ]; then
    HLE_CONFIG="${DATA_DIR}/hle_config.json"
    if [ -f "${HLE_CONFIG}" ]; then
        HLE_API_KEY=$(python3 -c "import json; print(json.load(open('${HLE_CONFIG}')).get('api_key',''))" 2>/dev/null || echo "")
        export HLE_API_KEY
    fi
fi

if [ -z "${HLE_API_KEY}" ]; then
    echo "[hle] No API key configured. Open the web UI to set one, or set HLE_API_KEY env var."
fi

PORT="${HLE_PORT:-8099}"
# Loopback only by default. Set HLE_BIND_HOST=0.0.0.0 to reach the UI from
# other machines; every route still requires the login token either way.
BIND_HOST="${HLE_BIND_HOST:-127.0.0.1}"
export HLE_DATA_DIR="${DATA_DIR}"
mkdir -p "${DATA_DIR}/logs"

echo "[hle] Starting HLE on ${BIND_HOST}:${PORT}..."
exec python3 -m uvicorn backend.main:app --host "${BIND_HOST}" --port "${PORT}" --app-dir "${APP_DIR}"
