#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
docker compose -f tests/compose/docker-compose.yml up -d nginx_cal httpd_cal
sleep 2
export BOOMSTICK_RUN_CALIBRATION=1
export TEST_NGINX_ORIGIN="${TEST_NGINX_ORIGIN:-http://127.0.0.1:18081}"
export TEST_APACHE_ORIGIN="${TEST_APACHE_ORIGIN:-http://127.0.0.1:18082}"
python -m pytest tests/calibration -q "$@"
