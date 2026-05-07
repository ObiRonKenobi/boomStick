#Requires -Version 5.0
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
docker compose -f tests/compose/docker-compose.yml up -d nginx_cal httpd_cal
Start-Sleep -Seconds 2
$env:BOOMSTICK_RUN_CALIBRATION = "1"
if (-not $env:TEST_NGINX_ORIGIN) { $env:TEST_NGINX_ORIGIN = "http://127.0.0.1:18081" }
if (-not $env:TEST_APACHE_ORIGIN) { $env:TEST_APACHE_ORIGIN = "http://127.0.0.1:18082" }
python -m pytest tests/calibration -q
