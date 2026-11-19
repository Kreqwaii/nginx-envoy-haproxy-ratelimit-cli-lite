# nginx-envoy-haproxy-ratelimit-cli-lite

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Offline reverse-proxy security & reliability linter for **Nginx** (`nginx.conf`), **HAProxy** (`haproxy.cfg`), and **Envoy** (`envoy.yaml`).  
Офлайн-линтер безопасности и надёжности для конфигов **Nginx**, **HAProxy** и **Envoy** на чистом Python 3.9+ (без внешних зависимостей).

## Quick Start / Быстрый старт

```bash
# Lint a single Nginx config (Markdown output)
python proxy_lint.py samples/nginx_weak.conf

# Lint multiple configs with JSON output and CI gate
python proxy_lint.py samples/nginx_weak.conf samples/haproxy_weak.cfg samples/envoy_weak.yaml --format json --fail-on HIGH

# Force proxy type
python proxy_lint.py custom.conf --type nginx --fail-on CRITICAL
```

## Rules / Правила проверки

| Rule ID | Proxy | Severity | Description |
| --- | --- | --- | --- |
| `NGX001` | Nginx | CRITICAL | Deprecated `TLSv1` / `TLSv1.1` in `ssl_protocols` |
| `NGX002` | Nginx | MEDIUM | Missing `server_tokens off;` |
| `NGX003` | Nginx | HIGH | Missing `Strict-Transport-Security`, `X-Content-Type-Options`, or `X-Frame-Options` |
| `NGX004` | Nginx | HIGH | API location (`/api`) without `limit_req_zone` / `limit_req` |
| `NGX005` | Nginx | MEDIUM | `proxy_pass` without `proxy_connect_timeout` / `proxy_read_timeout` |
| `NGX006` | Nginx | MEDIUM | `proxy_pass` without `proxy_set_header Host` |
| `NGX007` | Nginx | CRITICAL | Wildcard CORS `*` combined with `Access-Control-Allow-Credentials true` |
| `NGX008` | Nginx | LOW | Missing `gzip on;` or `brotli on;` compression |
| `HAP001` | HAProxy | CRITICAL | Deprecated `TLSv1` / `TLSv1.1` (`force-tlsv10`, `ssl-min-ver TLSv1`) |
| `HAP002` | HAProxy | MEDIUM | Missing `option httplog` |
| `HAP003` | HAProxy | HIGH | Missing `timeout connect`, `timeout client`, or `timeout server` |
| `HAP004` | HAProxy | HIGH | Missing `stick-table` rate-limiting policy |
| `HAP005` | HAProxy | MEDIUM | Missing `Strict-Transport-Security` response header |
| `ENV001` | Envoy | CRITICAL | Deprecated `TLSv1_0` / `TLSv1_1` in `tls_params` |
| `ENV002` | Envoy | HIGH | Missing `ratelimit` / `local_ratelimit` HTTP filter |
| `ENV003` | Envoy | MEDIUM | Envoy cluster missing `connect_timeout` |
| `ENV004` | Envoy | CRITICAL | Wildcard CORS `*` combined with `allow_credentials: true` |
| `ENV005` | Envoy | LOW | Missing `compressor` / `gzip` HTTP filter |

## Need the full Pro Studio?

Need the full Pro Studio (Web UI, cache-key & upstream circuit-breaker audit, SARIF 2.1.0, baseline diff)?  
Нужна полная Pro-версия (Web UI, аудит cache-key и circuit-breaker, экспорт SARIF 2.1.0, baseline diff)?

👉 **[Get Pro Studio on FunPay](https://funpay.com/users/20096179/)**
