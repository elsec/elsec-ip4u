# ip4u

A minimal HTTP server that returns the client's IP address as plain text.

## Build

```sh
make
```

## Run

```sh
API_KEY=your-secret-here ./server
```

If `API_KEY` is unset the server starts without authentication (useful for local development).

## Usage

```sh
curl -H "X-API-Key: your-secret-here" http://your-server:8080/
# → 203.0.113.42
```

## Proxy headers

When running behind a reverse proxy the server reads the real client IP from headers in this order:

1. `X-Forwarded-For` (first entry)
2. `X-Real-IP`
3. TCP peer address (fallback)

Example nginx config:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

## Authentication

All requests must include the `X-API-Key` header matching the `API_KEY` environment variable. Requests without a valid key receive `401 Unauthorized`. Requests to any path other than `/` also receive `401 Unauthorized`.

## Logging

Each request is logged to stderr as a JSON object:

```json
{"time":"2026-04-21T12:00:00Z","ip":"203.0.113.42","tcp_ip":"10.0.0.1","path":"/","x_forwarded_for":"203.0.113.42","status":200}
```

## Container

```sh
podman build -f Containerfile -t ip4u .
podman run -e API_KEY=your-secret-here -p 8080:8080 ip4u
```
