# ip4u

A minimal HTTP server that returns the client's IP address as plain text. Self-host it instead of relying on third-party services like `ifconfig.me`, `ipinfo.io`, or `checkip.amazonaws.com` — your IP lookups stay private and under your control.

## Build

```sh
make
```

## Run

```sh
SECRET_KEY=your-master-secret ./server
```

If `SECRET_KEY` is unset the server starts without authentication (useful for local development).

## Issuing client keys

```sh
SECRET_KEY=your-master-secret ./keygen <client_id>
# → alice:33201d28...
```

Give the output string to the client. They include it as-is in the `X-Client-Key` header.

## Usage

```sh
curl -H "X-Client-Key: alice:33201d28..." http://your-server:8080/
# → 203.0.113.42
```

## Cloudflare mode

Pass `--cloudflare` to use Cloudflare headers for IP resolution and logging:

```sh
SECRET_KEY=your-master-secret ./server --cloudflare
```

In this mode `CF-Connecting-IP` is used as the highest-priority IP source, and `CF-IPCountry` is included in the log. See [Cloudflare's documentation](https://developers.cloudflare.com/fundamentals/reference/http-request-headers/) for details on these headers.

## Proxy headers

When running behind a reverse proxy the server reads the real client IP from headers in this order:

1. `CF-Connecting-IP` (Cloudflare mode only)
2. `X-Forwarded-For` (first entry)
3. `X-Real-IP`
4. TCP peer address (fallback)

Example nginx config:

```nginx
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Real-IP $remote_addr;
```

## Authentication

Client keys are HMAC-SHA256 derived from a master `SECRET_KEY`. The `X-Client-Key` header format is `client_id:hmac_hex`. The server recomputes the HMAC for the given `client_id` and does a constant-time comparison. Requests without a valid key receive `401 Unauthorized`. Requests to any path other than `/` also receive `401 Unauthorized`.

## Logging

Each request is logged to stdout as a JSON object:

```json
{"time":"2026-04-21T12:00:00Z","ip":"203.0.113.42","tcp_ip":"10.0.0.1","path":"/","x_forwarded_for":"203.0.113.42","client_id":"alice","cf_country":"IE","status":200}
```

Optional fields (`x_forwarded_for`, `x_real_ip`, `client_id`, `cf_country`) are omitted when not present.

## Container

Build locally:

```sh
podman build -f Containerfile -t ip4u .
```

Or pull from the registry:

```sh
podman pull ghcr.io/elsec/elsec-ip4u:latest
```

Run (replace `ip4u` with `ghcr.io/elsec/elsec-ip4u:latest` if using the registry image):

```sh
# without Cloudflare
podman run --env-file .env -p 8080:8080 ip4u

# with Cloudflare
podman run --env-file .env -p 8080:8080 ip4u ./server --cloudflare
```

Where `.env` contains:

```
SECRET_KEY=your-master-secret
```

To issue a client key from the container:

```sh
podman run --rm -e SECRET_KEY=your-master-secret ip4u ./keygen alice
# → alice:33201d28...
```
