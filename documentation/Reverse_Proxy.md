# Running behind a reverse proxy

By default the viewer listens on port 8080 over plain HTTP. That is fine on a
private network, but exposing port 8080 to the internet means your mailcow logs,
and the password that protects them, travel unencrypted.

Putting a reverse proxy in front of it gives you HTTPS, a proper hostname and one
place to control access. If you already run mailcow, **you do not need to install
anything new**: mailcow ships with its own nginx, and it can serve the viewer
using the certificate it already renews for you. That is the first recipe below.

## Before you start: what the proxy has to do

Whichever proxy you use, four things must be right. Every example below already
includes them.

| Requirement | Why |
|---|---|
| Forward the WebSocket upgrade on `/ws/raw-logs` | The Live Logs page streams over a WebSocket. Without this the page loads but never shows a line |
| A long read timeout on that WebSocket | A quiet mail server sends nothing for minutes. nginx's 60 second default closes the stream and the page reconnects in a loop |
| Send `X-Forwarded-Proto` | The login session cookie is marked `Secure` only when the app knows the request arrived over HTTPS. Without this header the cookie is sent over plain HTTP too |
| Send `X-Forwarded-For` | Used for the failed-login rate limit. Without it every request looks like it came from the proxy, so one attacker locks out everyone |

### Give the viewer a hostname of its own

The viewer must be served from the root of a hostname, for example
`https://logs.example.com/`. **Serving it under a sub-path such as
`https://mail.example.com/logsviewer/` does not work.** The web interface asks for
`/api/...`, `/static/...` and `/ws/raw-logs` as absolute paths, so under a
sub-path every one of those requests would land on the wrong place. A sub-path
option may come later; for now, use a subdomain.

A subdomain costs nothing: point a DNS record at the same server, and with mailcow
the certificate is handled for you (see below).

### Close port 8080 to the world

Once the proxy is in front, the viewer should no longer be reachable directly.
In the viewer's `docker-compose.yml`, bind the port to localhost:

```yaml
    ports:
      - "127.0.0.1:8080:8080"
```

Or, when the proxy reaches the container over a Docker network (the mailcow
recipe below), remove the `ports:` block entirely.

---

## Recipe 1: mailcow's own nginx (recommended)

mailcow already runs nginx and already renews certificates. Adding the viewer to
it takes three small edits and no extra software.

These steps use the two mechanisms mailcow documents for this: a custom site file
in `data/conf/nginx/`, and `ADDITIONAL_SAN` for the certificate.

### 1. Point a DNS record at your server

Create an `A` record (and `AAAA` if you use IPv6) for `logs.example.com` pointing
at the same address as your mailcow host.

### 2. Let mailcow put that name on its certificate

In `mailcow.conf`, add the name to `ADDITIONAL_SAN`. Keep any names that are
already there, separate with commas, and do not add spaces:

```
ADDITIONAL_SAN=logs.example.com
```

Do **not** add it to `ADDITIONAL_SERVER_NAMES`. That setting is for names that
should serve the mailcow interface itself; this one serves the viewer.

Apply it from the mailcow directory:

```bash
docker compose up -d
```

### 3. Let mailcow's nginx reach the viewer

The two stacks are separate, so nginx cannot see the viewer container yet. Attach
the viewer to mailcow's network by adding this to the viewer's
`docker-compose.yml`:

```yaml
services:
  app:
    # ... existing configuration ...
    # Remove or comment out the ports block: the proxy reaches the container
    # over the Docker network, and nothing needs to be published on the host.
    networks:
      - mailcow-logs-network
      - mailcow-network

networks:
  # ... existing mailcow-logs-network ...
  mailcow-network:
    external: true
    name: mailcowdockerized_mailcow-network
```

Confirm the network name first, because it follows the folder mailcow was
installed in:

```bash
docker network ls | grep mailcow
```

If your mailcow lives in `/opt/mailcow-dockerized`, the name is
`mailcowdockerized_mailcow-network`. Then recreate the viewer:

```bash
docker compose up -d
```

### 4. Add the site to mailcow's nginx

In the mailcow directory, create `data/conf/nginx/logs-viewer.conf`:

```nginx
server {
  ssl_certificate /etc/ssl/mail/cert.pem;
  ssl_certificate_key /etc/ssl/mail/key.pem;
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_prefer_server_ciphers on;
  ssl_session_cache shared:SSL:50m;
  ssl_session_timeout 1d;
  ssl_session_tickets off;

  include /etc/nginx/conf.d/listen_plain.active;
  include /etc/nginx/conf.d/listen_ssl.active;

  server_name logs.example.com;
  server_tokens off;
  client_max_body_size 0;

  # Keep certificate renewal working for this name
  location ^~ /.well-known/acme-challenge/ {
    allow all;
    default_type "text/plain";
  }

  if ($scheme = http) {
    return 301 https://$host$request_uri;
  }

  # The Live Logs stream. Needs the WebSocket upgrade and a long timeout,
  # because a quiet server can send nothing for several minutes.
  location /ws/raw-logs {
    proxy_pass http://mailcow-logs-app:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
  }

  location / {
    proxy_pass http://mailcow-logs-app:8080;
    proxy_http_version 1.1;
    proxy_set_header Host $http_host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
```

`mailcow-logs-app` is the container name from the viewer's `docker-compose.yml`.
If you renamed it, use your own name here.

### 5. Restart nginx

```bash
docker compose restart nginx-mailcow
```

Open `https://logs.example.com`. If nginx refuses to start, check the file with
`docker compose logs nginx-mailcow`.

---

## Recipe 2: a standalone nginx on the host

For a server where nginx is installed directly and the viewer is published on
`127.0.0.1:8080`.

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name logs.example.com;

    ssl_certificate     /etc/letsencrypt/live/logs.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/logs.example.com/privkey.pem;

    location /ws/raw-logs {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

server {
    listen 80;
    listen [::]:80;
    server_name logs.example.com;
    return 301 https://$host$request_uri;
}
```

---

## Recipe 3: Caddy

Caddy obtains and renews the certificate on its own, and forwards WebSockets and
the `X-Forwarded-*` headers without extra configuration.

```caddyfile
logs.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

If the viewer runs as a container on a network Caddy can reach, use the container
name instead:

```caddyfile
logs.example.com {
    reverse_proxy mailcow-logs-app:8080
}
```

---

## Recipe 4: Traefik

Labels on the viewer's `app` service. This assumes Traefik is already running
with a `websecure` entrypoint and a certificate resolver named `le`.

```yaml
services:
  app:
    # ... existing configuration ...
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.mailcow-logs.rule=Host(`logs.example.com`)"
      - "traefik.http.routers.mailcow-logs.entrypoints=websecure"
      - "traefik.http.routers.mailcow-logs.tls.certresolver=le"
      - "traefik.http.services.mailcow-logs.loadbalancer.server.port=8080"
    networks:
      - mailcow-logs-network
      - traefik

networks:
  # ... existing mailcow-logs-network ...
  traefik:
    external: true
```

Traefik forwards WebSockets and sets the `X-Forwarded-*` headers itself. Its
default read timeout is unlimited, so the log stream stays open.

---

## After the proxy is in place

- **Turn on authentication** if you have not already. A viewer reachable from the
  internet without a password exposes every log line and every mailbox name. Set
  `BASIC_AUTH_ENABLED=true` with `AUTH_USERNAME` and `AUTH_PASSWORD`, or configure
  OAuth2. See `ENV_Settings.md`.
- **Set `SESSION_SECRET_KEY`** to a long random value. Without it the key is
  generated at startup, so every restart signs everyone out.
- **Check that port 8080 is closed** from outside: `curl http://your-server-ip:8080`
  from another machine should fail.

## Troubleshooting

**The Live Logs page stays empty, or reconnects every minute.**
The WebSocket is not getting through. Confirm the `/ws/raw-logs` location exists
in your proxy configuration, that it sets the `Upgrade` and `Connection` headers,
and that the read timeout is longer than a minute.

**Logging in appears to work, but every page bounces back to the login screen.**
The session cookie is not coming back. This is almost always a missing
`X-Forwarded-Proto` header: the app then treats the request as plain HTTP. Add it
to the `location /` block.

**The failed-login lockout triggers for everyone at once.**
`X-Forwarded-For` is missing, so every login attempt is attributed to the proxy's
own address. Add the header.

**Everything 404s, or the page loads without styling.**
You are serving the viewer under a sub-path. It has to sit at the root of its own
hostname; see the note near the top.
