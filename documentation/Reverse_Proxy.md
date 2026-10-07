# Running behind a reverse proxy

By default the viewer listens on port 8080 over plain HTTP. That is fine on a
private network, but exposing port 8080 to the internet means your mailcow logs,
and the password that protects them, travel unencrypted.

Putting a reverse proxy in front of it gives you HTTPS, a proper hostname and one
place to control access. If you already run mailcow, **you do not need to install
anything new**: mailcow ships with its own nginx, and it can serve the viewer
using the certificate it already renews for you. That is the first recipe below.

## Before you start: what the proxy has to do

Whichever proxy you use, these things must be right. The proxy configuration in
every example below already includes the first five; the last one is a setting
on the viewer itself, described in
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address).

| Requirement | Why |
|---|---|
| Forward the WebSocket upgrade on `/ws/raw-logs` | The Live Logs page streams over a WebSocket. Without this the page loads but never shows a line |
| A long read timeout on that WebSocket | A quiet mail server sends nothing for minutes. nginx's 60 second default closes the stream and the page reconnects in a loop |
| Send `X-Forwarded-Proto` | The login session cookie is marked `Secure` only when the app knows the request arrived over HTTPS. Without this header the cookie is sent over plain HTTP too |
| Pass the browser's `Host` header | Saving, banning and the other actions are refused (HTTP 403) when the app cannot tell they came from its own page. It compares the page's address with `Host`, or with `X-Forwarded-Host` when the proxy sends it |
| Send `X-Forwarded-For` | The failed-login limit counts each visitor separately only when the app knows their address. The header alone is not enough: see the next row |
| Set `FORWARDED_ALLOW_IPS` on the viewer to the proxy's address | The app reads `X-Forwarded-For` only from a proxy it trusts. Without this, every visitor is counted as the proxy, so ten wrong passwords from anyone block new Basic Auth logins for everyone for 15 minutes |

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

### Let the viewer see each visitor's address

The viewer trusts `X-Forwarded-For` only from the addresses listed in
`FORWARDED_ALLOW_IPS` (by default only `127.0.0.1`, which is never the proxy in a
Docker setup). Add the address the proxy connects from to the viewer's `.env` and
recreate the viewer with `docker compose up -d`:

```dotenv
# Example address only: use the one you find with the commands below.
FORWARDED_ALLOW_IPS=172.22.1.10
```

List exact addresses, separated by commas. The bundled Uvicorn 0.27 does not
accept ranges such as `172.22.1.0/24`. Never use `*`: it would let anyone who can
reach the viewer directly pick the address they are counted as. See
[ENV_Settings.md](ENV_Settings.md#login-attempt-limits-and-reverse-proxies) for
the details.

Which address to use depends on the recipe:

| Recipe | The proxy connects from | Find it with |
|---|---|---|
| 1. mailcow's nginx | The `nginx-mailcow` container's address on the mailcow network | In the mailcow directory: `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' $(docker compose ps -q nginx-mailcow)` |
| 2. nginx on the host, 3. Caddy on the host | The gateway of the viewer's Docker network, because the published `127.0.0.1:8080` reaches the container through it | `docker network inspect -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' <network>`, where `<network>` is the viewer's network from `docker network ls`, for example `mailcow-logs-viewer_mailcow-logs-network` |
| 3. Caddy in a container, 4. Traefik | The proxy container's address on the network it shares with the viewer | `docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' <proxy container>` |

A container's address can change when it is recreated, for example after a
mailcow or proxy update. If `FORWARDED_ALLOW_IPS` no longer matches, logins keep
working; failed attempts are just counted for everyone together again, so check
the address after such updates.

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

### 6. Trust mailcow's nginx in the viewer

Set `FORWARDED_ALLOW_IPS` in the viewer's `.env` to the `nginx-mailcow`
container's address, as described in
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address),
and recreate the viewer with `docker compose up -d`.

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

Then set `FORWARDED_ALLOW_IPS` in the viewer's `.env` to the gateway of the
viewer's Docker network; see
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address).

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

Then set `FORWARDED_ALLOW_IPS` in the viewer's `.env`: to the gateway of the
viewer's Docker network for the first form, or to the Caddy container's address
for the second; see
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address).

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
default read timeout is unlimited, so the log stream stays open. Set
`FORWARDED_ALLOW_IPS` in the viewer's `.env` to the Traefik container's address
on the `traefik` network; see
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address).

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
The viewer counts every login attempt against the proxy's address. Either
`FORWARDED_ALLOW_IPS` is not set to the address the proxy connects from, or that
address changed when a container was recreated, or the proxy does not send
`X-Forwarded-For`. See
[Let the viewer see each visitor's address](#let-the-viewer-see-each-visitors-address).

**Saving settings or running an action fails with 403, "came from another site".**
The proxy does not pass the browser's `Host` header, so the app cannot match the
page's address to its own. With nginx, add `proxy_set_header Host $http_host;`
to every `location` block, as in the recipes above. If the proxy cannot do that,
list the address you open the viewer at in `CORS_ALLOWED_ORIGINS` (for example
`https://logs.example.com`); see [ENV_Settings.md](ENV_Settings.md#cross-site-requests).

**Everything 404s, or the page loads without styling.**
You are serving the viewer under a sub-path. It has to sit at the root of its own
hostname; see the note near the top.
