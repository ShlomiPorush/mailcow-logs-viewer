# Reverse proxy

The app serves plain HTTP on port `8080`. To use it outside a private network, put an HTTPS reverse proxy in front of it and turn on [sign-in](OAuth2_Configuration.md).

## What the proxy must do

- Serve the app at the root of its own host name, such as `https://logs.example.com/`. A path such as `https://mail.example.com/logs/` does not work, because the app's pages call `/api`, `/static` and `/ws/raw-logs` from the root.
- Send every path to the app, including page addresses such as `/status/jobs`. Do not let the proxy look for them as files.
- Pass the original `Host` header, including a non-standard port, or set `X-Forwarded-Host` to it. The app rejects changes from a page whose address does not match ("This request came from another site and was rejected", HTTP 403).
- Set `X-Forwarded-Proto` to `https`. The app marks the session cookie `Secure` only when it knows the browser used HTTPS.
- Set `X-Forwarded-For` and tell the app to trust the proxy (see [Trusted proxy addresses](#trusted-proxy-addresses)). Otherwise the failed-login limit counts every visitor as the proxy.
- Forward WebSocket upgrades on `/ws/raw-logs` with a long idle timeout. The **Logs** page streams through it.
- Allow uploads of at least 10 MB. That is the app's limit for an uploaded DMARC or TLS report; a proxy limit of 20 MB leaves room for the upload's overhead.

## Close the direct port

Once the proxy works, visitors should not reach the app on port 8080 directly.

- Proxy on the same host: publish the port on loopback only. In the app's `docker-compose.yml`:

```yaml
services:
  app:
    ports:
      - "127.0.0.1:8080:8080"
```

- Proxy in a container on a shared Docker network: remove the app's `ports` block and point the proxy at `mailcow-logs-app:8080`.

## Trusted proxy addresses

Tell the app which address the proxy connects from. Add it to the app's `.env` and run `docker compose up -d`:

```dotenv
FORWARDED_ALLOW_IPS=192.0.2.10
```

Replace the example address with the real one:

- A proxy container on a shared network: the proxy container's address on that network.
- A proxy on the host that reaches the published port: the gateway address of the app's Docker network.

Look the addresses up instead of guessing; the public server address is usually wrong here:

```sh
docker network ls
docker network inspect <app-network>
docker inspect <proxy-container>
```

Without this setting, the app trusts only `127.0.0.1`. The app's version of Uvicorn accepts a comma-separated list of exact addresses, not ranges such as `172.18.0.0/16`. Do not use `*` if anyone can reach the app without the proxy, because they could then send a made-up address. Container addresses can change when containers are recreated, so check the value again after you change the proxy or the networks. See also [the environment variable reference](ENV_Settings.md#login-attempt-limits-and-reverse-proxies).

## nginx on the host

This recipe assumes nginx reaches the app at `127.0.0.1:8080` and you already have a certificate for `logs.example.com`.

```nginx
server {
    listen 80;
    server_name logs.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name logs.example.com;

    ssl_certificate /etc/letsencrypt/live/logs.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/logs.example.com/privkey.pem;
    client_max_body_size 20m;

    location /ws/raw-logs {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

1. Save the file in nginx's site configuration directory.
2. Run `nginx -t`, then reload nginx.
3. Set `FORWARDED_ALLOW_IPS` to the gateway address of the app's Docker network. nginx connects to `127.0.0.1:8080`, but Docker forwards the published port, so the app sees the connection come from that gateway. See [Trusted proxy addresses](#trusted-proxy-addresses).

## mailcow's nginx

You can also use the nginx and certificate that mailcow already runs.

### Connect the app to mailcow's network

In the app's `docker-compose.yml`, add mailcow's Docker network next to the app's own network, and remove the app's `ports` block:

```yaml
services:
  app:
    networks:
      - mailcow-logs-network
      - mailcow-network

networks:
  mailcow-network:
    external: true
    name: mailcowdockerized_mailcow-network
```

Keep the existing `mailcow-logs-network` definition; the app reaches its database through it. The name of mailcow's network depends on mailcow's Compose project name, so check it with `docker network ls`.

### Add the host name and a server block

<!-- VERIFY: On a real mailcow, confirm that acme-mailcow adds logs.example.com to the certificate and keeps it on renewal. The include paths, listen files and challenge routing were tested with the nginx image of mailcow 2026-09a (ghcr.io/mailcow/nginx:1.30.4-1). -->
Point a DNS record for `logs.example.com` at the mailcow host. In mailcow's `mailcow.conf`, add `logs.example.com` to `ADDITIONAL_SAN` (keep the names already there, separated by commas). Do not add it as another mailcow web interface name; the app gets its own server block.

In the mailcow directory, create `data/conf/nginx/logs-viewer.conf`:

```nginx
server {
    include /etc/nginx/conf.d/listen_plain.active;
    include /etc/nginx/conf.d/listen_ssl.active;
    server_name logs.example.com;

    ssl_certificate /etc/ssl/mail/cert.pem;
    ssl_certificate_key /etc/ssl/mail/key.pem;
    client_max_body_size 20m;
    root /web;

    resolver 127.0.0.11 valid=10s ipv6=off;
    set $logs_viewer http://mailcow-logs-app:8080;

    location ^~ /.well-known/acme-challenge/ {
        allow all;
        default_type "text/plain";
    }

    location /ws/raw-logs {
        if ($scheme = http) { return 301 https://$host$request_uri; }
        proxy_pass $logs_viewer;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location / {
        if ($scheme = http) { return 301 https://$host$request_uri; }
        proxy_pass $logs_viewer;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

Three lines in this block matter for mailcow. `root /web;` lets nginx serve the challenge file that `acme-mailcow` writes for the new name; without it the challenge returns 404 and the name never gets onto the certificate. `resolver` and `set $logs_viewer` make nginx look up the app when a request arrives: with the name written directly in `proxy_pass`, `nginx-mailcow` does not start while the app is down, and mailcow's web interface goes down with it. `ipv6=off` is needed because the app listens on IPv4 only.

### Apply and check

1. Run `docker compose up -d` in the app's directory and in the mailcow directory.
2. In the mailcow directory, run `docker compose exec nginx-mailcow nginx -t`, then `docker compose restart nginx-mailcow`. Browsers show a certificate error until mailcow's certificate includes the new name.
3. Set `FORWARDED_ALLOW_IPS` to the IPv4 address of `nginx-mailcow` on mailcow's network.
4. On mailcow's network, the app may reach mailcow from a different address. Check the allowed IPs of both API keys in mailcow under **System** > **Configuration** > **Access** > **Administrators** > **API**, then click **Validate** next to the read-write key in **Settings** > **Mailcow**.

## Caddy

With Caddy on the host and the app port on loopback:

```caddyfile
logs.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

With Caddy in a container on a shared network, use `reverse_proxy mailcow-logs-app:8080`. Caddy passes WebSockets and the forwarded headers by itself; see its [reverse_proxy directive](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy). Set `FORWARDED_ALLOW_IPS` to the address the app sees Caddy connect from: the gateway address of the app's Docker network when Caddy runs on the host, or the Caddy container's address on the shared network when Caddy runs in a container.

## Traefik

This recipe assumes Traefik already runs with a `websecure` entry point, a certificate resolver named `le` and a shared Docker network named `traefik`. Add the labels and the network to the app in its `docker-compose.yml`, and remove its `ports` block:

```yaml
services:
  app:
    labels:
      - "traefik.enable=true"
      - "traefik.docker.network=traefik"
      - "traefik.http.routers.mailcow-logs.rule=Host(`logs.example.com`)"
      - "traefik.http.routers.mailcow-logs.entrypoints=websecure"
      - "traefik.http.routers.mailcow-logs.tls.certresolver=le"
      - "traefik.http.services.mailcow-logs.loadbalancer.server.port=8080"
    networks:
      - mailcow-logs-network
      - traefik

networks:
  traefik:
    external: true
```

Keep the `mailcow-logs-network` definition for the database. Set `FORWARDED_ALLOW_IPS` to the Traefik container's address on the `traefik` network.

## Check the result

1. Open `https://logs.example.com`, sign in, and reload a page with a nested address such as `/status/jobs`.
2. In the browser's developer tools, check that the `session_id` cookie is marked `Secure`.
3. Save a harmless setting. If it fails with "This request came from another site", the proxy does not pass the host name.
4. Open **Logs** and check that new lines arrive.
5. From another machine, check that the old direct address on port 8080 no longer answers.

`/api/health` needs no sign-in, so monitoring can keep using it through the proxy.

## When a proxy request fails

| Problem | What to check |
| --- | --- |
| HTTP 403 "This request came from another site and was rejected" | `Host` or `X-Forwarded-Host` must match the host name and port in the browser. |
| **Logs** never connects | WebSocket upgrade headers and routing for `/ws/raw-logs`, and the proxy timeouts. |
| Sign-in keeps returning to the login page | That cookies reach the app, `X-Forwarded-Proto`, the OAuth2 callback URL, and session expiry. |
| One visitor's wrong passwords lock out everyone | `X-Forwarded-For`, the proxy's current address and `FORWARDED_ALLOW_IPS`. |
| A report upload fails before it reaches the app | The proxy's body size limit. |
| mailcow rejects a key after a network change | The allowed IPs of both API keys in mailcow. |
| Pages have no styling, or nested addresses return 404 | Serve the app at the root of the host name and send every path to it. |
