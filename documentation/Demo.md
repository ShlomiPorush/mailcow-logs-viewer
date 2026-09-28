# Public demo

The demo image lets people try mailcow Logs Viewer before installing it. It
runs the real application with a week of fictional mail traffic, and it cannot
reach any mail server or any other host on the internet.

It is a separate image, `ghcr.io/shlomiporush/mailcow-logs-viewer:demo`
(and `X.Y.Z-demo` for a given release), built from the same code as the
regular image. The regular image does not contain any of the demo code.

## What visitors see

- Every page filled with a fictional company: three hosted domains and an
  alias domain, mailboxes, aliases, a mail queue, quarantine, fail2ban bans,
  Rspamd maps, DNS checks, blocklist results, DMARC and TLS reports, rate
  limits, suppressions and a security alert.
- New mail and log lines every minute, so the dashboard, Messages and Live
  Logs keep moving.
- A notice at the top of every page that the data is fictional, with a link
  to the installation guide. `DEMO_PREVIEW_LABEL` adds a short label next to
  it, for example `DEMO_PREVIEW_LABEL="v3 preview"` while the demo runs a
  version that is not released yet. It is empty by default.

All names are reserved example names (`example.com`, `example.org`,
`example.net`) or `.test` domains, and every address is from the
documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).

## What visitors can change

Almost everything. Actions work the way they do on a real server: releasing a
quarantined message removes it, a ban shows up in fail2ban, a saved setting
applies. Every visitor sees every change until the nightly reset.

A few settings are fixed by the image and shown as locked in Settings,
because changing them would hurt the other visitors rather than show them
something: Basic Auth and OAuth2 (they would lock everyone out), the logo URL
(every browser would load an outside image), and the retention, fetch and
export limits.

Writes are capped at 30 per minute per visitor and 300 per minute in total.
A visitor over the cap gets a message to wait a moment. Pages and reads are
not limited.

## Every night at 00:00

At 00:00 in the container's time zone (`TZ`) the demo rebuilds itself: every
change is dropped and a fresh week of history is generated. This takes about
half a minute, during which the demo does not answer. The same happens on
every start.

The demo empties its database on every start. It refuses to start against a
database that holds tables it did not create, so it cannot wipe a real
database by mistake. Give it an empty database of its own; the compose file
below keeps it in memory.

## Run it

```bash
curl -O https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/docker-compose-demo.yml
TZ=Europe/Berlin docker compose -f docker-compose-demo.yml up -d
```

The demo listens on `127.0.0.1:8090` (change it with `DEMO_PORT`). It needs
no `.env`: the image carries every other setting.

Nothing else is needed on the host. The demo does not connect to mailcow,
DNS, SMTP, IMAP, GitHub or MaxMind; each of those is answered by a fake inside
the container, and a network guard blocks any connection that is not to the
database.

## Publish it with Cloudflare

Expose the demo through a Cloudflare Tunnel rather than an open port. Then
Cloudflare stops bot traffic before it reaches the container, and the demo's
per-visitor write cap can trust the visitor address Cloudflare sends
(`CF-Connecting-IP`). With an open port, a client could send any address in
that header and only the global cap would hold.

1. In Cloudflare Zero Trust, create a tunnel and copy its token.
2. Add a public hostname for the tunnel, for example `demo.example.com`, with
   the service `http://demo-app:8080`.
3. Start the demo with the tunnel profile:

   ```bash
   CLOUDFLARE_TUNNEL_TOKEN=<token> TZ=Europe/Berlin \
     docker compose -f docker-compose-demo.yml --profile tunnel up -d
   ```

4. In the Cloudflare dashboard for the zone, add a WAF custom rule:
   - Expression: `(http.host eq "demo.example.com")`
   - Action: **Managed Challenge**

   Visitors pass it once per session, bots do not.
5. Optional: add a rate limiting rule for writes, for example
   `(http.host eq "demo.example.com" and http.request.method ne "GET")`,
   counted per IP, to drop floods before they reach the container.

Keep the demo's port bound to `127.0.0.1` (the default) so the tunnel is the
only way in.

## Link to it

Once the demo is published, link to its hostname from the README.
