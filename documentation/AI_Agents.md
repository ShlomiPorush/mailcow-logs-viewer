# AI agents

An AI agent such as Claude Code or Codex can read what the app shows and, if you allow it, act on the mail server. The agent connects over [MCP](https://modelcontextprotocol.io). It never gets a password or a key. Instead it opens a page in your browser, where you choose which areas it may view or act in, and for how long.

## Turn on agent access

Agent access is off by default. It needs three things:

- Sign-in is on: Basic authentication, OAuth2, or both. See [Sign-in configuration](OAuth2_Configuration.md).
- **App address for agents** (`AGENT_ACCESS_URL`) is the address agents reach the app at, such as `https://logs.example.com`. It must be `https` and have no path. An `http` address works only on `localhost` or `127.0.0.1`, for a local test. If the field is empty when you turn **Agent access** on in Settings, Settings fills it in. It takes the address from the **OAuth2 Redirect URI**, or else from the address of the page you have open. Change it if agents reach the app at another address.
- **Agent access** (`AGENT_ACCESS_ENABLED`) is on.

The switch and the address are in **Settings** > **Agents**. Until all three are set, every agent address answers 404, and **Settings** > **Agents** shows what is missing.

## Connect an agent

1. Add the app to the agent with the command from **Settings** > **Agents**:

	```
	claude mcp add --transport http mailcow https://logs.example.com/mcp
	codex mcp add mailcow --url https://logs.example.com/mcp
	```

2. The agent opens a page in your browser. If it does not, run `claude mcp login mailcow` or `codex mcp login mailcow`.
3. Sign in if the app asks you to.
4. Check **Who is asking**. **Details published by claude.ai** means the agent's description came from that site. The app cannot check which program on your computer is asking, so continue only if you just started the connection yourself.
5. Choose **View** or **Act** for each area. **Act** includes **View**. The agent may ask for areas, but **Act** always starts off.
6. Choose the period, up to **Longest period (days)** (`AGENT_ACCESS_MAX_DAYS`, 90 by default), and click **Allow**.

The browser goes back to the agent, and the agent shows as connected in **Settings** > **Agents**.

## What an agent can do

The agent sees four tools. `get_access` tells it what it may do. `list_endpoints` lists the app's API calls in its areas. `read_api` runs a call that only reads. `perform_action` runs a call that changes something, and appears only when the connection has **Act** somewhere.

The areas follow the menu: Dashboard & Status, Messages, Outbound, Quarantine, Security, Rspamd, DMARC & TLS, Domains, Mailboxes, Logs, and Settings. A call outside the connection's areas fails and tells the agent which permission is missing.

An agent can never do the following, whatever the connection allows:

- Changing settings, including sign-in and agent access.
- Running background jobs by hand.
- Uploading files, such as DMARC reports or a suppression list.
- Adding, changing, or testing notification destinations.
- Reading passwords and keys. An agent sees them masked in **Settings**, as you do on the page.
- Managing agents.

DNS checks run only for the mail server's own domains.

## Keep agents safe

Much of what the app shows comes from strangers, such as subjects, sender names, log lines, and report contents. A message can contain text that tries to give an agent instructions. The app tells every agent to treat that text as data, but the agent decides what it does. Give **Act** only where you need it, for the shortest period, and use an agent that asks you before it acts.

## Disconnect an agent

**Settings** > **Agents** lists each agent with its areas, who approved it, when it ends and when it last worked. **Activity** shows its recent calls. **Disconnect** ends a connection at once. **Disconnect all** ends every connection.

A connection also ends:

- At the end of its period.
- When the agent revokes its own access.
- When a sign-in setting changes, such as the password or the OAuth2 provider. This happens whether you change it on the Settings page or in `.env`, and changing it back does not bring the connections back.

Turning **Agent access** off stops every agent at once. So does a new **App address for agents**, because each connection works only with the address it was made for. Connections whose period has not ended work again when you turn access back on or return to the old address.
