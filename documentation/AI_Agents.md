# AI agents

An AI agent such as Claude Code or Codex can read what the app shows and, if you allow it, take action on the mail server. The agent connects over [MCP](https://modelcontextprotocol.io). It never gets a password or a key. Instead it opens a page in your browser, where you choose which areas it may view or take action in, and for how long.

## Turn on agent connections

Agent connections are off by default. They need three things:

- Sign-in is on: Basic Auth, OAuth2, or both. See [Sign-in configuration](OAuth2_Configuration.md).
- **App URL** (`AGENT_ACCESS_URL`) is the address agents reach the app at, such as `https://logs.example.com`. It must be HTTPS and have no path. An HTTP address works only on `localhost` or `127.0.0.1`, for a local test. If the field is empty when you turn on **Allow agents to connect** in Settings, Settings fills it in. It takes the address from the **OAuth2 Redirect URI**, or else from the address of the page you have open. Change it if agents reach the app at another address.
- **Allow agents to connect** (`AGENT_ACCESS_ENABLED`) is on.

The switch and the address are in **Settings** > **Agents**. Until all three are set, every agent address answers 404, and **Settings** > **Agents** shows what is missing.

## Connect an agent

1. In a terminal on the computer where the agent runs, add the app with the command from **Settings** > **Agents**:

	```
	claude mcp add --transport http mailcow https://logs.example.com/mcp
	codex mcp add mailcow --url https://logs.example.com/mcp
	```

2. The agent opens a page in your browser. If it does not, run `claude mcp login mailcow` for Claude Code or `codex mcp login mailcow` for Codex.
3. Sign in if the app asks you to.
4. Check **Who is asking**. **Name from claude.ai** means the name came from that site. The page cannot verify the program asking to connect, so allow it only if you just started the connection yourself.
5. Choose **View** or **Take action** for each area. **Take action** includes **View**. The agent may ask for areas, but **Take action** always starts off.
6. Choose how long, up to **Maximum access duration (days)** (`AGENT_ACCESS_MAX_DAYS`, 90 by default), and click **Allow**.

The browser goes back to the agent, and the agent shows under **Allowed agents** in **Settings** > **Agents**.

## What an agent can do

The agent sees up to four tools. `get_access` tells it what it may do. `list_endpoints` lists the app's API calls in its areas. `read_api` runs a call that only reads. `perform_action` runs a call that changes something, and appears only when the agent may take action in some area.

The areas follow the menu: Dashboard & Status, Messages, Outbound, Quarantine, Security, Rspamd, DMARC & TLS, Domains, Mailboxes, Logs, and Settings. The consent page lists what each area allows. A call outside the agent's areas fails and tells the agent which permission is missing.

An agent can never do the following, whatever you allow:

- Change settings, including sign-in and agent connections.
- Run jobs from **Settings** > **Background Jobs**.
- Upload files, such as DMARC reports or a suppression list.
- Add, change, or test notification destinations.
- Read passwords and keys. An agent sees them hidden in **Settings**, as you do on the page.
- Manage agents.

DNS checks run only for the mail server's own domains.

## Keep agents safe

Much of what the app shows comes from strangers, such as subjects, sender names, log lines, and report contents. A message can contain text that tries to give an agent instructions. The app tells every agent to treat that text as data, but the agent decides what it does. Actions do not ask for another approval in this app. Allow actions only in the areas the agent needs, for the shortest time, and use an agent that asks you before it acts.

## Disconnect an agent

**Allowed agents** in **Settings** > **Agents** lists each agent with its areas, who allowed it, when its access expires and when it was last used. **Activity** shows its recent calls. **Disconnect** stops new requests from the agent at once. **Disconnect all** does the same for every agent. To use a disconnected agent again, allow it again from the agent.

Access also ends:

- When it expires.
- When the agent revokes its own access.
- When a sign-in setting changes, such as the password or the OAuth2 provider. This happens whether you change it on the Settings page or in `.env`, and changing it back does not restore the access.

Turning off **Allow agents to connect** stops every agent at once. So does a new **App URL**, because each agent's access works only with the address it was given for. Access that has not expired works again when you turn the switch back on or return to the old address.
