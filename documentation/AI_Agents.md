# AI agents

An AI agent such as Claude Code, Codex or T3 Code can read what the app shows and, if you allow it, take action on the mail server. It never gets a password or a key. It asks to connect, and you approve it on any device, including your phone. You choose which areas it may view or take action in, and for how long.

## Turn on agent access

Agent access is off by default. It needs three things:

- Sign-in is on: Basic Auth, OAuth2, or both. See [Sign-in configuration](OAuth2_Configuration.md). Without sign-in, the switch is locked and agents cannot connect.
- **App URL** (`AGENT_ACCESS_URL`) is the address agents reach the app at, such as `https://logs.example.com`. It must be HTTPS and have no path. An HTTP address works only on `localhost` or `127.0.0.1`, for a local test. If the field is empty when you turn on **Enable agent access** in Settings, Settings fills it in. It takes the address from the **OAuth2 Redirect URI**, or else from the address of the page you have open. Change it if agents reach the app at another address.
- **Enable agent access** (`AGENT_ACCESS_ENABLED`) is on.

The switch and the address are in **Settings** > **Agents**. Until all three are set, every agent address answers 404, and **Settings** > **Agents** shows what is missing.

## Connect an agent that runs commands

This is the way for Claude Code, Codex, T3 Code and other agents that run commands.

1. In **Settings** > **Agents**, on the **Agent** tab, copy the sentence and paste it to the agent. It looks like this:

	```
	Install the mailcow-logs skill into your personal skills folder as described at https://logs.example.com/agents/skill/, then connect to mailcow Logs Viewer.
	```

2. The agent downloads the skill from the app, runs `mailcow-logs connect`, and shows you a link and a code such as `BCDF-GHJK`.
3. Open the link on any device and sign in if the app asks you to. If you only have the code, open `https://logs.example.com/oauth/device` and type it.
4. Check that the page shows the same code as the agent. The name on the page is what the agent calls itself, and the app cannot check it, so approve only a request you just started in your own agent.
5. Choose **View** or **Take action** for each area. **Take action** includes **View**, and it always starts off.
6. Choose how long, up to **Maximum access duration (days)** (`AGENT_ACCESS_MAX_DAYS`, 90 by default), and click **Allow**.

The agent finishes on its own. The skill keeps the connection on that computer, shared by every conversation of that agent, and renews it until the time you chose ends.

## Connect over MCP

The **MCP** tab is for apps that add MCP servers, such as those that cannot run commands. Paste its sentence to the agent: it points to `https://logs.example.com/agents/mcp/`, which tells the agent how to add the server in the common MCP clients. Or add the **MCP server URL** yourself in the app's MCP settings. Approve the request in the browser that opens on that computer, the same way.

## What an agent can do

The areas follow the menu: Dashboard & Status, Messages, Outbound, Quarantine, Security, Rspamd, DMARC & TLS, Domains, Mailboxes, Logs, and Settings. The approval page lists what each area allows. A call outside the agent's areas fails and tells the agent which permission is missing.

An agent can never do the following, whatever you allow:

- Change settings, including sign-in and agent access.
- Run jobs from **Settings** > **Background Jobs**.
- Upload files, such as DMARC reports or a suppression list.
- Add, change, or test notification destinations.
- Read passwords and keys. An agent sees them hidden in **Settings**, as you do on the page.
- Manage agents.

DNS checks run only for the mail server's own domains.

## Keep agents safe

Much of what the app shows comes from strangers, such as subjects, sender names, log lines, and report contents. A message can contain text that tries to give an agent instructions. The app tells every agent to treat that text as data, but the agent decides what it does. Actions do not ask for another approval in this app. Allow actions only in the areas the agent needs, for the shortest time, and use an agent that asks you before it acts.

## Disconnect an agent

**Connected agents** in **Settings** > **Agents** lists each agent with how it connected (Skill or MCP), its areas, who allowed it, when its access expires and when it was last used. **Activity** shows its recent calls. **Edit** changes the areas it may view or take action in, and can set a new end counted from now; the change applies from its next request. **Disconnect** stops new requests from the agent at once. **Disconnect all** does the same for every agent and ends codes that are waiting for approval. To use a disconnected agent again, connect it again from the agent.

Access also ends:

- When it expires.
- When the agent disconnects itself (`mailcow-logs disconnect`).
- When a sign-in setting changes, such as the password or the OAuth2 provider. This happens whether you change it on the Settings page or in `.env`, and changing it back does not restore the access.

Turning off **Enable agent access** stops every agent at once. So does a new **App URL**, because each agent's access works only with the address it was given for. Access that has not expired works again when you turn the switch back on or return to the old address.
