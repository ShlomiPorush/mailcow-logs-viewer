"""Agent access: AI agents (Claude Code, Codex, any MCP client) use the app
after a signed-in person approves them in the browser.

- live.py      whether the feature is on, and the app's canonical address
- scopes.py    which /api route belongs to which area, and what is never offered
- store.py     grants, codes, tokens and the activity log in the database
- cimd.py      fetching a client's metadata document safely
- oauth.py     the OAuth 2.1 authorization server (metadata, authorize, token, register, revoke)
- consent.py   the consent page's API and the Settings > Agents management API
- dispatch.py  running one /api call for an agent inside the app, under its grant
- mcp.py       the MCP endpoint (/mcp) and its tools
"""
