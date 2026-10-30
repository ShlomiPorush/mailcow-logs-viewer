// =============================================================================
// API REFERENCE - the interactive API page (/docs)
// =============================================================================
// Scalar (assets/libs/scalar-api-reference.min.js) draws /openapi.json. Nothing
// on this page may reach a server other than this one: every Scalar feature
// that talks to scalar.com is off below (the AI agent, the MCP and developer
// tools, telemetry, the request proxy, its web fonts), and so is the button
// that opens the document in Scalar's hosted client. "Test Request" stays: it
// sends the request from this page, with the session cookie, to this server.
// After updating the bundle, run the browser pass (UI_SMOKE=1, see
// .github/scripts/ui_smoke.py check_api_docs): only a browser shows whether
// the new version still keeps to these options.
// =============================================================================

const API_DOCS_OPTIONS = Object.freeze({
    url: '/openapi.json',
    telemetry: false,
    proxyUrl: '',
    withDefaultFonts: false,
    hideClientButton: true,
    showDeveloperTools: 'never',
    agent: { disabled: true },
    mcp: { disabled: true },
    persistAuth: false,
});

// The app's theme, decided as in app.js; the page follows it and has no toggle
function apiDocsDarkMode() {
    return document.documentElement.classList.contains('dark');
}

// Scalar's colors and fonts taken from the app's tokens (assets/css/ui.css),
// which follow the dark class on <html>
const API_DOCS_CSS = `
.light-mode, .dark-mode {
    --scalar-font: var(--ui-font);
    --scalar-font-code: var(--ui-mono);
    --scalar-radius: var(--ui-radius-sm);
    --scalar-radius-lg: var(--ui-radius);
    --scalar-background-1: var(--ui-bg);
    --scalar-background-2: var(--ui-panel);
    --scalar-background-3: var(--ui-line);
    --scalar-border-color: var(--ui-line);
    --scalar-color-1: var(--ui-ink);
    --scalar-color-2: var(--ui-muted);
    --scalar-color-3: var(--ui-muted);
    --scalar-color-accent: var(--ui-focus);
    --scalar-color-green: var(--ui-ok);
    --scalar-color-red: var(--ui-fail);
    --scalar-color-yellow: var(--ui-warn);
    --scalar-color-blue: var(--ui-info);
    --scalar-sidebar-background-1: var(--ui-side);
    --scalar-sidebar-color-1: var(--ui-side-ink);
    --scalar-sidebar-color-2: var(--ui-side-muted);
    --scalar-sidebar-border-color: var(--ui-line);
    --scalar-sidebar-item-hover-background: var(--ui-side-card);
    --scalar-sidebar-item-active-background: var(--ui-side-card);
    --scalar-sidebar-color-active: var(--ui-side-ink);
    --scalar-sidebar-search-background: var(--ui-side-card);
    --scalar-sidebar-search-border-color: var(--ui-line);
}
`;

Scalar.createApiReference('#api-docs', {
    ...API_DOCS_OPTIONS,
    theme: 'default',
    forceDarkModeState: apiDocsDarkMode() ? 'dark' : 'light',
    hideDarkModeToggle: true,
    customCss: API_DOCS_CSS,
});
