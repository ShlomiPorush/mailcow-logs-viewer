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

function apiDocsDarkMode() {
    return document.documentElement.classList.contains('dark');
}

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
