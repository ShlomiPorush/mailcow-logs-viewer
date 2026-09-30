/**
 * Router module for SPA clean URL navigation
 * Handles History API based routing for the mailcow Logs Viewer
 */

// Valid base routes for the SPA
const VALID_ROUTES = [
    'dashboard',
    'messages',
    'netfilter',
    'queue',
    'quarantine',
    'spam-filter',
    'status',
    'domains',
    'dmarc',
    'mailbox-stats',
    'logs',
    'settings'
];

// URL aliases: URL path -> internal route name
const ROUTE_ALIASES = {
    'security': 'netfilter'
};

// Reverse aliases: internal route -> URL path
const ROUTE_DISPLAY = {
    'netfilter': 'security'
};

// Pages with tabs: every tab has its own address (/security/protection), so a
// tab can be reloaded, shared and reached with Back. The first tab is the
// page's own address. select() picks the tab before the page loads; show()
// switches it on a page already open. tabs: null takes any section name.
const SUBPAGES = {
    netfilter: { tabs: ['overview', 'events', 'protection', 'fail2ban', 'abuse'], current: () => securityTab,
        select: t => securityShowTab(t), show: t => securityShowTab(t) },
    quarantine: { tabs: ['messages', 'rules'], current: () => quarantineTab,
        select: t => quarantineShowTab(t), show: t => quarantineShowTab(t) },
    status: { tabs: ['server', 'blocklists', 'jobs'], current: () => statusTab,
        select: t => statusShowTab(t), show: t => statusShowTab(t) },
    'spam-filter': { tabs: ['suppressions', 'maps'], current: () => spamFilterSubTab,
        select: t => { spamFilterSubTab = t; }, show: t => spamFilterSwitchSubTab(t) },
    'mailbox-stats': { tabs: ['statistics', 'rate-limits'], current: () => mailboxStatsView,
        select: t => { mailboxStatsView = t; }, show: t => mailboxStatsSwitchView(t) },
    settings: { tabs: null, first: 'about', current: () => settingsTab,
        select: t => { settingsTab = t; }, show: t => { settingsTab = t; if (window.settingsShowTab) window.settingsShowTab(t); } }
};

function subpageFirst(route) {
    const page = SUBPAGES[route];
    return page.first || page.tabs[0];
}

function isSubpage(route, name) {
    const page = SUBPAGES[route];
    if (!page || !name) return false;
    return page.tabs ? page.tabs.includes(name) : /^[a-z0-9-]+$/.test(name);
}

// A tab was opened on the page on screen: give it its address. While a page
// loads (replace), the address is corrected instead of adding a Back step.
function routerSyncSubpage(route, name, replace = false) {
    if (typeof currentTab === 'undefined' || currentTab !== route || !SUBPAGES[route]) return;
    const path = buildPath(route, { sub: name });
    if (window.location.pathname === path) return;
    const state = { route, params: { sub: name } };
    if (replace) history.replaceState(state, '', path);
    else history.pushState(state, '', path);
}

/**
 * Parse the current URL path into route components
 * @returns {Object} Route info with baseRoute and optional params
 */
function parseRoute() {
    const path = window.location.pathname;

    // Root path = dashboard
    if (path === '/' || path === '') {
        return { baseRoute: 'dashboard', params: {} };
    }

    // Split path into segments
    const segments = path.split('/').filter(s => s.length > 0);

    if (segments.length === 0) {
        return { baseRoute: 'dashboard', params: {} };
    }

    // Resolve URL aliases (e.g., /security -> netfilter)
    const baseRoute = ROUTE_ALIASES[segments[0]] || segments[0];

    // Special handling for DMARC nested routes
    if (baseRoute === 'dmarc' && segments.length > 1) {
        return parseDmarcRoute(segments);
    }

    // Validate base route
    if (!VALID_ROUTES.includes(baseRoute)) {
        console.warn(`Unknown route: ${baseRoute}, defaulting to dashboard`);
        return { baseRoute: 'dashboard', params: {} };
    }

    // A tab of the page; an unknown one opens the page's first tab
    if (SUBPAGES[baseRoute]) {
        const sub = decodeURIComponent(segments[1] || '');
        return { baseRoute, params: { sub: isSubpage(baseRoute, sub) ? sub : subpageFirst(baseRoute) } };
    }

    return { baseRoute, params: {} };
}

/**
 * Parse DMARC-specific nested routes
 * @param {string[]} segments - URL path segments
 * @returns {Object} Route info for DMARC
 */
function parseDmarcRoute(segments) {
    // segments[0] = 'dmarc'
    // segments[1] = domain (e.g., 'example.com')
    // segments[2] = type ('report', 'source', 'tls', 'reports', 'sources')
    // segments[3] = id (date or IP)

    const params = { domain: null, type: null, id: null };

    // The TLS tab: /dmarc/tls, /dmarc/tls/<domain>, /dmarc/tls/<domain>/<date>
    if (segments[1] === 'tls') {
        return { baseRoute: 'dmarc', params: {
            tab: 'tls',
            domain: segments[2] ? decodeURIComponent(segments[2]) : null,
            id: segments[3] ? decodeURIComponent(segments[3]) : null
        } };
    }

    if (segments.length >= 2) {
        params.domain = decodeURIComponent(segments[1]);
    }

    if (segments.length >= 3) {
        params.type = segments[2];
    }

    if (segments.length >= 4) {
        params.id = decodeURIComponent(segments[3]);
    }

    return { baseRoute: 'dmarc', params };
}

/**
 * Build a URL path from route components
 * @param {string} baseRoute - The base route
 * @param {Object} params - Optional parameters
 * @returns {string} The URL path
 */
function buildPath(baseRoute, params = {}) {
    if (baseRoute === 'dashboard') {
        return '/';
    }

    // Use display name for URL (e.g., netfilter -> /security)
    const urlSegment = ROUTE_DISPLAY[baseRoute] || baseRoute;
    let path = `/${urlSegment}`;

    // A page's tab; the first tab is the page's own address
    if (SUBPAGES[baseRoute] && params.sub && params.sub !== subpageFirst(baseRoute)) {
        path += `/${encodeURIComponent(params.sub)}`;
    }

    // The DMARC page's TLS tab
    if (baseRoute === 'dmarc' && params.tab === 'tls') {
        path += '/tls';
        if (params.domain) {
            path += `/${encodeURIComponent(params.domain)}`;
            if (params.id) path += `/${encodeURIComponent(params.id)}`;
        }
        return path;
    }

    // Handle DMARC nested routes
    if (baseRoute === 'dmarc' && params.domain) {
        path += `/${encodeURIComponent(params.domain)}`;

        if (params.type) {
            path += `/${params.type}`;

            if (params.id) {
                path += `/${encodeURIComponent(params.id)}`;
            }
        }
    }

    return path;
}

/**
 * Navigate to a route - updates URL and switches tab
 * @param {string} route - The base route to navigate to
 * @param {Object} params - Optional route parameters (for nested routes)
 * @param {boolean} updateHistory - Whether to push to browser history (default: true)
 */
function navigateTo(route, params = {}, updateHistory = true) {
    // Handle legacy calls with just route string
    if (typeof params === 'boolean') {
        updateHistory = params;
        params = {};
    }

    // Validate base route
    if (!VALID_ROUTES.includes(route)) {
        console.warn(`Invalid route: ${route}, defaulting to dashboard`);
        route = 'dashboard';
        params = {};
    }

    // Note: disabled feature guard is in switchTab() which shows a "Feature Disabled" page

    // A page with tabs opens on the tab it was left on
    if (SUBPAGES[route] && !params.sub) {
        params = { ...params, sub: SUBPAGES[route].current() };
    }
    // DMARC & TLS too: the sidebar reopens the TLS tab when it was left there
    if (route === 'dmarc' && !Object.keys(params).length && typeof dmarcState !== 'undefined' && dmarcState.tab === 'tls') {
        params = { tab: 'tls' };
    }

    // Build the new path
    const newPath = buildPath(route, params);

    // Update history if path actually changed. With a dialog open, its history
    // entry becomes the new page instead of stacking one more entry
    if (updateHistory && window.location.pathname !== newPath) {
        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            history.replaceState({ route, params }, '', newPath);
        } else {
            history.pushState({ route, params }, '', newPath);
        }
    }

    // Always switch to the tab (even if URL is same, to handle returning to main view)
    if (typeof switchTab === 'function') {
        switchTab(route, params);
    } else {
        console.error('switchTab function not found');
    }
}

// =============================================================================
// Dialogs and the phone More sheet own one history entry while open, so the
// Back button (a phone's back gesture above all) closes them instead of
// leaving the page. The entry has the same address as the page.
// =============================================================================

// The docked message pane on the desktop Messages page is part of the page, not a dialog
const OVERLAY_SELECTOR = '.ui-dialog-backdrop:not(.hidden):not(.ui-docked), #container-logs-modal:not(.hidden), #mobile-menu.active';
let overlayHistoryEntry = false;
let overlayIgnorePop = false;
let overlaySyncQueued = false;

function openOverlays() {
    return [...document.querySelectorAll(OVERLAY_SELECTOR)].filter(el => el.getClientRects().length > 0);
}

// Close the dialog on top the way a user would: its Close or Cancel button
function closeTopOverlay() {
    const open = openOverlays();
    const top = open[open.length - 1];
    if (!top) return false;
    if (top.id === 'mobile-menu') {
        closeMobileMenu();
        return true;
    }
    const button = top.querySelector('[aria-label="Close"], [id$="-cancel"]')
        || [...top.querySelectorAll('button')].find(b => /^(cancel|close)$/i.test(b.textContent.trim())
            || /^close/i.test(b.getAttribute('onclick') || ''));
    if (button) button.click();
    else top.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    return true;
}

// Keep one history entry while anything is open, and drop it when all is closed
function syncOverlayHistory() {
    overlaySyncQueued = false;
    const open = openOverlays().length > 0;
    if (open && !overlayHistoryEntry) {
        history.pushState({ ...(history.state || {}), overlay: true }, '', window.location.href);
        overlayHistoryEntry = true;
    } else if (!open && overlayHistoryEntry) {
        overlayHistoryEntry = false;
        if (history.state && history.state.overlay) {
            overlayIgnorePop = true;
            history.back();
        }
    }
}

function watchOverlays() {
    const queue = () => {
        if (overlaySyncQueued) return;
        overlaySyncQueued = true;
        requestAnimationFrame(syncOverlayHistory);
    };
    // Dialogs open by a class change or by being added to the page
    new MutationObserver(queue).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] });
}
document.addEventListener('DOMContentLoaded', watchOverlays);

/**
 * Navigate specifically within DMARC section
 * @param {string} domain - Domain name (null for domains list)
 * @param {string} type - Type: 'reports', 'sources', 'tls', 'report', 'source'
 * @param {string} id - ID: date for report/tls, IP for source
 */
function navigateToDmarc(domain = null, type = null, id = null) {
    const params = {};
    if (domain) params.domain = domain;
    if (type) params.type = type;
    if (id) params.id = id;

    navigateTo('dmarc', params);
}

/**
 * Get current route from URL path
 * @returns {string} The current base route name
 */
function getCurrentRoute() {
    return parseRoute().baseRoute;
}

/**
 * Get current route with full parameters
 * @returns {Object} Route info with baseRoute and params
 */
function getFullRoute() {
    return parseRoute();
}

/**
 * Initialize the router
 * Sets up popstate listener and returns initial route info
 * @returns {Object} The initial route info { baseRoute, params }
 */
function initRouter() {
    console.log('Initializing SPA router...');

    // Handle browser back/forward buttons
    window.addEventListener('popstate', (event) => {
        // Back with a dialog or sheet open closes it and stays on the page
        if (overlayIgnorePop) {
            overlayIgnorePop = false;
            return;
        }
        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            closeTopOverlay();
            // Another dialog may still be open under it
            setTimeout(syncOverlayHistory, 0);
            return;
        }

        const routeInfo = event.state || parseRoute();
        const route = routeInfo.route || routeInfo.baseRoute || getCurrentRoute();
        const params = routeInfo.params || {};

        console.log('Popstate event, navigating to:', route, params);

        // Use switchTab directly to avoid pushing duplicate history entries
        if (typeof switchTab === 'function') {
            switchTab(route, params);
        }
    });

    // Get initial route from URL
    const routeInfo = parseRoute();

    // Replace current history state with route info
    history.replaceState({ route: routeInfo.baseRoute, params: routeInfo.params }, '', window.location.pathname);

    console.log('Router initialized, initial route:', routeInfo);
    return routeInfo;
}

// Tab labels for mobile menu display
const TAB_LABELS = {
    'dashboard': 'Dashboard',
    'messages': 'Messages',
    'netfilter': 'Security',
    'queue': 'Queue',
    'quarantine': 'Quarantine',
    'status': 'Status',
    'domains': 'Domains',
    'dmarc': 'DMARC & TLS',
    'mailbox-stats': 'Mailbox Stats',
    'logs': 'Logs',
    'settings': 'Settings',
    'spam-filter': 'Spam Filter'
};

/**
 * Toggle mobile menu open/close
 */
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.toggle('active');
        hamburgerBtn.classList.toggle('active');
    }
}

/**
 * Close mobile menu
 */
function closeMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.remove('active');
        hamburgerBtn.classList.remove('active');
    }
}

/**
 * Navigate from mobile menu - closes menu and navigates
 * @param {string} route - The route to navigate to
 */
function navigateToMobile(route) {
    // Close the mobile menu first
    closeMobileMenu();

    // Update mobile menu active state
    updateMobileMenuActiveState(route);

    // Update the current tab label
    updateCurrentTabLabel(route);

    // Navigate to the route
    navigateTo(route);
}

/**
 * Update mobile menu item active states
 * @param {string} activeRoute - The currently active route
 */
function updateMobileMenuActiveState(activeRoute) {
    // Remove active class from all mobile menu items
    document.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.classList.remove('active');
    });

    // Add active class to the new active item
    const activeItem = document.getElementById(`mobile-tab-${activeRoute}`);
    if (activeItem) {
        activeItem.classList.add('active');
    }
}

/**
 * Update the current tab label shown on mobile
 * @param {string} route - The current route
 */
function updateCurrentTabLabel(route) {
    const label = document.getElementById('current-tab-label');
    if (label) {
        label.textContent = TAB_LABELS[route] || route;
    }
}

// Close mobile menu when clicking outside
document.addEventListener('click', (event) => {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && mobileMenu.classList.contains('active')) {
        // Check if click is outside the menu content and hamburger button
        const menuContent = mobileMenu.querySelector('.mobile-menu-content');
        if (!menuContent.contains(event.target) && !hamburgerBtn.contains(event.target)) {
            closeMobileMenu();
        }
    }
});

// Expose functions globally
window.navigateTo = navigateTo;
window.navigateToDmarc = navigateToDmarc;
window.getCurrentRoute = getCurrentRoute;
window.getFullRoute = getFullRoute;
window.parseRoute = parseRoute;
window.buildPath = buildPath;
window.SUBPAGES = SUBPAGES;
window.routerSyncSubpage = routerSyncSubpage;
window.initRouter = initRouter;
window.VALID_ROUTES = VALID_ROUTES;
window.toggleMobileMenu = toggleMobileMenu;
window.closeMobileMenu = closeMobileMenu;
window.navigateToMobile = navigateToMobile;
window.updateMobileMenuActiveState = updateMobileMenuActiveState;
window.updateCurrentTabLabel = updateCurrentTabLabel;
window.TAB_LABELS = TAB_LABELS;
