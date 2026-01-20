/**
 * Router module for SPA clean URL navigation
 * Handles History API based routing for the Mailcow Logs Viewer
 */

// Valid base routes for the SPA
const VALID_ROUTES = [
    'dashboard',
    'messages',
    'netfilter',
    'queue',
    'quarantine',
    'status',
    'domains',
    'dmarc',
    'mailbox-stats',
    'settings'
];

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

    const baseRoute = segments[0];

    // Special handling for DMARC nested routes
    if (baseRoute === 'dmarc' && segments.length > 1) {
        return parseDmarcRoute(segments);
    }

    // Validate base route
    if (!VALID_ROUTES.includes(baseRoute)) {
        console.warn(`Unknown route: ${baseRoute}, defaulting to dashboard`);
        return { baseRoute: 'dashboard', params: {} };
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

    let path = `/${baseRoute}`;

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

    // Build the new path
    const newPath = buildPath(route, params);

    // Update history if path actually changed
    if (updateHistory && window.location.pathname !== newPath) {
        history.pushState({ route, params }, '', newPath);
    }

    // Always switch to the tab (even if URL is same, to handle returning to main view)
    if (typeof switchTab === 'function') {
        switchTab(route, params);
    } else {
        console.error('switchTab function not found');
    }
}

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
    'dmarc': 'DMARC',
    'mailbox-stats': 'Mailbox Stats',
    'settings': 'Settings'
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
window.initRouter = initRouter;
window.VALID_ROUTES = VALID_ROUTES;
window.toggleMobileMenu = toggleMobileMenu;
window.closeMobileMenu = closeMobileMenu;
window.navigateToMobile = navigateToMobile;
window.updateMobileMenuActiveState = updateMobileMenuActiveState;
window.updateCurrentTabLabel = updateCurrentTabLabel;
window.TAB_LABELS = TAB_LABELS;
