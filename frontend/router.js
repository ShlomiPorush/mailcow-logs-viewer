const VALID_ROUTES = [
    'dashboard',
    'messages',
    'netfilter',
    'outbound',
    'quarantine',
    'rspamd',
    'status',
    'domains',
    'dmarc',
    'mailbox-stats',
    'devices',
    'logs',
    'settings',
    'about'
];

const ROUTE_ALIASES = {
    'security': 'netfilter'
};

const ROUTE_DISPLAY = {
    'netfilter': 'security'
};

function canonicalRoute(route, params = {}) {
    const sub = (params && params.sub) || '';
    if (route === 'queue') return { route: 'outbound', params: { sub: 'queue' } };
    if (route === 'spam-filter') {
        return sub === 'maps' ? { route: 'rspamd', params: {} }
            : { route: 'outbound', params: { sub: 'suppressions' } };
    }
    return null;
}

const SUBPAGES = {
    netfilter: { tabs: ['overview', 'lists', 'settings', 'events'], current: () => securityTab,
        select: t => securityShowTab(t), show: t => securityShowTab(t) },
    quarantine: { tabs: ['messages', 'rules'], current: () => quarantineTab,
        select: t => quarantineShowTab(t), show: t => quarantineShowTab(t) },
    outbound: { tabs: ['queue', 'suppressions'], current: () => outboundTab,
        select: t => outboundShowTab(t, false), show: t => outboundShowTab(t) },
    status: { tabs: ['server', 'blocklists', 'jobs'], current: () => statusTab,
        select: t => statusShowTab(t), show: t => statusShowTab(t) },
    'mailbox-stats': { tabs: ['statistics', 'rate-limits'], current: () => mailboxStatsView,
        select: t => { mailboxStatsView = t; }, show: t => mailboxStatsSwitchView(t) },
    settings: { tabs: null, get first() { return settingsFirstTab || 'features'; }, current: () => settingsTab,
        select: t => { settingsTab = t; }, show: t => { settingsTab = t; if (window.settingsShowTab) window.settingsShowTab(t); } }
};

function subpageFirst(route) {
    const page = SUBPAGES[route];
    return page.first || page.tabs[0];
}

function isSubpage(route, name) {
    const page = SUBPAGES[route];
    if (!page || !name) return false;
    return page.tabs ? page.tabs.includes(name) : /^[a-z0-9_-]+$/.test(name);
}

let historyIdx = 0;
let routerHere = { route: 'dashboard', params: {} };
function routerPush(state, url) {
    routerSaveScroll();
    historyIdx += 1;
    routerNoteHere(state);
    history.pushState({ ...(state || {}), idx: historyIdx }, '', url);
}
function routerReplace(state, url) {
    routerNoteHere(state);
    history.replaceState({ ...(state || {}), idx: historyIdx }, '', url);
}
function routerNoteHere(state) {
    if (state && state.route && !state.overlay) routerHere = { route: state.route, params: state.params || {} };
}

function routerSyncSubpage(route, name, replace = false) {
    if (typeof currentTab === 'undefined' || currentTab !== route || !SUBPAGES[route]) return;
    const path = buildPath(route, { sub: name });
    if (window.location.pathname === path) return;
    const state = { route, params: { sub: name } };
    if (replace) routerReplace(state, path);
    else routerPush(state, path);
}

function parseRoute() {
    const path = window.location.pathname;

    if (path === '/' || path === '') {
        return { baseRoute: 'dashboard', params: {} };
    }

    const segments = path.split('/').filter(s => s.length > 0);

    if (segments.length === 0) {
        return { baseRoute: 'dashboard', params: {} };
    }

    const baseRoute = ROUTE_ALIASES[segments[0]] || segments[0];

    const moved = canonicalRoute(baseRoute, { sub: decodeURIComponent(segments[1] || '') });
    if (moved) return { baseRoute: moved.route, params: moved.params, moved: true };

    if (baseRoute === 'dmarc' && segments.length > 1) {
        return parseDmarcRoute(segments);
    }

    if (!VALID_ROUTES.includes(baseRoute)) {
        console.warn(`Unknown route: ${baseRoute}, defaulting to dashboard`);
        return { baseRoute: 'dashboard', params: {} };
    }

    if (SUBPAGES[baseRoute]) {
        const sub = decodeURIComponent(segments[1] || '');
        return { baseRoute, params: { sub: isSubpage(baseRoute, sub) ? sub : subpageFirst(baseRoute) } };
    }

    return { baseRoute, params: {} };
}

function parseDmarcRoute(segments) {
    const params = { domain: null, type: null, id: null };

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

function buildPath(baseRoute, params = {}) {
    if (baseRoute === 'dashboard') {
        return '/';
    }

    const urlSegment = ROUTE_DISPLAY[baseRoute] || baseRoute;
    let path = `/${urlSegment}`;

    if (SUBPAGES[baseRoute] && params.sub && params.sub !== subpageFirst(baseRoute)) {
        path += `/${encodeURIComponent(params.sub)}`;
    }

    if (baseRoute === 'dmarc' && params.tab === 'tls') {
        path += '/tls';
        if (params.domain) {
            path += `/${encodeURIComponent(params.domain)}`;
            if (params.id) path += `/${encodeURIComponent(params.id)}`;
        }
        return path;
    }

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

function navigateTo(route, params = {}, updateHistory = true, confirmed = false) {
    if (typeof params === 'boolean') {
        updateHistory = params;
        params = {};
    }

    const moved = canonicalRoute(route, params);
    if (moved) ({ route, params } = moved);

    if (!VALID_ROUTES.includes(route)) {
        console.warn(`Invalid route: ${route}, defaulting to dashboard`);
        route = 'dashboard';
        params = {};
    }

    if (SUBPAGES[route] && !params.sub) {
        params = { ...params, sub: SUBPAGES[route].current() };
    }

    if (!confirmed && typeof uiUnsavedCount === 'function' && uiUnsavedCount({ route, params })) {
        return uiConfirmLeave({ route, params }).then(ok => (ok ? navigateTo(route, params, updateHistory, true) : false));
    }

    const newPath = buildPath(route, params);

    if (updateHistory && window.location.pathname !== newPath) {
        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            routerReplace({ route, params }, newPath);
        } else {
            routerPush({ route, params }, newPath);
        }
    }

    routerHere = { route, params };
    if (typeof switchTab === 'function') {
        switchTab(route, params);
    } else {
        console.error('switchTab function not found');
    }
    return Promise.resolve(true);
}

const OVERLAY_SELECTOR = '.ui-dialog-backdrop:not(.hidden):not(.ui-docked), #mobile-menu.active, .ui-gs.is-sheet, .ui-sheet';
let overlayHistoryEntry = false;
let overlayIgnorePop = false;
let overlaySyncQueued = false;

function layerShown(el) {
    return el.getClientRects().length > 0;
}

function layerLevel(el) {
    const z = parseInt(getComputedStyle(el).zIndex, 10);
    return Number.isNaN(z) ? 0 : z;
}

function openOverlays() {
    return [...document.querySelectorAll(OVERLAY_SELECTOR)].filter(layerShown)
        .sort((a, b) => layerLevel(a) - layerLevel(b)
            || (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING ? -1 : 1));
}

let layerOwnEscape = false;
function closeTopOverlay() {
    const open = openOverlays();
    const top = open[open.length - 1];
    if (!top) return false;
    if (top.id === 'mobile-menu') {
        closeMobileMenu();
        return true;
    }
    const button = top.querySelector('[aria-label="Close"], [id$="-cancel"], [data-cancel]')
        || [...top.querySelectorAll('button')].find(b => /^(cancel|close)$/i.test(b.textContent.trim())
            || /^close/i.test(b.getAttribute('onclick') || ''));
    if (button) button.click();
    else {
        layerOwnEscape = true;
        try { top.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); } finally { layerOwnEscape = false; }
    }
    return true;
}

function layerChildOwnsEscape(top) {
    if (top.matches('.ui-gs')) return true;
    const picker = typeof uiPickers !== 'undefined' && uiPickers.open ? document.getElementById(`${uiPickers.open}-panel`) : null;
    if (picker && top.contains(picker)) return true;
    try { return !!top.querySelector(':popover-open'); } catch (e) { return false; }
}

window.addEventListener('keydown', event => {
    if (event.key !== 'Escape' || event.isComposing || layerOwnEscape) return;
    const open = openOverlays();
    const top = open[open.length - 1];
    if (!top || layerChildOwnsEscape(top)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    closeTopOverlay();
}, true);

let layerLastAction = null;
let layerNamedOpener = null;
const layerOpeners = new Map();
function layerControl(el) {
    return el instanceof Element ? el.closest('button, a[href], input, select, textarea, summary, [tabindex]') : null;
}
document.addEventListener('pointerdown', event => { layerLastAction = layerControl(event.target); }, true);
let layerFocused = null;
document.addEventListener('focusin', event => { layerFocused = event.target; }, true);
document.addEventListener('keydown', event => { layerLastAction = layerControl(event.target) || layerLastAction; }, true);
function uiLayerOpener(el) {
    layerNamedOpener = layerControl(el);
}
function uiLayerReturn(layer, el) {
    layerOpeners.set(layer, el ? layerControl(el) : null);
}

function layerUsable(el) {
    return !!el && el.isConnected && layerShown(el) && !el.closest('[inert]') && !el.disabled;
}

function layerPanel(layer) {
    return layer.querySelector('[role="dialog"], [role="alertdialog"], .ui-sheet-panel, .ui-dialog, .mobile-menu-content') || layer;
}

function layerFocusIn(layer) {
    if (layer.contains(document.activeElement)) return;
    const usable = el => el.getClientRects().length > 0 && !el.disabled;
    const touch = window.matchMedia('(pointer: coarse)').matches;
    if (layer.matches('.ui-gs')) {
        const results = layer.querySelector('.ui-gs-panel');
        const target = touch && results ? results : layer.querySelector('input');
        if (target === results && !results.hasAttribute('tabindex')) results.setAttribute('tabindex', '-1');
        if (target) target.focus({ preventScroll: true });
        return;
    }
    const field = touch ? null : [...layer.querySelectorAll('[autofocus], input:not([type="hidden"]), select, textarea')].find(usable);
    let target = field || [...layer.querySelectorAll('.ui-btn-primary')].find(usable);
    if (!target) {
        target = layerPanel(layer);
        if (!target.hasAttribute('tabindex')) target.setAttribute('tabindex', '-1');
        target.dataset.layerPanel = '';
    }
    target.focus({ preventScroll: true });
}

function layerFocusBack(opener, below) {
    if (layerUsable(opener)) { opener.focus({ preventScroll: true }); return; }
    if (below) { layerFocusIn(below); return; }
    const page = [...document.querySelectorAll('.ui-page:not(.hidden)')].find(layerShown);
    const barTitle = document.querySelector('#ui-topbar-title h1');
    const heading = (barTitle && layerShown(barTitle) ? barTitle : null) || (page && page.querySelector('h1, h2'));
    if (heading) {
        if (!heading.hasAttribute('tabindex')) heading.setAttribute('tabindex', '-1');
        heading.focus({ preventScroll: true });
    }
}

const layerInert = new Set();
function layerKeeps(top) {
    const keep = [...document.querySelectorAll('.ui-toast')];
    if (top && top.id === 'mobile-menu') keep.push(...document.querySelectorAll('.ui-tabbar'));
    return keep;
}
function layerInertTargets(top) {
    const targets = new Set();
    if (!top) return targets;
    const keep = layerKeeps(top);
    const mark = el => {
        if (el === top || el.contains(top) || ['SCRIPT', 'STYLE', 'TEMPLATE'].includes(el.tagName)) return;
        if (keep.includes(el)) return;
        if (keep.some(k => el.contains(k))) { [...el.children].forEach(mark); return; }
        targets.add(el);
    };
    for (let node = top; node.parentElement && node !== document.body; node = node.parentElement) {
        [...node.parentElement.children].forEach(child => { if (child !== node) mark(child); });
    }
    return targets;
}
function layerApplyInert(top) {
    const targets = layerInertTargets(top);
    for (const el of layerInert) {
        if (!targets.has(el)) { el.inert = false; layerInert.delete(el); }
    }
    for (const el of targets) {
        if (!layerInert.has(el) && !el.inert) { el.inert = true; layerInert.add(el); }
    }
}

function syncLayerFocus(open) {
    const top = open[open.length - 1] || null;
    const closed = [...layerOpeners.keys()].filter(el => !open.includes(el));
    const opened = open.filter(el => !layerOpeners.has(el));
    const closedOpeners = closed.map(el => layerOpeners.get(el));
    closed.forEach(el => {
        layerOpeners.delete(el);
        const marked = el.matches('[data-layer-modal]') ? el : el.querySelector('[data-layer-modal]');
        if (marked) { marked.removeAttribute('aria-modal'); delete marked.dataset.layerModal; }
    });
    opened.forEach(el => {
        const dialog = el.matches('[role="dialog"], [role="alertdialog"]') ? el : el.querySelector('[role="dialog"], [role="alertdialog"]');
        if (dialog && !el.matches('.ui-gs') && !dialog.hasAttribute('aria-modal')) {
            dialog.setAttribute('aria-modal', 'true');
            dialog.dataset.layerModal = '';
        }
        let opener = layerNamedOpener || layerLastAction;
        if (opener && el.contains(opener)) opener = null;
        layerOpeners.set(el, opener);
    });
    if (opened.length) layerNamedOpener = null;
    layerApplyInert(top);
    if (top && opened.includes(top)) layerFocusIn(top);
    else if (closed.length && !(top && top.contains(document.activeElement))) {
        layerFocusBack(closedOpeners[closedOpeners.length - 1], top);
    } else if (top && layerFocused && !layerFocused.isConnected && (!document.activeElement || document.activeElement === document.body)
        && !(typeof uiSortFocus !== 'undefined' && uiSortFocus && uiSortFocus.from.isConnected)) {
        layerFocusIn(top);
    }
}

function syncOverlayHistory() {
    overlaySyncQueued = false;
    const layers = openOverlays();
    syncLayerFocus(layers);
    const open = layers.some(el => !el.matches('[data-no-history]'));
    if (open && !overlayHistoryEntry) {
        routerPush({ ...(history.state || {}), overlay: true }, window.location.href);
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
    new MutationObserver(queue).observe(document.body, { subtree: true, childList: true, attributes: true, attributeFilter: ['class'] });
}
document.addEventListener('DOMContentLoaded', watchOverlays);

let routerPopUndo = false;
let routerPopConfirmed = false;
const routerScrolls = new Map();
function routerScrollAreas() {
    const page = [...document.querySelectorAll('.ui-page:not(.hidden)')].find(el => el.getClientRects().length);
    if (!page) return [];
    return [page, ...page.querySelectorAll('.ui-scroll, .ui-msg-items, #settings-content .settings-edit-content, .ui-logs-side')]
        .filter(el => el.scrollHeight > el.clientHeight);
}
function routerScrollKey(el) {
    if (el.id) return el.id;
    const owner = el.parentElement && el.parentElement.closest('[id]');
    return `${owner ? owner.id : ''}|${el.className}`;
}
function routerSaveScroll() {
    const areas = routerScrollAreas();
    if (!areas.length) return;
    const saved = {};
    areas.forEach(el => { if (el.scrollTop > 0) saved[routerScrollKey(el)] = el.scrollTop; });
    routerScrolls.set(historyIdx, saved);
}
let routerScrollRestore = null;
function routerRestoreScroll(idx) {
    if (routerScrollRestore) routerScrollRestore();
    const saved = routerScrolls.get(idx);
    if (!saved || !Object.keys(saved).length) return;
    const until = Date.now() + 5000;
    let stopped = false;
    const stop = () => {
        stopped = true;
        routerScrollRestore = null;
        ['wheel', 'touchstart', 'pointerdown', 'keydown'].forEach(type => window.removeEventListener(type, stop, true));
    };
    ['wheel', 'touchstart', 'pointerdown', 'keydown'].forEach(type => window.addEventListener(type, stop, true));
    routerScrollRestore = stop;
    const step = () => {
        if (stopped) return;
        let left = 0;
        for (const [key, top] of Object.entries(saved)) {
            const el = document.getElementById(key) || [...document.querySelectorAll('.ui-page:not(.hidden) *')].find(e => routerScrollKey(e) === key);
            if (!el) { left++; continue; }
            const max = el.scrollHeight - el.clientHeight;
            const want = Math.min(top, max);
            if (Math.abs(el.scrollTop - want) > 1) el.scrollTop = want;
            if (max < top) left++;
        }
        if (Date.now() < until) setTimeout(step, left ? 150 : 250);
        else stop();
    };
    requestAnimationFrame(step);
}

function navigateToDmarc(domain = null, type = null, id = null) {
    const params = {};
    if (domain) params.domain = domain;
    if (type) params.type = type;
    if (id) params.id = id;

    navigateTo('dmarc', params);
}

function getCurrentRoute() {
    return parseRoute().baseRoute;
}

function getFullRoute() {
    return parseRoute();
}

function initRouter() {
    console.log('Initializing SPA router...');

    window.addEventListener('popstate', (event) => {
        const idx = event.state && Number.isInteger(event.state.idx) ? event.state.idx : null;
        const delta = idx === null ? null : idx - historyIdx;
        if (routerPopUndo) {
            routerPopUndo = false;
            if (idx !== null) historyIdx = idx;
            return;
        }
        if (overlayIgnorePop) {
            overlayIgnorePop = false;
            if (idx !== null) historyIdx = idx;
            return;
        }
        if (typeof uiUnsavedAsking !== 'undefined' && uiUnsavedAsking && delta) {
            routerPopUndo = true;
            history.go(-delta);
            return;
        }
        if (overlayHistoryEntry && (delta === -1 || delta === null)) {
            overlayHistoryEntry = false;
            if (idx !== null) historyIdx = idx;
            closeTopOverlay();
            setTimeout(syncOverlayHistory, 0);
            return;
        }

        const routeInfo = event.state || parseRoute();
        let route = routeInfo.route || routeInfo.baseRoute || getCurrentRoute();
        let params = routeInfo.params || {};
        const moved = canonicalRoute(route, params);

        const target = { route: (moved || { route }).route, params: (moved || { params }).params };
        if (!routerPopConfirmed && delta === null && typeof uiUnsavedCount === 'function' && uiUnsavedCount(target)) {
            const here = routerHere;
            routerPush({ route: here.route, params: here.params }, buildPath(here.route, here.params));
            uiConfirmLeave(target).then(ok => { if (ok) navigateTo(target.route, target.params, true, true); });
            return;
        }
        if (!routerPopConfirmed && delta && typeof uiUnsavedCount === 'function'
            && uiUnsavedCount({ route: (moved || { route }).route, params: (moved || { params }).params })) {
            routerPopUndo = true;
            history.go(-delta);
            uiConfirmLeave({ route: (moved || { route }).route, params: (moved || { params }).params }).then(ok => {
                if (!ok) return;
                routerPopConfirmed = true;
                history.go(delta);
            });
            return;
        }
        routerPopConfirmed = false;
        routerSaveScroll();
        if (idx !== null) historyIdx = idx;

        if (overlayHistoryEntry) {
            overlayHistoryEntry = false;
            for (let i = 0; i < 10 && openOverlays().length; i++) closeTopOverlay();
        }
        if (moved) {
            ({ route, params } = moved);
            routerReplace({ route, params }, buildPath(route, params));
        }

        console.log('Popstate event, navigating to:', route, params);

        routerHere = { route, params };
        if (typeof switchTab === 'function') {
            switchTab(route, params);
        }
        routerRestoreScroll(historyIdx);
    });

    const routeInfo = parseRoute();
    routerHere = { route: routeInfo.baseRoute, params: routeInfo.params };
    if (history.state && Number.isInteger(history.state.idx)) historyIdx = history.state.idx;

    routerReplace({ route: routeInfo.baseRoute, params: routeInfo.params },
        routeInfo.moved ? buildPath(routeInfo.baseRoute, routeInfo.params) : window.location.pathname);

    window.addEventListener('beforeunload', event => {
        if (typeof uiUnsavedCount === 'function' && uiUnsavedCount()) {
            event.preventDefault();
            event.returnValue = '';
        }
    });
    if ('scrollRestoration' in history) history.scrollRestoration = 'manual';

    console.log('Router initialized, initial route:', routeInfo);
    return routeInfo;
}

const TAB_LABELS = {
    'dashboard': 'Dashboard',
    'messages': 'Messages',
    'netfilter': 'Security',
    'outbound': 'Outbound',
    'quarantine': 'Quarantine',
    'rspamd': 'Rspamd',
    'status': 'Status',
    'domains': 'Domains',
    'dmarc': 'DMARC & TLS',
    'mailbox-stats': 'Mailbox Stats',
    'devices': 'Devices',
    'logs': 'Logs',
    'settings': 'Settings',
    'about': 'About'
};

function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.toggle('active');
        hamburgerBtn.classList.toggle('active');
    }
}

function closeMobileMenu() {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && hamburgerBtn) {
        mobileMenu.classList.remove('active');
        hamburgerBtn.classList.remove('active');
    }
}

function navigateToMobile(route) {
    closeMobileMenu();

    navigateTo(route).then(moved => {
        if (!moved) return;
        updateMobileMenuActiveState(route);
        updateCurrentTabLabel(route);
    });
}

function updateMobileMenuActiveState(activeRoute) {
    document.querySelectorAll('.mobile-menu-item').forEach(item => {
        item.classList.remove('active');
    });

    const activeItem = document.getElementById(`mobile-tab-${activeRoute}`);
    if (activeItem) {
        activeItem.classList.add('active');
    }
}

function updateCurrentTabLabel(route) {
    const label = document.getElementById('current-tab-label');
    if (label) {
        label.textContent = TAB_LABELS[route] || route;
    }
}

document.addEventListener('click', (event) => {
    const mobileMenu = document.getElementById('mobile-menu');
    const hamburgerBtn = document.getElementById('hamburger-btn');

    if (mobileMenu && mobileMenu.classList.contains('active')) {
        const menuContent = mobileMenu.querySelector('.mobile-menu-content');
        if (!menuContent.contains(event.target) && !hamburgerBtn.contains(event.target)) {
            closeMobileMenu();
        }
    }
});

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
