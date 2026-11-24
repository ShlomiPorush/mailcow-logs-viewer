function navigateToMessagesWithFilter(options) {
    return openMessagesWith(() => {
        const filterSearch = document.getElementById('messages-filter-search');
        const filterSender = document.getElementById('messages-filter-sender');
        const filterRecipient = document.getElementById('messages-filter-recipient');
        const filterDirection = document.getElementById('messages-filter-direction');
        const filterStatus = document.getElementById('messages-filter-status');
        const filterUser = document.getElementById('messages-filter-user');
        const filterIp = document.getElementById('messages-filter-ip');

        if (filterSearch) filterSearch.value = '';
        if (filterSender) filterSender.value = '';
        if (filterRecipient) filterRecipient.value = '';
        if (filterDirection) filterDirection.value = '';
        if (filterStatus) filterStatus.value = '';
        if (filterUser) filterUser.value = '';
        if (filterIp) filterIp.value = '';

        if (options.email) {
            if (options.filterType === 'sender') {
                if (filterSender) filterSender.value = options.email;
            } else if (options.filterType === 'recipient') {
                if (filterRecipient) filterRecipient.value = options.email;
            } else if (options.filterType === 'user') {
                if (filterUser) filterUser.value = options.email;
            } else if (filterSearch) {
                filterSearch.value = options.email;
            }
        }
        if (options.direction && filterDirection) filterDirection.value = options.direction;
        if (options.status && filterStatus) filterStatus.value = options.status;
        if (options.ip && filterIp) filterIp.value = options.ip;

        const field = el => (el ? el.value : '');
        messagesExact = (options.exact && field(filterIp)) || options.address || options.domain ? {
            ip: options.exact ? field(filterIp) : '', address: options.address || '', domain: options.domain || '',
        } : null;

        if (options.datePreset && MESSAGES_ROLLING_PRESETS.includes(options.datePreset)) messagesShowDatePreset(options.datePreset);
        else if (options.start && options.end) messagesShowRange(options.start, options.end);
        readMessagesFilters();
    });
}

let messagesOpening = null;
function openMessagesWith(prepare) {
    messagesOpening = prepare;
    return navigateTo('messages').then(moved => {
        messagesOpening = null;
        return moved;
    });
}

let dmarcImapStatus = null;
let dmarcConfiguration = null;

function redirectToLogin(reason) {
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    const here = window.location.pathname + window.location.search;
    window.location.replace(typeof sessionGuardLoginPath === 'function' ? sessionGuardLoginPath(reason, here)
        : here === '/' ? '/login' : `/login?next=${encodeURIComponent(here)}`);
}

async function loginReasonOf(response) {
    return typeof sessionGuardReasonOf === 'function' ? sessionGuardReasonOf(response) : '';
}

async function authenticatedFetch(url, options = {}) {
    const { timeout, ownNotPermitted, ...rest } = options;
    const headers = {
        ...rest.headers,
    };
    let timer = null;
    if (timeout && typeof AbortController === 'function') {
        const control = new AbortController();
        const outer = rest.signal;
        if (outer) {
            if (outer.aborted) control.abort();
            else outer.addEventListener('abort', () => control.abort(), { once: true });
        }
        timer = setTimeout(() => control.abort(), timeout);
        rest.signal = control.signal;
    }

    try {
        const response = await fetch(url, {
            ...rest,
            headers,
            credentials: 'include'
        });

        if (response.status === 401) {
            redirectToLogin(await loginReasonOf(response));
            throw new Error('Authentication required');
        }
        if (response.status === 403 && !ownNotPermitted) await noteNotPermitted(response);

        return response;
    } catch (error) {
        clearTimeout(timer);
        throw error;
    }
}

async function noteNotPermitted(response) {
    try {
        const body = await response.clone().json();
        if (body && body.detail === UI_NOT_PERMITTED) {
            uiNotPermitted();
            refreshAppAccess();
        }
    } catch (e) {
    }
}

async function responseError(response) {
    return new Error(uiHttpErrorText(response.status, await uiReadJson(response)));
}

function actionErrorText(response, result) {
    if (!response.ok) return uiHttpErrorText(response.status, result);
    const msg = result && result.msg;
    if (mailcowWords(msg)) return msg;
    return msg ? `mailcow refused it (${[].concat(msg)[0]})` : uiApiErrorText(result, 'No reason was given');
}
function mailcowWords(msg) {
    return typeof msg === 'string' && /\s/.test(msg.trim()) ? msg : '';
}

async function handleLogout() {
    if (typeof uiConfirmLeave === 'function' && !(await uiConfirmLeave(undefined, { keep: true }))) return;
    try {
        const response = await authenticatedFetch('/api/auth/logout', { method: 'POST' });
        if (!response.ok) {
            showToast('Could not sign out. Try again in a moment.', 'error');
            return;
        }
    } catch (e) {
        return;
    }
    if (typeof uiUnsavedClear === 'function') uiUnsavedClear();
    window.location.href = '/login';
}

async function checkAuthentication() {
    try {
        const infoResponse = await fetch('/api/info', { credentials: 'include' });
        if (infoResponse.ok) {
            const infoData = await infoResponse.json();
            if (!infoData.auth_enabled) {
                return true;
            }
        }
    } catch (e) {
        console.warn('Could not check auth status, assuming enabled');
    }

    let reason = '';
    try {
        const statusResponse = await fetch('/api/auth/status', { credentials: 'include' });
        if (statusResponse.ok) {
            const statusData = await statusResponse.json();
            if (statusData.authenticated) {
                const logoutBtn = document.getElementById('logout-btn');
                if (logoutBtn) logoutBtn.classList.remove('hidden');
                document.getElementById('mobile-logout')?.classList.remove('hidden');
                setAppAccess(statusData);
                return true;
            }
            reason = statusData.reason;
        } else if (statusResponse.status === 401) {
            reason = await loginReasonOf(statusResponse);
        }
    } catch (e) {
    }

    redirectToLogin(reason);
    return false;
}

let currentTab = 'dashboard';
let appTimezone = 'UTC';
let appTimezoneStatus = { valid: true, configured: '' };
let appDateFormat = 'browser';
let appTimeFormat = '24h';
let currentPage = {
    netfilter: 1,
    messages: 1
};
let currentFilters = {
    netfilter: {},
    queue: {},
    messages: {}
};

let mailcowRwConfigured = false;
let rwStatusReady = Promise.resolve();

window.disabledFeatures = [];

const TOGGLEABLE_FEATURES = [
    { id: 'netfilter', label: 'Security', description: 'Review login attempts, bans, and protection rules.' },
    { id: 'queue', label: 'Queue', description: 'Outbound > Queue: mail waiting in the Postfix queue' },
    { id: 'suppressions', label: 'Suppressions', description: 'Outbound > Suppressions: recipients blocked after failed delivery' },
    { id: 'quarantine', label: 'Quarantine', description: 'Review quarantined messages and manage Auto-Rules.' },
    { id: 'rspamd', label: 'Rspamd', description: 'The Rspamd maps that allow or block mail, incoming and outgoing' },
    { id: 'domains', label: 'Domains', description: 'Domain DNS analysis and transports' },
    { id: 'dmarc', label: 'DMARC & TLS', description: 'Review DMARC and TLS reports.' },
    { id: 'mailbox-stats', label: 'Mailbox Stats', description: 'Mailbox and alias statistics' },
    { id: 'rate-limits', label: 'Rate Limits', description: 'Sender rate limit hits and the configured limits' },
    { id: 'devices', label: 'Devices', description: 'Review devices that sync through ActiveSync.' },
    { id: 'logs', label: 'Logs', description: 'Raw service log viewer' },
    { id: 'blacklist', label: 'Blocklists', description: 'Check whether sending IPs are on blocklists.' },
];

function isFeatureDisabled(featureId) {
    return window.disabledFeatures.includes(featureId);
}

const TAB_FEATURES = {
    outbound: { queue: 'queue', suppressions: 'suppressions' }
};

function tabFeatureOn(page, tab) {
    const feature = TAB_FEATURES[page] && TAB_FEATURES[page][tab];
    return !feature || !isFeatureDisabled(feature);
}

function pageTabOn(page, tab) {
    const tabs = Object.keys(TAB_FEATURES[page]);
    return tabs.includes(tab) && tabFeatureOn(page, tab) ? tab : (tabs.find(t => tabFeatureOn(page, t)) || tabs[0]);
}

function pageAllOff(page) {
    return !Object.keys(TAB_FEATURES[page]).some(tab => tabFeatureOn(page, tab));
}

function pageIsOff(page) {
    if (TAB_FEATURES[page]) return pageAllOff(page);
    if (page === 'mailbox-stats' && !isFeatureDisabled('rate-limits')) return false;
    return isFeatureDisabled(page);
}

const PAGE_AREAS = {
    dashboard: 'status', messages: 'messages', netfilter: 'security', outbound: 'outbound', quarantine: 'quarantine',
    rspamd: 'rspamd', status: 'status', domains: 'domains', dmarc: 'dmarc', 'mailbox-stats': 'mailboxes',
    devices: 'mailboxes', logs: 'logs', settings: 'admin', about: 'status',
};
const MENU_ORDER = ['dashboard', 'messages', 'outbound', 'quarantine', 'netfilter', 'rspamd', 'dmarc', 'status',
    'domains', 'mailbox-stats', 'devices', 'logs', 'settings', 'about'];

function userCanView(page) {
    const area = PAGE_AREAS[page];
    return !area || userCan(area);
}

function landingPage() {
    return MENU_ORDER.find(page => userCanView(page) && !pageIsOff(page)) || '';
}

function navEntryShown(btn) {
    return btn.style.display !== 'none' && !btn.classList.contains('ui-no-view');
}

function applyPageAccess() {
    for (const page of Object.keys(PAGE_AREAS)) {
        for (const id of [`tab-${page}`, `mobile-tab-${page}`, `tabbar-${page}`]) {
            const el = document.getElementById(id);
            if (el) el.classList.toggle('ui-no-view', !userCanView(page));
        }
    }
    document.querySelectorAll('.ui-server').forEach(el => el.classList.toggle('ui-no-view', !userCan('status')));
    document.getElementById('suppression-open-map')?.classList.toggle('ui-no-view', !userCan('rspamd'));
    document.querySelectorAll('[data-nav-group]').forEach(group => {
        group.classList.toggle('ui-no-view', ![...group.querySelectorAll('button')].some(navEntryShown));
    });
    const line = document.getElementById('ui-user-line');
    const name = document.getElementById('ui-user-name');
    if (line && name) {
        name.textContent = appAccess.name;
        line.classList.toggle('hidden', !appAccess.name);
    }
    const logout = document.getElementById('logout-btn');
    if (logout) logout.title = appAccess.name ? `Logout (${appAccess.name})` : 'Logout';
}

let accessRefreshAt = 0;
async function refreshAppAccess() {
    if (Date.now() - accessRefreshAt < 10000) return;
    accessRefreshAt = Date.now();
    try {
        const response = await fetch('/api/auth/status', { credentials: 'include' });
        if (!response.ok) return;
        appAccessCheck(await response.json());
    } catch (e) {
    }
}

// Hide the tabs of features
function applyTabFeatures(page) {
    const prefix = `${page}-tab-btn-`;
    let shown = 0;
    for (const tab of Object.keys(TAB_FEATURES[page])) {
        const btn = document.getElementById(prefix + tab);
        const on = tabFeatureOn(page, tab);
        if (btn) btn.classList.toggle('hidden', !on);
        if (on) shown++;
    }
    const bar = document.getElementById(`${page}-tabs`);
    if (bar) bar.classList.toggle('hidden', shown < 2);
}

function applyFeatureToggles() {
    const navIds = feature => [`tab-${feature}`, `mobile-tab-${feature}`, `tabbar-${feature}`];
    for (const feature of window.disabledFeatures) {
        for (const id of navIds(feature)) {
            const el = document.getElementById(id);
            if (el) el.style.display = 'none';
        }
    }
    for (const feature of TOGGLEABLE_FEATURES) {
        if (!window.disabledFeatures.includes(feature.id)) {
            for (const id of navIds(feature.id)) {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            }
        }
    }
    const openMap = document.getElementById('suppression-open-map');
    if (openMap) openMap.style.display = isFeatureDisabled('rspamd') ? 'none' : '';

    for (const page of Object.keys(TAB_FEATURES)) {
        for (const id of [`tab-${page}`, `mobile-tab-${page}`, `tabbar-${page}`]) {
            const el = document.getElementById(id);
            if (el) el.style.display = pageAllOff(page) ? 'none' : '';
        }
        applyTabFeatures(page);
    }
    if (typeof outboundTab !== 'undefined' && outboundTab !== pageTabOn('outbound', outboundTab)) {
        if (currentTab === 'outbound' && !pageAllOff('outbound')) outboundShowTab(outboundTab);
        else outboundTab = pageTabOn('outbound', outboundTab);
    }

    document.querySelectorAll('[data-nav-group]').forEach(group => {
        const visible = [...group.querySelectorAll('button')].some(navEntryShown);
        group.style.display = visible ? '' : 'none';
    });
    
    const blacklistSection = document.getElementById('blacklist-section');
    const dashboardBlacklistCard = document.getElementById('dashboard-blacklist-card');
    const statusBlacklistKpi = document.getElementById('status-kpi-blocklists-cell');
    const statusBlacklistTab = document.getElementById('status-tab-btn-blocklists');
    const blacklistOff = window.disabledFeatures.includes('blacklist');
    if (blacklistOff && typeof statusTab !== 'undefined' && statusTab === 'blocklists') statusShowTab('server');
    [blacklistSection, dashboardBlacklistCard, statusBlacklistKpi, statusBlacklistTab].forEach(el => {
        if (el) el.style.display = blacklistOff ? 'none' : '';
    });

    const mailboxStatsOff = window.disabledFeatures.includes('mailbox-stats');
    const rateLimitsOff = window.disabledFeatures.includes('rate-limits');

    const rateLimitsViewBtn = document.getElementById('mailbox-stats-view-rate-limits');
    if (rateLimitsOff) {
        if (rateLimitsViewBtn) rateLimitsViewBtn.style.display = 'none';
        if (typeof mailboxStatsView !== 'undefined' && mailboxStatsView === 'rate-limits' && !mailboxStatsOff) {
            mailboxStatsSwitchView('statistics');
        }
    } else {
        if (rateLimitsViewBtn) rateLimitsViewBtn.style.display = '';
    }

    const statsViewBtn = document.getElementById('mailbox-stats-view-statistics');
    const viewSwitcher = document.getElementById('mailbox-stats-views');
    if (mailboxStatsOff && !rateLimitsOff) {
        if (statsViewBtn) statsViewBtn.style.display = 'none';
        if (viewSwitcher) viewSwitcher.style.display = 'none';
        if (typeof mailboxStatsView !== 'undefined' && mailboxStatsView === 'statistics') {
            if (currentTab === 'mailbox-stats') {
                mailboxStatsSwitchView('rate-limits');
            } else {
                mailboxStatsView = 'rate-limits';
            }
        }
    } else {
        if (statsViewBtn) statsViewBtn.style.display = '';
        if (viewSwitcher) viewSwitcher.style.display = '';
    }

    const mailboxTabLabel = mailboxStatsOff && !rateLimitsOff ? 'Rate Limits' : 'Mailbox Stats';
    for (const tabId of ['tab-mailbox-stats', 'mobile-tab-mailbox-stats']) {
        const tab = document.getElementById(tabId);
        if (!tab) continue;
        tab.style.display = mailboxStatsOff && rateLimitsOff ? 'none' : '';
        setNavTabLabel(tab, mailboxTabLabel);
    }
}

function setNavTabLabel(tab, label) {
    const span = tab.querySelector('.ui-nav-label');
    if (span) {
        if (span.textContent !== label) span.textContent = label;
        tab.title = label;
        return;
    }
    for (let i = tab.childNodes.length - 1; i >= 0; i--) {
        const node = tab.childNodes[i];
        if (node.nodeType !== Node.TEXT_NODE) continue;
        const current = node.textContent.trim();
        if (!current) continue;
        if (current !== label) node.textContent = node.textContent.replace(current, label);
        return;
    }
    tab.appendChild(document.createTextNode(label));
}

function updateDisabledFeaturesCheckbox(featureId, isChecked, el) {
    const hiddenInput = document.getElementById('setting-disabled_features');
    if (!hiddenInput) return;

    const currentDisabled = new Set(
        hiddenInput.value.split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    );

    if (isChecked) {
        currentDisabled.delete(featureId);
    } else {
        currentDisabled.add(featureId);
    }

    hiddenInput.value = Array.from(currentDisabled).sort().join(',');

    const label = el ? el.closest('label') : null;
    if (label) {
        label.classList.toggle('is-on', isChecked);
        label.classList.toggle('is-off', !isChecked);
    }
}


async function fetchRwStatus() {
    try {
        const res = await authenticatedFetch('/api/rw-status');
        if (res.ok) {
            const data = await res.json();
            mailcowRwConfigured = data.rw_configured;
        }
    } catch (e) {
        console.warn('Failed to fetch RW status:', e);
        mailcowRwConfigured = false;
    }
    showQuarantineRulesAccess();
    if (currentTab === 'netfilter') {
        renderSecurityOverview();
        renderSecurityLists();
        renderSecuritySettings();
    }
    if (currentTab === 'outbound' && allQueueData.length) applyQueueFilters();
    if (currentTab === 'quarantine' && quarantineLastData) renderQuarantineData(quarantineLastData);
}

function showQuarantineRulesAccess() {
    document.getElementById('quarantine-rules-section')?.classList.toggle('hidden', !mailcowRwConfigured);
    const locked = document.getElementById('quarantine-rules-locked');
    if (locked) {
        locked.classList.toggle('hidden', mailcowRwConfigured);
        locked.innerHTML = mailcowRwConfigured ? ''
            : uiLocked('Auto-Rules are locked', `Rules release or delete held messages in mailcow by themselves, so they ${UI_RW_KEY_TEXT}`);
    }
    return mailcowRwConfigured;
}

document.addEventListener('DOMContentLoaded', async () => {
    uiInitMenus();
    console.log('=== mailcow Logs Viewer Initializing ===');

    const isAuthenticated = await checkAuthentication();
    if (!isAuthenticated) {
        console.log('Authentication required - showing login modal');
        return;
    }
    applyPageAccess();

    const requiredElements = [
        'app-title',
        'content-dashboard',
        'content-messages',
        'content-netfilter',
        'content-outbound',
        'content-quarantine',
        'content-status',
        'content-settings',
        'content-domains'
    ];

    const missing = requiredElements.filter(id => !document.getElementById(id));
    if (missing.length > 0) {
        console.error('Missing required elements:', missing);
    } else {
        console.log('[OK] All required DOM elements found');
    }

    await loadAppInfo();
    loadMailcowVersionStatus();
    rwStatusReady = fetchRwStatus().catch(() => {});

    const routeInfo = typeof initRouter === 'function' ? initRouter() : { baseRoute: 'dashboard', params: {} };
    const initialTab = routeInfo.baseRoute || routeInfo;
    const initialParams = routeInfo.params || {};
    console.log('Initial tab from URL:', initialTab, 'params:', initialParams);

    switchTab(initialTab, initialParams);

    startPageRefresh();

    console.log('=== Initialization Complete ===');
});

const AUTH_OFF_BANNER_DISMISSED_KEY = 'authOffBannerDismissed';

function authOffBannerDismissed() {
    try { return localStorage.getItem(AUTH_OFF_BANNER_DISMISSED_KEY) === '1'; } catch (e) { return false; }
}

function dismissAuthOffBanner() {
    try { localStorage.setItem(AUTH_OFF_BANNER_DISMISSED_KEY, '1'); } catch (e) {}
    const banner = document.getElementById('auth-off-banner');
    if (banner) banner.classList.add('hidden');
}

function setAppTimezone(info) {
    let zone = (info && info.timezone) || 'UTC';
    try {
        new Intl.DateTimeFormat('en-US', { timeZone: zone });
    } catch (e) {
        console.warn('Unknown time zone from the server, using UTC:', zone);
        zone = 'UTC';
    }
    appTimezone = zone;
    appTimezoneStatus = {
        valid: !info || info.timezone_valid !== false,
        configured: (info && typeof info.timezone_configured === 'string') ? info.timezone_configured : '',
    };
    if (info && typeof info.date_format === 'string') appDateFormat = info.date_format;
    if (info && typeof info.time_format === 'string') appTimeFormat = info.time_format;
}

let appTitleText = document.title;
let documentTitleQueued = false;
function queueDocumentTitle() {
    if (documentTitleQueued) return;
    documentTitleQueued = true;
    requestAnimationFrame(() => {
        documentTitleQueued = false;
        if (typeof currentTab === 'undefined' || !currentTab) return;
        const name = TAB_LABELS[currentTab] || currentTab;
        const sub = topbarSubLabel(currentTab);
        document.title = [name, sub && sub !== name ? sub : '', appTitleText].filter(Boolean).join(' · ');
    });
}

async function loadAppInfo() {
    try {
        const response = await authenticatedFetch('/api/info');
        const data = await response.json();

        if (data.app_title) {
            document.getElementById('app-title').textContent = data.app_title;
            appTitleText = data.app_title;
            queueDocumentTitle();
            const phoneTitle = document.getElementById('mtop-app-title');
            if (phoneTitle) phoneTitle.textContent = data.app_title;

            const footerName = document.getElementById('app-name-footer');
            if (footerName) {
                footerName.textContent = data.app_title;
            }
        }

        if (data.app_logo_url) {
            const logoImg = document.getElementById('app-logo');
            logoImg.src = data.app_logo_url;
            logoImg.classList.remove('hidden');
            document.getElementById('default-logo').classList.add('hidden');
            const phoneLogo = document.getElementById('mtop-logo');
            if (phoneLogo) phoneLogo.src = data.app_logo_url;
        }

        const footerVersion = document.getElementById('app-version-footer');
        if (footerVersion && data.version) {
            footerVersion.textContent = `v${data.version}`;
        }

        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            if (data.auth_enabled) {
                logoutBtn.classList.remove('hidden');
            } else {
                logoutBtn.classList.add('hidden');
            }
        }
        document.getElementById('mobile-logout')?.classList.toggle('hidden', !data.auth_enabled);

        const authOffBanner = document.getElementById('auth-off-banner');
        if (authOffBanner) authOffBanner.classList.toggle('hidden', data.auth_enabled !== false || authOffBannerDismissed());

        setAppTimezone(data);

        if (data.disabled_features && Array.isArray(data.disabled_features)) {
            window.disabledFeatures = data.disabled_features;
            console.log('Disabled features:', window.disabledFeatures);
            applyFeatureToggles();
        }
        window.settingsEditable = data.settings_edit_via_ui_enabled !== false;

        loadAppVersionStatus();
        const connectionChecked = loadMailcowConnectionStatus();

        placeShellUtilities();
        window.matchMedia('(max-width: 760px)').addEventListener('change', placeShellUtilities);
        window.matchMedia('(max-width: 760px)').addEventListener('change', () => placeTopbar());
        watchTopbarCrumbs();
        connectionChecked.then(startNavCounters);
        startAttention();
    } catch (error) {
        console.error('Failed to load app info:', error);
    }
}

function placeShellUtilities() {
    const tools = document.getElementById('ui-utilities');
    const phoneSlot = document.getElementById('ui-mtop-actions');
    const foot = document.getElementById('app-footer');
    if (!tools || !phoneSlot || !foot) return;
    if (window.matchMedia('(max-width: 760px)').matches) {
        if (tools.parentNode !== phoneSlot) phoneSlot.appendChild(tools);
    } else if (tools.parentNode !== foot) {
        foot.appendChild(tools);
    }
}

const TOPBAR_SKIP = new Set(['messages']);
let topbarMoves = [];
let topbarRoute = null;

function topbarMove(el, target) {
    if (!el || !target) return;
    const mark = document.createComment('topbar');
    el.replaceWith(mark);
    target.appendChild(el);
    topbarMoves.push([el, mark]);
}

function topbarRestore() {
    for (const [el, mark] of topbarMoves.reverse()) mark.replaceWith(el);
    topbarMoves = [];
    document.querySelectorAll('.ui-page-crumbs, .ui-head-slot, .ui-head-links').forEach(el => el.remove());
}

function placeTopbar(route = topbarRoute) {
    topbarRoute = route;
    const bar = document.getElementById('ui-topbar');
    if (!bar) return;
    topbarRestore();
    const page = route ? document.getElementById(`content-${route}`) : null;
    const head = page ? page.querySelector('.ui-page-head') : null;
    const intro = head ? head.firstElementChild : null;
    const title = intro ? intro.querySelector('.ui-h1') : null;
    const on = !!title && !TOPBAR_SKIP.has(route) && !window.matchMedia('(max-width: 760px)').matches;
    document.documentElement.classList.toggle('ui-has-topbar', on);
    if (!on) {
        placeHeadPrimary(route, intro, title);
        return;
    }

    const brandSlot = document.getElementById('ui-topbar-brand');
    topbarMove(document.querySelector('.ui-sidenav .ui-brand'), brandSlot);
    topbarMove(document.getElementById('ui-nav-toggle'), brandSlot);
    const crumbs = document.createElement('nav');
    crumbs.className = 'ui-crumbs ui-page-crumbs';
    crumbs.setAttribute('aria-label', 'You are here');
    title.before(crumbs);
    topbarMove(title, document.getElementById('ui-topbar-title'));
    [...head.children].filter(el => el !== intro).forEach(el => topbarMove(el, document.getElementById('ui-topbar-actions')));
    if (route === 'dmarc') topbarMove(document.getElementById('dmarc-last-sync-info'), intro);
    updateTopbarCrumbs();
}

function placeHeadPrimary(route, intro, title) {
    if (!title || !window.matchMedia('(max-width: 760px)').matches) return;
    const primary = intro.parentNode.querySelector('.ui-head-primary');
    if (!primary) return;
    const slot = document.createElement('span');
    slot.className = 'ui-head-slot';
    title.after(slot);
    topbarMove(primary, slot);
    if (route === 'dmarc') {
        const links = document.createElement('div');
        links.className = 'ui-head-links';
        intro.appendChild(links);
        ['dmarc-last-sync-info', 'dmarc-manage-btn'].forEach(id => topbarMove(document.getElementById(id), links));
        topbarMove(document.getElementById('dmarc-upload-btn'), slot);
    }
}

function topbarSubLabel(route) {
    const page = document.getElementById(`content-${route}`);
    const tab = page && page.querySelector('[role="tab"][aria-selected="true"], [role="tab"].active, .settings-edit-nav [aria-current="true"]');
    if (!tab) return '';
    const label = tab.cloneNode(true);
    label.querySelectorAll('.ui-tab-n, .ui-count, .ui-nav-count, .hidden').forEach(n => n.remove());
    return label.textContent.replace(/\s+/g, ' ').trim();
}

let topbarPageCrumbs = null;

function setPageCrumbs(route, sub, back, labels) {
    topbarPageCrumbs = labels && labels.length ? { route, sub, back, labels } : null;
    updateTopbarCrumbs();
}

function updateTopbarCrumbs() {
    queueDocumentTitle();
    const nav = document.querySelector('.ui-page-crumbs');
    if (!nav || !topbarRoute) return;
    const route = topbarRoute;
    const item = document.getElementById(`tab-${route}`);
    const group = item && item.closest('.ui-nav-group');
    const groupLabel = group && group.querySelector('.ui-nav-group-label');
    const name = TAB_LABELS[route] || route;
    const sub = topbarSubLabel(route);
    const parts = [];
    if (groupLabel) parts.push(`<span class="ui-crumb-group">${escapeHtml(groupLabel.textContent.trim())}</span>`);
    const inner = topbarPageCrumbs && topbarPageCrumbs.route === route && topbarPageCrumbs.sub === sub ? topbarPageCrumbs : null;
    parts.push(sub ? `<button type="button" class="ui-crumb" onclick="topbarOpenPage('${escapeJsArg(route)}')">${escapeHtml(name)}</button>`
        : inner ? `<button type="button" class="ui-crumb" onclick="${inner.back}">${escapeHtml(name)}</button>`
        : `<span class="ui-crumb-current" aria-current="page">${escapeHtml(name)}</span>`);
    if (sub && sub !== name) {
        parts.push(inner ? `<button type="button" class="ui-crumb" onclick="${inner.back}">${escapeHtml(sub)}</button>`
            : `<span class="ui-crumb-current" aria-current="page">${escapeHtml(sub)}</span>`);
    }
    if (inner) {
        inner.labels.forEach((item, i) => {
            const label = typeof item === 'string' ? item : item.label;
            const action = typeof item === 'string' ? null : item.action;
            parts.push(i === inner.labels.length - 1 ? `<span class="ui-crumb-current" aria-current="page">${escapeHtml(label)}</span>`
                : action ? `<button type="button" class="ui-crumb" onclick="${escapeHtml(action)}">${escapeHtml(label)}</button>`
                : `<span class="ui-crumb-group">${escapeHtml(label)}</span>`);
        });
    }
    nav.innerHTML = parts.join('<span class="ui-crumb-sep" aria-hidden="true">›</span>');
}

function topbarOpenPage(route) {
    if (typeof SUBPAGES !== 'undefined' && SUBPAGES[route]) navigateTo(route, { sub: subpageFirst(route) });
    else if (route === 'dmarc' && typeof dmarcOpenTab === 'function') dmarcOpenTab();
    else navigateTo(route);
}

function watchTopbarCrumbs() {
    const content = document.querySelector('.ui-content');
    if (!content || typeof MutationObserver === 'undefined') return;
    let queued = false;
    new MutationObserver(records => {
        if (queued || !records.some(r => r.target.matches && r.target.matches('[role="tab"], .settings-edit-tab'))) return;
        queued = true;
        requestAnimationFrame(() => { queued = false; updateTopbarCrumbs(); });
    }).observe(content, { subtree: true, attributes: true, attributeFilter: ['aria-selected', 'aria-current', 'class'] });
}

function setNavCount(page, count, isFail, title) {
    for (const el of [document.getElementById(`nav-count-${page}`), document.getElementById(`mobile-nav-count-${page}`)]) {
        if (!el) continue;
        if (count > 0) {
            el.textContent = count.toLocaleString();
            el.classList.toggle('is-fail', !!isFail);
            el.title = title || '';
            el.classList.remove('hidden');
        } else {
            el.classList.add('hidden');
        }
    }
}

const READ_FAILED = { failed: true };

function serverCheckFound(key, data) {
    if (data === READ_FAILED) return null;
    if (!data) return [];
    if (key === 'connection') return data.connected === false ? [data] : [];
    if (key === 'blocklist') return data.status === 'error' ? null : data.status === 'listed' ? [data] : [];
    if (key === 'containers') {
        if (data.containers_known === false) return null;
        return data.containers && data.containers.stopped > 0 ? [data.containers] : [];
    }
    if (key === 'dmarc') {
        return (data.insights || []).filter(i =>
            i.recommendations.some(r => r.type === 'tighten_policy' || r.type === 'low_pass_rate') || (i.new_sources && i.new_sources.length > 0));
    }
    return [data];
}

let mailcowConnection;

const NAV_COUNTERS_EVERY = 5 * 60 * 1000;
let navCountersAt = 0;

let navCountersPending = false;
function navCountersTick() {
    if (navCountersPending || document.hidden || Date.now() - navCountersAt < NAV_COUNTERS_EVERY - 2000) return;
    navCountersAt = Date.now();
    navCountersPending = true;
    loadMailcowConnectionStatus().finally(() => { navCountersPending = false; }).then(loadNavCounters);
}

function startNavCounters() {
    loadNavCounters();
    setInterval(navCountersTick, PAGE_REFRESH_TICK);
    document.addEventListener('visibilitychange', navCountersTick);
}

async function loadNavCounters() {
    navCountersAt = Date.now();
    const off = (feature, area) => (window.disabledFeatures || []).includes(feature) || !userCan(area);
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : READ_FAILED;
        } catch (e) {
            return READ_FAILED;
        }
    };
    const [dashboard, queue, quarantine, insights, summary, blacklist, info] = await Promise.all([
        off('netfilter', 'security') ? null : get('/api/logs/netfilter/overview'),
        off('queue', 'outbound') ? null : get('/api/queue'),
        off('quarantine', 'quarantine') ? null : get('/api/quarantine'),
        off('dmarc', 'dmarc') ? null : get('/api/dmarc/insights'),
        off('', 'status') ? null : get('/api/status/summary'),
        off('blacklist', 'status') ? null : get('/api/blacklist/summary'),
        off('', 'status') ? null : get('/api/settings/info'),
    ]);

    if (dashboard !== READ_FAILED) {
        const failedLogins = dashboard ? dashboard.failed_logins || 0 : 0;
        setNavCount('netfilter', failedLogins, false, `${failedLogins} failed logins in the last 24 hours`);
    }
    if (queue !== READ_FAILED) {
        const queued = queue && Array.isArray(queue.data) ? queue.data.length : 0;
        setNavCount('outbound', queued, false, `${queued} messages in the queue`);
    }
    if (quarantine !== READ_FAILED) {
        const held = quarantine ? (quarantine.total || (quarantine.data || []).length) : 0;
        setNavCount('quarantine', held, false, `${held} quarantined messages`);
    }
    if (insights !== READ_FAILED) {
        const dmarcActions = serverCheckFound('dmarc', insights).length;
        setNavCount('dmarc', dmarcActions, false, `${dmarcActions} DMARC insights`);
    }

    const found = {
        connection: serverCheckFound('connection', off('', 'status') ? null : mailcowConnection),
        containers: serverCheckFound('containers', summary),
        blocklist: serverCheckFound('blocklist', blacklist),
    };
    const problems = [];
    if (found.connection && found.connection.length) problems.push('not connected to mailcow');
    const stopped = found.containers && found.containers.length ? found.containers[0].stopped : 0;
    if (stopped > 0) problems.push(`${stopped} container${stopped === 1 ? '' : 's'} stopped`);
    if (found.blocklist && found.blocklist.length) problems.push('listed on a blocklist');
    const unchecked = Object.values(found).includes(null);
    if (problems.length || !unchecked) setNavCount('status', problems.length, true, problems.join(', '));

    const label = problems.length ? `${problems.length} problem${problems.length === 1 ? '' : 's'}`
        : unchecked ? 'Could not check' : 'No problems';
    const small = document.getElementById('ui-server-problems');
    if (small) {
        small.textContent = label;
        small.title = problems.join(', ');
        small.classList.toggle('has-problems', problems.length > 0);
    }
    const pip = document.getElementById('tabbar-pip-status');
    if (pip && (problems.length || !unchecked)) pip.classList.toggle('hidden', problems.length === 0);

    const host = document.getElementById('ui-server-host');
    const url = info && info.configuration ? info.configuration.mailcow_url : '';
    if (host && url) {
        try { host.textContent = new URL(url).hostname; } catch (e) { host.textContent = url; }
    }
}

async function loadMailcowConnectionStatus() {
    if (!userCan('status')) return;
    try {
        const response = await authenticatedFetch('/api/status/mailcow-connection');
        if (!response.ok) {
            mailcowConnection = READ_FAILED;
            return;
        }

        const data = await response.json();
        mailcowConnection = data;
        const indicator = document.getElementById('mailcow-connection-indicator');

        if (indicator) {
            indicator.classList.remove('hidden');
            if (data.connected) {
                indicator.classList.remove('text-red-500', 'text-gray-400');
                indicator.classList.add('text-green-500');
                indicator.title = 'Connected to mailcow';
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd"></path>';
                }
            } else {
                indicator.classList.remove('text-green-500', 'text-gray-400');
                indicator.classList.add('text-red-500');
                indicator.title = 'Not connected to mailcow';
                const svg = indicator.querySelector('svg');
                if (svg) {
                    svg.innerHTML = '<path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clip-rule="evenodd"></path>';
                }
            }
        }
    } catch (error) {
        console.error('Failed to load mailcow connection status:', error);
        mailcowConnection = READ_FAILED;
        const indicator = document.getElementById('mailcow-connection-indicator');
        if (indicator) {
            indicator.classList.remove('hidden');
            indicator.classList.remove('text-green-500', 'text-red-500');
            indicator.classList.add('text-gray-400');
            indicator.title = 'Connection status unknown';
        }
    }
}

async function loadAppVersionStatus() {
    if (!userCan('status')) return;
    try {
        const response = await authenticatedFetch('/api/status/app-version');
        if (!response.ok) return;

        const data = await response.json();
        const updateBadge = document.getElementById('update-badge');
        const footerVersion = document.getElementById('app-version-footer');

        if (footerVersion) {
            footerVersion.textContent = `v${data.current_version}`;
        }

        if (updateBadge && data.update_available) {
            updateBadge.classList.remove('hidden');
            updateBadge.title = `Update available: v${data.latest_version}`;
            updateBadge.textContent = `v${data.latest_version} available`;

            appUpdateInfo = data;
            updateBadge.onclick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showAppUpdateModal();
            };
        } else if (updateBadge) {
            updateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load app version status:', error);
    }
}

let appUpdateInfo = null;

function showAppUpdateModal() {
    if (!appUpdateInfo) return;
    showMarkdownModal(`Update: v${appUpdateInfo.latest_version}`, appUpdateInfo.changelog || 'No changelog available');
}

function showMarkdownModal(title, markdownContent) {
    let htmlContent = escapeHtml(markdownContent);
    try {
        if (typeof marked !== 'undefined') {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            htmlContent = renderMarkdown(markdownContent);
            const tpl = document.createElement('template');
            tpl.innerHTML = htmlContent;
            tpl.content.querySelectorAll('a[href^="http"]').forEach(a => {
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
            });
            htmlContent = tpl.innerHTML;
        }
    } catch (e) {
        console.error('Failed to parse markdown:', e);
    }

    if (uiIsPhone()) {
        uiSheetShow('markdown-sheet', {
            label: title,
            head: `<h3 class="ui-sheet-title">${escapeHtml(title)}</h3>`,
            body: `<div class="markdown-body">${htmlContent}</div>`,
            expand: true,
            progress: true
        });
        return;
    }

    const modal = document.getElementById('changelog-modal');
    const modalTitle = modal?.querySelector('h3');
    const content = document.getElementById('changelog-content');

    if (modal && content) {
        if (modalTitle) {
            modalTitle.textContent = title;
        }

        content.innerHTML = `<div class="markdown-body">${htmlContent}</div>`;
        revealChangelogModal(modal);
    }
}

async function loadMailcowVersionStatus() {
    if (!userCan('status')) return;
    try {
        const response = await authenticatedFetch('/api/status/version');
        if (!response.ok) return;

        const data = await response.json();
        const updateIcon = document.getElementById('mailcow-update-icon');
        const footerVersion = document.getElementById('mailcow-version-footer');
        const footerUpdateBadge = document.getElementById('mailcow-update-badge');

        if (footerVersion && data.current_version) {
            footerVersion.textContent = `mailcow: v${data.current_version}`;
        }

        if (data.update_available) {
            window.mailcowUpdateVersion = data.latest_version;
            window.mailcowUpdateName = data.name || '';
            window.mailcowUpdateChangelog = data.changelog || 'No changelog available';
            if (footerUpdateBadge) footerUpdateBadge.textContent = `mailcow ${data.latest_version} available`;

            const handleClick = (e) => {
                e.preventDefault();
                e.stopPropagation();
                showMailcowUpdateModal();
            };

            if (updateIcon) {
                updateIcon.classList.remove('hidden');
                updateIcon.title = `Update available: ${data.latest_version}`;
                updateIcon.onclick = handleClick;
            }

            if (footerUpdateBadge) {
                footerUpdateBadge.classList.remove('hidden');
                footerUpdateBadge.title = `Update available: ${data.latest_version}`;
                footerUpdateBadge.onclick = handleClick;
            }
        } else {
            if (updateIcon) updateIcon.classList.add('hidden');
            if (footerUpdateBadge) footerUpdateBadge.classList.add('hidden');
        }
    } catch (error) {
        console.error('Failed to load mailcow version status:', error);
    }
}

let lastDataCache = {
    messages: null,
    netfilter: null,
    queue: null,
    quarantine: null,
    dashboard: null,
    settings: null
};

let versionInfoCache = {
    app_version: null,
    version_info: null
};

const PAGE_REFRESH_TICK = 30000;
const PAGE_REFRESH_TIMEOUT = 20000;
const pageRefreshers = {};
const pageRefreshState = { route: null, at: 0, timer: null };

function registerPageRefresh(route, every, run) {
    pageRefreshers[route] = { every, run, busy: false };
}

function pageRefreshEvery(refresher) {
    return typeof refresher.every === 'function' ? refresher.every() : refresher.every;
}

function pageRefreshLoaded(route) {
    pageRefreshState.route = route;
    pageRefreshState.at = Date.now();
}

function pageRefreshRetry(route) {
    if (pageRefreshState.route === route) pageRefreshState.at = 0;
}

async function pageRefreshNow() {
    const route = currentTab;
    const refresher = pageRefreshers[route];
    if (!refresher || refresher.busy || pageIsOff(route) || !userCanView(route)) return;
    const modal = document.getElementById('message-modal');
    if (modal && !modal.classList.contains('hidden') && !modal.classList.contains('ui-docked')) return;
    refresher.busy = true;
    pageRefreshState.route = route;
    pageRefreshState.at = Date.now();
    try {
        await Promise.race([refresher.run(), new Promise(resolve => setTimeout(resolve, PAGE_REFRESH_TIMEOUT))]);
    } catch (error) {
        console.error(`Refresh of ${route} failed:`, error);
    } finally {
        refresher.busy = false;
    }
}

function pageRefreshTick() {
    if (document.hidden) return;
    const refresher = pageRefreshers[currentTab];
    if (!refresher) return;
    if (pageRefreshState.route !== currentTab) pageRefreshLoaded(currentTab);
    if (Date.now() - pageRefreshState.at >= pageRefreshEvery(refresher) - 2000) pageRefreshNow();
}

function startPageRefresh() {
    if (pageRefreshState.timer) return;
    pageRefreshState.timer = setInterval(pageRefreshTick, PAGE_REFRESH_TICK);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) pageRefreshTick(); });
}

registerPageRefresh('dashboard', 30000, () => smartRefreshDashboard());
registerPageRefresh('messages', 30000, () => smartRefreshMessages());
registerPageRefresh('netfilter', 30000, async () => {
    await smartRefreshNetfilter();
    await loadSecurityOverview();
    fail2banSettingsLoaded = false;
    loadFail2BanSettings();
    if (typeof refreshProtectionHits === 'function') refreshProtectionHits();
    if (typeof refreshSmtpAbusePanel === 'function' && Date.now() - smtpAbuseLoadedAt >= 58000) refreshSmtpAbusePanel();
});
registerPageRefresh('outbound', 30000, async () => {
    if (!isFeatureDisabled('queue')) await smartRefreshQueue();
    if (!isFeatureDisabled('suppressions')) {
        if (outboundTab === 'suppressions') await smartRefreshSuppressions();
        else await loadSuppressionStats();
    }
});
registerPageRefresh('quarantine', 30000, async () => {
    await smartRefreshQuarantine();
    if (quarantineTab !== 'rules' || !showQuarantineRulesAccess()) return;
    await loadQuarantineRules({ quiet: true });
    const history = document.getElementById('quarantine-rules-history');
    if (history && !history.classList.contains('hidden')) await loadQuarantineRuleHistory({ quiet: true });
});
registerPageRefresh('status', 30000, async () => {
    statusQuiet = true;
    try {
        await loadStatus();
    } finally {
        statusQuiet = false;
    }
});
registerPageRefresh('rspamd', 60000, () => refreshRspamdMaps());
registerPageRefresh('settings', 30000, async () => {
    await smartRefreshSettings();
    if (typeof refreshUsersPanel === 'function') await refreshUsersPanel();
});
registerPageRefresh('domains', 5 * 60 * 1000, () => refreshDomains());
registerPageRefresh('dmarc', 5 * 60 * 1000, () => dmarcReload(true));
registerPageRefresh('mailbox-stats', () => mailboxStatsRefreshEvery(), () => refreshMailboxStatsPage());
registerPageRefresh('devices', 60000, () => loadDevices(devicesPage, { quiet: true }));

function hasDataChanged(newData, cacheKey) {
    const oldData = lastDataCache[cacheKey];
    if (!oldData) return true;

    const newJson = JSON.stringify(newData);
    const oldJson = JSON.stringify(oldData);
    return newJson !== oldJson;
}

async function smartRefreshMessages() {
    const filters = currentFilters.messages || {};
    const busy = () => messagesFullLoad || messagesPaging.loading;
    if (messagesNoId || messagesRefreshing || busy()) return;
    refreshMessagesNoId();
    if (!lastDataCache.messages) return loadMessages();

    const free = () => messagesAtNewEdge() && !uiTextHeld(document.getElementById('messages-logs'));
    const gen = messagesGen;
    messagesRefreshing = true;
    try {
        if (messagesOrder === 'desc' && free()) {
            const response = await messagesFetch(`/api/messages?${messagesQueryParams()}`, PAGE_REFRESH_TIMEOUT);
            if (!response.ok) return;
            const data = await response.json();
            if (gen !== messagesGen || busy()) return;
            if (free()) {
                if (!messagesSameAsShown(data)) {
                    const now = messagesNewGeneration();
                    uiKeepFocus(document.getElementById('messages-logs'), 'data-key', () => renderMessagesData(data));
                    loadMessageFacets(filters, now);
                } else {
                    if (data.watermark != null) messagesNew.watermark = data.watermark;
                    loadMessageFacets(filters, gen);
                }
                return;
            }
        }
        if (messagesOrder === 'asc' && messagesPaging.cursor) {
            loadMessageFacets(filters, gen);
            return;
        }
        if (messagesNew.watermark === null) return;
        const params = messagesFilterParams(filters);
        params.set('after_id', messagesNew.watermark);
        const response = await messagesFetch(`/api/messages/new?${params}`, PAGE_REFRESH_TIMEOUT);
        if (!response.ok) return;
        const data = await response.json();
        if (gen !== messagesGen || busy()) return;
        messagesNew.count = data.count || 0;
        if (messagesOrder === 'asc' && free()) {
            messagesRefreshing = false;
            await messagesShowNew({ quiet: true });
            return;
        }
        renderMessagesNew();
        loadMessageFacets(filters, gen);
    } catch (error) {
        if (error.name !== 'AbortError') console.error('Messages refresh failed:', error);
    } finally {
        messagesRefreshing = false;
    }
}

const messagesNew = { watermark: null, count: 0 };

function messagesSameAsShown(data) {
    const shown = lastDataCache.messages;
    if (!shown) return false;
    const rows = data.data || [];
    const had = shown.data || [];
    return data.total === shown.total && rows.length <= had.length && JSON.stringify(rows) === JSON.stringify(had.slice(0, rows.length));
}

function messagesScroller(container) {
    for (let el = container; el && el !== document.body; el = el.parentElement) {
        const overflow = getComputedStyle(el).overflowY;
        if ((overflow === 'auto' || overflow === 'scroll') && el.scrollHeight > el.clientHeight + 1) return el;
    }
    return document.scrollingElement || document.documentElement;
}

function messagesInView(scroller) {
    if (scroller === document.scrollingElement || scroller === document.documentElement) return { top: 0, bottom: window.innerHeight };
    const box = scroller.getBoundingClientRect();
    return { top: box.top, bottom: box.bottom };
}

function messagesAtNewEdge() {
    const container = document.getElementById('messages-logs');
    if (!container || !container.getClientRects().length) return false;
    const rows = container.querySelectorAll('.ui-msg-item');
    if (!rows.length) return true;
    const view = messagesInView(messagesScroller(container));
    if (messagesOrder === 'asc') {
        return !messagesPaging.cursor && rows[rows.length - 1].getBoundingClientRect().bottom <= view.bottom + 8;
    }
    return rows[0].getBoundingClientRect().top >= view.top - 8;
}

function renderMessagesNew() {
    const list = document.querySelector('#messages-logs .ui-msg-list');
    let wrap = document.getElementById('messages-new-wrap');
    const count = messagesNew.count;
    if (!list || !count) {
        if (wrap) wrap.hidden = true;
        return;
    }
    if (!wrap) {
        wrap = document.createElement('div');
        wrap.id = 'messages-new-wrap';
        wrap.className = 'ui-msg-new-wrap';
        wrap.innerHTML = `<button type="button" class="ui-msg-new" onclick="messagesShowNew()">
            <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d=""></path></svg>
            <span></span></button>`;
    }
    const top = messagesOrder !== 'asc';
    wrap.classList.toggle('is-top', top);
    const bar = document.querySelector('#content-messages .ui-msg-searchbar');
    const sticky = bar && getComputedStyle(bar).position === 'sticky';
    wrap.style.setProperty('--ui-msg-new-top', sticky ? `${bar.offsetHeight}px` : '0px');
    if (top ? list.previousElementSibling !== wrap : list.nextElementSibling !== wrap) {
        if (top) list.before(wrap); else list.after(wrap);
    }
    wrap.querySelector('path').setAttribute('d', top ? 'M5 15l7-7 7 7' : 'M19 9l-7 7-7-7');
    wrap.querySelector('span').textContent = `${count.toLocaleString()} new ${count === 1 ? 'message' : 'messages'}`;
    wrap.hidden = false;
}

async function messagesShowNew({ quiet = false } = {}) {
    const container = document.getElementById('messages-logs');
    if (!container) return;
    if (messagesOrder === 'asc') {
        const shown = container.querySelectorAll('.ui-msg-item').length;
        const stillFree = () => messagesAtNewEdge() && !uiTextHeld(container);
        await loadMessages({ quiet, rows: Math.max(50, shown + messagesNew.count), toEnd: true, applyIf: quiet ? stillFree : null });
        return;
    }
    const scroller = messagesScroller(container);
    await loadMessages();
    if (scroller !== container) scroller.scrollTop = 0;
}

function messagesScrollToEnd(container) {
    const scroller = messagesScroller(container);
    scroller.scrollTop = scroller.scrollHeight;
}

function renderMessageRow(msg) {
    const tone = messageRowTone(msg);
    return `
        <div class="ui-msg-item${tone ? ` ui-msg-${tone}` : ''}" data-key="${escapeHtml(msg.correlation_key || '')}"${msg.message_id ? ` data-mid="${encodeURIComponent(msg.message_id)}"` : ''} onclick="if (!uiRowHeld(event)) viewMessageDetails('${escapeJsArg(msg.correlation_key)}')">
            <div class="ui-msg-l1">
                <b class="ui-msg-from ui-fit" title="${escapeHtml(msg.sender || '')}">${messageRowAddress(msg.sender)}</b>
                <button type="button" class="ui-row-open ui-msg-at" aria-label="${msg.first_seen ? `${escapeHtml(formatListTime(msg.first_seen))}, open` : 'Open'} the message: ${escapeHtml(msg.subject || 'No subject')}">${uiTime(msg.first_seen, formatListTime(msg.first_seen), { title: formatTime(msg.first_seen) })}</button>
            </div>
            <div class="ui-msg-to ui-fit" title="${escapeHtml(msg.recipient || '')}"><span class="ui-msg-to-word">to</span> ${messageRowAddress(msg.recipient)}${renderRecipientMore(msg)}</div>
            <div class="ui-msg-l3">
                <p class="ui-msg-sub" dir="auto" title="${escapeHtml(msg.subject || 'No subject')}">${escapeHtml(msg.subject || 'No subject')}</p>
                <span class="ui-msg-tags">${uiCorrelationTag(msg, { folder: true })}${msg.direction ? uiDirectionTag(msg.direction, { short: true }) : ''}${msg.is_spam ? '<span class="ui-tag ui-tag-spam">SPAM</span>' : ''}</span>
            </div>
        </div>`;
}

function messageRowAddress(value) {
    const html = value ? uiEntity('address', value, { plain: true, fit: true }) : 'Unknown';
    return html.startsWith('<span class="ui-ent') ? html : `<span class="ui-fit-text">${html}</span>`;
}

function messageRowTone(msg) {
    const tone = UI_STATUS_TONE[msg.final_status];
    if (tone) return tone;
    return msg.is_complete === false ? 'warn' : '';
}

function renderMessagesData(data) {
    const container = document.getElementById('messages-logs');
    if (!container) return;
    showMessagesFirstPage(container, data);
    if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
}

function showMessagesFirstPage(container, data) {
    lastDataCache.messages = { ...data, watermark: null };
    messagesNew.watermark = data.watermark ?? null;
    messagesNew.count = 0;
    const rows = data.data || [];
    messagesPaging.page = 1;
    messagesPaging.total = data.total || rows.length;
    messagesPaging.cursor = rows.length ? data.next_cursor || null : null;
    currentPage.messages = 1;
    setMessagesCount(messagesPaging.total);
    if (!rows.length) {
        container.innerHTML = messagesFiltersOn() ? `
            <div class="ui-empty">
                <p><b>No messages match these filters</b></p>
                <p><button onclick="clearMessagesFilters()" class="ui-btn ui-btn-sm">Clear filters</button></p>
            </div>` : '<p class="ui-empty">No messages yet. Mail that mailcow sends and receives shows up here.</p>';
        return;
    }
    renderMessagesList(container, data);
}

function setMessagesCount(total) {
    const countEl = document.getElementById('messages-count');
    if (countEl) countEl.textContent = total === null ? '' : messagesNoId
        ? uiCountLabel(total || 0, 'unlinked message', 'unlinked messages')
        : uiCountLabel(total || 0, 'message', 'messages');
}

const messagesPaging = { page: 1, pages: 1, total: 0, cursor: null, loading: false, failed: false, observer: null };
let messagesGen = 0;
let messagesFullLoad = false;
let messagesRefreshing = false;
const messagesRequests = new Set();

function messagesNewGeneration() {
    messagesGen++;
    messagesRequests.forEach(control => control.abort());
    messagesRequests.clear();
    messagesPaging.loading = false;
    messagesPaging.failed = false;
    return messagesGen;
}

async function messagesFetch(url, timeout = 0) {
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    if (control) messagesRequests.add(control);
    try {
        const response = await authenticatedFetch(url, { ...(control ? { signal: control.signal } : {}), ...(timeout ? { timeout } : {}) });
        const data = response.ok ? await response.json() : await uiReadJson(response);
        return { ok: response.ok, status: response.status, json: async () => data };
    } finally {
        if (control) messagesRequests.delete(control);
    }
}

const MESSAGES_FILTER_KEYS = ['search', 'sender', 'recipient', 'direction', 'user', 'status', 'ip', 'address', 'domain', 'exact_ip', 'exact', 'start_date', 'end_date'];

let messagesExact = null;
const MESSAGES_EXACT_FIELDS = ['ip'];

function setMessagesFilters(filters) {
    messagesExact = null;
    currentFilters.messages = filters;
}

function messagesWithExact(fields) {
    const x = messagesExact;
    if (x && MESSAGES_EXACT_FIELDS.some(key => x[key] && (fields[key] || '') !== x[key])) messagesExact = null;
    if (!messagesExact) return fields;
    return { ...fields, ...(x.ip ? { exact_ip: 'true' } : {}), ...(x.address ? { address: x.address } : {}), ...(x.domain ? { domain: x.domain } : {}) };
}

function messagesExactParts(x) {
    const parts = [];
    if (x.address) parts.push(['From or to', x.address]);
    if (x.domain) parts.push(['From or to', `@${x.domain}`]);
    if (x.ip) parts.push(['IP', x.ip]);
    return parts;
}

function clearMessagesExact() {
    if (messagesExact) {
        MESSAGES_EXACT_FIELDS.forEach(key => {
            const el = messagesExact[key] && document.getElementById(`messages-filter-${key}`);
            if (el) el.value = '';
        });
    }
    messagesExact = null;
    applyMessagesFilters();
}

let messagesNoId = false;
let messagesNoIdCount = 0;
const MESSAGES_NOID_KEYS = ['search', 'start_date', 'end_date'];

function messagesListUrl(params) {
    return `${messagesNoId ? '/api/messages/without-message-id' : '/api/messages'}?${params}`;
}

function showMessagesWithoutId(on) {
    messagesNoId = !!on;
    if (messagesNoId) {
        ['sender', 'recipient', 'user', 'ip', 'direction', 'status'].forEach(name => {
            const field = document.getElementById(`messages-filter-${name}`);
            if (field) field.value = '';
        });
        toggleMessagesFilters(false);
        const kept = currentFilters.messages || {};
        setMessagesFilters(Object.fromEntries(['search', 'date_range', 'start_date', 'end_date']
            .filter(key => kept[key]).map(key => [key, kept[key]])));
    }
    const page = document.getElementById('content-messages');
    if (page) page.classList.toggle('is-noid', messagesNoId);
    const modal = document.getElementById('message-modal');
    if (modal && !modal.classList.contains('hidden') && typeof closeMessageModal === 'function') closeMessageModal();
    currentPage.messages = 1;
    loadMessages();
}

function leaveMessagesWithoutId() {
    if (!messagesNoId) return;
    messagesNoId = false;
    const page = document.getElementById('content-messages');
    if (page) page.classList.remove('is-noid');
    renderMessagesNoId();
}

function renderMessagesNoId() {
    const link = document.getElementById('messages-noid');
    if (!link) return;
    const n = messagesNoIdCount;
    link.textContent = messagesNoId ? 'Back to main list' : `+ ${uiCountLabel(n, 'unlinked message', 'unlinked messages')}`;
    link.title = messagesNoId ? '' : 'Messages without a usable Message-ID could not be linked to their spam scan and are not in this list. Show them';
    link.classList.toggle('hidden', !messagesNoId && !n);
}

let messagesNoIdAsked = '';
async function refreshMessagesNoId() {
    if (messagesNoId) return renderMessagesNoId();
    const filters = messagesRangeFilters(currentFilters.messages || {});
    const params = new URLSearchParams({ limit: 1 });
    for (const key of MESSAGES_NOID_KEYS) {
        if (filters[key]) params.append(key, filters[key]);
    }
    const asked = params.toString();
    messagesNoIdAsked = asked;
    try {
        const response = await authenticatedFetch(`/api/messages/without-message-id?${asked}`, { timeout: PAGE_REFRESH_TIMEOUT });
        if (!response.ok) return;
        const data = await response.json();
        if (messagesNoId || asked !== messagesNoIdAsked) return;
        messagesNoIdCount = data.total || 0;
        renderMessagesNoId();
    } catch (error) {
        if (error.name !== 'AbortError') console.warn('Failed to count messages without a Message-ID:', error);
    }
}

function messagesQueryParams(cursor = null, limit = 50, upto = null) {
    const filters = messagesRangeFilters(currentFilters.messages || {});
    if (messagesNoId) {
        const params = new URLSearchParams({ limit });
        for (const key of MESSAGES_NOID_KEYS) {
            if (filters[key]) params.append(key, filters[key]);
        }
        if (messagesOrder === 'asc') params.append('order', 'asc');
        if (cursor) params.append('cursor', cursor);
        return params;
    }
    const params = new URLSearchParams({ page: 1, limit });
    for (const key of MESSAGES_FILTER_KEYS) {
        if (filters[key]) params.append(key, filters[key]);
    }
    if (messagesOrder === 'asc') params.append('order', 'asc');
    if (cursor) params.append('cursor', cursor);
    if (cursor && upto !== null && upto !== undefined) params.append('upto_id', upto);
    return params;
}

let messagesOrder = 'desc';
const MESSAGES_ORDER_ICONS = {
    desc: '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4.5h14M3 9h10M3 13.5h7m7.5-4.5v11m0 0l-3.5-3.5m3.5 3.5l3.5-3.5"></path></svg>',
    asc: '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4.5h14M3 9h10M3 13.5h7m7.5 6.5V9m0 0l-3.5 3.5M17.5 9l3.5 3.5"></path></svg>',
};
function renderMessagesSort() {
    const slot = document.getElementById('messages-sort');
    if (!slot) return;
    let button = slot.querySelector('button');
    if (!button) {
        slot.innerHTML = `<button type="button" class="ui-icon-btn ui-sort-btn-icon" onclick="setMessagesOrder(messagesOrder === 'asc' ? 'desc' : 'asc')"></button>`;
        button = slot.querySelector('button');
    }
    const asc = messagesOrder === 'asc';
    button.innerHTML = MESSAGES_ORDER_ICONS[asc ? 'asc' : 'desc'];
    button.setAttribute('aria-label', `Sort: ${asc ? 'Oldest first' : 'Newest first'}`);
    button.title = asc ? 'Oldest first. Click for newest first' : 'Newest first. Click for oldest first';
    button.classList.toggle('is-set', asc);
}
document.addEventListener('DOMContentLoaded', renderMessagesSort);
function setMessagesOrder(order) {
    messagesOrder = order === 'asc' ? 'asc' : 'desc';
    renderMessagesSort();
    loadMessages();
}

function messagesMoreText() {
    if (messagesPaging.cursor) return 'Loading more...';
    return messagesPaging.total ? `All ${messagesPaging.total} messages shown` : '';
}

function renderMessagesList(container, data) {
    container.innerHTML = `
        <div class="ui-msg-list">${data.data.map(renderMessageRow).join('')}</div>
        <p id="messages-more" class="ui-msg-more" aria-live="polite">${messagesMoreText()}</p>
    `;
    watchMessagesEnd(container);
}

function watchMessagesEnd(container) {
    if (messagesPaging.observer) messagesPaging.observer.disconnect();
    const sentinel = document.getElementById('messages-more');
    if (!sentinel || typeof IntersectionObserver === 'undefined') return;
    const root = container.scrollHeight > container.clientHeight + 1 || getComputedStyle(container).overflowY !== 'visible' ? container : null;
    messagesPaging.observer = new IntersectionObserver(entries => {
        if (entries.some(e => e.isIntersecting)) loadMoreMessages();
    }, { root, rootMargin: '0px 0px 600px 0px' });
    messagesPaging.observer.observe(sentinel);
}

async function loadMoreMessages(retry = false) {
    if (retry) messagesPaging.failed = false;
    if (messagesPaging.loading || messagesPaging.failed || !messagesPaging.cursor) return;
    const list = document.querySelector('#messages-logs .ui-msg-list');
    if (!list) return;
    messagesPaging.loading = true;
    const gen = messagesGen;
    try {
        const response = await messagesFetch(messagesListUrl(messagesQueryParams(messagesPaging.cursor, 50, messagesNew.watermark)));
        if (!response.ok) throw await responseError(response);
        const data = await response.json();
        if (gen !== messagesGen) return;
        const seen = new Set([...list.querySelectorAll('.ui-msg-item[data-key]')].map(row => row.dataset.key));
        const ids = new Set([...list.querySelectorAll('.ui-msg-item[data-mid]')].map(row => row.dataset.mid));
        const added = (data.data || []).filter(msg => !seen.has(msg.correlation_key || '') && !(msg.message_id && ids.has(encodeURIComponent(msg.message_id))));
        list.insertAdjacentHTML('beforeend', added.map(renderMessageRow).join(''));
        if (lastDataCache.messages) lastDataCache.messages = { ...lastDataCache.messages, data: (lastDataCache.messages.data || []).concat(added), total: data.total ?? lastDataCache.messages.total, next_cursor: data.next_cursor || null };
        messagesPaging.page += 1;
        currentPage.messages = messagesPaging.page;
        messagesPaging.cursor = data.next_cursor || null;
        messagesPaging.total = data.total ?? messagesPaging.total;
        setMessagesCount(messagesPaging.total);
        const more = document.getElementById('messages-more');
        if (more) more.textContent = messagesMoreText();
        if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
    } catch (error) {
        if (gen !== messagesGen) return;
        messagesPaging.failed = true;
        const more = document.getElementById('messages-more');
        if (more) more.innerHTML = `Could not load more messages. <button type="button" class="ui-link-row ui-link" onclick="loadMoreMessages(true)">Try again</button>`;
    } finally {
        if (gen === messagesGen) messagesPaging.loading = false;
    }
    if (gen !== messagesGen || messagesPaging.failed) return;
    const sentinel = document.getElementById('messages-more');
    const container = document.getElementById('messages-logs');
    if (sentinel && container && messagesPaging.cursor && sentinel.getClientRects().length) {
        const r = sentinel.getBoundingClientRect();
        const box = container.getBoundingClientRect();
        if (r.top < Math.max(box.bottom, window.innerHeight) + 600) loadMoreMessages();
    }
}

function renderNetfilterData(data) {
    const container = document.getElementById('netfilter-logs');
    if (!container) return;

    if (!data.data || data.data.length === 0) {
        container.innerHTML = Object.values(currentFilters.netfilter || {}).some(Boolean) ? `
            <div class="ui-empty">
                <p><b>No events match these filters</b></p>
                <p><button onclick="clearNetfilterFilters()" class="ui-btn ui-btn-sm">Clear filters</button></p>
            </div>` : '<p class="ui-empty">No events yet. Fail2ban bans, unbans and warnings show up here.</p>';
        const emptyCount = document.getElementById('security-count');
        if (emptyCount) emptyCount.textContent = uiCountLabel(0, 'event', 'events');
        return;
    }

    const countEl = document.getElementById('security-count');
    if (countEl) {
        countEl.textContent = uiCountLabel(data.total || 0, 'event', 'events');
    }

    const activeBannedIPs = new Set();
    if (fail2banActiveBans && fail2banActiveBans.length > 0) {
        fail2banActiveBans.forEach(function(ban) {
            if (ban.ip) activeBannedIPs.add(ban.ip);
            if (ban.network) {
                const baseIp = ban.network.split('/')[0];
                activeBannedIPs.add(baseIp);
                activeBannedIPs.add(ban.network);
            }
        });
    }

    const mayBan = mailcowRwConfigured && userCan('security', 'write');
    const lockedNote = mailcowRwConfigured || !userCan('security', 'write') ? '' : `<div class="ui-list-note">${uiLocked('Ban and Unban are locked', `Banning or unbanning an IP from this list ${UI_RW_KEY_TEXT}`)}</div>`;

    const tabCount = document.getElementById('security-tab-n-events');
    if (tabCount) {
        tabCount.textContent = data.total ? data.total.toLocaleString() : '';
        tabCount.classList.toggle('hidden', !data.total);
    }

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-ev-list">
            <div class="ui-ev-row ui-ev-head"><span>When</span><span>Address</span><span>Account</span><span>Action</span><span>Where</span><span></span></div>
            ${data.data.map((log, index) => {
                const isBan = log.action === 'ban' || log.action === 'banned';
                const isWarningOrUnban = log.action === 'warning' || log.action === 'unban';
                const ipInBlacklist = log.ip && fail2banBlacklist.some(entry => entry === log.ip || entry === fail2banEntry(log.ip));
                const showUnban = mayBan && log.ip && (isBan || ipInBlacklist);
                const showBan = mayBan && log.ip && isWarningOrUnban && !ipInBlacklist;
                const flagUrl = log.country_code ? getFlagUrl(log.country_code, '16x12') : '';
                const place = [log.country_name, log.city].filter(Boolean).join(', ');
                const org = log.asn_org ? ` (${log.asn_org})` : '';
                const account = log.username && log.username !== '-' ? uiEntity('address', log.username)
                    : (log.attempts_left !== null && log.attempts_left !== undefined ? `<span class="ui-muted">${escapeHtml(String(log.attempts_left))} attempts left</span>` : '<span class="ui-muted">-</span>');
                return `
                <div class="ui-ev-row ui-msg-${uiActionTone(log.action)}">
                    ${uiTime(log.time, formatListTime(log.time), { title: formatTime(log.time), cls: 'ui-muted' })}
                    <b class="ui-mono">${log.ip ? uiEntity('ip', log.ip, { mono: true }) : '-'}</b>
                    <span class="ui-ev-account">${account}</span>
                    <span>${uiActionTag(log.action)}</span>
                    <span class="ui-ev-where" title="${escapeHtml(place + org)}">${flagUrl ? `<img src="${flagUrl}" alt="" width="16" height="12" onerror="this.style.display='none'">` : ''}${escapeHtml(place || '-')}</span>
                    <span class="ui-st-acts">
                        ${showUnban ? `<button data-acts="security" onclick="unbanIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm" title="Unban ${escapeHtml(log.ip)}">Unban</button>` : ''}
                        ${showBan ? `<button data-acts="security" onclick="banIP('${escapeJsArg(log.ip)}', this)" class="ui-btn ui-btn-sm ui-btn-danger" title="Put ${escapeHtml(fail2banEntry(log.ip))} on the denylist; it stays until removed">Ban permanently</button>` : ''}
                        <button type="button" class="ui-icon-btn ui-icon-btn-sm ui-ev-toggle" aria-expanded="false" aria-controls="ev-detail-${index}" title="Show the log line" onclick="toggleEventDetail(this)"><svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg></button>
                    </span>
                    <div class="ui-ev-detail" id="ev-detail-${index}" hidden>
                        <p class="ui-mono">${escapeHtml(log.message || '-')}</p>
                        ${place || org ? `<p class="ui-muted">${escapeHtml([log.country_name, log.city].filter(Boolean).join(' '))}${escapeHtml(org)}</p>` : ''}
                    </div>
                </div>`;
            }).join('')}
        </div>
        ${renderPagination('netfilter', data.page, data.pages)}
    `;
}

function toggleEventDetail(btn) {
    const detail = document.getElementById(btn.getAttribute('aria-controls'));
    if (!detail) return;
    detail.hidden = !detail.hidden;
    btn.setAttribute('aria-expanded', !detail.hidden);
}

function fail2banEntry(ip) {
    return ip.includes('/') ? ip : `${ip}/${ip.includes(':') ? 128 : 32}`;
}

function fail2banBare(entry) {
    const value = String(entry || '');
    return value.replace(value.includes(':') ? /\/128$/ : /\/32$/, '');
}

async function unbanIP(ip, btnEl) {
    if (!uiMayAct('security')) return;
    const label = btnEl ? btnEl.textContent : '';
    const ipWithMask = fail2banEntry(ip);
    if (!await showConfirmModal({ title: 'Unban IP', message: 'Unban ' + ip + '? If it is part of a network ban, the whole network is unbanned.', confirmText: 'Unban', focusCancel: true })) return;
    try {
        if (btnEl) {
            btnEl.disabled = true;
            btnEl.textContent = 'Unbanning...';
        }
        const res = await authenticatedFetch('/api/fail2ban/unban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });
        const result = await uiReadJson(res);
        if (res.ok && result && result.status === 'success') {
            const lifted = result.networks || [ipWithMask];
            showToast(lifted.map(fail2banBare).join(', ') + ' queued for unbanning', 'success');
            if (fail2banActiveBans) fail2banActiveBans = fail2banActiveBans.filter(b => !lifted.includes(b.network) && fail2banBare(b.ip || b.network) !== fail2banBare(ip));
            renderSecurityOverview();
            refreshSecurityAddresses();
            setTimeout(() => { fail2banSettingsLoaded = false; loadFail2BanSettings(); }, 5000);
            smartRefreshNetfilter();
        } else {
            showToast('Could not unban the IP: ' + actionErrorText(res, result), 'error');
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.textContent = label;
            }
        }
    } catch (err) {
        showToast('Could not unban the IP: ' + uiErrorText(err), 'error');
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.textContent = label;
        }
    }
}

function fail2banLiftable() {
    if (!fail2banActiveBans) return [];
    const permanent = new Set(fail2banPermBans.map(b => b && (b.network || b.ip)));
    const queued = v => v === true || v === 1 || v === '1';
    const plain = n => typeof n === 'string' && /^[0-9A-Fa-f.:]+\/\d{1,3}$/.test(n);
    return [...new Set(fail2banActiveBans.filter(b => b && plain(b.network) && !permanent.has(b.network) && !queued(b.queued_for_unban)).map(b => b.network))];
}

async function unbanAllFail2ban(btnEl) {
    if (!uiMayAct('security')) return;
    const n = fail2banLiftable().length;
    if (!n) return;
    const bans = `${n.toLocaleString()} ban${n === 1 ? '' : 's'}`;
    if (!await showConfirmModal({
        title: 'Unban all?',
        message: `Fail2ban lifts its ${bans}, and those addresses can try to sign in again.\nBans by the protection rules and the denylist stay.`,
        confirmText: `Unban ${n.toLocaleString()}`, isDangerous: true, focusCancel: true,
    })) return;
    const label = btnEl ? btnEl.textContent : '';
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = 'Unbanning...';
    }
    let result = {};
    try {
        const res = await authenticatedFetch('/api/fail2ban/unban-all', { method: 'POST' });
        result = (await uiReadJson(res)) || {};
        if (!res.ok || result.status !== 'success') result = { ...result, status: 'error', msg: actionErrorText(res, result) };
    } catch (err) {
        result = { status: 'error', msg: uiErrorText(err) };
    }
    const lifted = result.networks || [];
    if (result.status === 'success') showToast(result.msg, 'success');
    else showToast('Unban all: ' + result.msg, 'error');
    if (lifted.length && fail2banActiveBans) fail2banActiveBans = fail2banActiveBans.filter(b => !lifted.includes(b.network));
    if (btnEl && document.body.contains(btnEl)) {
        btnEl.disabled = false;
        btnEl.textContent = label;
    }
    renderSecurityOverview();
    refreshSecurityAddresses();
    setTimeout(() => { fail2banSettingsLoaded = false; loadFail2BanSettings(); }, 5000);
    smartRefreshNetfilter();
}

async function banIP(ip, btnEl) {
    if (!uiMayAct('security')) return;
    const label = btnEl ? btnEl.textContent : '';
    const ipWithMask = fail2banEntry(ip);
    if (!await showConfirmModal({ title: 'Ban IP', message: `Add ${ipWithMask} to the Fail2ban denylist? It stays banned until removed.`, confirmText: 'Ban', isDangerous: true, focusCancel: true })) return;

    if (btnEl) {
        btnEl.disabled = true;
        btnEl.innerHTML = '<span class="loading-spinner-sm"></span>Banning...';
    }

    try {
        const response = await authenticatedFetch('/api/fail2ban/ban', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });

        const result = await uiReadJson(response);

        if (response.ok && result && result.status === 'success') {
            showToast(result.already ? result.msg : `IP ${ip} added to the denylist`, 'success');
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            smartRefreshNetfilter();
            return true;
        } else {
            showToast('Could not ban the IP: ' + actionErrorText(response, result), 'error');
            if (btnEl) {
                btnEl.disabled = false;
                btnEl.textContent = label;
            }
        }
    } catch (err) {
        showToast('Could not ban the IP: ' + uiErrorText(err), 'error');
        if (btnEl) {
            btnEl.disabled = false;
            btnEl.textContent = label;
        }
    }
}

async function allowIP(ip, btnEl) {
    if (!uiMayAct('security')) return;
    const label = btnEl ? btnEl.textContent : '';
    const ipWithMask = fail2banEntry(ip);
    if (!await showConfirmModal({ title: 'Allow IP', message: `Add ${ipWithMask} to the Fail2ban allowlist? It is exempt from bans unless also on the denylist.`, confirmText: 'Allow', focusCancel: true })) return;
    if (btnEl) {
        btnEl.disabled = true;
        btnEl.textContent = 'Allowing...';
    }
    try {
        const res = await authenticatedFetch('/api/fail2ban/allow', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ipWithMask })
        });
        const result = await uiReadJson(res);
        if (res.ok && result && result.status === 'success') {
            showToast(result.already ? result.msg : `IP ${ip} added to the allowlist`, 'success');
            fail2banSettingsLoaded = false;
            fail2banActiveBans = null;
            loadFail2BanSettings();
            return true;
        }
        showToast('Could not add the IP to the allowlist: ' + actionErrorText(res, result), 'error');
    } catch (err) {
        showToast('Could not add the IP to the allowlist: ' + uiErrorText(err), 'error');
    }
    if (btnEl) {
        btnEl.disabled = false;
        btnEl.textContent = label;
    }
}

async function loadNetfilterCountries() {
    try {
        const select = document.getElementById('netfilter-filter-country');
        if (!select) return;
        
        const response = await authenticatedFetch('/api/logs/netfilter/countries');
        if (!response.ok) return;
        
        const countries = await response.json();
        
        const currentValue = select.value;
        
        select.innerHTML = '<option value="" data-short="All">All Countries</option>';
        
        for (const c of countries) {
            const opt = document.createElement('option');
            opt.value = c.code;
            opt.textContent = `${c.name || c.code}`;
            select.appendChild(opt);
        }
        
        if (currentValue) select.value = currentValue;
        uiFilterBarSync();
    } catch (err) {
        console.error('Failed to load netfilter countries:', err);
    }
}

async function smartRefreshNetfilter() {
    const filters = currentFilters.netfilter || {};
    const params = new URLSearchParams({
        page: currentPage.netfilter || 1,
        limit: 50,
        ...filters
    });

    const response = await authenticatedFetch(`/api/logs/netfilter?${params}`);
    if (!response.ok) return;

    const data = await response.json();

    if (hasDataChanged(data, 'netfilter')) {
        console.log('[REFRESH] Netfilter data changed, updating UI');
        lastDataCache.netfilter = data;
        renderNetfilterData(data);
    }
}


async function smartRefreshQueue() {
    if (queueActing) return;
    const id = ++queueAsked;
    const kept = queueListKept();
    const response = await authenticatedFetch('/api/queue');
    if (!response.ok) return;

    const data = await response.json();
    await rwStatusReady;
    const listKept = await kept;
    if (queueActing || !queueTakeTurn(id)) return;
    const suppressChanged = listKept !== queueSuppressOn;
    queueSuppressOn = listKept;

    if (hasDataChanged(data, 'queue') || suppressChanged || queueLoading) {
        queueLoading = false;
        console.log('[REFRESH] Queue data changed, updating UI');
        lastDataCache.queue = data;
        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    }
}

async function smartRefreshQuarantine() {
    if (quarantineActing) return;
    const id = ++quarantineAsked;
    const response = await authenticatedFetch('/api/quarantine', { timeout: PAGE_REFRESH_TIMEOUT });
    if (!response.ok) return;

    const data = await response.json();
    await rwStatusReady;
    if (quarantineActing || !quarantineTakeTurn(id)) return;

    if (hasDataChanged(data, 'quarantine')) {
        console.log('[REFRESH] Quarantine data changed, updating UI');
        lastDataCache.quarantine = data;
        renderQuarantineData(data);
    }
}

let dashboardKpisAt = 0;

async function smartRefreshDashboard() {
    try {
        refreshMailFlowChart();
        loadDashboardStatusSummary();
        loadDashboardSecurity();
        if (Date.now() - dashboardTrendsAt >= 300000) loadDashboardTrends();
        if (Date.now() - dashboardKpisAt >= 300000) {
            dashboardKpisAt = Date.now();
            loadDashboardBlacklistSummary();
            loadDashboardHealth();
        }
    } catch (error) {
        console.error('Dashboard refresh error:', error);
    }
}

async function smartRefreshSettings() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) return;

        const data = await response.json();
        if (data.settings_edit_via_ui_enabled && !data.editable_config) {
            try {
                const editableRes = await authenticatedFetch('/api/settings');
                if (editableRes.ok) {
                    const editableData = await editableRes.json();
                    data.editable_config = editableData.configuration || {};
                }
            } catch (e) {}
        }

        if (hasDataChanged(data, 'settings')) {
            const content = document.getElementById('settings-content');
            if (content && !content.classList.contains('hidden') && content.querySelector('#settings-edit-form')) {
                return;
            }
            console.log('[REFRESH] Settings data changed, updating UI');
            lastDataCache.settings = data;

            if (content && !content.classList.contains('hidden')) {
                if (versionInfoCache.app_version) {
                    data.app_version = versionInfoCache.app_version;
                }
                if (versionInfoCache.version_info) {
                    data.version_info = versionInfoCache.version_info;
                }

                renderSettings(content, data);
            }
        }
    } catch (error) {
        console.error('Settings refresh error:', error);
    }
}

function switchTab(tab, params = {}) {
    console.log('Switching to tab:', tab, 'params:', params);

    if (tab === 'dashboard' && !userCanView('dashboard') && landingPage()) {
        tab = landingPage();
        params = {};
        if (typeof buildPath === 'function') routerReplace({ route: tab, params }, buildPath(tab, params));
    }

    if (!userCanView(tab)) {
        showNoAccessPage(tab);
        return;
    }

    if (pageIsOff(tab)) {
        const feature = TOGGLEABLE_FEATURES.find(f => f.id === tab);
        const featureLabel = feature ? feature.label : (TAB_LABELS[tab] || tab);
        console.warn(`Feature '${tab}' is disabled`);

        currentTab = tab;

        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));

        const tabContent = document.getElementById(`content-${tab}`);
        if (tabContent) {
            tabContent.classList.remove('hidden');
            tabContent.innerHTML = `
                <div class="ui-disabled-page">
                    ${uiLocked(`${featureLabel} is disabled`, 'This feature has been turned off by the administrator in Settings → Features.',
                        `<button onclick="navigateTo('dashboard')" class="ui-btn ui-btn-primary">Go to Dashboard</button>`)}
                </div>`;
        }

        const newPath = typeof buildPath === 'function' ? buildPath(tab) : `/${tab}`;
        if (window.location.pathname !== newPath) {
            routerReplace({ route: tab, params: {} }, newPath);
        }
        queueDocumentTitle();
        return;
    }

    const tabPage = typeof SUBPAGES !== 'undefined' ? SUBPAGES[tab] : null;
    const pageEl = document.getElementById(`content-${tab}`);
    if (tabPage && params.sub && currentTab === tab && pageEl && !pageEl.classList.contains('hidden')) {
        tabPage.show(params.sub);
        return;
    }

    currentTab = tab;
    pageRefreshLoaded(tab);

    document.querySelectorAll('[id^="tab-"], [id^="tabbar-"]').forEach(btn => btn.removeAttribute('aria-current'));
    for (const id of [`tab-${tab}`, `tabbar-${tab}`]) {
        const btn = document.getElementById(id);
        if (btn) btn.setAttribute('aria-current', 'page');
    }
    const moreBtn = document.getElementById('hamburger-btn');
    if (moreBtn) moreBtn.classList.toggle('ui-more-current', !document.getElementById(`tabbar-${tab}`));

    if (typeof updateMobileMenuActiveState === 'function') {
        updateMobileMenuActiveState(tab);
    }
    if (typeof updateCurrentTabLabel === 'function') {
        updateCurrentTabLabel(tab);
    }
    placeTopbar(tab);

    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.add('hidden');
    });

    const tabContent = document.getElementById(`content-${tab}`);
    if (tabContent) {
        tabContent.classList.remove('hidden');
    } else {
        console.error(`Tab content not found: content-${tab}`);
    }

    if (tabPage) {
        const sub = params.sub || tabPage.current();
        routerSyncSubpage(tab, sub, true);
        tabPage.select(sub);
    }

    console.log('Loading data for tab:', tab);
    if (tab !== 'logs' && typeof disconnectLogWebSocket === 'function') {
        disconnectLogWebSocket();
    }

    switch (tab) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'messages':
            leaveMessagesWithoutId();
            if (messagesOpening) messagesOpening();
            loadMessages();
            break;
        case 'netfilter':
            loadSecurityOverview();
            loadNetfilterLogs(1);
            loadFail2BanSettings();
            if (typeof loadProtection === 'function') loadProtection();
            loadNetfilterCountries();
            loadSmtpAbusePanel();
            loadSecurityAppSettings();
            break;
        case 'outbound':
            loadOutbound();
            break;
        case 'quarantine':
            loadQuarantine();
            initQuarantineRules();
            break;
        case 'rspamd':
            loadRspamdMaps();
            break;
        case 'status':
            loadStatus();
            break;
        case 'domains':
            loadDomains();
            break;
        case 'dmarc':
            handleDmarcRoute(Object.keys(params).length ? params : parseRoute().params);
            break;
        case 'mailbox-stats':
            initMailboxStatsPage();
            break;
        case 'devices':
            loadDevices();
            break;
        case 'logs':
            loadLogViewer();
            break;
        case 'settings':
            loadSettings();
            break;
        case 'about':
            loadAbout();
            break;
        default:
            console.warn('Unknown tab:', tab);
    }
    queueDocumentTitle();
}

function showNoAccessPage(tab) {
    currentTab = tab;
    if (typeof disconnectLogWebSocket === 'function') disconnectLogWebSocket();
    document.querySelectorAll('[id^="tab-"], [id^="tabbar-"]').forEach(btn => btn.removeAttribute('aria-current'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
    if (typeof updateMobileMenuActiveState === 'function') updateMobileMenuActiveState(tab);
    if (typeof updateCurrentTabLabel === 'function') updateCurrentTabLabel(tab);
    placeTopbar(null);
    const page = document.getElementById('content-no-access');
    if (page) {
        const landing = landingPage();
        const go = landing && landing !== tab
            ? `<button type="button" onclick="navigateTo('${landing}')" class="ui-btn ui-btn-primary">Go to ${escapeHtml(TAB_LABELS[landing] || landing)}</button>` : '';
        page.innerHTML = `
            <div class="ui-disabled-page">
                ${uiLocked('You do not have permission to view this page.', 'Ask an administrator if you need it.', go)}
            </div>`;
        page.classList.remove('hidden');
    }
    queueDocumentTitle();
}

async function loadDashboard() {
    try {
        console.log('Loading Dashboard...');
        loadDashboardStatusSummary();
        loadDashboardBlacklistSummary();
        loadDashboardHealth();
        dashboardKpisAt = Date.now();
        renderAttention();
        attentionRefresh();
        loadDashboardSecurity();
        loadDashboardTrends();
        loadMailFlowChart();
    } catch (error) {
        console.error('Failed to load dashboard:', error);
    }
}

const ATTENTION_ALERTS_EVERY = 30000;
const ATTENTION_CHECKS_EVERY = 5 * 60 * 1000;
const ATTENTION_CHECKS = ['connection', 'blocklist', 'containers', 'fail2ban', 'dmarc', 'appVersion', 'mailcowVersion'];
const attention = {
    ready: false,
    timeout: 20000,
    alerts: { seq: 0, busy: null, latest: null, at: 0, ok: null, list: [], total: 0, critical: 0 },
    checks: { seq: 0, busy: null, latest: null, at: 0, ok: {}, items: {} },
};

const dashboardAlerts = new Map();
let dashboardWritableAlertIds = [];

const ALERT_TYPE_AREAS = {
    volume_spike: 'security', auth_failure_burst: 'security', smtp_abuse_block: 'security',
    protection_breach: 'security', protection_ban_failed: 'security',
    dns_change: 'domains', dmarc_import_failed: 'dmarc',
};
const ALERT_ACTIVITY_TYPES = ['volume_spike', 'auth_failure_burst', 'smtp_abuse_block'];
const ALERT_OPEN_LABELS = {
    dns_change: 'Open domain', dmarc_import_failed: 'Open fetch history',
    protection_breach: 'Open Security', protection_ban_failed: 'Open Security',
};

function alertArea(alert) {
    return (alert && ALERT_TYPE_AREAS[alert.alert_type]) || 'admin';
}

function attentionLoad(state, force, read) {
    if (state.busy && !force) return state.busy;
    const seq = ++state.seq;
    const run = (async () => {
        const answer = await read();
        if (seq !== state.seq) return state.latest;
        return answer();
    })();
    state.busy = run;
    state.latest = run;
    run.finally(() => { if (state.busy === run) state.busy = null; });
    return run;
}

async function attentionRead(url) {
    try {
        const res = await authenticatedFetch(url, { timeout: attention.timeout });
        return res.ok ? await res.json() : READ_FAILED;
    } catch (e) {
        console.warn(`Needs attention could not read ${url}:`, e);
        return READ_FAILED;
    }
}

function loadDashboardSecurityAlerts({ force = true } = {}) {
    const s = attention.alerts;
    return attentionLoad(s, force, async () => {
        const read = userCan('alerts') ? await attentionRead('/api/security-alerts?acknowledged=false&limit=20') : { alerts: [] };
        const data = read === READ_FAILED ? null : read;
        return () => {
            s.at = Date.now();
            if (!data) { s.ok = false; renderAttention(); return false; }
            const alerts = data.alerts || [];
            s.ok = true;
            s.list = alerts;
            s.total = Number.isFinite(data.unacknowledged_count) ? data.unacknowledged_count : alerts.length;
            s.critical = Number.isFinite(data.unacknowledged_critical) ? data.unacknowledged_critical
                : alerts.filter(a => a.severity === 'critical').length;
            dashboardAlerts.clear();
            alerts.forEach(a => dashboardAlerts.set(Number(a.id), a));
            dashboardWritableAlertIds = Array.isArray(data.writable_ids) ? data.writable_ids.map(Number) : [];
            renderAttention();
            return true;
        };
    });
}

function renderDismissAll(button) {
    if (!button) return;
    const count = dashboardWritableAlertIds.length, n = count.toLocaleString();
    const words = count === 1 ? ['Dismiss 1', 'alert'] : [`Dismiss all ${n}`, 'alerts'];
    button.innerHTML = `${words[0]}<span class="ui-attn-wide">&nbsp;${words[1]}</span>`;
    button.setAttribute('aria-label', words.join(' '));
    button.classList.toggle('is-off', !attention.alerts.list.length || !count);
}

function attentionAlertLine(a) {
    if (!ALERT_ACTIVITY_TYPES.includes(a.alert_type)) return String(a.detail || '').split('\n')[0];
    const num = v => (v === null || v === undefined || v === '' ? NaN : Number(v));
    const raw = num(a.metric_value);
    const count = Number.isFinite(raw) && raw >= 0 ? Math.round(raw) : null;
    const detail = String(a.detail || '');
    const found = detail.match(a.alert_type === 'smtp_abuse_block' ? /\bin (\d+) minutes?\b/ : /\bin the last (\d+) minutes?\b/);
    const minutes = found && Number(found[1]) > 0 ? Number(found[1]) : null;
    const n = value => value.toLocaleString();
    const period = minutes ? ` in ${n(minutes)} ${minutes === 1 ? 'minute' : 'minutes'}` : '';
    const messages = c => `${n(c)} ${c === 1 ? 'message' : 'messages'}`;
    if (a.alert_type === 'volume_spike') {
        if (count === null) return 'Unusual sending was detected.';
        const usual = num(a.baseline_value);
        const ratio = minutes && Number.isFinite(usual) && usual > 0 ? Math.round((raw * 60 / minutes) / usual) : NaN;
        return `Sent ${messages(count)}${period}${Number.isFinite(ratio) && ratio > 1 ? `, about ${n(ratio)} times usual` : ''}.`;
    }
    if (a.alert_type === 'auth_failure_burst') {
        if (count === null) return 'Repeated sign-in failures were detected.';
        return `${n(count)} failed ${count === 1 ? 'sign-in' : 'sign-ins'}${period}.`;
    }
    if (a.alert_type === 'smtp_abuse_block') {
        if (count === null) return 'Sending was stopped by abuse protection.';
        return `Sending stopped after ${messages(count)}${period}.`;
    }
    return '';
}

function attentionAlertRows(where) {
    return attention.alerts.list.map(a => {
        const id = Number(a.id);
        const critical = a.severity === 'critical';
        const first = where === 'bell' ? 'attnBellOpen();' : '';
        const label = ALERT_OPEN_LABELS[a.alert_type];
        const place = where === 'bell' ? 'bell' : 'page';
        const activity = !label && ALERT_ACTIVITY_TYPES.includes(a.alert_type);
        const action = label ? `openStoredAlert(${id}, '${place}')` : activity ? `${first} openAlertActivity(${id})` : '';
        const button = label ? `<button type="button" onclick="openStoredAlert(${id}, '${place}')" class="ui-btn ui-btn-sm">${escapeHtml(label)}</button>`
            : activity ? `<button type="button" onclick="${first} openAlertActivity(${id})" class="ui-btn ui-btn-sm" title="What happened before and around this alert">Show activity</button>` : '';
        return `
            <div class="ui-alert${action ? ' ui-alert-go' : ''} ${critical ? 'ui-alert-fail' : 'ui-alert-warn'}" data-key="alert-${id}" data-swipe${action ? ` onclick="if (uiAlertRowClick(event)) { ${action} }"` : ''}>
                <div class="ui-alert-text">
                    <div class="ui-alert-title">
                        <span class="ui-tag ${critical ? 'ui-tag-fail' : 'ui-tag-warn'}">${escapeHtml((a.severity || 'warning').toUpperCase())}</span>
                        <b>${escapeHtml(a.title)}</b>
                    </div>
                    <p>${escapeHtml(attentionAlertLine(a))}</p>
                    <p class="ui-muted">${escapeHtml(formatTime(a.created_at))}</p>
                </div>
                ${button && where !== 'bell' ? `<div class="ui-alert-acts">${button}</div>` : ''}
                <button type="button" onclick="acknowledgeSecurityAlertOnce(${id}, this)" class="ui-icon-btn ui-icon-btn-sm ui-alert-x" title="Dismiss alert" aria-label="Dismiss alert" data-acts="alerts ${alertArea(a)}">${UI_CLOSE_ICON}</button>
            </div>`;
    }).join('');
}

const ALERT_OPEN = {
    dns_change: { go: () => navigateTo('domains'), then: a => showAlertDomain(a.subject) },
    dmarc_import_failed: { go: () => navigateTo('dmarc'), then: () => {
        if (!(window.disabledFeatures || []).includes('dmarc')) showDmarcSyncHistory();
    } },
    protection_breach: { go: openAlertSecurityReview },
    protection_ban_failed: { go: openAlertSecurityReview },
};

async function openStoredAlert(alertId, where) {
    const alert = dashboardAlerts.get(Number(alertId));
    const place = alert && ALERT_OPEN[alert.alert_type];
    if (!place) return;
    const moved = await place.go(alert);
    if (!moved) return;
    if (where === 'bell' && attnWindow) attnWindowClose({ toPage: true });
    if (place.then) await place.then(alert);
}

async function showAlertDomain(name) {
    if (!(await domainsLoading) || !name) return;
    if (document.getElementById('domain-search-input')) clearDomainFilters();
    const id = domainRowId(name);
    const details = document.getElementById(`${id}-details`);
    if (!details) {
        showToast(`${name} is not in the domain list any more.`, 'info');
        return;
    }
    if (details.classList.contains('hidden')) toggleDomainDetails(id);
    const row = [...document.querySelectorAll('[data-domain-row]')].find(el => el.dataset.domainRow === name);
    (row || details).scrollIntoView({ block: 'start' });
}

async function openAlertSecurityReview() {
    if (!(await navigateTo('netfilter', { sub: 'overview' }))) return false;
    securityCountry = null;
    securityNetwork = null;
    setSecurityFilter('review');
    return true;
}

function uiAlertRowClick(event) {
    return !event.target.closest('button, a') && !uiRowHeld(event);
}

function attentionStatus() {
    const a = attention.alerts, c = attention.checks;
    const items = ATTENTION_CHECKS.flatMap(k => c.items[k] || []);
    const total = items.length + a.total;
    const tone = items.some(i => i.tone === 'fail') || a.critical > 0 ? 'fail'
        : items.some(i => i.tone === 'warn') || a.total > 0 ? 'warn' : 'info';
    const failed = a.ok === false || ATTENTION_CHECKS.some(k => c.ok[k] === false);
    const loading = a.ok === null || ATTENTION_CHECKS.some(k => c.ok[k] === undefined);
    return { total, tone, failed, loading };
}

function renderAttentionNote(el, status) {
    if (!el) return;
    const html = status.failed
        ? 'Some checks could not run. <button type="button" class="ui-link-row ui-link" onclick="attentionRetry()">Try again</button>'
        : !status.loading && status.total === 0 ? 'Nothing needs attention right now.' : '';
    if (el.dataset.shown !== html) {
        el.innerHTML = html;
        el.dataset.shown = html;
    }
    el.classList.toggle('hidden', !html);
}

function attentionRetry() {
    if (attention.alerts.ok === false) loadDashboardSecurityAlerts();
    if (ATTENTION_CHECKS.some(k => attention.checks.ok[k] === false)) loadDashboardAttention();
}

function updateAttentionState() {
    const status = attentionStatus();
    const count = document.getElementById('dashboard-attention-count');
    if (count) count.textContent = status.total ? status.total.toLocaleString() : '';
    const winCount = document.getElementById('attn-win-count');
    if (winCount) winCount.textContent = status.total ? status.total.toLocaleString() : '';
    renderAttentionNote(document.getElementById('dashboard-attention-clear'), status);
    renderAttentionNote(document.getElementById('attn-win-state'), status);
    renderDismissAll(document.getElementById('dashboard-dismiss-all'));
    renderDismissAll(document.getElementById('attn-win-dismiss-all'));
    document.querySelectorAll('.ui-attn-scroll').forEach(scroll => {
        const overflows = scroll.scrollHeight > scroll.clientHeight + 1;
        scroll.classList.toggle('has-more', overflows && scroll.scrollTop + scroll.clientHeight < scroll.scrollHeight - 2);
        scroll.tabIndex = overflows || scroll.id === 'attn-win-scroll' ? 0 : -1;
        if (scroll.id !== 'dashboard-attention-scroll') return;
        const more = document.getElementById('dashboard-attention-more');
        if (!more) return;
        more.classList.toggle('is-off', !overflows);
        more.textContent = overflows ? `${uiCountLabel(status.total, 'item', 'items')}. Scroll the list for the rest` : ' ';
    });
    updateAttentionBell(status);
}
if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('scroll', event => {
        if (event.target instanceof Element && event.target.classList.contains('ui-attn-scroll')) updateAttentionState();
    }, true);
    window.addEventListener('resize', () => updateAttentionState());
}

function updateAttentionBell(status = attentionStatus()) {
    const label = status.total ? `Needs attention, ${uiCountLabel(status.total, 'item', 'items')}`
        : status.failed ? 'Needs attention, some checks could not run' : 'Needs attention';
    document.querySelectorAll('.ui-bell').forEach(bell => {
        bell.setAttribute('aria-label', label);
        const badge = bell.querySelector('.ui-bell-n');
        if (!badge) return;
        badge.textContent = status.total ? (status.total > 99 ? '99+' : String(status.total)) : '';
        badge.className = `ui-bell-n is-${status.total ? status.tone : status.failed ? 'unknown' : 'none'}`;
    });
}

function uiReplaceKeepingFocus(container, html) {
    if (container.dataset.shown === html) return false;
    const active = document.activeElement;
    let keep = null;
    if (active && container.contains(active)) {
        const item = active.closest('[data-key]');
        const items = [...container.querySelectorAll('[data-key]')];
        keep = { key: item && item.dataset.key, action: active.textContent.trim(), at: Math.max(0, items.indexOf(item)) };
    }
    const scroller = container.closest('.ui-attn-scroll, [data-keep-scroll]');
    const top = scroller ? scroller.scrollTop : 0;
    container.innerHTML = html;
    container.dataset.shown = html;
    if (scroller) scroller.scrollTop = top;
    if (keep) {
        const items = [...container.querySelectorAll('[data-key]')];
        const same = keep.key ? items.find(i => i.dataset.key === keep.key) : null;
        const item = same || items[Math.min(keep.at, items.length - 1)];
        const buttons = item ? [...item.querySelectorAll('button')] : [];
        const target = (same && buttons.find(b => b.textContent.trim() === keep.action)) || buttons[0] || scroller || null;
        if (target) target.focus({ preventScroll: true });
    }
    return true;
}

function attentionDmarcLine(insight, domains) {
    const types = (insight.recommendations || []).map(r => r.type);
    const sources = (insight.new_sources || []).length;
    const rate = insight.pass_rate === null || insight.pass_rate === undefined || insight.pass_rate === '' ? NaN : Number(insight.pass_rate);
    const fallback = 'Review mail identity checks and protection settings.';
    let line;
    if (types.includes('low_pass_rate')) {
        if (!(Number.isFinite(rate) && rate >= 0 && rate <= 100)) return fallback;
        line = `Only ${Math.round(rate)}% passed mail identity checks.`;
    } else if (sources) {
        line = sources === 1 ? 'Mail from a new source failed identity checks.' : 'Mail from new sources failed identity checks.';
    } else if (types.includes('tighten_policy')) {
        line = 'Reports suggest stronger protection is safe.';
    } else {
        return fallback;
    }
    if (domains <= 1) return line;
    const named = `${insight.domain}: ${line}`;
    return named.length <= 60 ? named : fallback;
}

function attentionCheckItems(key, data) {
    const found = serverCheckFound(key, data);
    if (!found || !found.length) return [];
    if (key === 'connection') {
        const item = { tone: 'fail', title: 'mailcow is not reachable', detail: 'Logs and server data may be out of date.' };
        return [userIsAdmin() ? { ...item, action: 'Open settings', onclick: "navigateTo('settings')", go: ['settings'] }
            : { ...item, action: 'Open status', onclick: "navigateTo('status')", go: ['status'] }];
    }
    if (key === 'blocklist') {
        const listedHosts = (data.hosts || []).filter(h => h.status === 'listed');
        const first = listedHosts[0];
        const title = listedHosts.length > 1
            ? `${listedHosts.length} of your addresses are on a blocklist`
            : `${first ? first.hostname : (data.server_ip || 'Your server')} is on a blocklist`;
        const whole = v => (v === null || v === undefined || v === '' ? NaN : Number(v));
        const listed = whole(first ? first.listed_count : data.listed_count);
        const checked = whole(first && first.total_blacklists ? first.total_blacklists : data.total_blacklists);
        const counted = listedHosts.length <= 1 && Number.isInteger(listed) && listed >= 0 && Number.isInteger(checked) && checked > 0 && checked >= listed;
        const detail = counted ? `On ${listed} of ${checked} ${checked === 1 ? 'list' : 'lists'}; some mail may bounce.` : 'Mail to some providers may bounce.';
        return [{ tone: 'fail', title, detail, action: 'Check listing', onclick: "navigateTo('status')", go: ['status'] }];
    }
    if (key === 'containers') {
        const containers = found[0];
        return [{ tone: 'fail', title: containers.stopped === 1 ? 'A mailcow container is stopped' : `${containers.stopped} mailcow containers are stopped`,
            detail: `${containers.running || 0} of ${containers.total || 0} containers are running.`, action: 'Open status', onclick: "navigateTo('status')", go: ['status'] }];
    }
    if (key === 'fail2ban') {
        const legacy = data.legacy_entries || [];
        if (!legacy.length) return [];
        const first = legacy[0];
        return [{ tone: 'warn',
            title: legacy.length === 1 ? `A Fail2ban entry ${first.list === 'whitelist' ? 'exempts' : 'blocks'} the whole ${first.network} network` : `${legacy.length} Fail2ban entries cover whole /32 networks`,
            detail: legacy.length === 1 ? 'Repair this entry in Security > Lists.' : 'Repair these entries in Security > Lists.',
            action: 'Open lists', onclick: "navigateTo('netfilter', { sub: 'lists' })", go: ['netfilter', { sub: 'lists' }] }];
    }
    if (key === 'dmarc') {
        const dmarc = found;
        return [{ tone: 'warn', title: dmarc.length === 1 ? `DMARC needs attention for ${dmarc[0].domain}` : `DMARC needs attention for ${dmarc.length} domains`,
            detail: attentionDmarcLine(dmarc[0], dmarc.length), action: 'Open DMARC', onclick: "navigateTo('dmarc')", go: ['dmarc'] }];
    }
    if (key === 'appVersion') {
        if (!data.update_available) return [];
        appUpdateInfo = data;
        return [{ tone: 'info', title: `Version ${data.latest_version} is available`,
            detail: `You are running ${data.current_version}. See what changed before updating.`, action: 'Read changes', onclick: 'showAppUpdateModal()', popup: true }];
    }
    if (key === 'mailcowVersion') {
        if (!data.update_available) return [];
        window.mailcowUpdateVersion = data.latest_version;
        window.mailcowUpdateName = data.name || '';
        window.mailcowUpdateChangelog = data.changelog || 'No changelog available';
        return [{ tone: 'info', title: `mailcow ${data.latest_version} is available`,
            detail: `You are running ${data.current_version}.`, action: 'Read changes', onclick: 'showMailcowUpdateModal()', popup: true }];
    }
    return [];
}

function loadDashboardAttention({ force = true } = {}) {
    const s = attention.checks;
    return attentionLoad(s, force, async () => {
        const off = (feature, area) => (window.disabledFeatures || []).includes(feature) || !userCan(area);
        const get = attentionRead;
        const [blocklist, containers, dmarc, appVersion, mailcowVersion, connection, fail2ban] = await Promise.all([
            off('blacklist', 'status') ? null : get('/api/blacklist/summary'),
            off('', 'status') ? null : get('/api/status/summary'),
            off('dmarc', 'dmarc') ? null : get('/api/dmarc/insights'),
            off('', 'status') ? null : get('/api/status/app-version'),
            off('', 'status') ? null : get('/api/status/version'),
            off('', 'status') ? null : get('/api/status/mailcow-connection'),
            off('netfilter', 'security') ? null : get('/api/fail2ban'),
        ]);
        const read = { connection, blocklist, containers, fail2ban, dmarc, appVersion, mailcowVersion };
        return () => {
            for (const key of ATTENTION_CHECKS) {
                if (!serverCheckFound(key, read[key])) { s.ok[key] = false; continue; }
                s.ok[key] = true;
                s.items[key] = attentionCheckItems(key, read[key]);
            }
            const failed = ATTENTION_CHECKS.some(k => s.ok[k] === false);
            s.at = failed ? Date.now() - ATTENTION_CHECKS_EVERY + 60000 : Date.now();
            renderAttention();
        };
    });
}

function attentionCheckRows(where) {
    return ATTENTION_CHECKS.flatMap(k => attention.checks.items[k] || []).map(item => {
        const act = where !== 'bell' ? item.onclick
            : item.go ? `attnBellGo(${escapeHtml(JSON.stringify(item.go))})` : `attnBellOpen(); ${item.onclick}`;
        return `
        <div class="ui-alert ui-alert-${item.tone}${item.popup ? ' ui-alert-go' : ''}" data-key="check-${escapeHtml(item.title)}"${item.popup ? ` onclick="if (uiAlertRowClick(event)) { ${act} }"` : ''}>
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            ${where === 'bell' ? '' : `<button type="button" class="ui-btn ui-btn-sm" onclick="${act}">${escapeHtml(item.action)}</button>`}
        </div>`;
    }).join('');
}

function renderAttention() {
    for (const [where, checksId, alertsId] of [['dashboard', 'dashboard-attention', 'dashboard-security-alerts'], ['bell', 'attn-win-checks', 'attn-win-alerts']]) {
        const checks = document.getElementById(checksId);
        if (checks) uiReplaceKeepingFocus(checks, attentionCheckRows(where));
        const alerts = document.getElementById(alertsId);
        if (alerts) {
            uiReplaceKeepingFocus(alerts, attentionAlertRows(where));
            alerts.classList.toggle('hidden', !attention.alerts.list.length);
        }
    }
    updateAttentionState();
}

function attentionRefresh({ force = false } = {}) {
    if (!attention.ready) return;
    if (!force && document.hidden) return;
    const now = Date.now();
    if (force || now - attention.alerts.at >= ATTENTION_ALERTS_EVERY - 2000) loadDashboardSecurityAlerts({ force });
    if (force || now - attention.checks.at >= ATTENTION_CHECKS_EVERY - 2000) loadDashboardAttention({ force });
}

function startAttention() {
    if (attention.ready) return;
    attention.ready = true;
    attentionRefresh();
    setInterval(attentionRefresh, ATTENTION_ALERTS_EVERY);
    document.addEventListener('visibilitychange', () => { if (!document.hidden) attentionRefresh(); });
    window.matchMedia('(max-width: 760px)').addEventListener('change', event => {
        if (attnWindow && attnWindow.phone !== event.matches) attnWindowClose();
    });
}

let attnWindow = null;
function attnWindowOpen(bell) {
    if (attnWindow && attnWindow.el.isConnected) { attnWindowClose(); return; }
    attnWindow = null;
    const phone = window.matchMedia('(max-width: 760px)').matches;
    const head = `<h2 id="attn-win-title" class="ui-attn-win-title">Needs attention <span id="attn-win-count" class="ui-count"></span></h2>
        <button type="button" id="attn-win-dismiss-all" class="ui-btn ui-btn-sm is-off" onclick="acknowledgeAllSecurityAlertsOnce(this)" data-acts="alerts"></button>`;
    const list = `<div id="attn-win-checks"></div><div id="attn-win-alerts" class="hidden"></div><p id="attn-win-state" class="ui-dash-clear hidden"></p>`;
    const foot = `<div class="ui-attn-win-foot"><button type="button" class="ui-link-row ui-attn-win-go" onclick="attnBellGo(['dashboard'])">Open the Dashboard</button></div>`;
    uiLayerOpener(bell);
    let el;
    if (phone) {
        el = uiSheetShow('attn-sheet', { label: 'Needs attention', head, body: list + foot, onClose: () => attnWindowClose() });
        const body = el.querySelector('.ui-sheet-body');
        body.dataset.keepScroll = '';
        body.tabIndex = -1;
    } else {
        el = document.createElement('div');
        el.id = 'attn-window';
        el.className = 'ui-dialog-backdrop ui-attn-backdrop';
        el.innerHTML = `<section class="ui-attn-win" role="dialog" aria-labelledby="attn-win-title">
            <div class="ui-attn-win-head">${head}<button type="button" class="ui-icon-btn ui-attn-win-x" onclick="attnWindowClose()" aria-label="Close" title="Close">${UI_CLOSE_ICON}</button></div>
            <div id="attn-win-scroll" class="ui-attn-scroll ui-attn-win-list" data-keep-scroll tabindex="0">${list}</div>${foot}</section>`;
        el.addEventListener('click', event => { if (uiBackdropClick(event)) attnWindowClose(); });
        document.body.appendChild(el);
        const at = bell.getBoundingClientRect();
        const panel = el.firstElementChild;
        panel.style.top = `${Math.round(at.bottom + 8)}px`;
        panel.style.right = `${Math.max(16, Math.round(document.documentElement.clientWidth - at.right))}px`;
    }
    attnWindow = { bell, el, phone };
    document.querySelectorAll('.ui-bell').forEach(b => {
        b.setAttribute('aria-expanded', String(b === bell));
        if (b === bell) b.setAttribute('aria-controls', el.id);
    });
    renderAttention();
    attentionRefresh();
}

function attnWindowClose({ toPage = false } = {}) {
    const w = attnWindow;
    if (!w) return;
    attnWindow = null;
    if (toPage) uiLayerReturn(w.el, null);
    if (w.phone) uiSheetClose('attn-sheet');
    else w.el.remove();
    document.querySelectorAll('.ui-bell').forEach(b => {
        b.setAttribute('aria-expanded', 'false');
        b.removeAttribute('aria-controls');
    });
}

async function attnBellGo(go) {
    const moved = await navigateTo(go[0], go[1] || {});
    if (moved && attnWindow) attnWindowClose({ toPage: true });
}

function attnBellOpen() {
    const w = attnWindow;
    if (!w) return;
    attnWindowClose();
    uiLayerOpener(w.bell);
}

const DASH_PERIODS = {
    '24h': { name: '24 hours', last: 'last 24 hours', all: 'All 24 hours' },
    '7d': { name: '7 days', last: 'last 7 days', all: 'All 7 days' },
    '30d': { name: '30 days', last: 'last 30 days', all: 'All 30 days' },
};
const dashFlow = {
    period: '24h',
    data: null,
    full: null,
    prev: null,
    limits: null,
    zoom: null,
    pick: null,
    view: 0,
    periodGen: 0, periodControl: null, zoomGen: 0, zoomControl: null,
    loadedAt: 0, zoomer: null, overview: null, previewing: false,
    stale: false,
    dataView: -1,
    failed: false,
};

function mailFlowHour(t) {
    return formatClock(t);
}

function mailFlowSpan(from, to, day = formatDay) {
    const end = to - 1;
    const sameDay = zonedDateString(from) === zonedDateString(end);
    if (isZonedMidnight(from) && isZonedMidnight(to)) return sameDay ? day(from) : `${day(from)} to ${day(end)}`;
    if (sameDay) return `${day(from)}, ${mailFlowHour(from)} to ${mailFlowHour(to)}`;
    return `${day(from)}, ${mailFlowHour(from)} to ${day(end)}, ${mailFlowHour(to)}`;
}

function mailFlowBucketFor(len) {
    return len <= 48 * 3600000 ? 'hour' : len <= 10 * 86400000 ? '6h' : 'day';
}

function setDashFlowPeriod(period) {
    if (!DASH_PERIODS[period]) return;
    dashFlow.period = period;
    dashFlow.zoom = null;
    dashFlow.pick = null;
    dashFlow.full = null;
    dashFlow.data = null;
    mailFlowFiguresUnknown();
    dashFlow.view++;
    document.querySelectorAll('#dashboard-flow-period button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.period === period)));
    loadMailFlowChart();
}

function pickMailFlowHour(t) {
    dashFlow.pick = t === null || dashFlow.pick === t ? null : t;
    renderMailFlowStats();
}

function dashFlowStep(step) {
    const l = dashFlow.limits, d = dashFlow.data;
    if (!l || !d) return;
    if (step === 'reset') { dashFlowZoom(null); return; }
    const bars = d.buckets.map(b => ({ s: Date.parse(b.start), e: Date.parse(b.end) }));
    const n = bars.length;
    if (!n) return;
    const shown = { from: bars[0].s, to: bars[n - 1].e };
    const len = shown.to - shown.from;
    const k = Math.max(1, Math.floor(n / 2));
    if (step === 'in') {
        if (n < 2) return;
        const i = Math.floor((n - k) / 2);
        dashFlowZoom({ from: bars[i].s, to: bars[i + k - 1].e });
    } else if (step === 'earlier') {
        const from = Math.max(l.from, shown.from - (k < n ? bars[k].s - bars[0].s : len));
        dashFlowZoom({ from, to: from + len });
    } else if (step === 'later') {
        const to = Math.min(l.to, shown.to + (k < n ? bars[n - 1].e - bars[n - 1 - k].e : len));
        dashFlowZoom({ from: to - len, to });
    } else {
        dashFlowZoom(uiTimeZoomStep(shown, l, step));
    }
}

function dashFlowZoom(span) {
    const l = dashFlow.limits;
    dashFlow.zoom = !span || (l && span.from <= l.from + 1 && span.to >= l.to - 1) ? null : { from: span.from, to: span.to };
    dashFlow.pick = null;
    dashFlow.view++;
    dashFlow.stale = false;
    if (!dashFlow.zoom && dashFlow.full) {
        dashFlow.zoomGen++;
        if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
        dashFlow.data = dashFlow.full;
        dashFlow.failed = false;
        renderMailFlowChart();
        return;
    }
    loadMailFlowChart();
}

function mailFlowBusy() {
    return dashFlow.previewing || !!(dashFlow.overview && dashFlow.overview.busy());
}

function mailFlowSettle() {
    if (dashFlow.stale && !mailFlowBusy()) loadMailFlowChart();
}

function mailFlowGet(query, control) {
    return authenticatedFetch(`/api/stats/flow?${query}`, control ? { signal: control.signal } : {}).then(async res => {
        if (!res.ok) throw await responseError(res);
        return res.json();
    });
}

function mailFlowFailed() {
    const chart = document.getElementById('dashboard-flow-chart');
    if (!chart) return;
    dashFlow.failed = true;
    const failed = '<p class="ui-empty ui-text-fail ui-flow-failed">Could not load the mail flow. It tries again on the next refresh.</p>';
    if (dashFlow.zoomer) { dashFlow.zoomer.destroy(); dashFlow.zoomer = null; }
    dashFlow.previewing = false;
    const view = chart.querySelector('.ui-flow-view');
    if (view) view.innerHTML = failed;
    else chart.innerHTML = mailFlowFrame(failed);
    if (!dashFlow.data) mailFlowFiguresUnknown();
}

function mailFlowFiguresUnknown() {
    for (const id of ['stat-messages-24h', 'stat-blocked-24h', 'stat-deferred-24h', 'stat-auth-failures-24h']) {
        const el = document.getElementById(id);
        if (el) el.textContent = '-';
    }
    for (const id of ['stat-messages-note', 'stat-blocked-note', 'stat-deferred-note', 'stat-auth-failures-note']) {
        const el = document.getElementById(id);
        if (el) { el.textContent = ''; el.title = ''; }
    }
    const figure = document.getElementById('dashboard-flow-messages');
    if (figure) figure.disabled = true;
    const long = document.querySelector('#dashboard-flow-title .ui-flow-long');
    if (long) long.textContent = `Mail flow, ${DASH_PERIODS[dashFlow.period].last}`;
}

function loadMailFlowChart() {
    const chart = document.getElementById('dashboard-flow-chart');
    if (!chart) return;
    if (mailFlowBusy()) return;
    dashFlow.stale = false;
    if (!chart.querySelector('.ui-flow-view')) chart.innerHTML = mailFlowFrame('<p class="ui-empty ui-flow-failed" role="status">Loading...</p>');
    if (dashFlow.zoom && dashFlow.full) loadMailFlowZoom();
    else loadMailFlowPeriod();
}

async function loadMailFlowPeriod() {
    const gen = ++dashFlow.periodGen;
    if (dashFlow.periodControl) dashFlow.periodControl.abort();
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    dashFlow.periodControl = control;
    const period = dashFlow.period;
    try {
        const [data, prev] = await Promise.all([mailFlowGet(`period=${period}`, control), mailFlowGet(`period=${period}&previous=true`, control)]);
        if (gen !== dashFlow.periodGen || period !== dashFlow.period) return;
        dashFlow.full = data;
        dashFlow.prev = prev;
        dashFlow.loadedAt = Date.now();
        dashFlow.limits = { from: Date.parse(data.from), to: Date.parse(data.to), min: 3600000 };
        if (!dashFlow.zoom) {
            if (mailFlowBusy()) { dashFlow.stale = true; return; }
            dashFlow.data = data;
            dashFlow.failed = false;
            renderMailFlowChart();
            return;
        }
        const l = dashFlow.limits, z = dashFlow.zoom;
        const from = Math.max(z.from, l.from), to = Math.min(z.to, l.to);
        const moved = from !== z.from || to !== z.to;
        if (mailFlowBusy()) {
            if (moved) { dashFlow.zoom = to - from >= l.min ? { from, to } : null; dashFlow.view++; }
            dashFlow.stale = true;
            return;
        }
        if (moved) { dashFlowZoom(to - from >= l.min ? { from, to } : null); return; }
        if (dashFlow.dataView !== dashFlow.view) { loadMailFlowZoom(); return; }
        renderMailFlowOverview(true);
    } catch (error) {
        if (gen !== dashFlow.periodGen || (error && error.name === 'AbortError')) return;
        if (mailFlowBusy()) { dashFlow.failed = true; dashFlow.stale = true; return; }
        if (!dashFlow.zoom) mailFlowFailed();
    }
}

async function loadMailFlowZoom() {
    const z = dashFlow.zoom, view = dashFlow.view;
    const gen = ++dashFlow.zoomGen;
    if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    dashFlow.zoomControl = control;
    const iso = t => new Date(t).toISOString();
    try {
        const data = await mailFlowGet(`from=${iso(z.from)}&to=${iso(z.to)}&bucket=${mailFlowBucketFor(z.to - z.from)}`, control);
        if (gen !== dashFlow.zoomGen || view !== dashFlow.view) return;
        if (mailFlowBusy()) { dashFlow.stale = true; return; }
        dashFlow.data = data;
        dashFlow.failed = false;
        dashFlow.zoom = { from: Date.parse(data.from), to: Date.parse(data.to) };
        const l = dashFlow.limits;
        if (l) dashFlow.limits = { ...l, to: Math.max(l.to, dashFlow.zoom.to) };
        if (l && dashFlow.zoom.from <= l.from + 1 && dashFlow.zoom.to >= l.to - 1) dashFlow.zoom = null;
        renderMailFlowChart();
    } catch (error) {
        if (gen !== dashFlow.zoomGen || view !== dashFlow.view || (error && error.name === 'AbortError')) return;
        if (mailFlowBusy()) { dashFlow.failed = true; dashFlow.stale = true; return; }
        mailFlowFailed();
    }
}

function refreshMailFlowChart() {
    if (mailFlowBusy()) return;
    if (dashFlow.failed) { loadMailFlowChart(); return; }
    const every = dashFlow.period === '24h' ? 60000 : 300000;
    if (Date.now() - dashFlow.loadedAt >= every) loadMailFlowPeriod();
}

function renderMailFlowOverview(alone = false) {
    const strip = document.querySelector('#dashboard-flow-chart .ui-ov');
    if (!strip) return;
    const draw = () => {
        if (dashFlow.overview) { dashFlow.overview.destroy(); dashFlow.overview = null; }
        const full = dashFlow.full, l = dashFlow.limits;
        if (!full || !l) { strip.innerHTML = ''; return; }
        const bars = full.buckets.map(b => ({ s: Date.parse(b.start), e: Date.parse(b.end), v: b.clean + b.spam }));
        const max = Math.max(1, ...bars.map(b => b.v));
        const kept = full.kept_from ? Date.parse(full.kept_from) : null;
        const i = kept === null ? -1 : bars.findIndex(b => kept < b.e);
        const gone = kept === null || kept <= l.from ? 0 : i < 0 ? 1 : (i + Math.max(0, kept - bars[i].s) / (bars[i].e - bars[i].s)) / bars.length;
        strip.innerHTML = `<div class="ui-ov-bars" aria-hidden="true">${bars.map(b => `<i style="height:${Math.max(6, b.v / max * 100)}%"></i>`).join('')}</div>`
            + (gone ? `<div class="ui-ov-gone" style="width:${gone * 100}%" aria-hidden="true"></div>` : '');
        const edges = bars.map(b => b.s).concat(l.to);
        const big = dashFlow.period === '24h' ? 6 * 3600000 : dashFlow.period === '7d' ? 86400000 : 7 * 86400000;
        dashFlow.overview = uiTimeOverview(strip, {
            limits: () => dashFlow.limits,
            span: () => dashFlow.zoom || dashFlow.limits,
            snap: uiNearestLocalHour,
            step: (t, dir, isBig) => (isBig ? t + dir * big
                : dir > 0 ? (edges.find(e => e > t + 1) ?? l.to) : ([...edges].reverse().find(e => e < t - 1) ?? l.from)),
            label: t => `${formatDay(t)}, ${mailFlowHour(t)}`,
            change: span => dashFlowZoom(span),
            idle: mailFlowSettle,
        });
    };
    if (alone) uiRedrawKeepingFocus(strip, draw);
    else draw();
}

function mailFlowFoot(can) {
    const off = on => (on ? '' : ' disabled');
    const figure = document.getElementById('dashboard-flow-messages');
    if (figure) figure.disabled = !can.view;
    return `<div class="ui-flow-foot">
            <div class="ui-flow-legend"><span><i class="ui-flow-clean"></i>Clean</span><span><i class="ui-flow-spam"></i>Spam</span></div>
            <div class="ui-flow-zoom" role="group" aria-label="Zoom the chart">
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('earlier')" aria-label="Earlier" title="Earlier"${off(can.earlier)}>&lsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('out')" aria-label="Zoom out" title="Zoom out"${off(can.out)}>&minus;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('in')" aria-label="Zoom in" title="Zoom in (or pinch, drag across bars, Ctrl+wheel)"${off(can.in)}>+</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="dashFlowStep('later')" aria-label="Later" title="Later"${off(can.later)}>&rsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm${can.zoomed ? '' : ' is-off'}" onclick="dashFlowStep('reset')" aria-label="Reset zoom" title="Reset zoom"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg></button>
            </div>
            <span class="ui-flow-actions">
                <button type="button" id="dashboard-flow-view" class="ui-btn ui-btn-sm" onclick="openMailFlowHourMessages()"${off(can.view)}>View these messages</button>
                <button type="button" id="dashboard-flow-reset" class="ui-more is-off" onclick="pickMailFlowHour(null)">Clear</button>
            </span>
        </div>`;
}

function mailFlowFrame(inner) {
    return `<div class="ui-flow-view">${inner}</div><div class="ui-flow-axis" aria-hidden="true"></div><div class="ui-ov" data-zoom></div>${mailFlowFoot({})}`;
}

function renderMailFlowChart() {
    const chart = document.getElementById('dashboard-flow-chart');
    const d = dashFlow.data;
    if (!chart || !d) return;
    const bars = d.buckets.map(b => ({ ...b, s: Date.parse(b.start), e: Date.parse(b.end) }));
    const max = Math.max(1, ...bars.map(b => b.clean + b.spam));
    const n = bars.length;
    const label = (b, i) => {
        const p = zonedParts(b.s);
        if (i === n - 1 && b.partial) return '<span class="is-major">Now</span>';
        if (d.bucket === 'hour') return p.hour % 6 === 0 ? `<span class="is-major">${formatClock(b.s, { compact: true })}</span>` : p.hour % 3 === 0 ? `<span class="is-minor">${formatClock(b.s, { compact: true })}</span>` : '<span></span>';
        if (d.bucket === '6h') return p.hour < 6 ? `<span class="is-major">${escapeHtml(formatDayMonth(b.s))}</span>` : '<span></span>';
        return (n <= 10 || (i % 5 === 0 && i < n - 5)) ? `<span class="is-major">${escapeHtml(formatDayMonth(b.s))}</span>` : '<span></span>';
    };
    const zoomed = !!dashFlow.zoom;
    dashFlow.dataView = dashFlow.view;
    const shown = { from: Date.parse(d.from), to: Date.parse(d.to) };
    const kept = d.kept_from ? Date.parse(d.kept_from) : null;
    let gone = 0;
    if (kept !== null && kept > shown.from) {
        const i = bars.findIndex(b => kept < b.e);
        gone = i < 0 ? 1 : (i + Math.max(0, kept - bars[i].s) / (bars[i].e - bars[i].s)) / n;
    }
    if (dashFlow.zoomer) { dashFlow.zoomer.destroy(); dashFlow.zoomer = null; }
    uiRedrawKeepingFocus(chart, () => { chart.innerHTML = `
        <div class="ui-flow-view">
            <div class="ui-flow-bars" role="group" aria-label="Messages per ${d.bucket === 'day' ? 'day' : d.bucket === '6h' ? 'six hours' : 'hour'}" data-zoom>${bars.map(b => `
                <button type="button" class="ui-flow-bar${b.partial ? ' is-partial' : ''}" data-t="${b.s}" data-start="${b.s}" data-end="${b.e}" aria-pressed="false" onclick="pickMailFlowHour(${b.s})"
                    title="${escapeHtml(mailFlowSpan(b.s, b.e))}: ${Number(b.messages).toLocaleString()} messages, ${Number(b.clean).toLocaleString()} clean, ${Number(b.spam).toLocaleString()} spam${b.partial ? ', so far' : ''}. Click for its numbers">
                    <i class="ui-flow-spam" style="height: ${(b.spam / max) * 100}%"></i>
                    <i class="ui-flow-clean" style="height: ${(b.clean / max) * 100}%"></i>
                </button>`).join('')}</div>
            ${gone ? `<div class="ui-flow-gone" style="width:${gone * 100}%" title="Logs older than the retention days are cleaned up">${gone > .2 ? '<span>Logs cleaned up</span>' : ''}</div>` : ''}
            <div class="ui-flow-band hidden" aria-hidden="true"></div>
        </div>
        <div class="ui-flow-axis" aria-hidden="true">${bars.map(label).join('')}</div>
        <div class="ui-ov" data-zoom role="group" aria-label="The whole period, with the span shown"></div>
        ${mailFlowFoot({ zoomed, earlier: zoomed && shown.from > dashFlow.limits.from, out: zoomed, in: shown.to - shown.from > dashFlow.limits.min, later: zoomed && shown.to < dashFlow.limits.to, view: true })}`;
        renderMailFlowOverview(); });
    const box = chart.querySelector('.ui-flow-bars');
    const view = chart.querySelector('.ui-flow-view');
    const band = chart.querySelector('.ui-flow-band');
    dashFlow.zoomer = uiTimeZoom(box, {
        bars: () => [...box.querySelectorAll('.ui-flow-bar')],
        span: () => dashFlow.zoom || dashFlow.limits,
        limits: () => dashFlow.limits,
        preview: (span, kind) => {
            if (!dashFlow.previewing) {
                dashFlow.previewing = true;
                if (dashFlow.zoomControl) dashFlow.zoomControl.abort();
                dashFlow.zoomGen++;
            }
            if (kind === 'select') {
                const r = view.getBoundingClientRect();
                band.classList.remove('hidden');
                band.style.left = `${span.x1 - r.left}px`;
                band.style.width = `${span.x2 - span.x1}px`;
                return;
            }
            const len = shown.to - shown.from, next = span.to - span.from;
            const k = len / next;
            const x = -(span.from - shown.from) / len * view.clientWidth * k;
            box.style.transformOrigin = '0 0';
            box.style.transform = `translateX(${x}px) scaleX(${k})`;
        },
        change: span => { dashFlow.previewing = false; dashFlowZoom({ from: span.from, to: span.to }); },
        cancel: () => {
            dashFlow.previewing = false;
            box.style.transform = '';
            band.classList.add('hidden');
            loadMailFlowChart();
        },
    });
    renderMailFlowStats();
}

function renderMailFlowStats() {
    const d = dashFlow.data;
    if (!d) return;
    const period = DASH_PERIODS[dashFlow.period];
    const bar = dashFlow.pick === null ? null : d.buckets.find(b => Date.parse(b.start) === dashFlow.pick);
    if (!bar) dashFlow.pick = null;
    const set = (id, text) => { const el = document.getElementById(id); if (el) { el.textContent = text; if (el.tagName === 'SMALL') el.title = text; } };
    const n = v => (v || 0).toLocaleString();
    const src = bar || d.totals;
    set('stat-messages-24h', n(src.messages));
    set('stat-blocked-24h', n(src.blocked));
    set('stat-deferred-24h', n(src.deferred));
    set('stat-auth-failures-24h', n(src.auth_failures));
    const p = dashFlow.prev && dashFlow.prev.totals;
    const before = key => {
        if (bar) return `${dashFlow.zoom ? 'Shown' : period.name}: ${n(d.totals[key])}`;
        if (dashFlow.zoom || !p) return '';
        return `Previous: ${n(p[key])}${dashFlow.prev.older_may_be_gone ? ' (partial)' : ''}`;
    };
    const note = document.getElementById('stat-messages-note');
    if (note) {
        const lines = [`${n(src.deliveries)} deliveries`, before('messages')];
        note.innerHTML = lines.map(line => `<span>${escapeHtml(line) || '&nbsp;'}</span>`).join('');
        note.title = lines.filter(Boolean).join(', ');
    }
    set('stat-blocked-note', before('blocked'));
    set('stat-deferred-note', before('deferred'));
    set('stat-auth-failures-note', before('auth_failures'));
    const shown = bar ? [Date.parse(bar.start), Date.parse(bar.end)] : dashFlow.zoom ? [Date.parse(d.from), Date.parse(d.to)] : null;
    const soFar = bar && bar.partial ? ', so far' : '';
    const long = document.querySelector('#dashboard-flow-title .ui-flow-long');
    const short = document.querySelector('#dashboard-flow-title .ui-flow-short');
    if (long) long.textContent = `Mail flow, ${shown ? mailFlowSpan(...shown) : period.last}${soFar}`;
    if (short) short.textContent = shown ? `${mailFlowSpan(...shown, formatDayMonth)}${soFar}` : 'Mail flow';
    document.getElementById('dashboard-flow-reset')?.classList.toggle('is-off', !bar);
    document.getElementById('dashboard-flow-clear')?.classList.toggle('hidden', !bar);
    const bars = document.querySelector('#dashboard-flow-chart .ui-flow-bars');
    if (bars) {
        bars.classList.toggle('has-pick', !!bar);
        bars.querySelectorAll('.ui-flow-bar').forEach(b => b.setAttribute('aria-pressed', String(!!bar && Number(b.dataset.t) === dashFlow.pick)));
    }
}

function messagesShowRange(start, endInclusive, label = '') {
    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = start;
    document.getElementById('messages-end-date').value = endInclusive;
    document.getElementById('messages-date-range-start').value = zonedDateString(Date.parse(start));
    document.getElementById('messages-date-range-end').value = zonedDateString(Date.parse(endInclusive));
    document.getElementById('messages-date-range-label').textContent = label || mailFlowSpan(Date.parse(start), Date.parse(endInclusive) + 1);
    setMessagesDatePresetActive(null);
}

function openMessagesRange({ start, endInclusive, user = '', label = '' }) {
    return openMessagesWith(() => {
        ['search', 'sender', 'recipient', 'user', 'ip', 'direction', 'status'].forEach(key => {
            const el = document.getElementById(`messages-filter-${key}`);
            if (el) el.value = '';
        });
        if (user) {
            const field = document.getElementById('messages-filter-user');
            if (field) field.value = user;
        }
        messagesShowRange(start, endInclusive, label);
        setMessagesFilters({ start_date: start, end_date: endInclusive, ...(user ? { user } : {}) });
        currentPage.messages = 1;
    });
}

function openMailFlowHourMessages() {
    const d = dashFlow.data;
    if (!d) return;
    const bar = dashFlow.pick === null ? null : d.buckets.find(b => Date.parse(b.start) === dashFlow.pick);
    if (bar) openMessagesRange({ start: bar.start, endInclusive: bar.end_inclusive });
    else openMessagesRange({ start: d.from, endInclusive: d.to_inclusive });
}

function acknowledgeSecurityAlertOnce(alertId, button) {
    return uiOnce(`alert-ack:${alertId}`, () => acknowledgeSecurityAlert(alertId), button);
}
async function acknowledgeSecurityAlert(alertId) {
    if (!uiMayAct('alerts')) return;
    const alert =dashboardAlerts.get(Number(alertId)) || (typeof alertActivity !== 'undefined' && alertActivity && Number(alertActivity.alert.id) === Number(alertId) ? alertActivity.alert : null);
    const area = alert ? alertArea(alert) : null;
    if (area && !uiMayAct(area)) return;
    const name = !alert ? 'the alert' : alert.subject && !String(alert.title).includes(alert.subject) ? `${alert.title}: ${alert.subject}` : alert.title;
    try {
        const res = await authenticatedFetch(`/api/security-alerts/${alertId}/acknowledge`, { method: 'POST' });
        if (!res.ok) throw await responseError(res);
        const done = await res.json();
        loadDashboardSecurityAlerts();
        if (!done.receipt) { showToast('Already dismissed', 'info'); return; }
        offerAlertUndo(done.receipt, 'Alert dismissed', `Undo dismissing ${name}`, area ? [area] : ALERT_AREAS);
    } catch (e) {
        showToast(`Could not dismiss the alert: ${uiSentence(uiErrorText(e))}`, 'error');
    }
}

function acknowledgeAllSecurityAlertsOnce(button) {
    return uiOnce('alert-ack-all', acknowledgeAllSecurityAlerts, button, 'Dismissing...');
}
async function acknowledgeAllSecurityAlerts() {
    if (!uiMayAct('alerts')) return;
    const ids = dashboardWritableAlertIds.slice();
    if (!ids.length) return;
    const areas = ALERT_AREAS.filter(a => userCan(a, 'write'));
    try {
        const res = await authenticatedFetch('/api/security-alerts/acknowledge-all', {
            method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }),
        });
        if (!res.ok) throw await responseError(res);
        const done = await res.json();
        loadDashboardSecurityAlerts();
        if (!done.receipt) { showToast('Already dismissed', 'info'); return; }
        const words = `${uiCountLabel(done.acknowledged, 'alert', 'alerts')} dismissed`;
        offerAlertUndo(done.receipt, words, `Undo dismissing ${uiCountLabel(done.acknowledged, 'alert', 'alerts')}`, areas);
    } catch (e) {
        showToast(`Could not dismiss the alerts: ${uiSentence(uiErrorText(e))}`, 'error');
    }
}

function offerAlertUndo(receipt, message, undoName, areas) {
    showToast(message, 'success', { duration: 10000, action: { label: 'Undo', ariaLabel: undoName, onAction: () => undoAlertDismissal(receipt, undoName, areas) } });
}

function offerAlertsRefresh(message) {
    showToast(message, 'warning', { duration: Infinity, action: { label: 'Refresh', ariaLabel: 'Refresh Needs attention', onAction: async () => {
        if (!(await loadDashboardSecurityAlerts())) offerAlertsRefresh('Needs attention could not be refreshed. Try again.');
        else showToast('Needs attention is up to date', 'success');
    } } });
}

async function undoAlertDismissal(receipt, undoName, areas = ALERT_AREAS) {
    if (!uiMayAct('alerts')) return;
    if (!areas.some(a => userCan(a, 'write'))) { uiNotPermitted(); return; }
    try {
        const res = await authenticatedFetch(`/api/security-alerts/acknowledgements/${encodeURIComponent(receipt)}/undo`, { method: 'POST' });
        if (!res.ok) throw await responseError(res);
        const done = await res.json();
        const shown = await loadDashboardSecurityAlerts();
        const back = done.restored ? `${uiCountLabel(done.restored, 'alert', 'alerts')} back` : '';
        if (!shown) {
            offerAlertsRefresh(back ? `${back}, but Needs attention could not be refreshed.` : 'Needs attention could not be refreshed.');
            return;
        }
        const place = attnWindow ? ['#attn-win-alerts', attnWindow.phone ? '#attn-sheet .ui-sheet-body' : '#attn-win-scroll']
            : typeof currentTab === 'undefined' || currentTab === 'dashboard' ? ['#dashboard-security-alerts', '#dashboard-attention-scroll'] : null;
        if (place) {
            const row = done.ids && done.ids.map(id => document.querySelector(`${place[0]} [data-key="alert-${Number(id)}"]`)).find(Boolean);
            const target = row ? row.querySelector('.ui-alert-x') : document.querySelector(place[1]);
            if (target) target.focus({ preventScroll: false });
        }
        showToast(back ? `${back} in Needs attention` : 'Nothing to undo: dismissed again, or your access changed', back ? 'success' : 'info');
    } catch (e) {
        showToast(`Could not undo: ${uiSentence(uiErrorText(e))}`, 'error', { duration: Infinity, action: { label: 'Retry', ariaLabel: `Retry: ${undoName}`, onAction: () => undoAlertDismissal(receipt, undoName, areas) } });
    }
}

const DASH_TRENDS = {
    storage_used: { label: 'Mail storage used', format: v => `${Math.round(v)}%` },
    security_review: { label: 'Addresses to review', format: v => `${Math.round(v)}`, feature: 'netfilter' },
    security_banned: { label: 'Addresses banned', format: v => `${Math.round(v)}`, feature: 'netfilter' },
};
let dashboardTrends = null;
let dashboardTrendsAt = 0;

async function loadDashboardTrends() {
    dashboardTrendsAt = Date.now();
    const names = Object.keys(DASH_TRENDS).filter(n => !DASH_TRENDS[n].feature || !isFeatureDisabled(DASH_TRENDS[n].feature));
    try {
        const res = await authenticatedFetch(`/api/stats/trends?names=${names.join(',')}&days=7`);
        if (!res.ok) return;
        dashboardTrends = (await res.json()).trends || {};
        paintDashboardTrends();
    } catch (e) {
        console.warn('Failed to load trends:', e);
    }
}

function paintDashboardTrends() {
    document.querySelectorAll('.ui-spark[data-trend]').forEach(el => {
        const name = el.dataset.trend, meta = DASH_TRENDS[name];
        if (!meta || !dashboardTrends || !(name in dashboardTrends)) { el.innerHTML = ''; return; }
        el.innerHTML = uiSparkline(dashboardTrends[name], { days: 7, label: meta.label, format: meta.format });
    });
}

function setDashKpi(id, value, tone, note) {
    const el = document.getElementById(id);
    if (el) { el.textContent = value; el.className = tone ? `ui-${tone}` : ''; }
    const noteEl = document.getElementById(`${id}-note`);
    if (noteEl && note !== undefined) noteEl.textContent = note;
}
function dashKpiFailed(...ids) {
    for (const id of ids) {
        const el = document.getElementById(id);
        const noteEl = document.getElementById(`${id}-note`);
        if (noteEl) noteEl.textContent = !el || el.textContent === '-' ? 'Could not load' : 'Could not update';
    }
}
function dashKpiUnknown(id) {
    const shown = document.getElementById(id)?.textContent;
    if (shown && shown !== '-' && shown !== 'Unknown') dashKpiFailed(id);
    else setDashKpi(id, 'Unknown', '', 'mailcow did not answer');
}

async function loadDashboardSecurity() {
    const panel = document.getElementById('dashboard-security-panel');
    if (!panel) return;
    if (isFeatureDisabled('netfilter') || !userCan('security')) {
        panel.classList.add('hidden');
        return;
    }
    panel.classList.remove('hidden');
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : null;
        } catch (e) {
            return null;
        }
    };
    const [page, rules, abuse] = await Promise.all([
        get('/api/security/addresses?list=review&limit=1'),
        protectionSaved ? null : get('/api/protection/rules'),
        smtpAbuseStatus ? null : get('/api/smtp-abuse/status?limit=1'),
        fail2banSettingsLoaded ? null : loadFail2BanSettings(),
    ]);
    if (rules) {
        protectionCaps = rules.capabilities || protectionCaps;
        if (!protectionDirty) {
            protectionRules = rules.rules;
            protectionSaved = JSON.parse(JSON.stringify(rules.rules));
        }
    }
    if (abuse) smtpAbuseStatus = abuse;
    renderDashboardSecurity(page || dashboardSecurityPage);
}

let dashboardSecurityPage = null;
let dashboardProtectionsOpen = false;

function renderDashboardSecurity(page = dashboardSecurityPage) {
    dashboardSecurityPage = page;
    const box = document.getElementById('dashboard-security');
    if (!box) return;
    const known = !page || page.fail2ban_known !== false;
    const counts = page && known ? page.all_counts : null;
    const n = key => counts ? Number(counts[key]).toLocaleString() : page ? 'Unknown' : '-';
    const protections = securityProtectionItems();
    const on = protections.filter(securityProtectionOn);
    const lineState = on.some(p => p.state === 'on') ? 'on' : on.length ? 'watch' : 'off';
    box.innerHTML = `
        <div class="ui-stats ui-dash-sec-stats">
            <button type="button" class="ui-stat" onclick="openSecurityList('review')"><span>To review</span><b>${n('review')}</b><small>${!page ? 'Could not load' : known ? 'Not banned' : 'Fail2ban did not answer'}</small><span class="ui-spark" data-trend="security_review"></span></button>
            <button type="button" class="ui-stat" onclick="openSecurityList('banned')"><span>Banned now</span><b${counts && counts.banned ? ' class="ui-text-fail"' : ''}>${n('banned')}</b><small>${!page ? 'Could not load' : known ? 'By Fail2ban and the rules' : 'Fail2ban did not answer'}</small><span class="ui-spark" data-trend="security_banned"></span></button>
        </div>
        <button type="button" class="ui-dash-sec-prot is-${lineState}" aria-expanded="${dashboardProtectionsOpen}" aria-controls="dashboard-protections"
            onclick="dashboardProtectionsOpen = !dashboardProtectionsOpen; renderDashboardSecurity()">
            <span class="ui-prot-mark" aria-hidden="true">${securityProtectionMark(lineState)}</span><b>Protection ${on.length} of ${protections.length} on</b><span class="ui-dash-sec-chev" aria-hidden="true"></span>
            ${on.length && !dashboardProtectionsOpen ? `<span class="ui-dash-sec-on">${on.map(p => escapeHtml(p.name)).join(' · ')}</span>` : ''}
        </button>
        ${dashboardProtectionsOpen ? `<div id="dashboard-protections" class="ui-dash-sec-list">${protections.map(p => securityProtectionButton(p, 'openSecurityProtection')).join('')}</div>` : ''}`;
    paintDashboardTrends();
}

async function loadDashboardHealth() {
    try {
        const [infoRes, versionRes] = await Promise.all([authenticatedFetch('/api/settings/info'), authenticatedFetch('/api/status/app-version')]);
        if (infoRes.ok) {
            const info = await infoRes.json();
            const jobs = summarizeJobs(info.background_jobs || {});
            setDashKpi('dash-kpi-jobs', `${jobs.healthy} of ${jobs.running} healthy`, jobs.failed.length ? 'fail' : '',
                jobs.failed.length ? `${jobs.failed.map(([name]) => name).join(', ')} failed` : (jobs.off ? `${jobs.off} off with their feature` : 'None failed'));
            const c = info.correlation_status || {};
            if (c.known === false || !info.correlation_status) setDashKpi('dash-kpi-linking', 'Unknown', '', 'Could not count');
            else setDashKpi('dash-kpi-linking', `${c.completion_rate || 0}%`, c.incomplete ? 'warn' : '',
                `${(c.complete || 0).toLocaleString()} of ${(c.total || 0).toLocaleString()} complete`);
        }
        else dashKpiFailed('dash-kpi-jobs', 'dash-kpi-linking');
        if (versionRes.ok) {
            const v = await versionRes.json();
            setDashKpi('dash-kpi-version', v.current_version || '-', '', v.update_available ? `${v.latest_version} available`
                : v.latest_version === 'unknown' ? 'Update check failed' : 'Up to date');
        }
        else dashKpiFailed('dash-kpi-version');
    } catch (error) {
        console.error('Failed to load dashboard health:', error);
        dashKpiFailed('dash-kpi-jobs', 'dash-kpi-linking', 'dash-kpi-version');
    }
}

async function loadDashboardStatusSummary() {
    try {
        console.log('Loading Dashboard Status Summary...');

        const response = await authenticatedFetch('/api/status/summary');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Status summary data:', data);

        const containers = data.containers || {};
        if (data.containers_known === false) dashKpiUnknown('dash-kpi-containers');
        else setDashKpi('dash-kpi-containers', `${containers.running || 0} of ${containers.total || 0} running`, containers.stopped > 0 ? 'fail' : '',
            [containers.stopped ? `${containers.stopped} stopped` : 'All running', containers.ignored ? `${containers.ignored} ignored` : ''].filter(Boolean).join(', '));

        const storage = data.storage || {};
        const usedPercent = parseInt(storage.used_percent) || 0;
        const storageLevel = usedPercent > 90 ? 'fail' : usedPercent > 75 ? 'warn' : '';
        if (storage.known === false) dashKpiUnknown('dash-kpi-storage');
        else setDashKpi('dash-kpi-storage', `${storage.used_percent || '0%'} used`, storageLevel, `${storage.used || '0'} of ${storage.total || '0'}`);

        const systemDiv = document.getElementById('dashboard-system-summary');
        const system = data.system || {};
        if (system.known === false) {
            if (!systemDiv.querySelector('.ui-kv')) systemDiv.innerHTML = '<p class="ui-empty ui-text-fail">Could not load: mailcow did not answer</p>';
            return;
        }
        systemDiv.innerHTML = `
            <div class="ui-kv"><span>Domains</span><b>${Number(system.domains || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Mailboxes</span><b>${Number(system.mailboxes || 0).toLocaleString()}</b></div>
            <div class="ui-kv"><span>Aliases</span><b>${Number(system.aliases || 0).toLocaleString()}</b></div>
        `;
    } catch (error) {
        console.error('Failed to load status summary:', error);
        dashKpiFailed('dash-kpi-containers', 'dash-kpi-storage');
        const systemDiv = document.getElementById('dashboard-system-summary');
        if (systemDiv && systemDiv.querySelector('.ui-loading')) {
            systemDiv.innerHTML = `<p class="ui-empty ui-text-fail">Could not load: ${escapeHtml(uiErrorText(error))}</p>`;
        }
    }
}

let netfilterExact = null;

function setNetfilterFilters(filters) {
    netfilterExact = null;
    currentFilters.netfilter = filters;
}

function netfilterFilterFields() {
    return {
        ip: document.getElementById('netfilter-filter-ip').value,
        username: document.getElementById('netfilter-filter-username').value,
        action: document.getElementById('netfilter-filter-action').value,
        country_code: document.getElementById('netfilter-filter-country').value
    };
}

function netfilterWithExact(fields) {
    const x = netfilterExact;
    if (x && ((x.ip && (fields.ip || '') !== x.ip) || (x.username && (fields.username || '') !== x.username))) netfilterExact = null;
    if (!netfilterExact) return fields;
    return {
        ...fields, ...(x.ip ? { exact_ip: 'true' } : {}), ...(x.username ? { exact_username: 'true' } : {}),
        ...(x.domain ? { username_domain: x.domain } : {}),
        ...(x.start_date ? { start_date: x.start_date } : {}), ...(x.end_date ? { end_date: x.end_date } : {}),
    };
}

function renderNetfilterExact() {
    const slot = document.getElementById('netfilter-exact');
    if (!slot) return;
    const x = netfilterExact;
    const what = !x ? '' : x.ip ? ['IP', x.ip] : x.username ? ['Account', x.username] : x.domain ? ['Accounts on', x.domain] : '';
    slot.innerHTML = what ? `<span class="ui-sec-filter" title="Matched whole, not as a part of a longer value"><span>${escapeHtml(what[0])} <bdi>${escapeHtml(what[1])}</bdi>${x.period ? `, ${escapeHtml(x.period)}` : ''}</span><button type="button" onclick="clearNetfilterExact()" aria-label="Remove this filter" title="Remove this filter">&times;</button></span>` : '';
}

function clearNetfilterExact() {
    if (netfilterExact) {
        if (netfilterExact.ip) document.getElementById('netfilter-filter-ip').value = '';
        if (netfilterExact.username) document.getElementById('netfilter-filter-username').value = '';
    }
    netfilterExact = null;
    applyNetfilterFilters();
}

function applyNetfilterFilters() {
    currentFilters.netfilter = netfilterWithExact(netfilterFilterFields());
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

function clearNetfilterFilters() {
    document.getElementById('netfilter-filter-ip').value = '';
    document.getElementById('netfilter-filter-username').value = '';
    document.getElementById('netfilter-filter-action').value = '';
    document.getElementById('netfilter-filter-country').value = '';
    setNetfilterFilters({});
    currentPage.netfilter = 1;
    loadNetfilterLogs();
}

async function loadNetfilterLogs(page = 1) {
    const container = document.getElementById('netfilter-logs');
    uiFilterBarSync();
    renderNetfilterExact();

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

        const filters = currentFilters.netfilter || {};
        const params = new URLSearchParams({
            page: page,
            limit: 50,
            ...filters
        });

        console.log('Loading Netfilter logs:', `/api/logs/netfilter?${params}`);

        const response = await authenticatedFetch(`/api/logs/netfilter?${params}`);
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Netfilter data:', data);

        lastDataCache.netfilter = data;

        renderNetfilterData(data);

        currentPage.netfilter = page;
    } catch (error) {
        console.error('Failed to load Netfilter logs:', error);
        document.getElementById('netfilter-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load logs: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton(`loadNetfilterLogs(${Number(page) || 1})`)}</p>`;
        const countEl = document.getElementById('security-count');
        if (countEl) countEl.textContent = '';
    }
}

let fail2banSettingsLoaded = false;
let fail2banActiveBans = null;
let fail2banBlacklist = [];
let fail2banWhitelist = [];
let fail2banPermBans = [];
let fail2banLegacy = [];
let fail2banPolicy = null;

async function loadFail2BanSettings() {
    if (fail2banSettingsLoaded) return;
    try {
        const response = await authenticatedFetch('/api/fail2ban');
        if (!response.ok) throw await responseError(response);
        const data = await response.json();
        const list = value => (value || '').replace(/\n/g, ',').split(',').map(e => e.trim()).filter(e => e);
        fail2banSettingsLoaded = true;
        fail2banLoadError = false;
        fail2banActiveBans = data.active_bans || [];
        fail2banPermBans = data.perm_bans || [];
        fail2banBlacklist = list(data.blacklist);
        fail2banWhitelist = list(data.whitelist);
        fail2banLegacy = data.legacy_entries || [];
        fail2banPolicy = {
            ban_time: data.ban_time, max_ban_time: data.max_ban_time, ban_time_increment: !!Number(data.ban_time_increment),
            max_attempts: data.max_attempts, retry_window: data.retry_window,
            netban_ipv4: data.netban_ipv4, netban_ipv6: data.netban_ipv6
        };
    } catch (error) {
        console.error('Failed to load Fail2Ban settings:', error);
        fail2banLoadError = true;
        fail2banSettingsLoaded = false;
    }
    renderSecurityOverview();
    refreshSecurityAddresses();
    if (!securityListsTyping()) renderSecurityLists();
    if (!securityEditing()) renderSecuritySettings();
    if (lastDataCache.netfilter && mailcowRwConfigured) renderNetfilterData(lastDataCache.netfilter);
}

let allQueueData = [];
let queueSuppressOn = false;
let queueAsked = 0;
let queueApplied = 0;
let queueLoading = false;

function queueListKept() {
    return authenticatedFetch('/api/suppressions/config')
        .then(r => (r.ok ? r.json() : null))
        .then(config => !!(config && config.list_kept === true))
        .catch(() => false);
}

function queueTakeTurn(id) {
    if (id < queueApplied) return false;
    queueApplied = id;
    return true;
}

async function loadQueue() {
    const container = document.getElementById('queue-logs');
    uiFilterBarSync();
    const id = ++queueAsked;

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
        queueLoading = true;

        console.log('Loading Queue...');

        const kept = queueListKept();
        const response = await authenticatedFetch('/api/queue');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Queue data:', data);
        await rwStatusReady;
        const listKept = await kept;
        if (!queueTakeTurn(id)) return;

        queueLoading = false;
        queueSuppressOn = listKept;
        allQueueData = data.data || [];
        updateQueueSummary();
        applyQueueFilters();
    } catch (error) {
        if (!queueTakeTurn(id)) return;
        queueLoading = false;
        console.error('Failed to load queue:', error);
        document.getElementById('queue-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load queue: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadQueue()')}</p>`;
        const countEl = document.getElementById('queue-count');
        if (countEl) countEl.textContent = '';
    }
}

function updateQueueSummary() {
    const el = document.getElementById('queue-summary');
    if (!el) return;
    if (!allQueueData.length) {
        el.textContent = 'The queue is empty.';
        return;
    }
    const count = name => allQueueData.filter(i => (i.queue_name || '').toLowerCase() === name).length;
    const parts = [];
    if (count('deferred')) parts.push(`${count('deferred')} waiting to retry`);
    if (count('hold')) parts.push(`${count('hold')} on hold`);
    if (count('active')) parts.push(`${count('active')} being delivered`);
    const other = allQueueData.length - count('deferred') - count('hold') - count('active');
    if (other) parts.push(`${other} other`);
    el.textContent = `${allQueueData.length} ${allQueueData.length === 1 ? 'message' : 'messages'}: ${parts.join(', ')}. Postfix retries deferred mail on its own.`;
}

function keepCheckedRows(selector, draw, update) {
    const checked = new Set([...document.querySelectorAll(`${selector}:checked`)].map(cb => cb.value));
    draw();
    if (!checked.size) return;
    document.querySelectorAll(selector).forEach(cb => { if (checked.has(cb.value)) cb.checked = true; });
    update();
}

let queueActing = 0;

function applyQueueFilters() {
    keepCheckedRows('.queue-checkbox', drawQueueRows, queueUpdateSelection);
}

function drawQueueRows() {
    const searchTerm = document.getElementById('queue-filter-search')?.value.toLowerCase() || '';
    const queueId = document.getElementById('queue-filter-queue-id')?.value.toLowerCase() || '';

    let filteredData = allQueueData;

    if (searchTerm) {
        filteredData = filteredData.filter(item =>
            item.sender.toLowerCase().includes(searchTerm) ||
            item.recipients.some(r => r.toLowerCase().includes(searchTerm))
        );
    }

    if (queueId) {
        filteredData = filteredData.filter(item =>
            item.queue_id.toLowerCase().includes(queueId)
        );
    }

    const container = document.getElementById('queue-logs');

    const countEl = document.getElementById('queue-count');
    if (countEl) {
        countEl.textContent = uiCountLabel(filteredData.length, 'message', 'messages');
    }

    if (filteredData.length === 0) {
        container.innerHTML = searchTerm || queueId ? `
            <div class="ui-empty">
                <p><b>No queued messages match these filters</b></p>
                <p><button onclick="clearQueueFilters()" class="ui-btn ui-btn-sm">Clear filters</button></p>
            </div>` : '<p class="ui-empty">Mail waiting to be delivered or retried shows up here.</p>';
        return;
    }

    const mayAct = userCan('outbound', 'write');
    const canAct = mailcowRwConfigured && mayAct;

    const lockedNote = canAct || !mayAct ? '' : `<div class="ui-list-note">${uiLocked('Queue actions are locked', `Retry, hold, release, delete and flush ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px 318px; --ui-table-min: 1000px'
        : '--ui-cols: minmax(200px, 1.6fr) 84px minmax(240px, 2.8fr) 70px 104px; --ui-table-min: 740px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" data-sort-at="queue-filter-search" data-sort-name="mail queue" style="${cols}">
        ${canAct ? `
            <div class="ui-toolbar ui-table-tools">
                <button onclick="queueSelectAll()" id="queue-select-all-btn" class="ui-btn ui-btn-sm">Select All</button>
                <button onclick="queueBulkRetry()" id="queue-bulk-retry-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Retry Selected</button>
                <button onclick="queueBulkDelete()" id="queue-bulk-delete-btn" class="hidden ui-btn ui-btn-sm ui-btn-danger-solid">Delete Selected</button>
                <span id="queue-selection-count" class="hidden ui-muted"></span>
                <span class="ui-toolbar-gap"></span>
                <button onclick="queueFlushAll()" id="queue-flush-all-btn" class="ui-btn ui-btn-sm ui-btn-primary" title="Retry delivery of every message in the queue">
                    <svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                    Flush All
                </button>
                <button onclick="queueDeleteAll()" id="queue-delete-all-btn" class="ui-btn ui-btn-sm ui-btn-danger-solid">Delete All</button>
            </div>
        ` : ''}
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span data-sort-kind="text">Recipient</span><span data-sort-kind="text">State</span><span data-sort-kind="text">Last response</span><span class="ui-td-end" data-sort-kind="number">Size</span><span class="ui-td-end">Actions</span></div>
            ${filteredData.map(item => {
                const qid = item.queue_id || '';
                const queueName = (item.queue_name || '').toLowerCase();
                const isHold = queueName === 'hold';
                const queueTone = { hold: '', deferred: 'warn', active: 'ok', incoming: 'info', bounce: 'fail', corrupt: 'fail' }[queueName] || '';
                const stateText = isHold ? 'On hold' : (item.queue_name || 'unknown').replace(/^./, c => c.toUpperCase());
                const recipients = item.recipients.map(r => {
                    const email = r.split(' ')[0].replace(/[<>]/g, '').trim();
                    const rest = r.includes(' ') ? r.substring(r.indexOf(' ')).trim().replace(/^\((.*)\)$/, '$1') : '';
                    return { email, response: rest };
                });
                const responses = recipients.filter(r => r.response);
                const queued = new Date(item.arrival_time * 1000).toISOString();
                const suppress = !queueSuppressOn || !mayAct ? '' : recipients.length === 1
                    ? `<button onclick="showAddSuppressionModal('${escapeJsArg(recipients[0].email)}', '${escapeJsArg(qid)}')" title="Suppress ${escapeHtml(recipients[0].email)}" class="ui-btn ui-btn-sm">Suppress</button>`
                    : uiMenu('Suppress', recipients.map(r => `<button type="button" role="menuitem" onclick="showAddSuppressionModal('${escapeJsArg(r.email)}', '${escapeJsArg(qid)}')">${escapeHtml(r.email)}</button>`).join(''));
                return `
                <div class="ui-tr ui-q-row" data-queue-id="${escapeHtml(qid)}">
                    ${canAct ? `<input type="checkbox" class="queue-checkbox ui-check" value="${escapeHtml(qid)}" onchange="queueUpdateSelection()" aria-label="Select ${escapeHtml(qid)}" />` : ''}
                    <div class="ui-td ui-q-who">
                        <div>${recipients.map(r => uiEntity('address', r.email)).join(', ')}</div>
                        <small>From ${uiEntity('address', item.sender)}, queued <span title="${escapeHtml(formatTime(queued))}">${formatAgo(queued)}</span>, ID ${copyableText(qid)}</small>
                    </div>
                    <span class="ui-td">${uiTag(stateText, queueTone)}</span>
                    <div class="ui-td ui-td-wrap ui-mono ui-q-resp">${responses.length
                        ? responses.map(r => `<div>${recipients.length > 1 ? `<span class="ui-muted">${escapeHtml(r.email)}:</span> ` : ''}${escapeHtml(r.response)}</div>`).join('')
                        : `<span class="ui-muted">${isHold ? 'Put on hold' : '-'}</span>`}</div>
                    <span class="ui-td ui-td-end">${formatSize(item.message_size)}</span>
                    <span class="ui-td ui-td-end ui-row-actions">
                    ${canAct ? `
                        <button onclick="queueRetry('${escapeJsArg(qid)}')" title="Retry delivery" class="queue-action-btn ui-btn ui-btn-sm">Retry</button>
                        ${isHold
                            ? `<button onclick="queueUnhold('${escapeJsArg(qid)}')" title="Release from hold" class="queue-action-btn ui-btn ui-btn-sm">Unhold</button>`
                            : `<button onclick="queueHold('${escapeJsArg(qid)}')" title="Hold message" class="queue-action-btn ui-btn ui-btn-sm">Hold</button>`}
                        <button onclick="queueDeleteItem('${escapeJsArg(qid)}')" title="Delete from queue" class="queue-action-btn ui-btn ui-btn-sm ui-btn-danger">Delete</button>` : ''}
                        ${suppress}
                    </span>
                </div>`;
            }).join('')}
        </div>
    `;
}

function clearQueueFilters() {
    document.getElementById('queue-filter-search').value = '';
    document.getElementById('queue-filter-queue-id').value = '';
    applyQueueFilters();
}

function queueUpdateSelection() {
    const checked = document.querySelectorAll('.queue-checkbox:checked');
    const deleteAll = document.getElementById('queue-delete-all-btn');
    if (deleteAll) deleteAll.classList.toggle('hidden', checked.length > 0);
    const bulkRetry = document.getElementById('queue-bulk-retry-btn');
    const bulkDelete = document.getElementById('queue-bulk-delete-btn');
    const countLabel = document.getElementById('queue-selection-count');
    const selectAll = document.getElementById('queue-select-all-btn');
    const rows = document.querySelectorAll('.queue-checkbox').length;
    if (selectAll) selectAll.textContent = rows && checked.length === rows ? 'Deselect All' : 'Select All';

    if (checked.length > 0) {
        if (bulkRetry) { bulkRetry.classList.remove('hidden'); bulkRetry.classList.add('inline-flex'); }
        if (bulkDelete) { bulkDelete.classList.remove('hidden'); bulkDelete.classList.add('inline-flex'); }
        if (countLabel) { countLabel.classList.remove('hidden'); countLabel.textContent = `${checked.length} selected`; }
    } else {
        if (bulkRetry) { bulkRetry.classList.add('hidden'); bulkRetry.classList.remove('inline-flex'); }
        if (bulkDelete) { bulkDelete.classList.add('hidden'); bulkDelete.classList.remove('inline-flex'); }
        if (countLabel) { countLabel.classList.add('hidden'); countLabel.textContent = ''; }
    }
}

function queueSelectAll() {
    const checkboxes = document.querySelectorAll('.queue-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => { cb.checked = !allChecked; });
    const btn = document.getElementById('queue-select-all-btn');
    if (btn) btn.textContent = allChecked ? 'Select All' : 'Deselect All';
    queueUpdateSelection();
}

function queueGetSelectedIds() {
    return Array.from(document.querySelectorAll('.queue-checkbox:checked')).map(cb => cb.value);
}

async function queueBulkRetry() {
    const ids = queueGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Retry delivery', message: `Retry delivery of ${ids.length} message(s)?`, confirmText: 'Retry' })) return;
    await queueAction('deliver', ids);
}

async function queueBulkDelete() {
    const ids = queueGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete messages', message: `Permanently delete ${ids.length} message(s) from the queue? This cannot be undone.`, confirmText: 'Delete', isDangerous: true })) return;
    await queueDeleteRequest(ids);
}

async function queueRetry(qid) {
    await queueAction('deliver', [String(qid)]);
}

async function queueHold(qid) {
    await queueAction('hold', [String(qid)]);
}

async function queueUnhold(qid) {
    await queueAction('unhold', [String(qid)]);
}

async function queueDeleteItem(qid) {
    if (!await showConfirmModal({ title: 'Delete message', message: 'Delete this message from the queue? This cannot be undone.', confirmText: 'Delete', isDangerous: true })) return;
    await queueDeleteRequest([String(qid)]);
}

async function queueFlushAll() {
    if (!await showConfirmModal({ title: 'Flush queue', message: 'Flush (retry delivery of) ALL messages in the queue?', confirmText: 'Flush all' })) return;
    await queueAction('flush', ['mailqitems-all']);
}

async function queueDeleteAll() {
    if (!await showConfirmModal({ title: 'Delete all', message: 'Permanently delete ALL messages from the queue? This cannot be undone.', confirmText: 'Delete all', isDangerous: true })) return;
    await queueAction('super_delete', ['mailqitems-all']);
}

async function queueAction(action, itemIds) {
    if (!uiMayAct('outbound')) return;
    queueActing++;
    document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
        .forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });

    try {
        const res = await authenticatedFetch('/api/queue/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds, action: action })
        });

        const result = await uiReadJson(res);
        if (res.ok && result && result.status === 'success') {
            const labels = { deliver: 'Retry delivery', hold: 'Hold', unhold: 'Unhold', flush: 'Flush all', super_delete: 'Delete all' };
            showToast(mailcowWords(result.msg) || `${labels[action] || action} completed`, 'success');
            lastDataCache.queue = null;
            await loadQueue();
        } else {
            showToast(`Queue action failed: ` + actionErrorText(res, result), 'error');
        }
    } catch (err) {
        showToast(`Queue action failed: ` + uiErrorText(err), 'error');
    } finally {
        queueActing--;
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

async function queueDeleteRequest(itemIds) {
    if (!uiMayAct('outbound')) return;
    queueActing++;
    document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
        .forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });

    try {
        const res = await authenticatedFetch('/api/queue/delete', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds })
        });

        const result = await uiReadJson(res);
        if (res.ok && result && result.status === 'success') {
            showToast(mailcowWords(result.msg) || 'Message deleted from queue', 'success');
            lastDataCache.queue = null;
            await loadQueue();
        } else {
            showToast('Failed to delete from queue: ' + actionErrorText(res, result), 'error');
        }
    } catch (err) {
        showToast('Failed to delete from queue: ' + uiErrorText(err), 'error');
    } finally {
        queueActing--;
        document.querySelectorAll('.queue-action-btn, .queue-checkbox, #queue-flush-all-btn, #queue-delete-all-btn, #queue-select-all-btn, #queue-bulk-retry-btn, #queue-bulk-delete-btn')
            .forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

let quarantineLastData = null;

function quarantineActionTone(action) {
    return ['reject', 'discard'].includes(String(action || '').toLowerCase()) ? 'fail' : 'warn';
}


let quarantineAsked = 0;
let quarantineApplied = 0;
let quarantineActing = 0;

function quarantineTakeTurn(id) {
    if (id < quarantineApplied) return false;
    quarantineApplied = id;
    return true;
}

async function loadQuarantine() {
    const container = document.getElementById('quarantine-logs');
    uiFilterBarSync();
    const id = ++quarantineAsked;

    try {
        container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';

        console.log('Loading Quarantine...');

        const response = await authenticatedFetch('/api/quarantine');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Quarantine data:', data);
        await rwStatusReady;
        if (!quarantineTakeTurn(id)) return;

        lastDataCache.quarantine = data;
        renderQuarantineData(data);
    } catch (error) {
        if (!quarantineTakeTurn(id)) return;
        lastDataCache.quarantine = null;
        console.error('Failed to load quarantine:', error);
        document.getElementById('quarantine-logs').innerHTML = `<p class="ui-empty ui-text-fail">Failed to load quarantine: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadQuarantine()')}</p>`;
    }
}

function renderQuarantineData(data) {
    keepCheckedRows('.quarantine-checkbox', () => drawQuarantineRows(data), quarantineUpdateSelection);
}

function drawQuarantineRows(data) {
    const container = document.getElementById('quarantine-logs');
    if (!container) return;

    quarantineLastData = data;
    const summary = document.getElementById('quarantine-summary');
    const countEl = document.getElementById('quarantine-count');
    if (countEl) countEl.textContent = uiCountLabel(data.total || (data.data || []).length, 'message', 'messages');
    if (summary) {
        const total = data.total || (data.data || []).length;
        summary.textContent = total
            ? `${total.toLocaleString()} ${total === 1 ? 'message' : 'messages'} held as likely spam. Releasing one delivers it to the recipient.`
            : 'Nothing is held right now.';
    }

    if (!data.data || data.data.length === 0) {
        container.innerHTML = '<p class="ui-empty">Messages that mailcow holds as likely spam show up here.</p>';
        return;
    }

    const mayAct = userCan('quarantine', 'write');
    const canAct = mailcowRwConfigured && mayAct;
    const items = data.data;

    const lockedNote = canAct || !mayAct ? '' : `<div class="ui-list-note">${uiLocked('Quarantine actions are locked', `Release, delete, spam learning and the auto-rules ${UI_RW_KEY_TEXT}`)}</div>`;
    const cols = canAct
        ? '--ui-cols: 20px minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 336px; --ui-table-min: 1080px'
        : '--ui-cols: minmax(200px, 2fr) minmax(150px, 1.3fr) minmax(120px, 1fr) 56px 64px 76px; --ui-table-min: 760px';

    container.innerHTML = `
        ${lockedNote}
        <div class="ui-table ui-stack" data-sort-at="quarantine-list-summary" data-sort-name="quarantined messages" data-sort-default="Held:desc" style="${cols}">
        ${!canAct ? '' : `
            <div class="ui-toolbar ui-table-tools">
                <button onclick="quarantineSelectAll()" id="quarantine-select-all-btn" class="ui-btn ui-btn-sm">Select All</button>
                <button onclick="quarantineBulkRelease()" id="quarantine-bulk-release-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Release Selected</button>
                <button onclick="quarantineBulkDelete()" id="quarantine-bulk-delete-btn" class="hidden ui-btn ui-btn-sm ui-btn-danger-solid">Delete Selected</button>
                <button onclick="quarantineBulkLearnHam()" id="quarantine-bulk-learnham-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Not Spam</button>
                <button onclick="quarantineBulkLearnSpam()" id="quarantine-bulk-learnspam-btn" class="hidden ui-btn ui-btn-sm ui-btn-primary">Learn Spam</button>
                <span id="quarantine-selection-count" class="hidden ui-muted"></span>
                <span class="ui-toolbar-gap"></span>
                <button onclick="quarantineReleaseAll()" id="quarantine-release-all-btn" class="ui-btn ui-btn-sm ui-btn-primary">Release All</button>
                <button onclick="quarantineDeleteAll()" id="quarantine-delete-all-btn" class="ui-btn ui-btn-sm ui-btn-danger-solid">Delete All</button>
            </div>
        `}
            <div class="ui-tr ui-tr-head">${canAct ? '<span></span>' : ''}<span data-sort-kind="text">Message</span><span data-sort-kind="text">For</span><span data-sort-kind="text">Why</span><span class="ui-td-end" data-sort-kind="number">Score</span><span data-sort-kind="date">Held</span><span class="ui-td-end">Actions</span></div>
            ${items.map(item => {
                const itemId = item.id !== undefined ? item.id : '';
                const idArg = escapeJsArg(String(itemId));
                const hasScore = item.score !== undefined && item.score !== null;
                return `
                <div class="ui-tr ui-q-row" data-quarantine-id="${escapeHtml(String(itemId))}" onclick="quarantineRowClick(event, '${idArg}')">
                    ${canAct ? `<input type="checkbox" class="quarantine-checkbox ui-check" value="${escapeHtml(String(itemId))}" onchange="quarantineUpdateSelection()" aria-label="Select message" />` : ''}
                    <div class="ui-td ui-q-who">
                        <button type="button" class="ui-link-row" dir="auto" title="View details" onclick="showQuarantineDetails('${idArg}')">${escapeHtml(item.subject || 'No subject')}</button>
                        <small>${item.sender ? uiEntity('address', item.sender, { plain: true }) : 'Unknown'}${item.qid ? `, ID ${escapeHtml(item.qid)}` : ''}</small>
                    </div>
                    <span class="ui-td">${item.rcpt ? uiEntity('address', item.rcpt, { plain: true }) : 'Unknown'}</span>
                    <span class="ui-td ui-td-wrap">${uiTag(item.action || 'Quarantined', quarantineActionTone(item.action))}${item.virus_flag ? ` ${uiTag('Virus', 'spam')}` : ''}</span>
                    <span class="ui-td ui-td-end${hasScore && item.score >= 15 ? ' ui-text-fail' : ''}"${hasScore && isFinite(Number(item.score)) ? ` data-sort="${Number(item.score)}"` : ''}><small class="ui-sec-unit">Score </small>${hasScore ? item.score.toFixed(1) : '-'}</span>
                    <time class="ui-td" title="${escapeHtml(formatTime(item.created))}"${isFinite(Date.parse(item.created)) ? ` data-sort="${Date.parse(item.created)}"` : ''}><small class="ui-sec-unit">Held </small>${formatAgo(item.created).replace(' ago', '')}</time>
                    <span class="ui-td ui-td-end ui-row-actions">
                        ${canAct ? `
                            <button onclick="quarantineRelease('${idArg}')" title="Release message" class="quarantine-action-btn ui-btn ui-btn-sm">Release</button>
                            <button onclick="quarantineLearnHam('${idArg}')" title="Release and train as not spam" class="quarantine-action-btn ui-btn ui-btn-sm">Not spam</button>
                            <button onclick="quarantineLearnSpam('${idArg}')" title="Delete and train as spam" class="quarantine-action-btn ui-btn ui-btn-sm">Spam</button>
                            <button onclick="showAddRuleFromQuarantine('${escapeJsArg(item.sender || '')}', '${escapeJsArg(item.rcpt || '')}', '${escapeJsArg(item.subject || '')}')" title="Create an auto-rule from this message" class="quarantine-action-btn ui-btn ui-btn-sm">Rule</button>
                            <button onclick="quarantineDelete('${idArg}')" title="Delete message" class="quarantine-action-btn ui-btn ui-btn-sm ui-btn-danger">Delete</button>
                        ` : `<button onclick="showQuarantineDetails('${idArg}')" title="View details" class="quarantine-action-btn ui-btn ui-btn-sm">Details</button>`}
                    </span>
                </div>`;
            }).join('')}
        </div>
    `;
}

function quarantineRowClick(event, itemId) {
    if (event.target.closest('button, a, input, select, label, .copyable, .ui-ent, [role="menu"]') || uiRowHeld(event)) return;
    showQuarantineDetails(itemId);
}

function quarantineUpdateSelection() {
    const checked = document.querySelectorAll('.quarantine-checkbox:checked');
    const bulkBtns = ['quarantine-bulk-release-btn', 'quarantine-bulk-delete-btn', 'quarantine-bulk-learnham-btn', 'quarantine-bulk-learnspam-btn'];
    const countLabel = document.getElementById('quarantine-selection-count');
    const selectAll = document.getElementById('quarantine-select-all-btn');
    const rows = document.querySelectorAll('.quarantine-checkbox').length;
    if (selectAll) selectAll.textContent = rows && checked.length === rows ? 'Deselect All' : 'Select All';

    ['quarantine-release-all-btn', 'quarantine-delete-all-btn'].forEach(id => { const el = document.getElementById(id); if (el) el.classList.toggle('hidden', checked.length > 0); });
    if (checked.length > 0) {
        bulkBtns.forEach(id => { const el = document.getElementById(id); if (el) { el.classList.remove('hidden'); el.classList.add('inline-flex'); } });
        if (countLabel) { countLabel.classList.remove('hidden'); countLabel.textContent = `${checked.length} selected`; }
    } else {
        bulkBtns.forEach(id => { const el = document.getElementById(id); if (el) { el.classList.add('hidden'); el.classList.remove('inline-flex'); } });
        if (countLabel) { countLabel.classList.add('hidden'); countLabel.textContent = ''; }
    }
}

function quarantineSelectAll() {
    const checkboxes = document.querySelectorAll('.quarantine-checkbox');
    const allChecked = Array.from(checkboxes).every(cb => cb.checked);
    checkboxes.forEach(cb => { cb.checked = !allChecked; });
    const btn = document.getElementById('quarantine-select-all-btn');
    if (btn) btn.textContent = allChecked ? 'Select All' : 'Deselect All';
    quarantineUpdateSelection();
}

function quarantineGetSelectedIds() {
    return Array.from(document.querySelectorAll('.quarantine-checkbox:checked')).map(cb => cb.value);
}

async function quarantineRelease(itemId) {
    await quarantineAction('release', [String(itemId)]);
}

async function quarantineDelete(itemId) {
    if (!await showConfirmModal({ title: 'Delete message', message: 'Delete this quarantined message permanently? This cannot be undone.', confirmText: 'Delete', isDangerous: true })) return;
    await quarantineAction('delete', [String(itemId)]);
}

async function quarantineLearnHam(itemId) {
    if (!await showConfirmModal({ title: 'Not spam', message: 'Release this message and train Rspamd that it is not spam?', confirmText: 'Not spam' })) return;
    await quarantineAction('learnham', [String(itemId)]);
}

async function quarantineLearnSpam(itemId) {
    if (!await showConfirmModal({ title: 'Mark as spam', message: 'Delete this message and train Rspamd that it is spam? This cannot be undone.', confirmText: 'Mark as spam', isDangerous: true })) return;
    await quarantineAction('learnspam', [String(itemId)]);
}

async function quarantineBulkRelease() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Release messages', message: `Release ${ids.length} quarantined message(s)?`, confirmText: 'Release' })) return;
    await quarantineAction('release', ids);
}

async function quarantineBulkDelete() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete messages', message: `Permanently delete ${ids.length} quarantined message(s)? This cannot be undone.`, confirmText: 'Delete', isDangerous: true })) return;
    await quarantineAction('delete', ids);
}

async function quarantineBulkLearnHam() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Not spam', message: `Release ${ids.length} message(s) and train Rspamd as not spam?`, confirmText: 'Not spam' })) return;
    await quarantineAction('learnham', ids);
}

async function quarantineBulkLearnSpam() {
    const ids = quarantineGetSelectedIds();
    if (ids.length === 0) return;
    if (!await showConfirmModal({ title: 'Mark as spam', message: `Delete ${ids.length} message(s) and train Rspamd as spam? This cannot be undone.`, confirmText: 'Mark as spam', isDangerous: true })) return;
    await quarantineAction('learnspam', ids);
}

async function quarantineReleaseAll() {
    const allIds = Array.from(document.querySelectorAll('.quarantine-checkbox')).map(cb => cb.value).filter(Boolean);
    if (allIds.length === 0) return;
    if (!await showConfirmModal({ title: 'Release all', message: `Release ALL ${allIds.length} quarantined message(s)?`, confirmText: 'Release all' })) return;
    await quarantineAction('release', allIds);
}

async function quarantineDeleteAll() {
    const allIds = Array.from(document.querySelectorAll('.quarantine-checkbox')).map(cb => cb.value).filter(Boolean);
    if (allIds.length === 0) return;
    if (!await showConfirmModal({ title: 'Delete all', message: `Permanently delete ALL ${allIds.length} quarantined message(s)? This cannot be undone.`, confirmText: 'Delete all', isDangerous: true })) return;
    await quarantineAction('delete', allIds);
}

async function quarantineAction(action, itemIds) {
    if (!uiMayAct('quarantine')) return;
    const allBtns = '.quarantine-action-btn, .quarantine-checkbox, #quarantine-bulk-release-btn, #quarantine-bulk-delete-btn, #quarantine-bulk-learnham-btn, #quarantine-bulk-learnspam-btn, #quarantine-select-all-btn, #quarantine-release-all-btn, #quarantine-delete-all-btn';
    document.querySelectorAll(allBtns).forEach(el => { el.disabled = true; el.style.opacity = '0.5'; });
    quarantineActing++;

    try {
        const endpoints = {
            'release': '/api/quarantine/release',
            'delete': '/api/quarantine/delete',
            'learnham': '/api/quarantine/learnham',
            'learnspam': '/api/quarantine/learnspam'
        };
        const endpoint = endpoints[action] || '/api/quarantine/' + action;
        const res = await authenticatedFetch(endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items: itemIds })
        });

        const result = await uiReadJson(res);
        const actionLabels = { release: 'released', delete: 'deleted', learnham: 'released & marked as not spam', learnspam: 'deleted & marked as spam' };
        if (res.ok && result && result.status === 'success') {
            showToast(mailcowWords(result.msg) || `Message(s) ${actionLabels[action] || action} successfully`, 'success');
            lastDataCache.quarantine = null;
            await loadQuarantine();
        } else {
            showToast(`Failed to ${action} message(s): ` + actionErrorText(res, result), 'error');
        }
    } catch (err) {
        showToast(`Failed to ${action} message(s): ` + uiErrorText(err), 'error');
    } finally {
        quarantineActing--;
        document.querySelectorAll(allBtns).forEach(el => { el.disabled = false; el.style.opacity = ''; });
    }
}

async function showQuarantineDetails(itemId) {
    const existing = document.getElementById('quarantine-detail-modal');
    if (existing) existing.remove();

    uiDialog({
        id: 'quarantine-detail-modal', title: 'Quarantine Item Details', size: 'wide',
        close: closeQuarantineDetails, backdropClose: closeQuarantineDetails,
        bodyId: 'quarantine-detail-content',
        body: '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading details...</p></div>',
        footId: 'quarantine-detail-footer', footHidden: true,
    });
    document.body.style.overflow = 'hidden';

    try {
        const res = await authenticatedFetch(`/api/quarantine/${encodeURIComponent(itemId)}/details`);
        if (!res.ok) throw await responseError(res);
        const data = await res.json();
        renderQuarantineDetailContent(data, itemId);
    } catch (err) {
        document.getElementById('quarantine-detail-content').innerHTML = `
            <div class="ui-empty">
                <p class="ui-text-fail">Could not load the details: ${escapeHtml(uiErrorText(err))}</p>
            </div>`;
    }
}

function closeQuarantineDetails() {
    const modal = document.getElementById('quarantine-detail-modal');
    if (modal) modal.remove();
    document.body.style.overflow = '';
}

function renderQuarantineDetailContent(data, itemId) {
    const content = document.getElementById('quarantine-detail-content');
    const footer = document.getElementById('quarantine-detail-footer');
    if (!content) return;

    const allSymbols = (data.symbols || []);
    const activeSymbols = allSymbols.filter(s => (s.score || 0) !== 0).sort((a, b) => Math.abs(b.score || 0) - Math.abs(a.score || 0));
    const zeroSymbols = allSymbols.filter(s => (s.score || 0) === 0).sort((a, b) => (a.name || '').localeCompare(b.name || ''));

    const recipientsHtml = (data.recipients || []).map(r =>
        `<span class="ui-qd-rcpt"><small class="${r.type === 'smtp' ? 'ui-text-info' : 'ui-muted'}">${escapeHtml(r.type)}</small> ${uiEntity('address', r.address)}</span>`
    ).join(' ');

    const score = data.score || 0;
    const scoreTone = score >= 15 ? 'fail' : score >= 6 ? 'warn' : 'ok';

    const buildSymbolRows = (syms) => syms.map(s => {
        const sc = s.score || 0;
        const tone = sc > 0 ? 'ui-text-fail' : sc < 0 ? 'ui-text-ok' : 'ui-muted';
        const opts = (s.options || []).join(', ');
        return `<tr>
            <td class="ui-mono">${escapeHtml(s.name || '')}</td>
            <td class="ui-muted">${escapeHtml(s.group || '')}</td>
            <td class="ui-td-end ${tone}"><b>${sc !== 0 ? (sc > 0 ? '+' : '') + sc.toFixed(2) : '0'}</b></td>
            <td class="ui-muted ui-qd-opts" title="${escapeHtml(opts)}">${escapeHtml(opts)}</td>
        </tr>`;
    }).join('');

    const symbolTable = rows => `<div class="ui-dtable-scroll"><table class="ui-dtable"><thead><tr>
        <th>Symbol</th><th>Group</th><th class="ui-td-end">Score</th><th>Details</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;

    const plainText = (data.text_plain || '').trim();
    const textContent = (plainText && plainText !== '-') ? data.text_plain : (data.text_html || '');
    const mayAct = userCan('quarantine', 'write');
    const canAct = mailcowRwConfigured && mayAct;

    content.innerHTML = `
        <div class="ui-qd">
            <div class="ui-md-ids ui-qd-facts">
                <div class="ui-md-fact ui-qd-wide"><span>Subject</span><div dir="auto">${copyableText(data.subject || '-')}</div></div>
                <div class="ui-md-fact"><span>From (Header)</span><div>${uiEntity('address', data.header_from || '-')}</div></div>
                <div class="ui-md-fact"><span>Envelope From</span><div class="ui-mono">${uiEntity('address', data.env_from || '-', { mono: true })}</div></div>
                <div class="ui-md-fact ui-qd-wide"><span>Recipients</span><div class="ui-chip-row">${recipientsHtml || '<span class="ui-muted">-</span>'}</div></div>
                <div class="ui-md-fact"><span>Score</span><div class="ui-text-${scoreTone}"><b>${score.toFixed(2)}</b></div></div>
                <div class="ui-md-fact"><span>Action</span><div>${uiTag(data.action || '-', quarantineActionTone(data.action))}</div></div>
            </div>

            <div>
                <h4 class="ui-md-h">Rspamd Symbols</h4>
                ${activeSymbols.length > 0 ? symbolTable(buildSymbolRows(activeSymbols)) : '<p class="ui-muted">No active symbols</p>'}
                ${zeroSymbols.length > 0 ? `
                <details class="ui-dns-more">
                    <summary>Informational symbols (score 0) - ${zeroSymbols.length} items</summary>
                    ${symbolTable(buildSymbolRows(zeroSymbols))}
                </details>` : ''}
            </div>

            ${textContent ? `
            <div>
                <h4 class="ui-md-h">Email Content</h4>
                <pre class="ui-qd-text" dir="auto">${escapeHtml(textContent)}</pre>
            </div>` : ''}

            ${data.fuzzy_hashes && data.fuzzy_hashes.length > 0 ? `
            <div>
                <h4 class="ui-md-h">Fuzzy Hashes</h4>
                <div class="ui-qd-text">${data.fuzzy_hashes.map(h => escapeHtml(JSON.stringify(h))).join('<br>')}</div>
            </div>` : ''}
        </div>
    `;

    if (footer && canAct) {
        footer.className = 'ui-dialog-foot';
        footer.innerHTML = `
            <button onclick="closeQuarantineDetails(); quarantineLearnSpam('${escapeJsArg(itemId)}')" class="ui-btn" title="Delete & train as Spam">Spam</button>
            <button onclick="closeQuarantineDetails(); quarantineLearnHam('${escapeJsArg(itemId)}')" class="ui-btn" title="Release & train as Not Spam">Not Spam</button>
            <span class="ui-toolbar-gap"></span>
            <button onclick="closeQuarantineDetails(); quarantineDelete('${escapeJsArg(itemId)}')" class="ui-btn ui-btn-danger">Delete</button>
            <button onclick="closeQuarantineDetails(); quarantineRelease('${escapeJsArg(itemId)}')" class="ui-btn ui-btn-primary">Release</button>
        `;
    } else if (footer && !mayAct) {
        footer.className = 'hidden';
        footer.innerHTML = '';
    } else if (footer) {
        footer.className = 'ui-dialog-foot ui-dialog-foot-note';
        footer.innerHTML = uiLocked('Quarantine actions are locked', `Release, delete and spam learning ${UI_RW_KEY_TEXT}`);
    }
}

let _quarantineRulesCache = null;

async function initQuarantineRules() {
    const section = document.getElementById('quarantine-rules-section');
    if (!section) return;
    
    if (!mailcowRwConfigured) {
        await fetchRwStatus();
    }
    
    if (showQuarantineRulesAccess()) {
        loadQuarantineRules();
    }
}

function showPageTab(page, tab) {
    Object.keys(TAB_FEATURES[page]).forEach(name => {
        const btn = document.getElementById(`${page}-tab-btn-${name}`);
        if (btn) { btn.classList.toggle('active', name === tab); btn.setAttribute('aria-selected', name === tab); }
        const panel = document.getElementById(`${page}-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
}

let quarantineTab = 'messages';
function quarantineShowTab(tab) {
    quarantineTab = tab;
    routerSyncSubpage('quarantine', tab);
    ['messages', 'rules'].forEach(name => {
        const btn = document.getElementById(`quarantine-tab-btn-${name}`);
        if (btn) { btn.classList.toggle('active', name === tab); btn.setAttribute('aria-selected', name === tab); }
        const panel = document.getElementById(`quarantine-tab-${name}`);
        if (panel) panel.classList.toggle('hidden', name !== tab);
    });
}

let outboundTab = 'queue';
function outboundShowTab(tab, load = true) {
    const asked = tab;
    tab = pageTabOn('outbound', tab);
    outboundTab = tab;
    routerSyncSubpage('outbound', tab, tab !== asked);
    showPageTab('outbound', tab);
    if (!load || currentTab !== 'outbound') return;
    if (tab === 'suppressions') loadSuppressionsTab();
    else if (!isFeatureDisabled('queue')) loadQueue();
}

function loadOutbound() {
    applyTabFeatures('outbound');
    const queueOn = !isFeatureDisabled('queue'), suppressionsOn = !isFeatureDisabled('suppressions');
    const queueSummary = document.getElementById('queue-summary');
    const suppressionSummary = document.getElementById('suppression-summary');
    if (queueSummary && !queueOn) queueSummary.textContent = '';
    if (suppressionSummary && !suppressionsOn) suppressionSummary.textContent = '';
    if (queueOn) loadQueue();
    outboundShowTab(outboundTab, false);
    if (outboundTab === 'suppressions') loadSuppressionsTab();
    else if (suppressionsOn) loadSuppressionStats();
}

async function loadQuarantineRules({ quiet = false } = {}) {
    const container = document.getElementById('quarantine-rules-list');
    if (!container) return;
    
    try {
        const res = await authenticatedFetch('/api/quarantine/rules', quiet ? { timeout: PAGE_REFRESH_TIMEOUT } : {});
        if (!res.ok) throw await responseError(res);
        const data = await res.json();
        _quarantineRulesCache = data;
        
        const countEl = document.getElementById('quarantine-rules-count');
        const activeCount = data.data.filter(r => r.enabled).length;
        if (countEl) countEl.textContent = uiCountLabel(data.data.length, 'rule', 'rules');
        const tabCount = document.getElementById('quarantine-tab-n-rules');
        if (tabCount) { tabCount.textContent = activeCount || ''; tabCount.classList.toggle('hidden', !activeCount); }
        
        if (!data.data || data.data.length === 0) {
            uiReplaceKeepingFocus(container, '<p class="ui-empty">No rules configured. Click "Add Rule" to create one.</p>');
            return;
        }
        
        uiReplaceKeepingFocus(container, `<div class="ui-table ui-stack ui-qr-table">${data.data.map(rule => {
            const matchLabels = { sender: 'Sender', sender_domain: 'Sender Domain', recipient: 'Recipient', subject: 'Subject' };
            const actionLabel = rule.action === 'delete' ? 'Delete' : 'Release';
            const repair = quarantineRuleRepair(rule);

            return `
            <div class="ui-tr${rule.enabled ? '' : ' ui-row-off'}" data-key="rule-${Number(rule.id)}">
                <div class="ui-td ui-q-who">
                    <div><b dir="auto">${escapeHtml(rule.name)}</b> ${uiTag(actionLabel, rule.action === 'delete' ? 'fail' : 'ok')}
                        ${rule.is_regex ? uiTag('Regex', 'info') : ''} ${!rule.enabled ? uiTag('Disabled', '') : ''} ${repair ? uiTag('Check', 'warn') : ''}</div>
                    <small>${escapeHtml(matchLabels[rule.match_type] || rule.match_type)}: <code class="ui-mono" dir="auto">${escapeHtml(rule.match_value)}</code></small>
                    ${repair ? '<small class="ui-text-warn">Looks for a backslash. An earlier version may have changed this rule when it was edited.</small>' : ''}
                    <small>Hits: ${escapeHtml(String(rule.hit_count))}${rule.last_hit_at ? ' · Last: ' + formatTime(rule.last_hit_at) : ''}${rule.notes ? ' · ' + escapeHtml(rule.notes) : ''}</small>
                </div>
                <span class="ui-td ui-td-end ui-row-actions">
                    ${repair ? `<button onclick="repairQuarantineRule(${Number(rule.id)})" title="${escapeHtml(`Look for "${repair.text}" instead`)}" class="ui-btn ui-btn-sm" data-acts="quarantine">Repair</button>` : ''}
                    <button onclick="toggleQuarantineRuleOnce(${Number(rule.id)}, this)" title="${rule.enabled ? 'Click to disable this rule' : 'Click to enable this rule'}"
                        class="ui-btn ui-btn-sm${rule.enabled ? ' ui-btn-on' : ''}" data-acts="quarantine">${rule.enabled ? 'Enabled' : 'Disabled'}</button>
                    <button onclick="showEditQuarantineRuleModal(${Number(rule.id)})" title="Edit" class="ui-btn ui-btn-sm" data-acts="quarantine">Edit</button>
                    <button onclick="deleteQuarantineRule(${Number(rule.id)}, '${escapeJsArg(rule.name)}')" title="Delete" class="ui-btn ui-btn-sm ui-btn-danger" data-acts="quarantine">Delete</button>
                </span>
            </div>`;
        }).join('')}</div>`);
    } catch (err) {
        console.error('Failed to load quarantine rules:', err);
        if (quiet && _quarantineRulesCache) return;
        uiReplaceKeepingFocus(container, `<p class="ui-empty ui-text-fail">Failed to load rules: ${escapeHtml(uiSentence(uiErrorText(err)))}${uiRetryButton('loadQuarantineRules()')}</p>`);
    }
}

function showAddQuarantineRuleModal() {
    _showQuarantineRuleModal(null, null);
}

function showEditQuarantineRuleModal(ruleId) {
    const rule = _quarantineRulesCache?.data?.find(r => r.id === ruleId);
    if (!rule) { showToast('Rule not found', 'error'); return; }
    _showQuarantineRuleModal(rule, null);
}

function showAddRuleFromQuarantine(sender, recipient, subject) {
    const senderDomain = sender.includes('@') ? sender.split('@').pop() : '';
    const prefill = { sender, recipient, subject, senderDomain };
    _showQuarantineRuleModal(null, prefill);
}

const QRULE_REGEX_SPECIAL = '.*+?^${}()|[]\\';
function quarantineRuleMatchMode(rule) {
    const value = rule.match_value || '';
    if (!rule.is_regex) return { mode: 'exact', value };
    let text = '';
    for (let i = 0; i < value.length; i++) {
        if (value[i] === '\\' && i + 1 < value.length && QRULE_REGEX_SPECIAL.includes(value[i + 1])) {
            text += value[++i];
        } else if (QRULE_REGEX_SPECIAL.includes(value[i])) {
            return { mode: 'regex', value };
        } else {
            text += value[i];
        }
    }
    return { mode: 'contains', value: text };
}

function quarantineRuleRepair(rule) {
    const ruleMode = quarantineRuleMatchMode(rule);
    if (ruleMode.mode !== 'contains' || !ruleMode.value.includes('\\')) return null;
    const once = quarantineRuleMatchMode({ is_regex: true, match_value: ruleMode.value });
    return once.mode === 'contains' ? { pattern: ruleMode.value, text: once.value } : null;
}

function _showQuarantineRuleModal(rule, prefill) {
    const isEdit = !!rule;
    const title = isEdit ? 'Edit Rule' : 'Add Quarantine Rule';
    const ruleMode = isEdit ? quarantineRuleMatchMode(rule) : { mode: 'exact', value: '' };

    const defaultName = isEdit ? escapeHtml(rule.name) : (prefill ? escapeHtml(`Rule for ${prefill.sender}`) : '');
    const defaultMatchType = isEdit ? rule.match_type : (prefill ? 'sender' : 'sender');
    const defaultMatchValue = isEdit ? escapeHtml(ruleMode.value) : (prefill ? escapeHtml(prefill.sender) : '');
    const defaultAction = isEdit ? rule.action : 'release';
    const defaultNotes = isEdit && rule.notes ? escapeHtml(rule.notes) : '';
    
    const prefillButtons = prefill ? `
        <div class="ui-qr-prefill">
            <span class="ui-label">Quick fill from email:</span>
            <div class="ui-chip-row">
                <button type="button" onclick="qrulePrefill('sender', '${escapeJsArg(prefill.sender)}')" class="ui-chip">Sender: ${escapeHtml(prefill.sender)}</button>
                ${prefill.senderDomain ? `<button type="button" onclick="qrulePrefill('sender_domain', '${escapeJsArg(prefill.senderDomain)}')" class="ui-chip">Domain: ${escapeHtml(prefill.senderDomain)}</button>` : ''}
                <button type="button" onclick="qrulePrefill('recipient', '${escapeJsArg(prefill.recipient)}')" class="ui-chip">Recipient: ${escapeHtml(prefill.recipient)}</button>
            </div>
        </div>
    ` : '';

    const body = `
                ${prefillButtons}
                <label><span class="ui-label">Rule Name <span class="ui-text-fail">*</span></span>
                    <input type="text" id="qrule-name" value="${defaultName}" class="ui-input" placeholder="e.g., Allow notifications from service X">
                </label>
                <div class="ui-qr-pair">
                    <label><span class="ui-label">Match Type</span>
                        <select id="qrule-match-type" class="ui-select">
                            <option value="sender" ${defaultMatchType === 'sender' ? 'selected' : ''}>Sender</option>
                            <option value="sender_domain" ${defaultMatchType === 'sender_domain' ? 'selected' : ''}>Sender Domain</option>
                            <option value="recipient" ${defaultMatchType === 'recipient' ? 'selected' : ''}>Recipient</option>
                            <option value="subject" ${defaultMatchType === 'subject' ? 'selected' : ''}>Subject</option>
                        </select>
                    </label>
                    <label><span class="ui-label">Action</span>
                        <select id="qrule-action" class="ui-select">
                            <option value="release" ${defaultAction === 'release' ? 'selected' : ''}>Release</option>
                            <option value="delete" ${defaultAction === 'delete' ? 'selected' : ''}>Delete</option>
                        </select>
                    </label>
                </div>
                <label><span class="ui-label">Match Value <span class="ui-text-fail">*</span></span>
                    <input type="text" id="qrule-match-value" value="${defaultMatchValue}" class="ui-input ui-mono" placeholder="e.g., noreply@example.com">
                </label>
                <label><span class="ui-label">Match Mode</span>
                    <select id="qrule-match-mode" onchange="updateQRuleMatchHelp()" class="ui-select">
                        <option value="exact" ${ruleMode.mode === 'exact' ? 'selected' : ''}>Exact Match - matches the full value exactly</option>
                        <option value="contains" ${ruleMode.mode === 'contains' ? 'selected' : ''}>Contains - matches if value appears anywhere</option>
                        <option value="regex" ${ruleMode.mode === 'regex' ? 'selected' : ''}>Regex (advanced) - custom regular expression</option>
                    </select>
                    <small id="qrule-match-help" class="ui-muted"></small>
                </label>
                <label><span class="ui-label">Notes (optional)</span>
                    <textarea id="qrule-notes" rows="2" class="ui-textarea" placeholder="Why this rule exists...">${defaultNotes}</textarea>
                </label>
                <div class="ui-alert ui-alert-warn ui-qr-note">
                    <div class="ui-alert-text"><p><b>Priority:</b> Delete rules always take priority over Release rules. If both match, the email will be deleted.</p></div>
                </div>`;

    uiDialog({
        id: 'quarantine-rule-modal-overlay', title, size: 'sm', close: closeQuarantineRuleModal, bodyClass: 'ui-form', body,
        foot: `<button onclick="closeQuarantineRuleModal()" class="ui-btn">Cancel</button>
            <button onclick="saveQuarantineRuleOnce(${isEdit ? Number(rule.id) : 'null'}, this)" class="ui-btn ui-btn-primary">${isEdit ? 'Save Changes' : 'Create Rule'}</button>`,
    });
    updateQRuleMatchHelp();
    uiGuardDialog(document.getElementById('quarantine-rule-modal-overlay'));
}

function qrulePrefill(matchType, value) {
    const typeEl = document.getElementById('qrule-match-type');
    const valueEl = document.getElementById('qrule-match-value');
    const nameEl = document.getElementById('qrule-name');
    if (typeEl) typeEl.value = matchType;
    if (valueEl) valueEl.value = value;
    if (nameEl && nameEl.value.startsWith('Rule for ')) {
        const labels = { sender: 'Sender', sender_domain: 'Domain', recipient: 'Recipient' };
        nameEl.value = `${labels[matchType] || matchType}: ${value}`;
    }
}

function updateQRuleMatchHelp() {
    const mode = document.getElementById('qrule-match-mode')?.value;
    const helpEl = document.getElementById('qrule-match-help');
    if (!helpEl) return;
    const hints = {
        exact: 'Example: noreply@example.com - will only match this exact address',
        contains: 'Example: example.com - will match any value containing "example.com"',
        regex: 'Example: ^.*@(spam|junk)\\.com$ - advanced pattern matching'
    };
    helpEl.textContent = hints[mode] || '';
}

function closeQuarantineRuleModal(saved = false) {
    const overlay = document.getElementById('quarantine-rule-modal-overlay');
    if (!overlay) return;
    if (saved) {
        uiDialogSaved(overlay);
        overlay.remove();
    } else uiCloseGuarded(overlay, () => overlay.remove());
}

function saveQuarantineRuleOnce(ruleId, button) {
    return uiOnce(button || 'quarantine-rule', () => saveQuarantineRule(ruleId), button, ruleId === null ? 'Creating...' : 'Saving...');
}
async function saveQuarantineRule(ruleId) {
    const name = document.getElementById('qrule-name')?.value?.trim();
    const matchType = document.getElementById('qrule-match-type')?.value;
    let matchValue = document.getElementById('qrule-match-value')?.value?.trim();
    const matchMode = document.getElementById('qrule-match-mode')?.value || 'exact';
    const action = document.getElementById('qrule-action')?.value;
    const notes = document.getElementById('qrule-notes')?.value?.trim() || null;
    
    if (!name) { uiFieldProblem(document.getElementById('qrule-name'), 'Enter a name for the rule.'); return; }
    if (!matchValue) { uiFieldProblem(document.getElementById('qrule-match-value'), 'Enter the value to match.'); return; }
    
    let isRegex = false;
    if (matchMode === 'contains') {
        const escaped = matchValue.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        matchValue = escaped;
        isRegex = true;
    } else if (matchMode === 'regex') {
        isRegex = true;
    }
    
    const body = { name, match_type: matchType, match_value: matchValue, is_regex: isRegex, action, notes };
    await _submitQuarantineRule(ruleId, body);
}

async function _submitQuarantineRule(ruleId, body, doneMessage) {
    if (!uiMayAct('quarantine')) return;
    try {
        const isEdit = ruleId !== null;
        const url = isEdit ? `/api/quarantine/rules/${ruleId}` : '/api/quarantine/rules';
        const method = isEdit ? 'PUT' : 'POST';
        
        const res = await authenticatedFetch(url, {
            method,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        
        if (!res.ok) throw await responseError(res);
        
        closeQuarantineRuleModal(true);
        showToast(doneMessage || (isEdit ? 'Rule updated' : 'Rule created'), 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to save rule: ' + uiErrorText(err), 'error');
    }
}

async function repairQuarantineRule(ruleId) {
    const rule = _quarantineRulesCache?.data?.find(r => r.id === ruleId);
    const repair = rule && quarantineRuleRepair(rule);
    if (!repair) { showToast('Rule not found', 'error'); return; }
    await _submitQuarantineRule(ruleId, {
        name: rule.name, match_type: rule.match_type, match_value: repair.pattern,
        is_regex: true, action: rule.action, notes: rule.notes || null,
    }, 'Rule repaired');
}

async function deleteQuarantineRule(ruleId, ruleName) {
    if (!uiMayAct('quarantine')) return;
    if (!await showConfirmModal({ title: 'Delete rule', message: `Delete rule "${ruleName}"? This cannot be undone.`, confirmText: 'Delete', isDangerous: true })) return;
    
    try {
        const res = await authenticatedFetch(`/api/quarantine/rules/${ruleId}`, { method: 'DELETE' });
        if (!res.ok) throw await responseError(res);
        
        showToast('Rule deleted', 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to delete rule: ' + uiErrorText(err), 'error');
    }
}

function toggleQuarantineRuleOnce(ruleId, button) {
    return uiOnce(`quarantine-rule-toggle:${ruleId}`, () => toggleQuarantineRule(ruleId), button);
}
async function toggleQuarantineRule(ruleId) {
    if (!uiMayAct('quarantine')) return;
    try {
        const res = await authenticatedFetch(`/api/quarantine/rules/${ruleId}/toggle`, { method: 'POST' });
        if (!res.ok) throw await responseError(res);
        
        const rule = await res.json();
        showToast(`Rule ${rule.enabled ? 'enabled' : 'disabled'}`, 'success');
        await loadQuarantineRules();
    } catch (err) {
        showToast('Failed to toggle rule: ' + uiErrorText(err), 'error');
    }
}

function testQuarantineRulesOnce(button) {
    return uiOnce('quarantine-rules-test', testQuarantineRules, button, 'Testing...');
}
async function testQuarantineRules() {
    const opener = layerLastAction || document.activeElement;
    try {
        showToast('Testing rules against quarantine...', 'info');
        const res = await authenticatedFetch('/api/quarantine/rules/test', { method: 'POST' });
        if (!res.ok) throw await responseError(res);
        
        const data = await res.json();
        
        if (data.total_matches === 0) {
            showToast(`No matches found (${data.total_quarantine} quarantine items checked)`, 'info');
            return;
        }
        
        const byRule = {};
        for (const m of data.matches) {
            const key = m.rule_id;
            if (!byRule[key]) {
                byRule[key] = { rule_name: m.rule_name, action: m.action, rule_enabled: m.rule_enabled, items: [] };
            }
            byRule[key].items.push(m);
        }
        
        const groupsHtml = Object.values(byRule).map(group => {
            const tone = group.action === 'delete' ? 'fail' : 'ok';
            const itemsHtml = group.items.map(m => `
                <div class="ui-qt-item${group.rule_enabled ? ` ui-qt-${tone}` : ''}">
                    <div>${uiEntity('address', m.sender || '?', { plain: true })} → ${uiEntity('address', m.recipient || '?', { plain: true })}</div>
                    <small class="ui-muted" dir="auto" title="${escapeHtml(m.subject || '')}">${escapeHtml((m.subject || 'No subject').substring(0, 80))}</small>
                </div>
            `).join('');

            return `
            <div class="ui-qt-group${!group.rule_enabled ? ' ui-row-off' : ''}">
                <div class="ui-list-head">
                    <b dir="auto">${escapeHtml(group.rule_name)}</b> ${uiTag(group.action, tone)}
                    ${!group.rule_enabled ? uiTag('Disabled - will not execute', '') : ''}
                    <span class="ui-muted ui-head-actions">${group.items.length} match${group.items.length !== 1 ? 'es' : ''}</span>
                </div>
                <div class="ui-qt-items">${itemsHtml}</div>
            </div>`;
        }).join('');

        const disabledCount = data.matches.filter(m => !m.rule_enabled).length;
        const activeCount = data.matches.length - disabledCount;
        const noMatches = data.total_matches === 0;

        document.getElementById('qrule-test-modal')?.remove();
        uiLayerOpener(opener);
        const closeTest = () => document.getElementById('qrule-test-modal')?.remove();
        uiDialog({
            id: 'qrule-test-modal', title: 'Test Results', size: 'sm', close: closeTest, backdropClose: closeTest, bodyClass: 'ui-form',
            body: `
                    <div class="ui-kpis">
                        <div class="ui-kpi"><b>${escapeHtml(String(data.total_matches))}</b>matched</div>
                        <div class="ui-kpi"><b class="ui-muted">${escapeHtml(String(data.total_quarantine))}</b>total</div>
                    </div>
                    ${disabledCount > 0 ? `<p class="ui-text-warn">${disabledCount} from disabled rules</p>` : ''}
                    ${noMatches ? '<p class="ui-empty">No quarantine items matched any rules.</p>' : groupsHtml}
                    <p class="ui-kv-note ui-list-foot">This is a dry-run preview. No actions were taken.</p>`,
        });
    } catch (err) {
        showToast('Test failed: ' + uiErrorText(err), 'error');
    }
}

function toggleQuarantineRuleHistory() {
    const section = document.getElementById('quarantine-rules-history');
    if (!section) return;
    
    if (section.classList.contains('hidden')) {
        section.classList.remove('hidden');
        loadQuarantineRuleHistory();
    } else {
        section.classList.add('hidden');
    }
}

async function loadQuarantineRuleHistory({ quiet = false } = {}) {
    const container = document.getElementById('quarantine-rules-history-list');
    if (!container) return;
    
    if (!quiet) uiReplaceKeepingFocus(container, '<p class="ui-empty">Loading...</p>');

    try {
        const res = await authenticatedFetch('/api/quarantine/rules/logs?limit=20', quiet ? { timeout: PAGE_REFRESH_TIMEOUT } : {});
        if (!res.ok) throw await responseError(res);
        const data = await res.json();

        if (!data.data || data.data.length === 0) {
            uiReplaceKeepingFocus(container, '<p class="ui-empty">No actions recorded yet</p>');
            return;
        }

        uiReplaceKeepingFocus(container, `<div class="ui-qt-history">${data.data.map(log => `
            <div class="ui-qt-hrow">
                ${uiTag(log.action, log.action === 'delete' ? 'fail' : 'ok')}
                <span class="ui-q-who" title="${escapeHtml(log.sender || '')} → ${escapeHtml(log.recipient || '')}">${uiEntity('address', log.sender || '?', { plain: true })} → ${uiEntity('address', log.recipient || '?', { plain: true })}</span>
                ${uiTime(log.created_at, formatTime(log.created_at), { title: `Rule: ${log.rule_name || ''}`, cls: 'ui-muted' })}
            </div>
        `).join('')}</div>`);
    } catch (err) {
        if (quiet) return;
        uiReplaceKeepingFocus(container, `<p class="ui-empty ui-text-fail">Failed: ${escapeHtml(uiErrorText(err))}</p>`);
    }
}

function applyMessagesFilters() {
    readMessagesFilters();
    loadMessages();
}

function readMessagesFilters() {
    currentFilters.messages = messagesWithExact({
        search: document.getElementById('messages-filter-search').value,
        sender: document.getElementById('messages-filter-sender').value,
        recipient: document.getElementById('messages-filter-recipient').value,
        direction: document.getElementById('messages-filter-direction').value,
        user: document.getElementById('messages-filter-user').value,
        status: document.getElementById('messages-filter-status').value,
        ip: document.getElementById('messages-filter-ip').value,
        date_range: document.getElementById('messages-date-range').value,
        start_date: document.getElementById('messages-start-date').value,
        end_date: document.getElementById('messages-end-date').value
    });
    if (messagesNoId) {
        const kept = currentFilters.messages;
        currentFilters.messages = Object.fromEntries(['search', 'date_range', 'start_date', 'end_date']
            .filter(key => kept[key]).map(key => [key, kept[key]]));
    }
    currentPage.messages = 1;
}

function toggleMessagesFilters(open) {
    const panel = document.getElementById('messages-more-filters');
    const btn = document.getElementById('messages-filters-btn');
    if (!panel) return;
    const show = typeof open === 'boolean' ? open : panel.classList.contains('hidden');
    panel.classList.toggle('hidden', !show);
    if (btn) btn.setAttribute('aria-expanded', show);
    if (show) { const first = panel.querySelector('input'); if (first) first.focus(); }
}

const MESSAGES_MORE_FILTERS = ['sender', 'recipient', 'user', 'ip', 'address', 'domain'];
function messagesFiltersOn(f = currentFilters.messages || {}) {
    return !!(MESSAGES_MORE_FILTERS.some(k => f[k]) || f.search || f.status || f.direction || f.start_date || f.end_date || f.date_range);
}

function updateMessagesFilterState() {
    const f = currentFilters.messages || {};
    const advanced = MESSAGES_MORE_FILTERS.filter(k => f[k]).length;
    const any = messagesFiltersOn(f);
    const badge = document.getElementById('messages-filters-n');
    if (badge) { badge.textContent = advanced || ''; badge.classList.toggle('hidden', !advanced); }
    const button = document.getElementById('messages-filters-btn');
    if (button) button.setAttribute('aria-label', advanced ? `Filters, ${advanced} in use` : 'Filters');
    const clear = document.getElementById('messages-clear-filters');
    if (clear) clear.classList.toggle('hidden', !any);
    const chips = document.getElementById('messages-exact');
    if (chips) {
        const parts = messagesExact ? messagesExactParts(messagesExact) : [];
        chips.innerHTML = parts.length ? `<span class="ui-sec-filter" title="Matched whole, not as a part of a longer value"><span>${parts.map(([label, value]) =>
            `${escapeHtml(label)} <bdi>${escapeHtml(value)}</bdi>`).join(', ')}</span><button type="button" onclick="clearMessagesExact()" aria-label="Remove this filter" title="Remove this filter">&times;</button></span>` : '';
    }
}

function clearMessagesFilters() {
    document.getElementById('messages-filter-search').value = '';
    document.getElementById('messages-filter-sender').value = '';
    document.getElementById('messages-filter-recipient').value = '';
    document.getElementById('messages-filter-direction').value = '';
    document.getElementById('messages-filter-user').value = '';
    document.getElementById('messages-filter-status').value = '';
    document.getElementById('messages-filter-ip').value = '';
    document.getElementById('messages-date-range').value = '';
    document.getElementById('messages-start-date').value = '';
    document.getElementById('messages-end-date').value = '';
    document.getElementById('messages-date-range-start').value = '';
    document.getElementById('messages-date-range-end').value = '';
    document.getElementById('messages-date-range-label').textContent = 'All Time';
    setMessagesDatePresetActive('');
    setMessagesFilters({});
    currentPage.messages = 1;
    loadMessages();
}

function setMessagesDatePresetActive(preset) {
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        btn.setAttribute('aria-pressed', String(preset !== null && btn.getAttribute('data-preset') === preset));
    });
}

const MESSAGES_PICKERS = ['status', 'direction', 'time'];

function toggleMessagesPicker(kind, open) {
    if (kind && open !== false) {
        uiPickerOpen(`messages-${kind}`);
        return;
    }
    MESSAGES_PICKERS.forEach(k => {
        if (uiPickerIsOpen(`messages-${k}`)) uiPickerClose(`messages-${k}`, { returnFocus: true });
    });
}

function messagesTimePanelOpened() {
    document.getElementById('messages-time-start').value = document.getElementById('messages-date-range-start').value;
    document.getElementById('messages-time-end').value = document.getElementById('messages-date-range-end').value;
}

function toggleMessagesTimePanel(open) {
    toggleMessagesPicker('time', open);
}

function applyMessagesTimePanelRange() {
    document.getElementById('messages-date-range-start').value = document.getElementById('messages-time-start').value;
    document.getElementById('messages-date-range-end').value = document.getElementById('messages-time-end').value;
    applyMessagesCustomDateRange();
}

function toggleMessagesDateRangePicker() {
    const dropdown = document.getElementById('messages-date-range-dropdown');
    const arrow = document.getElementById('messages-date-range-arrow');
    const isHidden = dropdown.classList.contains('hidden');
    dropdown.classList.toggle('hidden');
    arrow.style.transform = isHidden ? 'rotate(180deg)' : '';
}

function messagesPresetStart(preset, now = new Date()) {
    if (preset === 'today') return zonedDayStart(zonedDateString(now)).toISOString();
    const days = { '7days': 7, '30days': 30, '90days': 90 }[preset];
    if (!days) return '';
    return new Date(new Date(now).getTime() - days * 86400000).toISOString();
}

const MESSAGES_ROLLING_PRESETS = ['today', '7days', '30days', '90days'];
function messagesRangeFilters(filters, now = new Date()) {
    if (!MESSAGES_ROLLING_PRESETS.includes(filters.date_range)) return filters;
    return { ...filters, start_date: messagesPresetStart(filters.date_range, now), end_date: '' };
}

function messagesShowDatePreset(preset, now = new Date()) {
    const labels = { '': 'All Time', 'today': 'Today', '7days': 'Last 7 Days', '30days': 'Last 30 Days', '90days': 'Last 90 Days' };
    document.getElementById('messages-date-range-label').textContent = labels[preset] || 'All Time';
    document.getElementById('messages-date-range').value = preset;

    const startDate = messagesPresetStart(preset, now);
    document.getElementById('messages-start-date').value = startDate;
    document.getElementById('messages-end-date').value = startDate ? new Date(now).toISOString() : '';

    setMessagesDatePresetActive(preset);
}

function selectMessagesDatePreset(preset, now = new Date()) {
    messagesShowDatePreset(preset, now);

    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
    toggleMessagesTimePanel(false);
    applyMessagesFilters();
}

function applyMessagesCustomDateRange() {
    const startInput = document.getElementById('messages-date-range-start').value;
    const endInput = document.getElementById('messages-date-range-end').value;

    if (!startInput || !endInput) {
        showToast('Please select both start and end dates', 'warning');
        return;
    }

    const startDate = zonedDayStart(startInput);
    const endDate = new Date(zonedDayStart(addDaysToDateString(endInput, 1)).getTime() - 1);

    if (startDate > endDate) {
        showToast('Start date must be before end date', 'warning');
        return;
    }

    document.getElementById('messages-date-range').value = 'custom';
    document.getElementById('messages-start-date').value = startDate.toISOString();
    document.getElementById('messages-end-date').value = endDate.toISOString();

    const fmt = day => formatDayKey(day);
    document.getElementById('messages-date-range-label').textContent = `${fmt(startInput)} - ${fmt(endInput)}`;

    setMessagesDatePresetActive(null);

    document.getElementById('messages-date-range-dropdown').classList.add('hidden');
    document.getElementById('messages-date-range-arrow').style.transform = '';
    toggleMessagesTimePanel(false);
    applyMessagesFilters();
}

document.addEventListener('click', function(e) {
    const container = document.getElementById('messages-date-range-picker-container');
    if (container && !container.contains(e.target)) {
        const dropdown = document.getElementById('messages-date-range-dropdown');
        const arrow = document.getElementById('messages-date-range-arrow');
        if (dropdown && !dropdown.classList.contains('hidden')) {
            dropdown.classList.add('hidden');
            if (arrow) arrow.style.transform = '';
        }
    }
});

const MESSAGE_STATUS_FACETS = [['', 'All messages'], ['delivered', 'Delivered'], ['deferred', 'Deferred'], ['bounced', 'Bounced'],
    ['rejected', 'Rejected'], ['spam', 'Spam'], ['discarded', 'Discarded (Sieve)']];
const MESSAGE_DIRECTION_FACETS = [['', 'Any direction'], ['inbound', 'Inbound'], ['outbound', 'Outbound'], ['internal', 'Internal']];

function messagesFilterParams(filters) {
    filters = messagesRangeFilters(filters);
    const params = new URLSearchParams();
    for (const key of MESSAGES_FILTER_KEYS) {
        if (filters[key]) params.append(key, filters[key]);
    }
    return params;
}

function setMessagesFacet(kind, value) {
    const select = document.getElementById(kind === 'status' ? 'messages-filter-status' : 'messages-filter-direction');
    if (select) select.value = value;
    toggleMessagesPicker(null, false);
    applyMessagesFilters();
}

function renderFacetList(kind, entries, counts, current, asOptions = false) {
    return entries.map(([value, label]) => {
        const count = counts ? counts[value || 'all'] : undefined;
        const tone = kind === 'status' && value ? (UI_STATUS_TONE[value] || '') : '';
        const state = asOptions ? `role="option" tabindex="-1" aria-selected="${String(current === value)}"` : `aria-pressed="${String(current === value)}"`;
        return `<button type="button" class="ui-fct" ${state} onclick="setMessagesFacet('${kind}', '${value}')">
            ${kind === 'status' && value ? `<i class="ui-fct-dot${tone ? ` ui-fct-${tone}` : ''}"></i>` : ''}${kind === 'direction' && value ? `<i class="ui-fct-dot ui-dir-${value}"></i>` : ''}<span>${escapeHtml(label)}</span>
            <small>${count === undefined ? '' : escapeHtml(String(count))}</small></button>`;
    }).join('');
}

async function loadMessageFacets(filters, gen = messagesGen) {
    const statusList = document.getElementById('messages-facet-status');
    const directionList = document.getElementById('messages-facet-direction');
    let data = null;
    try {
        const params = messagesFilterParams(filters);
        for (const preset of ['today', '7days', '30days', '90days']) params.append('since', `${preset}:${messagesPresetStart(preset)}`);
        const response = await messagesFetch(`/api/messages/facets?${params}`);
        if (response.ok) data = await response.json();
    } catch (e) {
        if (e.name !== 'AbortError') console.warn('Failed to load message facets:', e);
    }
    if (gen !== messagesGen) return;
    const status = filters.status || '';
    const direction = filters.direction || '';
    if (statusList) statusList.innerHTML = renderFacetList('status', MESSAGE_STATUS_FACETS, data && data.status, status);
    if (directionList) directionList.innerHTML = renderFacetList('direction', MESSAGE_DIRECTION_FACETS, data && data.direction, direction);
    document.querySelectorAll('.messages-date-preset-btn').forEach(btn => {
        const count = data && data.time ? data.time[btn.dataset.preset || 'all'] : undefined;
        let small = btn.querySelector('small');
        if (!small) { small = document.createElement('small'); btn.appendChild(small); }
        small.textContent = count === undefined ? '' : String(count);
    });
    const pick = (kind, entries, counts, current, anyLabel) => {
        const options = document.getElementById(`messages-${kind}-options`);
        if (options) options.innerHTML = renderFacetList(kind, entries, counts, current, true);
        const button = document.getElementById(`messages-${kind}-pick`);
        const valueLabel = document.getElementById(`messages-${kind}-value`);
        const chosen = entries.find(([value]) => value === current);
        if (valueLabel) valueLabel.textContent = current && chosen ? chosen[1] : anyLabel;
        if (button) button.classList.toggle('is-set', !!current);
    };
    pick('status', MESSAGE_STATUS_FACETS, data && data.status, status, 'All');
    pick('direction', MESSAGE_DIRECTION_FACETS, data && data.direction, direction, 'Any');
    uiPickerRefocus();
    const timeButton = document.getElementById('messages-time-pick');
    if (timeButton) timeButton.classList.toggle('is-set', !!(filters.start_date || filters.end_date));
}

async function messagesNoIdFacets(filters, gen = messagesGen) {
    const presets = document.querySelectorAll('.messages-date-preset-btn');
    const show = time => presets.forEach(btn => {
        const count = time ? time[btn.dataset.preset || 'all'] : undefined;
        let small = btn.querySelector('small');
        if (!small) { small = document.createElement('small'); btn.appendChild(small); }
        small.textContent = count === undefined ? '' : String(count);
    });
    show(null);
    const timeButton = document.getElementById('messages-time-pick');
    if (timeButton) timeButton.classList.toggle('is-set', !!(filters.start_date || filters.end_date));
    const params = new URLSearchParams({ limit: 1 });
    if (filters.search) params.append('search', filters.search);
    for (const preset of ['today', '7days', '30days', '90days']) params.append('since', `${preset}:${messagesPresetStart(preset)}`);
    try {
        const response = await messagesFetch(`/api/messages/without-message-id?${params}`);
        const data = response.ok ? await response.json() : null;
        if (gen === messagesGen && messagesNoId && data) show(data.time);
    } catch (error) {
        if (error.name !== 'AbortError') console.warn('Failed to count messages without a Message-ID by time:', error);
    }
}

function afterMessagesRendered(data) {
    if (typeof markSelectedMessageRow === 'function' && window.openMessageKey) markSelectedMessageRow(window.openMessageKey);
    const modal = document.getElementById('message-modal');
    const slot = typeof messageReaderSlot === 'function' ? messageReaderSlot() : null;
    if (slot && modal && modal.classList.contains('hidden') && data.data && data.data.length) {
        viewMessageDetails(data.data[0].correlation_key);
    }
}

async function loadMessages({ quiet = false, rows = 50, toEnd = false, applyIf = null } = {}) {
    const container = document.getElementById('messages-logs');
    renderMessagesSort();
    const gen = messagesNewGeneration();
    messagesFullLoad = true;
    if (!quiet) container.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
    const filters = currentFilters.messages || {};
    if (messagesNoId) messagesNoIdFacets(filters, gen);
    else loadMessageFacets(filters, gen);
    updateMessagesFilterState();
    renderMessagesNoId();
    if (!quiet) container.scrollTop = 0;
    try {
        const timeout = quiet ? PAGE_REFRESH_TIMEOUT : 0;
        const response = await messagesFetch(messagesListUrl(messagesQueryParams(null, Math.min(500, rows))), timeout);
        if (!response.ok) {
            throw await responseError(response);
        }
        const data = await response.json();
        while (data.next_cursor && (data.data || []).length < rows && gen === messagesGen) {
            const next = await messagesFetch(messagesListUrl(messagesQueryParams(data.next_cursor, Math.min(500, rows - data.data.length), data.watermark)), timeout);
            if (!next.ok) throw await responseError(next);
            const page = await next.json();
            data.data = data.data.concat(page.data || []);
            data.next_cursor = page.next_cursor;
            data.total = page.total ?? data.total;
        }
        if (gen !== messagesGen) return;
        if (applyIf && !applyIf()) {
            renderMessagesNew();
            return;
        }
        if (quiet && messagesSameAsShown(data) && (data.data || []).length === (lastDataCache.messages.data || []).length) {
            if (data.watermark != null) messagesNew.watermark = data.watermark;
            messagesNew.count = 0;
            renderMessagesNew();
            return;
        }
        if (quiet) uiKeepFocus(container, 'data-key', () => showMessagesFirstPage(container, data));
        else showMessagesFirstPage(container, data);
        afterMessagesRendered(data);
        refreshMessagesNoId();
        if (toEnd) messagesScrollToEnd(container);
    } catch (error) {
        if (gen !== messagesGen) return;
        if (quiet) return;
        console.error('Failed to load messages:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Failed to load messages: ${escapeHtml(uiSentence(uiErrorText(error)))} <button type="button" class="ui-link-row ui-link" onclick="loadMessages()">Try again</button></p>`;
        setMessagesCount(null);
        messagesPaging.page = 1;
        messagesPaging.cursor = null;
        messagesPaging.total = 0;
        currentPage.messages = 1;
        lastDataCache.messages = null;
    } finally {
        if (gen === messagesGen) messagesFullLoad = false;
    }
}

const statusState = { containers: null, blocklists: null, jobs: null };
let statusTab = 'server';

function openStatusTab(tab) {
    statusShowTab(tab);
    navigateTo('status');
}

function summarizeJobs(jobs) {
    const all = statusJobCategories(jobs || {}).flatMap(cat => cat.jobs.filter(j => j[2]));
    const isOff = job => job.feature_disabled === true || job.status === 'disabled' || job.enabled === false;
    const failed = all.filter(([, , job]) => !isOff(job) && job.status === 'failed');
    const off = all.filter(([, , job]) => isOff(job)).length;
    return { all, isOff, failed, off, healthy: all.length - failed.length - off, running: all.length - off };
}
let statusCtrFilter = 'all';
let statusJobFilterValue = 'all';

function statusShowTab(tab) {
    statusTab = tab;
    routerSyncSubpage('status', tab);
    document.querySelectorAll('.ui-st-tabs .modal-tab').forEach(btn => {
        const on = btn.id === `status-tab-btn-${tab}`;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', on);
    });
    document.querySelectorAll('.ui-st-panel').forEach(panel => panel.classList.toggle('hidden', panel.id !== `status-tab-${tab}`));
}

function setStatusTabCount(tab, count, isFail) {
    const el = document.getElementById(`status-tab-n-${tab}`);
    if (!el) return;
    el.textContent = count;
    el.classList.toggle('hidden', !count);
    el.classList.toggle('is-fail', !!isFail);
}

function statusContainerFilter(filter) {
    statusCtrFilter = filter;
    document.querySelectorAll('[data-ctr-filter]').forEach(b => b.setAttribute('aria-pressed', b.dataset.ctrFilter === filter));
    document.querySelectorAll('#status-containers .ui-ctr').forEach(row => {
        row.hidden = filter === 'problems' && !row.classList.contains('is-down');
    });
}

function statusJobFilter(filter) {
    statusJobFilterValue = filter;
    document.querySelectorAll('[data-job-filter]').forEach(b => b.setAttribute('aria-pressed', b.dataset.jobFilter === filter));
    document.querySelectorAll('#status-jobs .ui-jg').forEach(group => {
        let shown = 0;
        group.querySelectorAll('.ui-jobrow').forEach(row => {
            const show = filter === 'all' || (filter === 'problems' && row.classList.contains('is-failed'))
                || (filter === 'off' && row.classList.contains('is-off'));
            row.hidden = !show;
            if (show) shown++;
        });
        group.hidden = shown === 0;
        group.open = filter === 'all' ? (group.hasAttribute('data-failed') || statusJobsOpen.has(group.dataset.group)) : shown > 0;
    });
}

function blocklistLookupLink(r, label) {
    if (!/^https:\/\//.test(r.info_url || '')) return '';
    return `<a href="${escapeHtml(r.info_url)}" target="_blank" rel="noopener noreferrer" class="ui-btn ui-btn-sm" title="Look up on ${escapeHtml(r.name)}">${label}</a>`;
}

function renderStatusAttention() {
    const box = document.getElementById('status-attention');
    const count = document.getElementById('status-attention-count');
    if (!box) return;
    const items = [];
    for (const c of statusState.containers || []) {
        if (c.ignored || c.running) continue;
        items.push({ tone: 'fail', title: `${c.name} is stopped`, detail: `State: ${c.state}. It is not running, so what it does is off until it starts again.`,
            actions: `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${escapeJsArg(c.container)}', true)" title="Stop counting and alerting on ${escapeHtml(c.name)}" data-acts="status">Ignore</button>` });
    }
    const blOff = (window.disabledFeatures || []).includes('blacklist');
    for (const host of blOff ? [] : (statusState.blocklists || [])) {
        for (const r of (host.results || []).filter(x => x.listed && !x.ignored)) {
            items.push({ tone: 'fail', title: `${host.hostname} is on ${r.name}`,
                detail: `${host.source || 'system'}, listed on ${host.listed_count || 1} of ${host.total_blacklists || '?'} lists. Mail to some providers may bounce.`,
                actions: `${blocklistLookupLink(r, 'Look up')}<button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', true)" title="Keep checking ${escapeHtml(r.name)} but never count or alert on it" data-acts="status">Ignore this list</button>` });
        }
    }
    for (const job of statusState.jobs || []) {
        if (!job.failed) continue;
        items.push({ tone: 'warn', title: `${job.name} failed`, detail: job.error || 'The last run did not finish.',
            actions: `<button type="button" class="ui-btn ui-btn-sm" onclick="triggerBackgroundJob('${escapeJsArg(job.key)}', this, '${escapeJsArg(job.name)}')" data-acts="admin">Run now</button>` });
    }
    const loaded = statusState.containers && statusState.jobs;
    if (count) count.textContent = items.length ? String(items.length) : '';
    if (!items.length) {
        box.innerHTML = loaded ? '<p class="ui-st-allgood">Everything is running. Nothing needs you right now.</p>'
            : '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
        return;
    }
    box.innerHTML = items.map(item => `
        <div class="ui-alert ui-alert-${item.tone}">
            <div class="ui-alert-text"><div class="ui-alert-title"><b>${escapeHtml(item.title)}</b></div><p>${escapeHtml(item.detail)}</p></div>
            <div class="ui-st-acts">${item.actions}</div>
        </div>`).join('');
}

let statusQuiet = false;
function statusFailed(el, html) {
    if (el && (!statusQuiet || el.querySelector('.ui-loading'))) el.innerHTML = html;
}
function statusHold(container) {
    if (!statusQuiet || !container) return false;
    const active = document.activeElement;
    return uiTextHeld(container) || Boolean(active && container.contains(active) && active.matches(':focus-visible'));
}

async function loadStatus() {
    try {
        await Promise.all([
            loadStatusContainers(),
            loadStatusSystem(),
            loadStatusStorage(),
            loadStatusExtended(),
            loadStatusAppVersion()
        ]);
        const lastChecked = document.getElementById('status-last-checked');
        uiAgo(lastChecked, new Date().toISOString(), 'Updated ');
        renderStatusAttention();
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

function setStatusKpi(id, value, tone) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value;
    el.className = tone ? `ui-${tone}` : '';
}

async function loadStatusAppVersion() {
    const note = document.getElementById('status-kpi-version-note');
    try {
        const res = await authenticatedFetch('/api/status/app-version');
        if (!res.ok) throw await responseError(res);
        const data = await res.json();
        setStatusKpi('status-kpi-version', data.current_version || '-');
        if (note) {
            note.innerHTML = data.update_available
                ? `<button data-acts="admin" type="button" class="ui-link-row ui-text-info" onclick="navigateTo('settings')">Update ${escapeHtml(data.latest_version)} available</button>`
                : 'Up to date';
        }
    } catch (error) {
        setStatusKpi('status-kpi-version', '-');
        if (note) note.textContent = 'Version';
    }
}

async function setContainerIgnored(container, ignored) {
    if (!uiMayAct('status')) return;
    try {
        const res = await authenticatedFetch(`/api/status/containers/${encodeURIComponent(container)}/ignore`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ignored })
        });
        if (!res.ok) throw await responseError(res);
        showToast(ignored ? `${container.replace('-mailcow', '')} is ignored. It no longer counts or alerts.` : `${container.replace('-mailcow', '')} counts again.`, 'success');
        loadStatusContainers();
        loadNavCounters();
    } catch (e) {
        showToast(`Could not change the container: ${uiErrorText(e)}`, 'error');
    }
}

async function loadStatusContainers() {
    try {
        const response = await authenticatedFetch('/api/status/containers');
        if (!response.ok) throw await responseError(response);
        const data = await response.json();

        const container = document.getElementById('status-containers');

        const containersList = Object.entries(data.containers).map(([key, value]) => ({
            name: (value.name || key).replace('-mailcow', ''),
            container: key,
            state: value.state || 'unknown',
            started_at: value.started_at || null,
            ignored: !!value.ignored
        }));

        const note = document.getElementById('status-containers-note');
        if (containersList.length > 0) {
            const isRunning = c => (c.state || 'unknown').toString().toLowerCase().trim() === 'running';
            const counted = containersList.filter(c => !c.ignored);
            const running = counted.filter(isRunning).length;
            const stopped = counted.length - running;
            const ignoredCount = containersList.length - counted.length;
            setStatusKpi('status-kpi-containers', `${running} of ${counted.length} running`, stopped > 0 ? 'fail' : '');
            const summaryText = [stopped ? `${stopped} stopped` : 'All running', ignoredCount ? `${ignoredCount} ignored` : ''].filter(Boolean).join(', ');
            if (note) note.textContent = summaryText;
            const summary = document.getElementById('status-containers-summary');
            if (summary) summary.textContent = summaryText;
            setStatusTabCount('server', stopped, true);
            statusState.containers = containersList.map(c => ({ ...c, running: isRunning(c) }));

            const rank = c => c.ignored ? 2 : (isRunning(c) ? 1 : 0);
            const ordered = [...containersList].sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));
            if (!statusHold(container)) container.innerHTML = `<div class="ui-ctrs">${ordered.map(c => {
                const up = isRunning(c);
                const since = c.started_at ? formatAgo(c.started_at).replace(' ago', '') : '';
                const arg = escapeJsArg(c.container);
                const action = c.ignored
                    ? `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${arg}', false)" data-acts="status">Stop ignoring</button>`
                    : (up ? '' : `<button type="button" class="ui-btn ui-btn-sm" onclick="setContainerIgnored('${arg}', true)" title="Stop counting and alerting on ${escapeHtml(c.name)}" data-acts="status">Ignore</button>`);
                const state = c.ignored ? 'ignored' : (up ? (since ? `up ${since}` : 'running') : String(c.state || 'unknown'));
                return `
                <div class="ui-ctr${c.ignored ? ' is-ignored' : (up ? '' : ' is-down')}" title="${escapeHtml(c.ignored ? 'Ignored: shown here but never counted or alerted' : (c.started_at ? `Started ${formatTime(c.started_at)}` : 'Start time unknown'))}">
                    <i class="ui-mdot${c.ignored ? '' : (up ? ' ui-mdot-ok' : ' ui-mdot-fail')}"></i>
                    <b>${escapeHtml(c.name)}</b>
                    <small>${escapeHtml(state)}</small>${action ? `<span class="ui-ctr-act">${action}</span>` : ''}
                </div>`;
            }).join('')}</div>`;
            statusContainerFilter(statusCtrFilter);
            renderStatusAttention();
        } else {
            setStatusKpi('status-kpi-containers', '-');
            if (note) note.textContent = '';
            if (!statusHold(container)) container.innerHTML = '<p class="ui-empty ui-panel">No container information available</p>';
        }
    } catch (error) {
        console.error('Failed to load containers status:', error);
        setStatusKpi('status-kpi-containers', '-');
        statusFailed(document.getElementById('status-containers'), `<p class="ui-empty ui-panel ui-text-fail">Failed to load containers: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusContainers()')}</p>`);
    }
}

async function loadStatusSystem() {
    const container = document.getElementById('status-system');

    try {
        console.log('Loading System Info...');

        const [infoResponse, versionResponse] = await Promise.all([
            authenticatedFetch('/api/status/mailcow-info'),
            authenticatedFetch('/api/status/version')
        ]);

        if (!infoResponse.ok) {
            throw await responseError(infoResponse);
        }

        const data = await infoResponse.json();
        const versionData = versionResponse.ok ? await versionResponse.json() : null;

        console.log('System info data:', data);

        let versionHtml = '';
        if (versionData && versionData.current_version) {
            window.mailcowUpdateVersion = versionData.latest_version;
            window.mailcowUpdateName = versionData.name || '';
            window.mailcowUpdateChangelog = versionData.changelog || 'No changelog available';

            const updateBadge = versionData.update_available
                ? ` <button onclick="showMailcowUpdateModal()" class="ui-tag ui-tag-info ui-tag-btn">Update Available</button>`
                : '';
            versionHtml = `v${escapeHtml(versionData.current_version)}${updateBadge}`;
        }

        const row = (label, part) => `<dt>${label}</dt><dd>${Number(part.total || 0).toLocaleString()} <small>${Number(part.active || 0).toLocaleString()} active</small></dd>`;
        if (!statusHold(container)) container.innerHTML = `
            <div class="ui-srv-big">${versionHtml || 'mailcow'}</div>
            <dl class="ui-srv-dl">
                ${row('Domains', data.domains || {})}
                ${row('Mailboxes', data.mailboxes || {})}
                ${row('Aliases', data.aliases || {})}
            </dl>
        `;
    } catch (error) {
        console.error('Failed to load system info:', error);
        statusFailed(document.getElementById('status-system'), `<p class="ui-empty ui-text-fail">Failed to load system info: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusSystem()')}</p>`);
    }
}

function showMailcowUpdateModal() {
    if (window.mailcowUpdateVersion && window.mailcowUpdateChangelog) {
        const title = window.mailcowUpdateName
            ? `Update Available: ${window.mailcowUpdateName}`
            : `mailcow Update: ${window.mailcowUpdateVersion}`;

        showMarkdownModal(title, window.mailcowUpdateChangelog);
    }
}



async function loadStatusStorage() {
    const container = document.getElementById('status-storage');

    try {
        console.log('Loading Storage Info...');

        const response = await authenticatedFetch('/api/status/storage');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Storage info data:', data);

        const usedPercent = parseInt(data.used_percent) || 0;
        const level = usedPercent > 90 ? 'fail' : usedPercent > 75 ? 'warn' : 'ok';
        setStatusKpi('status-kpi-storage', `${data.used_percent || `${usedPercent}%`} used`, level === 'ok' ? '' : level);
        const storageNote = document.getElementById('status-kpi-storage-note');
        if (storageNote) storageNote.textContent = [data.used && data.total ? `${data.used} of ${data.total}` : '', data.disk || ''].filter(Boolean).join(', ');

        const size = [data.used && data.total ? `${data.used} of ${data.total}` : '', data.disk ? `on ${data.disk}` : ''].filter(Boolean).join(' ');
        if (!statusHold(container)) container.innerHTML = `
            <div class="ui-srv-big${level === 'ok' ? '' : ` ui-text-${level}`}">${escapeHtml(String(data.used_percent || '0%'))} used</div>
            <div class="ui-meter ui-${level}"><i style="width: ${usedPercent}%"></i></div>
            ${size ? `<small>${escapeHtml(size)}</small>` : ''}
        `;
    } catch (error) {
        console.error('Failed to load storage info:', error);
        setStatusKpi('status-kpi-storage', '-');
        statusFailed(document.getElementById('status-storage'), `<p class="ui-empty ui-text-fail">Failed to load storage info: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusStorage()')}</p>`);
    }
}

async function loadStatusExtended() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        console.log('Extended status data loaded:', data);

        renderStatusImport(data.import_status || {});

        renderStatusCorrelation(data.correlation_status || {}, data.recent_incomplete_correlations || [], (data.configuration || {}).max_correlation_age_minutes);

        renderStatusJobs(data.background_jobs || {});

        await loadBlacklistStatus();

    } catch (error) {
        console.error('Failed to load extended status:', error);
        statusFailed(document.getElementById('status-import'), `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusExtended()')}</p>`);
        statusFailed(document.getElementById('status-correlation'), `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusExtended()')}</p>`);
        statusFailed(document.getElementById('status-jobs'), `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadStatusExtended()')}</p>`);
    }
}

function checkHost(hostname) {
    return checkBlacklists(true, hostname);
}

let blacklistCheckBtnIdle = null;

async function checkBlacklists(force = false, host = null) {
    if (!uiMayAct('status')) return;
    const btn = document.getElementById('blacklist-check-btn');
    const container = document.getElementById('status-blacklist');

    if (btn) {
        if (blacklistCheckBtnIdle === null) blacklistCheckBtnIdle = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `
            <svg class="animate-spin -ms-1 me-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
            </svg>
            Running...
        `;
    }

    showToast('Starting blacklist check...', 'info');

    if (container) {
        const existing = document.getElementById('blacklist-temp-progress');
        if (existing) existing.remove();

        const progressHtml = `
            <div id="blacklist-temp-progress" class="ui-panel ui-bl-progress">
                <div class="ui-bl-progress-head">
                    <span class="ui-text-info">
                        <svg class="animate-spin h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
                            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                        </svg>
                        Running Scan...
                    </span>
                    <span id="blacklist-progress-text" class="ui-muted">Initializing...</span>
                </div>
                <div class="ui-meter ui-meter-info"><i id="blacklist-progress-bar" style="width: 0%"></i></div>
            </div>
        `;
        container.insertAdjacentHTML('afterbegin', progressHtml);
    }

    let progressInterval = setInterval(async () => {
        try {
            const progressRes = await authenticatedFetch('/api/blacklist/progress');
            if (progressRes.ok) {
                const progress = await progressRes.json();
                const progressBar = document.getElementById('blacklist-progress-bar');
                const progressText = document.getElementById('blacklist-progress-text');

                if (progressBar) {
                    progressBar.style.width = `${progress.percent}%`;
                }
                if (progressText) {
                    progressText.textContent = `${progress.current}/${progress.total} scanned${progress.current_blacklist ? ` - ${progress.current_blacklist}` : ''}`;
                }

                if (!progress.in_progress && progress.current >= progress.total) {
                    clearInterval(progressInterval);
                    showToast('Blacklist check completed', 'success');
                    const temp = document.getElementById('blacklist-temp-progress');
                    if (temp) temp.remove();

                    await loadBlacklistStatus();
                }
            }
        } catch (e) {
        }
    }, 1000);

    try {
        const params = new URLSearchParams();
        if (force) params.set('force', 'true');
        if (host) params.set('host', host);
        const qs = params.toString();
        const response = await authenticatedFetch(`/api/blacklist/check${qs ? '?' + qs : ''}`, { method: 'POST' });
        if (!response.ok) {
            throw await responseError(response);
        }
        const body = await response.json().catch(() => null);
        if (body && body.status === 'busy') {
            showToast(body.message || 'A blocklist check is already running. Try again when it is done.', 'warning');
            if (host) {
                clearInterval(progressInterval);
                const temp = document.getElementById('blacklist-temp-progress');
                if (temp) temp.remove();
            }
            return;
        }
        if (host) {
            clearInterval(progressInterval);
            const temp = document.getElementById('blacklist-temp-progress');
            if (temp) temp.remove();
            showToast(`Check completed for ${host}`, 'success');
            await loadBlacklistStatus();
        }
    } catch (error) {
        clearInterval(progressInterval);
        const temp = document.getElementById('blacklist-temp-progress');
        if (temp) temp.remove();

        console.error('Failed to check blacklists:', error);
        showToast(`Failed to check: ${uiErrorText(error)}`, 'error');
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = blacklistCheckBtnIdle;
        }
    }
}

async function loadBlacklistStatus() {
    const container = document.getElementById('status-blacklist');
    if (!container) return;

    const detailsElement = container.querySelector('details[open]');
    if (detailsElement) {
    }

    try {
        const response = await authenticatedFetch('/api/blacklist/monitored');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();
        renderBlacklistStatus(data);
    } catch (error) {
        console.error('Failed to load blacklist status:', error);
        statusFailed(container, `<p class="ui-empty ui-text-fail">Failed to load: ${escapeHtml(uiSentence(uiErrorText(error)))}${uiRetryButton('loadBlacklistStatus()')}</p>`);
    }
}


async function loadDashboardBlacklistSummary() {
    if (!document.getElementById('dash-kpi-blocklists')) return;
    try {
        const response = await authenticatedFetch('/api/blacklist/summary');
        if (!response.ok) throw await responseError(response);
        const data = await response.json();
        if (!data.has_data) {
            setDashKpi('dash-kpi-blocklists', '-', '', 'No check yet; the first one runs by itself');
            return;
        }
        const hosts = data.hosts || [];
        const listedHosts = hosts.filter(h => h.status === 'listed');
        const checked = data.checked_at ? `checked ${formatAgo(data.checked_at)}` : '';
        const fig = data.figure && data.figure.valid ? data.figure : null;
        if (data.status === 'listed') {
            setDashKpi('dash-kpi-blocklists', fig ? `${fig.value} of ${fig.of} listed` : `${listedHosts.length || data.hosts_listed || 1} of ${hosts.length || 1} listed`, 'fail',
                listedHosts.map(h => `${h.hostname} on ${h.listed_count} of ${h.total_blacklists || '?'}`).join(', '));
        } else if (data.status === 'error') {
            setDashKpi('dash-kpi-blocklists', 'Check error', 'warn', checked);
        } else if (data.status === 'clean') {
            setDashKpi('dash-kpi-blocklists', `${hosts.length || 1} clean`, '', [`${hosts.length} address${hosts.length === 1 ? '' : 'es'}`, checked].filter(Boolean).join(', '));
        } else {
            setDashKpi('dash-kpi-blocklists', 'Unknown', '', checked);
        }
    } catch (error) {
        console.error('Failed to load blacklist summary:', error);
        dashKpiFailed('dash-kpi-blocklists');
    }
}


function renderBlacklistStatus(data) {
    const container = document.getElementById('status-blacklist');
    if (!container) return;

    if (!data.hosts || data.hosts.length === 0) {
        setStatusKpi('status-kpi-blocklists', '-');
        if (!statusHold(container)) container.innerHTML = `
            <div class="ui-empty ui-panel">
                <b>No Monitored Hosts</b>
                <p>Syncing monitoring targets...</p>
            </div>
        `;
        return;
    }

    const withData = data.hosts.filter(host => host.has_data);
    const listed = withData.filter(host => (host.listed_count || 0) > 0).length;
    setStatusKpi('status-kpi-blocklists', withData.length ? `${listed} of ${withData.length} listed` : '-', listed > 0 ? 'fail' : '');
    setStatusTabCount('blocklists', listed, true);
    statusState.blocklists = data.hosts;

    const ignoredLists = new Map();
    data.hosts.forEach(host => (host.results || []).forEach(r => { if (r.ignored && r.zone) ignoredLists.set(r.zone, r.name); }));
    const blNote = document.getElementById('status-kpi-blocklists-note');
    if (blNote) blNote.textContent = ignoredLists.size ? `${ignoredLists.size} list${ignoredLists.size === 1 ? '' : 's'} ignored for every address` : 'Addresses on a blocklist';
    const blSummary = document.getElementById('status-blacklist-summary');
    if (blSummary) blSummary.textContent = `${data.hosts.length} address${data.hosts.length === 1 ? '' : 'es'}${listed ? `, ${listed} listed` : ''}`;

    const progress = document.getElementById('blacklist-temp-progress');
    const openStates = {};
    container.querySelectorAll('details').forEach(el => {
        if (el.open && el.id) openStates[el.id] = true;
    });

    const RESULT_TONE = { clean: 'ok', listed: 'fail', error: 'warn', timeout: 'warn' };
    const detail = r => r.response ? `${r.name}: ${r.response}` : r.name;
    const lookupIcon = r => /^https:\/\//.test(r.info_url || '')
        ? `<a href="${escapeHtml(r.info_url)}" target="_blank" rel="noopener noreferrer" class="ui-bl-link" title="Look up on ${escapeHtml(r.name)}" aria-label="Look up on ${escapeHtml(r.name)}"><svg width="12" height="12" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"></path></svg></a>`
        : '';
    const ignoreToggle = r => r.zone && r.zone !== 'unknown'
        ? `<button type="button" class="ui-bl-ign" data-acts="status" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', ${!r.ignored})" title="${r.ignored ? 'Count and alert on this list again' : 'Keep checking this list but never count or alert on it'}">${r.ignored ? 'Stop ignoring' : 'Ignore'}</button>`
        : '';

    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-st-hosts">
        ${data.hosts.map(host => {
            const hostId = `bl-host-${String(host.hostname).replace(/[^A-Za-z0-9_-]/g, '-')}`;
            const results = host.results || [];
            const listedOn = results.filter(r => r.listed && !r.ignored);
            const others = results.filter(r => !(r.listed && !r.ignored));
            const total = host.total_blacklists || 0;
            const result = !host.has_data ? uiTag('Not checked yet', '')
                : host.status === 'listed' ? uiTag(`Listed on ${host.listed_count || 0} of ${total}`, 'fail')
                : host.status === 'error' ? uiTag('Check error', 'warn')
                : host.status === 'clean' ? uiTag(`Clean on ${total}`, 'ok')
                : uiTag('Unknown', '');
            return `
            <section class="ui-panel ui-bl-row">
                <div class="ui-st-host-head">
                    <b class="ui-mono">${uiEntity('ip', host.hostname, { mono: true, plain: true })}</b>
                    <span class="ui-tag ui-tag-line">${escapeHtml(host.source || 'system')}</span>
                    ${result}
                    <span class="ui-st-host-tools">
                        ${host.checked_at ? uiTime(host.checked_at, `checked ${formatAgo(host.checked_at)}`, { title: formatTime(host.checked_at), cls: 'ui-muted' }) : '<span class="ui-muted">never checked</span>'}
                        <button onclick="checkHost('${escapeJsArg(host.hostname)}')" class="ui-btn ui-btn-sm" title="Run Check for this Host" data-acts="status">Check now</button>
                    </span>
                </div>
                ${listedOn.map(r => `
                <div class="ui-st-listing">
                    <div><b>${escapeHtml(r.name)}</b><small>${escapeHtml(r.response ? `Answer ${r.response}` : 'Listed')}</small></div>
                    <span class="ui-st-acts">${blocklistLookupLink(r, 'Look up')}<button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(r.zone)}', true)" data-acts="status">Ignore list</button></span>
                </div>`).join('')}
                ${host.has_data && others.length ? `
                <details id="${hostId}" class="ui-bl-all"${openStates[hostId] ? ' open' : ''}>
                    <summary>${listedOn.length ? `${others.length} other lists` : `All ${others.length} lists`}</summary>
                    <div class="ui-bl-grid">
                        ${others.map(r => {
                            const tone = r.ignored ? '' : (RESULT_TONE[r.status] || '');
                            const state = r.listed ? 'listed, ignored' : (r.ignored ? 'ignored' : (r.status || 'unknown'));
                            return `<span class="ui-bl-item${tone ? ` ui-bl-${tone}` : ''}${r.ignored ? ' is-ignored' : ''}" title="${escapeHtml(detail(r))}"><i class="ui-mdot${tone ? ` ui-mdot-${tone}` : ''}"></i>${escapeHtml(r.name)}${lookupIcon(r)}<small>${escapeHtml(state)}</small>${ignoreToggle(r)}</span>`;
                        }).join('')}
                    </div>
                </details>` : ''}
            </section>`;
        }).join('')}
        ${ignoredLists.size ? `
            <section class="ui-panel">
                <div class="ui-panel-head">Ignored lists <span class="ui-count">${ignoredLists.size}</span></div>
                ${[...ignoredLists].map(([zone, name]) => `
                <div class="ui-st-listing">
                    <div><b>${escapeHtml(name)}</b><small>Checked and shown, never counted or alerted, for every address</small></div>
                    <span class="ui-st-acts"><button type="button" class="ui-btn ui-btn-sm" onclick="setBlocklistIgnored('${escapeJsArg(zone)}', false)" data-acts="status">Stop ignoring</button></span>
                </div>`).join('')}
            </section>` : ''}
        </div>
    `;
    if (progress) container.prepend(progress);
    renderStatusAttention();
}

async function setBlocklistIgnored(zone, ignored) {
    if (!uiMayAct('status')) return;
    try {
        const res = await authenticatedFetch(`/api/blacklist/lists/${encodeURIComponent(zone)}/ignore`, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ignored })
        });
        if (!res.ok) throw await responseError(res);
        const data = await res.json();
        showToast(ignored ? `${data.name} is ignored for every address.` : `${data.name} counts again.`, 'success');
        loadBlacklistStatus();
        loadNavCounters();
    } catch (e) {
        showToast(`Could not change the blocklist: ${uiErrorText(e)}`, 'error');
    }
}

function renderStatusImport(imports) {
    const container = document.getElementById('status-import');
    const row = (title, d) => `
        <div class="ui-tr">
            <b class="ui-td">${title}</b>
            ${d ? `
            <span class="ui-td"><small class="ui-sec-unit">Last Fetch Run </small>${d.last_fetch_run ? uiTime(d.last_fetch_run, formatAgo(d.last_fetch_run), { title: formatTime(d.last_fetch_run) }) : 'Never'}</span>
            <span class="ui-td"><small class="ui-sec-unit">Last Import </small>${d.last_import ? uiTime(d.last_import, formatAgo(d.last_import), { title: formatTime(d.last_import) }) : 'Never'}</span>
            <span class="ui-td ui-td-end"><small class="ui-sec-unit">Total Entries </small>${Number(d.total_entries || 0).toLocaleString()}</span>
            <span class="ui-td"><small class="ui-sec-unit">Oldest Entry </small>${d.oldest_entry ? uiTime(d.oldest_entry, formatTime(d.oldest_entry)) : '-'}</span>
            ` : '<span class="ui-td ui-muted">No data</span><span></span><span></span><span></span>'}
        </div>`;
    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-table ui-stack" data-nosort style="--ui-cols: minmax(130px, 1fr) minmax(110px, 1fr) minmax(110px, 1fr) 110px minmax(150px, 1.2fr); --ui-table-min: 660px">
            <div class="ui-tr ui-tr-head"><span>Source</span><span>Last Fetch Run</span><span>Last Import</span><span class="ui-td-end">Total Entries</span><span>Oldest Entry</span></div>
            ${row('Postfix Logs', imports.postfix)}
            ${row('Rspamd Logs', imports.rspamd)}
            ${row('Netfilter Logs', imports.netfilter)}
        </div>
    `;
}

function renderStatusCorrelation(correlation, incompleteList, maxAgeMinutes) {
    const container = document.getElementById('status-correlation');
    setStatusKpi('status-kpi-linking', `${correlation.completion_rate || 0}%`, correlation.incomplete ? 'warn' : '');
    const linkingNote = document.getElementById('status-kpi-linking-note');
    if (linkingNote) linkingNote.textContent = `${(correlation.complete || 0).toLocaleString()} of ${(correlation.total || 0).toLocaleString()} complete, ${(correlation.incomplete || 0).toLocaleString()} waiting`;
    if (!statusHold(container)) container.innerHTML = `
        <div class="ui-srv-big${correlation.incomplete ? ' ui-text-warn' : ''}">${escapeHtml(String(correlation.completion_rate || 0))}%</div>
        <small>${Number(correlation.complete || 0).toLocaleString()} of ${Number(correlation.total || 0).toLocaleString()} complete, ${Number(correlation.incomplete || 0).toLocaleString()} incomplete, ${Number(correlation.expired || 0).toLocaleString()} expired</small>
        ${correlation.last_update ? `<small title="${escapeHtml(formatTime(correlation.last_update))}">Updated ${formatAgo(correlation.last_update)}</small>` : ''}
    `;
    const pending = document.getElementById('status-correlation-pending');
    if (pending) pending.innerHTML = incompleteList.length > 0 ? `
        <section class="ui-sec-block">
            <div class="ui-list-head" id="status-pending-head"><h2 class="ui-h2">Waiting to be linked</h2> <span class="ui-count">${incompleteList.length}</span></div>
            <div class="ui-table ui-stack" data-sort-at="status-pending-head" data-sort-name="messages waiting to be linked" style="--ui-cols: minmax(180px, 1.4fr) minmax(220px, 2fr) 90px; --ui-table-min: 560px">
                <div class="ui-tr ui-tr-head"><span data-sort-kind="text">Message ID</span><span data-sort-kind="text">From and to</span><span class="ui-td-end" data-sort-kind="date">Age</span></div>
                ${incompleteList.map(item => `
                    <div class="ui-tr">
                        <span class="ui-td ui-mono">${copyableText(item.message_id || 'N/A')}</span>
                        <span class="ui-td">${uiEntity('address', item.sender || 'N/A')} → ${uiEntity('address', item.recipient || 'N/A')}</span>
                        <span class="ui-td ui-td-end ui-text-warn">${escapeHtml(String(item.age_minutes))}m ago</span>
                    </div>`).join('')}
            </div>
            <p class="ui-kv-note ui-list-foot">Each is linked when its delivery logs arrive, or marked expired once it is ${escapeHtml(String(maxAgeMinutes || 10))} minutes old.</p>
        </section>` : '';
}

function renderStatusJobs(jobs) {
    const container = document.getElementById('status-jobs');
    const categories = statusJobCategories(jobs);
    renderStatusJobsTable(container, categories, jobs);
}

function statusJobCategories(jobs) {
    return [
        {
            title: 'Log Processing',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4"></path>',
            jobs: [
                ['Fetch Logs', 'fetch_logs', jobs.fetch_logs],
                ['Cleanup Logs', 'cleanup_logs', jobs.cleanup_logs]
            ]
        },
        {
            title: 'Correlation Engine',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path>',
            jobs: [
                ['Complete Correlations', 'complete_correlations', jobs.complete_correlations],
                ['Update Final Status', 'update_final_status', jobs.update_final_status],
                ['Expire Correlations', 'expire_correlations', jobs.expire_correlations],
                ['Dovecot Deliveries', 'correlate_dovecot', jobs.correlate_dovecot]
            ]
        },
        {
            title: 'Data Sync',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>',
            jobs: [
                ['Sync Active Domains', 'sync_local_domains', jobs.sync_local_domains],
                ['Mailbox Statistics', 'mailbox_stats', jobs.mailbox_stats],
                ['Alias Statistics', 'alias_stats', jobs.alias_stats],
                ['Sync Transports & Relayhosts', 'sync_transports', jobs.sync_transports],
                ['Turned-Off Features', 'feature_data_sweep', jobs.feature_data_sweep],
                ['Trend Samples', 'trend_samples', jobs.trend_samples]
            ]
        },
        {
            title: 'DMARC & TLS',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>',
            jobs: [
                ['DMARC & TLS IMAP Import', 'dmarc_imap_sync', jobs.dmarc_imap_sync],
                ['Cleanup DMARC & TLS Reports', 'cleanup_dmarc_reports', jobs.cleanup_dmarc_reports],
                ['Weekly Summary Report', 'send_weekly_summary', jobs.send_weekly_summary]
            ]
        },
        {
            title: 'Security & Monitoring',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z"></path>',
            jobs: [
                ['DNS Check (All Domains)', 'dns_check', jobs.dns_check],
                ['IP Blacklist Check (All Hosts)', 'blacklist_check', jobs.blacklist_check],
                ['Protection Rules', 'protection_rules', jobs.protection_rules],
                ['Anomaly Detection', 'anomaly_detection', jobs.anomaly_detection],
                ['Outgoing Spam', 'smtp_abuse', jobs.smtp_abuse]
            ]
        },
        {
            title: 'System',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path>',
            jobs: [
                ['Check App Version', 'check_app_version', jobs.check_app_version],
                ['Credential Checks', 'check_credentials', jobs.check_credentials],
                ['Update MaxMind Databases', 'update_geoip', jobs.update_geoip]
            ]
        },
        {
            title: 'Live Logs',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>',
            jobs: [
                ['Fetch Raw Logs', 'fetch_raw_logs', jobs.fetch_raw_logs],
                ['Cleanup Raw Logs', 'cleanup_raw_logs', jobs.cleanup_raw_logs]
            ]
        },
        {
            title: 'Devices',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z"></path>',
            jobs: [
                ['ActiveSync Devices', 'eas_devices', jobs.eas_devices],
                ['Cleanup ActiveSync Devices', 'cleanup_eas_devices', jobs.cleanup_eas_devices]
            ]
        },
        {
            title: 'Outbound',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z"></path>',
            jobs: [
                ['Detect Suppressions', 'detect_suppressions', jobs.detect_suppressions],
                ['Sync with Rspamd', 'sync_suppressions', jobs.sync_suppressions],
                ['Expire Suppressions', 'expire_suppressions', jobs.expire_suppressions],
                ['Cleanup Deferred Queue', 'cleanup_deferred_queue', jobs.cleanup_deferred_queue]
            ]
        },
        {
            title: 'Quarantine',
            icon: '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.618 5.984A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01"></path>',
            jobs: [
                ['Process Quarantine Rules', 'process_quarantine_rules', jobs.process_quarantine_rules]
            ]
        }
    ];
}

function renderStatusJobsTable(container, categories, jobs) {
    const summary = summarizeJobs(jobs);
    const all = summary.all;
    const isOff = summary.isOff;
    statusState.jobs = all.map(([name, key, job]) => ({ name, key, failed: !isOff(job) && job.status === 'failed', error: job.error || '' }));
    const failed = summary.failed.length;
    const off = summary.off;
    setStatusKpi('status-kpi-jobs', `${all.length - failed - off} of ${all.length - off} healthy`, failed ? 'fail' : '');
    const jobsNote = [failed ? `${failed} failed` : 'None failed', off ? `${off} off because a feature or setting is off` : ''].filter(Boolean).join(', ');
    const kpiNote = document.getElementById('status-kpi-jobs-note');
    if (kpiNote) kpiNote.textContent = jobsNote;
    const jobsSummary = document.getElementById('status-jobs-summary');
    if (jobsSummary) jobsSummary.textContent = `${all.length} jobs, ${jobsNote.charAt(0).toLowerCase()}${jobsNote.slice(1)}`;
    setStatusTabCount('jobs', failed, true);

    const isFailed = job => !isOff(job) && job.status === 'failed';
    const chevron = '<svg class="ui-collapse-chevron" width="18" height="18" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>';
    let html = '';
    for (const cat of categories) {
        const validJobs = cat.jobs.filter(j => j[2]);
        if (validJobs.length === 0) continue;
        const catFailed = validJobs.filter(j => isFailed(j[2])).length;
        const catOff = validJobs.filter(j => isOff(j[2])).length;
        const note = [catFailed ? `<span class="ui-text-fail">${catFailed} failed</span>` : 'all OK', catOff ? `${catOff} off` : ''].filter(Boolean).join(' · ');
        const open = catFailed > 0 || statusJobsOpen.has(cat.title);
        html += `
            <details class="ui-panel ui-collapse ui-jg" data-group="${escapeHtml(cat.title)}"${catFailed ? ' data-failed' : ''}${open ? ' open' : ''} ontoggle="statusJobGroupToggled(this)">
                <summary class="ui-panel-head">${escapeHtml(cat.title)} <span class="ui-count">${validJobs.length} ${validJobs.length === 1 ? 'job' : 'jobs'} · ${note}</span>${chevron}</summary>
                <div class="ui-jg-body">${validJobs.map(j => renderJobCard(j[0], j[1], j[2])).join('')}</div>
            </details>`;
    }
    if (!statusHold(container)) container.innerHTML = `<div class="ui-jgs">${html}</div>`;
    statusJobFilter(statusJobFilterValue);
    renderStatusAttention();
}

const statusJobsOpen = new Set();
function statusJobGroupToggled(el) {
    if (statusJobFilterValue !== 'all') return;
    if (el.open) statusJobsOpen.add(el.dataset.group); else statusJobsOpen.delete(el.dataset.group);
}

async function triggerBackgroundJob(jobKey, buttonEl, jobName = null) {
    if (!buttonEl) return;

    buttonEl.disabled = true;
    const originalContent = buttonEl.innerHTML;
    buttonEl.innerHTML = '<span class="inline-block animate-spin w-3 h-3 border-2 border-current border-t-transparent rounded-full"></span> Running...';
    buttonEl.classList.add('opacity-50', 'cursor-not-allowed');

    try {
        await runBackgroundJob(jobKey, jobName);
    } finally {
        buttonEl.disabled = false;
        buttonEl.innerHTML = originalContent;
        buttonEl.classList.remove('opacity-50', 'cursor-not-allowed');
    }
}

async function runBackgroundJob(jobKey, jobName = null) {
    if (!uiMayAct('admin')) return;
    const displayName = jobName || jobKey;
    try {
        const response = await authenticatedFetch(`/api/settings/jobs/${encodeURIComponent(jobKey)}/run`, {
            method: 'POST'
        });

        if (!response.ok) {
            const err = await response.json().catch(() => null);
            const detail = uiHttpErrorText(response.status, err);
            if (response.status === 409 && /already running/i.test(detail)) {
                showToast(`Job "${displayName}" is already running`, 'warning');
                return 'running';
            }
            if (response.status === 409) {
                showToast(`Job "${displayName}" cannot run now. ${detail.replace(/^The job cannot run\.\s*/, '')}`.trim(), 'warning');
                return 'unavailable';
            }
            throw new Error(detail);
        }

        showToast(`Job "${displayName}" started successfully`, 'success');

        setTimeout(() => {
            loadStatusExtended();
        }, 1000);
        return 'started';
    } catch (error) {
        console.error(`Failed to trigger job ${jobKey}:`, error);
        showToast(`Failed to start job: ${uiErrorText(error)}`, 'error');
        return 'failed';
    }
}

function showChangelogModal(changelog) {
    const modal = document.getElementById('changelog-modal');
    const modalTitle = modal?.querySelector('h3');
    const content = document.getElementById('changelog-content');

    if (modal && content) {
        if (modalTitle) {
            modalTitle.textContent = 'Changelog';
        }
        if (typeof marked !== 'undefined' && changelog) {
            marked.setOptions({
                breaks: true,
                gfm: true
            });
            content.innerHTML = renderMarkdown(changelog);
        } else {
            content.textContent = changelog || 'No changelog available';
        }
        revealChangelogModal(modal);
    }
}

function revealChangelogModal(modal) {
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden';
    const body = modal.querySelector('.ui-dialog-body');
    if (body) body.scrollTop = 0;
    uiReadProgress(modal.querySelector('.ui-dialog-head'), body);
}

function closeChangelogModal() {
    const modal = document.getElementById('changelog-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
        const modalTitle = modal.querySelector('h3');
        if (modalTitle) {
            modalTitle.textContent = 'Changelog';
        }
    }
}

function getFlagUrl(countryCode, size = '24x18') {
    if (typeof countryCode !== 'string' || !/^[a-z]{2}$/i.test(countryCode)) {
        return null;
    }
    return `/static/assets/flags/${size}/${countryCode.toLowerCase()}.png`;
}

function renderGeoIPInfo(rspamdData, size = '24x18') {
    if (!rspamdData || !rspamdData.ip) {
        return '';
    }

    const ip = rspamdData.ip;
    const hasGeoIP = rspamdData.country_code;

    if (!hasGeoIP) {
        return `<p>Source IP: ${copyableText(ip)}</p>`;
    }

    const flagUrl = getFlagUrl(rspamdData.country_code, size);
    const [width, height] = size.split('x').map(Number);

    let parts = [`<strong>${copyableText(ip)}</strong>`];

    if (rspamdData.country_name && flagUrl) {
        const countryPart =
            `<br><span style="display: inline-flex; align-items: baseline; gap: 4px; vertical-align: baseline; margin-top: 5px;">` +
            `<img src="${flagUrl}" alt="${escapeHtml(rspamdData.country_name)}" ` +
            `style="width:${width}px; height:${height}px; display: block;" ` +
            `onerror="this.style.display='none'">` +
            `${escapeHtml(rspamdData.country_name)}` +
            `</span>`;
        parts.push(countryPart);
    }

    if (rspamdData.city) {
        parts.push(escapeHtml(rspamdData.city));
    }

    if (rspamdData.asn_org) {
        parts.push(`(${escapeHtml(rspamdData.asn_org)})`);
    }

    return `<p style="margin: 0;">Source: ${parts.join(' ')}</p>`;
}

function renderGeoIPForDMARC(record, size = '24x18') {
    if (!record || !record.source_ip) {
        return '';
    }

    const ip = record.source_ip;
    const hasGeoIP = record.country_code;

    if (!hasGeoIP) {
        return escapeHtml(ip);
    }

    const flagUrl = getFlagUrl(record.country_code, size);
    const [width, height] = size.split('x').map(Number);

    let parts = [];

    if (record.country_name) {
        parts.push(escapeHtml(record.country_name));
    }

    if (record.city) {
        parts.push(escapeHtml(record.city));
    }

    if (record.asn_org) {
        parts.push(escapeHtml(record.asn_org));
    }

    const locationText = parts.join(', ');

    if (flagUrl && locationText) {
        return `<img src="${flagUrl}" alt="${escapeHtml(record.country_name || '')}" style="width:${width}px; height:${height}px; vertical-align:middle; margin-inline-end:4px;" onerror="this.style.display='none'">${locationText}`;
    }

    return locationText || escapeHtml(ip);
}


function renderPagination(type, currentPage, totalPages) {
    if (totalPages <= 1) return '';

    return `
        <div class="ui-pagination">
            <button onclick="loadLogs('${type}', ${Number(currentPage) - 1})" ${currentPage === 1 ? 'disabled' : ''} class="ui-btn">
                Previous
            </button>
            <span class="ui-muted">Page ${Number(currentPage)} of ${Number(totalPages)}</span>
            <button onclick="loadLogs('${type}', ${Number(currentPage) + 1})" ${currentPage === totalPages ? 'disabled' : ''} class="ui-btn">
                Next
            </button>
        </div>
    `;
}

function loadLogs(type, page) {
    currentPage[type] = page;
    switch (type) {
        case 'messages':
            loadMessages();
            break;
        case 'netfilter':
            loadNetfilterLogs(page);
            break;
    }
}

function initDarkMode() {
    const theme = localStorage.getItem('theme');
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

    if (theme === 'dark' || (!theme && prefersDark)) {
        document.documentElement.classList.add('dark');
        document.getElementById('theme-toggle-light-icon').classList.remove('hidden');
    } else {
        document.documentElement.classList.remove('dark');
        document.getElementById('theme-toggle-dark-icon').classList.remove('hidden');
    }
}

function toggleDarkMode() {
    document.documentElement.classList.toggle('dark');
    const isDark = document.documentElement.classList.contains('dark');
    localStorage.setItem('theme', isDark ? 'dark' : 'light');

    document.getElementById('theme-toggle-dark-icon').classList.toggle('hidden');
    document.getElementById('theme-toggle-light-icon').classList.toggle('hidden');
}

initDarkMode();

document.addEventListener('DOMContentLoaded', function () {
    const changelogModal = document.getElementById('changelog-modal');
    if (changelogModal) {
        changelogModal.addEventListener('click', function (e) {
            if (uiBackdropClick(e)) {
                closeChangelogModal();
            }
        });

        const changelogContent = changelogModal.querySelector('.bg-white, .dark\\:bg-gray-800');
        if (changelogContent) {
            changelogContent.addEventListener('click', function (e) {
                e.stopPropagation();
            });
        }
    }
});

const DOCS_SITE_URL = 'https://shlomiporush.github.io/mailcow-logs-viewer/';
const DOCS_REPO_URL = 'https://github.com/ShlomiPorush/mailcow-logs-viewer/blob/main/';

// A help page's relative links point to the documentation site, where they work
function helpDocMarkdown(markdown, docName) {
    return markdown
        .replace(/^[ \t]*!\[[^\]]*\]\([^)\s]*\)[ \t]*$/gm, '')
        .replace(/(\]\()([^)\s]+)(\))/g, (match, open, target, close) => {
            if (/^[a-z][a-z0-9+.-]*:/i.test(target)) return match;
            if (target.startsWith('#')) return `${open}${DOCS_SITE_URL}HelpDocs/${docName}/${target}${close}`;
            const [path, anchor] = target.split('#');
            const hash = anchor ? `#${anchor}` : '';
            const parts = ['documentation', 'HelpDocs'];
            for (const segment of path.split('/')) {
                if (segment === '..') parts.pop();
                else if (segment && segment !== '.') parts.push(segment);
            }
            const file = parts.join('/');
            let url;
            if (file === 'README.md') url = DOCS_SITE_URL;
            else if (file === 'CHANGELOG.md') url = `${DOCS_SITE_URL}changelog/`;
            else if (file.startsWith('documentation/') && file.endsWith('.md')) {
                url = `${DOCS_SITE_URL}${file.slice('documentation/'.length, -'.md'.length)}/`;
            } else url = DOCS_REPO_URL + file;
            return `${open}${url}${hash}${close}`;
        });
}

async function showHelpModal(docName, title) {
    const opener = layerLastAction || document.activeElement;
    try {
        const response = await authenticatedFetch(`/api/docs/${docName}`);

        if (!response.ok) {
            throw await responseError(response);
        }

        const markdown = helpDocMarkdown(await response.text(), docName);
        uiLayerOpener(opener);
        showMarkdownModal(`Help - ${title || docName.replace(/_/g, ' ')}`, markdown);

    } catch (error) {
        console.error('Failed to load help documentation:', error);
        if (uiIsPhone()) {
            uiSheetShow('markdown-sheet', { label: 'Help', head: '<h3 class="ui-sheet-title">Help</h3>',
                body: `<p class="ui-text-fail">Failed to load help documentation: ${escapeHtml(uiErrorText(error))}</p>` });
            return;
        }

        const modal = document.getElementById('changelog-modal');
        const modalTitle = modal?.querySelector('h3');
        const content = document.getElementById('changelog-content');

        if (modal && content) {
            if (modalTitle) {
                modalTitle.textContent = 'Help';
            }
            content.innerHTML = `<p class="text-red-500">Failed to load help documentation: ${escapeHtml(uiErrorText(error))}</p>`;
            revealChangelogModal(modal);
        }
    }
}

console.log('[OK] mailcow Logs Viewer - Complete Frontend Loaded');
console.log('Features: Dashboard, Messages, Postfix, Rspamd, Netfilter, Queue, Quarantine, Status, Mailbox Stats, Settings');
console.log('UI: Dark mode, Modals with tabs, Responsive design');

let containerLogsInterval = null;

function containerLogsAtEnd(content) {
    const box = content.parentElement;
    return !box || box.scrollHeight - box.scrollTop - box.clientHeight <= 4;
}

async function fetchContainerLogs(silent = false) {
    const content = document.getElementById('container-logs-content');

    if (content && silent && (uiTextHeld(content) || !containerLogsAtEnd(content) || document.hidden)) return;

    if (content && !silent) {
        content.textContent = 'Loading logs...';
    }

    try {
        const response = await authenticatedFetch('/api/status/container-logs?lines=500');
        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();

        if (content && data.logs) {
            if (silent && (uiTextHeld(content) || !containerLogsAtEnd(content))) return;
            const isScrolledToBottom = containerLogsAtEnd(content);

            if (data.logs.length === 0) {
                if (!silent) content.textContent = 'No logs available.';
            } else {
                content.replaceChildren(...data.logs.join('').replace(/\r?\n$/, '').split(/\r?\n/).map(text => {
                    const line = document.createElement('span');
                    line.className = 'ui-log-line';
                    line.textContent = text;
                    return line;
                }));
            }

            if (!silent || isScrolledToBottom) {
                const container = content.parentElement;
                if (container) {
                    container.scrollTop = container.scrollHeight;
                }
            }
        }
    } catch (error) {
        console.error('Failed to load container logs:', error);
        if (content && !silent) {
            content.textContent = `Failed to load logs: ${uiErrorText(error)}`;
        }
    }
}

function loadContainerLogs() {
    const modal = document.getElementById('container-logs-modal');

    if (modal) {
        modal.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
    }

    if (containerLogsInterval) clearInterval(containerLogsInterval);

    requestAnimationFrame(() => {
        if (modal && modal.classList.contains('hidden')) return;
        if (modal) uiDialogSheetFull(modal);
        fetchContainerLogs(false);
        if (containerLogsInterval) clearInterval(containerLogsInterval);
        containerLogsInterval = setInterval(() => {
            fetchContainerLogs(true);
        }, 2000);
    });
}

function closeContainerLogsModal() {
    const modal = document.getElementById('container-logs-modal');
    if (modal) {
        modal.classList.add('hidden');
        document.body.style.overflow = '';
    }

    if (containerLogsInterval) {
        clearInterval(containerLogsInterval);
        containerLogsInterval = null;
    }
}

const NAV_SUBPAGE_TABS = {
    quarantine: '#quarantine-tabs:not(.hidden)',
    outbound: '#outbound-tabs:not(.hidden)',
    netfilter: '.ui-se-tabs',
    status: '.ui-st-tabs',
    'mailbox-stats': '#mailbox-stats-views'
};
let navFlyout = null;
let navFlyoutTimer = null;

function navSubpageTabs(page) {
    const list = document.querySelector(NAV_SUBPAGE_TABS[page]);
    if (!list) return [];
    return [...list.querySelectorAll('[role="tab"]')].filter(btn => !btn.hidden && !btn.classList.contains('hidden') && btn.style.display !== 'none');
}

function hideNavFlyout() {
    clearTimeout(navFlyoutTimer);
    if (navFlyout) navFlyout.classList.remove('is-open');
}

function showNavFlyout(item, page) {
    clearTimeout(navFlyoutTimer);
    const tabs = navSubpageTabs(page);
    if (tabs.length < 2) return hideNavFlyout();
    if (!navFlyout) {
        navFlyout = document.createElement('div');
        navFlyout.className = 'ui-fly';
        navFlyout.setAttribute('role', 'menu');
        navFlyout.addEventListener('mouseenter', () => clearTimeout(navFlyoutTimer));
        navFlyout.addEventListener('mouseleave', () => { navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        navFlyout.addEventListener('keydown', e => {
            const items = [...navFlyout.querySelectorAll('.ui-fly-item')];
            const i = items.indexOf(document.activeElement);
            if (e.key === 'ArrowDown') { e.preventDefault(); items[(i + 1) % items.length].focus(); }
            if (e.key === 'ArrowUp') { e.preventDefault(); items[(i - 1 + items.length) % items.length].focus(); }
            const back = getComputedStyle(navFlyout).direction === 'rtl' ? 'ArrowRight' : 'ArrowLeft';
            if (e.key === 'Escape' || e.key === back) { e.preventDefault(); hideNavFlyout(); navFlyout.owner && navFlyout.owner.focus(); }
        });
        navFlyout.addEventListener('focusout', e => { if (!navFlyout.contains(e.relatedTarget)) hideNavFlyout(); });
        document.body.appendChild(navFlyout);
    }
    const onPage = item.getAttribute('aria-current') === 'page';
    const label = item.querySelector('.ui-nav-label');
    navFlyout.owner = item;
    navFlyout.innerHTML = `<div class="ui-fly-title">${escapeHtml(label ? label.textContent : page)}</div>` + tabs.map((btn, i) => {
        const copy = btn.cloneNode(true);
        const count = copy.querySelector('.ui-tab-n');
        const countText = count && !count.classList.contains('hidden') ? count.textContent.trim() : '';
        if (count) count.remove();
        const on = onPage && (btn.classList.contains('active') || btn.getAttribute('aria-selected') === 'true');
        return `<button type="button" role="menuitem" class="ui-fly-item${on ? ' is-on' : ''}" data-i="${i}">
            <span>${copy.innerHTML.trim()}</span>${countText ? `<small class="ui-nav-count${count.classList.contains('is-fail') ? ' is-fail' : ''}">${escapeHtml(countText)}</small>` : ''}</button>`;
    }).join('');
    navFlyout.querySelectorAll('.ui-fly-item').forEach(el => el.addEventListener('click', () => {
        tabs[Number(el.dataset.i)].click();
        hideNavFlyout();
        if (currentTab !== page) navigateTo(page);
    }));
    const rect = item.getBoundingClientRect();
    navFlyout.style.top = `${Math.max(8, Math.min(rect.top - 6, window.innerHeight - navFlyout.offsetHeight - 8))}px`;
    const rtl = getComputedStyle(item).direction === 'rtl';
    navFlyout.style.left = `${rtl ? rect.left - navFlyout.offsetWidth - 8 : rect.right + 8}px`;
    navFlyout.classList.add('is-open');
    navFlyout.style.top = `${Math.max(8, Math.min(rect.top - 6, window.innerHeight - navFlyout.offsetHeight - 8))}px`;
}

function initNavFlyouts() {
    Object.keys(NAV_SUBPAGE_TABS).forEach(page => {
        const item = document.getElementById(`tab-${page}`);
        if (!item) return;
        item.classList.toggle('has-sub', navSubpageTabs(page).length > 1);
        item.setAttribute('aria-haspopup', 'menu');
        item.addEventListener('mouseenter', () => showNavFlyout(item, page));
        item.addEventListener('mouseleave', () => { navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        item.addEventListener('focus', () => showNavFlyout(item, page));
        item.addEventListener('blur', e => { if (!navFlyout || !navFlyout.contains(e.relatedTarget)) navFlyoutTimer = setTimeout(hideNavFlyout, 150); });
        item.addEventListener('click', hideNavFlyout);
        item.addEventListener('keydown', e => {
            if (e.key !== 'ArrowRight') return;
            e.preventDefault();
            showNavFlyout(item, page);
            const first = navFlyout && navFlyout.querySelector('.ui-fly-item');
            if (first) first.focus();
        });
    });
    window.addEventListener('resize', hideNavFlyout);
}
document.addEventListener('DOMContentLoaded', initNavFlyouts);

function resetWindowPan() {
    const el = document.activeElement;
    const editing = el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
    if (editing) return;
    if (window.scrollX || window.scrollY || document.scrollingElement.scrollTop) window.scrollTo(0, 0);
}
window.addEventListener('scroll', resetWindowPan, { passive: true });
document.addEventListener('focusout', () => setTimeout(resetWindowPan, 300));
if (window.visualViewport) window.visualViewport.addEventListener('resize', () => setTimeout(resetWindowPan, 100));

function syncNavToggle() {
    const collapsed = document.documentElement.classList.contains('ui-nav-collapsed');
    const btn = document.getElementById('ui-nav-toggle');
    if (!btn) return;
    const label = collapsed ? 'Expand menu' : 'Collapse menu';
    btn.setAttribute('aria-label', label);
    btn.title = label;
    btn.setAttribute('aria-expanded', String(!collapsed));
}

function toggleNavCollapsed() {
    const collapsed = document.documentElement.classList.toggle('ui-nav-collapsed');
    try { localStorage.setItem('navCollapsed', collapsed ? '1' : '0'); } catch (e) {}
    if (typeof hideNavFlyout === 'function') hideNavFlyout();
    syncNavToggle();
}
document.addEventListener('DOMContentLoaded', syncNavToggle);
