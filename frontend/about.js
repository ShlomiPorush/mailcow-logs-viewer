// =============================================================================
// ABOUT - this app: whether what it connects to works, its version and its
// configuration. Moved out of Settings, which keeps only what can be edited.
// Classic script sharing the global scope; loaded after utils.js, app.js and settings.js.
// =============================================================================

async function loadAbout() {
    const box = document.getElementById('about-content');
    if (!box) return;
    const get = async url => {
        try {
            const res = await authenticatedFetch(url);
            return res.ok ? await res.json() : null;
        } catch (e) {
            return null;
        }
    };
    const [info, app, version, mailcow, rw, health] = await Promise.all([
        get('/api/settings/info'), get('/api/info'), get('/api/status/app-version'),
        get('/api/status/mailcow-connection'), get('/api/rw-status'), get('/api/health'),
    ]);
    if (!info) {
        box.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load the app information. Refresh the page to try again.</p>';
        return;
    }
    if (version) versionInfoCache.version_info = version;
    const appVersion = (app && app.version) || versionInfoCache.app_version || 'Unknown';
    const versionInfo = version || versionInfoCache.version_info || {};
    const config = info.configuration || {};

    box.innerHTML = `
        <div class="ui-list-head"><h2 class="ui-h2">What the app relies on</h2></div>
        <div class="ui-st-cards ui-about-health">${aboutHealthCards(info, mailcow, rw, health).join('')}</div>
        <div class="ui-dash-grid ui-status-pair">
            ${aboutVersionPanel(appVersion, versionInfo)}
            ${aboutConfigurationPanel(config)}
        </div>
    `;
    wireVersionPanel(box, appVersion, versionInfo);
}

// One card per thing the app depends on: is it set up, does it work, and where to fix it.
// The database comes first: without it nothing else works.
function aboutHealthCards(info, mailcow, rw, health) {
    const card = (label, tone, value, detail, actions) => `
        <div class="ui-st-card ui-about-card">
            <span class="ui-st-card-label">${escapeHtml(label)}</span>
            <b class="${tone ? `ui-${tone}` : ''}">${escapeHtml(value)}</b>
            <small>${detail}</small>
            ${actions ? `<div class="ui-chip-row">${actions}</div>` : ''}
        </div>`;
    const settingsBtn = section => `<button type="button" class="ui-btn ui-btn-sm" onclick="navigateTo('settings', { sub: '${section}' })">Settings</button>`;
    const mono = text => `<span class="ui-mono">${escapeHtml(text)}</span>`;
    const config = info.configuration || {};
    const smtp = info.smtp_configuration || {};
    const imap = info.dmarc_configuration || {};
    const geoip = info.geoip_configuration || {};
    const maxmind = config.maxmind_status;
    const cards = [];

    const dbOk = health && health.database === 'connected';
    const postgres = `PostgreSQL${config.database_version ? ` ${escapeHtml(config.database_version)}` : ''}`;
    cards.push(card('Database', health ? (dbOk ? 'ok' : 'fail') : 'warn', health ? (dbOk ? 'Connected' : 'Not connected') : 'Unknown',
        !health ? `Could not check ${postgres}.`
            : dbOk ? `${postgres}. Every log, message and report is stored here.`
                : `${postgres} is not answering. Nothing can be read or saved until it is back.`, ''));

    cards.push(card('mailcow API', !mailcow ? 'warn' : mailcow.connected ? 'ok' : 'fail',
        !mailcow ? 'Unknown' : mailcow.connected ? 'Connected' : 'Not connected',
        !config.mailcow_url ? 'Add the mailcow address and API key to start reading the logs.'
            : !mailcow ? `Could not check ${mono(config.mailcow_url)}.`
                : mailcow.connected ? `Logs are read from ${mono(config.mailcow_url)}.`
                    : `No new logs until ${mono(config.mailcow_url)} can be reached.`, settingsBtn('mailcow')));

    const rwOn = rw ? rw.rw_configured : mailcowRwConfigured;
    cards.push(card('Read-write API key', rwOn ? 'ok' : 'warn', rwOn ? 'Configured' : 'Not configured',
        rwOn ? 'You can ban addresses, release messages and edit maps in mailcow from here.'
            : 'View only. Add a read-write key to ban, release and edit from here.', settingsBtn('mailcow')));

    const smtpOn = smtp.enabled && smtp.configured !== false;
    cards.push(card('Email alerts (SMTP)', smtpOn ? 'ok' : '', smtpOn ? 'Configured' : 'Not set up',
        smtpOn ? `Alerts and the weekly summary are sent through ${mono(`${smtp.host || ''}${smtp.port ? `:${smtp.port}` : ''}`)}.`
            : 'Set it up to get alerts and the weekly summary by email.',
        (smtpOn ? '<button type="button" class="ui-btn ui-btn-sm" onclick="testSmtpConnection()">Test SMTP</button>' : '') + settingsBtn('smtp')));

    cards.push(card('Report mailbox (IMAP)', imap.imap_sync_enabled ? 'ok' : '', imap.imap_sync_enabled ? 'Collecting' : 'Not set up',
        imap.imap_sync_enabled ? `DMARC and TLS reports are collected from ${mono(imap.imap_host || '')}.`
            : 'Reports arrive only when you upload them. Connect a mailbox to collect them automatically.',
        (imap.imap_sync_enabled ? '<button type="button" class="ui-btn ui-btn-sm" onclick="testImapConnection()">Test IMAP</button>' : '') + settingsBtn('dmarc_imap')));

    let geoTone = '', geoValue = 'Not set up', geoDetail = 'Add a free MaxMind license key to see where IP addresses come from.';
    if (geoip.enabled) {
        const licenseBad = maxmind && maxmind.configured && maxmind.valid === false;
        const dbBad = geoip.db_valid === false;
        geoTone = licenseBad || dbBad ? 'fail' : 'ok';
        geoValue = licenseBad ? 'License invalid' : dbBad ? 'Database damaged' : 'Working';
        geoDetail = licenseBad ? `MaxMind refused the license key${maxmind.error ? `: ${escapeHtml(maxmind.error)}` : '.'}`
            : dbBad ? 'The location databases are damaged. Download them again in Settings.'
                : maxmind ? 'Shows the country and network of every IP address.'
                    : 'Shows the country and network of every IP address. The license has not been checked yet.';
    }
    cards.push(card('MaxMind GeoIP', geoTone, geoValue, geoDetail, settingsBtn('maxmind')));

    cards.push(card('Rspamd', config.rspamd_configured ? 'ok' : '', config.rspamd_configured ? 'Configured' : 'Not set up',
        config.rspamd_configured ? 'Spam Filter maps are read and kept in sync.'
            : 'Add the Rspamd password to see and sync the Spam Filter maps.', settingsBtn('mailcow')));

    // Basic Auth names its user, OAuth2 its provider
    const methods = [
        config.basic_auth_enabled ? `Basic Auth${config.auth_username ? ` (${escapeHtml(config.auth_username)})` : ''}` : '',
        config.oauth2_enabled ? `OAuth2${config.oauth2_provider_name ? ` (${escapeHtml(config.oauth2_provider_name)})` : ''}` : '',
    ].filter(Boolean);
    cards.push(card('Sign-in', config.auth_enabled ? 'ok' : 'warn', config.auth_enabled ? 'Required' : 'Open',
        config.auth_enabled ? `Signing in with ${methods.join(' or ') || 'a password'}.`
            : 'Anyone who can reach this app can see everything in it.', settingsBtn('auth')));
    return cards;
}

function aboutVersionPanel(appVersion, versionInfo) {
    return `
        <section class="ui-panel">
            <div class="ui-panel-head">Version</div>
            <div class="ui-kv"><span>Current Version</span><b><button type="button" id="current-version-text" class="ui-link-row ui-link" title="Click to view changelog">v${escapeHtml(appVersion)}</button></b></div>
            <div class="ui-kv"><span>Latest Version</span><b id="settings-latest-version">${renderLatestVersionState(versionInfo)}</b></div>
            <div class="ui-set-version-foot">
                <span id="settings-version-checked" class="ui-muted">${versionInfo.last_checked ? `Last checked: ${formatDate(versionInfo.last_checked)}` : ''}</span>
                <button type="button" id="check-version-btn" class="ui-btn ui-btn-sm">
                    <svg id="check-version-icon" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                    </svg>
                    <span id="check-version-text">Check Now</span>
                </button>
            </div>
            <div id="settings-update-note">${renderUpdateNote(versionInfo)}</div>
        </section>`;
}

function aboutConfigurationPanel(config) {
    const kv = (label, value, cls = '') => `<div class="ui-kv"><span>${label}</span><b class="${cls}">${value}</b></div>`;
    return `
        <section class="ui-panel">
            <div class="ui-panel-head">Configuration</div>
            ${kv('mailcow URL', escapeHtml(config.mailcow_url || 'N/A'), 'ui-mono ui-kv-small')}
            ${kv('Server IP', config.server_ip ? `<span class="ui-text-ok">✓</span> ${escapeHtml(config.server_ip)}` : '<span class="ui-muted">Not available</span>', 'ui-mono ui-kv-small')}
        </section>`;
}

// The version number opens its changelog; Check Now asks GitHub again
function wireVersionPanel(content, appVersion, versionInfo) {
    const currentVersionText = document.getElementById('current-version-text');
    if (currentVersionText) {
        currentVersionText.onclick = async () => {
            try {
                const versionForApi = appVersion.startsWith('v') ? appVersion.substring(1) : appVersion;
                const response = await authenticatedFetch(`/api/status/app-version/changelog/${encodeURIComponent(versionForApi)}`);
                if (response.ok) {
                    const data = await response.json();
                    showChangelogModal(data.changelog || 'No changelog available');
                } else {
                    showChangelogModal('Failed to load changelog');
                }
            } catch (error) {
                console.error('Failed to load changelog:', error);
                showChangelogModal('Failed to load changelog');
            }
        };
    }

    if (typeof marked !== 'undefined' && versionInfo && versionInfo.changelog) {
        marked.setOptions({ breaks: true, gfm: true });
        content.querySelectorAll('.update-changelog-content').forEach(el => {
            el.innerHTML = renderMarkdown(versionInfo.changelog);
        });
    }

    const btn = document.getElementById('check-version-btn');
    if (!btn) return;
    const REFRESH_PATH = 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15';
    btn.onclick = async () => {
        const icon = document.getElementById('check-version-icon');
        const text = document.getElementById('check-version-text');
        const reset = (cls, delay) => setTimeout(() => {
            btn.classList.remove(cls);
            if (text) text.textContent = 'Check Now';
            const path = icon && icon.querySelector('path');
            if (path) path.setAttribute('d', REFRESH_PATH);
            btn.disabled = false;
        }, delay);
        btn.disabled = true;
        if (icon) icon.classList.add('animate-spin');
        if (text) text.textContent = 'Checking...';
        try {
            const response = await authenticatedFetch('/api/status/app-version?force=true');
            const fresh = await response.json();
            versionInfoCache.version_info = fresh;
            updateVersionInfoUI(fresh);
            btn.classList.add('ui-btn-done');
            if (text) text.textContent = 'Done';
            if (icon) {
                icon.classList.remove('animate-spin');
                const path = icon.querySelector('path');
                if (path) path.setAttribute('d', 'M5 13l4 4L19 7');
            }
            btn.disabled = false;
            reset('ui-btn-done', 3000);
        } catch (error) {
            console.error('Failed to check version:', error);
            btn.classList.add('ui-btn-failed');
            if (text) text.textContent = 'Error';
            if (icon) icon.classList.remove('animate-spin');
            reset('ui-btn-failed', 2000);
        }
    };
}
