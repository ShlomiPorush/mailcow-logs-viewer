const APP_COLORS = {
    directions: {
        inbound: {
            badge: 'bg-indigo-100 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/20',
            bg: 'bg-indigo-100 dark:bg-indigo-500/25',
            text: 'text-indigo-700 dark:text-indigo-400'
        },
        outbound: {
            badge: 'bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-500/20',
            bg: 'bg-blue-100 dark:bg-blue-500/25',
            text: 'text-blue-700 dark:text-blue-400'
        },
        internal: {
            badge: 'bg-teal-100 dark:bg-teal-500/10 text-teal-800 dark:text-teal-300 border border-teal-200 dark:border-teal-500/20',
            bg: 'bg-teal-100 dark:bg-teal-500/25',
            text: 'text-teal-700 dark:text-teal-400'
        }
    },
    statuses: {
        delivered: {
            badge: 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-500/20',
            bg: 'bg-emerald-100 dark:bg-emerald-500/25',
            text: 'text-emerald-700 dark:text-emerald-400'
        },
        sent: {
            badge: 'bg-green-100 dark:bg-green-500/10 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-500/20',
            bg: 'bg-green-100 dark:bg-green-500/25',
            text: 'text-green-700 dark:text-green-400'
        },
        deferred: {
            badge: 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-500/20',
            bg: 'bg-yellow-100 dark:bg-yellow-500/25',
            text: 'text-yellow-700 dark:text-yellow-400'
        },
        bounced: {
            badge: 'bg-orange-100 dark:bg-orange-500/10 text-orange-700 dark:text-orange-300 border border-orange-200 dark:border-orange-500/20',
            bg: 'bg-orange-100 dark:bg-orange-500/25',
            text: 'text-orange-700 dark:text-orange-400'
        },
        rejected: {
            badge: 'bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-500/20',
            bg: 'bg-red-100 dark:bg-red-500/25',
            text: 'text-red-700 dark:text-red-400'
        },
        spam: {
            badge: 'bg-fuchsia-100 dark:bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300 border border-fuchsia-200 dark:border-fuchsia-500/20',
            bg: 'bg-fuchsia-100 dark:bg-fuchsia-500/25',
            text: 'text-fuchsia-700 dark:text-fuchsia-400'
        },
        discarded: {
            badge: 'bg-slate-100 dark:bg-slate-500/10 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-500/20',
            bg: 'bg-slate-100 dark:bg-slate-500/25',
            text: 'text-slate-700 dark:text-slate-400'
        },
        expired: {
            badge: 'bg-zinc-100 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-500/20',
            bg: 'bg-zinc-100 dark:bg-zinc-500/25',
            text: 'text-zinc-700 dark:text-zinc-400'
        }
    },
    default: {
        badge: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300',
        bg: 'bg-gray-100 dark:bg-gray-700',
        text: 'text-gray-600 dark:text-gray-400'
    }
};

function getDirectionBadgeClass(direction) {
    return APP_COLORS.directions[direction]?.badge || APP_COLORS.default.badge;
}

function getDirectionBgClass(direction) {
    return APP_COLORS.directions[direction]?.bg || APP_COLORS.default.bg;
}

function getDirectionTextClass(direction) {
    return APP_COLORS.directions[direction]?.text || APP_COLORS.default.text;
}

function getStatusBadgeClass(status) {
    return APP_COLORS.statuses[status]?.badge || APP_COLORS.default.badge;
}

function getStatusBgClass(status) {
    return APP_COLORS.statuses[status]?.bg || APP_COLORS.default.bg;
}

function getStatusTextClass(status) {
    return APP_COLORS.statuses[status]?.text || APP_COLORS.default.text;
}

function getStatusClass(status) {
    const statusColors = APP_COLORS.statuses[status];
    if (statusColors) {
        return statusColors.badge;
    }
    return APP_COLORS.default.badge;
}

function getDirectionClass(direction) {
    const directionColors = APP_COLORS.directions[direction];
    if (directionColors) {
        return directionColors.badge;
    }
    return APP_COLORS.default.badge;
}

const UI_STATUS_TONE = {
    delivered: 'ok', sent: 'ok', deferred: 'warn', bounced: 'fail', rejected: 'fail', spam: 'spam',
};

function uiTag(text, tone) {
    return `<span class="ui-tag${tone ? ` ui-tag-${tone}` : ''}">${escapeHtml(String(text))}</span>`;
}

const UI_DIRECTION_SHORT = { inbound: 'In', outbound: 'Out', internal: 'Int' };
function uiDirectionTag(direction, { short = false } = {}) {
    const known = ['inbound', 'outbound', 'internal'].includes(direction);
    const cls = `ui-tag ui-tag-dir${known ? ` ui-dir-${direction}` : ''}`;
    if (short && known) {
        return `<span class="${cls}" title="${direction}"><span aria-hidden="true">${UI_DIRECTION_SHORT[direction]}</span><span class="ui-sr-only">${direction}</span></span>`;
    }
    return `<span class="${cls}">${escapeHtml(String(direction))}</span>`;
}

function uiStatusTag(status) {
    return uiTag(status, UI_STATUS_TONE[status]);
}

function uiCorrelationTag(msg, { folder = false } = {}) {
    const status = getCorrelationStatusDisplay(msg);
    if (!status) return '';
    const tone = UI_STATUS_TONE[msg.final_status] || (msg.is_complete ? 'ok' : 'warn');
    let title = msg.final_status || (msg.is_complete ? 'Correlation complete' : 'Waiting for Postfix logs');
    if (folder && msg.dovecot_status === 'stored' && msg.dovecot_mailbox) title += `, folder ${msg.dovecot_mailbox}`;
    const text = status.display.replace(/^[^A-Za-z0-9]+\s*/, '');
    return `<span class="ui-tag ui-tag-${tone}" title="${escapeHtml(title)}">${escapeHtml(text)}</span>`;
}

function uiActionTone(action) {
    if (action === 'ban' || action === 'banned') return 'fail';
    if (action === 'unban') return 'ok';
    if (action === 'info') return 'info';
    return 'warn';
}

function uiActionTag(action) {
    return uiTag(getActionLabel(action), uiActionTone(action));
}

const UI_LOCK_ICON = '<svg class="ui-locked-icon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>';

function uiLocked(title, textHtml, action = 'settings') {
    const button = action === 'settings'
        ? `<button type="button" class="ui-btn ui-btn-sm" onclick="navigateTo('settings')" data-acts="admin">Open Settings</button>`
        : (action || '');
    return `<div class="ui-locked">${UI_LOCK_ICON}<div><b>${escapeHtml(title)}</b><p>${textHtml}</p></div>${button}</div>`;
}

const UI_RW_KEY_TEXT = 'requires a <strong>read-write API key</strong>. Add it in Settings > mailcow > Connection.';

const appAccess = { admin: true, scopes: new Set(), name: '' };

const ACCESS_ACT_AREAS = ['status', 'outbound', 'quarantine', 'security', 'rspamd', 'dmarc', 'domains', 'mailboxes'];

const ALERT_AREAS = ['security', 'domains', 'dmarc'];

let appAccessLoaded = null;
let appAccessReloading = false;

function appAccessKey(status) {
    const scopes = status && Array.isArray(status.scopes) ? [...status.scopes].sort() : [];
    return JSON.stringify([!status || status.is_admin !== false, scopes]);
}

function setAppAccess(status) {
    if (appAccessLoaded === null) appAccessLoaded = appAccessKey(status);
    appAccess.admin = !status || status.is_admin !== false;
    appAccess.scopes = new Set(status && Array.isArray(status.scopes) ? status.scopes : []);
    appAccess.name = status && typeof status.user_name === 'string' ? status.user_name : '';
    const root = document.documentElement;
    ACCESS_ACT_AREAS.forEach(area => root.classList.toggle(`ui-no-act-${area}`, !userCan(area, 'write')));
    root.classList.toggle('ui-no-act-alerts', !userCan('alerts', 'write'));
    root.classList.toggle('ui-no-admin', !appAccess.admin);
}

function appAccessCheck(status) {
    if (appAccessLoaded === null || !status || status.authenticated !== true) return false;
    if (appAccessKey(status) === appAccessLoaded) return false;
    if (!appAccessReloading) {
        appAccessReloading = true;
        showToast('Your access changed.', 'info');
        setTimeout(() => {
            location.reload();
            setTimeout(() => { appAccessReloading = false; }, 5000);
        }, 1500);
    }
    return true;
}

function userIsAdmin() {
    return appAccess.admin;
}

function userCan(area, kind = 'read') {
    if (appAccess.admin) return true;
    if (area === 'admin' || area === 'settings') return false;
    if (area === 'alerts') return ALERT_AREAS.some(a => appAccess.scopes.has(`${a}:${kind}`));
    return appAccess.scopes.has(`${area}:${kind}`);
}

const UI_NOT_PERMITTED = 'You do not have permission for this.';
let uiNotPermittedAt = 0;

function uiNotPermitted() {
    if (Date.now() - uiNotPermittedAt < 10000) return;
    uiNotPermittedAt = Date.now();
    showToast(UI_NOT_PERMITTED, 'error');
}

function uiMayAct(area) {
    if (userCan(area, 'write')) return true;
    uiNotPermitted();
    return false;
}

function uiSaveBar(id, { save = '', discard = '', form = '' } = {}) {
    const saveAttrs = form ? `type="submit" form="${form}"` : `type="button" onclick="${save}"`;
    return `<div class="ui-savebar hidden" id="${id}" role="region" aria-label="Unsaved changes">
            <span class="ui-savebar-count" aria-live="polite"></span>
            <button type="button" class="ui-btn ui-savebar-discard" onclick="${discard}">Discard</button>
            <button ${saveAttrs} class="ui-btn ui-savebar-save">Save changes</button>
        </div>`;
}

function uiSaveBarUpdate(id, count) {
    const bar = document.getElementById(id);
    if (!bar) return;
    bar.classList.toggle('hidden', !count);
    const label = bar.querySelector('.ui-savebar-count');
    if (label) label.textContent = `${count} unsaved change${count === 1 ? '' : 's'}`;
}

const uiActionsRunning = new Set();
async function uiOnce(key, work, button = null, busyText = '') {
    if (uiActionsRunning.has(key)) return undefined;
    uiActionsRunning.add(key);
    const kept = button ? [...button.childNodes] : null;
    const wasDisabled = button ? button.disabled : false;
    if (button) {
        button.disabled = true;
        button.setAttribute('aria-busy', 'true');
        if (busyText) button.textContent = busyText;
    }
    try {
        return await work();
    } finally {
        uiActionsRunning.delete(key);
        if (button) {
            button.replaceChildren(...kept);
            button.disabled = wasDisabled;
            button.removeAttribute('aria-busy');
        }
    }
}

function uiRetryButton(call) {
    return ` <button type="button" class="ui-link-row ui-link" onclick="uiRetrying(this); ${call}">Try again</button>`;
}
function uiRetrying(button) {
    const note = button.closest('p');
    const host = button.closest('[data-shown]');
    if (host) delete host.dataset.shown;
    if (note) note.outerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
}

function uiLoadingShow(el) {
    if (!el) return;
    if (!el.uiSpinner) el.uiSpinner = [...el.childNodes].map(node => node.cloneNode(true));
    else el.replaceChildren(...el.uiSpinner.map(node => node.cloneNode(true)));
    el.classList.remove('hidden');
}

function uiSaveBarBusy(id, busy) {
    const bar = document.getElementById(id);
    if (!bar) return;
    bar.querySelectorAll('button').forEach(b => { b.disabled = busy; });
    const save = bar.querySelector('.ui-savebar-save');
    if (save) save.textContent = busy ? 'Saving...' : 'Save changes';
}

function getCorrelationStatusDisplay(msg) {
    if (msg.final_status) {
        const statusEmoji = {
            'delivered': '✓',
            'sent': '✓',
            'bounced': '↩',
            'rejected': '✗',
            'deferred': '⏳',
            'spam': '⚠',
            'discarded': '⊘',
            'expired': '⏸'
        };
        const statusText = {
            'delivered': 'Delivered',
            'sent': 'Sent',
            'bounced': 'Bounced',
            'rejected': 'Rejected',
            'deferred': 'Deferred',
            'spam': 'Spam',
            'discarded': 'Discarded',
            'expired': 'Expired'
        };
        const emoji = statusEmoji[msg.final_status] || '•';
        const text = statusText[msg.final_status] || msg.final_status;
        return { display: `${emoji} ${text}`, class: getStatusClass(msg.final_status) };
    }

    if (msg.is_complete === true) {
        return { display: '✓ Linked', class: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' };
    }

    if (msg.is_complete === false) {
        return { display: '⏳ Pending', class: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300' };
    }

    return null;
}

function getActionLabel(action) {
    switch (action) {
        case 'ban':
            return 'BAN';
        case 'unban':
            return 'UNBAN';
        case 'banned':
            return 'BAN';
        case 'warning':
            return 'warning';
        case 'info':
            return 'info';
        default:
            return action || 'warning';
    }
}

function getActionClass(action) {
    switch (action) {
        case 'ban':
        case 'banned':
            return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300';
        case 'unban':
            return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300';
        case 'warning':
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
        case 'info':
            return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300';
        default:
            return 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-300';
    }
}

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    let cleanText = String(text).replace(/\\"/g, '"');
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return cleanText.replace(/[&<>"']/g, function (m) { return map[m]; });
}

function uiCountLabel(n, one, many) {
    const count = Number(n) || 0;
    return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

// escapeHtml is not enough here: the browser decodes &#039; before the JS runs, so a quote breaks out.
function escapeJsArg(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/\\/g, '\\\\')
        .replace(/'/g, "\\'")
        .replace(/"/g, '\\x22')
        .replace(/</g, '\\x3c')
        .replace(/>/g, '\\x3e')
        .replace(/&/g, '\\x26')
        .replace(/\r/g, '\\r')
        .replace(/\n/g, '\\n');
}

function escapeRegex(string) {
    return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function markdownCallouts(html) {
    if (typeof document === 'undefined' || !/\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]/i.test(html)) return html;
    const tpl = document.createElement('template');
    tpl.innerHTML = html;
    tpl.content.querySelectorAll('blockquote').forEach(quote => {
        const first = quote.querySelector('p');
        const match = first && first.innerHTML.match(/^\s*\[!(NOTE|TIP|IMPORTANT|WARNING|CAUTION)\]\s*(<br>)?\s*/i);
        if (!match) return;
        const type = match[1].toLowerCase();
        first.innerHTML = first.innerHTML.slice(match[0].length);
        const box = document.createElement('div');
        box.className = `markdown-alert markdown-alert-${type}`;
        const title = document.createElement('p');
        title.className = 'markdown-alert-title';
        title.textContent = type.charAt(0).toUpperCase() + type.slice(1);
        box.append(title, ...quote.childNodes);
        if (!first.textContent.trim()) first.remove();
        quote.replaceWith(box);
    });
    return tpl.innerHTML;
}

function renderMarkdown(markdownText) {
    const html = typeof marked !== 'undefined' ? marked.parse(markdownText || '') : '';
    if (html && typeof DOMPurify !== 'undefined') {
        return markdownCallouts(DOMPurify.sanitize(html));
    }
    return escapeHtml(markdownText || '');
}

function formatListTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    if (isNaN(date)) return '-';
    const today = zonedDateString(new Date());
    const day = zonedDateString(date);
    if (day === today) return formatClock(date);
    return day.slice(0, 4) === today.slice(0, 4) ? formatDayMonth(date) : formatDay(date);
}

let uiMenuSeq = 0;
function uiMenu(label, itemsHtml, { small = true, icon = '', cls = '', attrs = '' } = {}) {
    const id = `ui-menu-${++uiMenuSeq}`;
    const button = icon
        ? `<button type="button" class="ui-icon-btn${cls ? ` ${cls}` : ''}" popovertarget="${id}" aria-haspopup="menu" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}"${attrs ? ` ${attrs}` : ''}>${icon}</button>`
        : `<button type="button" class="ui-btn${small ? ' ui-btn-sm' : ''}${cls ? ` ${cls}` : ''}" popovertarget="${id}" aria-haspopup="menu"${attrs ? ` ${attrs}` : ''}>${escapeHtml(label)}</button>`;
    return `${button}
        <div id="${id}" popover class="ui-menu" role="menu" onclick="if (event.target.closest('button')) this.hidePopover()">${itemsHtml}</div>`;
}

let uiHelpSeq = 0;
function uiHelp(name, text) {
    const id = `ui-help-${++uiHelpSeq}`;
    const paragraphs = [].concat(text).map(p => `<p>${escapeHtml(p)}</p>`).join('');
    return `<span class="ui-field-help" role="button" tabindex="0" data-help="${id}" aria-controls="${id}" aria-expanded="false" aria-label="More about ${escapeHtml(name)}">
            <svg width="15" height="15" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" aria-hidden="true"><circle cx="8" cy="8" r="6.5"/><path d="M8 7.3V11M8 4.9v.1"/></svg></span>
        <div id="${id}" popover class="ui-field-help-panel">${paragraphs}</div>`;
}

// Under the whole field
function uiHelpPlace(panel, opener) {
    const name = opener.parentElement.getBoundingClientRect();
    const row = (opener.closest('.ui-set-field, .ui-set-bool') || opener).getBoundingClientRect();
    const rtl = getComputedStyle(opener).direction === 'rtl';
    const left = rtl ? name.right - panel.offsetWidth : name.left;
    panel.style.left = `${Math.max(8, Math.min(left, window.innerWidth - panel.offsetWidth - 8))}px`;
    const below = row.bottom - 8;
    panel.style.top = `${below + panel.offsetHeight > window.innerHeight - 8 ? Math.max(8, row.top - panel.offsetHeight + 8) : below}px`;
}

function uiInitHelp() {
    let closing = 0;
    const panelOf = el => (el ? document.getElementById(el.dataset.help) : null);
    const setOpen = (panel, open) => {
        if (!panel || panel.matches(':popover-open') === open) return;
        if (!open) return panel.hidePopover();
        panel.showPopover();
        const opener = document.querySelector(`[data-help="${panel.id}"]`);
        if (opener) uiHelpPlace(panel, opener);
    };
    const hovered = event => {
        if (event.pointerType !== 'mouse' || !(event.target instanceof Element)) return null;
        const spot = event.target.closest('.ui-field-help, .ui-field-help-panel');
        return spot && (spot.classList.contains('ui-field-help-panel') ? spot : panelOf(spot));
    };
    document.addEventListener('pointerover', event => {
        const panel = hovered(event);
        if (!panel) return;
        clearTimeout(closing);
        setOpen(panel, true);
    });
    document.addEventListener('pointerout', event => {
        const panel = hovered(event);
        if (panel) closing = setTimeout(() => setOpen(panel, false), 250);
    });
    let press = null;
    document.addEventListener('pointerdown', event => {
        const opener = event.target instanceof Element ? event.target.closest('.ui-field-help') : null;
        const panel = panelOf(opener);
        press = panel ? { opener, open: panel.matches(':popover-open') } : null;
    }, true);
    document.addEventListener('pointercancel', () => { press = null; }, true);
    document.addEventListener('click', event => {
        const opener = event.target instanceof Element ? event.target.closest('.ui-field-help') : null;
        const panel = panelOf(opener);
        const wasOpen = press && press.opener === opener ? press.open : panel && panel.matches(':popover-open');
        press = null;
        if (panel) setOpen(panel, event.pointerType === 'mouse' || !wasOpen);
    });
    document.addEventListener('keydown', event => {
        if (event.key !== 'Enter' && event.key !== ' ') return;
        const panel = panelOf(event.target instanceof Element && event.target.closest('.ui-field-help'));
        if (!panel) return;
        event.preventDefault();
        press = null;
        setOpen(panel, !panel.matches(':popover-open'));
    });
    document.addEventListener('beforetoggle', event => {
        const panel = event.target;
        if (!(panel instanceof HTMLElement) || !panel.classList.contains('ui-field-help-panel')) return;
        const opener = document.querySelector(`[data-help="${panel.id}"]`);
        if (opener) opener.setAttribute('aria-expanded', String(event.newState === 'open'));
    }, true);
}

// Called once at startup
function uiInitMenus() {
    uiInitHelp();
    document.addEventListener('toggle', event => {
        const menu = event.target;
        if (!(menu instanceof HTMLElement) || !menu.classList.contains('ui-menu') || event.newState !== 'open') return;
        const button = document.querySelector(`[popovertarget="${menu.id}"], [aria-controls="${menu.id}"]`);
        if (!button) return;
        const r = button.getBoundingClientRect();
        const rtl = getComputedStyle(button).direction === 'rtl';
        const left = rtl ? r.left : r.right - menu.offsetWidth;
        menu.style.left = `${Math.max(8, Math.min(left, window.innerWidth - menu.offsetWidth - 8))}px`;
        const below = r.bottom + 4;
        menu.style.top = `${below + menu.offsetHeight > window.innerHeight - 8 ? Math.max(8, r.top - menu.offsetHeight - 4) : below}px`;
    }, true);

    window.addEventListener('scroll', event => {
        if (event.target instanceof Element && event.target.closest('.ui-field-help-panel')) return;
        document.querySelectorAll('.ui-menu:popover-open, .ui-field-help-panel:popover-open').forEach(menu => menu.hidePopover());
    }, true);
}

function formatAgo(isoString) {
    if (!isoString) return '-';
    const minutes = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 60000));
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours} h ago`;
    return `${Math.round(hours / 24)} d ago`;
}

const uiAgoLabels = new Map();
let uiAgoTimer = null;
function uiAgo(el, iso, prefix = '') {
    if (!el || !iso) return;
    uiAgoLabels.set(el, { iso, prefix });
    el.textContent = `${prefix}${formatAgo(iso)}`;
    el.title = formatTime(iso);
    if (!uiAgoTimer && typeof setInterval === 'function') {
        uiAgoTimer = setInterval(() => uiAgoLabels.forEach((v, node) => {
            if (!node.isConnected) uiAgoLabels.delete(node);
            else node.textContent = `${v.prefix}${formatAgo(v.iso)}`;
        }), 30000);
    }
}

function appTz() {
    return (typeof appTimezone === 'string' && appTimezone) || 'UTC';
}

const tzPartFormats = new Map();
function tzPartFormat(tz) {
    if (!tzPartFormats.has(tz)) {
        tzPartFormats.set(tz, new Intl.DateTimeFormat('en-US', {
            timeZone: tz, hourCycle: 'h23', weekday: 'short',
            year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit'
        }));
    }
    return tzPartFormats.get(tz);
}

function zonedParts(value, tz = appTz()) {
    const date = value instanceof Date ? value : new Date(value);
    const parts = {};
    for (const p of tzPartFormat(tz).formatToParts(date)) parts[p.type] = p.value;
    return {
        year: +parts.year, month: +parts.month, day: +parts.day,
        hour: +parts.hour, minute: +parts.minute, second: +parts.second, weekday: parts.weekday
    };
}

function zonedTimeToDate(year, month, day, hour = 0, minute = 0, second = 0, tz = appTz()) {
    const wall = Date.UTC(year, month - 1, day, hour, minute, second);
    const offsetAt = t => {
        const p = zonedParts(new Date(t), tz);
        return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - t;
    };
    const wallOf = t => t + offsetAt(t);
    const early = wall - offsetAt(wall - 86400000);
    const late = wall - offsetAt(wall + 86400000);
    const fits = [early, late].filter(t => wallOf(t) === wall);
    return new Date(fits.length ? Math.min(...fits) : early);
}

const pad2 = n => String(n).padStart(2, '0');

function zonedDateString(value = new Date(), tz = appTz()) {
    const p = zonedParts(value, tz);
    return `${p.year}-${pad2(p.month)}-${pad2(p.day)}`;
}

function addDaysToDateString(dateStr, days) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const next = new Date(Date.UTC(y, m - 1, d + days));
    return `${next.getUTCFullYear()}-${pad2(next.getUTCMonth() + 1)}-${pad2(next.getUTCDate())}`;
}

function zonedDayStart(dateStr, tz = appTz()) {
    const [y, m, d] = dateStr.split('-').map(Number);
    return zonedTimeToDate(y, m, d, 0, 0, 0, tz);
}

function isZonedMidnight(t) {
    const p = zonedParts(t);
    return new Date(t).getTime() % 1000 === 0 && p.hour === 0 && p.minute === 0 && p.second === 0;
}

function addDaysInZone(value, days, tz = appTz()) {
    const p = zonedParts(value, tz);
    return zonedTimeToDate(p.year, p.month, p.day + days, p.hour, p.minute, p.second, tz);
}

function formatDayKey(dateStr, { year = true, weekday = '' } = {}) {
    const [y, m, d] = String(dateStr).slice(0, 10).split('-').map(Number);
    if (!y || !m || !d) return '-';
    return writeDate({ year: y, month: m, day: d }, { year, weekday });
}

function toZonedInputValue(value, tz = appTz()) {
    const p = zonedParts(value, tz);
    return `${p.year}-${pad2(p.month)}-${pad2(p.day)}T${pad2(p.hour)}:${pad2(p.minute)}`;
}

function fromZonedInputValue(text, tz = appTz()) {
    const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(text || '');
    if (!m) return null;
    return zonedTimeToDate(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), tz);
}

const DATE_FORMAT_ORDERS = {
    'DD/MM/YYYY': { order: ['day', 'month', 'year'], sep: '/' },
    'MM/DD/YYYY': { order: ['month', 'day', 'year'], sep: '/' },
    'DD.MM.YYYY': { order: ['day', 'month', 'year'], sep: '.' },
    'YYYY-MM-DD': { order: ['year', 'month', 'day'], sep: '-' },
};

function appDateFmt() {
    return (typeof appDateFormat === 'string' && DATE_FORMAT_ORDERS[appDateFormat]) ? appDateFormat : 'browser';
}

function appTimeFmt() {
    return (typeof appTimeFormat === 'string' && ['24h', '12h', 'browser'].includes(appTimeFormat)) ? appTimeFormat : '24h';
}

const browserFormats = new Map();
function browserFormat(options) {
    const key = JSON.stringify(options);
    if (!browserFormats.has(key)) browserFormats.set(key, new Intl.DateTimeFormat(undefined, { ...options, timeZone: 'UTC' }));
    return browserFormats.get(key);
}

function writeDate(p, { year = true, weekday = '', fmt = appDateFmt() } = {}) {
    const utc = new Date(Date.UTC(p.year, p.month - 1, p.day));
    let text;
    if (!DATE_FORMAT_ORDERS[fmt]) fmt = 'browser';
    if (fmt === 'browser') {
        text = browserFormat({ day: '2-digit', month: '2-digit', ...(year ? { year: 'numeric' } : {}) }).format(utc);
    } else {
        const { order, sep } = DATE_FORMAT_ORDERS[fmt];
        const part = { day: pad2(p.day), month: pad2(p.month), year: String(p.year).padStart(4, '0') };
        text = order.filter(k => year || k !== 'year').map(k => part[k]).join(sep);
    }
    if (!weekday) return text;
    return `${new Intl.DateTimeFormat('en-US', { weekday, timeZone: 'UTC' }).format(utc)}, ${text}`;
}

function writeClock(p, { seconds = false, compact = false, fmt = appTimeFmt() } = {}) {
    if (!['24h', '12h', 'browser'].includes(fmt)) fmt = '24h';
    const whole = compact && !seconds && p.minute === 0;
    if (fmt === 'browser') {
        const rest = { minute: '2-digit', ...(seconds ? { second: '2-digit' } : {}) };
        const twelve = ['h11', 'h12'].includes(browserFormat({ hour: 'numeric', ...rest }).resolvedOptions().hourCycle);
        const options = twelve && whole ? { hour: 'numeric' } : { hour: twelve ? 'numeric' : '2-digit', ...rest };
        return browserFormat(options).format(new Date(Date.UTC(2000, 0, 1, p.hour, p.minute, p.second || 0)));
    }
    const tail = `${pad2(p.minute)}${seconds ? `:${pad2(p.second || 0)}` : ''}`;
    if (fmt === '12h') return `${(p.hour % 12) || 12}${whole ? '' : `:${tail}`} ${p.hour < 12 ? 'AM' : 'PM'}`;
    return `${pad2(p.hour)}:${tail}`;
}

function zonedOrNull(value) {
    if (value === null || value === undefined || value === '') return null;
    const date = value instanceof Date ? value : new Date(value);
    return isNaN(date) ? null : zonedParts(date);
}

function formatTime(value, { seconds = true } = {}) {
    const p = zonedOrNull(value);
    return p ? `${writeDate(p)}, ${writeClock(p, { seconds })}` : '-';
}

function formatDate(value) {
    return formatTime(value);
}

function formatDay(value, { year = true, weekday = '' } = {}) {
    const p = zonedOrNull(value);
    return p ? writeDate(p, { year, weekday }) : '-';
}

function formatDayMonth(value, { weekday = '' } = {}) {
    return formatDay(value, { year: false, weekday });
}

function formatClock(value, { seconds = false, compact = false } = {}) {
    const p = zonedOrNull(value);
    return p ? writeClock(p, { seconds, compact }) : '-';
}

function formatClockAt(hour, minute) {
    return writeClock({ hour, minute, second: 0 });
}

function uiTime(value, text, { title = '', cls = '' } = {}) {
    const ms = value === null || value === undefined || value === '' ? NaN : new Date(value).getTime();
    const attrs = `${cls ? ` class="${escapeHtml(cls)}"` : ''}${isNaN(ms) ? '' : ` datetime="${new Date(ms).toISOString()}"`}${title ? ` title="${escapeHtml(title)}"` : ''}`;
    return `<time${attrs}>${escapeHtml(text)}</time>`;
}

function formatSeconds(seconds) {
    if (seconds >= 86400) {
        const days = Math.floor(seconds / 86400);
        const hours = Math.floor((seconds % 86400) / 3600);
        return hours > 0 ? `${days}d ${hours}h` : `${days}d`;
    }
    if (seconds >= 3600) {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return mins > 0 ? `${hours}h ${mins}m` : `${hours}h`;
    }
    if (seconds >= 60) {
        const mins = Math.floor(seconds / 60);
        return `${mins}m`;
    }
    return `${seconds}s`;
}

function formatSize(bytes) {
    if (!bytes) return '0 B';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(2) + ' MB';
}

function formatBytes(bytes) {
    if (bytes === 0 || bytes === '0') return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function copyToClipboard(text, event, label) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    if (!navigator.clipboard) {
        showToast('Copying needs HTTPS. Select the text and copy it yourself.', 'error');
        return;
    }
    navigator.clipboard.writeText(text).then(() => {
        showToast(label ? `${label} copied` : 'Copied: ' + text, 'success');
        if (event && event.currentTarget) {
            const icon = event.currentTarget.querySelector('.copy-icon');
            if (icon) {
                icon.classList.add('copied');
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>';
                setTimeout(() => {
                    icon.classList.remove('copied');
                    icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>';
                }, 1500);
            }
        }
    }).catch(err => {
        console.error('Copy failed:', err);
        showToast('Failed to copy', 'error');
    });
}

function copyableText(text, extraClasses) {
    if (!text || text === '-') return escapeHtml(text || '-');
    const cls = extraClasses ? ' ' + extraClasses : '';
    const escaped = escapeHtml(text);
    const safeText = escapeJsArg(text);
    return `<span class="copyable${cls}" onclick="copyToClipboard('${safeText}', event)" title="Click to copy"><bdi>${escaped}</bdi><svg class="copy-icon w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></span>`;
}

const UI_ENTITY_KINDS = ['ip', 'address', 'domain'];
const UI_ENTITY_IPV4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const UI_ENTITY_LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i;

function entityIsIp(value) {
    const v = String(value);
    if (UI_ENTITY_IPV4.test(v)) return true;
    if (!v.includes(':') || !/^[0-9a-f:.]+$/i.test(v) || v.length > 45) return false;
    const halves = v.split('::');
    if (halves.length > 2) return false;
    const groups = halves.map(h => (h ? h.split(':') : []));
    const last = groups[groups.length - 1];
    const tail = last.length && last[last.length - 1].includes('.') ? last.pop() : null;
    if (tail !== null && !UI_ENTITY_IPV4.test(tail)) return false;
    const parts = groups.flat();
    if (!parts.every(p => /^[0-9a-f]{1,4}$/i.test(p))) return false;
    const count = parts.length + (tail !== null ? 2 : 0);
    return halves.length === 2 ? count < 8 : count === 8;
}

function entityIsDomain(value) {
    let v = String(value);
    if (v.endsWith('.')) v = v.slice(0, -1);
    if (!v || v.length > 253 || /[@/:\s]/.test(v)) return false;
    const labels = v.split('.');
    if (labels.length < 2 || /^\d+$/.test(labels[labels.length - 1])) return false;
    return labels.every(l => UI_ENTITY_LABEL.test(l) || (/[^\x00-\x7f]/.test(l) && l.length <= 63 && /^[\p{L}\p{M}\p{N}_-]+$/u.test(l)));
}

function entityKindOf(value) {
    if (value === null || value === undefined) return null;
    const v = String(value).trim();
    if (!v || v.length > 254 || /[\s\x00-\x1f\x7f]/.test(v)) return null;
    if (v.includes('@')) {
        const at = v.lastIndexOf('@');
        const local = v.slice(0, at);
        return local && local.length <= 64 && entityIsDomain(v.slice(at + 1)) ? 'address' : null;
    }
    if (entityIsIp(v)) return 'ip';
    if (entityIsDomain(v)) return 'domain';
    return null;
}

const ENTITY_CARD_AREAS = {
    ip: ['messages', 'security', 'mailboxes', 'dmarc', 'status'],
    address: ['messages', 'security', 'mailboxes', 'outbound'],
    domain: ['messages', 'security', 'mailboxes', 'dmarc', 'outbound', 'domains'],
};

function userCanOpenEntity(kind) {
    return (ENTITY_CARD_AREAS[kind] || []).every(area => userCan(area));
}

function uiEntity(kind, value, { mono = false, cls = '', plain = false, label = '', fit = false } = {}) {
    const text = value === null || value === undefined ? '' : String(value).trim();
    const found = entityKindOf(text);
    if (!found || (kind !== 'auto' && kind !== found) || !userCanOpenEntity(found)) {
        if (plain || !text || text === '-') return escapeHtml(text || '-');
        return copyableText(text, [mono ? 'ui-mono' : '', cls].filter(Boolean).join(' '));
    }
    const what = { ip: 'IP address', address: 'address', domain: 'domain' }[found];
    const v = uiEntityAttr(text);
    const at = text.lastIndexOf('@');
    const shown = label ? escapeHtml(label)
        : fit && found === 'address' && at > 0 ? `<span class="ui-fit-loc">${uiEntityAttr(text.slice(0, at))}</span><span class="ui-fit-dom">${uiEntityAttr(text.slice(at))}</span>`
        : v;
    return `<span class="ui-ent${cls ? ` ${escapeHtml(cls)}` : ''}"><button type="button" class="ui-ent-btn${mono ? ' ui-mono' : ''}" data-entity-kind="${found}" data-entity-value="${v}" title="Open the card of this ${what}"><bdi>${shown}</bdi></button>`
        + `<button type="button" class="ui-ent-copy" data-entity-copy="${v}" title="Copy" aria-label="Copy ${v}"><svg class="copy-icon" width="13" height="13" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button></span>`;
}

function uiEntityAttr(text) {
    return String(text).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' })[c]);
}

function uiEntityClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) return;
    const copy = target.closest('[data-entity-copy]');
    const entity = copy ? null : target.closest('[data-entity-kind]');
    if (!copy && !entity) return;
    if (entity && uiEntitySelecting(event, entity)) return;
    event.preventDefault();
    event.stopPropagation();
    if (copy) {
        copyToClipboard(copy.dataset.entityCopy, { currentTarget: copy, stopPropagation() {}, preventDefault() {} });
        return;
    }
    const menu = entity.closest('.ui-menu');
    if (menu && typeof menu.hidePopover === 'function') { try { menu.hidePopover(); } catch (e) {} }
    if (typeof openEntityCard === 'function') openEntityCard(entity.dataset.entityKind, entity.dataset.entityValue, { from: entity });
}
if (typeof document !== 'undefined' && document && typeof document.addEventListener === 'function') {
    document.addEventListener('click', uiEntityClick, true);
}

function uiEntitySelecting(event, entity) {
    if (event.button || event.shiftKey || event.ctrlKey || event.metaKey || event.altKey) return true;
    if (!event.detail) return false;
    const selection = typeof window.getSelection === 'function' ? window.getSelection() : null;
    if (!selection || selection.isCollapsed || !selection.rangeCount || !String(selection)) return false;
    return selection.getRangeAt(0).intersectsNode(entity) || uiPressMoved(event) || event.detail > 1;
}

function showToast(message, type = 'info', options = {}) {
    const existingToast = document.getElementById('toast-notification');
    const heldToast = document.getElementById('toast-refusal');
    const onScreen = el => !!el && el.style.opacity !== '0';
    if (!options.action && [existingToast, heldToast].some(el => onScreen(el) && el.dataset.message === String(message))) return;
    const focusWasInIt = !!existingToast && existingToast.contains(document.activeElement);
    if (existingToast && !heldToast && onScreen(existingToast) && existingToast.dataset.message === UI_NOT_PERMITTED) {
        existingToast.id = 'toast-refusal';
    } else if (existingToast) {
        existingToast.remove();
    }

    const icons = {
        'success': '✓',
        'error': '✗',
        'warning': '⚠',
        'info': 'ℹ'
    };
    const kind = icons[type] ? type : 'info';

    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.dataset.message = String(message);
    toast.className = `ui-toast ui-toast-${kind}`;
    toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    toast.innerHTML = `
        <span class="ui-toast-icon" aria-hidden="true">${icons[kind]}</span>
        <p>${escapeHtml(message)}</p>
        ${options.action ? `<button type="button" class="ui-btn ui-btn-sm ui-toast-action"${options.action.ariaLabel ? ` aria-label="${escapeHtml(options.action.ariaLabel)}"` : ''}>${escapeHtml(options.action.label)}</button>` : ''}
        <button type="button" onclick="this.parentElement.remove()" class="ui-icon-btn" title="Close" aria-label="Close">${UI_CLOSE_ICON}</button>
    `;
    let busy = false;
    let holdNow = () => {};
    if (options.action) {
        const button = toast.querySelector('.ui-toast-action');
        button.addEventListener('click', () => {
            if (busy) return;
            const result = options.action.onAction();
            if (!result || typeof result.then !== 'function') { toast.remove(); return; }
            busy = true;
            holdNow();
            button.setAttribute('aria-disabled', 'true');
            Promise.resolve(result).catch(() => {}).finally(() => { if (toast.isConnected) toast.remove(); });
        });
    }

    document.body.appendChild(toast);
    const held = document.getElementById('toast-refusal');
    if (held) held.style.bottom = `${parseFloat(getComputedStyle(toast).bottom) + toast.offsetHeight + 8}px`;
    if (options.duration === Infinity) {
        if (focusWasInIt) toast.querySelector('button').focus({ preventScroll: true });
        return;
    }

    let left = options.duration || 4000;
    let started = Date.now();
    let timer = null;
    const hold = () => busy || toast.matches(':hover') || toast.contains(document.activeElement);
    let fading = false;
    let removing = null;
    const fade = () => {
        if (!toast.parentElement) return;
        if (busy) { timer = null; return; }
        fading = true;
        toast.style.opacity = '0';
        toast.style.transition = 'opacity 0.3s';
        removing = setTimeout(() => toast.remove(), 300);
    };
    const run = () => {
        clearTimeout(timer);
        started = Date.now();
        timer = setTimeout(fade, left);
    };
    const pause = () => {
        if (fading) {
            clearTimeout(removing);
            fading = false;
            timer = null;
            left = 1500;
            toast.style.opacity = '';
            toast.style.transition = '';
            return;
        }
        if (timer === null) return;
        clearTimeout(timer);
        timer = null;
        left = Math.max(1500, left - (Date.now() - started));
        toast.style.opacity = '';
        toast.style.transition = '';
    };
    const resume = () => { if (timer === null && !hold()) run(); };
    holdNow = pause;
    toast.addEventListener('mouseenter', pause);
    toast.addEventListener('focusin', pause);
    toast.addEventListener('mouseleave', () => setTimeout(resume, 0));
    toast.addEventListener('focusout', () => setTimeout(resume, 0));
    if (focusWasInIt) toast.querySelector('button').focus({ preventScroll: true });
    if (!hold()) run();
}

const UI_CLOSE_ICON = '<svg width="20" height="20" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';

const UI_DIALOG_SIZES = { sm: 'ui-dialog-sm', md: 'ui-dialog-md', wide: '' };

function uiDialog({ id, title, size, body = '', foot = '', close = null, role = 'dialog', label = '', titleId = '', describedBy = '',
    bodyId = '', bodyClass = '', footId = '', footClass = '', footHidden = false, dialogClass = '', backdropClass = '',
    form = null, dataset = null, backdropClose = null } = {}) {
    if (!(size in UI_DIALOG_SIZES)) throw new Error(`uiDialog: size must be one of ${Object.keys(UI_DIALOG_SIZES).join(', ')}`);
    if (role !== 'alertdialog' && typeof close !== 'function') throw new Error('uiDialog: a dialog needs a close function for its X');
    const backdrop = document.createElement('div');
    if (id) backdrop.id = id;
    backdrop.className = `ui-dialog-backdrop${backdropClass ? ` ${backdropClass}` : ''}`;
    backdrop.setAttribute('role', role);
    if (titleId) backdrop.setAttribute('aria-labelledby', titleId);
    else backdrop.setAttribute('aria-label', label || title);
    if (describedBy) backdrop.setAttribute('aria-describedby', describedBy);
    if (dataset) Object.entries(dataset).forEach(([key, value]) => { backdrop.dataset[key] = value; });
    const bodyTag = form ? 'form' : 'div';
    const bodyAttrs = `${form ? ` id="${escapeHtml(form.id)}"` : bodyId ? ` id="${escapeHtml(bodyId)}"` : ''}${form && form.onsubmit ? ` onsubmit="${escapeHtml(form.onsubmit)}"` : ''} class="ui-dialog-body${bodyClass ? ` ${bodyClass}` : ''}"`;
    const x = typeof close === 'function'
        ? `<button type="button" class="ui-icon-btn" data-dialog-x title="Close" aria-label="Close">${UI_CLOSE_ICON}</button>` : '';
    backdrop.innerHTML = `
        <div class="ui-dialog ui-dialog-fit${UI_DIALOG_SIZES[size] ? ` ${UI_DIALOG_SIZES[size]}` : ''}${dialogClass ? ` ${dialogClass}` : ''}">
            <div class="ui-dialog-head"><h3${titleId ? ` id="${escapeHtml(titleId)}"` : ''}>${escapeHtml(title)}</h3>${x}</div>
            <${bodyTag}${bodyAttrs}>${body}</${bodyTag}>
            ${foot || footId ? `<div${footId ? ` id="${escapeHtml(footId)}"` : ''} class="${footHidden ? 'hidden' : `ui-dialog-foot${footClass ? ` ${footClass}` : ''}`}">${foot}</div>` : ''}
        </div>`;
    const dialog = backdrop.firstElementChild;
    const bodyEl = dialog.querySelector(':scope > .ui-dialog-body');
    if (x) dialog.querySelector('[data-dialog-x]').addEventListener('click', () => close());
    if (backdropClose) backdrop.addEventListener('click', event => { if (uiBackdropClick(event)) backdropClose(); });
    document.body.appendChild(backdrop);
    return { backdrop, dialog, body: bodyEl, foot: footId ? document.getElementById(footId) : dialog.querySelector(':scope > .ui-dialog-foot') };
}

const uiKeysDown = new Set();
if (typeof window !== 'undefined' && window && typeof window.addEventListener === 'function') {
    window.addEventListener('keydown', e => uiKeysDown.add(e.key), true);
    window.addEventListener('keyup', e => uiKeysDown.delete(e.key), true);
    window.addEventListener('blur', () => uiKeysDown.clear());
}

let confirmModalClose = null;
function showConfirmModal({ title = 'Confirm', message = 'Are you sure?', confirmText = 'Confirm', cancelText = 'Cancel', confirmColor, isDangerous = false, focusCancel = false, noHistory = false } = {}) {
    if (confirmModalClose) confirmModalClose(false);
    return new Promise((resolve) => {
        const existing = document.getElementById('app-confirm-modal');
        if (existing) existing.remove();

        const escapedMessage = escapeHtml(message).replace(/\n/g, '<br>');

        const { backdrop: overlay } = uiDialog({
            id: 'app-confirm-modal', title, size: 'sm', role: 'alertdialog', backdropClass: 'ui-confirm',
            dataset: noHistory ? { noHistory: '' } : null,
            body: `<p class="ui-confirm-text">${escapedMessage}</p>`,
            foot: `<button type="button" id="app-confirm-cancel" class="ui-btn">${escapeHtml(cancelText)}</button>
                <button type="button" id="app-confirm-ok" class="ui-btn ${isDangerous ? 'ui-btn-danger-solid' : 'ui-btn-primary'}"
                    ${confirmColor ? `style="background: ${escapeHtml(confirmColor)}"` : ''}>${escapeHtml(confirmText)}</button>`,
        });
        const overflowBefore = document.body.style.overflow;
        document.body.style.overflow = 'hidden';

        const cancelBtn = document.getElementById('app-confirm-cancel');
        const okBtn = document.getElementById('app-confirm-ok');

        const held = new Set(uiKeysDown);
        const guard = (e) => {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            if (e.type === 'keyup') {
                if (held.delete(e.key)) e.preventDefault();
                return;
            }
            if (!e.repeat) { held.delete(e.key); return; }
            e.preventDefault();
            e.stopImmediatePropagation();
        };
        window.addEventListener('keydown', guard, true);
        window.addEventListener('keyup', guard, true);

        let focusTimer = null;
        let settled = false;
        function cleanup(result) {
            if (settled) return;
            settled = true;
            if (confirmModalClose === cleanup) confirmModalClose = null;
            clearTimeout(focusTimer);
            window.removeEventListener('keydown', guard, true);
            window.removeEventListener('keyup', guard, true);
            overlay.remove();
            document.body.style.overflow = overflowBefore;
            resolve(result);
        }
        confirmModalClose = cleanup;
        overlay.addEventListener('click', (e) => { if (uiBackdropClick(e)) cleanup(false); });
        cancelBtn.addEventListener('click', () => cleanup(false));
        okBtn.addEventListener('click', () => cleanup(true));
        if (focusCancel) cancelBtn.focus({ preventScroll: true });
        else focusTimer = setTimeout(() => { if (!settled) okBtn.focus(); }, 100);
    });
}

let choiceModalClose = null;
function showChoiceModal({ title, message, choices, cancelText = 'Cancel' }) {
    if (choiceModalClose) choiceModalClose(null);
    return new Promise((resolve) => {
        const buttons = choices.map((c, i) => `<button type="button" class="ui-btn${c.kind === 'danger' ? ' ui-btn-danger-solid' : c.kind === 'primary' ? ' ui-btn-primary' : ''}" data-choice="${i}">${escapeHtml(c.label)}</button>`).join('');
        const { backdrop: overlay } = uiDialog({
            id: 'app-choice-modal', title, size: 'sm', role: 'alertdialog', backdropClass: 'ui-confirm', describedBy: 'app-choice-text',
            body: `<p class="ui-confirm-text" id="app-choice-text">${escapeHtml(message).replace(/\n/g, '<br>')}</p>`,
            foot: `<button type="button" class="ui-btn" data-cancel>${escapeHtml(cancelText)}</button>${buttons}`,
        });
        overlay.setAttribute('aria-modal', 'true');
        const overflowBefore = document.body.style.overflow;
        document.body.style.overflow = 'hidden';
        function done(result) {
            if (choiceModalClose === done) choiceModalClose = null;
            overlay.remove();
            document.body.style.overflow = overflowBefore;
            resolve(result);
        }
        choiceModalClose = done;
        overlay.addEventListener('click', (e) => { if (uiBackdropClick(e)) done(null); });
        overlay.querySelector('[data-cancel]').addEventListener('click', () => done(null));
        overlay.querySelectorAll('[data-choice]').forEach(btn => btn.addEventListener('click', () => done(choices[Number(btn.dataset.choice)].value)));
        setTimeout(() => overlay.querySelector('[data-cancel]').focus(), 50);
    });
}

const uiDialogStarts = new WeakMap();
function uiFormValues(root) {
    return JSON.stringify([...root.querySelectorAll('input, select, textarea')].filter(el => !el.hasAttribute('data-guard-skip')).map(el => {
        if (el.type === 'checkbox' || el.type === 'radio') return el.checked;
        if (el.tagName === 'SELECT') return [...el.options].map(o => o.selected);
        return el.value;
    }));
}
function uiGuardDialog(modal) {
    if (modal) uiDialogStarts.set(modal, uiFormValues(modal));
}
let uiDiscardAsking = null;
async function uiCloseGuarded(modal, close) {
    if (!modal || !modal.isConnected || uiDiscardAsking) return;
    const start = uiDialogStarts.get(modal);
    if (start !== undefined && start !== uiFormValues(modal)) {
        uiDiscardAsking = modal;
        let discard = false;
        try {
            discard = await showConfirmModal({ title: 'Discard your changes?', message: 'What you changed in this window is not saved.',
                confirmText: 'Discard', cancelText: 'Keep editing', isDangerous: true, focusCancel: true });
        } finally {
            uiDiscardAsking = null;
        }
        if (!discard || !modal.isConnected) return;
    }
    close();
}
function uiCancelDialog(id) {
    const modal = document.getElementById(id);
    uiCloseGuarded(modal, () => modal.remove());
}
function uiDialogSaved(modal) {
    if (modal && uiDiscardAsking === modal) document.getElementById('app-confirm-cancel')?.click();
}
function uiCloseSavedDialog(id) {
    const modal = document.getElementById(id);
    uiDialogSaved(modal);
    modal?.remove();
}

function uiFieldProblem(field, text, after = field) {
    if (!field) return;
    const id = `${field.id}-invalid`;
    document.getElementById(id)?.remove();
    const note = document.createElement('small');
    note.className = 'ui-set-invalid ui-text-fail';
    note.id = id;
    note.textContent = text;
    (after || field).insertAdjacentElement('afterend', note);
    field.setAttribute('aria-invalid', 'true');
    const described = (field.getAttribute('aria-describedby') || '').split(' ').filter(Boolean);
    if (!described.includes(id)) field.setAttribute('aria-describedby', [...described, id].join(' '));
    field.addEventListener('input', () => {
        field.removeAttribute('aria-invalid');
        note.remove();
    }, { once: true });
    field.focus();
}

function uiApiErrorText(body, fallback) {
    const detail = body && body.detail;
    if (Array.isArray(detail)) {
        const lines = detail.map(item => {
            if (!item || typeof item !== 'object') return String(item);
            const loc = Array.isArray(item.loc) ? item.loc.filter(p => p !== 'body' && typeof p === 'string') : [];
            const field = loc.length ? loc[loc.length - 1].replace(/_/g, ' ') : '';
            return field ? `${field}: ${item.msg || 'not valid'}` : (item.msg || '');
        }).filter(Boolean);
        return lines.length ? lines.join('; ') : fallback;
    }
    if (detail && typeof detail === 'object') return detail.message || fallback;
    return detail || fallback;
}

const UI_SERVER_SAYS_NOTHING = new Set(['An error occurred', 'Internal Server Error', 'Internal server error']);
function uiHttpErrorText(status, body) {
    const said = uiApiErrorText(body, '');
    if (said && !UI_SERVER_SAYS_NOTHING.has(said)) return said;
    if (status === 502 || status === 503 || status === 504) return 'The server did not answer. It may be restarting';
    if (status === 404) return 'Not found. It may have been removed';
    if (status === 413) return 'Too large for the server';
    if (status === 429) return 'Too many requests. Wait a moment';
    if (status >= 500) return 'The server hit an error. If it keeps happening, check the app log';
    return `The server refused the request (HTTP ${status})`;
}
function uiErrorText(error) {
    if (!error) return 'Something went wrong';
    if (typeof error === 'string') return error;
    if (error.name === 'AbortError' || error.name === 'TimeoutError') return 'The server took too long to answer';
    if (error.name === 'SyntaxError') return 'The server sent an answer the app could not read';
    if (error.name === 'TypeError' && /fetch|network|load failed/i.test(error.message || '')) return 'Could not reach the server. Check the connection';
    if (['TypeError', 'ReferenceError', 'RangeError'].includes(error.name)) return 'Something went wrong in the page. Reload it';
    return error.message || 'Something went wrong';
}
function uiSentence(text) {
    return String(text).replace(/[^.!?]$/, '$&.');
}
async function uiReadJson(response) {
    try {
        return await response.json();
    } catch (e) {
        return null;
    }
}

// =============================================================================
const uiUnsavedEntries = new Map();
function uiUnsavedRegister(key, entry) {
    uiUnsavedEntries.set(key, { keeps: () => false, ...entry });
}
function uiUnsavedUnregister(key) {
    uiUnsavedEntries.delete(key);
}
function uiUnsavedClear() {
    uiUnsavedEntries.clear();
}
function uiUnsavedDrop(target) {
    for (const entry of uiUnsavedEntries.values()) {
        if (!(target && entry.keeps({ params: {}, ...target })) && typeof entry.drop === 'function') entry.drop();
    }
}
function uiUnsavedCount(target) {
    let n = 0;
    for (const entry of uiUnsavedEntries.values()) {
        let count = 0;
        try { count = Number(entry.count()) || 0; } catch (e) { count = 0; }
        if (count && !(target && entry.keeps({ params: {}, ...target }))) n += count;
    }
    return n;
}
let uiUnsavedAsking = null;
function uiConfirmLeave(target, { keep = false } = {}) {
    const n = uiUnsavedCount(target);
    if (!n) return Promise.resolve(true);
    if (uiUnsavedAsking) return uiUnsavedAsking;
    const changes = n === 1 ? '1 unsaved change' : `${n} unsaved changes`;
    uiUnsavedAsking = showConfirmModal({
        title: 'Leave without saving?',
        message: `You have ${changes}. Leaving drops ${n === 1 ? 'it' : 'them'}.`,
        confirmText: 'Leave', cancelText: 'Stay', isDangerous: true, focusCancel: true, noHistory: true,
    }).then(leave => {
        if (leave && !keep) uiUnsavedDrop(target);
        return leave;
    }).finally(() => { uiUnsavedAsking = null; });
    return uiUnsavedAsking;
}

function jobRunsText(job) {
    return [
        job.interval,
        job.clock ? `${job.clock.weekday ? `Weekly, ${job.clock.weekday}` : 'Daily'} at ${formatClockAt(job.clock.hour, job.clock.minute)} (${job.clock.zone})` : job.schedule,
        job.retention ? `keeps ${job.retention}` : '',
        job.max_age ? `Max: ${job.max_age}` : '',
        job.expire_after ? `Expire: ${job.expire_after}` : '',
    ].filter(Boolean).join(', ');
}

function renderJobCard(name, jobKey, job) {
    if (!job) {
        return '';
    }

    const isRunning = job.status === 'running';
    const isFeatureOff = job.feature_disabled === true;
    const isDisabled = job.status === 'disabled' || job.enabled === false || isFeatureOff;

    let statusBadge = '';

    if (isFeatureOff) {
        statusBadge = '<span class="ui-tag ui-tag-warn" title="The feature this job belongs to is turned off in Settings">feature off</span>';
    } else if (isDisabled) {
        statusBadge = `<span class="ui-tag" title="${escapeHtml(job.disabled_reason || 'This job is turned off in its settings, so it cannot be run')}">off</span>`;
    } else {
        switch (job.status) {
            case 'running':
                statusBadge = '<span class="ui-tag ui-tag-info">running</span>';
                break;
            case 'success':
                statusBadge = '<span class="ui-tag ui-tag-ok">success</span>';
                break;
            case 'failed':
                statusBadge = '<span class="ui-tag ui-tag-fail">failed</span>';
                break;
            case 'scheduled':
                statusBadge = '<span class="ui-tag ui-tag-spam">scheduled</span>';
                break;
            default:
                statusBadge = '<span class="ui-tag">idle</span>';
        }
    }

    const failed = !isDisabled && job.status === 'failed';
    const dot = isDisabled ? '' : failed ? ' ui-mdot-fail' : job.status === 'running' ? ' ui-mdot-info' : job.status === 'success' ? ' ui-mdot-ok' : '';
    return `
        <div class="ui-jobrow${isDisabled ? ' is-off' : ''}${failed ? ' is-failed' : ''}" data-job="${escapeHtml(jobKey)}">
            <i class="ui-mdot${dot}"></i>
            <span class="ui-jobrow-name"><b>${escapeHtml(name)}</b>${job.description ? `<small title="${escapeHtml(job.description)}">${escapeHtml(job.description)}</small>` : ''}${isDisabled && !isFeatureOff && job.disabled_reason ? `<small class="ui-text-warn">${escapeHtml(job.disabled_reason)}</small>` : ''}</span>
            <span class="ui-jobrow-runs">${escapeHtml(jobRunsText(job) || '-')}${job.pending_items !== undefined ? ` <small class="ui-text-warn">Pending: ${escapeHtml(String(job.pending_items))}</small>` : ''}</span>
            <span class="ui-jobrow-last" title="${job.last_run ? escapeHtml(formatTime(job.last_run)) : ''}">${job.last_run ? formatAgo(job.last_run) : 'Not run yet'}</span>
            <span class="ui-jobrow-tag">${job.status === 'success' && !isDisabled ? '' : statusBadge}</span>
            <span class="ui-jobrow-act">${!isDisabled ? `
                <button onclick="triggerBackgroundJob('${escapeJsArg(jobKey)}', this, '${escapeJsArg(name)}')"
                    class="ui-btn ui-btn-sm" ${isRunning ? 'disabled' : ''} title="${isRunning ? 'Job is running' : 'Run this job now'}" data-acts="admin">Run</button>`
                : !isFeatureOff && job.settings_section ? `
                <button onclick="navigateTo('settings', { sub: '${escapeJsArg(job.settings_section)}' })" class="ui-btn ui-btn-sm" data-acts="admin"
                    title="${escapeHtml(job.disabled_reason || '')}">Settings</button>` : ''}</span>
            ${job.error ? `<p class="ui-job-error ui-mono">${escapeHtml(job.error)}</p>` : ''}
        </div>
    `;
}

function renderRecipientMore(msg) {
    const more = (Number(msg.recipient_count) || 0) - 1;
    if (more < 1) return '';
    const said = `and ${more} more ${more === 1 ? 'recipient' : 'recipients'}`;
    return `<span class="ui-tag ui-rcpt-more" title="${said}"><span aria-hidden="true">+${more}</span><span class="ui-sr-only"> ${said}</span></span>`;
}

const uiFitLines = new Set();
const uiFitObserver = typeof ResizeObserver === 'function'
    ? new ResizeObserver(entries => uiFitAddresses(entries.map(entry => entry.target)))
    : null;

const uiFitSegmenter = typeof Intl !== 'undefined' && Intl.Segmenter ? new Intl.Segmenter() : null;
function uiFitChars(text) {
    return uiFitSegmenter ? Array.from(uiFitSegmenter.segment(text), part => part.segment) : Array.from(text);
}
function uiFitCut(chars, keep) {
    return chars.slice(0, keep).join('').replace(/[._+-]+$/, '') + '…';
}

function uiFitFits(line) {
    return line.scrollWidth <= line.clientWidth;
}

function uiFitAddresses(lines) {
    const jobs = [];
    for (const line of lines) {
        const loc = line.isConnected ? line.querySelector('.ui-fit-loc') : null;
        const btn = loc && loc.closest('.ui-ent-btn');
        if (!btn) continue;
        const full = btn.dataset.entityValue || '';
        const local = full.slice(0, full.lastIndexOf('@'));
        if (btn.dataset.fitTitle === undefined) btn.dataset.fitTitle = btn.title;
        loc.textContent = local;
        line.classList.remove('is-over');
        jobs.push({ line, loc, btn, full, local, cut: false, over: false });
    }
    const cut = jobs.filter(job => job.line.clientWidth && !uiFitFits(job.line));
    cut.forEach(job => { job.cut = true; job.chars = uiFitChars(job.local); job.lo = 0; job.hi = job.chars.length - 1; });
    let open = cut.filter(job => job.lo < job.hi);
    while (open.length) {
        open.forEach(job => { job.mid = Math.ceil((job.lo + job.hi) / 2); job.loc.textContent = uiFitCut(job.chars, job.mid); });
        open.forEach(job => { if (uiFitFits(job.line)) job.lo = job.mid; else job.hi = job.mid - 1; });
        open = open.filter(job => job.lo < job.hi);
    }
    cut.forEach(job => { job.loc.textContent = uiFitCut(job.chars, job.lo); });
    cut.forEach(job => { job.over = !uiFitFits(job.line); });
    for (const job of jobs) {
        job.line.classList.toggle('is-over', job.over);
        if (job.cut) job.btn.setAttribute('aria-label', job.full);
        else job.btn.removeAttribute('aria-label');
        job.btn.title = job.cut ? job.full : job.btn.dataset.fitTitle;
    }
}

function uiFitWatch(node, on) {
    const lines = node.matches('.ui-fit') ? [node] : node.querySelectorAll('.ui-fit');
    for (const line of lines) {
        if (on) { uiFitLines.add(line); uiFitObserver.observe(line); }
        else { uiFitLines.delete(line); uiFitObserver.unobserve(line); }
    }
}

if (uiFitObserver && typeof MutationObserver !== 'undefined' && document.body) {
    new MutationObserver(records => {
        for (const record of records) {
            record.removedNodes.forEach(node => { if (node instanceof Element) uiFitWatch(node, false); });
            record.addedNodes.forEach(node => { if (node instanceof Element) uiFitWatch(node, true); });
        }
    }).observe(document.body, { subtree: true, childList: true });
    if (document.fonts) document.fonts.addEventListener('loadingdone', () => uiFitAddresses([...uiFitLines]));
}

const uiTableSorts = new Map();

function uiSortHeads(table) {
    const head = table.tagName === 'TABLE' ? table.querySelector('thead tr') : table.querySelector(':scope > .ui-tr-head');
    return head ? [...head.children] : [];
}

function uiSortLabel(cell) {
    return cell.dataset.sortLabel !== undefined ? cell.dataset.sortLabel : cell.textContent.trim();
}

function uiTableKey(table) {
    const owner = table.id ? table : table.closest('[id]');
    return `${owner ? owner.id : ''}|${uiSortHeads(table).map(uiSortLabel).join('|')}`;
}

function uiSortable(table, cell) {
    if (!cell || table.hasAttribute('data-nosort') || cell.hasAttribute('data-nosort')) return false;
    if (table.closest('.markdown-body')) return false;
    if (table.hasAttribute('data-sort-handler')) return cell.hasAttribute('data-sort-key');
    const label = uiSortLabel(cell);
    return label !== '' && !/^actions?$/i.test(label);
}

function uiSortState(cell) {
    return cell.getAttribute('aria-sort') || cell.dataset.sortState || 'none';
}
function uiSetSortState(cell, state) {
    if (cell.dataset.sortState !== state) cell.dataset.sortState = state;
    if (cell.tagName === 'TH') {
        if (cell.getAttribute('aria-sort') !== state) cell.setAttribute('aria-sort', state);
    } else if (cell.hasAttribute('aria-sort')) {
        cell.removeAttribute('aria-sort');
    }
    const said = cell.querySelector(':scope > .ui-sort-btn > .ui-sort-said');
    const words = cell.tagName === 'TH' || state === 'none' ? '' : `, sorted ${state}`;
    if (said && said.textContent !== words) said.textContent = words;
}

function uiSortEnhance(cell) {
    if (cell.querySelector(':scope > .ui-sort-btn') || cell.querySelector('button, a, input, select, textarea')) return;
    cell.dataset.sortLabel = cell.textContent.trim();
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'ui-sort-btn';
    while (cell.firstChild) button.appendChild(cell.firstChild);
    const said = document.createElement('span');
    said.className = 'ui-sort-said ui-sr-only';
    button.appendChild(said);
    cell.appendChild(button);
}

function uiSortValue(cell) {
    if (!cell) return { n: null, t: '' };
    if (cell.hasAttribute && cell.hasAttribute('data-sort')) {
        const v = cell.getAttribute('data-sort');
        return v === '' || isNaN(Number(v)) ? { n: null, t: v.toLowerCase() } : { n: Number(v), t: v };
    }
    const time = cell.matches && cell.matches('time[datetime]') ? cell : cell.querySelector && cell.querySelector('time[datetime]');
    if (time) {
        const n = Date.parse(time.getAttribute('datetime'));
        if (!isNaN(n)) return { n, t: (time.textContent || '').trim().toLowerCase() };
    }
    const copy = cell.cloneNode(true);
    copy.querySelectorAll('.ui-sec-unit, .ui-phone-only').forEach(el => el.remove());
    const text = copy.textContent.replace(/\s+/g, ' ').trim();
    const t = text.toLowerCase();
    if (!text || text === '-') return { n: null, t: '' };
    const size = text.match(/^(-?\d+(?:[.,]\d+)?)\s*(b|kb|mb|gb|tb)$/i);
    if (size) return { n: parseFloat(size[1].replace(',', '.')) * 1024 ** ['b', 'kb', 'mb', 'gb', 'tb'].indexOf(size[2].toLowerCase()), t };
    const span = t.match(/^(?:up\s+)?(\d+(?:\.\d+)?)\s*(sec|s|min|mo|m|h|d|w|y)[a-z]*(\s+ago)?$/);
    if (span || t === 'just now') {
        const unit = { s: 1, sec: 1, m: 60, min: 60, h: 3600, d: 86400, w: 604800, mo: 2592000, y: 31536000 };
        if (!span) return { n: 0, t };
        const secs = Number(span[1]) * unit[span[2]];
        return { n: span[3] ? -secs : secs, t };
    }
    const num = text.replace(/,/g, '').match(/^(-?\d+(?:\.\d+)?)\s*(%|k|m)?(\s|$)/i);
    if (num) return { n: parseFloat(num[1]) * ({ k: 1e3, m: 1e6 }[(num[2] || '').toLowerCase()] || 1), t };
    if (/\d{1,4}[./-]\d{1,2}[./-]\d{1,4}/.test(text)) {
        const [a, b, c, rest] = text.split(/[^\d]+/).filter(Boolean);
        const dotted = /\d\.\d/.test(text);
        const y = String(c).length === 4 ? c : a;
        const mo = dotted ? b : a, da = dotted ? a : b;
        const time = Date.parse(`${y}-${String(mo).padStart(2, '0')}-${String(da).padStart(2, '0')}T${(text.match(/\d{1,2}:\d{2}(:\d{2})?/) || ['00:00'])[0].padStart(5, '0')}Z`);
        if (!isNaN(time)) return { n: time, t };
    }
    return { n: null, t };
}

function uiSortCell(row, index) {
    if (!row || index < 0) return null;
    return [...row.children].filter(c => !c.classList.contains('ui-tr-break'))[index] || null;
}

function uiSortUnits(table) {
    if (table.tagName === 'TABLE') {
        const body = table.tBodies[0];
        return body ? [{ parent: body, units: [...body.rows].filter(r => !r.hasAttribute('data-sort-fixed') && r.cells.length > 1).map(r => [r]),
            fixed: [...body.rows].filter(r => r.hasAttribute('data-sort-fixed') || r.cells.length <= 1) }] : [];
    }
    const kids = [...table.children];
    const start = kids.findIndex(k => k.classList.contains('ui-tr-head')) + 1;
    const segments = [];
    let seg = { parent: table, units: [], fixed: [] };
    for (const el of kids.slice(start)) {
        if (el.classList.contains('ui-tr-group')) { segments.push(seg); seg = { parent: table, units: [], fixed: [], after: el }; continue; }
        if (el.classList.contains('ui-tr')) seg.units.push([el]);
        else if (seg.units.length) seg.units[seg.units.length - 1].push(el);
        else seg.fixed.push(el);
    }
    segments.push(seg);
    return segments;
}

function uiSortRowId(row) {
    if (row.dataset.sortId !== undefined) return row.dataset.sortId;
    const first = uiSortCell(row, 0);
    return first ? first.textContent.replace(/\s+/g, ' ').trim() : '';
}
function uiSortPositions(table) {
    const units = uiSortUnits(table).flatMap(seg => seg.units);
    const fresh = units.filter(u => u[0].dataset.sortPos === undefined);
    if (!fresh.length) return false;
    if (fresh.length === units.length || !table._sortPlaces) table._sortPlaces = new Map();
    const places = table._sortPlaces;
    if (fresh.length === units.length) {
        units.forEach((u, i) => { u[0].dataset.sortPos = String(i); places.set(uiSortRowId(u[0]), i); });
        return true;
    }
    let next = Math.max(...units.filter(u => u[0].dataset.sortPos !== undefined).map(u => Number(u[0].dataset.sortPos))) + 1;
    for (const u of fresh) {
        const known = places.get(uiSortRowId(u[0]));
        const pos = known !== undefined ? known : next++;
        u[0].dataset.sortPos = String(pos);
        places.set(uiSortRowId(u[0]), pos);
    }
    return true;
}

function uiApplyTableSort(table, index, dir) {
    const heads = uiSortHeads(table);
    heads.forEach((h, i) => { if (uiSortable(table, h)) uiSetSortState(h, i === index ? (dir > 0 ? 'ascending' : 'descending') : 'none'); });
    uiSortPositions(table);
    for (const seg of uiSortUnits(table)) {
        const keyed = seg.units.map((unit, pos) => ({ unit, pos,
            v: index < 0 ? { n: Number(unit[0].dataset.sortPos), t: '' } : uiSortValue(uiSortCell(unit[0], index)) }));
        if (index < 0) dir = 1;
        keyed.sort((a, b) => {
            const ae = a.v.n === null && !a.v.t, be = b.v.n === null && !b.v.t;
            if (ae !== be) return ae ? 1 : -1;
            let c;
            if (a.v.n !== null && b.v.n !== null) c = a.v.n - b.v.n;
            else c = a.v.t.localeCompare(b.v.t, undefined, { sensitivity: 'base' });
            return c ? c * dir : a.pos - b.pos;
        });
        let anchor = seg.after ? seg.after.nextSibling : (seg.parent.tagName === 'TBODY' ? seg.parent.firstChild : uiSortHeads(table)[0].parentNode.nextSibling);
        for (const { unit } of keyed) for (const el of unit) { seg.parent.insertBefore(el, anchor); anchor = el.nextSibling; }
        for (const el of seg.fixed) if (seg.parent.tagName === 'TBODY') seg.parent.appendChild(el);
    }
    if (index < 0) delete table.dataset.sortedBy;
    else table.dataset.sortedBy = `${index}:${dir}`;
}

const UI_SORT_KINDS = {
    text: { asc: 'A to Z', desc: 'Z to A', first: 1 },
    number: { asc: 'Low to high', desc: 'High to low', first: -1 },
    date: { asc: 'Oldest first', desc: 'Newest first', first: -1 },
};
function uiSortWords(cell) {
    return UI_SORT_KINDS[cell && cell.dataset.sortKind] || { asc: 'Ascending', desc: 'Descending' };
}
function uiSortFirstDir(table, cell) {
    const kind = UI_SORT_KINDS[cell.dataset.sortKind];
    if (kind) return kind.first;
    const index = uiSortHeads(table).indexOf(cell);
    const numeric = uiSortUnits(table).some(seg => seg.units.some(u => uiSortValue(uiSortCell(u[0], index)).n !== null));
    return numeric ? -1 : 1;
}

function uiClearTableSort(owner) {
    for (const key of [...uiTableSorts.keys()]) if (key.startsWith(`${owner}|`)) uiTableSorts.delete(key);
}

let uiSortFocus = null;
function uiSortOwner(table) {
    const owner = table.id ? table : table.closest('[id]');
    return owner ? owner.id : '';
}
function uiSortNth(table) {
    const owner = uiSortOwner(table);
    return [...document.querySelectorAll('.ui-table, table')].filter(t => uiSortOwner(t) === owner).indexOf(table);
}
function uiSortBy(table, cell) {
    const current = uiSortState(cell);
    let dir = current === 'descending' ? 1 : current === 'ascending' ? -1 : uiSortFirstDir(table, cell);
    if (current === 'none' && !table.hasAttribute('data-sort-handler') && table.dataset.sortDefault) {
        const heads = uiSortHeads(table);
        const fallback = uiSortDefault(table, heads);
        if (fallback && fallback.cell === cell && heads.every(h => uiSortState(h) === 'none')) dir = -fallback.dir;
    }
    uiSortSet(table, cell, dir);
}

function uiSortSet(table, cell, dir) {
    const active = document.activeElement;
    if (active && cell.contains(active)) {
        uiSortFocus = { owner: uiSortOwner(table), nth: uiSortNth(table), label: uiSortLabel(cell),
            server: table.hasAttribute('data-sort-handler'), from: active, until: Date.now() + 5000 };
    }
    const heads = uiSortHeads(table);
    const index = heads.indexOf(cell);
    const handler = table.getAttribute('data-sort-handler');
    const fallback = !handler && table.dataset.sortDefault ? uiSortDefault(table, heads) : null;
    if (fallback && fallback.cell === cell && fallback.dir === dir) { uiSortReset(table); return; }
    const before = heads.map(uiSortState);
    heads.forEach(h => { if (uiSortable(table, h)) uiSetSortState(h, h === cell ? (dir > 0 ? 'ascending' : 'descending') : 'none'); });
    if (typeof requestAnimationFrame === 'function' && !uiTableSortQueued) { uiTableSortQueued = true; requestAnimationFrame(uiRefreshTableSorts); }
    if (handler) {
        if (table._sortUndo) before.splice(0, before.length, ...table._sortUndo);
        table._sortUndo = before;
        const token = table._sortToken = {};
        if (typeof setTimeout === 'function') setTimeout(() => {
            if (!table.isConnected || table._sortToken !== token) return;
            delete table._sortUndo;
            delete table._sortToken;
            heads.forEach((h, i) => { if (uiSortable(table, h)) uiSetSortState(h, before[i]); });
            if (typeof uiRefreshTableSorts === 'function') uiRefreshTableSorts();
        }, uiSortWait);
        if (typeof window[handler] === 'function') window[handler](cell.getAttribute('data-sort-key'), dir > 0 ? 'asc' : 'desc');
        return;
    }
    uiTableSorts.set(uiTableKey(table), { index, dir });
    uiApplyTableSort(table, index, dir);
}
let uiSortWait = 8000;

function uiSortReset(table) {
    uiTableSorts.delete(uiTableKey(table));
    uiApplyTableSort(table, -1, 1);
}

document.addEventListener('click', event => {
    const cell = event.target.closest('.ui-tr-head > *, thead th');
    if (!cell) return;
    const table = cell.closest('.ui-table, table');
    if (!table || !uiSortable(table, cell)) return;
    uiSortBy(table, cell);
});

document.addEventListener('keydown', event => {
    if ((event.key !== 'Enter' && event.key !== ' ') || event.defaultPrevented) return;
    const row = event.target;
    if (!(row instanceof Element) || !row.matches('[data-row-open]')) return;
    event.preventDefault();
    row.click();
});

let uiPress = null;
document.addEventListener('mousedown', event => {
    uiPress = { x: event.clientX, y: event.clientY, target: event.target, down: true };
    if (event.detail > 1 && !event.shiftKey && event.target instanceof Element && event.target.closest('[data-line-select]')) window.getSelection().removeAllRanges();
}, true);
const uiPressEnd = () => { if (uiPress) uiPress.down = false; };
document.addEventListener('mouseup', uiPressEnd, true);
document.addEventListener('mousemove', event => { if (!event.buttons) uiPressEnd(); }, true);
if (typeof window.addEventListener === 'function') window.addEventListener('blur', uiPressEnd);
function uiPressMoved(event) {
    return Boolean(uiPress) && Math.hypot(event.clientX - uiPress.x, event.clientY - uiPress.y) > 3;
}
function uiRowHeld(event) {
    if (!event || !event.detail || !(event.currentTarget instanceof Element)) return false;
    const selection = window.getSelection && window.getSelection();
    if (!selection || !selection.rangeCount || !String(selection) || !selection.getRangeAt(0).intersectsNode(event.currentTarget)) return false;
    return uiPressMoved(event) || event.detail > 1 || event.shiftKey;
}

function uiBackdropClick(event, backdrop = event.currentTarget) {
    if (event.target !== backdrop) return false;
    return !event.detail || !uiPress || uiPress.target === backdrop;
}

function uiSortControlKey(table) {
    const nth = uiSortNth(table);
    return `${uiSortOwner(table)}${nth > 0 ? `-${nth}` : ''}`;
}
function uiSortTableFor(key) {
    return [...document.querySelectorAll('.ui-table, table')].find(t => uiSortControlKey(t) === key) || null;
}
function uiSortDefault(table, heads) {
    const [label, order] = (table.dataset.sortDefault || '').split(':');
    const cell = label ? heads.find(h => uiSortLabel(h) === label) : null;
    return cell ? { cell, dir: order === 'asc' ? 1 : -1 } : null;
}
function uiSortCurrent(table, heads) {
    const cell = heads.find(h => uiSortable(table, h) && uiSortState(h) !== 'none');
    if (cell) return { cell, dir: uiSortState(cell) === 'ascending' ? 1 : -1 };
    return uiSortDefault(table, heads);
}
function uiSortSaid(current) {
    if (!current) return 'Sort: Default order';
    const words = uiSortWords(current.cell);
    return `Sort: ${uiSortLabel(current.cell)}, ${current.dir > 0 ? words.asc : words.desc}`;
}
const UI_SORT_ICON = '<svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 4v16m0 0l-3-3m3 3l3-3M17 20V4m0 0l-3 3m3-3l3 3"></path></svg>';

function uiSortControlSync(table, heads) {
    const key = uiSortControlKey(table);
    let slot = [...document.querySelectorAll('.ui-sort-slot')].find(el => el.dataset.sortFor === key);
    const at = table.dataset.sortAt ? document.getElementById(table.dataset.sortAt) : null;
    const sortable = heads.filter(h => uiSortable(table, h));
    if (!at || !sortable.length || table.matches('[data-sort-icon="off"]')) {
        if (slot) { slot.remove(); return true; }
        return false;
    }
    let changed = false;
    if (!slot) {
        slot = document.createElement('span');
        slot.className = 'ui-sort-slot';
        slot.dataset.sortFor = key;
    }
    const search = at.closest('.ui-search');
    if (search ? search.nextElementSibling !== slot : slot.parentElement !== at || at.lastElementChild !== slot) {
        if (search) search.after(slot); else at.appendChild(slot);
        changed = true;
    }
    const id = `ui-sort-${key.replace(/[^\w-]/g, '_')}`;
    const fallback = uiSortDefault(table, heads);
    const current = uiSortCurrent(table, heads);
    const set = !!current && !(fallback && current.cell === fallback.cell && current.dir === fallback.dir);
    const columns = sortable.map(h => uiSortLabel(h)).join('|');
    if (slot.dataset.columns !== columns || !slot.querySelector('.ui-picker')) {
        slot.dataset.columns = columns;
        const listName = (table.dataset.sortName || '').trim();
        const panel = `<fieldset class="ui-sort-group"><legend>Sort by</legend>
            ${fallback ? '' : `<label class="ui-sort-opt"><input type="radio" name="${id}-by" value="" onchange="uiSortPick('${escapeJsArg(key)}', 'by', this.value)"><span>Default order</span></label>`}
            ${sortable.map(h => `<label class="ui-sort-opt"><input type="radio" name="${id}-by" value="${heads.indexOf(h)}" onchange="uiSortPick('${escapeJsArg(key)}', 'by', this.value)"><span>${escapeHtml(uiSortLabel(h))}</span></label>`).join('')}
            </fieldset>
            <fieldset class="ui-sort-group ui-sort-dir"><legend>Order</legend>
            <label class="ui-sort-opt"><input type="radio" name="${id}-dir" value="1" onchange="uiSortPick('${escapeJsArg(key)}', 'dir', this.value)"><span data-dir="asc"></span></label>
            <label class="ui-sort-opt"><input type="radio" name="${id}-dir" value="-1" onchange="uiSortPick('${escapeJsArg(key)}', 'dir', this.value)"><span data-dir="desc"></span></label>
            </fieldset>`;
        slot.innerHTML = uiPicker({ id, label: 'Sort', icon: true, panel, panelLabel: listName ? `Sort ${listName}` : 'Sort', panelClass: 'ui-sort-panel' });
        slot.dataset.sig = '';
        changed = true;
    }
    const sig = `${current ? heads.indexOf(current.cell) + ':' + current.dir : ''}|${set}`;
    if (slot.dataset.sig === sig) return changed;
    slot.dataset.sig = sig;
    const button = slot.querySelector('.ui-picker-btn');
    const said = uiSortSaid(current);
    button.setAttribute('aria-label', said);
    button.title = said;
    button.classList.toggle('is-set', set);
    const by = current ? String(heads.indexOf(current.cell)) : '';
    slot.querySelectorAll(`input[name="${id}-by"]`).forEach(r => { r.checked = r.value === by; });
    const dirs = slot.querySelector('.ui-sort-dir');
    dirs.disabled = !current;
    const words = uiSortWords(current && current.cell);
    dirs.querySelector('[data-dir="asc"]').textContent = words.asc;
    dirs.querySelector('[data-dir="desc"]').textContent = words.desc;
    dirs.querySelectorAll('input').forEach(r => { r.checked = !!current && Number(r.value) === current.dir; });
    return true;
}

function uiSortPick(key, group, value) {
    const table = uiSortTableFor(key);
    if (!table) return;
    const heads = uiSortHeads(table);
    if (group === 'by') {
        if (value === '') { uiSortReset(table); return; }
        const cell = heads[Number(value)];
        if (cell && uiSortable(table, cell)) uiSortSet(table, cell, uiSortFirstDir(table, cell));
        return;
    }
    const current = uiSortCurrent(table, heads);
    if (current) uiSortSet(table, current.cell, Number(value) > 0 ? 1 : -1);
}

// Mark the sortable headers
let uiTableSortQueued = false;
function uiRefreshTableSorts() {
    uiTableSortQueued = false;
    let pickers = false;
    const seen = new Set();
    document.querySelectorAll('.ui-table, table').forEach(table => {
        const heads = uiSortHeads(table);
        heads.forEach(h => {
            if (!uiSortable(table, h)) return;
            uiSortEnhance(h);
            uiSetSortState(h, uiSortState(h));
        });
        if (!table.hasAttribute('data-sort-handler')) {
            if (uiSortPositions(table)) delete table.dataset.sortedBy;
            const state = uiTableSorts.get(uiTableKey(table));
            if (state && table.dataset.sortedBy !== `${state.index}:${state.dir}`) uiApplyTableSort(table, state.index, state.dir);
        }
        seen.add(uiSortControlKey(table));
        if (uiSortControlSync(table, heads)) pickers = true;
    });
    document.querySelectorAll('.ui-sort-slot').forEach(slot => { if (!seen.has(slot.dataset.sortFor)) slot.remove(); });
    if (pickers) uiPickerRefocus();
    uiSortFocusBack();
}
function uiSortFocusBack() {
    const want = uiSortFocus;
    if (!want) return;
    if (Date.now() > want.until) { uiSortFocus = null; return; }
    if (want.from.isConnected) return;
    uiSortFocus = null;
    const active = document.activeElement;
    if (active && active !== document.body) return;
    const table = [...document.querySelectorAll('.ui-table, table')].filter(t => uiSortOwner(t) === want.owner)[want.nth];
    if (!table) return;
    const target = uiSortHeads(table).find(h => uiSortLabel(h) === want.label)?.querySelector('.ui-sort-btn');
    if (target && target.getClientRects().length) target.focus({ preventScroll: true });
}
document.addEventListener('focusin', event => {
    if (uiSortFocus && event.target !== uiSortFocus.from && event.target instanceof Element
        && !event.target.closest('.ui-tr-head, thead')) uiSortFocus = null;
}, true);
document.addEventListener('DOMContentLoaded', () => {
    new MutationObserver(() => {
        if (uiTableSortQueued) return;
        uiTableSortQueued = true;
        requestAnimationFrame(uiRefreshTableSorts);
    }).observe(document.body, { subtree: true, childList: true });
    uiRefreshTableSorts();
});

const UI_COPY_PATH = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path>';
document.addEventListener('click', event => {
    const box = event.target instanceof Element && event.target.closest('[data-line-select]');
    if (!box || event.target.closest('button, a') || event.detail !== 1 || event.shiftKey || uiPressMoved(event)) return;
    const line = event.target.closest(box.dataset.lineSelect);
    if (!line || !box.contains(line)) return;
    uiLineCopyRemove();
    const range = document.createRange();
    range.selectNodeContents(line);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'ui-line-copy';
    copy.title = 'Copy line';
    copy.setAttribute('aria-label', 'Copy line');
    copy.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">${UI_COPY_PATH}</svg>`;
    copy.addEventListener('mousedown', e => e.preventDefault());
    copy.addEventListener('click', e => { e.stopPropagation(); uiLineCopy(line, copy); });
    line.appendChild(copy);
});

function uiLineCopyRemove() {
    document.querySelectorAll('.ui-line-copy').forEach(button => button.remove());
}

document.addEventListener('selectionchange', () => {
    const copy = document.querySelector('.ui-line-copy');
    if (!copy) return;
    const line = copy.parentElement;
    if (!line || String(window.getSelection()).trim() !== line.textContent.trim()) copy.remove();
});

async function uiLineCopy(line, button) {
    const text = line.textContent;
    let copied = false;
    try {
        if (navigator.clipboard) { await navigator.clipboard.writeText(text); copied = true; }
    } catch (e) {}
    if (!copied) {
        const field = document.createElement('textarea');
        field.value = text;
        field.setAttribute('readonly', '');
        field.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
        document.body.appendChild(field);
        field.select();
        try { copied = document.execCommand('copy'); } catch (e) { copied = false; }
        field.remove();
        if (line.isConnected) {
            const range = document.createRange();
            range.selectNodeContents(line);
            range.setEndBefore(button);
            const selection = window.getSelection();
            selection.removeAllRanges();
            selection.addRange(range);
        }
    }
    if (!copied) { showToast('Could not copy. Press Ctrl+C to copy the selected line.', 'error'); return; }
    showToast('Line copied', 'success');
    button.classList.add('is-copied');
    button.querySelector('svg').innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>';
}

function uiScrollParent(el) {
    for (let node = el; node && node !== document.body; node = node.parentElement) {
        const overflow = getComputedStyle(node).overflowY;
        if ((overflow === 'auto' || overflow === 'scroll') && node.scrollHeight > node.clientHeight + 1) return node;
    }
    return document.scrollingElement || document.documentElement;
}

function uiKeepRowInView(list, rowSelector, keyAttr, draw) {
    const scroller = uiScrollParent(list);
    const top = scroller === document.scrollingElement || scroller === document.documentElement ? 0 : scroller.getBoundingClientRect().top;
    const anchor = [...list.querySelectorAll(rowSelector)].find(row => row.getBoundingClientRect().bottom > top);
    const key = anchor ? anchor.getAttribute(keyAttr) : null;
    const before = anchor ? anchor.getBoundingClientRect().top : 0;
    draw();
    if (key === null) return;
    const again = [...list.querySelectorAll(rowSelector)].find(row => row.getAttribute(keyAttr) === key);
    const moved = again ? again.getBoundingClientRect().top - before : 0;
    if (Math.abs(moved) >= 1) scroller.scrollTop += moved;
}

function uiTextHeld(box) {
    if (!box) return false;
    if (uiPress && uiPress.down && uiPress.target instanceof Node && box.contains(uiPress.target)) return true;
    const selection = window.getSelection();
    return Boolean(selection && selection.rangeCount && String(selection) && selection.getRangeAt(0).intersectsNode(box));
}

const uiSheetClosers = {};
const uiIsPhone = () => window.matchMedia('(max-width: 760px)').matches;

function uiSheetShow(id, { label = '', head = '', body = '', expand = false, progress = false, onClose = null } = {}) {
    let sheet = document.getElementById(id);
    const fresh = !sheet;
    if (fresh) {
        sheet = document.createElement('div');
        sheet.id = id;
        sheet.className = 'ui-sheet';
        document.body.appendChild(sheet);
    }
    uiSheetClosers[id] = onClose;
    const shown = JSON.stringify([label, head, body, expand, progress]);
    if (!fresh && (sheet.dataset.shown === shown || uiTextHeld(sheet))) return sheet;
    sheet.dataset.shown = shown;
    const focused = !fresh && document.activeElement && sheet.contains(document.activeElement) ? document.activeElement : null;
    const focusName = focused ? (focused.getAttribute('aria-label') || focused.textContent.trim()) : '';
    const old = sheet.querySelector('.ui-sheet-body');
    const keep = old ? old.scrollTop : 0;
    sheet.classList.toggle('is-expand', expand);
    sheet.innerHTML = `
        <div class="ui-sheet-back" onclick="uiSheetDismiss('${id}')"></div>
        <section class="ui-sheet-panel" role="dialog" aria-modal="true" aria-label="${escapeHtml(label)}">
            <span class="ui-sheet-grip" aria-hidden="true"></span>
            <div class="ui-sheet-head">${head}<button type="button" class="ui-icon-btn ui-sheet-x" onclick="uiSheetDismiss('${id}')" aria-label="Close" title="Close">${UI_CLOSE_ICON}</button></div>
            <div class="ui-sheet-body">${body}</div>
        </section>`;
    const bodyEl = sheet.querySelector('.ui-sheet-body');
    bodyEl.scrollTop = keep;
    if (expand) {
        const panel = sheet.querySelector('.ui-sheet-panel');
        if (sheet.dataset.height) panel.style.height = `${sheet.dataset.height}px`;
        bodyEl.addEventListener('scroll', () => {
            const height = panel.getBoundingClientRect().height;
            const room = window.innerHeight - height;
            const grow = Math.min(bodyEl.scrollTop, room);
            if (grow <= 0) return;
            panel.style.height = `${height + grow}px`;
            sheet.dataset.height = height + grow;
            bodyEl.scrollTop -= grow;
            sheet.classList.toggle('is-full', room - grow < 1);
        }, { passive: true });
    }
    if (progress) uiReadProgress(sheet.querySelector('.ui-sheet-head'), bodyEl);
    if (focused) {
        const again = [...sheet.querySelectorAll('button, a, input, select, [tabindex]')]
            .find(el => el.tagName === focused.tagName && (el.getAttribute('aria-label') || el.textContent.trim()) === focusName);
        if (again) again.focus({ preventScroll: true });
    }
    uiSheetSwipe(sheet, bodyEl, id);
    document.body.classList.add('ui-sheet-on');
    return sheet;
}

function uiReadProgress(head, scroller) {
    if (!head || !scroller) return;
    const box = head.parentElement;
    let bar = box.querySelector(':scope > .ui-read-bar');
    if (!bar) {
        bar = document.createElement('span');
        bar.className = 'ui-read-bar';
        bar.setAttribute('aria-hidden', 'true');
        bar.innerHTML = '<i></i>';
        box.appendChild(bar);
    }
    const update = () => {
        const room = scroller.scrollHeight - scroller.clientHeight;
        bar.classList.toggle('hidden', room <= 1);
        bar.style.height = `${head.offsetTop + head.offsetHeight}px`;
        bar.firstElementChild.style.width = `${room > 1 ? Math.min(100, scroller.scrollTop / room * 100) : 0}%`;
    };
    if (!scroller.dataset.readBar) {
        scroller.dataset.readBar = '1';
        scroller.addEventListener('scroll', update, { passive: true });
    }
    update();
    requestAnimationFrame(update);
}

function uiSheetDismiss(id) {
    const closer = uiSheetClosers[id];
    if (typeof closer === 'function') closer();
    else uiSheetClose(id);
}

function uiSheetClose(id) {
    const sheet = document.getElementById(id);
    if (sheet) sheet.remove();
    delete uiSheetClosers[id];
    if (!document.querySelector('.ui-sheet')) document.body.classList.remove('ui-sheet-on');
}

function uiSheetSwipe(sheet, body, id) {
    const panel = sheet.querySelector('.ui-sheet-panel');
    let startY = null, startHeight = 0, byHead = false, pulled = 0;
    panel.addEventListener('touchstart', event => {
        byHead = !!event.target.closest('.ui-sheet-head, .ui-sheet-grip');
        if (!byHead && body.scrollTop > 0) { startY = null; return; }
        startY = event.touches[0].clientY;
        startHeight = panel.getBoundingClientRect().height;
        pulled = 0;
        panel.style.transition = 'none';
        panel.classList.toggle('is-held', byHead);
    }, { passive: true });
    panel.addEventListener('touchmove', event => {
        if (startY === null) return;
        const moved = event.touches[0].clientY - startY;
        if (moved < 0 && byHead) {
            const height = Math.min(window.innerHeight, startHeight - moved);
            sheet.classList.add('is-expand');
            panel.style.height = `${height}px`;
            sheet.dataset.height = height;
            sheet.classList.toggle('is-full', window.innerHeight - height < 1);
        }
        pulled = Math.max(0, moved);
        panel.style.transform = pulled ? `translateY(${pulled}px)` : '';
    }, { passive: true });
    const end = () => {
        panel.classList.remove('is-held');
        if (startY === null) return;
        startY = null;
        panel.style.transition = 'transform .2s ease';
        if (pulled > Math.min(120, panel.offsetHeight / 4)) {
            panel.style.transform = 'translateY(100%)';
            setTimeout(() => uiSheetDismiss(id), 200);
        } else {
            panel.style.transform = '';
        }
    };
    panel.addEventListener('touchend', end);
    panel.addEventListener('touchcancel', end);
}

let uiSwipe = null;
let uiSwipeEndedAt = 0;

function uiSwipeDistance(row) {
    return Math.min(96, row.offsetWidth * 0.35);
}

function uiSwipeStill() {
    return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

function uiSwipeBack(row, still) {
    row.style.transition = still ? 'none' : 'transform .2s ease, opacity .2s ease';
    row.style.transform = '';
    row.style.opacity = '';
}

function uiSwipeDown(event) {
    if (event.pointerType !== 'touch' || uiSwipe) return;
    const row = event.target.closest && event.target.closest('[data-swipe]');
    const x = row && row.querySelector(':scope > .ui-alert-x');
    if (!x || x.disabled || x.hasAttribute('aria-busy') || !x.getClientRects().length) return;
    uiSwipe = { row, x, id: event.pointerId, x0: event.clientX, y0: event.clientY, dx: 0, moved: false };
}

function uiSwipeMove(event) {
    const s = uiSwipe;
    if (!s || event.pointerId !== s.id) return;
    const dx = event.clientX - s.x0, dy = event.clientY - s.y0;
    if (!s.moved) {
        if (Math.hypot(dx, dy) < 6) return;
        if (Math.abs(dy) > Math.abs(dx)) { uiSwipe = null; return; }
        s.moved = true;
        try { s.row.setPointerCapture(event.pointerId); } catch (e) {}
        s.row.style.transition = 'none';
    }
    s.dx = dx;
    s.row.style.transform = `translateX(${dx}px)`;
    s.row.style.opacity = String(Math.max(0.3, 1 - Math.abs(dx) / (s.row.offsetWidth || 1)));
}

function uiSwipeEnd(event) {
    const s = uiSwipe;
    if (!s || event.pointerId !== s.id) return;
    uiSwipe = null;
    if (!s.moved) return;
    uiSwipeEndedAt = Date.now();
    const still = uiSwipeStill();
    if (event.type !== 'pointerup' || Math.abs(s.dx) < uiSwipeDistance(s.row)) { uiSwipeBack(s.row, still); return; }
    s.row.style.transition = still ? 'none' : 'transform .2s ease, opacity .2s ease';
    s.row.style.transform = `translateX(${s.dx < 0 ? '-' : ''}100%)`;
    s.row.style.opacity = '0';
    s.x.click();
    const done = () => { if (s.row.isConnected) uiSwipeBack(s.row, still); };
    if (!s.x.hasAttribute('aria-busy')) { done(); return; }
    const watch = new MutationObserver(() => {
        if (s.x.hasAttribute('aria-busy')) return;
        watch.disconnect();
        done();
    });
    watch.observe(s.x, { attributes: true, attributeFilter: ['aria-busy'] });
}

document.addEventListener('pointerdown', uiSwipeDown);
document.addEventListener('pointermove', uiSwipeMove);
document.addEventListener('pointerup', uiSwipeEnd);
document.addEventListener('pointercancel', uiSwipeEnd);
document.addEventListener('click', event => {
    if (Date.now() - uiSwipeEndedAt > 400 || !event.target.closest || event.target.closest('.ui-alert-x')) return;
    if (event.target.closest('[data-swipe]')) { event.stopPropagation(); event.preventDefault(); }
}, true);

function uiToggleFilters(button) {
    const bar = button.closest('.ui-filters');
    const open = bar.classList.toggle('is-open');
    button.setAttribute('aria-expanded', String(open));
    if (open) {
        const first = bar.querySelector('.ui-fbar-more input, .ui-fbar-more select, .ui-fbar-more button');
        if (first) first.focus();
    }
}

function uiSelectPick(selectId, index) {
    const select = document.getElementById(selectId);
    if (!select) return;
    select.selectedIndex = index;
    select.dispatchEvent(new Event('change', { bubbles: true }));
    uiFilterBarSync();
}

function uiSelectDefault(select) {
    return [...select.options].find(o => o.defaultSelected) || select.options[0];
}

function uiFilterChanged(el) {
    if (el.matches('[data-no-filter]')) return false;
    if (el.matches('[data-filter-default]')) return el.value !== el.dataset.filterDefault;
    if (el.tagName === 'SELECT') {
        const initial = uiSelectDefault(el);
        return !!initial && el.value !== initial.value;
    }
    if (el.type === 'checkbox') return el.checked !== el.defaultChecked;
    if (el.type === 'hidden' || el.type === 'date' || el.type === 'datetime-local') return false;
    return el.value.trim() !== '';
}

function uiFilterBarSync() {
    document.querySelectorAll('select[data-picker-label]').forEach(select => {
        let slot = select.previousElementSibling;
        if (!slot || !slot.classList.contains('ui-picker-slot')) {
            slot = document.createElement('span');
            slot.className = 'ui-picker-slot';
            select.before(slot);
            select.classList.add('hidden');
        }
        const options = [...select.options];
        const chosen = select.selectedOptions[0] || options[0];
        const short = o => (o && (o.dataset.short || o.textContent.trim())) || '';
        slot.innerHTML = uiPicker({
            id: `${select.id}-picker`, label: select.dataset.pickerLabel, hostClass: select.dataset.pickerHost || '',
            value: escapeHtml(short(chosen)), set: uiFilterChanged(select),
            search: select.dataset.pickerSearch || (options.length > 10 ? `Search ${select.dataset.pickerLabel.toLowerCase()}` : ''),
            options: options.map((o, i) => ({ label: o.textContent.trim(), selected: o === chosen, onclick: `uiSelectPick('${escapeJsArg(select.id)}', ${i})` })),
        });
    });
    document.querySelectorAll('.ui-fbar').forEach(bar => {
        bar.querySelectorAll('.ui-picker[data-state]').forEach(host => {
            const input = document.getElementById(host.dataset.state);
            const button = host.querySelector('.ui-picker-btn');
            if (input && button) button.classList.toggle('is-set', uiFilterChanged(input));
        });
        const more = bar.querySelector('.ui-fbar-more');
        const badge = bar.querySelector('.ui-filters-toggle .ui-msg-filter-n');
        if (more && badge) {
            const changed = [...more.querySelectorAll('input, select')].filter(uiFilterChanged).length;
            badge.textContent = changed ? String(changed) : '';
            badge.classList.toggle('hidden', !changed);
            const name = changed ? `Filters, ${changed} in use` : 'Filters';
            const toggle = badge.closest('.ui-filters-toggle');
            if (toggle.getAttribute('aria-label') !== name) { toggle.setAttribute('aria-label', name); toggle.title = name; }
        }
        const summary = bar.nextElementSibling;
        const clear = summary && summary.classList.contains('ui-list-summary') && summary.querySelector('.ui-clear-filters');
        if (clear) clear.classList.toggle('hidden', !uiFilterBarOn(bar));
    });
    uiPickerRefocus();
}

function uiFilterBarOn(bar) {
    return [...bar.querySelectorAll('input, select')]
        .filter(el => !el.closest('.ui-picker-panel') || el.matches('[data-filter-default]'))
        .some(uiFilterChanged);
}

function uiTimeZoomClamp(span, limits) {
    const want = span.to - span.from;
    const len = Math.max(limits.min, Math.min(want, limits.to - limits.from));
    const from = Math.max(limits.from, Math.min(span.from - (len - want) / 2, limits.to - len));
    return { from, to: from + len };
}

function uiTimeZoomStep(span, limits, step) {
    const len = span.to - span.from;
    if (step === 'in' || step === 'out') {
        const mid = (span.from + span.to) / 2;
        const next = step === 'in' ? len / 2 : len * 2;
        return uiTimeZoomClamp({ from: mid - next / 2, to: mid + next / 2 }, limits);
    }
    const by = (step === 'later' ? 1 : -1) * len / 2;
    return uiTimeZoomClamp({ from: span.from + by, to: span.to + by }, limits);
}

function uiTimeZoom(box, opts) {
    const pointers = new Map();
    let state = 'idle';
    let start = null;
    let shown = null;
    let swallow = false;
    let wheelTimer = null;
    const rect = () => {
        const parent = box.offsetParent;
        if (!parent || !box.offsetWidth) return box.getBoundingClientRect();
        const p = parent.getBoundingClientRect();
        return { left: p.left + parent.clientLeft + box.offsetLeft, width: box.offsetWidth };
    };
    const timeAt = (x, span) => {
        const r = rect();
        return span.from + Math.max(0, Math.min(1, (x - r.left) / (r.width || 1))) * (span.to - span.from);
    };
    const barAt = x => {
        const bars = opts.bars();
        let best = null, gap = Infinity;
        for (const bar of bars) {
            const b = bar.getBoundingClientRect();
            const d = x < b.left ? b.left - x : x > b.right ? x - b.right : 0;
            if (d < gap) { gap = d; best = bar; }
        }
        return best;
    };
    const zoomed = () => { const s = opts.span(), l = opts.limits(); return s.to - s.from < l.to - l.from - 1; };
    const preview = (span, kind) => { shown = span; opts.preview(span, kind); };
    const finish = () => {
        const done = shown;
        state = 'idle'; start = null; shown = null;
        if (done) { swallow = true; opts.change(done); }
    };
    const cancel = () => {
        const was = state !== 'idle' && state !== 'pressing';
        state = 'idle'; start = null; shown = null;
        if (was && opts.cancel) opts.cancel();
    };
    const twoFingers = () => {
        const [a, b] = [...pointers.values()];
        return { mid: (a.x + b.x) / 2, dist: Math.max(8, Math.hypot(a.x - b.x, a.y - b.y)) };
    };
    const beginPinch = () => {
        const f = twoFingers();
        state = 'pinching';
        start = { span: shown || opts.span(), mid: f.mid, dist: f.dist };
    };
    const beginPan = p => { state = 'panning'; start = { span: shown || opts.span(), x: p.x }; };

    const onDown = event => {
        if (event.pointerType === 'mouse' && event.button !== 0) return;
        pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
        if (pointers.size === 2) {
            try { box.setPointerCapture(event.pointerId); } catch (e) {}
            beginPinch();
        } else if (pointers.size === 1) {
            state = 'pressing';
            start = { x: event.clientX, y: event.clientY };
        }
    };
    const onMove = event => {
        if (!pointers.has(event.pointerId)) return;
        pointers.set(event.pointerId, { x: event.clientX, y: event.clientY });
        const p = pointers.get(event.pointerId);
        if (state === 'pressing') {
            const dx = p.x - start.x, dy = p.y - start.y;
            if (Math.hypot(dx, dy) < 6) return;
            if (Math.abs(dy) > Math.abs(dx)) { state = 'idle'; pointers.delete(event.pointerId); return; }
            try { box.setPointerCapture(event.pointerId); } catch (e) {}
            if (zoomed()) beginPan({ x: start.x });
            else { state = 'selecting'; start = { x: start.x, span: opts.span() }; }
        }
        if (state === 'pinching' && pointers.size >= 2) {
            const f = twoFingers();
            const s = start.span, len = s.to - s.from;
            const anchor = timeAt(start.mid, s);
            const next = len * start.dist / f.dist;
            const ratio = (anchor - s.from) / len;
            const shift = (f.mid - start.mid) / (rect().width || 1) * next;
            preview(uiTimeZoomClamp({ from: anchor - ratio * next - shift, to: anchor - ratio * next - shift + next }, opts.limits()), 'pinch');
        } else if (state === 'panning') {
            const s = start.span, len = s.to - s.from;
            const by = -(p.x - start.x) / (rect().width || 1) * len;
            preview(uiTimeZoomClamp({ from: s.from + by, to: s.to + by }, opts.limits()), 'pan');
        } else if (state === 'selecting') {
            const a = barAt(start.x), b = barAt(p.x);
            if (!a || !b) return;
            const from = Math.min(Number(a.dataset.start), Number(b.dataset.start));
            const to = Math.max(Number(a.dataset.end), Number(b.dataset.end));
            preview({ from, to, x1: Math.min(start.x, p.x), x2: Math.max(start.x, p.x) }, 'select');
        }
    };
    const onUp = event => {
        if (!pointers.has(event.pointerId)) return;
        pointers.delete(event.pointerId);
        if (state === 'pinching') {
            if (pointers.size === 1) { beginPan([...pointers.values()][0]); return; }
            if (pointers.size === 0) finish();
            return;
        }
        if (pointers.size) return;
        if (state === 'selecting') {
            if (shown && shown.to - shown.from >= opts.limits().min) { const { from, to } = shown; shown = uiTimeZoomClamp({ from, to }, opts.limits()); finish(); }
            else cancel();
            return;
        }
        if (state === 'panning') { finish(); return; }
        state = 'idle';
    };
    const onCancel = event => {
        pointers.delete(event.pointerId);
        if (!pointers.size || state === 'pinching') cancel();
    };
    const onLost = event => {
        if (event.target === box && pointers.has(event.pointerId) && state !== 'idle') onCancel(event);
    };
    const onClick = event => {
        if (!swallow) return;
        swallow = false;
        event.preventDefault();
        event.stopPropagation();
    };
    const onWheel = event => {
        if (!event.ctrlKey) return;
        event.preventDefault();
        const unit = event.deltaMode === 1 ? 16 : event.deltaMode === 2 ? 400 : 1;
        const s = shown || opts.span(), len = s.to - s.from;
        const anchor = timeAt(event.clientX, s), ratio = (anchor - s.from) / len;
        const next = len * Math.exp(event.deltaY * unit * 0.004);
        preview(uiTimeZoomClamp({ from: anchor - ratio * next, to: anchor - ratio * next + next }, opts.limits()), 'wheel');
        clearTimeout(wheelTimer);
        wheelTimer = setTimeout(() => { if (shown) { swallow = false; const done = shown; shown = null; opts.change(done); } }, 220);
    };
    box.addEventListener('pointerdown', onDown);
    box.addEventListener('pointermove', onMove);
    box.addEventListener('pointerup', onUp);
    box.addEventListener('pointercancel', onCancel);
    box.addEventListener('lostpointercapture', onLost);
    box.addEventListener('click', onClick, true);
    box.addEventListener('wheel', onWheel, { passive: false });
    return {
        busy: () => state !== 'idle' && state !== 'pressing' || !!wheelTimer && !!shown,
        destroy() {
            clearTimeout(wheelTimer);
            box.removeEventListener('pointerdown', onDown);
            box.removeEventListener('pointermove', onMove);
            box.removeEventListener('pointerup', onUp);
            box.removeEventListener('pointercancel', onCancel);
            box.removeEventListener('lostpointercapture', onLost);
            box.removeEventListener('click', onClick, true);
            box.removeEventListener('wheel', onWheel);
        },
    };
}

function uiRedrawKeepingFocus(container, draw) {
    const active = document.activeElement;
    const inside = !!active && active !== container && container.contains(active);
    const name = el => el.getAttribute('aria-label') || el.textContent.trim();
    const was = inside ? {
        thumb: active.dataset ? active.dataset.thumb : undefined,
        start: active.dataset ? active.dataset.start : undefined,
        name: name(active),
        group: active.closest('[role="group"]')?.getAttribute('aria-label') || null,
        picked: container.querySelector('[data-start][aria-pressed="true"]')?.dataset.start,
    } : null;
    draw();
    if (!was) return;
    const shown = b => getComputedStyle(b).visibility !== 'hidden' && (typeof b.checkVisibility !== 'function' || b.checkVisibility());
    const enabled = sel => [...container.querySelectorAll(sel)].filter(b => !b.disabled && shown(b));
    const inGroup = was.group ? [...container.querySelectorAll('[role="group"]')].find(g => g.getAttribute('aria-label') === was.group) : null;
    const nearestBar = t => {
        const bars = [...container.querySelectorAll('[data-start][data-end]')];
        return bars.find(b => Number(b.dataset.start) <= t && t < Number(b.dataset.end))
            || bars.reduce((best, b) => (!best || Math.abs(b.dataset.start - t) < Math.abs(best.dataset.start - t) ? b : best), null);
    };
    const target = was.thumb !== undefined ? container.querySelector(`[data-thumb="${CSS.escape(was.thumb)}"]`)
        : was.start !== undefined
        ? container.querySelector(`[data-start="${CSS.escape(was.start)}"]`) || nearestBar(Number(was.start))
        : enabled(inGroup ? '[role="group"] button' : 'button').find(b => name(b) === was.name && (!inGroup || inGroup.contains(b)))
            || (was.picked !== undefined && container.querySelector(`[data-start="${CSS.escape(was.picked)}"]`))
            || (inGroup && enabled('button').find(b => inGroup.contains(b)))
            || null;
    if (target) target.focus({ preventScroll: true });
}

function uiSparkline(points, { days = 7, now = Date.now(), format = v => String(v), label = 'Trend' } = {}) {
    const W = 72, H = 18, pad = 2;
    const from = now - days * 86400000;
    const hourly = (points || []).filter(p => p.value !== null && p.value !== undefined && Date.parse(p.slot) >= from)
        .sort((a, b) => Date.parse(a.slot) - Date.parse(b.slot));
    const firstRead = hourly.length ? Number(hourly[0].value) : null, lastRead = hourly.length ? Number(hourly[hourly.length - 1].value) : null;
    const when = t => formatTime(t, { seconds: false });
    if (hourly.length < 2 || Date.parse(hourly[hourly.length - 1].slot) - Date.parse(hourly[0].slot) < 86400000) return '';
    const step = days > 2 ? 6 * 3600000 : 3600000;
    const pts = [];
    let group = null;
    const flush = () => { if (group) pts.push({ t: group.t / group.n, v: group.v / group.n, start: group.start }); group = null; };
    hourly.forEach((p, i) => {
        const t = Date.parse(p.slot), v = Number(p.value);
        const gap = i === 0 || t - Date.parse(hourly[i - 1].slot) > 5400000;
        const key = Math.floor(t / step);
        if (gap || !group || group.key !== key) { const start = gap; flush(); group = { key, t: 0, v: 0, n: 0, start }; }
        group.t += t; group.v += v; group.n += 1;
    });
    flush();
    const last = hourly[hourly.length - 1];
    pts.push({ t: Date.parse(last.slot), v: Number(last.value), start: false });
    const values = pts.map(p => p.v);
    const lo = Math.min(...values), hi = Math.max(...values);
    const x = t => pad + (Math.max(from, Math.min(now, t)) - from) / (now - from) * (W - 2 * pad);
    const y = v => (hi === lo ? H / 2 : H - pad - (v - lo) / (hi - lo) * (H - 2 * pad));
    const d = pts.map(p => `${p.start ? 'M' : 'L'}${x(p.t).toFixed(1)} ${y(p.v).toFixed(1)}`).join(' ');
    const lone = pts.filter((p, i) => p.start && i < pts.length - 1 && pts[i + 1].start)
        .map(p => `<circle class="is-lone" cx="${x(p.t).toFixed(1)}" cy="${y(p.v).toFixed(1)}" r="1.2"/>`).join('');
    const words = `${label}, last ${days} days: from ${format(firstRead)} to ${format(lastRead)}, as of ${when(Date.parse(last.as_of || last.slot))}`;
    return `<svg class="ui-spark-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${escapeHtml(words)}"><title>${escapeHtml(words)}</title><path d="${d}"/>${lone}<circle cx="${x(Date.parse(last.slot)).toFixed(1)}" cy="${y(Number(last.value)).toFixed(1)}" r="1.8"/></svg>`;
}

// Overview strip under a zoomable chart:

// The span a drag of the window by dt makes
function uiOverviewMove(start, dt, limits, snap = t => t) {
    const len = start.to - start.from;
    const sn = x => Math.max(limits.from, Math.min(limits.to, snap(x)));
    let from = Math.max(limits.from, Math.min(start.from + dt, limits.to - len));
    from = sn(from);
    const to = from + len >= limits.to - 1 ? limits.to : sn(from + len);
    return to - from >= limits.min ? { from, to } : { from: Math.max(limits.from, to - len), to };
}

function uiOverviewEdge(span, edge, t, limits, snap = t => t) {
    const at = x => (x >= limits.to - 1 ? limits.to : x <= limits.from + 1 ? limits.from : Math.max(limits.from, Math.min(limits.to, snap(x))));
    if (edge === 'start') {
        const most = span.to - limits.min;
        let x = Math.max(limits.from, Math.min(t, most));
        let from = at(x);
        for (let i = 0, d = from - most + 60000; i < 24 && from > most && x > limits.from; i++, d *= 2) { x -= d; from = at(Math.max(limits.from, x)); }
        return { from: Math.min(from, Math.max(limits.from, most)), to: span.to };
    }
    const least = span.from + limits.min;
    let x = Math.min(limits.to, Math.max(t, least));
    let to = at(x);
    for (let i = 0, d = least - to + 60000; i < 24 && to < least && x < limits.to; i++, d *= 2) { x += d; to = at(Math.min(limits.to, x)); }
    return { from: span.from, to: Math.max(to, Math.min(limits.to, least)) };
}

function uiOverviewCenter(span, t, limits, snap = t => t) {
    const len = span.to - span.from;
    return uiOverviewMove(span, t - len / 2 - span.from, limits, snap);
}

function uiNearestLocalHour(t) {
    const Q = 900000;
    const key = x => {
        const p = zonedParts(x);
        const offset = Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(x / 1000) * 1000;
        return `${p.year}-${p.month}-${p.day}-${p.hour}/${offset}`;
    };
    const k = key(t);
    let start = Math.floor(t / Q) * Q;
    for (let i = 0; i < 12 && key(start - Q) === k; i++) start -= Q;
    let next = start + Q;
    for (let i = 0; i < 12 && key(next) === k; i++) next += Q;
    return t - start <= next - t ? start : next;
}

function uiTimeOverview(box, opts) {
    box.querySelectorAll('.ui-ov-win, .ui-ov-thumb').forEach(el => el.remove());
    const win = document.createElement('div');
    win.className = 'ui-ov-win';
    win.setAttribute('aria-hidden', 'true');
    const thumb = edge => {
        const el = document.createElement('div');
        el.className = 'ui-ov-thumb';
        el.dataset.thumb = edge;
        el.tabIndex = 0;
        el.setAttribute('role', 'slider');
        el.setAttribute('aria-label', edge === 'start' ? 'Start of the span shown' : 'End of the span shown');
        return el;
    };
    const startThumb = thumb('start'), endThumb = thumb('end');
    box.append(win, startThumb, endThumb);
    let shown = null;
    let drag = null;
    let keyTimer = null;
    const snap = opts.snap || (t => t);
    const width = () => box.getBoundingClientRect().width || 1;
    const timeAt = x => {
        const l = opts.limits(), r = box.getBoundingClientRect();
        return l.from + Math.max(0, Math.min(1, (x - r.left) / (r.width || 1))) * (l.to - l.from);
    };
    const draw = span => {
        const l = opts.limits();
        const pos = t => ((t - l.from) / ((l.to - l.from) || 1)) * 100;
        const a = pos(span.from), b = pos(span.to);
        win.style.left = `${a}%`;
        win.style.width = `${Math.max(0, b - a)}%`;
        startThumb.style.left = `${a}%`;
        endThumb.style.left = `${b}%`;
        const set = (el, now, min, max) => {
            el.setAttribute('aria-valuemin', String(Math.round(min)));
            el.setAttribute('aria-valuemax', String(Math.round(max)));
            el.setAttribute('aria-valuenow', String(Math.round(now)));
            el.setAttribute('aria-valuetext', opts.label(now));
        };
        set(startThumb, span.from, l.from, Math.max(l.from, span.to - l.min));
        set(endThumb, span.to, Math.min(l.to, span.from + l.min), l.to);
    };
    const current = () => shown || opts.span();
    const commit = span => {
        const before = opts.span();
        shown = null;
        if (span && (span.from !== before.from || span.to !== before.to)) opts.change(span);
        else { draw(opts.span()); if (opts.idle) opts.idle(); }
    };
    draw(opts.span());

    const onDown = event => {
        if (event.pointerType === 'mouse' && event.button !== 0) return;
        if (drag) return;
        const edge = event.target.closest && event.target.closest('.ui-ov-thumb');
        const kind = edge ? edge.dataset.thumb : event.target === win ? 'move' : 'press';
        drag = { kind, x: event.clientX, y: event.clientY, span: current(), id: event.pointerId, moved: false };
    };
    const onMove = event => {
        if (!drag || event.pointerId !== drag.id) return;
        const dx = event.clientX - drag.x, dy = event.clientY - drag.y;
        if (!drag.moved) {
            if (Math.hypot(dx, dy) < 6) return;
            if (Math.abs(dy) > Math.abs(dx)) { drag = null; return; }
            drag.moved = true;
            try { box.setPointerCapture(event.pointerId); } catch (e) {}
        }
        const l = opts.limits();
        if (drag.kind === 'move') shown = uiOverviewMove(drag.span, dx / width() * (l.to - l.from), l, snap);
        else if (drag.kind === 'start' || drag.kind === 'end') shown = uiOverviewEdge(drag.span, drag.kind, timeAt(event.clientX), l, snap);
        else return;
        draw(shown);
    };
    const onUp = event => {
        if (!drag || event.pointerId !== drag.id) return;
        const d = drag;
        drag = null;
        if (d.moved) { commit(shown); return; }
        if (d.kind === 'press') commit(uiOverviewCenter(d.span, timeAt(event.clientX), opts.limits(), snap));
    };
    const onCancel = event => {
        if (!drag || event.pointerId !== drag.id) return;
        drag = null;
        shown = null;
        draw(opts.span());
        if (opts.idle) opts.idle();
    };
    const onKey = event => {
        const el = event.target.closest && event.target.closest('.ui-ov-thumb');
        if (!el) return;
        const edge = el.dataset.thumb, span = current(), l = opts.limits();
        const t = edge === 'start' ? span.from : span.to;
        let next;
        if (event.key === 'ArrowLeft' || event.key === 'ArrowDown') next = opts.step(t, -1, false);
        else if (event.key === 'ArrowRight' || event.key === 'ArrowUp') next = opts.step(t, 1, false);
        else if (event.key === 'PageDown') next = opts.step(t, -1, true);
        else if (event.key === 'PageUp') next = opts.step(t, 1, true);
        else if (event.key === 'Home') next = l.from;
        else if (event.key === 'End') next = l.to;
        else return;
        event.preventDefault();
        shown = uiOverviewEdge(span, edge, next, l, snap);
        draw(shown);
        clearTimeout(keyTimer);
        keyTimer = setTimeout(() => { keyTimer = null; commit(shown); }, 350);
    };
    box.addEventListener('pointerdown', onDown);
    box.addEventListener('pointermove', onMove);
    box.addEventListener('pointerup', onUp);
    box.addEventListener('pointercancel', onCancel);
    box.addEventListener('keydown', onKey);
    return {
        busy: () => !!(drag && drag.moved) || !!keyTimer,
        destroy() {
            clearTimeout(keyTimer);
            box.removeEventListener('pointerdown', onDown);
            box.removeEventListener('pointermove', onMove);
            box.removeEventListener('pointerup', onUp);
            box.removeEventListener('pointercancel', onCancel);
            box.removeEventListener('keydown', onKey);
        },
    };
}

// Phones: every dialog opens like the help sheet
function uiDialogSheet(backdrop) {
    const dialog = backdrop.querySelector(':scope > .ui-dialog');
    if (!dialog) return;
    dialog.style.height = '';
    if (uiIsPhone()) dialog.querySelectorAll('.ui-dialog-body').forEach(body => { body.scrollTop = 0; });
    dialog.style.transform = '';
    backdrop.classList.remove('is-grown', 'is-full');
    if (backdrop.dataset.sheet) return;
    backdrop.dataset.sheet = '1';
    const active = () => uiIsPhone() && !backdrop.classList.contains('ui-docked');

    backdrop.addEventListener('scroll', event => {
        const body = event.target;
        if (!active() || !(body instanceof Element) || !dialog.contains(body) || body.scrollTop <= 0) return;
        const height = dialog.getBoundingClientRect().height;
        const room = window.innerHeight - height;
        const grow = Math.min(body.scrollTop, room);
        if (grow < 1) return;
        backdrop.classList.add('is-grown');
        dialog.style.height = `${height + grow}px`;
        body.scrollTop -= grow;
        backdrop.classList.toggle('is-full', room - grow < 1);
    }, { capture: true, passive: true });

    let startY = null, startHeight = 0, fixedPart = false, pulled = 0;
    let ignore = false;
    const closeButton = () => {
        const button = dialog.querySelector('.ui-dialog-head [aria-label="Close"], .ui-dialog-head .ui-icon-btn')
            || dialog.querySelector(':scope > .ui-dialog-foot :is([data-cancel], [id$="-cancel"])');
        return button && !button.disabled ? button : null;
    };
    const cancelPull = () => {
        startY = null;
        pulled = 0;
        dialog.classList.remove('is-held');
        dialog.style.transition = 'transform .2s ease';
        dialog.style.transform = '';
    };
    dialog.addEventListener('touchstart', event => {
        if (event.touches.length > 1 || (event.target instanceof Element && event.target.closest('[data-zoom]'))) {
            ignore = true;
            cancelPull();
            return;
        }
        if (ignore) return;
        startY = null;
        if (!active()) return;
        fixedPart = !event.target.closest('.ui-dialog-body');
        if (!fixedPart) {
            for (let el = event.target; el && el !== dialog; el = el.parentElement) {
                if (el.scrollTop > 0) return;
            }
        }
        startY = event.touches[0].clientY;
        startHeight = dialog.getBoundingClientRect().height;
        pulled = 0;
        dialog.style.transition = 'none';
        dialog.classList.toggle('is-held', fixedPart);
    }, { passive: true });
    dialog.addEventListener('touchmove', event => {
        if (ignore || startY === null) return;
        const moved = event.touches[0].clientY - startY;
        if (moved < 0 && fixedPart) {
            const height = Math.min(window.innerHeight, startHeight - moved);
            backdrop.classList.add('is-grown');
            dialog.style.height = `${height}px`;
            backdrop.classList.toggle('is-full', window.innerHeight - height < 1);
        }
        pulled = closeButton() ? Math.max(0, moved) : 0;
        dialog.style.transform = pulled ? `translateY(${pulled}px)` : '';
    }, { passive: true });
    const end = event => {
        if (ignore) {
            if (!event || !event.touches || event.touches.length === 0) ignore = false;
            return;
        }
        dialog.classList.remove('is-held');
        if (startY === null) return;
        startY = null;
        dialog.style.transition = 'transform .2s ease';
        if (pulled > Math.min(120, dialog.offsetHeight / 4)) {
            dialog.style.transform = 'translateY(100%)';
            setTimeout(() => {
                const button = closeButton();
                if (button) button.click();
                dialog.style.transition = '';
                dialog.style.transform = '';
            }, 200);
        } else {
            dialog.style.transform = '';
        }
    };
    dialog.addEventListener('touchend', end);
    dialog.addEventListener('touchcancel', end);
}

function uiDialogSheetFull(backdrop) {
    const dialog = backdrop && backdrop.querySelector(':scope > .ui-dialog');
    if (!dialog || !uiIsPhone() || backdrop.classList.contains('ui-docked') || backdrop.classList.contains('is-full')) return;
    backdrop.classList.add('is-grown', 'is-full');
    dialog.style.height = `${window.innerHeight}px`;
}

if (typeof MutationObserver !== 'undefined' && document.body) new MutationObserver(records => {
    for (const record of records) {
        if (record.type === 'attributes') {
            const el = record.target;
            const wasHidden = /(^|\s)hidden(\s|$)/.test(record.oldValue || '');
            if (wasHidden && el.classList.contains('ui-dialog-backdrop') && !el.classList.contains('hidden')) uiDialogSheet(el);
            continue;
        }
        record.addedNodes.forEach(node => {
            if (!(node instanceof Element)) return;
            const found = node.matches('.ui-dialog-backdrop') ? [node] : [...node.querySelectorAll('.ui-dialog-backdrop')];
            found.filter(el => !el.classList.contains('hidden')).forEach(uiDialogSheet);
        });
    }
}).observe(document.body, { subtree: true, childList: true, attributes: true, attributeOldValue: true, attributeFilter: ['class'] });

const uiPickers = { open: null, held: null, query: {} };

function uiPickerIsOpen(id) {
    return uiPickers.open === id;
}

function uiPickerMatches(label, query) {
    const plain = text => text.toLowerCase().replace(/_/g, ' ');
    return !query || plain(label).includes(plain(query.trim()));
}

function uiPicker({ id, label, value, set = false, options = null, panel = '', panelLabel = '', panelClass = '', hostClass = '', onOpen = '', search = '', field = false, labelledBy = '', disabled = false, icon = false }) {
    const open = uiPickerIsOpen(id);
    const list = Array.isArray(options);
    const query = search ? (uiPickers.query[id] || '') : '';
    const items = list ? options.map(o => `<button type="button" role="option" class="ui-fct" tabindex="-1" aria-selected="${o.selected ? 'true' : 'false'}"${o.value !== undefined ? ` data-value="${escapeHtml(String(o.value))}"` : ''}${uiPickerMatches(o.label, query) ? '' : ' hidden'}${o.disabled ? ' disabled' : ''} onclick="${o.onclick}">${o.dot !== undefined ? `<i class="ui-fct-dot${o.dot ? ` ui-fct-${escapeHtml(o.dot)}` : ''}" aria-hidden="true"></i>` : ''}<span>${escapeHtml(o.label)}</span>${o.hint !== undefined ? `<small>${escapeHtml(String(o.hint))}</small>` : ''}</button>`).join('') : '';
    const anyShown = list && options.some(o => uiPickerMatches(o.label, query));
    let role = list ? 'listbox' : 'dialog';
    let body = list ? `<span class="ui-label" aria-hidden="true">${escapeHtml(label)}</span>${items}` : panel;
    if (list && search) {
        role = 'dialog';
        body = `<input type="search" class="ui-input ui-picker-search" placeholder="${escapeHtml(search)}" aria-label="${escapeHtml(search)}" aria-controls="${escapeHtml(id)}-list" aria-autocomplete="list" autocomplete="off" spellcheck="false" value="${escapeHtml(query)}">
            <span id="${escapeHtml(id)}-list" class="ui-fct-list ui-picker-list" role="listbox" aria-label="${escapeHtml(label)}">${items}</span>
            <span class="ui-picker-none ui-muted${anyShown ? ' hidden' : ''}" role="status">No matches</span>`;
    }
    const button = icon
        ? `<button type="button" class="ui-icon-btn ui-sort-btn-icon ui-picker-btn${set ? ' is-set' : ''}" aria-haspopup="${role}" aria-expanded="${open}" aria-controls="${escapeHtml(id)}-panel" aria-label="${escapeHtml(label)}" title="${escapeHtml(label)}">${UI_SORT_ICON}</button>`
        : field
        ? `<button type="button" class="ui-select ui-select-btn ui-picker-btn" aria-haspopup="${role}" aria-expanded="${open}" aria-controls="${escapeHtml(id)}-panel"${labelledBy ? ` aria-labelledby="${escapeHtml(labelledBy)}"` : ''}${disabled ? ' disabled' : ''}><span>${value}</span><svg class="ui-select-arrow" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg></button>`
        : `<button type="button" class="ui-msg-range ui-picker-btn${set ? ' is-set' : ''}" aria-haspopup="${role}" aria-expanded="${open}" aria-controls="${escapeHtml(id)}-panel"><span class="ui-picker-name">${escapeHtml(label)}:</span> ${value}</button>`;
    return `<span class="ui-popover-host ui-picker${field ? ' is-field' : ''}${hostClass ? ` ${hostClass}` : ''}" data-picker="${escapeHtml(id)}"${onOpen ? ` data-on-open="${escapeHtml(onOpen)}"` : ''}>
        ${button}
        <span id="${escapeHtml(id)}-panel" class="ui-popover ui-msg-time-panel ui-picker-panel${search ? ' has-search' : ''}${panelClass ? ` ${panelClass}` : ''}${open ? '' : ' hidden'}" role="${role}" aria-label="${escapeHtml(panelLabel || label)}">${body}</span>
    </span>`;
}

function uiPickerParts(id) {
    const host = [...document.querySelectorAll('.ui-picker')].find(el => el.dataset.picker === id);
    if (!host) return {};
    const button = host.querySelector('.ui-picker-btn');
    const panel = button && document.getElementById(button.getAttribute('aria-controls'));
    return { host, button, panel };
}

function uiPickerList(panel) {
    return panel.matches('[role="listbox"]') ? panel : panel.querySelector('[role="listbox"]');
}

function uiPickerItems(panel) {
    const list = uiPickerList(panel);
    return list ? [...list.querySelectorAll('[role="option"]')].filter(o => !o.hidden && !o.disabled) : [];
}

function uiPickerFocusables(panel) {
    return [...panel.querySelectorAll('button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])')]
        .filter(el => !el.disabled && !el.hidden && !el.closest('.hidden'));
}

function uiPickerBounds(panel) {
    const fixed = el => el && el.getClientRects().length && ['fixed', 'sticky'].includes(getComputedStyle(el).position);
    const top = document.querySelector('.ui-mtop');
    const bar = document.querySelector('.ui-tabbar');
    let lo = fixed(top) ? top.getBoundingClientRect().bottom : 0;
    let hi = fixed(bar) ? bar.getBoundingClientRect().top : window.innerHeight;
    for (let box = panel && panel.parentElement; box && box !== document.body; box = box.parentElement) {
        const style = getComputedStyle(box);
        if (style.overflowY === 'visible' && style.overflowX === 'visible') continue;
        const r = box.getBoundingClientRect();
        if (!r.height) continue;
        lo = Math.max(lo, r.top);
        hi = Math.min(hi, r.bottom);
    }
    return { top: lo + 8, bottom: hi - 8 };
}
function uiPickerPlace(panel) {
    panel.style.transform = '';
    panel.style.maxHeight = '';
    panel.style.overflowY = '';
    panel.classList.remove('is-up');
    const button = panel.parentElement && panel.parentElement.querySelector('.ui-picker-btn');
    let bounds = uiPickerBounds(panel);
    if (button) {
        const at = button.getBoundingClientRect();
        if (at.height && (at.bottom > bounds.bottom || at.top < bounds.top) && button.scrollIntoView) {
            button.scrollIntoView({ block: 'center', behavior: 'instant' });
            bounds = uiPickerBounds(panel);
        }
    }
    const down = panel.getBoundingClientRect();
    if (down.height && down.bottom > bounds.bottom) {
        panel.classList.add('is-up');
        const up = panel.getBoundingClientRect();
        if (up.bottom - bounds.top <= bounds.bottom - down.top) panel.classList.remove('is-up');
    }
    const placed = panel.getBoundingClientRect();
    if (placed.height && (placed.top < bounds.top || placed.bottom > bounds.bottom)) {
        const room = panel.classList.contains('is-up') ? placed.bottom - bounds.top : bounds.bottom - placed.top;
        if (room > 0) { panel.style.maxHeight = `${Math.floor(room)}px`; panel.style.overflowY = 'auto'; }
    }
    const rect = panel.getBoundingClientRect();
    const width = document.documentElement.clientWidth;
    let shift = 0;
    if (rect.right > width - 8) shift = width - 8 - rect.right;
    if (rect.left + shift < 8) shift = 8 - rect.left;
    if (shift) panel.style.transform = `translateX(${Math.round(shift)}px)`;
}

function uiPickerOpen(id) {
    if (uiPickers.open && uiPickers.open !== id) uiPickerClose(uiPickers.open);
    const { host, button, panel } = uiPickerParts(id);
    if (!panel) return;
    uiPickers.open = id;
    const hook = host.dataset.onOpen;
    if (hook && typeof window[hook] === 'function') window[hook]();
    panel.classList.remove('hidden');
    button.setAttribute('aria-expanded', 'true');
    uiPickerPlace(panel);
    uiPickerFocusInside(panel);
}

function uiPickerReveal(el, panel) {
    for (let box = el.parentElement; box; box = box.parentElement) {
        if (box.scrollHeight > box.clientHeight + 1) {
            const b = box.getBoundingClientRect(), r = el.getBoundingClientRect();
            if (r.top < b.top) box.scrollTop -= b.top - r.top;
            else if (r.bottom > b.bottom) box.scrollTop += r.bottom - b.bottom;
        }
        if (box === panel) break;
    }
}
function uiTouchOnly() {
    return typeof window.matchMedia === 'function' && window.matchMedia('(hover: none) and (pointer: coarse)').matches;
}
function uiPickerFocusInside(panel) {
    const still = { preventScroll: true };
    const show = el => { el.focus(still); uiPickerReveal(el, panel); };
    const search = panel.querySelector('.ui-picker-search');
    if (search && !uiTouchOnly()) { show(search); return; }
    if (search || panel.getAttribute('role') === 'listbox') {
        const items = uiPickerItems(panel);
        const target = items.find(o => o.getAttribute('aria-selected') === 'true') || items[0];
        if (target) show(target);
        return;
    }
    const first = panel.querySelector('input[type="radio"]:checked:not(:disabled)') || uiPickerFocusables(panel)[0];
    if (first) show(first);
    else { panel.setAttribute('tabindex', '-1'); panel.focus(still); }
}

function uiPickerFilter(panel, query) {
    const list = uiPickerList(panel);
    if (!list) return;
    let shown = 0;
    list.querySelectorAll('[role="option"]').forEach(option => {
        const match = uiPickerMatches(option.textContent, query);
        option.hidden = !match;
        if (match) shown++;
    });
    const none = panel.querySelector('.ui-picker-none');
    if (none) none.classList.toggle('hidden', shown > 0);
}

function uiPickerClose(id, { returnFocus = false } = {}) {
    if (uiPickers.open === id) uiPickers.open = null;
    const { button, panel } = uiPickerParts(id);
    if (panel) {
        panel.classList.add('hidden');
        panel.style.transform = '';
        panel.style.maxHeight = '';
        panel.style.overflowY = '';
        const search = panel.querySelector('.ui-picker-search');
        if (search && search.value) { search.value = ''; uiPickerFilter(panel, ''); }
    }
    delete uiPickers.query[id];
    if (button) {
        button.setAttribute('aria-expanded', 'false');
        if (returnFocus) uiPickerFocusButton(id);
    }
}

function uiPickerFocusButton(id) {
    const { button } = uiPickerParts(id);
    if (!button) return;
    uiPickers.held = id;
    button.focus();
}

function uiPickerRefocus() {
    const lost = !document.activeElement || document.activeElement === document.body;
    if (uiPickers.open) {
        const { panel } = uiPickerParts(uiPickers.open);
        if (panel && !panel.contains(document.activeElement)) {
            uiPickerPlace(panel);
            uiPickerFocusInside(panel);
        }
    } else if (uiPickers.held && lost) {
        uiPickerFocusButton(uiPickers.held);
    }
}

if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('click', event => {
        if (!(event.target instanceof Element)) return;
        const button = event.target.closest('.ui-picker-btn');
        if (button) {
            const id = button.closest('.ui-picker').dataset.picker;
            if (uiPickerIsOpen(id)) uiPickerClose(id);
            else uiPickerOpen(id);
            return;
        }
        const option = event.target.closest('.ui-picker [role="option"]');
        if (option) {
            const id = option.closest('.ui-picker').dataset.picker;
            uiPickerClose(id);
            requestAnimationFrame(() => uiPickerFocusButton(id));
            return;
        }
        if (uiPickers.open) {
            const { host } = uiPickerParts(uiPickers.open);
            if (!host || !host.contains(event.target)) uiPickerClose(uiPickers.open);
        }
    });

    document.addEventListener('input', event => {
        const search = event.target instanceof Element && event.target.closest('.ui-picker-search');
        if (!search) return;
        const id = search.closest('.ui-picker').dataset.picker;
        uiPickers.query[id] = search.value;
        uiPickerFilter(search.closest('.ui-picker-panel'), search.value);
    });

    document.addEventListener('keydown', event => {
        if (!(event.target instanceof Element)) return;
        const onButton = event.target.closest('.ui-picker-btn');
        if (onButton && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
            event.preventDefault();
            uiPickerOpen(onButton.closest('.ui-picker').dataset.picker);
            return;
        }
        const id = uiPickers.open;
        if (!id) return;
        const { panel } = uiPickerParts(id);
        if (!panel) return;
        if (event.key === 'Escape') {
            event.preventDefault();
            event.stopPropagation();
            uiPickerClose(id, { returnFocus: true });
            return;
        }
        if (!panel.contains(event.target)) return;
        const items = uiPickerItems(panel);
        const search = panel.querySelector('.ui-picker-search');
        if (search && event.target === search) {
            if (event.key === 'ArrowDown' && items.length) { event.preventDefault(); items[0].focus(); }
            else if (event.key === 'Enter') { event.preventDefault(); if (items.length) items[0].click(); }
            return;
        }
        const list = uiPickerList(panel);
        if (!list || !list.contains(event.target)) return;
        const at = items.indexOf(document.activeElement);
        const go = index => {
            event.preventDefault();
            if (index < 0 && search) { search.focus(); return; }
            items[Math.max(0, Math.min(items.length - 1, index))].focus();
        };
        if (event.key === 'ArrowDown') go(at + 1);
        else if (event.key === 'ArrowUp') go(at - 1);
        else if (event.key === 'Home') go(0);
        else if (event.key === 'End') go(items.length - 1);
    }, true);

    document.addEventListener('focusin', event => {
        if (uiPickers.held && event.target instanceof Element && !event.target.closest(`.ui-picker[data-picker="${uiPickers.held}"]`)) uiPickers.held = null;
    });

    document.addEventListener('focusout', event => {
        const id = uiPickers.open;
        if (!id || !(event.target instanceof Element)) return;
        const { host } = uiPickerParts(id);
        if (!host || !host.contains(event.target)) return;
        const next = event.relatedTarget;
        if (next && !host.contains(next) && !next.contains(host)) uiPickerClose(id);
    });

    if (typeof window.addEventListener === 'function') window.addEventListener('resize', () => {
        if (!uiPickers.open) return;
        const { panel } = uiPickerParts(uiPickers.open);
        if (panel) uiPickerPlace(panel);
    });
}

function uiKeepFocus(container, keyAttr, draw) {
    const active = document.activeElement;
    if (!container || !active || active === document.body || !container.contains(active)) {
        draw();
        return;
    }
    const row = active.closest(`[${keyAttr}]`);
    const key = row ? row.getAttribute(keyAttr) : null;
    const name = el => el.getAttribute('aria-label') || el.textContent.trim();
    const controls = el => [...el.querySelectorAll('button, a, input, select, [tabindex]')];
    const label = name(active);
    const index = row && active !== row ? controls(row).indexOf(active) : -1;
    draw();
    if (key === null) return;
    const again = [...container.querySelectorAll(`[${keyAttr}]`)].find(el => el.getAttribute(keyAttr) === key);
    if (!again) return;
    const list = controls(again);
    const same = index >= 0 && list[index] && list[index].tagName === active.tagName ? list[index] : null;
    const target = active === row ? again
        : list.find(el => el.tagName === active.tagName && name(el) === label) || same || (again.tabIndex >= 0 ? again : list[0]);
    if (target && typeof target.focus === 'function') target.focus({ preventScroll: true });
}
