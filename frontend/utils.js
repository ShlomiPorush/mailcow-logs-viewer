// =============================================================================
// Shared helpers - colors, escaping, formatting, clipboard, toasts
// =============================================================================
// Loaded as a classic script BEFORE app.js (same global scope - the same
// pattern router.js and spam_filter.js already use). Everything here must
// stay dependency-free apart from other helpers in this file, browser APIs,
// the vendored libs (marked, DOMPurify), and late-bound globals like
// appTimezone that app.js defines before any of these run.
// =============================================================================

const APP_COLORS = {
    // Email Direction Colors
    directions: {
        inbound: {
            // Indigo
            badge: 'bg-indigo-100 dark:bg-indigo-500/10 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-500/20',
            bg: 'bg-indigo-100 dark:bg-indigo-500/25',
            text: 'text-indigo-700 dark:text-indigo-400'
        },
        outbound: {
            // Blue
            badge: 'bg-blue-100 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border border-blue-200 dark:border-blue-500/20',
            bg: 'bg-blue-100 dark:bg-blue-500/25',
            text: 'text-blue-700 dark:text-blue-400'
        },
        internal: {
            // Teal
            badge: 'bg-teal-100 dark:bg-teal-500/10 text-teal-800 dark:text-teal-300 border border-teal-200 dark:border-teal-500/20',
            bg: 'bg-teal-100 dark:bg-teal-500/25',
            text: 'text-teal-700 dark:text-teal-400'
        }
    },
    statuses: {
        delivered: {
            // Emerald
            badge: 'bg-emerald-100 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border border-emerald-200 dark:border-emerald-500/20',
            bg: 'bg-emerald-100 dark:bg-emerald-500/25',
            text: 'text-emerald-700 dark:text-emerald-400'
        },
        sent: {
            // Green
            badge: 'bg-green-100 dark:bg-green-500/10 text-green-700 dark:text-green-300 border border-green-200 dark:border-green-500/20',
            bg: 'bg-green-100 dark:bg-green-500/25',
            text: 'text-green-700 dark:text-green-400'
        },
        deferred: {
            // Yellow (Fixed: Changed from Amber to Yellow)
            badge: 'bg-yellow-100 dark:bg-yellow-500/10 text-yellow-700 dark:text-yellow-300 border border-yellow-200 dark:border-yellow-500/20',
            bg: 'bg-yellow-100 dark:bg-yellow-500/25',
            text: 'text-yellow-700 dark:text-yellow-400'
        },
        bounced: {
            // Orange
            badge: 'bg-orange-100 dark:bg-orange-500/10 text-orange-700 dark:text-orange-300 border border-orange-200 dark:border-orange-500/20',
            bg: 'bg-orange-100 dark:bg-orange-500/25',
            text: 'text-orange-700 dark:text-orange-400'
        },
        rejected: {
            // Red
            badge: 'bg-red-100 dark:bg-red-500/10 text-red-700 dark:text-red-300 border border-red-200 dark:border-red-500/20',
            bg: 'bg-red-100 dark:bg-red-500/25',
            text: 'text-red-700 dark:text-red-400'
        },
        spam: {
            // Fuchsia
            badge: 'bg-fuchsia-100 dark:bg-fuchsia-500/10 text-fuchsia-700 dark:text-fuchsia-300 border border-fuchsia-200 dark:border-fuchsia-500/20',
            bg: 'bg-fuchsia-100 dark:bg-fuchsia-500/25',
            text: 'text-fuchsia-700 dark:text-fuchsia-400'
        },
        discarded: {
            // Slate - dropped by a Dovecot Sieve rule, never reached the mailbox
            badge: 'bg-slate-100 dark:bg-slate-500/10 text-slate-700 dark:text-slate-300 border border-slate-300 dark:border-slate-500/20',
            bg: 'bg-slate-100 dark:bg-slate-500/25',
            text: 'text-slate-700 dark:text-slate-400'
        },
        expired: {
            // Zinc
            badge: 'bg-zinc-100 dark:bg-zinc-500/10 text-zinc-700 dark:text-zinc-300 border border-zinc-200 dark:border-zinc-500/20',
            bg: 'bg-zinc-100 dark:bg-zinc-500/25',
            text: 'text-zinc-700 dark:text-zinc-400'
        }
    },
    // Default color for unknown values
    default: {
        badge: 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-300',
        bg: 'bg-gray-100 dark:bg-gray-700',
        text: 'text-gray-600 dark:text-gray-400'
    }
};

// Helper functions for accessing colors
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

// v3 status and direction tags (assets/css/ui.css). The colour follows the
// meaning: delivered and sent are good, deferred waits, bounced and rejected
// failed, spam is spam, anything else is neutral.
const UI_STATUS_TONE = {
    delivered: 'ok', sent: 'ok', deferred: 'warn', bounced: 'fail', rejected: 'fail', spam: 'spam',
};

// A v3 tag with the given text and tone (ok, warn, fail, spam, info or none)
function uiTag(text, tone) {
    return `<span class="ui-tag${tone ? ` ui-tag-${tone}` : ''}">${escapeHtml(String(text))}</span>`;
}

// Inbound, outbound and internal keep their own colours, as before the redesign
function uiDirectionTag(direction) {
    const known = ['inbound', 'outbound', 'internal'].includes(direction);
    return `<span class="ui-tag ui-tag-dir${known ? ` ui-dir-${direction}` : ''}">${escapeHtml(String(direction))}</span>`;
}

function uiStatusTag(status) {
    return uiTag(status, UI_STATUS_TONE[status]);
}

// The correlation status of a message (getCorrelationStatusDisplay) as a v3
// tag: same text and tooltip, tone from the final status; Linked is good and
// Pending waits.
function uiCorrelationTag(msg) {
    const status = getCorrelationStatusDisplay(msg);
    if (!status) return '';
    const tone = UI_STATUS_TONE[msg.final_status] || (msg.is_complete ? 'ok' : 'warn');
    const title = msg.final_status || (msg.is_complete ? 'Correlation complete' : 'Waiting for Postfix logs');
    // The word only; the symbol (checkmark, cross) of the old badge is left out, the tone carries it
    const text = status.display.replace(/^[^A-Za-z0-9]+\s*/, '');
    return `<span class="ui-tag ui-tag-${tone}" title="${escapeHtml(title)}">${escapeHtml(text)}</span>`;
}

// Tone of a netfilter action tag; the text comes from getActionLabel
function uiActionTone(action) {
    if (action === 'ban' || action === 'banned') return 'fail';
    if (action === 'unban') return 'ok';
    if (action === 'info') return 'info';
    return 'warn';
}

function uiActionTag(action) {
    return uiTag(getActionLabel(action), uiActionTone(action));
}

// The locked area (assets/css/ui.css .ui-locked): shown instead of silently
// hiding controls. Says what is missing and where to set it. textHtml is
// trusted markup written in this codebase, never data.
const UI_LOCK_ICON = '<svg class="ui-locked-icon" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 0 1 8 0v4"></path></svg>';

function uiLocked(title, textHtml, action = 'settings') {
    const button = action === 'settings'
        ? `<button type="button" class="ui-btn ui-btn-sm" onclick="navigateTo('settings')">Open Settings</button>`
        : (action || '');
    return `<div class="ui-locked">${UI_LOCK_ICON}<div><b>${escapeHtml(title)}</b><p>${textHtml}</p></div>${button}</div>`;
}

// The Read-Write key sentence used by every locked area that needs it
const UI_RW_KEY_TEXT = 'needs a <strong>Read-Write API key</strong> (<code>MAILCOW_API_KEY_RW</code>). Configure it in Settings → Mailcow → Connection.';

// The floating save bar every editable page uses, shown only with unsaved changes.
// Place it inside the page or tab it saves: a hidden page hides its bar too.
// save and discard are onclick code; with form, Save submits that form instead.
function uiSaveBar(id, { save = '', discard = '', form = '' } = {}) {
    const saveAttrs = form ? `type="submit" form="${form}"` : `type="button" onclick="${save}"`;
    return `<div class="ui-savebar hidden" id="${id}" role="region" aria-label="Unsaved changes">
            <span class="ui-savebar-count" aria-live="polite"></span>
            <button type="button" class="ui-btn ui-savebar-discard" onclick="${discard}">Discard</button>
            <button ${saveAttrs} class="ui-btn ui-savebar-save">Save changes</button>
        </div>`;
}

// Show the bar with the number of unsaved changes, or hide it at zero
function uiSaveBarUpdate(id, count) {
    const bar = document.getElementById(id);
    if (!bar) return;
    bar.classList.toggle('hidden', !count);
    const label = bar.querySelector('.ui-savebar-count');
    if (label) label.textContent = `${count} unsaved change${count === 1 ? '' : 's'}`;
}

// While saving: both buttons off and Save says so
function uiSaveBarBusy(id, busy) {
    const bar = document.getElementById(id);
    if (!bar) return;
    bar.querySelectorAll('button').forEach(b => { b.disabled = busy; });
    const save = bar.querySelector('.ui-savebar-save');
    if (save) save.textContent = busy ? 'Saving...' : 'Save changes';
}

function getCorrelationStatusDisplay(msg) {
    // If there's a final_status, show it with emoji
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

    // If no final_status but correlation is complete, show Linked
    if (msg.is_complete === true) {
        return { display: '✓ Linked', class: 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300' };
    }

    // If correlation is not complete, show Pending
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
            return 'BAN'; // Legacy support
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
        case 'banned': // Legacy support
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

// Escape a value embedded as a JS single-quoted string inside an inline HTML
// A list's count, as every list shows it above itself: "1,920 events", "1 device"
function uiCountLabel(n, one, many) {
    const count = Number(n) || 0;
    return `${count.toLocaleString()} ${count === 1 ? one : many}`;
}

// event handler, e.g. onclick="fn('${escapeJsArg(value)}')". escapeHtml is NOT
// safe there: the browser HTML-decodes the attribute (&#039; -> ') before the
// JS parser runs, letting a quote break out of the string. \xNN escapes leave
// no HTML-special characters, so the result is safe in both contexts.
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

// Render markdown to sanitized HTML. marked passes raw HTML through
// unchanged, so DOMPurify strips any script vectors before innerHTML.
// GitHub callouts ("> [!NOTE]", TIP, IMPORTANT, WARNING, CAUTION): marked
// leaves them as quotes, so give them their box and title. Works on the
// already sanitized HTML and only moves nodes and adds a text title.
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
    // Library failed to load - fail safe by escaping rather than injecting
    return escapeHtml(markdownText || '');
}

// Time for a list row: the time of day for today, the day and month before
// that, in the app timezone. The full timestamp goes in the row tooltip.
function formatListTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    if (zonedDateString(date) === zonedDateString(new Date())) {
        return formatInZone(date, { hour: '2-digit', minute: '2-digit', hour12: false });
    }
    return formatInZone(date, { day: 'numeric', month: 'short' });
}

// A "More" menu for a table row. It opens as a popover, so the table's own
// scrolling cannot clip it; the toggle listener below puts it under its button.
let uiMenuSeq = 0;
function uiMenu(label, itemsHtml) {
    const id = `ui-menu-${++uiMenuSeq}`;
    return `<button type="button" class="ui-btn ui-btn-sm" popovertarget="${id}" aria-haspopup="menu">${escapeHtml(label)}</button>
        <div id="${id}" popover class="ui-menu" role="menu" onclick="if (event.target.closest('button')) this.hidePopover()">${itemsHtml}</div>`;
}

// Called once at startup: places an opening menu and closes it on scroll
function uiInitMenus() {
    document.addEventListener('toggle', event => {
        const menu = event.target;
        if (!(menu instanceof HTMLElement) || !menu.classList.contains('ui-menu') || event.newState !== 'open') return;
        const button = document.querySelector(`[popovertarget="${menu.id}"]`);
        if (!button) return;
        const r = button.getBoundingClientRect();
        const rtl = getComputedStyle(button).direction === 'rtl';
        const left = rtl ? r.left : r.right - menu.offsetWidth;
        menu.style.left = `${Math.max(8, Math.min(left, window.innerWidth - menu.offsetWidth - 8))}px`;
        const below = r.bottom + 4;
        menu.style.top = `${below + menu.offsetHeight > window.innerHeight - 8 ? Math.max(8, r.top - menu.offsetHeight - 4) : below}px`;
    }, true);

    // An open menu would drift away from its button on scroll, so close it
    window.addEventListener('scroll', () => {
        document.querySelectorAll('.ui-menu:popover-open').forEach(menu => menu.hidePopover());
    }, true);
}

// "6 min ago", "3 h ago", "2 d ago"; the full time is for a tooltip
function formatAgo(isoString) {
    if (!isoString) return '-';
    const minutes = Math.max(0, Math.round((Date.now() - new Date(isoString).getTime()) / 60000));
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.round(minutes / 60);
    if (hours < 48) return `${hours} h ago`;
    return `${Math.round(hours / 24)} d ago`;
}

// A time written as "5 min ago" in an element, with the exact time on hover. The
// labels are written again every 30 seconds, so the page does not go stale.
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

// ---------------------------------------------------------------------------
// The app's time zone. Every time on screen, every "day" and every time a user
// types or picks follows the zone the server works in (/api/info `timezone`:
// TZ or Settings > Application, UTC when unset), never the browser's zone.
// ---------------------------------------------------------------------------

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

// The wall-clock parts of an instant in the app's zone (month is 1-12)
function zonedParts(value, tz = appTz()) {
    const date = value instanceof Date ? value : new Date(value);
    const parts = {};
    for (const p of tzPartFormat(tz).formatToParts(date)) parts[p.type] = p.value;
    return {
        year: +parts.year, month: +parts.month, day: +parts.day,
        hour: +parts.hour, minute: +parts.minute, second: +parts.second, weekday: parts.weekday
    };
}

// The instant whose wall-clock time in the app's zone is the one given. A time
// skipped by a daylight saving change moves forward; a repeated one takes the
// first of the two.
function zonedTimeToDate(year, month, day, hour = 0, minute = 0, second = 0, tz = appTz()) {
    const wall = Date.UTC(year, month - 1, day, hour, minute, second);
    const offsetAt = t => {
        const p = zonedParts(new Date(t), tz);
        return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - t;
    };
    const wallOf = t => t + offsetAt(t);
    // The offsets a day before and after cover both sides of any change
    const early = wall - offsetAt(wall - 86400000);
    const late = wall - offsetAt(wall + 86400000);
    const fits = [early, late].filter(t => wallOf(t) === wall);
    return new Date(fits.length ? Math.min(...fits) : early);
}

const pad2 = n => String(n).padStart(2, '0');

// YYYY-MM-DD of an instant in the app's zone
function zonedDateString(value = new Date(), tz = appTz()) {
    const p = zonedParts(value, tz);
    return `${p.year}-${pad2(p.month)}-${pad2(p.day)}`;
}

// YYYY-MM-DD n days after another one (calendar days, no zone involved)
function addDaysToDateString(dateStr, days) {
    const [y, m, d] = dateStr.split('-').map(Number);
    const next = new Date(Date.UTC(y, m - 1, d + days));
    return `${next.getUTCFullYear()}-${pad2(next.getUTCMonth() + 1)}-${pad2(next.getUTCDate())}`;
}

// The instant a day (YYYY-MM-DD) starts in the app's zone
function zonedDayStart(dateStr, tz = appTz()) {
    const [y, m, d] = dateStr.split('-').map(Number);
    return zonedTimeToDate(y, m, d, 0, 0, 0, tz);
}

// The same wall-clock time n days later (or earlier) in the app's zone, so a
// daylight saving change in between does not move the hour
function addDaysInZone(value, days, tz = appTz()) {
    const p = zonedParts(value, tz);
    return zonedTimeToDate(p.year, p.month, p.day + days, p.hour, p.minute, p.second, tz);
}

// A day (YYYY-MM-DD) written as it is, with Intl options; no zone moves it
function formatDayKey(dateStr, options, locale = 'en-US') {
    const [y, m, d] = String(dateStr).slice(0, 10).split('-').map(Number);
    if (!y || !m || !d) return '-';
    return new Intl.DateTimeFormat(locale, { ...options, timeZone: 'UTC' }).format(new Date(Date.UTC(y, m - 1, d)));
}

// The value of an <input type="datetime-local"> for an instant, in the app's zone
function toZonedInputValue(value, tz = appTz()) {
    const p = zonedParts(value, tz);
    return `${p.year}-${pad2(p.month)}-${pad2(p.day)}T${pad2(p.hour)}:${pad2(p.minute)}`;
}

// The instant an <input type="datetime-local"> value means, read in the app's zone
function fromZonedInputValue(text, tz = appTz()) {
    const m = /^(\d{4})-(\d{2})-(\d{2})(?:T(\d{2}):(\d{2})(?::(\d{2}))?)?$/.exec(text || '');
    if (!m) return null;
    return zonedTimeToDate(+m[1], +m[2], +m[3], +(m[4] || 0), +(m[5] || 0), +(m[6] || 0), tz);
}

// Intl formatting in the app's zone
function formatInZone(value, options, locale = undefined) {
    const date = value instanceof Date ? value : new Date(value);
    if (isNaN(date)) return '-';
    return new Intl.DateTimeFormat(locale, { ...options, timeZone: appTz() }).format(date);
}

function formatTime(isoString) {
    if (!isoString) return '-';
    return formatInZone(isoString, {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    });
}

// A day as formatTime writes it (its date part), and its day and month alone (a chart's axis)
function formatDay(value) {
    return formatInZone(value, { day: '2-digit', month: '2-digit', year: 'numeric' });
}

function formatDayMonth(value) {
    return formatInZone(value, { day: '2-digit', month: '2-digit' });
}

function formatDate(isoString) {
    if (!isoString) return '-';
    // Use formatTime for consistent date/time formatting
    return formatTime(isoString);
}

// DD/MM of a day (YYYY-MM-DD) as written, or of an instant in the app's zone
function formatDateShort(dateStr) {
    const day = /^\d{4}-\d{2}-\d{2}$/.test(dateStr) ? dateStr : zonedDateString(dateStr);
    const [, month, date] = day.split('-');
    return `${date}/${month}`;
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

function copyToClipboard(text, event) {
    if (event) {
        event.stopPropagation();
        event.preventDefault();
    }
    // Browsers offer the clipboard only over HTTPS (and on localhost)
    if (!navigator.clipboard) {
        showToast('Copying needs HTTPS. Select the text and copy it yourself.', 'error');
        return;
    }
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied: ' + text, 'success');
        // Brief visual feedback on the icon
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
    // escapeJsArg handles both the JS-string and HTML-attribute contexts
    const safeText = escapeJsArg(text);
    return `<span class="copyable${cls}" onclick="copyToClipboard('${safeText}', event)" title="Click to copy"><bdi>${escaped}</bdi><svg class="copy-icon w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></span>`;
}

// options.action: { label, ariaLabel, onAction } a button that runs onAction and
// closes the toast (Undo, Retry); options.duration: how long it stays (ms; Infinity
// keeps it until closed). One toast at a time: a new one replaces the last, and
// the keyboard's place moves with it if it was in the one replaced.
function showToast(message, type = 'info', options = {}) {
    // Remove existing toast if any
    const existingToast = document.getElementById('toast-notification');
    const focusWasInIt = !!existingToast && existingToast.contains(document.activeElement);
    if (existingToast) {
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
    toast.className = `ui-toast ui-toast-${kind}`;
    toast.setAttribute('role', kind === 'error' ? 'alert' : 'status');
    toast.innerHTML = `
        <span class="ui-toast-icon" aria-hidden="true">${icons[kind]}</span>
        <p>${escapeHtml(message)}</p>
        ${options.action ? `<button type="button" class="ui-btn ui-btn-sm ui-toast-action"${options.action.ariaLabel ? ` aria-label="${escapeHtml(options.action.ariaLabel)}"` : ''}>${escapeHtml(options.action.label)}</button>` : ''}
        <button type="button" onclick="this.parentElement.remove()" class="ui-icon-btn" title="Close" aria-label="Close">×</button>
    `;
    // An action still running holds the toast like the pointer or the keyboard does
    let busy = false;
    // Set below where the toast has a timer (not for one that stays until closed)
    let holdNow = () => {};
    if (options.action) {
        const button = toast.querySelector('.ui-toast-action');
        button.addEventListener('click', () => {
            if (busy) return;
            const result = options.action.onAction();
            if (!result || typeof result.then !== 'function') { toast.remove(); return; }
            // Until it is done the toast stays, with the keyboard in it: what comes next
            // (a message, Retry) takes the keyboard over from here
            busy = true;
            holdNow();
            button.setAttribute('aria-disabled', 'true');
            Promise.resolve(result).catch(() => {}).finally(() => { if (toast.isConnected) toast.remove(); });
        });
    }

    document.body.appendChild(toast);
    if (options.duration === Infinity) {
        if (focusWasInIt) toast.querySelector('button').focus({ preventScroll: true });
        return;
    }

    // It goes after 4 seconds (or its own duration), but waits while the pointer or the
    // focus is on it, and then gives the rest of its time (at least 1.5 seconds) to read it
    let left = options.duration || 4000;
    let started = Date.now();
    let timer = null;
    const hold = () => busy || toast.matches(':hover') || toast.contains(document.activeElement);
    let fading = false;
    let removing = null;
    const fade = () => {
        if (!toast.parentElement) return;
        // An action still running: the toast waits for it (its end removes the toast)
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
        // Caught while it fades (the pointer, the keyboard, a click on its action): it comes back
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

// =============================================================================
// Shared UI helpers used across pages (confirm dialog, status/job cards)
// =============================================================================

/**
 * Show a styled confirmation modal (replaces native confirm()).
 * Returns a Promise<boolean>: true if confirmed, false if cancelled.
 */
function showConfirmModal({ title = 'Confirm', message = 'Are you sure?', confirmText = 'Confirm', cancelText = 'Cancel', confirmColor, isDangerous = false, focusCancel = false, noHistory = false } = {}) {
    return new Promise((resolve) => {
        const existing = document.getElementById('app-confirm-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'app-confirm-modal';
        overlay.className = 'ui-dialog-backdrop ui-confirm';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-label', title);
        // A question asked during Back or Forward writes no history entry of its own
        if (noHistory) overlay.dataset.noHistory = '';

        // Callers pass plain text (channel names, emails, domains, ...) - escape
        // it before it goes into innerHTML, then turn newlines into breaks.
        const escapedMessage = escapeHtml(message).replace(/\n/g, '<br>');

        overlay.innerHTML = `
            <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
                <div class="ui-dialog-head"><h3>${escapeHtml(title)}</h3></div>
                <div class="ui-dialog-body"><p class="ui-confirm-text">${escapedMessage}</p></div>
                <div class="ui-dialog-foot">
                    <button type="button" id="app-confirm-cancel" class="ui-btn">${escapeHtml(cancelText)}</button>
                    <button type="button" id="app-confirm-ok" class="ui-btn ${isDangerous ? 'ui-btn-danger-solid' : 'ui-btn-primary'}"
                        ${confirmColor ? `style="background: ${escapeHtml(confirmColor)}"` : ''}>${escapeHtml(confirmText)}</button>
                </div>
            </div>
        `;

        document.body.appendChild(overlay);
        document.body.style.overflow = 'hidden';

        const cancelBtn = document.getElementById('app-confirm-cancel');
        const okBtn = document.getElementById('app-confirm-ok');

        function cleanup(result) {
            overlay.remove();
            document.body.style.overflow = '';
            resolve(result);
        }
        // Escape (through the layers in router.js) and a click outside cancel
        overlay.addEventListener('click', (e) => { if (uiBackdropClick(e)) cleanup(false); });
        cancelBtn.addEventListener('click', () => cleanup(false));
        okBtn.addEventListener('click', () => cleanup(true));
        setTimeout(() => (focusCancel ? cancelBtn : okBtn).focus(), 100);
    });
}

// A dialog with several answers: resolves to the picked choice's value, or
// null for Cancel, Escape or a click outside. Focus starts on Cancel, so
// Enter never picks a destructive choice by itself.
// choices: [{ value, label, kind: 'primary' | 'danger' | '' }]
// A second dialog closes the first as cancelled, listener and all.
let choiceModalClose = null;
function showChoiceModal({ title, message, choices, cancelText = 'Cancel' }) {
    if (choiceModalClose) choiceModalClose(null);
    return new Promise((resolve) => {
        const overlay = document.createElement('div');
        overlay.id = 'app-choice-modal';
        overlay.className = 'ui-dialog-backdrop ui-confirm';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-label', title);
        overlay.setAttribute('aria-describedby', 'app-choice-text');
        const buttons = choices.map((c, i) => `<button type="button" class="ui-btn${c.kind === 'danger' ? ' ui-btn-danger-solid' : c.kind === 'primary' ? ' ui-btn-primary' : ''}" data-choice="${i}">${escapeHtml(c.label)}</button>`).join('');
        overlay.innerHTML = `
            <div class="ui-dialog ui-dialog-fit ui-dialog-sm">
                <div class="ui-dialog-head"><h3>${escapeHtml(title)}</h3></div>
                <div class="ui-dialog-body"><p class="ui-confirm-text" id="app-choice-text">${escapeHtml(message).replace(/\n/g, '<br>')}</p></div>
                <div class="ui-dialog-foot"><button type="button" class="ui-btn" data-cancel>${escapeHtml(cancelText)}</button>${buttons}</div>
            </div>`;
        document.body.appendChild(overlay);
        document.body.style.overflow = 'hidden';
        // Escape cancels and the page behind is inert, both through the layers
        // (router.js), which also give the focus back to the opener
        function done(result) {
            if (choiceModalClose === done) choiceModalClose = null;
            overlay.remove();
            document.body.style.overflow = '';
            resolve(result);
        }
        choiceModalClose = done;
        overlay.addEventListener('click', (e) => { if (uiBackdropClick(e)) done(null); });
        overlay.querySelector('[data-cancel]').addEventListener('click', () => done(null));
        overlay.querySelectorAll('[data-choice]').forEach(btn => btn.addEventListener('click', () => done(choices[Number(btn.dataset.choice)].value)));
        setTimeout(() => overlay.querySelector('[data-cancel]').focus(), 50);
    });
}

// A dialog where something is typed asks before it drops what was changed:
// Cancel, Close, Escape and Back all close it through uiCancelDialog. The
// starting point is taken once the dialog shows its first values; a save closes
// the dialog directly and asks nothing
const uiDialogStarts = new WeakMap();
function uiFormValues(root) {
    return JSON.stringify([...root.querySelectorAll('input, select, textarea')].map(el => {
        if (el.type === 'checkbox' || el.type === 'radio') return el.checked;
        if (el.tagName === 'SELECT') return [...el.options].map(o => o.selected);
        return el.value;
    }));
}
function uiGuardDialog(modal) {
    if (modal) uiDialogStarts.set(modal, uiFormValues(modal));
}
let uiDiscardAsking = null;   // the dialog whose discard question is open
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
// A save closes its dialog at once; a discard question still open for it goes too
function uiDialogSaved(modal) {
    if (modal && uiDiscardAsking === modal) document.getElementById('app-confirm-cancel')?.click();
}
function uiCloseSavedDialog(id) {
    const modal = document.getElementById(id);
    uiDialogSaved(modal);
    modal?.remove();
}

// What the server said went wrong, in words: its detail text, a detail object's
// message, or a validation list (FastAPI 422) as "field: problem" for each field
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

// =============================================================================
// Changes not saved yet. A page or an editor that would lose them registers how
// many it holds: uiUnsavedRegister(key, { count, keeps }). Moving away (another
// page, Back and Forward, Refresh, the editor's own way back) asks first, and
// closing or reloading the browser tab asks through the browser. keeps(target)
// says which moves keep the changes: Settings keeps them across its sections,
// Security keeps them across pages. A planned reload clears the list first.
// target: { route, params } a move, { route, params, reload: true } the same page
// loaded again, nothing: the browser leaving the app.
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
let uiUnsavedAsking = null;   // the open question, so one move asks once
// keep: Leave does not drop the changes yet (signing out drops them only once it worked)
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
        // The reason comes from the server (no IMAP, no MaxMind key, no Read-Write key, a setting that is off)
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

    const runs = [
        job.interval,
        job.schedule,
        job.retention ? `keeps ${job.retention}` : '',
        job.max_age ? `Max: ${job.max_age}` : '',
        job.expire_after ? `Expire: ${job.expire_after}` : '',
    ].filter(Boolean);

    // A healthy job shows a green dot and no tag; everything else says what it is
    const failed = !isDisabled && job.status === 'failed';
    const dot = isDisabled ? '' : failed ? ' ui-mdot-fail' : job.status === 'running' ? ' ui-mdot-info' : job.status === 'success' ? ' ui-mdot-ok' : '';
    return `
        <div class="ui-jobrow${isDisabled ? ' is-off' : ''}${failed ? ' is-failed' : ''}">
            <i class="ui-mdot${dot}"></i>
            <span class="ui-jobrow-name"><b>${escapeHtml(name)}</b>${job.description ? `<small title="${escapeHtml(job.description)}">${escapeHtml(job.description)}</small>` : ''}${isDisabled && !isFeatureOff && job.disabled_reason ? `<small class="ui-text-warn">${escapeHtml(job.disabled_reason)}</small>` : ''}</span>
            <span class="ui-jobrow-runs">${escapeHtml(runs.join(', ') || '-')}${job.pending_items !== undefined ? ` <small class="ui-text-warn">Pending: ${escapeHtml(String(job.pending_items))}</small>` : ''}</span>
            <span class="ui-jobrow-last" title="${job.last_run ? escapeHtml(formatTime(job.last_run)) : ''}">${job.last_run ? formatAgo(job.last_run) : 'Not run yet'}</span>
            <span class="ui-jobrow-tag">${job.status === 'success' && !isDisabled ? '' : statusBadge}</span>
            <span class="ui-jobrow-act">${!isDisabled ? `
                <button onclick="triggerBackgroundJob('${escapeJsArg(jobKey)}', this, '${escapeJsArg(name)}')"
                    class="ui-btn ui-btn-sm" ${isRunning ? 'disabled' : ''} title="${isRunning ? 'Job is running' : 'Run this job now'}">Run</button>`
                : !isFeatureOff && job.settings_section ? `
                <button onclick="navigateTo('settings', { sub: '${escapeJsArg(job.settings_section)}' })" class="ui-btn ui-btn-sm"
                    title="${escapeHtml(job.disabled_reason || '')}">Settings</button>` : ''}</span>
            ${job.error ? `<p class="ui-job-error ui-mono">${escapeHtml(job.error)}</p>` : ''}
        </div>
    `;
}

// Shared message-list metadata.
// The folder Dovecot actually delivered a message into. A folder other than
// the inbox is the usual explanation for "the mail never arrived" when Rspamd
// did not flag it as spam (issue #65).
function renderMailboxFolderHint(msg) {
    if (msg.dovecot_status !== 'stored') return '';
    const folder = msg.dovecot_mailbox;
    if (!folder) return '';
    return `<span>Folder: ${escapeHtml(folder)}</span>`;
}

// A message that was delivered more than once - forwarded, copied or released
// from quarantine - is one row in the list (issue #36). Shown as a plain
// metadata entry; the dialog shows the deliveries as a journey.
function renderDeliveriesChip(msg) {
    const deliveries = msg.deliveries || 1;
    if (deliveries < 2) return '';
    return `<span>Deliveries: ${escapeHtml(String(deliveries))}</span>`;
}

// =============================================================================
// Sortable table headers. A click on a column header sorts the rows: numbers
// high to low first, text A to Z first, and a second click turns it around.
// The order survives the page's own refreshes. A table paged on the server
// names a handler instead (data-sort-handler) and its sortable headers carry
// the server's field (data-sort-key), so the order covers every page. A table
// or a header with data-nosort, and headers with no text, do not sort.
// =============================================================================

const uiTableSorts = new Map();

function uiSortHeads(table) {
    const head = table.tagName === 'TABLE' ? table.querySelector('thead tr') : table.querySelector(':scope > .ui-tr-head');
    return head ? [...head.children] : [];
}

// A header's own words, without the order a screen reader is told after them
function uiSortLabel(cell) {
    return cell.dataset.sortLabel !== undefined ? cell.dataset.sortLabel : cell.textContent.trim();
}

function uiTableKey(table) {
    const owner = table.id ? table : table.closest('[id]');
    return `${owner ? owner.id : ''}|${uiSortHeads(table).map(uiSortLabel).join('|')}`;
}

function uiSortable(table, cell) {
    if (!cell || table.hasAttribute('data-nosort') || cell.hasAttribute('data-nosort')) return false;
    // A table in help or release notes is text to read, not a list
    if (table.closest('.markdown-body')) return false;
    if (table.hasAttribute('data-sort-handler')) return cell.hasAttribute('data-sort-key');
    const label = uiSortLabel(cell);
    return label !== '' && !/^actions?$/i.test(label);
}

// The order a header shows: none, ascending or descending. A page that sorts on
// the server writes it as aria-sort in its header; aria-sort stays only on a real
// column header (th), and a list's header button says the order in words
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

// A sortable header holds a button, so the keyboard reaches it and Enter or Space sorts
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

// The value a cell sorts by: its data-sort, else its text read as a number,
// a size, a time ago or a date when it is one
function uiSortValue(cell) {
    if (!cell) return { n: null, t: '' };
    if (cell.hasAttribute && cell.hasAttribute('data-sort')) {
        const v = cell.getAttribute('data-sort');
        return isNaN(Number(v)) ? { n: null, t: v.toLowerCase() } : { n: Number(v), t: v };
    }
    const copy = cell.cloneNode(true);
    copy.querySelectorAll('.ui-sec-unit, .ui-phone-only').forEach(el => el.remove());
    const text = copy.textContent.replace(/\s+/g, ' ').trim();
    const t = text.toLowerCase();
    if (!text || text === '-') return { n: null, t: '' };
    const size = text.match(/^(-?\d+(?:[.,]\d+)?)\s*(b|kb|mb|gb|tb)$/i);
    if (size) return { n: parseFloat(size[1].replace(',', '.')) * 1024 ** ['b', 'kb', 'mb', 'gb', 'tb'].indexOf(size[2].toLowerCase()), t };
    // A time ago (recent first when high to low) or a plain duration (longest first)
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
        // The app writes dates as MM/DD/YYYY or DD.MM.YYYY; either reads in order once the year leads
        const dotted = /\d\.\d/.test(text);
        const y = String(c).length === 4 ? c : a;
        const mo = dotted ? b : a, da = dotted ? a : b;
        // Read as UTC: only the order counts, and the browser's zone would fold the hour it skips
        const time = Date.parse(`${y}-${String(mo).padStart(2, '0')}-${String(da).padStart(2, '0')}T${(text.match(/\d{1,2}:\d{2}(:\d{2})?/) || ['00:00'])[0].padStart(5, '0')}Z`);
        if (!isNaN(time)) return { n: time, t };
    }
    return { n: null, t };
}

// The cell a row holds for a column: a helper element in a row (the phone's
// line break) is not a cell
function uiSortCell(row, index) {
    if (!row || index < 0) return null;
    return [...row.children].filter(c => !c.classList.contains('ui-tr-break'))[index] || null;
}

// Rows travel with what follows them up to the next row (an opened detail)
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

// Each row keeps the place it was drawn in, so the list's own order can come
// back (Default order). Rows drawn anew come in that order; it tells whether
// any row is new since the list was last sorted. A row drawn again on its own
// (one domain checked again) finds its place by its data-sort-id, else by its
// first cell's text.
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

// index -1 puts the list's own order back
function uiApplyTableSort(table, index, dir) {
    const heads = uiSortHeads(table);
    heads.forEach((h, i) => { if (uiSortable(table, h)) uiSetSortState(h, i === index ? (dir > 0 ? 'ascending' : 'descending') : 'none'); });
    uiSortPositions(table);
    for (const seg of uiSortUnits(table)) {
        const keyed = seg.units.map((unit, pos) => ({ unit, pos,
            v: index < 0 ? { n: Number(unit[0].dataset.sortPos), t: '' } : uiSortValue(uiSortCell(unit[0], index)) }));
        if (index < 0) dir = 1;
        keyed.sort((a, b) => {
            // Empty values go last either way
            const ae = a.v.n === null && !a.v.t, be = b.v.n === null && !b.v.t;
            if (ae !== be) return ae ? 1 : -1;
            let c;
            if (a.v.n !== null && b.v.n !== null) c = a.v.n - b.v.n;
            else c = a.v.t.localeCompare(b.v.t, undefined, { sensitivity: 'base' });
            return c ? c * dir : a.pos - b.pos;
        });
        // Put them back in order, ahead of anything fixed at the end (a "No matches" row)
        let anchor = seg.after ? seg.after.nextSibling : (seg.parent.tagName === 'TBODY' ? seg.parent.firstChild : uiSortHeads(table)[0].parentNode.nextSibling);
        for (const { unit } of keyed) for (const el of unit) { seg.parent.insertBefore(el, anchor); anchor = el.nextSibling; }
        for (const el of seg.fixed) if (seg.parent.tagName === 'TBODY') seg.parent.appendChild(el);
    }
    if (index < 0) delete table.dataset.sortedBy;
    else table.dataset.sortedBy = `${index}:${dir}`;
}

// What a column holds, from its data-sort-kind: it names the two orders in the
// Sort menu and says which one a column starts with. Without it the orders are
// Ascending and Descending, and numbers start high to low.
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

// A header's click or keys: the sorted column turns around, another column
// starts in its own first order (uiSortFirstDir)
// A list sorted on the server is drawn again: the focus goes back to the same
// header once the new list is there
let uiSortFocus = null;   // { owner, nth, label, server, from, until }
function uiSortOwner(table) {
    const owner = table.id ? table : table.closest('[id]');
    return owner ? owner.id : '';
}
// Which of the lists under one owner this is (a mailbox and its aliases)
function uiSortNth(table) {
    const owner = uiSortOwner(table);
    return [...document.querySelectorAll('.ui-table, table')].filter(t => uiSortOwner(t) === owner).indexOf(table);
}
function uiSortBy(table, cell) {
    const current = uiSortState(cell);
    let dir = current === 'descending' ? 1 : current === 'ascending' ? -1 : uiSortFirstDir(table, cell);
    // A list shown in the order it arrives in (data-sort-default): its column turns around too
    if (current === 'none' && !table.hasAttribute('data-sort-handler') && table.dataset.sortDefault) {
        const heads = uiSortHeads(table);
        const fallback = uiSortDefault(table, heads);
        if (fallback && fallback.cell === cell && heads.every(h => uiSortState(h) === 'none')) dir = -fallback.dir;
    }
    uiSortSet(table, cell, dir);
}

// Sort by a column in an order (1 low to high, -1 high to low), from a header or
// the Sort menu. The headers show it at once, also while a list sorted on the
// server is on its way, so a second choice builds on the first.
function uiSortSet(table, cell, dir) {
    const active = document.activeElement;
    if (active && cell.contains(active)) {
        uiSortFocus = { owner: uiSortOwner(table), nth: uiSortNth(table), label: uiSortLabel(cell),
            server: table.hasAttribute('data-sort-handler'), from: active, until: Date.now() + 5000 };
    }
    const heads = uiSortHeads(table);
    const index = heads.indexOf(cell);
    const handler = table.getAttribute('data-sort-handler');
    // The order a list sorted in the page arrives in is its own order, exactly
    // (rows equal in that column keep their places)
    const fallback = !handler && table.dataset.sortDefault ? uiSortDefault(table, heads) : null;
    if (fallback && fallback.cell === cell && fallback.dir === dir) { uiSortReset(table); return; }
    const before = heads.map(uiSortState);
    heads.forEach(h => { if (uiSortable(table, h)) uiSetSortState(h, h === cell ? (dir > 0 ? 'ascending' : 'descending') : 'none'); });
    // The Sort button shows it too, before a list sorted on the server comes back
    if (typeof requestAnimationFrame === 'function' && !uiTableSortQueued) { uiTableSortQueued = true; requestAnimationFrame(uiRefreshTableSorts); }
    if (handler) {
        // A list sorted on the server comes back drawn anew; when it does not
        // (the request failed), its headers go back to the order still shown
        // Choices in a row before any answer keep the order the rows still show
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
// How long a list sorted on the server has to come back before its headers go back
let uiSortWait = 8000;

// Default order: the list's own order again, and no remembered order
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

// A row that opens something on click (data-row-open, with tabindex) opens on
// Enter and Space too, when the row itself has the focus: a button or a copyable
// value inside it keeps its own keys
document.addEventListener('keydown', event => {
    if ((event.key !== 'Enter' && event.key !== ' ') || event.defaultPrevented) return;
    const row = event.target;
    if (!(row instanceof Element) || !row.matches('[data-row-open]')) return;
    event.preventDefault();
    row.click();
});

// A click that ends selecting text in a row (a drag, a double or triple click on
// a word, or Shift+click) leaves the row closed so the text can be copied: a
// row's click handler asks uiRowHeld(event) first. A plain click, also on text
// already selected, and Enter or Space (a click with no mouse, detail 0) still
// open it.
let uiPress = null;
document.addEventListener('mousedown', event => {
    uiPress = { x: event.clientX, y: event.clientY, target: event.target, down: true };
    // The first click of a double click selected a whole log line; clear it so
    // the browser selects the word (Shift keeps the selection it extends)
    if (event.detail > 1 && !event.shiftKey && event.target instanceof Element && event.target.closest('[data-line-select]')) window.getSelection().removeAllRanges();
}, true);
const uiPressEnd = () => { if (uiPress) uiPress.down = false; };
document.addEventListener('mouseup', uiPressEnd, true);
// A release outside the window never reaches the page: moving back with no
// button down, or leaving the window, ends the press too
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

// A click on a dialog's backdrop closes it only when the press started on the
// backdrop too. A drag that selects text in the dialog and ends outside it reaches
// the backdrop as a click, and leaves the dialog open. A click with no mouse
// (detail 0) is taken as it is.
function uiBackdropClick(event, backdrop = event.currentTarget) {
    if (event.target !== backdrop) return false;
    return !event.detail || !uiPress || uiPress.target === backdrop;
}

// The Sort button of a list: an icon next to the list's search, or at the end
// of its header row, that opens a menu with two groups, the column ("Sort by")
// and its order. A list names where it goes with data-sort-at (the id of its
// search field, or of the element it ends), says the order it arrives in with
// data-sort-default="<column>:asc|desc" (else the menu offers "Default order"),
// and data-sort-icon="off" leaves it out. Its headers keep sorting; the two
// always show the same order.
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
// The order the list shows: a sorted header, else the order it arrived in
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
    // Next to the search field, else at the end of the element named
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
    // The menu is built once per set of columns, then kept up to date in place,
    // so a choice in an open menu keeps the focus on it
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

// A choice in the Sort menu: a column starts in its own first order, an order
// applies to the column shown, and "Default order" brings the list's own order back
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

// Mark the sortable headers, and put a remembered order back after a refresh
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
            // Rows drawn anew in the same list (a filter, a refresh) are not sorted yet
            if (uiSortPositions(table)) delete table.dataset.sortedBy;
            const state = uiTableSorts.get(uiTableKey(table));
            if (state && table.dataset.sortedBy !== `${state.index}:${state.dir}`) uiApplyTableSort(table, state.index, state.dir);
        }
        seen.add(uiSortControlKey(table));
        if (uiSortControlSync(table, heads)) pickers = true;
    });
    // A Sort button whose list is gone goes too
    document.querySelectorAll('.ui-sort-slot').forEach(slot => { if (!seen.has(slot.dataset.sortFor)) slot.remove(); });
    if (pickers) uiPickerRefocus();
    uiSortFocusBack();
}
function uiSortFocusBack() {
    const want = uiSortFocus;
    if (!want) return;
    if (Date.now() > want.until) { uiSortFocus = null; return; }
    // The list was not drawn again yet: the control that sorted is still there
    if (want.from.isConnected) return;
    uiSortFocus = null;
    const active = document.activeElement;
    // The focus went somewhere already (the user moved on, or the picker took it back)
    if (active && active !== document.body) return;
    const table = [...document.querySelectorAll('.ui-table, table')].filter(t => uiSortOwner(t) === want.owner)[want.nth];
    if (!table) return;   // the answer is no list (nothing found, an error): the layers place the focus
    const target = uiSortHeads(table).find(h => uiSortLabel(h) === want.label)?.querySelector('.ui-sort-btn');
    if (target && target.getClientRects().length) target.focus({ preventScroll: true });
}
// Moving on to anything else ends the wait for the list
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

// A log box with data-line-select="<line selector>": a plain click on a line
// selects the whole line and puts a Copy button at its end. A drag, a double or
// triple click and Shift+click select as usual.
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
    // After the range, so the button is not part of the selection
    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'ui-line-copy';
    copy.title = 'Copy line';
    copy.setAttribute('aria-label', 'Copy line');
    copy.innerHTML = `<svg width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">${UI_COPY_PATH}</svg>`;
    // A press on the button keeps the line selected
    copy.addEventListener('mousedown', e => e.preventDefault());
    copy.addEventListener('click', e => { e.stopPropagation(); uiLineCopy(line, copy); });
    line.appendChild(copy);
});

function uiLineCopyRemove() {
    document.querySelectorAll('.ui-line-copy').forEach(button => button.remove());
}

// The Copy button goes once its line is no longer the selection
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
    } catch (e) { /* falls back to the selection below */ }
    // Without HTTPS the browser offers no clipboard API: copy the line's text
    // through a hidden field, then put the line selection back
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

// True while the user selects or has selected text in box, so live updates
// leave that text where it is
function uiTextHeld(box) {
    if (!box) return false;
    if (uiPress && uiPress.down && uiPress.target instanceof Node && box.contains(uiPress.target)) return true;
    const selection = window.getSelection();
    return Boolean(selection && selection.rangeCount && String(selection) && selection.getRangeAt(0).intersectsNode(box));
}

// =============================================================================
// SHEET - a panel from the bottom of the screen on phones. Its handle and head
// stay on top while its body scrolls. Pulling it down (by the head, or by the
// body scrolled to the top) closes it, and a short pull springs back. With
// expand it opens at four fifths and rises with the reader's scroll to the full screen.
// =============================================================================

const uiSheetClosers = {};  // sheet id -> what closing it does
const uiIsPhone = () => window.matchMedia('(max-width: 760px)').matches;

// Show the sheet, or redraw it in place: the body keeps its scroll and a grown
// sheet stays full screen
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
    const old = sheet.querySelector('.ui-sheet-body');
    const keep = old ? old.scrollTop : 0;
    sheet.classList.toggle('is-expand', expand);
    sheet.innerHTML = `
        <div class="ui-sheet-back" onclick="uiSheetDismiss('${id}')"></div>
        <section class="ui-sheet-panel" role="dialog" aria-modal="true" aria-label="${escapeHtml(label)}">
            <span class="ui-sheet-grip" aria-hidden="true"></span>
            <div class="ui-sheet-head">${head}<button type="button" class="ui-icon-btn ui-sheet-x" onclick="uiSheetDismiss('${id}')" aria-label="Close" title="Close">&times;</button></div>
            <div class="ui-sheet-body">${body}</div>
        </section>`;
    const bodyEl = sheet.querySelector('.ui-sheet-body');
    bodyEl.scrollTop = keep;
    if (expand) {
        // The sheet rises with the reader's scroll: what the body scrolls goes into the
        // sheet's height first, until it fills the screen; then the body scrolls
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
    uiSheetSwipe(sheet, bodyEl, id);
    document.body.classList.add('ui-sheet-on');
    return sheet;
}

// An information sheet's or dialog's top as its reading gauge: everything above
// the text (the grip and the head) fills as the text is read, and stays plain
// when there is nothing to scroll
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

// Close as its owner wants (an owner may keep state of what is open)
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

// A drag on the grip or the head moves the sheet: up grows it to the full
// screen, down pulls it closed; from the content only a pull down at its top
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

// Filter bars: a search, the common filters as pickers, the rarer ones behind
// "Filters", and under the bar one line with the count and "Clear filters".
//   <section class="ui-filters ui-fbar">
//     <div class="ui-fbar-row"> search, Filters button, the page's own buttons
//     <div class="ui-fbar-pickers"> <select data-picker-label="Reason"> ... (shown as pickers)
//     <div class="ui-fbar-more"> the rarer filters
//   </section>
//   <p class="ui-list-summary"><span id="...-count"></span><button class="ui-clear-filters">
// A select with data-picker-label keeps its value, its options and its onchange,
// so the page's own code reads it as before; the picker only shows it. A select
// with data-no-filter (sort order) is not counted as a filter, and data-picker-host
// adds a class to the picker (ui-picker-end: it opens toward the start).
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

// A filter differs from where it starts (an empty search, a select's first or
// default option, a checkbox as written in the page, a value with data-filter-default)
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
    // A select shows as a picker wherever it is: in a filter bar, or alone (a sort order)
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
            // A long list gets a search field
            search: select.dataset.pickerSearch || (options.length > 10 ? `Search ${select.dataset.pickerLabel.toLowerCase()}` : ''),
            options: options.map((o, i) => ({ label: o.textContent.trim(), selected: o === chosen, onclick: `uiSelectPick('${escapeJsArg(select.id)}', ${i})` })),
        });
    });
    document.querySelectorAll('.ui-fbar').forEach(bar => {
        // A picker whose value lives in an input (a period) shows when it is in use
        bar.querySelectorAll('.ui-picker[data-state]').forEach(host => {
            const input = document.getElementById(host.dataset.state);
            const button = host.querySelector('.ui-picker-btn');
            if (input && button) button.classList.toggle('is-set', uiFilterChanged(input));
        });
        const fields = [...bar.querySelectorAll('input, select')].filter(el => !el.closest('.ui-picker-panel') || el.matches('[data-filter-default]'));
        const more = bar.querySelector('.ui-fbar-more');
        const badge = bar.querySelector('.ui-filters-toggle .ui-msg-filter-n');
        if (more && badge) {
            const changed = [...more.querySelectorAll('input, select')].filter(uiFilterChanged).length;
            badge.textContent = changed ? String(changed) : '';
            badge.classList.toggle('hidden', !changed);
            // The count is in the button's name too, not only on the screen
            const name = changed ? `Filters, ${changed} in use` : 'Filters';
            const toggle = badge.closest('.ui-filters-toggle');
            if (toggle.getAttribute('aria-label') !== name) { toggle.setAttribute('aria-label', name); toggle.title = name; }
        }
        const summary = bar.nextElementSibling;
        const clear = summary && summary.classList.contains('ui-list-summary') && summary.querySelector('.ui-clear-filters');
        if (clear) clear.classList.toggle('hidden', !fields.some(uiFilterChanged));
    });
    uiPickerRefocus();
}

// =============================================================================
// Time zoom on a bar chart: drag across the bars to zoom into that span (a
// mouse), pinch on the chart (a touch screen), Ctrl+wheel or a trackpad pinch
// (which Chromium sends as a Ctrl wheel) to zoom at the pointer, one finger or
// a drag to move a zoomed chart; a tap or click on a bar stays a pick. Buttons
// beside the chart do the same without a gesture (uiTimeZoomStep).
//   uiTimeZoom(box, { bars, span, limits, preview, change }) -> { destroy, busy }
//     bars():   the bar elements in time order, each with data-start / data-end (ms)
//     span():   the visible { from, to } (ms); limits(): { from, to, min }
//     preview(span, kind): during a gesture (kind: 'pinch' | 'pan' | 'select' | 'wheel')
//     change(span): at its end; cancel() when it is called off
// The chart keeps touch-action: pan-y, so the page still scrolls up and down
// under a finger; a pinch and a sideways drag come to the chart.
// =============================================================================
function uiTimeZoomClamp(span, limits) {
    const want = span.to - span.from;
    const len = Math.max(limits.min, Math.min(want, limits.to - limits.from));
    // Made longer or shorter around its middle, then kept inside the data
    const from = Math.max(limits.from, Math.min(span.from - (len - want) / 2, limits.to - len));
    return { from, to: from + len };
}

// A step from the buttons: in (0.5), out (2), earlier (-1) or later (+1) by half the span
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
    const pointers = new Map();   // pointerId -> { x, y }
    let state = 'idle';           // idle | pressing | selecting | panning | pinching
    let start = null;             // what the gesture started from
    let shown = null;             // the span previewed so far
    let swallow = false;          // the click that ends a gesture is not a pick
    let wheelTimer = null;
    // Where the chart sits in the page, without the stretch a preview puts on
    // it (offsets ignore transforms): a pinch or a wheel keeps one frame
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
    // The bar under an x, or the nearest one: its own edges, not a straight line through time
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
            // A second finger: a pinch, from wherever the first one got to
            try { box.setPointerCapture(event.pointerId); } catch (e) { /* the pointer may be gone */ }
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
            // Mostly up or down: the page scrolls, the chart lets it
            if (Math.abs(dy) > Math.abs(dx)) { state = 'idle'; pointers.delete(event.pointerId); return; }
            try { box.setPointerCapture(event.pointerId); } catch (e) { /* ignore */ }
            if (zoomed()) beginPan({ x: start.x });
            else { state = 'selecting'; start = { x: start.x, span: opts.span() }; }
        }
        if (state === 'pinching' && pointers.size >= 2) {
            const f = twoFingers();
            const s = start.span, len = s.to - s.from;
            const anchor = timeAt(start.mid, s);
            const next = len * start.dist / f.dist;
            const ratio = (anchor - s.from) / len;
            // The time under the fingers stays under them, and follows their middle
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
            if (pointers.size === 1) { beginPan([...pointers.values()][0]); return; }   // two fingers to one: it moves on, no jump
            if (pointers.size === 0) finish();
            return;
        }
        if (pointers.size) return;
        if (state === 'selecting') {
            // A span of one bar or more: zoom to it (at least the shortest span)
            if (shown && shown.to - shown.from >= opts.limits().min) { const { from, to } = shown; shown = uiTimeZoomClamp({ from, to }, opts.limits()); finish(); }
            else cancel();
            return;
        }
        if (state === 'panning') { finish(); return; }
        state = 'idle';   // a press without a move: a click picks the bar
    };
    // The browser took a finger away: the gesture is called off, a pinch too
    // when only one of its fingers goes (the other ends it as a plain lift)
    const onCancel = event => {
        pointers.delete(event.pointerId);
        if (!pointers.size || state === 'pinching') cancel();
    };
    // A finger lifted lets go of its capture: that is expected and ends nothing.
    // A bar handing a touch's own capture over to the box bubbles up here too:
    // only the box losing it while the gesture is on calls the gesture off
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
        // A gesture is on: a redraw waits, an answer on its way is set aside
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

// Redraw a chart without losing the keyboard's place: focus goes back to the
// same bar or column (by its start), else the button of the same name in the
// same group, else the bar that was picked, else the first button of that
// group. A focus outside the container is left alone.
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
    // A button kept in its place but hidden (visibility) takes no focus
    // (visibility checked by itself: older browsers have checkVisibility without that option)
    const shown = b => getComputedStyle(b).visibility !== 'hidden' && (typeof b.checkVisibility !== 'function' || b.checkVisibility());
    const enabled = sel => [...container.querySelectorAll(sel)].filter(b => !b.disabled && shown(b));
    const inGroup = was.group ? [...container.querySelectorAll('[role="group"]')].find(g => g.getAttribute('aria-label') === was.group) : null;
    // A bar that is gone (zoomed past, or bars of another length): the one holding its time, else the nearest
    const nearestBar = t => {
        const bars = [...container.querySelectorAll('[data-start][data-end]')];
        return bars.find(b => Number(b.dataset.start) <= t && t < Number(b.dataset.end))
            || bars.reduce((best, b) => (!best || Math.abs(b.dataset.start - t) < Math.abs(best.dataset.start - t) ? b : best), null);
    };
    // A strip's thumb by which edge it holds; a bar by its time (bars have no names of their own); a button by its name
    const target = was.thumb !== undefined ? container.querySelector(`[data-thumb="${CSS.escape(was.thumb)}"]`)
        : was.start !== undefined
        ? container.querySelector(`[data-start="${CSS.escape(was.start)}"]`) || nearestBar(Number(was.start))
        : enabled(inGroup ? '[role="group"] button' : 'button').find(b => name(b) === was.name && (!inGroup || inGroup.contains(b)))
            || (was.picked !== undefined && container.querySelector(`[data-start="${CSS.escape(was.picked)}"]`))
            || (inGroup && enabled('button').find(b => inGroup.contains(b)))
            || null;
    if (target) target.focus({ preventScroll: true });
}

// =============================================================================
// A small trend beside a figure: its hourly samples over the last days as a
// line (a gap where an hour has no sample), the latest point marked. Until the
// samples span a day: nothing (an empty string). The words (aria-label and
// title) say the trend's start and end and when it was read.
//   uiSparkline(points, { days, now, format }) -> SVG markup, or ''
//     points: [{ slot, value, as_of }] oldest first (slot, as_of: ISO); format(value) -> words
// =============================================================================
function uiSparkline(points, { days = 7, now = Date.now(), format = v => String(v), label = 'Trend' } = {}) {
    const W = 72, H = 18, pad = 2;
    const from = now - days * 86400000;
    const hourly = (points || []).filter(p => p.value !== null && p.value !== undefined && Date.parse(p.slot) >= from)
        .sort((a, b) => Date.parse(a.slot) - Date.parse(b.slot));
    // The words use the samples as read: the first and the latest
    const firstRead = hourly.length ? Number(hourly[0].value) : null, lastRead = hourly.length ? Number(hourly[hourly.length - 1].value) : null;
    const when = t => `${formatDay(t)}, ${formatInZone(t, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }, 'en-US')}`;
    // Nothing until the samples span a day: a dot or a stub says nothing yet (the place stays, the card keeps its size)
    if (hourly.length < 2 || Date.parse(hourly[hourly.length - 1].slot) - Date.parse(hourly[0].slot) < 86400000) return '';
    // Runs of samples with no missing hour between them (an hour and a half or more
    // apart breaks the line); within a run, six hours to a point over a week (their
    // average, at their mean time): a line, not a comb; the latest reading itself ends it
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
    // A run of one point draws no line: a dot shows it (the latest reading has its own mark)
    const lone = pts.filter((p, i) => p.start && i < pts.length - 1 && pts[i + 1].start)
        .map(p => `<circle class="is-lone" cx="${x(p.t).toFixed(1)}" cy="${y(p.v).toFixed(1)}" r="1.2"/>`).join('');
    const words = `${label}, last ${days} days: from ${format(firstRead)} to ${format(lastRead)}, as of ${when(Date.parse(last.as_of || last.slot))}`;
    return `<svg class="ui-spark-svg" viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" role="img" aria-label="${escapeHtml(words)}"><title>${escapeHtml(words)}</title><path d="${d}"/>${lone}<circle cx="${x(Date.parse(last.slot)).toFixed(1)}" cy="${y(Number(last.value)).toFixed(1)}" r="1.8"/></svg>`;
}

// =============================================================================
// Overview strip under a zoomable chart: the whole period in small bars, with a
// window over the span the chart shows. Drag the window to move it, drag an
// edge to resize it, click beside it to center it there. Its two edges are
// sliders for the keyboard ("Start of the span shown", "End of the span
// shown"): arrows by one step, Page Up / Page Down by a big step, Home / End
// to the limits. Every change snaps to the chart's own resolution (snap) and
// keeps at least the shortest span (limits.min); the end of the data is a
// legal edge even inside a step.
//   uiTimeOverview(box, { limits, span, snap, step, label, change }) -> { busy, destroy }
//     limits(): { from, to, min }; span(): { from, to } shown; snap(t): t on an edge
//     step(t, dir, big): the next edge from t (dir -1 or 1); label(t): the words for t
//     change(span): after a drag ends, or a moment after the last key
//     idle(): optional, when a drag or keys end with no new span (or a drag is called off)
// The caller draws the bars inside box; this adds the window and its edges.
// =============================================================================

// The span a drag of the window by dt makes: same length, inside the limits, snapped
function uiOverviewMove(start, dt, limits, snap = t => t) {
    const len = start.to - start.from;
    const sn = x => Math.max(limits.from, Math.min(limits.to, snap(x)));
    let from = Math.max(limits.from, Math.min(start.from + dt, limits.to - len));
    from = sn(from);
    const to = from + len >= limits.to - 1 ? limits.to : sn(from + len);
    return to - from >= limits.min ? { from, to } : { from: Math.max(limits.from, to - len), to };
}

// The span when one edge moves to t: snapped, kept at least the shortest span from the other edge
function uiOverviewEdge(span, edge, t, limits, snap = t => t) {
    const at = x => (x >= limits.to - 1 ? limits.to : x <= limits.from + 1 ? limits.from : Math.max(limits.from, Math.min(limits.to, snap(x))));
    if (edge === 'start') {
        const most = span.to - limits.min;
        let x = Math.max(limits.from, Math.min(t, most));
        let from = at(x);
        // Steps that double reach the edge before it on any grid (quarters, hours, days)
        for (let i = 0, d = from - most + 60000; i < 24 && from > most && x > limits.from; i++, d *= 2) { x -= d; from = at(Math.max(limits.from, x)); }
        return { from: Math.min(from, Math.max(limits.from, most)), to: span.to };
    }
    const least = span.from + limits.min;
    let x = Math.min(limits.to, Math.max(t, least));
    let to = at(x);
    for (let i = 0, d = least - to + 60000; i < 24 && to < least && x < limits.to; i++, d *= 2) { x += d; to = at(Math.min(limits.to, x)); }
    return { from: span.from, to: Math.max(to, Math.min(limits.to, least)) };
}

// The span centered at t, same length, inside the limits
function uiOverviewCenter(span, t, limits, snap = t => t) {
    const len = span.to - span.from;
    return uiOverviewMove(span, t - len / 2 - span.from, limits, snap);
}

// The nearest edge of an hour of the app's zone to t, found as the server finds its
// hour bars: walking UTC in quarter hours to where the zone's hour (or its offset,
// on the night the clocks go back) changes. A zone off by half an hour, or whose
// clocks move by half an hour, has its edges where they really are.
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
    let shown = null;         // the span drawn while a drag or keys are on
    let drag = null;          // { kind: 'move' | 'start' | 'end' | 'press', x, span, id }
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
        // Each edge's own bounds depend on the other edge and the shortest span
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
            // Mostly up or down: the page scrolls, the strip lets it
            if (Math.abs(dy) > Math.abs(dx)) { drag = null; return; }
            drag.moved = true;
            try { box.setPointerCapture(event.pointerId); } catch (e) { /* the pointer may be gone */ }
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
        // A press without a move beside the window: center the window there
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
        // Keys held or pressed in a row ask the server once, a moment after the last
        clearTimeout(keyTimer);
        keyTimer = setTimeout(() => { keyTimer = null; commit(shown); }, 350);
    };
    box.addEventListener('pointerdown', onDown);
    box.addEventListener('pointermove', onMove);
    box.addEventListener('pointerup', onUp);
    box.addEventListener('pointercancel', onCancel);
    box.addEventListener('keydown', onKey);
    return {
        // A drag or keys are on: a redraw waits, an answer on its way is set aside
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

// Phones: every dialog opens like the help sheet, at four fifths of the
// screen; it rises with the reader's scroll to the full screen, and a pull down
// on its head, or on its content scrolled to the top, closes it
function uiDialogSheet(backdrop) {
    const dialog = backdrop.querySelector(':scope > .ui-dialog');
    if (!dialog) return;
    // Each opening starts at four fifths again, at the top
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

    // A drag on its fixed top part (head, header, tabs) moves the sheet itself: up
    // grows it to the full screen, as scrolling does; down pulls it closed
    let startY = null, startHeight = 0, fixedPart = false, pulled = 0;
    // A touch that starts on a chart that zooms ([data-zoom]), or a second
    // finger, is no pull: it neither moves nor closes the sheet, until every
    // finger is lifted
    let ignore = false;
    const closeButton = () => dialog.querySelector('.ui-dialog-head [aria-label="Close"], .ui-dialog-head .ui-icon-btn');
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

// A jump to a place further down a phone's sheet (a link to a part of the same
// dialog) grows the sheet to the full screen first, as scrolling there would:
// otherwise the sheet takes the jump's scroll to grow and the place stays below
function uiDialogSheetFull(backdrop) {
    const dialog = backdrop && backdrop.querySelector(':scope > .ui-dialog');
    if (!dialog || !uiIsPhone() || backdrop.classList.contains('ui-docked') || backdrop.classList.contains('is-full')) return;
    backdrop.classList.add('is-grown', 'is-full');
    dialog.style.height = `${window.innerHeight}px`;
}

// A dialog is prepared each time it is shown or added to the page (only where
// there is a page to watch: the frontend tests load this file without one)
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

// =============================================================================
// Pickers: a filter button that opens its choices (Security, Messages, lists)
// =============================================================================
// One accessible drop-down for the whole app, after the WAI-ARIA listbox and
// dialog patterns. A short list of choices is a listbox: arrows, Home and End
// move between them, Enter or Space picks one. A long list gets a search field
// above it that narrows the choices as one types; Arrow Down moves into the
// list and Enter picks the first match. Richer content (a custom range,
// country bars) is a dialog. In all of them the focus moves inside on open,
// Escape closes and returns it to the button, and a click or focus outside
// closes. The button names the filter and its value ("Period: Last 7 days").
// An open panel is moved back onto the screen when it would run past an edge.
//
// Markup (uiPicker builds it; static markup may follow the same shape):
//   <span class="ui-popover-host ui-picker" data-picker="ID">
//     <button class="ui-msg-range ui-picker-btn" aria-haspopup aria-expanded aria-controls="ID-panel">
//     <span id="ID-panel" class="ui-popover ui-picker-panel" role="listbox|dialog"> ...
// A page that redraws an open picker keeps it open: uiPickerIsOpen(id).
// In a form (field: true) the button looks like a select and shows only the
// value; the form's label names it (labelledBy).

// open: the picker shown; held: the picker whose button has the focus, so a
// redraw of the page (new data) can give it back; query: what was typed in a search
const uiPickers = { open: null, held: null, query: {} };

function uiPickerIsOpen(id) {
    return uiPickers.open === id;
}

// "new york" finds America/New_York
function uiPickerMatches(label, query) {
    const plain = text => text.toLowerCase().replace(/_/g, ' ');
    return !query || plain(label).includes(plain(query.trim()));
}

// options: [{ label, hint, dot, value, selected, onclick }] for a list (value: the option's
// data-value; dot: a status tone, as the Outcome filter shows it, '' for a grey one);
// panel: HTML for a dialog; search: the search field's label, for a long list
function uiPicker({ id, label, value, set = false, options = null, panel = '', panelLabel = '', panelClass = '', hostClass = '', onOpen = '', search = '', field = false, labelledBy = '', disabled = false, icon = false }) {
    const open = uiPickerIsOpen(id);
    const list = Array.isArray(options);
    const query = search ? (uiPickers.query[id] || '') : '';
    const items = list ? options.map(o => `<button type="button" role="option" class="ui-fct" tabindex="-1" aria-selected="${o.selected ? 'true' : 'false'}"${o.value !== undefined ? ` data-value="${escapeHtml(String(o.value))}"` : ''}${uiPickerMatches(o.label, query) ? '' : ' hidden'} onclick="${o.onclick}">${o.dot !== undefined ? `<i class="ui-fct-dot${o.dot ? ` ui-fct-${escapeHtml(o.dot)}` : ''}" aria-hidden="true"></i>` : ''}<span>${escapeHtml(o.label)}</span>${o.hint !== undefined ? `<small>${escapeHtml(String(o.hint))}</small>` : ''}</button>`).join('') : '';
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
    return list ? [...list.querySelectorAll('[role="option"]')].filter(o => !o.hidden) : [];
}

function uiPickerFocusables(panel) {
    return [...panel.querySelectorAll('button, input, select, textarea, a[href], [tabindex]:not([tabindex="-1"])')]
        .filter(el => !el.disabled && !el.hidden && !el.closest('.hidden'));
}

// An open panel stays on the screen: it moves back from an edge it would run
// past, opens upward when there is more room above, and scrolls when it is
// taller than the room it has. The room is the screen under a fixed top bar and
// above a fixed tab bar (phones), within every box around the panel that cuts
// what overflows it (the page's scrolling area).
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
    // A button under a bar (reached with the keyboard) comes into view first
    if (button) {
        const at = button.getBoundingClientRect();
        if (at.height && (at.bottom > bounds.bottom || at.top < bounds.top) && button.scrollIntoView) {
            button.scrollIntoView({ block: 'center', behavior: 'instant' });
            bounds = uiPickerBounds(panel);
        }
    }
    const down = panel.getBoundingClientRect();
    if (down.height && down.bottom > bounds.bottom) {
        // Measured where the panel really hangs from, which is not always its button
        panel.classList.add('is-up');
        const up = panel.getBoundingClientRect();
        if (up.bottom - bounds.top <= bounds.bottom - down.top) panel.classList.remove('is-up');
    }
    // Taller than the room on its side: it scrolls within that room
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

// The search field, else the chosen option or the first one; in a dialog its first control
// The panel is already placed on the screen, so the focus does not scroll the
// page; a choice further down a long list is scrolled into view inside the panel
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
// A screen used by touch only (a phone): a field that takes the focus brings up the keyboard
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

// Narrow a long list to the options that hold the typed text
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
        // The next opening shows every choice again
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

// After a page redraws a picker, the focus goes back where it was: inside the
// open picker, or on the button of the one just closed
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
            // The option's own handler ran first and may have redrawn the picker
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

    // Capture, so Escape closes the picker before it reaches a dialog or sheet under it
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
            // With no match, Enter does nothing (it would submit a form around the picker)
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

    // The focus moving on elsewhere ends the claim of a closed picker's button
    document.addEventListener('focusin', event => {
        if (uiPickers.held && event.target instanceof Element && !event.target.closest(`.ui-picker[data-picker="${uiPickers.held}"]`)) uiPickers.held = null;
    });

    // Tabbing out of an open picker closes it
    document.addEventListener('focusout', event => {
        const id = uiPickers.open;
        if (!id || !(event.target instanceof Element)) return;
        const { host } = uiPickerParts(id);
        if (!host || !host.contains(event.target)) return;
        const next = event.relatedTarget;
        // A click on a label in the panel can hand the focus to the dialog around
        // it (a layer takes the focus itself): that is not leaving the picker
        if (next && !host.contains(next) && !next.contains(host)) uiPickerClose(id);
    });

    // A panel open while the window changes size stays on the screen
    if (typeof window.addEventListener === 'function') window.addEventListener('resize', () => {
        if (!uiPickers.open) return;
        const { panel } = uiPickerParts(uiPickers.open);
        if (panel) uiPickerPlace(panel);
    });
}
