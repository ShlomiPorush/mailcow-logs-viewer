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

function uiDirectionTag(direction) {
    return `<span class="ui-tag ui-tag-line">${escapeHtml(String(direction))}</span>`;
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
function renderMarkdown(markdownText) {
    const html = marked.parse(markdownText || '');
    if (typeof DOMPurify !== 'undefined') {
        return DOMPurify.sanitize(html);
    }
    // Library failed to load - fail safe by escaping rather than injecting
    return escapeHtml(markdownText || '');
}

// Time for a list row: the time of day for today, the day and month before
// that, in the app timezone. The full timestamp goes in the row tooltip.
function formatListTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    const tz = appTimezone && appTimezone !== 'UTC' ? appTimezone : undefined;
    try {
        const day = d => new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
        if (day(date) === day(new Date())) {
            return new Intl.DateTimeFormat(undefined, { timeZone: tz, hour: '2-digit', minute: '2-digit', hour12: false }).format(date);
        }
        return new Intl.DateTimeFormat(undefined, { timeZone: tz, day: 'numeric', month: 'short' }).format(date);
    } catch (e) {
        return formatTime(isoString);
    }
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

function formatTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    // Use timezone from app configuration if set, otherwise use browser's local timezone
    // The date is already in UTC (with 'Z' suffix), so browser will convert it correctly
    try {
        if (appTimezone && appTimezone !== 'UTC') {
            // Use Intl.DateTimeFormat with app timezone
            const formatter = new Intl.DateTimeFormat(undefined, {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false,
                timeZone: appTimezone
            });
            return formatter.format(date);
        } else {
            // Use browser's local timezone and locale
            return date.toLocaleString(undefined, {
                day: '2-digit',
                month: '2-digit',
                year: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false
            });
        }
    } catch (e) {
        // Fallback to browser's local timezone if timezone is invalid
        console.warn('Invalid timezone, using browser local timezone:', appTimezone, e);
        return date.toLocaleString(undefined, {
            day: '2-digit',
            month: '2-digit',
            year: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    }
}

function formatDate(isoString) {
    if (!isoString) return '-';
    // Use formatTime for consistent date/time formatting
    return formatTime(isoString);
}

function formatDateShort(dateStr) {
    const date = new Date(dateStr);
    const month = (date.getMonth() + 1).toString().padStart(2, '0');
    const day = date.getDate().toString().padStart(2, '0');
    return `${day}/${month}`;
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

function showToast(message, type = 'info') {
    // Remove existing toast if any
    const existingToast = document.getElementById('toast-notification');
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
        <button type="button" onclick="this.parentElement.remove()" class="ui-icon-btn" title="Close" aria-label="Close">×</button>
    `;

    document.body.appendChild(toast);

    // Auto-remove after 4 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s';
            setTimeout(() => toast.remove(), 300);
        }
    }, 4000);
}

// =============================================================================
// Shared UI helpers used across pages (confirm dialog, status/job cards)
// =============================================================================

/**
 * Show a styled confirmation modal (replaces native confirm()).
 * Returns a Promise<boolean>: true if confirmed, false if cancelled.
 */
function showConfirmModal({ title = 'Confirm', message = 'Are you sure?', confirmText = 'Confirm', cancelText = 'Cancel', confirmColor, isDangerous = false } = {}) {
    return new Promise((resolve) => {
        const existing = document.getElementById('app-confirm-modal');
        if (existing) existing.remove();

        const overlay = document.createElement('div');
        overlay.id = 'app-confirm-modal';
        overlay.className = 'ui-dialog-backdrop ui-confirm';
        overlay.setAttribute('role', 'alertdialog');
        overlay.setAttribute('aria-label', title);

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
            document.removeEventListener('keydown', onKey);
            document.body.style.overflow = '';
            resolve(result);
        }
        // Escape cancels, like the other dialogs
        function onKey(event) {
            if (event.key === 'Escape') cleanup(false);
        }
        document.addEventListener('keydown', onKey);

        cancelBtn.addEventListener('click', () => cleanup(false));
        okBtn.addEventListener('click', () => cleanup(true));
        setTimeout(() => okBtn.focus(), 100);
    });
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
        // Without this tag the missing Run button had no explanation
        statusBadge = '<span class="ui-tag" title="This job is turned off in its settings, so it cannot be run">disabled</span>';
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

    return `
        <div class="ui-tr ui-job${isFeatureOff ? ' is-off' : ''}">
            <div class="ui-td ui-q-who">
                <div>${escapeHtml(name)}</div>
                ${job.description ? `<small title="${escapeHtml(job.description)}">${escapeHtml(job.description)}</small>` : ''}
            </div>
            <div class="ui-td ui-td-wrap">
                ${escapeHtml(runs.join(', ') || '-')}
                ${job.pending_items !== undefined ? `<small class="ui-text-warn ui-job-pending">Pending: ${job.pending_items}</small>` : ''}
            </div>
            <span class="ui-td">${statusBadge}</span>
            <span class="ui-td" title="${job.last_run ? escapeHtml(formatTime(job.last_run)) : ''}"><small class="ui-sec-unit">Last run </small>${job.last_run ? formatAgo(job.last_run) : '-'}</span>
            <span class="ui-td ui-td-end ui-row-actions">
                ${!isDisabled ? `
                    <button
                        onclick="triggerBackgroundJob('${escapeJsArg(jobKey)}', this, '${escapeJsArg(name)}')"
                        class="ui-btn ui-btn-sm"
                        ${isRunning ? 'disabled' : ''}
                        title="${isRunning ? 'Job is running' : 'Run this job now'}">
                        Run
                    </button>
                ` : ''}
            </span>
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
    return `<span>Deliveries: ${deliveries}</span>`;
}
