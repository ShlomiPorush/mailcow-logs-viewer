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

    const colors = {
        'success': 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border-green-500',
        'error': 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border-red-500',
        'warning': 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 border-yellow-500',
        'info': 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-200 border-blue-500'
    };

    const icons = {
        'success': '✓',
        'error': '✗',
        'warning': '⚠',
        'info': 'ℹ'
    };

    const toast = document.createElement('div');
    toast.id = 'toast-notification';
    toast.className = `fixed bottom-4 right-4 z-50 ${colors[type]} border-l-4 p-4 rounded shadow-lg max-w-md animate-slide-in`;
    toast.innerHTML = `
        <div class="flex items-start gap-3">
            <span class="text-xl font-bold flex-shrink-0">${icons[type]}</span>
            <p class="text-sm flex-1">${escapeHtml(message)}</p>
            <button onclick="this.parentElement.parentElement.remove()" class="text-lg font-bold hover:opacity-70 flex-shrink-0">×</button>
        </div>
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

        const gradientColor = confirmColor || (isDangerous
            ? 'linear-gradient(135deg,#ef4444,#dc2626)'
            : 'linear-gradient(135deg,#3b82f6,#2563eb)');

        const iconBg = isDangerous
            ? 'linear-gradient(135deg,#ef4444,#dc2626)'
            : 'linear-gradient(135deg,#3b82f6,#2563eb)';

        const iconSvg = isDangerous
            ? '<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"></path>'
            : '<path stroke-linecap="round" stroke-linejoin="round" d="M8.228 9c.549-1.165 2.03-2 3.772-2 2.21 0 4 1.343 4 3 0 1.4-1.278 2.575-3.006 2.907-.542.104-.994.54-.994 1.093m0 3h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>';

        const overlay = document.createElement('div');
        overlay.id = 'app-confirm-modal';
        overlay.style.cssText = 'position:fixed;inset:0;z-index:99999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,0.6);backdrop-filter:blur(4px);';

        // Callers pass plain text (channel names, emails, domains, ...) - escape
        // it before it goes into innerHTML, then turn newlines into breaks.
        const escapedMessage = escapeHtml(message).replace(/\n/g, '<br>');

        overlay.innerHTML = `
            <div style="background:var(--color-bg-primary, #1f2937);border:1px solid var(--color-border, #374151);border-radius:12px;padding:28px;max-width:420px;width:90%;box-shadow:0 25px 50px rgba(0,0,0,0.4);">
                <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px;">
                    <div style="width:40px;height:40px;border-radius:10px;background:${iconBg};display:flex;align-items:center;justify-content:center;flex-shrink:0;">
                        <svg width="20" height="20" fill="none" stroke="white" stroke-width="2" viewBox="0 0 24 24">${iconSvg}</svg>
                    </div>
                    <div>
                        <h3 style="margin:0;font-size:16px;font-weight:600;color:#f3f4f6;">${title}</h3>
                    </div>
                </div>
                <p style="margin:0 0 24px;font-size:14px;color:#d1d5db;line-height:1.5;">${escapedMessage}</p>
                <div style="display:flex;justify-content:flex-end;gap:10px;">
                    <button type="button" id="app-confirm-cancel"
                        style="padding:9px 18px;border-radius:6px;border:1px solid #4b5563;background:transparent;color:#d1d5db;font-size:13px;font-weight:500;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.background='#374151'" onmouseout="this.style.background='transparent'">
                        ${cancelText}
                    </button>
                    <button type="button" id="app-confirm-ok"
                        style="padding:9px 18px;border-radius:6px;border:none;background:${gradientColor};color:white;font-size:13px;font-weight:600;cursor:pointer;transition:all 0.15s;"
                        onmouseover="this.style.opacity='0.9'" onmouseout="this.style.opacity='1'">
                        ${confirmText}
                    </button>
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

    return `
        <div class="ui-job${isFeatureOff ? ' is-off' : ''}">
            <div class="flex items-start justify-between gap-3 mb-2">
                <div class="flex-1 min-w-0">
                    <h4 class="font-semibold text-gray-900 dark:text-white text-sm">${escapeHtml(name)}</h4>
                    <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">${escapeHtml(job.description || '')}</p>
                </div>
                <div class="flex flex-col items-end gap-1.5">
                    ${statusBadge}
                    ${!isDisabled ? `
                        <button 
                            onclick="triggerBackgroundJob('${escapeJsArg(jobKey)}', this, '${escapeJsArg(name)}')" 
                            class="ui-btn ui-btn-sm"
                            ${isRunning ? 'disabled' : ''}
                            title="${isRunning ? 'Job is running' : 'Run this job now'}">
                            ${isRunning ? '<span class="inline-block animate-spin w-3 h-3 border-2 border-current border-t-transparent rounded-full"></span>' : '<span class="text-[10px]">▶</span>'}
                            Run
                        </button>
                    ` : ''}
                </div>
            </div>
            
            <div class="flex flex-wrap gap-x-4 gap-y-1 text-xs text-gray-600 dark:text-gray-400">
                ${job.interval ? `<span>⏱ ${job.interval}</span>` : ''}
                ${job.schedule ? `<span>📅 ${job.schedule}</span>` : ''}
                ${job.retention ? `<span>🗂 ${job.retention}</span>` : ''}
                ${job.max_age ? `<span>⏳ Max: ${job.max_age}</span>` : ''}
                ${job.expire_after ? `<span>⏱ Expire: ${job.expire_after}</span>` : ''}
                ${job.pending_items !== undefined ? `<span class="font-medium text-yellow-600 dark:text-yellow-400">📋 Pending: ${job.pending_items}</span>` : ''}
            </div>
            
            ${job.last_run ? `
                <div class="mt-2 pt-2 border-t border-gray-200 dark:border-gray-600">
                    <p class="text-xs text-gray-500 dark:text-gray-400">
                        Last run: <span class="text-gray-900 dark:text-white font-medium">${formatTime(job.last_run)}</span>
                    </p>
                </div>
            ` : ''}
            
            ${job.error ? `
                <div class="mt-2 p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded">
                    <p class="text-xs text-red-700 dark:text-red-300 font-mono break-all">${escapeHtml(job.error)}</p>
                </div>
            ` : ''}
        </div>
    `;
}

function renderImportCard(title, data, color) {
    if (!data) {
        return `<div class="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
            <p class="font-semibold text-gray-900 dark:text-white">${title}</p>
            <p class="text-sm text-gray-500 dark:text-gray-400 mt-2">No data</p>
        </div>`;
    }

    const colorClasses = {
        blue: 'border-blue-200 dark:border-blue-800 bg-blue-50 dark:bg-blue-900/20',
        purple: 'border-purple-200 dark:border-purple-800 bg-purple-50 dark:bg-purple-900/20',
        red: 'border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20'
    };

    return `
        <div class="p-4 border ${colorClasses[color]} rounded-lg">
            <p class="font-semibold text-gray-900 dark:text-white mb-3">${title}</p>
            <div class="space-y-2 text-sm">
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Last Fetch Run</p>
                    <p class="text-gray-900 dark:text-white font-medium">${data.last_fetch_run ? formatTime(data.last_fetch_run) : 'Never'}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Last Import</p>
                    <p class="text-gray-900 dark:text-white">${data.last_import ? formatTime(data.last_import) : 'Never'}</p>
                </div>
                <div>
                    <p class="text-xs text-gray-500 dark:text-gray-400">Total Entries</p>
                    <p class="text-gray-900 dark:text-white font-semibold">${(data.total_entries || 0).toLocaleString()}</p>
                </div>
                ${data.oldest_entry ? `
                    <div>
                        <p class="text-xs text-gray-500 dark:text-gray-400">Oldest Entry</p>
                        <p class="text-gray-900 dark:text-white">${formatTime(data.oldest_entry)}</p>
                    </div>
                ` : ''}
            </div>
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
