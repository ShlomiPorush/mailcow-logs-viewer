// =============================================================================
// ALERT ACTIVITY - the history behind a security alert, in a window
// =============================================================================
// Classic script sharing the global scope; loaded after app.js. A volume spike
// shows the mailbox's sent mail over time with its usual rate, and what it sent
// around the alert (an SMTP block by abuse protection the same, with its limit);
// an auth failure burst shows the username's failed logins and where they came from.

let alertActivity = null;          // /api/security-alerts/{id}/activity
let alertActivityRange = '24h';    // 24h | 48h | 7d

async function openAlertActivity(alertId) {
    const modal = document.getElementById('alert-activity-modal');
    const content = document.getElementById('alert-activity-content');
    alertActivity = null;
    alertActivityRange = '24h';
    content.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';
    document.getElementById('alert-activity-title').textContent = 'Activity';
    modal.classList.remove('hidden');
    try {
        const response = await authenticatedFetch(`/api/security-alerts/${encodeURIComponent(alertId)}/activity`);
        if (!response.ok) throw new Error(`The server answered ${response.status}`);
        alertActivity = await response.json();
        renderAlertActivity();
    } catch (error) {
        content.innerHTML = `<p class="ui-empty">Could not load the activity: ${escapeHtml(error.message)}. Try again in a moment.</p>`;
    }
}

function closeAlertActivity() {
    document.getElementById('alert-activity-modal').classList.add('hidden');
}

// A volume spike and an SMTP block by abuse protection both count the
// mailbox's sent mail; an auth failure burst counts a username's failed logins
function alertActivityIsSentMail(alert) {
    return alert.alert_type === 'volume_spike' || alert.alert_type === 'smtp_abuse_block';
}

function setAlertActivityRange(range) {
    alertActivityRange = range;
    renderAlertActivity();
}

// The columns of the chosen range: quarters of an hour for a day or two, hours
// for the baseline period ('7d', named for the default of 7 days). A baseline
// longer than a week gets columns of several hours, so the bars stay visible.
function alertActivityColumns(data) {
    const quarters = data.buckets.map(b => ({ start: new Date(b.start), count: b.count }));
    const days = Math.max(1, Number(data.baseline_days) || 7);
    const hours = { '24h': 24, '48h': 48, '7d': 24 * days }[alertActivityRange];
    const keep = quarters.slice(-Math.min(quarters.length, hours * (60 / data.bucket_minutes) + 8));
    if (alertActivityRange !== '7d') return { cols: keep, minutes: data.bucket_minutes };
    const step = Math.ceil(days / 7) * 3600000;
    const cols = [];
    keep.forEach(q => {
        const hour = new Date(q.start); hour.setMinutes(0, 0, 0);
        const start = step > 3600000 ? new Date(Math.floor(hour.getTime() / step) * step) : hour;
        const last = cols[cols.length - 1];
        if (last && last.start.getTime() === start.getTime()) last.count += q.count;
        else cols.push({ start, count: q.count });
    });
    return { cols, minutes: step / 60000 };
}

function alertActivityChart(data) {
    const a = data.alert;
    const spike = a.alert_type === 'volume_spike';
    const sent = alertActivityIsSentMail(a);
    const { cols, minutes } = alertActivityColumns(data);
    const at = new Date(a.created_at);
    // An SMTP block whose window is not known (its abuse action is gone) marks no period
    const from = data.window_minutes ? new Date(at.getTime() - data.window_minutes * 60000) : null;
    const max = Math.max(4, ...cols.map(c => c.count));
    const top = Math.ceil(max / 4) * 4;
    // A spike's usual rate, per column; a burst or a block has no usual rate, only a threshold
    const usual = spike ? (a.baseline_value || 0) * minutes / 60 : null;
    const fmt = d => d.toLocaleString(undefined, { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' });
    const what = sent ? 'sent' : 'failed logins';
    const markAt = cols.findIndex(c => at >= c.start && at < new Date(c.start.getTime() + minutes * 60000));
    const ranges = [['24h', '24 hours'], ['48h', '2 days'], ['7d', `${escapeHtml(String(data.baseline_days))} days`]];
    const per = minutes === 60 ? 'hour' : minutes > 60 ? `${minutes / 60} hours` : `${minutes} minutes`;
    return `<div class="ui-aa-head"><b>${sent ? 'What it sent' : 'Failed logins'}</b><span class="ui-muted">${sent ? 'this mailbox only' : 'this username only'}</span>
            <span class="ui-seg ui-head-actions" role="group" aria-label="Period">${ranges.map(([k, l]) => `<button type="button" aria-pressed="${alertActivityRange === k}" onclick="setAlertActivityRange('${k}')">${l}</button>`).join('')}</span></div>
        <div class="ui-aa-chart">
            <div class="ui-aa-grid">${[top, top * .75, top * .5, top * .25, 0].map(v => `<i><span>${Math.round(v)}</span></i>`).join('')}</div>
            <div class="ui-aa-cols">${cols.map(c => {
                const inAlert = from && new Date(c.start.getTime() + minutes * 60000) > from && c.start <= at;
                const tip = `${fmt(c.start)}: ${c.count} ${what}`;
                return `<span class="ui-aa-col${inAlert ? ' is-alert' : ''}" data-tip="${escapeHtml(tip)}" title="${escapeHtml(tip)}"><i style="height:${c.count / top * 100}%"></i></span>`;
            }).join('')}</div>
            ${usual !== null ? `<div class="ui-aa-usual" style="bottom:${Math.max(usual / top * 100, .6)}%"><span>usual: ${(a.baseline_value || 0).toFixed(2)} an hour</span></div>` : ''}
            ${markAt >= 0 ? `<div class="ui-aa-mark" style="left:${(markAt + .5) / cols.length * 100}%"><span>Alert ${at.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })}</span></div>` : ''}
        </div>
        <div class="ui-aa-x"><span>${escapeHtml(fmt(cols[0].start))}</span><span>${escapeHtml(fmt(cols[cols.length - 1].start))}</span></div>
        <p class="ui-aa-legend"><span><i></i>${sent ? 'Sent' : 'Failed logins'}, per ${escapeHtml(per)}</span>${from ? `<span><i class="is-alert"></i>The alert's ${escapeHtml(String(data.window_minutes))} minutes</span>` : ''}${usual !== null ? `<span><i class="is-usual"></i>Its usual rate over ${escapeHtml(String(data.baseline_days))} days</span>` : ''}</p>`;
}

function alertActivityList(title, rows, total, tone) {
    if (!rows.length) return '';
    return `<div class="ui-aa-box"><h4>${escapeHtml(title)}</h4>${rows.map(r => `<div class="ui-aa-row"><span title="${escapeHtml(r.name)}">${escapeHtml(r.name)}</span>
        <span class="ui-aa-bar"><i style="width:${total ? r.count / total * 100 : 0}%;${tone ? `background:var(--ui-${tone(r.name)})` : ''}"></i></span><b>${Number(r.count).toLocaleString()}</b></div>`).join('')}</div>`;
}

function renderAlertActivity() {
    const data = alertActivity;
    const content = document.getElementById('alert-activity-content');
    if (!data || !content) return;
    const a = data.alert;
    const spike = a.alert_type === 'volume_spike';
    const sent = alertActivityIsSentMail(a);
    const at = new Date(a.created_at);
    const around = data.around;
    // Without a known window, "Around the alert" starts where the server says
    const lead = data.window_minutes ?? Math.round((at - new Date(around.from)) / 60000);
    const from = new Date(at.getTime() - lead * 60000);
    const before = data.buckets.filter(b => new Date(b.start) < from).reduce((s, b) => s + b.count, 0);
    const critical = a.severity === 'critical';
    document.getElementById('alert-activity-title').innerHTML = `<span class="ui-tag ${critical ? 'ui-tag-fail' : 'ui-tag-warn'}">${escapeHtml((a.severity || 'warning').toUpperCase())}</span> ${escapeHtml(a.subject || '')}`;
    const results = { delivered: 'ok', sent: 'ok', deferred: 'warn', bounced: 'fail', rejected: 'fail', expired: 'fail', discarded: 'fail' };
    const unknown = data.window_minutes == null;
    const figures = sent && unknown ? [
        [spike ? 'Counted for the alert' : 'Counted for the block', (a.metric_value || 0).toLocaleString(), true],
        ['The window', 'Unknown'],
        spike ? [`Usual, an hour (${data.baseline_days} days)`, (a.baseline_value || 0).toFixed(2)]
            : ['The limit', (a.baseline_value || 0).toLocaleString()],
        [`Sent in the ${data.baseline_days} days before`, before.toLocaleString()]
    ] : unknown ? [
        ['Counted for the alert', (a.metric_value || 0).toLocaleString(), true],
        ['The window', 'Unknown'],
        ['The alert starts at', (a.baseline_value || 0).toLocaleString()],
        [`Failed in the ${data.baseline_days} days before`, before.toLocaleString()]
    ] : sent ? [
        [`Sent in the alert's ${data.window_minutes} minutes`, (a.metric_value || 0).toLocaleString(), true],
        ['That is, an hour', Math.round((a.metric_value || 0) * 60 / data.window_minutes).toLocaleString(), true],
        // A block has no usual rate: its baseline value is the abuse protection limit
        spike ? [`Usual, an hour (${data.baseline_days} days)`, (a.baseline_value || 0).toFixed(2)]
            : [`The limit, in ${data.window_minutes} minutes`, (a.baseline_value || 0).toLocaleString()],
        [`Sent in the ${data.baseline_days} days before`, before.toLocaleString()]
    ] : [
        [`Failed logins in ${data.window_minutes} minutes`, (a.metric_value || 0).toLocaleString(), true],
        ['The alert starts at', (a.baseline_value || 0).toLocaleString()],
        ['From addresses', (around.address_count ?? (around.addresses || []).length).toLocaleString()],
        [`Failed in the ${data.baseline_days} days before`, before.toLocaleString()]
    ];
    content.innerHTML = `
        <p class="ui-muted ui-aa-sub">${escapeHtml(a.title)} · ${escapeHtml(formatTime(a.created_at))}</p>
        <div class="ui-aa-strip">${figures.map(([label, value, bad]) => `<div><small>${escapeHtml(label)}</small><b${bad ? ' class="ui-text-fail"' : ''}>${escapeHtml(value)}</b></div>`).join('')}</div>
        <section>${alertActivityChart(data)}</section>
        <section><div class="ui-aa-head"><b>Around the alert</b><span class="ui-muted">${uiCountLabel(around.total, sent ? 'message' : 'failed login', sent ? 'messages' : 'failed logins')}, from ${escapeHtml(String(lead))} minutes before it to an hour after</span></div>
            ${around.total ? `<div class="ui-aa-two">${sent
                ? alertActivityList('Recipient domains', around.recipient_domains, around.total) + alertActivityList('What happened to them', around.results, around.total, n => results[n] || 'muted')
                    + `<div class="ui-aa-box ui-aa-wide"><h4>Subjects</h4>${around.subjects.map(s => `<div class="ui-aa-subj"><span title="${escapeHtml(s.name)}" dir="auto">${escapeHtml(s.name)}</span><small>${uiCountLabel(s.count, 'message', 'messages')}</small></div>`).join('')}</div>`
                : alertActivityList('Addresses', around.addresses, around.total) + alertActivityList('Countries', around.countries, around.total) + alertActivityList('Networks', around.networks, around.total)}</div>`
            : '<p class="ui-empty">Nothing in the logs around the alert. They may have been cleaned up since.</p>'}</section>
        <p class="ui-muted ui-aa-note">${sent
            ? 'Spam from a hijacked mailbox usually goes to many unrelated domains with the same few subjects, and much of it bounces or is rejected. Mail the user really sent goes to people they write to.'
            : 'Many addresses or networks trying one username point to an attack spread out to stay under the ban; one address is a single machine, possibly a device with an old password.'}</p>
        <div class="ui-aa-acts">
            ${sent ? `<button type="button" class="ui-btn" onclick="closeAlertActivity(); navigateToMessagesWithFilter({ email: '${escapeJsArg(a.subject)}', filterType: 'user' })">Open in Messages</button>`
                : `<button type="button" class="ui-btn" onclick="closeAlertActivity(); openAlertSecurityEvents('${escapeJsArg(a.subject)}')">Open in Security</button>`}
            ${a.acknowledged ? '' : `<button type="button" class="ui-btn ui-btn-primary" onclick="closeAlertActivity(); acknowledgeSecurityAlert(${Number(a.id)})">Dismiss the alert</button>`}
        </div>`;
}

// The Security page's events for a username
function openAlertSecurityEvents(username) {
    ['netfilter-filter-ip', 'netfilter-filter-action', 'netfilter-filter-country'].forEach(id => {
        const field = document.getElementById(id);
        if (field) field.value = '';
    });
    const field = document.getElementById('netfilter-filter-username');
    if (field) field.value = username;
    currentFilters.netfilter = { ip: '', username, action: '', country_code: '' };
    currentPage.netfilter = 1;
    navigateTo('netfilter', { sub: 'events' });
    setTimeout(() => { if (typeof applyNetfilterFilters === 'function') applyNetfilterFilters(); }, 100);
}

// Esc closes the window, like the other dialogs
document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    const modal = document.getElementById('alert-activity-modal');
    if (modal && !modal.classList.contains('hidden')) closeAlertActivity();
});
