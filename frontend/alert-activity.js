// =============================================================================
// ALERT ACTIVITY - the history behind a security alert, in a window
// =============================================================================
// Classic script sharing the global scope; loaded after app.js. A volume spike
// shows the mailbox's sent mail over time with its usual rate, and what it sent
// around the alert (an SMTP block by abuse protection the same, with its limit);
// an auth failure burst shows the username's failed logins and where they came from.
// The chart's columns are buttons: a click picks one (its count, and Open in
// Messages for its time); the chart zooms in time like the dashboard's
// (uiTimeZoom), over the 15-minute counts the window already has.

let alertActivity = null;          // /api/security-alerts/{id}/activity
let alertActivityRange = '24h';    // 24h | 48h | 7d: the span shown, without a zoom
let alertActivityZoom = null;      // { from, to } (ms) inside the data
let alertActivityPick = null;      // a column's start (ms)
let alertActivityGen = 0;          // the window opened last: an older answer is dropped
let alertActivityControl = null;
let alertActivityZoomer = null;
let alertActivityOverviewer = null;  // the strip under the chart (uiTimeOverview)

async function openAlertActivity(alertId) {
    const modal = document.getElementById('alert-activity-modal');
    const content = document.getElementById('alert-activity-content');
    const gen = ++alertActivityGen;
    if (alertActivityControl) alertActivityControl.abort();
    const control = typeof AbortController === 'function' ? new AbortController() : null;
    alertActivityControl = control;
    alertActivity = null;
    alertActivityZoom = null;
    alertActivityPick = null;
    content.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
    document.getElementById('alert-activity-title').textContent = 'Activity';
    document.getElementById('alert-activity-dismiss')?.classList.add('hidden');
    const openSlot = document.getElementById('alert-activity-open');
    if (openSlot) openSlot.innerHTML = '';
    // The footer shows once there is something in it (not while loading, nor after an error)
    document.getElementById('alert-activity-foot')?.classList.add('hidden');
    modal.classList.remove('hidden');
    try {
        const response = await authenticatedFetch(`/api/security-alerts/${encodeURIComponent(alertId)}/activity`, control ? { signal: control.signal } : {});
        if (!response.ok) throw new Error(`The server answered ${response.status}`);
        const data = await response.json();
        if (gen !== alertActivityGen) return;
        alertActivity = data;
        // Sent mail opens on its usual-rate period; failed logins on a day
        alertActivityRange = alertActivityIsSentMail(data.alert) ? '7d' : '24h';
        renderAlertActivity();
    } catch (error) {
        if (gen !== alertActivityGen || (error && error.name === 'AbortError')) return;
        content.innerHTML = `<p class="ui-empty">Could not load the activity: ${escapeHtml(error.message)}. Try again in a moment.</p>`;
    }
}

function closeAlertActivity() {
    alertActivityGen++;
    if (alertActivityControl) alertActivityControl.abort();
    if (alertActivityZoomer) { alertActivityZoomer.destroy(); alertActivityZoomer = null; }
    if (alertActivityOverviewer) { alertActivityOverviewer.destroy(); alertActivityOverviewer = null; }
    document.getElementById('alert-activity-modal').classList.add('hidden');
}

// A volume spike and an SMTP block by abuse protection both count the
// mailbox's sent mail; an auth failure burst counts a username's failed logins
function alertActivityIsSentMail(alert) {
    return alert.alert_type === 'volume_spike' || alert.alert_type === 'smtp_abuse_block';
}

function setAlertActivityRange(range) {
    alertActivityRange = range;
    alertActivityZoom = null;
    alertActivityPick = null;
    renderAlertActivity();
}

function pickAlertActivityColumn(t) {
    alertActivityPick = t === null || alertActivityPick === t ? null : t;
    renderAlertActivity();
}

// The data's 15-minute counts, as spans of time: each from its start to the
// next one's, the last up to where the data ends (now, for a recent alert)
function alertActivityQuarters(data) {
    const quarter = data.bucket_minutes * 60000;
    const end = data.data_end ? Date.parse(data.data_end) : null;
    return data.buckets.map(b => {
        const start = Date.parse(b.start);
        return { start, end: end !== null ? Math.min(start + quarter, end) : start + quarter, count: b.count };
    });
}

// The span the range buttons show: the last hours of the data
function alertActivityRangeSpan(data) {
    const q = alertActivityQuarters(data);
    if (!q.length) return null;
    const days = Math.max(1, Number(data.baseline_days) || 7);
    const hours = { '24h': 24, '48h': 48, '7d': 24 * days }[alertActivityRange];
    const to = q[q.length - 1].end;
    // As before: the chosen hours and the two after the alert, from the end of the data
    const from = Math.max(q[0].start, to - (hours + 2) * 3600000);
    return { from, to };
}

// The columns of a span: quarters of an hour up to two days, hours beyond
// (several hours for a baseline longer than a week, so the bars stay visible).
// An hour column starts where the app's zone shows a whole hour; on the night
// the clocks go back both 02:00 start one, an hour apart; a skipped hour starts
// none. Every zone is a whole number of quarters off UTC, so these hours fall on
// the quarters' grid.
function alertActivityColumns(data, span) {
    const keep = alertActivityQuarters(data).filter(q => q.start >= span.from && q.start < span.to);
    const quarterMinutes = data.bucket_minutes;
    if (span.to - span.from <= 48 * 3600000 || !keep.length) {
        return { cols: keep.map(q => ({ start: new Date(q.start), end: new Date(q.end), count: q.count })), minutes: quarterMinutes };
    }
    // Whole days: the two hours after the alert do not make a week's columns longer
    const days = Math.floor((span.to - span.from) / 86400000);
    const stepHours = Math.max(1, Math.ceil(days / 7));
    const cols = [];
    for (const q of keep) {
        const p = zonedParts(q.start);
        if (!cols.length || (p.minute === 0 && p.second === 0 && p.hour % stepHours === 0)) {
            if (cols.length) cols[cols.length - 1].end = new Date(q.start);
            cols.push({ start: new Date(q.start), count: 0 });
        }
        cols[cols.length - 1].count += q.count;
        cols[cols.length - 1].end = new Date(q.end);
    }
    return { cols, minutes: stepHours * 60 };
}

// A column's length, when it is not the usual one: "3 hours", "45 minutes"
function alertActivitySpan(minutes) {
    return minutes % 60 ? uiCountLabel(minutes, 'minute', 'minutes') : uiCountLabel(minutes / 60, 'hour', 'hours');
}

function alertActivityChart(data, span) {
    const a = data.alert;
    const spike = a.alert_type === 'volume_spike';
    const sent = alertActivityIsSentMail(a);
    const { cols, minutes } = alertActivityColumns(data, span);
    if (!cols.length) return '<p class="ui-empty">No counts kept for this time.</p>';
    const at = new Date(a.created_at);
    // An SMTP block whose window is not known (its abuse action is gone) marks no period
    const from = data.window_minutes ? new Date(at.getTime() - data.window_minutes * 60000) : null;
    const max = Math.max(4, ...cols.map(c => c.count));
    const top = Math.ceil(max / 4) * 4;
    // A spike's usual rate, for the real length of each column (a clock change or
    // the ends of the data make some longer or shorter); a burst or a block has
    // no usual rate, only a threshold. It stays the alert's own rate, whatever is zoomed.
    const usualIn = c => (a.baseline_value || 0) * (c.end - c.start) / 3600000;
    const usual = spike ? (a.baseline_value || 0) * minutes / 60 : null;
    // The date as the rest of the app writes it, on a 24-hour clock
    const fmt = d => `${formatDay(d)}, ${formatInZone(d, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }, 'en-US')}`;
    const what = sent ? 'sent' : 'failed logins';
    const markAt = cols.findIndex(c => at >= c.start && at < c.end);
    const ranges = [['24h', '24 hours'], ['48h', '2 days'], ['7d', `${escapeHtml(String(data.baseline_days))} days`]];
    const per = minutes === 60 ? 'hour' : minutes > 60 ? `${minutes / 60} hours` : `${minutes} minutes`;
    const zoomed = !!alertActivityZoom;
    const limits = alertActivityLimits(data);
    return `<div class="ui-aa-head"><b>${sent ? 'What it sent' : 'Failed logins'}</b><span class="ui-muted">${sent ? 'this mailbox only' : 'this username only'}</span>
            <span class="ui-seg ui-head-actions" role="group" aria-label="Period">${ranges.map(([k, l]) => `<button type="button" aria-pressed="${!zoomed && alertActivityRange === k}" onclick="setAlertActivityRange('${k}')">${l}</button>`).join('')}</span></div>
        <div class="ui-aa-chart">
            <div class="ui-aa-grid">${[top, top * .75, top * .5, top * .25, 0].map(v => `<i><span>${Math.round(v)}</span></i>`).join('')}</div>
            <div class="ui-aa-cols${alertActivityPick !== null ? ' has-pick' : ''}" role="group" aria-label="${sent ? 'Sent' : 'Failed logins'} per ${escapeHtml(per)}" data-zoom>${cols.map(c => {
                const inAlert = from && c.end > from && c.start <= at;
                // A column made shorter or longer by a clock change or the ends of the data says how long it is
                const len = (c.end - c.start) / 60000;
                const tip = `${fmt(c.start)}: ${c.count} ${what}${len !== minutes ? ` in ${alertActivitySpan(len)}` : ''}`;
                const norm = usual !== null ? `<b class="ui-aa-norm" style="bottom:${Math.max(usualIn(c) / top * 100, .6)}%"></b>` : '';
                const s = c.start.getTime();
                return `<button type="button" class="ui-aa-col${inAlert ? ' is-alert' : ''}" data-start="${s}" data-end="${c.end.getTime()}" aria-pressed="${alertActivityPick === s}" aria-label="${escapeHtml(tip)}" title="${escapeHtml(tip)}" onclick="pickAlertActivityColumn(${s})"><i style="height:${c.count / top * 100}%"></i>${norm}</button>`;
            }).join('')}</div>
            ${usual !== null ? `<div class="ui-aa-usual" style="bottom:${Math.max(usual / top * 100, .6)}%"><span>usual: ${(a.baseline_value || 0).toFixed(2)} an hour</span></div>` : ''}
            ${markAt >= 0 ? `<div class="ui-aa-mark" style="left:${(markAt + .5) / cols.length * 100}%"><span>Alert ${formatInZone(at, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }, 'en-US')}</span></div>` : ''}
            <div class="ui-flow-band hidden" aria-hidden="true"></div>
        </div>
        <div class="ui-aa-x"><span>${escapeHtml(fmt(cols[0].start))}</span><span>${escapeHtml(fmt(cols[cols.length - 1].start))}</span></div>
        <div class="ui-ov" data-zoom role="group" aria-label="All the data, with the span shown"></div>
        <div class="ui-flow-foot">
            <p class="ui-aa-legend"><span><i></i>${sent ? 'Sent' : 'Failed logins'}, per ${escapeHtml(per)}</span>${from ? `<span><i class="is-alert"></i>The alert's ${escapeHtml(String(data.window_minutes))} minutes</span>` : ''}${usual !== null ? `<span><i class="is-usual"></i>Its usual rate over ${escapeHtml(String(data.baseline_days))} days</span>` : ''}</p>
            <div class="ui-flow-zoom" role="group" aria-label="Zoom the chart">
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="alertActivityStep('earlier')" aria-label="Earlier" title="Earlier"${span.from > limits.from ? '' : ' disabled'}>&lsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="alertActivityStep('out')" aria-label="Zoom out" title="Zoom out"${span.to - span.from < limits.to - limits.from ? '' : ' disabled'}>&minus;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="alertActivityStep('in')" aria-label="Zoom in" title="Zoom in (or pinch, drag across columns, Ctrl+wheel)"${span.to - span.from > limits.min ? '' : ' disabled'}>+</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm" onclick="alertActivityStep('later')" aria-label="Later" title="Later"${span.to < limits.to ? '' : ' disabled'}>&rsaquo;</button>
                <button type="button" class="ui-icon-btn ui-icon-btn-sm${zoomed ? '' : ' is-off'}" onclick="alertActivityStep('reset')" aria-label="Reset zoom" title="Reset zoom"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v5h5"/></svg></button>
            </div>
        </div>`;
}

// How far the chart zooms out and moves: all the data; at most down to an hour
function alertActivityLimits(data) {
    const q = alertActivityQuarters(data);
    return q.length ? { from: q[0].start, to: q[q.length - 1].end, min: 3600000 } : { from: 0, to: 1, min: 1 };
}

// An instant on the data's quarters (the data's end, even inside a quarter, is one too)
function alertActivitySnap(data) {
    const l = alertActivityLimits(data);
    const quarter = data.bucket_minutes * 60000;
    return t => {
        const q = Math.max(l.from, Math.min(l.to, l.from + Math.round((t - l.from) / quarter) * quarter));
        // The nearer of the quarter's edge and the data's end
        return Math.abs(l.to - t) < Math.abs(q - t) ? l.to : q;
    };
}

// A span as the chart shows it: its columns start on the first quarter at or after its start
function alertActivityShown(data, span) {
    const l = alertActivityLimits(data), quarter = data.bucket_minutes * 60000;
    return { from: Math.min(span.to, l.from + Math.ceil((span.from - l.from) / quarter) * quarter), to: span.to };
}

// Show a span: snapped to the quarters (at least the shortest span); the pressed range's own span is no zoom
function alertActivityShow(data, next) {
    const l = alertActivityLimits(data), snap = alertActivitySnap(data);
    // The range itself, asked as it is: no zoom
    const raw = alertActivityRangeSpan(data);
    if (raw && Math.abs(next.from - raw.from) <= 1 && Math.abs(next.to - raw.to) <= 1) {
        alertActivityZoom = null;
        alertActivityPick = null;
        renderAlertActivity();
        return;
    }
    let from = snap(next.from), to = snap(next.to);
    if (to - from < l.min) {
        to = Math.min(l.to, snap(from + l.min));
        if (to - from < l.min) {
            // Back from the end to a quarter at least the shortest span before it
            const quarter = data.bucket_minutes * 60000;
            from = Math.max(l.from, l.from + Math.floor((to - l.min - l.from) / quarter) * quarter);
        }
    }
    // The range is counted back from the data's end, off the quarters: compared as the chart shows it
    const range = raw && alertActivityShown(data, raw);
    alertActivityZoom = range && Math.abs(range.from - from) <= 1 && Math.abs(range.to - to) <= 1 ? null : { from, to };
    alertActivityPick = null;
    renderAlertActivity();
}

function alertActivityStep(step) {
    const data = alertActivity;
    if (!data) return;
    if (step === 'reset') { alertActivityZoom = null; alertActivityPick = null; renderAlertActivity(); return; }
    const span = alertActivityZoom || alertActivityRangeSpan(data);
    alertActivityShow(data, uiTimeZoomStep(span, alertActivityLimits(data), step));
}

// The strip under the chart: all the data in small bars, a window over the span shown
function alertActivityOverview(data, span) {
    if (alertActivityOverviewer) { alertActivityOverviewer.destroy(); alertActivityOverviewer = null; }
    const strip = document.querySelector('#alert-activity-content .ui-ov');
    const l = alertActivityLimits(data);
    if (!strip || l.to - l.from < l.min) return;
    const cols = alertActivityColumns(data, l).cols;
    const max = Math.max(1, ...cols.map(c => c.count));
    strip.innerHTML = `<div class="ui-ov-bars" aria-hidden="true">${cols.map(c => `<i style="height:${Math.max(6, c.count / max * 100)}%"></i>`).join('')}</div>`;
    const edges = cols.map(c => c.start.getTime()).concat(l.to);
    const fmt = t => `${formatDay(t)}, ${formatInZone(t, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' }, 'en-US')}`;
    alertActivityOverviewer = uiTimeOverview(strip, {
        limits: () => l,
        // Its edges where the chart's columns are
        span: () => alertActivityShown(data, span),
        snap: alertActivitySnap(data),
        // One step is one bar of the strip, a big step a day
        step: (t, dir, big) => (big ? t + dir * 86400000
            : dir > 0 ? (edges.find(e => e > t + 1) ?? l.to) : ([...edges].reverse().find(e => e < t - 1) ?? l.from)),
        label: fmt,
        change: next => alertActivityShow(data, next),
    });
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
    // Dismiss and the way on are in the footer, at the bottom of the window however far it scrolls
    const dismiss = document.getElementById('alert-activity-dismiss');
    if (dismiss) {
        dismiss.classList.toggle('hidden', !!a.acknowledged);
        dismiss.onclick = () => { closeAlertActivity(); acknowledgeSecurityAlert(Number(a.id)); };
    }
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
    const span = alertActivityZoom || alertActivityRangeSpan(data) || { from: 0, to: 1 };
    // The picked column, if it is still shown
    const cols = alertActivityColumns(data, span).cols;
    const picked = alertActivityPick === null ? null : cols.find(c => c.start.getTime() === alertActivityPick);
    if (!picked) alertActivityPick = null;
    const pickedLine = picked ? `<p class="ui-aa-picked">${escapeHtml(mailFlowSpan(picked.start.getTime(), picked.end.getTime()))}: <b>${picked.count.toLocaleString()}</b> ${sent ? 'sent' : 'failed logins'} <button type="button" class="ui-more" onclick="pickAlertActivityColumn(null)">Clear</button></p>` : '';
    if (alertActivityZoomer) { alertActivityZoomer.destroy(); alertActivityZoomer = null; }
    uiRedrawKeepingFocus(content, () => { content.innerHTML = `
        <p class="ui-muted ui-aa-sub">${escapeHtml(a.title)} · ${escapeHtml(formatTime(a.created_at))}</p>
        <div class="ui-aa-strip">${figures.map(([label, value, bad]) => `<div><small>${escapeHtml(label)}</small><b${bad ? ' class="ui-text-fail"' : ''}>${escapeHtml(value)}</b></div>`).join('')}</div>
        <section>${alertActivityChart(data, span)}${pickedLine}</section>
        <section><div class="ui-aa-head"><b>Around the alert</b><span class="ui-muted">${uiCountLabel(around.total, sent ? 'message' : 'failed login', sent ? 'messages' : 'failed logins')}, from ${escapeHtml(String(lead))} minutes before it to an hour after</span></div>
            ${around.total ? `<div class="ui-aa-two">${sent
                ? alertActivityList('Recipient domains', around.recipient_domains, around.total) + alertActivityList('What happened to them', around.results, around.total, n => results[n] || 'muted')
                    + `<div class="ui-aa-box ui-aa-wide"><h4>Subjects</h4>${around.subjects.map(s => `<div class="ui-aa-subj"><span title="${escapeHtml(s.name)}" dir="auto">${escapeHtml(s.name)}</span><small>${uiCountLabel(s.count, 'message', 'messages')}</small></div>`).join('')}</div>`
                : alertActivityList('Addresses', around.addresses, around.total) + alertActivityList('Countries', around.countries, around.total) + alertActivityList('Networks', around.networks, around.total)}</div>`
            : '<p class="ui-empty">Nothing in the logs around the alert. They may have been cleaned up since.</p>'}</section>
        <p class="ui-muted ui-aa-note">${sent
            ? 'Spam from a hijacked mailbox usually goes to many unrelated domains with the same few subjects, and much of it bounces or is rejected. Mail the user really sent goes to people they write to.'
            : 'Many addresses or networks trying one username point to an attack spread out to stay under the ban; one address is a single machine, possibly a device with an old password.'}</p>
`;
        alertActivityOverview(data, span); });
    // The way on, in the footer
    document.getElementById('alert-activity-foot')?.classList.remove('hidden');
    const open = document.getElementById('alert-activity-open');
    if (open) uiRedrawKeepingFocus(open, () => {
        open.innerHTML = sent ? `<button type="button" class="ui-btn ui-btn-primary" onclick="openAlertActivityMessages()">${picked ? 'Open this time in Messages' : 'Open in Messages'}</button>`
            : `<button type="button" class="ui-btn ui-btn-primary" onclick="closeAlertActivity(); openAlertSecurityEvents('${escapeJsArg(a.subject)}')">Open in Security</button>`;
    });
    // Zoom by gesture over the columns (a preview stretches them; the end draws the span)
    const box = content.querySelector('.ui-aa-cols');
    const chart = content.querySelector('.ui-aa-chart');
    const band = content.querySelector('.ui-flow-band');
    if (box) {
        let previewing = false;
        alertActivityZoomer = uiTimeZoom(box, {
            bars: () => [...box.querySelectorAll('.ui-aa-col')],
            span: () => span,
            limits: () => alertActivityLimits(data),
            preview: (next, kind) => {
                previewing = true;
                if (kind === 'select') {
                    const r = chart.getBoundingClientRect();
                    band.classList.remove('hidden');
                    band.style.left = `${next.x1 - r.left}px`;
                    band.style.width = `${next.x2 - next.x1}px`;
                    return;
                }
                const len = span.to - span.from, k = len / (next.to - next.from);
                box.style.transformOrigin = '0 0';
                box.style.transform = `translateX(${-(next.from - span.from) / len * box.clientWidth * k}px) scaleX(${k})`;
            },
            change: next => {
                previewing = false;
                alertActivityShow(data, next);
            },
            cancel: () => { previewing = false; box.style.transform = ''; band.classList.add('hidden'); },
        });
    }
}

// The mailbox's messages on the Messages page, in the picked column's time,
// else around the alert (from its window before it to an hour after)
function openAlertActivityMessages() {
    const data = alertActivity;
    if (!data) return;
    const a = data.alert;
    const span = alertActivityZoom || alertActivityRangeSpan(data);
    const picked = alertActivityPick === null || !span ? null : alertActivityColumns(data, span).cols.find(c => c.start.getTime() === alertActivityPick);
    const start = picked ? picked.start.toISOString() : data.around.from;
    // The column's last microsecond (the database keeps microseconds; a column ends on a whole millisecond)
    // The last column, cut at now (its quarter still running), ends at that exact
    // moment; a whole column ends a microsecond before its end, as it is counted
    const lastBucket = data.buckets[data.buckets.length - 1];
    const atDataEnd = picked && data.data_end && lastBucket && lastBucket.partial
        && picked.end.getTime() === Date.parse(data.data_end);
    const endInclusive = !picked ? data.around.to
        : atDataEnd ? data.data_end : new Date(picked.end.getTime() - 1).toISOString().replace('Z', '999Z');
    closeAlertActivity();
    openMessagesRange({ start, endInclusive, user: a.subject || '' });
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
    navigateTo('netfilter', { sub: 'events' }).then(moved => {
        if (moved) setTimeout(() => { if (typeof applyNetfilterFilters === 'function') applyNetfilterFilters(); }, 100);
    });
}
