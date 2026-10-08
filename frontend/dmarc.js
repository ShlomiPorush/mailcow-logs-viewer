// =============================================================================
// DMARC & TLS-RPT - domains, a domain, its senders, a day of reports, upload,
// IMAP sync and report management
// =============================================================================
// Classic script sharing the global scope; loaded after utils.js and app.js in
// index.html. Every screen renders into #dmarc-view: all domains, a domain (mail
// per day, the mail flow, its senders and TLS beside the to-do list and its
// records), a sender, a day of DMARC reports and a day of TLS reports.

let dmarcState = {
    currentView: 'domains',      // domains | domain | report | source | tls
    currentDomain: null,
    breadcrumb: [],              // [{ label, action }] after the page's name
    domains: null,               // /api/dmarc/domains
    daily: [],                   // messages per day across the domains
    insights: null,              // /api/dmarc/insights
    domain: null                 // the open domain: { name, overview, groups, tls, insight }
};

// The page has no tabs any more; /dmarc/tls and the old tab links open the domains
function dmarcOpenTab() {
    navigateTo('dmarc');
}

// Pass rates: green from 95%, amber from 80%, red below
function dmarcTone(pct) {
    return pct >= 95 ? 'ok' : pct >= 80 ? 'warn' : 'fail';
}

function dmarcPct(value) {
    return `${Math.round((Number(value) || 0) * 100) / 100}%`;
}

function dmarcNum(value) {
    return (Number(value) || 0).toLocaleString();
}

function dmarcDay(date, long = false) {
    const d = new Date(`${date}T00:00:00`);
    return d.toLocaleDateString('en-US', long ? { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' } : { month: 'short', day: 'numeric' });
}

function dmarcTag(tone, label, solid = false) {
    return `<span class="ui-dm-pill ui-dm-${tone}${solid ? ' is-solid' : ''}">${escapeHtml(label)}</span>`;
}

async function dmarcGet(url) {
    const response = await authenticatedFetch(url);
    if (!response.ok) throw new Error(`The server answered ${response.status}`);
    return response.json();
}

function dmarcView() {
    return document.getElementById('dmarc-view');
}

function dmarcLoading(text) {
    const view = dmarcView();
    if (view) view.innerHTML = `<div class="ui-loading"><div class="loading"></div><p>${escapeHtml(text)}</p></div>`;
}

function dmarcFailed(error) {
    const view = dmarcView();
    if (view) view.innerHTML = `<div class="ui-dm-card"><p class="ui-dm-empty">Could not load this: ${escapeHtml(error.message)}. Try again in a moment.</p></div>`;
}

// The address of what is open; a load from the address itself does not add a step
function dmarcPush(params) {
    if (typeof buildPath !== 'function') return;
    const path = buildPath('dmarc', params);
    if (window.location.pathname !== path) history.pushState({ route: 'dmarc', params }, '', path);
}

function dmarcReplace(params) {
    if (typeof buildPath !== 'function') return;
    history.replaceState({ route: 'dmarc', params }, '', buildPath('dmarc', params));
}

// =============================================================================
// BREADCRUMBS
// =============================================================================

function updateDmarcBreadcrumb() {
    // With the top bar the levels join its crumbs; on a phone this row shows them
    if (typeof setPageCrumbs === 'function') setPageCrumbs('dmarc', '', 'dmarcOpenTab()', dmarcState.breadcrumb);
    const container = document.getElementById('dmarc-breadcrumb');
    if (!container) return;
    if (!dmarcState.breadcrumb.length) {
        container.innerHTML = '';
        container.classList.add('hidden');
        return;
    }
    container.classList.remove('hidden');
    const separator = '<span class="ui-crumb-sep" aria-hidden="true">/</span>';
    container.innerHTML = `<button type="button" class="ui-crumb" onclick="dmarcOpenTab()">DMARC &amp; TLS</button>${dmarcState.breadcrumb.map((item, idx) =>
        idx === dmarcState.breadcrumb.length - 1 || !item.action
            ? `${separator}<span class="ui-crumb-current">${escapeHtml(item.label)}</span>`
            : `${separator}<button type="button" class="ui-crumb" onclick="${item.action}">${escapeHtml(item.label)}</button>`).join('')}`;
}

// The levels after the page's name, for each screen
function setDmarcBreadcrumb(type, data = {}) {
    const domain = data.domain ? { label: data.domain, action: `loadDomainOverview('${escapeJsArg(data.domain)}')` } : null;
    switch (type) {
        case 'domain':
            dmarcState.breadcrumb = [{ label: data.domain, action: null }];
            break;
        case 'reportDetails':
            dmarcState.breadcrumb = [domain, { label: dmarcDay(data.date), action: null }];
            break;
        case 'sourceDetails':
            dmarcState.breadcrumb = [domain, { label: data.name || data.ip, action: null }];
            break;
        case 'tlsDetails':
            dmarcState.breadcrumb = [domain, { label: `TLS, ${dmarcDay(data.date)}`, action: null }];
            break;
        default:
            dmarcState.breadcrumb = [];
    }
    updateDmarcBreadcrumb();
}

// =============================================================================
// LOADING AND ROUTES
// =============================================================================

async function loadDmarcSettings() {
    try {
        const response = await authenticatedFetch('/api/settings/info');
        if (!response.ok) {
            dmarcConfiguration = null;
            return;
        }
        const data = await response.json();
        dmarcConfiguration = data.dmarc_configuration || {};
    } catch (error) {
        console.error('Error loading DMARC settings:', error);
        dmarcConfiguration = null;
    }
}

// The upload and sync controls: settings once, the mailbox status each time
function dmarcLoadControls() {
    const loads = [loadDmarcImapStatus()];
    if (!dmarcConfiguration) loads.push(loadDmarcSettings());
    // Manage Reports counts the reports: opened straight on a domain, read the list for it
    if (!dmarcState.domains) dmarcGet('/api/dmarc/domains').then(list => dmarcUpdateManageButton(list.domains || [])).catch(() => {});
    return Promise.all(loads).then(updateDmarcControls);
}

// All domains
async function loadDmarc() {
    dmarcState.currentView = 'domains';
    dmarcState.currentDomain = null;
    setDmarcBreadcrumb('domains');
    if (!dmarcState.domains) dmarcLoading('Loading DMARC reports...');
    else renderDmarcHome();
    dmarcLoadControls();
    await loadDmarcDomains();
}

/**
 * Open what the address names. /dmarc/tls and /dmarc/tls/<domain> are from when
 * TLS had its own tab: they open the domains and the domain.
 * @param {Object} params - { domain, type, id } or { tab: 'tls', domain, id }
 */
async function handleDmarcRoute(params = {}) {
    // Opened from the address (a link, Back, Refresh): read the domain afresh
    dmarcState.domain = null;
    if (params.tab === 'tls') {
        if (params.domain && params.id && params.id !== 'providers') return loadTLSReportDetails(params.domain, params.id, false);
        dmarcReplace(params.domain ? { domain: params.domain } : {});
        return params.domain ? loadDomainOverview(params.domain, false) : loadDmarc();
    }
    if (!params.domain) return loadDmarc();
    if (params.type === 'report' && params.id) return loadReportDetails(params.domain, params.id, false);
    if (params.type === 'source' && params.id) return loadSourceDetails(params.domain, params.id, false);
    // /dmarc/<domain>/sources, /reports and /tls were tabs of the domain
    if (params.type) dmarcReplace({ domain: params.domain });
    return loadDomainOverview(params.domain, false);
}

// =============================================================================
// ALL DOMAINS
// =============================================================================

async function loadDmarcDomains() {
    try {
        const [list, insights] = await Promise.all([dmarcGet('/api/dmarc/domains'), dmarcGet('/api/dmarc/insights').catch(() => null)]);
        dmarcState.domains = list.domains || [];
        dmarcState.daily = list.daily || [];
        dmarcState.insights = insights;
        dmarcState.domain = null;
        dmarcUpdateManageButton(dmarcState.domains);
        if (dmarcState.currentView === 'domains') renderDmarcHome();
    } catch (error) {
        console.error('Error loading DMARC domains:', error);
        if (dmarcState.currentView === 'domains') dmarcFailed(error);
    }
}

function dmarcInsightFor(domain) {
    return ((dmarcState.insights || {}).insights || []).find(i => i.domain === domain) || null;
}

// What to do on every domain, the most important first
function dmarcHomeTasks(domains) {
    const tasks = [];
    domains.forEach(d => {
        const rec = d.dmarc_record || {}, tls = d.tls_rpt_record || {};
        const volume = (d.stats_30d || {}).total_messages || 0;
        const name = escapeJsArg(d.domain);
        if (rec.checked && !rec.found) tasks.push({ w: 1000 + volume, tone: 'fail', domain: d.domain, title: 'Publish a DMARC record',
            text: `${uiCountLabel(volume, 'message', 'messages')} in 30 days, and receivers have no policy to refuse fakes.`, label: 'Show the record', action: `openDmarcRecord('dmarc', '${name}')` });
        if (d.failing_sources) tasks.push({ w: 600 + d.failing_sources, tone: 'fail', domain: d.domain, title: `${uiCountLabel(d.failing_sources, 'sender fails', 'senders fail')} DMARC`,
            text: 'Mail in your name that failed SPF and DKIM. Open the domain to see who sent it.', label: 'Look at it', action: `loadDomainOverview('${name}')` });
        if (rec.found && rec.policy === 'none') {
            const advice = ((dmarcInsightFor(d.domain) || {}).recommendations || [])[0];
            tasks.push({ w: volume >= 100 ? 500 : 50, tone: 'warn', domain: d.domain, title: 'The policy only monitors (p=none)',
                text: advice ? advice.message : 'Mail that fails is still delivered.', label: 'See the policy', action: `openDmarcRecord('dmarc', '${name}')` });
        }
        if (tls.checked && !tls.found) tasks.push({ w: 100, tone: 'warn', domain: d.domain, title: 'Publish a TLS-RPT record',
            text: 'Receivers then tell you when mail to you could not be encrypted.', label: 'Show the record', action: `openDmarcRecord('tls', '${name}')` });
    });
    return tasks.sort((a, b) => b.w - a.w);
}

function dmarcPolicyTag(d) {
    const rec = d.dmarc_record || {};
    if (!rec.checked) return dmarcTag('mut', 'Not checked');
    if (!rec.found) return dmarcTag('fail', 'No record', true);
    return rec.policy === 'reject' ? dmarcTag('ok', 'Reject') : rec.policy === 'quarantine' ? dmarcTag('warn', 'Quarantine') : dmarcTag('warn', rec.policy ? rec.policy[0].toUpperCase() + rec.policy.slice(1) : 'Unknown');
}

function renderDmarcHome() {
    const view = dmarcView();
    if (!view) return;
    const domains = dmarcState.domains || [];
    if (!domains.length) {
        view.innerHTML = `<div class="ui-dm-card"><p class="ui-dm-empty">No reports yet. They arrive from the report mailbox, or upload one with Upload Report.</p></div>`;
        return;
    }
    const total = domains.reduce((s, d) => s + ((d.stats_30d || {}).total_messages || 0), 0);
    const pass = total ? domains.reduce((s, d) => s + ((d.stats_30d || {}).total_messages || 0) * ((d.stats_30d || {}).dmarc_pass_pct || 0), 0) / total : 0;
    const enforced = domains.filter(d => ['reject', 'quarantine'].includes((d.dmarc_record || {}).policy)).length;
    view.innerHTML = `
        <div class="ui-dm-card"><header>Last 30 days</header><div class="ui-dm-strip">
            <div><small>Domains with reports</small><b class="is-big">${domains.length}</b></div>
            <div><small>Messages reported</small><b class="is-big">${dmarcNum(total)}</b></div>
            <div><small>Passed DMARC</small><b class="is-big ui-text-${dmarcTone(pass)}">${total ? dmarcPct(pass.toFixed(1)) : '-'}</b></div>
            <div><small>Enforced (quarantine or reject)</small><b class="is-big">${enforced} of ${domains.length}</b></div></div></div>
        <div class="ui-dm-lay"><div>
            <div class="ui-dm-card"><header>Messages per day<small>every domain</small></header><div class="ui-dm-body">${dmarcChart(dmarcState.daily, { h: 150, open: null })}</div></div>
            <div class="ui-dm-card"><header>Domains <span class="ui-count">${domains.length}</span></header>
            <table class="ui-dm-tbl"><thead><tr><th>Domain</th><th>DMARC policy</th><th class="r">Messages</th><th class="r">Passed DMARC</th><th class="ui-dm-hm">TLS-RPT</th><th class="r ui-dm-hm">Encrypted</th><th class="r ui-dm-hm">Failing senders</th></tr></thead><tbody>
            ${domains.map(d => {
                const s = d.stats_30d || {}, tls = d.tls_rpt_record || {};
                return `<tr class="is-go" onclick="loadDomainOverview('${escapeJsArg(d.domain)}')"><td><button type="button" class="ui-dm-link">${escapeHtml(d.domain)}</button></td>
                    <td>${dmarcPolicyTag(d)}</td><td class="r ui-num">${d.has_dmarc ? dmarcNum(s.total_messages) : '<span class="ui-muted">-</span>'}</td>
                    <td class="r">${d.has_dmarc ? `<span class="ui-text-${dmarcTone(s.dmarc_pass_pct)}">${dmarcPct(s.dmarc_pass_pct)}</span>` : '<span class="ui-muted">-</span>'}</td>
                    <td class="ui-dm-hm">${!tls.checked ? dmarcTag('mut', 'Not checked') : tls.found ? dmarcTag('ok', 'Published') : dmarcTag('warn', 'Missing')}</td>
                    <td class="r ui-dm-hm">${d.has_tls ? `<span class="ui-text-${dmarcTone(s.tls_success_pct)}">${dmarcPct(s.tls_success_pct)}</span>` : '<span class="ui-muted">-</span>'}</td>
                    <td class="r ui-dm-hm">${d.failing_sources ? `<span class="ui-text-fail">${escapeHtml(String(d.failing_sources))}</span>` : '<span class="ui-muted">0</span>'}</td></tr>`;
            }).join('')}</tbody></table></div>
        </div><aside>${dmarcTodoCard(dmarcHomeTasks(domains), true)}</aside></div>`;
}

// =============================================================================
// PIECES: the chart, the to-do list, the mail flow
// =============================================================================

// Messages (or TLS sessions) per day, passed on failed; a day opens its reports
function dmarcChart(daily, opts = {}) {
    if (!daily.length) return '<p class="ui-dm-empty">No reports in the last 30 days.</p>';
    const h = opts.h || 190;
    const ok = x => opts.tls ? x.total_success : x.dmarc_pass;
    const bad = x => opts.tls ? x.total_fail : x.dmarc_fail;
    const max = Math.max(1, ...daily.map(x => ok(x) + bad(x)));
    const step = Math.pow(10, Math.floor(Math.log10(max)));
    const top = Math.ceil(max / step) * step;
    const short = v => v >= 10000 ? `${(v / 1000).toFixed(1).replace(/\.0$/, '')}k` : dmarcNum(v);
    const domain = dmarcState.currentDomain ? escapeJsArg(dmarcState.currentDomain) : '';
    const words = opts.tls ? ['encrypted', 'failed'] : ['passed', 'failed'];
    return `<div class="ui-dm-legend"><span><i class="is-ok"></i>${opts.tls ? 'Encrypted' : 'Passed DMARC'}</span><span><i class="is-fail"></i>Failed</span>${opts.open !== null && domain ? '<span>A day opens its reports</span>' : ''}</div>
        <div class="ui-dm-chart"><div class="ui-dm-grid" style="height:${h}px">${[top, top * .75, top * .5, top * .25, 0].map(t => `<i><span>${short(Math.round(t))}</span></i>`).join('')}</div>
        <div class="ui-dm-cols" style="height:${h}px">${daily.map(x => {
            const tip = `${dmarcDay(x.date)}: ${dmarcNum(ok(x))} ${words[0]}, ${dmarcNum(bad(x))} ${words[1]}`;
            const day = escapeJsArg(x.date);
            const open = opts.open === null || !domain ? 'disabled'
                : opts.tls ? `onclick="loadTLSReportDetails('${domain}', '${day}')"` : `onclick="loadReportDetails('${domain}', '${day}')"`;
            return `<button type="button" class="ui-dm-col" data-tip="${escapeHtml(tip)}" aria-label="${escapeHtml(tip)}" ${open}><i style="height:${ok(x) / top * h}px"></i><i class="is-fail" style="height:${bad(x) / top * h}px"></i></button>`;
        }).join('')}</div>
        <div class="ui-dm-x"><span>${dmarcDay(daily[0].date)}</span><span>${dmarcDay(daily[daily.length - 1].date)}</span></div></div>`;
}

function dmarcTodoCard(tasks, withDomain = false) {
    if (!tasks.length) return '<div class="ui-dm-card"><header>To do</header><p class="ui-dm-empty">Nothing to do. The records are in place and every sender passes.</p></div>';
    return `<div class="ui-dm-card"><header>To do <span class="ui-count">${tasks.length}</span></header>${tasks.slice(0, 8).map(t => `
        <div class="ui-dm-task ui-dm-${t.tone}"><div><b>${escapeHtml(t.title)}</b>${withDomain ? `<small class="ui-dm-task-domain">${escapeHtml(t.domain)}</small>` : ''}
            <p>${escapeHtml(t.text)}</p><button type="button" class="ui-btn ui-btn-sm" onclick="${t.action}">${escapeHtml(t.label)}</button></div></div>`).join('')}
        ${tasks.length > 8 ? `<p class="ui-dm-more">and ${tasks.length - 8} more</p>` : ''}</div>`;
}

// Your domain, the senders that sent as it, the receivers that reported it
function dmarcFlow(x) {
    const groups = x.groups.slice(0, 8);
    const receivers = Object.create(null); // keyed by reporter names from the reports
    groups.forEach(g => g.reporters.forEach(r => {
        const e = receivers[r.org_name] || (receivers[r.org_name] = { name: r.org_name, count: 0, pass: 0, from: Object.create(null) });
        e.count += r.count; e.pass += r.dmarc_pass; e.from[g.key] = (e.from[g.key] || 0) + r.count;
    }));
    const recv = Object.values(receivers).sort((a, b) => b.count - a.count).slice(0, 8);
    if (!groups.length) return '<p class="ui-dm-empty">No senders in the last 30 days.</p>';
    const total = groups.reduce((s, g) => s + g.total, 0) || 1, rtotal = recv.reduce((s, r) => s + r.count, 0) || 1;
    const links = [];
    recv.forEach((r, ri) => Object.entries(r.from).forEach(([key, count]) => {
        const gi = groups.findIndex(g => g.key === key);
        if (gi >= 0) links.push([gi, ri, Math.max(2, count / rtotal * 24), dmarcTone(groups[gi].passPct)]);
    }));
    const node = (col, i, title, sub, pct, action) => `<${action ? 'button type="button"' : 'div'} class="ui-dm-node ui-dm-${dmarcTone(pct)}" data-col="${col}" data-i="${i}" ${action ? `onclick="${action}"` : ''}><b>${escapeHtml(title)}</b><small>${escapeHtml(sub)}</small></${action ? 'button' : 'div'}>`;
    const domain = escapeJsArg(x.name);
    return `<div class="ui-dm-flow" id="dmarc-flow" data-g='${escapeHtml(JSON.stringify(groups.map(g => [Math.max(3, g.total / total * 24), dmarcTone(g.passPct)])))}' data-l='${escapeHtml(JSON.stringify(links))}'>
        <svg aria-hidden="true"></svg><span class="ui-dm-colh" data-col="0">Your domain</span><span class="ui-dm-colh" data-col="1">Sent by</span><span class="ui-dm-colh" data-col="2">Reported by</span>
        ${node(0, 0, x.name, `${dmarcNum(x.totals.total_messages)} messages · ${dmarcPct(x.totals.dmarc_pass_pct)} pass`, x.totals.dmarc_pass_pct)}
        ${groups.map((g, i) => node(1, i, g.name, `${dmarcNum(g.total)} · ${dmarcPct(g.passPct)} pass`, g.passPct, `loadSourceDetails('${domain}', '${escapeJsArg(g.ips[0].source_ip)}')`)).join('')}
        ${recv.map((r, i) => node(2, i, r.name, `${dmarcNum(r.count)} · ${dmarcPct(r.count ? r.pass / r.count * 100 : 0)} pass`, r.count ? r.pass / r.count * 100 : 0)).join('')}
    </div><div class="ui-dm-legend ui-dm-flow-legend"><span><i class="is-ok"></i>95% or more pass</span><span><i class="is-warn"></i>80% or more</span><span><i class="is-fail"></i>Less</span><span>Line width is the volume</span></div>`;
}

// Lay the flow out for its width: three columns side by side, or down the page on a phone
function drawDmarcFlow() {
    const el = document.getElementById('dmarc-flow');
    if (!el || !el.offsetWidth) return;
    watchDmarcFlowSize();
    const svg = el.querySelector('svg');
    const w = el.clientWidth;
    const G = JSON.parse(el.dataset.g), L = JSON.parse(el.dataset.l);
    const cols = [[], [], []];
    el.querySelectorAll('.ui-dm-node').forEach(nd => { cols[+nd.dataset.col][+nd.dataset.i] = nd; });
    const color = tone => `var(--ui-${tone})`;
    const pos = [[], [], []];
    const narrow = w < 600;
    el.querySelectorAll('.ui-dm-colh').forEach(h => { h.style.display = narrow ? 'none' : ''; });
    if (narrow) {
        let y = 0;
        cols.forEach((list, c) => {
            const cw = (w - (list.length - 1) * 8) / Math.max(1, list.length);
            let rowH = 0;
            list.forEach((nd, i) => {
                Object.assign(nd.style, { width: `${cw}px`, left: `${i * (cw + 8)}px`, top: `${y}px` });
                rowH = Math.max(rowH, nd.offsetHeight);
            });
            list.forEach((nd, i) => { pos[c][i] = { x: i * (cw + 8) + cw / 2, top: y, bottom: y + rowH }; });
            y += rowH + 44;
        });
        el.style.height = `${y - 44}px`;
    } else {
        const nw = Math.min(210, (w - 80) / 3), xs = [0, w / 2 - nw / 2, w - nw], gap = 10;
        const heights = cols.map(list => list.reduce((s, nd) => { nd.style.width = `${nw}px`; return s + nd.offsetHeight + gap; }, -gap));
        const H = Math.max(...heights) + 26;
        cols.forEach((list, c) => {
            let y = 26 + (H - 26 - heights[c]) / 2;
            el.querySelectorAll(`.ui-dm-colh[data-col="${c}"]`).forEach(h => { h.style.left = `${xs[c]}px`; });
            list.forEach((nd, i) => {
                Object.assign(nd.style, { left: `${xs[c]}px`, top: `${y}px` });
                pos[c][i] = { left: xs[c], right: xs[c] + nw, mid: y + nd.offsetHeight / 2 };
                y += nd.offsetHeight + gap;
            });
        });
        el.style.height = `${H}px`;
    }
    const curve = (a, b, width, tone) => {
        const d = narrow ? `M${a.x},${a.bottom} C${a.x},${(a.bottom + b.top) / 2} ${b.x},${(a.bottom + b.top) / 2} ${b.x},${b.top}`
            : `M${a.right},${a.mid} C${(a.right + b.left) / 2},${a.mid} ${(a.right + b.left) / 2},${b.mid} ${b.left},${b.mid}`;
        return `<path d="${d}" stroke="${color(tone)}" stroke-width="${width}" fill="none" stroke-opacity=".45" stroke-linecap="round"/>`;
    };
    svg.innerHTML = G.map(([width, tone], i) => pos[1][i] ? curve(pos[0][0], pos[1][i], width, tone) : '').join('')
        + L.map(([gi, ri, width, tone]) => pos[1][gi] && pos[2][ri] ? curve(pos[1][gi], pos[2][ri], width, tone) : '').join('');
}

// The flow is laid out again when the window changes size
let dmarcFlowResize = null;
let dmarcFlowWatching = false;
function watchDmarcFlowSize() {
    if (dmarcFlowWatching) return;
    dmarcFlowWatching = true;
    window.addEventListener('resize', () => {
        clearTimeout(dmarcFlowResize);
        dmarcFlowResize = setTimeout(drawDmarcFlow, 150);
    });
}

// =============================================================================
// A DOMAIN
// =============================================================================

// The senders of a domain, one per network (ASN); an address without one stands alone
function dmarcGroups(sources) {
    const groups = Object.create(null); // keyed by names from the reports
    sources.forEach(s => {
        const key = s.asn_org || s.source_ip;
        const g = groups[key] || (groups[key] = { key, name: s.asn_org || s.source_ip, ips: [], total: 0, pass: 0, spf: 0, dkim: 0, reporters: Object.create(null) });
        g.ips.push(s);
        g.total += s.total_count || 0; g.pass += s.dmarc_pass || 0; g.spf += s.spf_pass || 0; g.dkim += s.dkim_pass || 0;
        (s.reporters || []).forEach(r => {
            const e = g.reporters[r.org_name] || (g.reporters[r.org_name] = { org_name: r.org_name, count: 0, dmarc_pass: 0 });
            e.count += r.count; e.dmarc_pass += r.dmarc_pass;
        });
    });
    return Object.values(groups).map(g => ({
        ...g, reporters: Object.values(g.reporters),
        passPct: g.total ? g.pass / g.total * 100 : 0, spfPct: g.total ? g.spf / g.total * 100 : 0, dkimPct: g.total ? g.dkim / g.total * 100 : 0,
        place: [g.ips[0].asn, g.ips[0].country_name].filter(Boolean).join(' · ')
    })).sort((a, b) => (a.passPct >= 50) - (b.passPct >= 50) || b.total - a.total);
}

// The open domain's data, read once and kept while it stays open
async function dmarcLoadDomain(domain) {
    if (dmarcState.domain && dmarcState.domain.name === domain) return dmarcState.domain;
    const enc = encodeURIComponent(domain);
    const [overview, sources, tls, insight, days] = await Promise.all([
        dmarcGet(`/api/dmarc/domains/${enc}/overview?days=30`),
        dmarcGet(`/api/dmarc/domains/${enc}/sources?days=30&limit=500`),
        dmarcGet(`/api/dmarc/domains/${enc}/tls-reports/daily?days=30&limit=31`).catch(() => ({ data: [] })),
        dmarcGet(`/api/dmarc/insights?domain=${enc}`).catch(() => null),
        dmarcGet(`/api/dmarc/domains/${enc}/reports?days=30&limit=31`).catch(() => ({ data: [] }))
    ]);
    const groups = dmarcGroups(sources.data || []);
    const sent = groups.reduce((s, g) => s + g.total, 0);
    dmarcState.domain = {
        name: domain, overview, groups, tls: tls || { data: [] }, insight, days: (days || {}).data || [],
        totals: overview.totals || {}, record: overview.dmarc_record || {}, tlsRecord: overview.tls_rpt_record || {},
        spfPct: sent ? groups.reduce((s, g) => s + g.spf, 0) / sent * 100 : 0,
        dkimSeen: groups.some(g => g.dkim > 0)
    };
    return dmarcState.domain;
}

function dmarcDomainTasks(x) {
    const tasks = [];
    const name = escapeJsArg(x.name);
    const policy = x.record.record ? String(x.record.policy || (x.record.settings || {}).policy || '').toLowerCase() : '';
    const volume = x.totals.total_messages || 0;
    if (!x.record.record) tasks.push({ w: 1000, tone: 'fail', title: 'Publish a DMARC record', label: 'Show the record', action: `openDmarcRecord('dmarc', '${name}')`,
        text: `${uiCountLabel(volume, 'message', 'messages')} in 30 days, and receivers have no policy to refuse fakes.` });
    x.groups.filter(g => g.passPct < 50).forEach(g => tasks.push({ w: 600 + g.total, tone: 'fail', title: `${g.name} fails DMARC`, label: 'Look at it',
        action: `loadSourceDetails('${name}', '${escapeJsArg(g.ips[0].source_ip)}')`,
        text: `${uiCountLabel(g.total, 'message', 'messages')}: SPF ${dmarcPct(g.spfPct)}, DKIM ${dmarcPct(g.dkimPct)}. If it is yours, set up SPF or DKIM for it; if not, ${policy === 'reject' ? 'your policy refuses it' : 'a stricter policy stops it'}.` }));
    if (policy === 'none') {
        const advice = ((x.insight || {}).recommendations || [])[0];
        tasks.push({ w: volume >= 100 ? 500 : 50, tone: 'warn', title: 'The policy only monitors (p=none)', label: 'See the policy', action: `openDmarcRecord('dmarc', '${name}')`,
            text: advice ? advice.message : 'Mail that fails is still delivered.' });
    }
    x.groups.filter(g => g.passPct >= 95 && g.spfPct < 50).forEach(g => tasks.push({ w: 200, tone: 'warn', title: `${g.name} passes on DKIM only`, label: 'Look at it',
        action: `loadSourceDetails('${name}', '${escapeJsArg(g.ips[0].source_ip)}')`, text: 'SPF does not include it. Fine for a newsletter service; add it to SPF if it should be there.' }));
    if (!x.tlsRecord.record) tasks.push({ w: 100, tone: 'warn', title: 'Publish a TLS-RPT record', label: 'Show the record', action: `openDmarcRecord('tls', '${name}')`,
        text: 'Receivers then tell you when mail to you could not be encrypted.' });
    return tasks.sort((a, b) => b.w - a.w);
}

function dmarcRecordsCard(x) {
    const name = escapeJsArg(x.name);
    const policy = x.record.record ? String(x.record.policy || (x.record.settings || {}).policy || '').toLowerCase() : '';
    const rows = [
        ['DMARC', x.record.record ? `p=${policy || '?'}` : 'No record at _dmarc', policy === 'reject' ? dmarcTag('ok', 'Enforced') : policy === 'quarantine' ? dmarcTag('warn', 'Partial') : policy ? dmarcTag('warn', 'Monitoring') : dmarcTag('fail', 'Missing', true), 'dmarc'],
        ['SPF', `${Math.round(x.spfPct)}% of mail aligned`, x.spfPct >= 95 ? dmarcTag('ok', 'OK') : dmarcTag('warn', 'Gaps'), 'dmarc'],
        ['DKIM', x.dkimSeen ? 'Your mail is signed' : 'No signed mail in the reports', x.dkimSeen ? dmarcTag('ok', 'OK') : dmarcTag('fail', 'Missing', true), 'dmarc'],
        ['TLS-RPT', x.tlsRecord.record ? 'Receivers report encryption' : 'No record at _smtp._tls', x.tlsRecord.record ? dmarcTag('ok', 'OK') : dmarcTag('warn', 'Missing'), 'tls']];
    return `<div class="ui-dm-card"><header>Records<small>a record opens its details</small></header>${rows.map(([label, sub, tag, kind]) =>
        `<button type="button" class="ui-dm-rec" onclick="openDmarcRecord('${kind}', '${name}')"><span><b>${label}</b><small>${escapeHtml(sub)}</small></span>${tag}<span class="ui-muted" aria-hidden="true">›</span></button>`).join('')}</div>`;
}

function dmarcSendersCard(x) {
    if (!x.groups.length) return '';
    const name = escapeJsArg(x.name);
    return `<div class="ui-dm-card"><header>Senders <span class="ui-count">${x.groups.length}</span><small>who sent mail as ${escapeHtml(x.name)}, failing first</small></header>
        <table class="ui-dm-tbl"><thead><tr><th>Sender</th><th class="r">Messages</th><th class="r">Passed DMARC</th><th class="r ui-dm-hm">SPF aligned</th><th class="r ui-dm-hm">DKIM aligned</th><th class="r ui-dm-hm">Addresses</th></tr></thead><tbody>
        ${x.groups.map(g => `<tr class="is-go" onclick="loadSourceDetails('${name}', '${escapeJsArg(g.ips[0].source_ip)}')"><td><button type="button" class="ui-dm-link">${escapeHtml(g.name)}</button>${g.place ? `<small class="ui-dm-sub">${escapeHtml(g.place)}</small>` : ''}</td>
            <td class="r ui-num">${dmarcNum(g.total)}</td><td class="r ui-text-${dmarcTone(g.passPct)}">${dmarcPct(g.passPct)}</td>
            <td class="r ui-dm-hm ui-text-${dmarcTone(g.spfPct)}">${dmarcPct(g.spfPct)}</td><td class="r ui-dm-hm ui-text-${dmarcTone(g.dkimPct)}">${dmarcPct(g.dkimPct)}</td><td class="r ui-dm-hm">${g.ips.length}</td></tr>`).join('')}</tbody></table></div>`;
}

// One row a day: how much mail, from how many senders, who reported it
function dmarcDaysCard(x) {
    if (!x.days.length) return '';
    const name = escapeJsArg(x.name);
    return `<div class="ui-dm-card"><header>Daily reports <span class="ui-count">${x.days.length}</span></header>
        <table class="ui-dm-tbl"><thead><tr><th>Day</th><th class="r">Messages</th><th class="r ui-dm-hm">Senders</th><th class="ui-dm-hm">Reported by</th><th class="r">Passed DMARC</th></tr></thead><tbody>
        ${x.days.map(r => `<tr class="is-go" onclick="loadReportDetails('${name}', '${escapeJsArg(r.date)}')"><td><button type="button" class="ui-dm-link">${dmarcDay(r.date)}</button></td>
            <td class="r ui-num">${dmarcNum(r.total_messages)}</td><td class="r ui-dm-hm">${dmarcNum(r.unique_ips)}</td><td class="ui-dm-hm ui-muted">${escapeHtml((r.reporters || []).join(', '))}</td>
            <td class="r ui-text-${dmarcTone(r.dmarc_pass_pct)}">${dmarcPct(r.dmarc_pass_pct)}</td></tr>`).join('')}</tbody></table></div>`;
}

// Whether mail to the domain arrived encrypted, from its TLS reports
function dmarcTlsCard(x) {
    const days = (x.tls.data || []).slice().reverse();
    const name = escapeJsArg(x.name);
    if (!days.length) return `<div class="ui-dm-card"><header>Encryption of mail to you (TLS)</header><p class="ui-dm-empty">No TLS reports for ${escapeHtml(x.name)} in the last 30 days.
        <button type="button" class="ui-dm-link" onclick="openDmarcRecord('tls', '${name}')">See the TLS-RPT record</button></p></div>`;
    const totals = x.tls.totals || {};
    const reporters = Object.create(null); // keyed by reporter names from the reports
    days.forEach(d => (d.reports || []).forEach(r => {
        const e = reporters[r.organization_name] || (reporters[r.organization_name] = { name: r.organization_name, ok: 0, fail: 0 });
        e.ok += r.successful_sessions || 0; e.fail += r.failed_sessions || 0;
    }));
    return `<div class="ui-dm-card"><header>Encryption of mail to you (TLS)</header>
        <div class="ui-dm-strip ui-dm-strip-line"><div><small>Sessions</small><b>${dmarcNum((totals.total_successful_sessions || 0) + (totals.total_failed_sessions || 0))}</b></div>
            <div><small>Encrypted</small><b class="ui-text-${dmarcTone(totals.overall_success_rate)}">${dmarcPct(totals.overall_success_rate)}</b></div>
            <div><small>Failed</small><b class="${totals.total_failed_sessions ? 'ui-text-fail' : ''}">${dmarcNum(totals.total_failed_sessions)}</b></div>
            <div><small>Reports</small><b>${dmarcNum(totals.total_reports)}</b></div></div>
        <div class="ui-dm-body">${dmarcChart(days, { tls: true, h: 120 })}</div>
        <table class="ui-dm-tbl"><thead><tr><th>Reported by</th><th class="r">Sessions</th><th class="r">Failed</th><th class="r">Encrypted</th></tr></thead><tbody>
        ${Object.values(reporters).sort((a, b) => (b.ok + b.fail) - (a.ok + a.fail)).map(r => `<tr><td>${escapeHtml(r.name)}</td><td class="r ui-num">${dmarcNum(r.ok + r.fail)}</td>
            <td class="r ${r.fail ? 'ui-text-fail' : ''}">${dmarcNum(r.fail)}</td><td class="r ui-text-${dmarcTone(r.ok + r.fail ? r.ok / (r.ok + r.fail) * 100 : 100)}">${dmarcPct(r.ok + r.fail ? r.ok / (r.ok + r.fail) * 100 : 100)}</td></tr>`).join('')}</tbody></table></div>`;
}

async function loadDomainOverview(domain, updateUrl = true) {
    dmarcState.currentView = 'domain';
    dmarcState.currentDomain = domain;
    if (updateUrl) dmarcPush({ domain });
    setDmarcBreadcrumb('domain', { domain });
    if (!dmarcState.domain || dmarcState.domain.name !== domain) dmarcLoading('Loading the domain...');
    dmarcLoadControls();
    try {
        const x = await dmarcLoadDomain(domain);
        if (dmarcState.currentView !== 'domain' || dmarcState.currentDomain !== domain) return;
        dmarcView().innerHTML = `
            <div class="ui-dm-ttl"><div><small>Last 30 days</small><h2>${escapeHtml(domain)}</h2></div></div>
            <div class="ui-dm-lay"><div>
                <div class="ui-dm-card"><header>Messages per day</header><div class="ui-dm-body">${dmarcChart(x.overview.daily_stats || [])}</div></div>
                ${x.groups.length ? `<div class="ui-dm-card"><header>Mail flow<small>your domain, who sent it, who reported it</small></header><div class="ui-dm-body">${dmarcFlow(x)}</div></div>` : ''}
                ${dmarcSendersCard(x)}
                ${dmarcDaysCard(x)}
                ${dmarcTlsCard(x)}
            </div><aside>${dmarcTodoCard(dmarcDomainTasks(x))}${dmarcRecordsCard(x)}</aside></div>`;
        drawDmarcFlow();
    } catch (error) {
        console.error('Error loading the DMARC domain:', error);
        dmarcFailed(error);
    }
}

// =============================================================================
// THE RECORD WINDOWS
// =============================================================================

async function openDmarcRecord(kind, domain) {
    const modal = document.getElementById('dmarc-record-modal');
    const content = document.getElementById('dmarc-record-content');
    document.getElementById('dmarc-record-title').textContent = `${kind === 'tls' ? 'TLS-RPT' : 'DMARC'} record · ${domain}`;
    content.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading...</p></div>';
    modal.classList.remove('hidden');
    try {
        const x = await dmarcLoadDomain(domain);
        content.innerHTML = kind === 'tls' ? dmarcTlsRecord(x) : dmarcDmarcRecord(x);
    } catch (error) {
        content.innerHTML = `<p class="ui-dm-empty">Could not read the record: ${escapeHtml(error.message)}.</p>`;
    }
}

function closeDmarcRecordModal() {
    document.getElementById('dmarc-record-modal').classList.add('hidden');
}

// Esc closes the record window, like the other dialogs
document.addEventListener('keydown', event => {
    if (event.key !== 'Escape') return;
    const modal = document.getElementById('dmarc-record-modal');
    if (modal && !modal.classList.contains('hidden')) closeDmarcRecordModal();
});

function dmarcCopyBlock(text) {
    return `<div class="ui-dm-code"><span>${escapeHtml(text)}</span><button type="button" class="ui-btn ui-btn-sm" onclick="copyToClipboard('${escapeJsArg(text)}', event)">Copy</button></div>`;
}

function dmarcDmarcRecord(x) {
    const settings = x.record.settings || {};
    const current = x.record.record ? String(x.record.policy || settings.policy || '').toLowerCase() : '';
    const next = current === 'reject' ? null : current === 'quarantine' ? 'reject' : 'quarantine';
    const failing = x.groups.filter(g => g.passPct < 50).reduce((s, g) => s + g.total, 0);
    const ready = x.groups.filter(g => g.passPct >= 50).every(g => g.passPct >= 95);
    const rua = (settings.aggregate_report_uris || [])[0] || `mailto:dmarc@${x.name}`;
    // Report URIs come from DNS: only mailto: becomes a link, anything else stays text
    const formatUriAsEmail = (uri) => {
        const text = String(uri).trim();
        if (!/^mailto:/i.test(text)) return escapeHtml(text);
        return `<a href="${escapeHtml(text)}" class="ui-link">${escapeHtml(text.replace(/^mailto:/i, ''))}</a>`;
    };
    const option = (id, title, text) => `<div class="${current === id ? 'is-on' : ''}"><h4>${title}${current === id ? ` ${dmarcTag('mut', 'Now')}` : ''}</h4><p>${text}</p></div>`;
    return `${x.record.record ? `${dmarcCopyBlock(x.record.record)}
            <dl class="ui-dm-kv"><dt>Policy</dt><dd>${escapeHtml(settings.policy || current || '-')}</dd>
            <dt>Subdomains</dt><dd>${escapeHtml(settings.subdomain_policy || 'same as the domain')}</dd>
            <dt>Applied to</dt><dd>${escapeHtml(settings.percentage ?? 100)}% of mail</dd>
            <dt>Reports go to</dt><dd>${(settings.aggregate_report_uris || []).map(formatUriAsEmail).join(', ') || '-'}</dd>
            ${settings.forensic_report_uris && settings.forensic_report_uris.length ? `<dt>Failure reports go to</dt><dd>${settings.forensic_report_uris.map(formatUriAsEmail).join(', ')}</dd>` : ''}
            <dt>Alignment</dt><dd>SPF ${escapeHtml(settings.spf_alignment || 'relaxed')}, DKIM ${escapeHtml(settings.dkim_alignment || 'relaxed')}</dd></dl>
            ${(x.record.warnings || []).map(w => `<p class="ui-text-warn ui-dm-note">${escapeHtml(w)}</p>`).join('')}`
        : `<p class="ui-dm-lead"><b class="ui-text-fail">No DMARC record at _dmarc.${escapeHtml(x.name)}.</b> Receivers have no policy to refuse mail that pretends to be you.</p>`}
        <dl class="ui-dm-kv"><dt>SPF</dt><dd>${Math.round(x.spfPct)}% of your mail is aligned with SPF</dd><dt>DKIM</dt><dd>${x.dkimSeen ? 'Your mail is signed' : 'No signed mail in the reports'}</dd></dl>
        <h4 class="ui-dm-h4">Policy</h4>
        <div class="ui-dm-pol">${option('none', 'None', 'Mail that fails is still delivered. Reports only.')}${option('quarantine', 'Quarantine', 'Mail that fails goes to spam.')}${option('reject', 'Reject', 'Mail that fails is refused.')}</div>
        ${next ? `<p class="ui-dm-note">${ready ? '<b class="ui-text-ok">Ready.</b> Every sender that passes, passes on 95% or more.' : '<b class="ui-text-warn">Not yet.</b> A sender passes on under 95%: fix it first.'}
            With p=${next}, receivers would have ${next === 'reject' ? 'refused' : 'sent to spam'} <b>${dmarcNum(failing)}</b> messages in the last 30 days, all from senders that fail.</p>
            ${dmarcCopyBlock(`_dmarc.${x.name}  TXT  "v=DMARC1; p=${next}; rua=${rua}"`)}` : '<p class="ui-dm-note ui-text-ok">The strictest policy is in place.</p>'}`;
}

function dmarcTlsRecord(x) {
    const tls = x.tlsRecord || {};
    const user = (dmarcImapStatus && (dmarcImapStatus.configuration || {}).user) || '';
    if (tls.record) return `${dmarcCopyBlock(tls.record)}<dl class="ui-dm-kv"><dt>Reports go to</dt><dd>${escapeHtml((tls.report_uris || []).join(', ') || '-')}</dd></dl>
        ${(tls.warnings || []).map(w => `<p class="ui-text-warn ui-dm-note">${escapeHtml(w)}</p>`).join('')}`;
    return `<p class="ui-dm-lead"><b class="ui-text-warn">No TLS-RPT record.</b> Sending servers report failed encrypted deliveries only to domains that publish one. Publish:</p>
        ${dmarcCopyBlock(`_smtp._tls.${x.name}  TXT  "v=TLSRPTv1; rua=mailto:${user || `tls-reports@${x.name}`}"`)}
        ${user ? `<p class="ui-dm-note">The address is the mailbox this page reads, so the reports show up here.</p>` : '<p class="ui-dm-note">Send the reports to the mailbox this page reads, so they show up here.</p>'}`;
}

// =============================================================================
// A SENDER, A DAY OF REPORTS, A DAY OF TLS
// =============================================================================

async function loadSourceDetails(domain, sourceIp, updateUrl = true) {
    dmarcState.currentView = 'source';
    dmarcState.currentDomain = domain;
    if (updateUrl) dmarcPush({ domain, type: 'source', id: sourceIp });
    setDmarcBreadcrumb('sourceDetails', { domain, ip: sourceIp });
    dmarcLoading('Loading the sender...');
    dmarcLoadControls();
    try {
        const x = await dmarcLoadDomain(domain);
        const g = x.groups.find(gr => gr.ips.some(ip => ip.source_ip === sourceIp));
        const ips = g ? g.ips : [{ source_ip: sourceIp }];
        const details = await Promise.all(ips.map(ip => dmarcGet(`/api/dmarc/domains/${encodeURIComponent(domain)}/sources/${encodeURIComponent(ip.source_ip)}/details?days=30`).catch(() => null)));
        if (dmarcState.currentView !== 'source' || dmarcState.currentDomain !== domain) return;
        const first = details.find(Boolean) || {};
        const name = g ? g.name : (first.asn_org || sourceIp);
        setDmarcBreadcrumb('sourceDetails', { domain, ip: sourceIp, name });
        const sum = g || { total: (first.totals || {}).total_messages || 0, passPct: (first.totals || {}).dmarc_pass_pct || 0, spfPct: (first.totals || {}).spf_pass_pct || 0, dkimPct: (first.totals || {}).dkim_pass_pct || 0, pass: (first.totals || {}).dmarc_pass || 0, ips };
        const policy = x.record.record ? String(x.record.policy || (x.record.settings || {}).policy || '').toLowerCase() : '';
        const rows = details.flatMap((d, i) => ((d || {}).envelope_from_groups || []).map(e => ({ ...e, ip: ips[i].source_ip })));
        const place = [first.city, first.country_name].filter(Boolean).join(', ');
        dmarcView().innerHTML = `
            <div class="ui-dm-ttl"><div><small>Sender</small><h2>${escapeHtml(name)}</h2><p class="ui-muted">${escapeHtml([place, first.asn].filter(Boolean).join(' · ') || 'No location or network known')}</p></div>
                <div>${sum.passPct < 50 ? dmarcTag('fail', 'Fails DMARC', true) : sum.spfPct < 50 ? dmarcTag('warn', 'Passes on DKIM only') : dmarcTag('ok', 'Passes')}</div></div>
            ${sum.passPct < 50 ? `<div class="ui-dm-card ui-dm-alert"><div class="ui-dm-body"><b class="ui-text-fail">Not set up to send as ${escapeHtml(domain)}.</b>
                <p>Receivers ${policy === 'reject' ? 'refused' : policy === 'quarantine' ? 'sent to spam' : 'still delivered'} these ${uiCountLabel(sum.total, 'message', 'messages')}${x.record.record ? '' : ', because there is no DMARC record'}.
                If you know this sender (a CRM, a newsletter tool, a scanner), set up SPF or DKIM for it. If you do not, someone is sending as you: ${policy === 'reject' ? 'your policy already stops it.' : x.record.record ? 'a stricter policy stops it.' : 'a DMARC record lets receivers refuse it.'}</p></div></div>` : ''}
            <div class="ui-dm-card"><header>Last 30 days</header><div class="ui-dm-strip">
                <div><small>Messages</small><b class="is-big">${dmarcNum(sum.total)}</b></div>
                <div><small>Passed DMARC</small><b class="is-big ui-text-${dmarcTone(sum.passPct)}">${dmarcPct(sum.passPct)}</b></div>
                <div><small>SPF aligned</small><b class="is-big ui-text-${dmarcTone(sum.spfPct)}">${dmarcPct(sum.spfPct)}</b></div>
                <div><small>DKIM aligned</small><b class="is-big ui-text-${dmarcTone(sum.dkimPct)}">${dmarcPct(sum.dkimPct)}</b></div>
                <div><small>Addresses</small><b class="is-big">${ips.length}</b></div></div></div>
            <div class="ui-dm-card"><header>What receivers saw <span class="ui-count">${rows.length}</span></header>
            ${rows.length ? `<table class="ui-dm-tbl"><thead><tr><th>Address</th><th>From</th><th class="ui-dm-hm">Envelope from</th><th class="r">Messages</th><th>SPF</th><th>DKIM</th><th class="ui-dm-hm">Reported by</th></tr></thead><tbody>
            ${rows.map(e => `<tr><td class="ui-mono">${escapeHtml(e.ip)}</td><td>${escapeHtml(e.header_from || '-')}</td><td class="ui-dm-hm">${escapeHtml(e.envelope_from || '-')}</td><td class="r ui-num">${dmarcNum(e.volume)}</td>
                <td>${e.spf_aligned ? dmarcTag('ok', 'Aligned') : dmarcTag('fail', e.spf_result || 'Fail')}</td><td>${e.dkim_aligned ? dmarcTag('ok', 'Aligned') : dmarcTag('fail', e.dkim_result || 'Fail')}</td>
                <td class="ui-dm-hm ui-muted">${escapeHtml(e.reporter || '-')}</td></tr>`).join('')}</tbody></table>` : '<p class="ui-dm-empty">No details for this sender.</p>'}</div>`;
    } catch (error) {
        console.error('Error loading the DMARC sender:', error);
        dmarcFailed(error);
    }
}

async function loadReportDetails(domain, reportDate, updateUrl = true) {
    dmarcState.currentView = 'report';
    dmarcState.currentDomain = domain;
    if (updateUrl) dmarcPush({ domain, type: 'report', id: reportDate });
    setDmarcBreadcrumb('reportDetails', { domain, date: reportDate });
    dmarcLoading('Loading the reports...');
    dmarcLoadControls();
    try {
        const [r, x] = await Promise.all([dmarcGet(`/api/dmarc/domains/${encodeURIComponent(domain)}/reports/${encodeURIComponent(reportDate)}/details`), dmarcLoadDomain(domain)]);
        if (dmarcState.currentView !== 'report' || dmarcState.currentDomain !== domain) return;
        const t = r.totals || {};
        const name = escapeJsArg(domain);
        const sender = s => s.asn_org || s.source_ip;
        dmarcView().innerHTML = `
            <div class="ui-dm-ttl"><div><small>DMARC reports</small><h2>${dmarcDay(reportDate, true)}</h2><p class="ui-muted">${escapeHtml(domain)}</p></div></div>
            <div class="ui-dm-card"><header>That day</header><div class="ui-dm-strip">
                <div><small>Messages</small><b class="is-big">${dmarcNum(t.total_messages)}</b></div>
                <div><small>Passed DMARC</small><b class="is-big ui-text-${dmarcTone(t.dmarc_pass_pct)}">${dmarcPct(t.dmarc_pass_pct)}</b></div>
                <div><small>SPF aligned</small><b class="is-big ui-text-${dmarcTone(t.spf_pass_pct)}">${dmarcPct(t.spf_pass_pct)}</b></div>
                <div><small>DKIM aligned</small><b class="is-big ui-text-${dmarcTone(t.dkim_pass_pct)}">${dmarcPct(t.dkim_pass_pct)}</b></div>
                <div><small>Reported by</small><b>${escapeHtml((t.reporters || []).join(', ') || '-')}</b></div></div></div>
            <div class="ui-dm-card"><header>Who sent that day <span class="ui-count">${(r.sources || []).length}</span></header>
            <table class="ui-dm-tbl"><thead><tr><th>Sender</th><th class="ui-dm-hm">Address</th><th class="ui-dm-hm">Envelope from</th><th class="r">Messages</th><th class="r">Passed DMARC</th><th class="r ui-dm-hm">SPF</th><th class="r ui-dm-hm">DKIM</th><th class="ui-dm-hm">Reported by</th></tr></thead><tbody>
            ${(r.sources || []).map(s => `<tr class="is-go" onclick="loadSourceDetails('${name}', '${escapeJsArg(s.source_ip)}')"><td><button type="button" class="ui-dm-link">${escapeHtml(sender(s))}</button></td>
                <td class="ui-dm-hm ui-mono">${escapeHtml(s.source_ip)}</td><td class="ui-dm-hm">${escapeHtml(s.envelope_from || '-')}</td><td class="r ui-num">${dmarcNum(s.volume)}</td>
                <td class="r ui-text-${dmarcTone(s.dmarc_pass_pct)}">${dmarcPct(s.dmarc_pass_pct)}</td><td class="r ui-dm-hm ui-text-${dmarcTone(s.spf_pass_pct)}">${dmarcPct(s.spf_pass_pct)}</td>
                <td class="r ui-dm-hm ui-text-${dmarcTone(s.dkim_pass_pct)}">${dmarcPct(s.dkim_pass_pct)}</td><td class="ui-dm-hm ui-muted">${escapeHtml(s.reporter || '-')}</td></tr>`).join('')}</tbody></table></div>
            <div class="ui-dm-card"><header>Other days</header><div class="ui-dm-body">${dmarcChart(x.overview.daily_stats || [], { h: 90 })}</div></div>`;
    } catch (error) {
        console.error('Error loading the DMARC day:', error);
        dmarcFailed(error);
    }
}

async function loadTLSReportDetails(domain, reportDate, updateUrl = true) {
    dmarcState.currentView = 'tls';
    dmarcState.currentDomain = domain;
    if (updateUrl) dmarcPush({ tab: 'tls', domain, id: reportDate });
    setDmarcBreadcrumb('tlsDetails', { domain, date: reportDate });
    dmarcLoading('Loading the TLS reports...');
    dmarcLoadControls();
    try {
        const r = await dmarcGet(`/api/dmarc/domains/${encodeURIComponent(domain)}/tls-reports/${encodeURIComponent(reportDate)}/details`);
        if (dmarcState.currentView !== 'tls' || dmarcState.currentDomain !== domain) return;
        const s = r.stats || {};
        dmarcView().innerHTML = `
            <div class="ui-dm-ttl"><div><small>TLS reports</small><h2>${dmarcDay(reportDate, true)}</h2><p class="ui-muted">${escapeHtml(domain)}</p></div></div>
            <div class="ui-dm-card"><header>That day</header><div class="ui-dm-strip">
                <div><small>Sessions</small><b class="is-big">${dmarcNum(s.total_sessions)}</b></div>
                <div><small>Encrypted</small><b class="is-big ui-text-${dmarcTone(s.success_rate)}">${dmarcPct(s.success_rate)}</b></div>
                <div><small>Failed</small><b class="is-big ${s.total_fail ? 'ui-text-fail' : ''}">${dmarcNum(s.total_fail)}</b></div>
                <div><small>Receivers reporting</small><b class="is-big">${dmarcNum(s.total_providers)}</b></div></div></div>
            <div class="ui-dm-card"><header>Who reported <span class="ui-count">${(r.providers || []).length}</span></header>
            <table class="ui-dm-tbl"><thead><tr><th>Reported by</th><th class="ui-dm-hm">Policy</th><th class="ui-dm-hm">MX</th><th class="r">Sessions</th><th class="r">Failed</th><th class="r">Encrypted</th></tr></thead><tbody>
            ${(r.providers || []).map(p => `<tr><td><b>${escapeHtml(p.organization_name)}</b>${p.contact_info ? `<small class="ui-dm-sub">${escapeHtml(p.contact_info)}</small>` : ''}</td>
                <td class="ui-dm-hm">${(p.policies || []).map(q => dmarcTag('mut', String(q.policy_type || '').toUpperCase())).join(' ')}</td>
                <td class="ui-dm-hm ui-mono">${escapeHtml((p.policies || []).flatMap(q => q.mx_host || []).join(', '))}</td><td class="r ui-num">${dmarcNum(p.total_sessions)}</td>
                <td class="r ${p.failed_sessions ? 'ui-text-fail' : ''}">${dmarcNum(p.failed_sessions)}</td><td class="r ui-text-${dmarcTone(p.success_rate)}">${dmarcPct(p.success_rate)}</td></tr>
                ${(p.policies || []).flatMap(q => q.failure_details || []).map(f => `<tr><td colspan="6" class="ui-text-fail ui-dm-note">${escapeHtml(f.result_type || 'Failure')}: ${dmarcNum(f.failed_session_count)} sessions${f.receiving_mx_hostname ? ` to ${escapeHtml(f.receiving_mx_hostname)}` : ''}</td></tr>`).join('')}`).join('')}</tbody></table></div>`;
    } catch (error) {
        console.error('Error loading the TLS day:', error);
        dmarcFailed(error);
    }
}

// Manage Reports shows how many there are, and hides with none
function dmarcUpdateManageButton(domains) {
    const manageBtn = document.getElementById('dmarc-manage-btn');
    if (!manageBtn) return;
    const totalReports = domains.reduce((sum, d) => sum + (d.report_count || 0) + (d.tls_report_count || 0), 0);
    manageBtn.textContent = `Manage Reports (${totalReports})`;
    manageBtn.classList.toggle('hidden', totalReports === 0);
}

// =============================================================================
// UPLOAD
// =============================================================================

async function uploadDmarcReport(event) {
    const file = event.target.files[0];
    if (!file) return;

    try {
        const formData = new FormData();
        formData.append('file', file);

        const response = await authenticatedFetch('/api/dmarc/upload', {
            method: 'POST',
            body: formData
        });

        if (response.status === 403) {
            showToast('Manual upload is disabled', 'error');
            event.target.value = '';
            return;
        }

        if (!response.ok) throw new Error('Upload failed');

        const result = await response.json();
        const reportType = result.report_type === 'tls-rpt' ? 'TLS-RPT' : 'DMARC';

        if (result.status === 'success') {
            const count = result.records_count || result.policies_count || 0;
            const countLabel = result.report_type === 'tls-rpt' ? 'policies' : 'records';
            showToast(`${reportType} report uploaded: ${count} ${countLabel}`, 'success');

            // Reload what the page shows, on either tab
            handleDmarcRoute(parseRoute().params);
        } else if (result.status === 'duplicate') {
            showToast(`${reportType} report already exists`, 'warning');
        }

    } catch (error) {
        console.error('Upload error:', error);
        showToast('Failed to upload report', 'error');
    }

    event.target.value = '';
}

// =============================================================================
// IMAP
// =============================================================================

async function loadDmarcImapStatus() {
    try {
        const response = await authenticatedFetch('/api/dmarc/imap/status');
        if (!response.ok) {
            dmarcImapStatus = null;
            return;
        }

        dmarcImapStatus = await response.json();
        updateDmarcControls();

    } catch (error) {
        console.error('Error loading DMARC IMAP status:', error);
        dmarcImapStatus = null;
    }
}

function updateDmarcControls() {
    const uploadBtn = document.getElementById('dmarc-upload-btn');
    const syncContainer = document.getElementById('dmarc-sync-container');
    const lastSyncInfo = document.getElementById('dmarc-last-sync-info');

    // Upload Report: shown once the settings are known; off in Settings means a disabled button that says so
    if (uploadBtn) {
        const known = !!dmarcConfiguration;
        const allowed = dmarcConfiguration?.manual_upload_enabled === true;
        uploadBtn.classList.toggle('hidden', !known);
        uploadBtn.setAttribute('aria-disabled', allowed ? 'false' : 'true');
        uploadBtn.title = allowed ? '' : 'Manual upload is turned off in Settings, DMARC';
        const input = document.getElementById('dmarc-file-input');
        if (input) input.disabled = !allowed;
    }

    // Sync from IMAP: without IMAP set up the button stays, disabled, and the line under it says why
    const syncBtn = document.getElementById('dmarc-sync-btn');
    if (dmarcImapStatus && !dmarcImapStatus.enabled) {
        syncContainer.classList.remove('hidden');
        if (syncBtn) {
            syncBtn.disabled = true;
            syncBtn.title = 'IMAP sync is not set up';
        }
        lastSyncInfo.innerHTML = `<span class="ui-muted">Not set up</span>
            <button type="button" onclick="navigateTo('settings', { sub: 'dmarc_imap' })" class="ui-link-row ui-link">Set up IMAP</button>`;
    } else if (dmarcImapStatus && dmarcImapStatus.enabled) {
        syncContainer.classList.remove('hidden');
        if (syncBtn && syncBtn.title === 'IMAP sync is not set up') {
            syncBtn.disabled = false;
            syncBtn.title = '';
        }

        if (dmarcImapStatus.latest_sync) {
            const sync = dmarcImapStatus.latest_sync;
            const tone = sync.status === 'error' ? 'ui-text-fail' : sync.status === 'running' ? 'ui-text-info' : 'ui-text-ok';
            const state = sync.status === 'error' ? 'failed' : sync.status === 'running' ? 'running' : 'done';
            lastSyncInfo.innerHTML = `
                <span class="${tone}" title="${escapeHtml(formatTime(sync.started_at))}">Last sync ${state}: ${formatAgo(sync.started_at)}</span>
                <button type="button" onclick="showDmarcSyncHistory()" class="ui-link-row ui-link">View History</button>
            `;
        } else {
            lastSyncInfo.innerHTML = '<span class="ui-muted">Never synced</span>';
        }
    } else {
        syncContainer.classList.add('hidden');
    }
}

async function triggerDmarcSync() {
    const btn = document.getElementById('dmarc-sync-btn');
    const btnText = document.getElementById('dmarc-sync-btn-text');

    if (!dmarcImapStatus || !dmarcImapStatus.enabled) {
        showToast('IMAP sync is not enabled', 'error');
        return;
    }

    btn.disabled = true;
    btnText.textContent = 'Syncing...';

    try {
        const response = await authenticatedFetch('/api/dmarc/imap/sync', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'already_running') {
            showToast('Sync is already in progress', 'info');
        } else if (result.status === 'started') {
            showToast('IMAP sync started', 'success');

            // Immediate UI update to show "Running" state
            await loadDmarcImapStatus();

            // Delayed update to catch the final result (success/fail)
            setTimeout(async () => {
                await loadDmarcImapStatus();
                await loadDmarcDomains();
            }, 5000); // Increased to 5s to give the sync time to work
        }

    } catch (error) {
        console.error('Error triggering sync:', error);
        showToast('Failed to start sync', 'error');
    } finally {
        btn.disabled = false;
        btnText.textContent = 'Sync from IMAP';
    }
}


async function showDmarcSyncHistory() {
    const modal = document.getElementById('dmarc-sync-history-modal');
    const content = document.getElementById('dmarc-sync-history-content');

    modal.classList.remove('hidden');

    const closeOnBackdrop = (e) => {
        if (e.target === modal) {
            closeDmarcSyncHistoryModal();
            modal.removeEventListener('click', closeOnBackdrop);
        }
    };
    modal.addEventListener('click', closeOnBackdrop);

    try {
        const response = await authenticatedFetch('/api/dmarc/imap/history?limit=20');
        const data = await response.json();

        if (data.data.length === 0) {
            content.innerHTML = '<p class="ui-empty">No sync history yet</p>';
            return;
        }

        const STATUS_TONE = { success: 'ok', error: 'fail', running: 'info' };
        content.innerHTML = `
            <div class="ui-table ui-stack" style="--ui-cols: minmax(150px, 1.4fr) 80px 90px 70px 70px 80px 70px 80px; --ui-table-min: 760px">
                <div class="ui-tr ui-tr-head"><span>Date</span><span>Type</span><span>Status</span><span class="ui-td-end">Emails</span><span class="ui-td-end">Created</span><span class="ui-td-end">Duplicate</span><span class="ui-td-end">Failed</span><span>Duration</span></div>
                ${data.data.map(sync => `
                <div class="ui-tr">
                    <span class="ui-td">${formatDate(sync.started_at)}</span>
                    <span class="ui-td">${uiTag(sync.sync_type, sync.sync_type === 'manual' ? 'info' : '')}</span>
                    <span class="ui-td">${uiTag(sync.status, STATUS_TONE[sync.status] || '')}</span>
                    <span class="ui-td ui-td-end"><small class="ui-sec-unit">Emails </small>${escapeHtml(String(sync.emails_found || 0))}</span>
                    <span class="ui-td ui-td-end ui-text-ok"><small class="ui-sec-unit">Created </small>${escapeHtml(String(sync.reports_created || 0))}</span>
                    <span class="ui-td ui-td-end ui-muted"><small class="ui-sec-unit">Duplicate </small>${escapeHtml(String(sync.reports_duplicate || 0))}</span>
                    <span class="ui-td ui-td-end${sync.reports_failed > 0 ? ' ui-text-fail' : ''}"><small class="ui-sec-unit">Failed </small>${escapeHtml(String(sync.reports_failed || 0))}</span>
                    <span class="ui-td">${sync.duration_seconds ? `${Math.round(sync.duration_seconds)}s` : '-'}</span>
                </div>`).join('')}
            </div>
        `;

    } catch (error) {
        console.error('Error loading sync history:', error);
        content.innerHTML = '<p class="ui-empty ui-text-fail">Failed to load sync history</p>';
    }
}

function closeDmarcSyncHistoryModal() {
    document.getElementById('dmarc-sync-history-modal').classList.add('hidden');
}

// =============================================================================
// REPORTS MANAGEMENT
// =============================================================================
// This part runs in the pagination test with only document, authenticatedFetch,
// escapeHtml, escapeJsArg, console, showToast, showConfirmModal and dmarcState.

const reportsManagementState = { page: 1, limit: 50, request: 0 };

async function showReportsManagementModal() {
    const modal = document.getElementById('dmarc-reports-management-modal');
    modal.classList.remove('hidden');
    modal.onclick = (event) => {
        if (event.target === modal) closeReportsManagementModal();
    };
    await loadReportsManagementPage(1);
}

async function loadReportsManagementPage(page) {
    if (!Number.isInteger(page) || page < 1) return;
    const request = ++reportsManagementState.request;
    const content = document.getElementById('dmarc-reports-management-content');

    // Show loading
    content.innerHTML = '<div class="ui-loading"><div class="loading"></div><p>Loading reports...</p></div>';

    try {
        const response = await authenticatedFetch(`/api/dmarc/reports/all?page=${page}&limit=${reportsManagementState.limit}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        if (request !== reportsManagementState.request) return;
        reportsManagementState.page = data.page;
        renderReportsManagementTable(data.reports || [], data.allow_delete, data);

    } catch (error) {
        if (request !== reportsManagementState.request) return;
        console.error('Error loading reports:', error);
        content.innerHTML = `<div class="ui-empty"><p class="ui-text-fail">Failed to load reports. Please try again.</p>
            <button onclick="loadReportsManagementPage(${page})" class="ui-btn ui-btn-sm">Retry</button></div>`;
    }
}

function closeReportsManagementModal() {
    reportsManagementState.request++;
    document.getElementById('dmarc-reports-management-modal').classList.add('hidden');
}

function renderReportsManagementTable(reports, allowDelete, { total, page, total_pages: totalPages }) {
    const content = document.getElementById('dmarc-reports-management-content');

    if (reports.length === 0) {
        content.innerHTML = '<p class="ui-empty">No reports found</p>';
        return;
    }

    const pageButton = (label, target, disabled) => `<button onclick="loadReportsManagementPage(${Number(target)})" ${disabled ? 'disabled' : ''} class="ui-btn ui-btn-sm">${label}</button>`;
    const pagination = totalPages > 1 ? `<nav aria-label="Report pages" class="ui-pager">
        ${pageButton('First', 1, page === 1)}
        ${pageButton('Previous', page - 1, page === 1)}
        <span class="ui-muted">Page ${Number(page)} of ${Number(totalPages)}</span>
        ${pageButton('Next', page + 1, page === totalPages)}
        ${pageButton('Last', totalPages, page === totalPages)}
    </nav>` : '';
    const dateTime = value => value ? new Date(value).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' }) : '-';
    const day = ts => ts ? new Date(ts * 1000).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }) : '-';
    const cols = allowDelete
        ? '--ui-cols: minmax(150px, 1.2fr) 70px minmax(140px, 1.2fr) minmax(120px, 1fr) 70px minmax(110px, .9fr) 80px'
        : '--ui-cols: minmax(150px, 1.2fr) 70px minmax(140px, 1.2fr) minmax(120px, 1fr) 70px minmax(110px, .9fr)';

    content.innerHTML = `
        <p class="ui-muted ui-mgmt-total">
            Total: <span class="ui-strong">${escapeHtml(String(total))}</span> reports
        </p>
        ${allowDelete ? '' : `<div class="ui-list-note">${uiLocked('Deleting reports is off', 'Turn on report deletion in Settings, DMARC.',
            `<button type="button" class="ui-btn ui-btn-sm" onclick="closeReportsManagementModal(); navigateTo('settings', { sub: 'dmarc' })">Open Settings</button>`)}</div>`}
        <div data-nosort class="ui-table ui-stack" style="${cols}; --ui-table-min: 780px">
            <div class="ui-tr ui-tr-head"><span>Import Date</span><span>Type</span><span>Domain</span><span>Reporter</span><span class="ui-td-end">Records</span><span>Period</span>${allowDelete ? '<span class="ui-td-end">Actions</span>' : ''}</div>
            ${reports.map(report => `
            <div class="ui-tr">
                <span class="ui-td">${dateTime(report.created_at)}</span>
                <span class="ui-td"><span class="ui-tag${report.type === 'dmarc' ? ' ui-tag-info' : ' ui-tag-ok'}">${escapeHtml(String(report.type).toUpperCase())}</span></span>
                <b class="ui-td">${escapeHtml(report.domain)}</b>
                <span class="ui-td">${escapeHtml(report.org_name || '-')}</span>
                <span class="ui-td ui-td-end"><small class="ui-sec-unit">Records </small>${escapeHtml(String(report.record_count))}</span>
                <span class="ui-td">${day(report.begin_date)} - ${day(report.end_date)}</span>
                ${allowDelete ? `<span class="ui-td ui-td-end ui-row-actions"><button onclick="deleteReport('${escapeJsArg(report.type)}', ${Number(report.id)}, '${escapeJsArg(report.domain)}')" class="ui-btn ui-btn-sm ui-btn-danger" title="Delete report">Delete</button></span>` : ''}
            </div>`).join('')}
        </div>
        ${pagination}
    `;
}

async function deleteReport(reportType, reportId, domain) {
    if (!await showConfirmModal({ title: 'Delete Report', message: `Are you sure you want to delete this ${reportType.toUpperCase()} report for ${domain}?\n\nThis action cannot be undone.`, confirmText: 'Delete', isDangerous: true })) {
        return;
    }

    try {
        const response = await authenticatedFetch(`/api/dmarc/reports/${reportType}/${reportId}`, {
            method: 'DELETE'
        });

        if (response.status === 403) {
            showToast('Report deletion is disabled', 'error');
            return;
        }

        if (!response.ok) {
            throw new Error('Failed to delete report');
        }

        showToast(`${reportType.toUpperCase()} report deleted`, 'success');

        // Refresh the modal
        if (!document.getElementById('dmarc-reports-management-modal').classList.contains('hidden')) {
            await loadReportsManagementPage(reportsManagementState.page);
        }

        // Refresh domains list if visible
        if (dmarcState.currentView === 'domains') {
            await loadDmarcDomains();
        }

    } catch (error) {
        console.error('Error deleting report:', error);
        showToast('Failed to delete report', 'error');
    }
}
