// Entity card: what the app stores about one IP address, email address (or
// mailbox) or domain, opened from any value that shows one (uiEntity in utils.js).
// Loaded after message-details.js; uses authenticatedFetch, renderMessageRow
// (app.js), renderDeviceRow (devices.js) and the utils.js helpers.
//
// The card is #entity-card in index.html: the frame of the message details dialog
// (a header, pinned tabs and the open tab in one scroll), with its own ids and
// state. It reads GET /api/entities/{ip,address,domain}?value= once per opening;
// each source in the answer is ok, disabled (its feature is off) or error, and a
// source that is not ok is shown as such, never as zero.
//
// Layers: like the message dialog, a card opens over every dialog already open
// (it goes last on the page), so a card opened from a message comes over it and a
// message opened from the card comes over the card. A value inside the card opens
// its own card in the same dialog (it replaces the one shown). Escape and Back
// close the top layer (router.js).

const ENTITY_DAYS_NEW = 7;     // a device is New for this many days, as on the Devices page default
const ENTITY_DAYS_STALE = 30;
const ENTITY_RECENT = 5;       // rows in the Overview's Recent list

let entityCardSeq = 0;         // each opening; a late answer to an older one is dropped
let entityCardState = null;    // { kind, value, data, tab, filter }

// Names of a card's sources as a person reads them
const ENTITY_SOURCE_NAMES = { messages: 'Messages', security: 'Security events', protection: 'Protection catches', devices: 'Devices' };
const ENTITY_TIMELINE_GROUPS = [
    ['all', 'All'], ['message', 'Messages'], ['security', 'Security events'], ['protection', 'Protection'], ['device', 'Devices'],
];
const ENTITY_TIMELINE_GROUP = {
    message: 'message', security: 'security', ban: 'security', unban: 'security', protection: 'protection',
    device_first_seen: 'device', device_last_seen: 'device',
};

// =============================================================================
// OPEN AND CLOSE
// =============================================================================

function openEntityCard(kind, value, { from = null } = {}) {
    if (!UI_ENTITY_KINDS.includes(kind) || !value) return;
    const card = document.getElementById('entity-card');
    if (!card) return;
    entityRblStop();
    const seq = ++entityCardSeq;
    const wasOpen = !card.classList.contains('hidden');
    // The focus goes back to what opened the card when it closes, also when it was
    // opened from code (no click or key the layers saw first)
    if (!wasOpen && from && typeof uiLayerOpener === 'function') uiLayerOpener(from);
    entityCardPlace(card, from, wasOpen);
    entityCardState = { kind, value: String(value), data: null, tab: 'overview', filter: 'all' };

    card.classList.remove('hidden');
    const body = document.getElementById('entity-card-body');
    if (body) body.scrollTop = 0;
    entityCardTitle(kind, null);
    entityCardHeader(null);
    const tabs = document.getElementById('entity-card-tabs');
    if (tabs) tabs.innerHTML = '';
    const content = document.getElementById('entity-card-content');
    if (content) content.innerHTML = '<div class="ui-loading" role="status"><div class="loading"></div><p>Loading...</p></div>';
    // Opened again while open: the focus goes into the card, not to the value it came from
    if (wasOpen && typeof layerFocusIn === 'function') requestAnimationFrame(() => { if (seq === entityCardSeq) layerFocusIn(card); });
    entityCardLoad(seq, kind, String(value));
}

// Over every dialog already open: the last open layer on the page is on top
// (router.js openOverlays). The card on top already stays where it is, so the
// focus in it is not lost
function entityCardPlace(card, from, wasOpen) {
    const open = typeof openOverlays === 'function' ? openOverlays() : [];
    const onTop = wasOpen && open[open.length - 1] === card;
    if (!onTop) document.body.appendChild(card);
    // A card opened from a sheet replaces the sheet: a sheet lies above every dialog
    const sheet = from && from.closest ? from.closest('.ui-sheet') : null;
    if (sheet && sheet.id && typeof uiSheetDismiss === 'function') uiSheetDismiss(sheet.id);
    // Brought over a dialog it was under: closing it goes back to the value it came from
    if (wasOpen && from && !card.contains(from) && !sheet && typeof uiLayerReturn === 'function') uiLayerReturn(card, from);
}

function closeEntityCard() {
    const card = document.getElementById('entity-card');
    if (!card) return;
    entityCardSeq++;
    entityCardState = null;
    entityRblStop();
    card.classList.add('hidden');
    const header = document.getElementById('entity-card-header');
    if (header) header.innerHTML = '';
    const tabs = document.getElementById('entity-card-tabs');
    if (tabs) tabs.innerHTML = '';
    const content = document.getElementById('entity-card-content');
    if (content) content.innerHTML = '';
}

// To Settings from a source that is off. A page with changes not saved asks first
// (router.js); once the move is made, the card closes, and so do the dialogs under
// it that only show something (a message, another detail view), which would
// otherwise cover Settings. A dialog with fields of its own stays: it asks itself
// before anything in it is dropped
async function entityCardSettings() {
    const moved = await navigateTo('settings');
    if (!moved) return;
    closeEntityCard();
    entityCardCloseViews();
}

function entityCardCloseViews() {
    if (typeof openOverlays !== 'function') return;
    const views = openOverlays().filter(el => el.matches('.ui-dialog-backdrop') && el.id !== 'entity-card'
        && !el.querySelector('form, textarea, select, input:not([type="search"]):not([type="hidden"])'));
    // Top first, each through its own X
    views.reverse().forEach(el => {
        const close = el.querySelector('.ui-dialog-head [aria-label="Close"]');
        if (close) close.click();
    });
}

// keep: the card read again after an action (entityCardRefresh): the open tab,
// the timeline filter, the scroll and the focus stay, and a failed read keeps
// what is shown
async function entityCardLoad(seq, kind, value, { keep = false } = {}) {
    let data = null;
    let problem = '';
    try {
        const response = await authenticatedFetch(`/api/entities/${kind}?value=${encodeURIComponent(value)}`);
        const body = await response.json().catch(() => null);
        if (!response.ok) problem = uiApiErrorText(body, `The server answered ${response.status}.`);
        else data = body;
        // Ban and Allow come with the Read-Write key: asked once more when it is not known to be there
        if (kind === 'ip' && !entityRwAsked && typeof mailcowRwConfigured !== 'undefined' && !mailcowRwConfigured
            && typeof fetchRwStatus === 'function') {
            entityRwAsked = true;
            await fetchRwStatus();
        }
    } catch (error) {
        problem = 'The server could not be reached.';
    }
    // Another card was opened, or this one closed, while this one loaded
    if (seq !== entityCardSeq || !entityCardState) return;
    if (!data || typeof data !== 'object' || !data.sources) {
        if (keep) {
            showToast(`The card could not be read again. ${problem || ''}`.trim(), 'error');
            return;
        }
        const content = document.getElementById('entity-card-content');
        if (content) content.innerHTML = `<div class="ui-empty" role="alert"><b class="ui-text-fail">Could not load this card</b>${escapeHtml(problem || 'The answer was not readable.')}</div>`;
        return;
    }
    const body = document.getElementById('entity-card-body');
    const scroll = keep && body ? body.scrollTop : 0;
    const focused = keep ? entityCardFocusKey() : null;
    entityCardState.data = data;
    entityCardTitle(kind, data);
    entityCardHeader(data);
    entityCardDrawTabs();
    entityCardShowTab(keep ? entityCardState.tab : 'overview');
    if (keep) {
        if (body) body.scrollTop = scroll;
        entityCardRefocus(focused);
    }
}

// The card read again, after an action changed what it shows (a ban, a block,
// a blocklist check). An older answer still on its way is dropped
function entityCardRefresh() {
    const state = entityCardState;
    if (!state || !state.data) return;
    entityCardLoad(++entityCardSeq, state.kind, state.value, { keep: true });
}

// What had the focus in the card, to find it again once the card is drawn anew
function entityCardFocusKey() {
    const card = document.getElementById('entity-card');
    const el = document.activeElement;
    if (!card || !el || !card.contains(el) || el === card) return null;
    const act = el.closest('[data-ent-act]');
    return act ? `[data-ent-act="${act.dataset.entAct}"]` : el.id ? `#${el.id}` : '.ui-ent-value';
}

// Its action again, else the value at the top: never lost to the page under the card
function entityCardRefocus(key) {
    if (!key) return;
    const card = document.getElementById('entity-card');
    const el = card && (card.querySelector(`${key}:not([disabled])`) || card.querySelector('.ui-ent-value'));
    if (el) el.focus();
}

// =============================================================================
// HEADER
// =============================================================================

function entityCardTitle(kind, data) {
    const title = document.getElementById('entity-card-title');
    if (!title) return;
    let text = { ip: 'IP address', address: 'Email address', domain: 'Domain' }[kind] || 'Details';
    const mailbox = data && data.sources && data.sources.mailbox;
    if (kind === 'address' && mailbox && mailbox.state === 'ok') {
        if (mailbox.mailbox) text = 'Mailbox';
        else if (mailbox.alias) text = 'Alias';
    }
    title.textContent = text;
}

function entityCardHeader(data) {
    const header = document.getElementById('entity-card-header');
    if (!header || !entityCardState) return;
    const shown = data ? (data.display || data.value) : entityCardState.value;
    const facts = data ? entityCardFacts(data) : [];
    const verdict = data ? entityCardVerdict(data) : null;
    // The value copies on click here (a button, so the keyboard copies it too);
    // everywhere else a click opens this card
    const v = uiEntityAttr(shown);
    header.innerHTML = `
        <h2 class="ui-md-subject ui-ent-title"><button type="button" class="copyable ui-ent-value" data-entity-copy="${v}" title="Click to copy" aria-label="Copy ${v}"><bdi>${v}</bdi><svg class="copy-icon w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button></h2>
        ${facts.length ? `<div class="ui-md-who ui-ent-who">${facts.map(([label, html]) => `<span>${escapeHtml(label)}</span><div>${html}</div>`).join('')}</div>` : ''}
        ${verdict ? `<div class="ui-md-verdict-bar${verdict.tone ? ` ui-md-verdict-${verdict.tone}` : ''}"><div>${escapeHtml(verdict.text)}${verdict.note ? `<small>${escapeHtml(verdict.note)}</small>` : ''}</div></div>` : ''}
        ${data ? entityCardActionsHtml(data) : ''}`;
}

const entitySrc = (data, name) => (data && data.sources && data.sources[name]) || { state: 'error', reason: null };
const entityOk = src => src && src.state === 'ok';
const entityNum = n => (Number(n) || 0).toLocaleString();

// The range in words: "the last 7 days"
function entityRangeText(data) {
    const r = data && data.range;
    const start = r ? new Date(r.start).getTime() : NaN;
    const end = r ? new Date(r.end).getTime() : NaN;
    if (isNaN(start) || isNaN(end)) return 'the last 7 days';
    const days = Math.max(1, Math.round((end - start) / 86400000));
    return days === 1 ? 'the last day' : `the last ${days} days`;
}
function entityRangeShort(data) {
    return entityRangeText(data).replace(/^the last /, '');
}

// A value inside the card: its own value stays text, any other opens its card
function entityCardValue(kind, value, opts = {}) {
    if (!value) return '<span class="ui-muted">-</span>';
    const own = entityCardState && String(value).trim().toLowerCase() === String(entityCardState.data ? entityCardState.data.value : entityCardState.value).toLowerCase();
    if (own) return `<bdi>${escapeHtml(value)}</bdi>`;
    return uiEntity(kind, value, { ...opts });
}

// The timeline's sources that are off or failed, as a person names them
function entityLeftOut(data) {
    const left = data && data.timeline && Array.isArray(data.timeline.left_out) ? data.timeline.left_out : [];
    return left.map(name => ENTITY_SOURCE_NAMES[name] || name);
}

// "Nothing" is said only of the sources that were read; the others are named
// short: the header line, which names the sources left out without the reason
function entityNothingText(data, short = false) {
    const left = entityLeftOut(data);
    if (left.length && short) return `Nothing found in the sources that could be read. Not included: ${left.join(', ')}`;
    return left.length
        ? `Nothing found in ${entityRangeText(data)} in the sources that could be read. Not included, because they are turned off or could not be read: ${left.join(', ')}.`
        : `Nothing stored in ${entityRangeText(data)}.`;
}

function entityCardSeen(data) {
    const timeline = data.timeline;
    if (!timeline || !Array.isArray(timeline.items)) return null;
    const items = timeline.items.filter(i => i && i.time);
    if (!items.length) return `<span class="ui-muted">${escapeHtml(entityNothingText(data, true))}</span>`;
    const last = items[0].time;
    const first = items[items.length - 1].time;
    const left = entityLeftOut(data);
    const missing = left.length ? `<span class="ui-muted">. Not included: ${escapeHtml(left.join(', '))}</span>` : '';
    // A list cut at its newest rows does not reach the first event
    if (timeline.truncated) return `Last ${uiTime(last, formatAgo(last), { title: formatTime(last) })}${missing}`;
    return `First ${uiTime(first, formatDay(first), { title: formatTime(first) })}, last ${uiTime(last, formatAgo(last), { title: formatTime(last) })}${missing}`;
}

function entityCardFacts(data) {
    const facts = [];
    if (data.kind === 'ip') {
        const geo = entitySrc(data, 'geo');
        if (entityOk(geo) && (geo.country_name || geo.city || geo.asn_org)) {
            const flag = geo.country_code ? getFlagUrl(geo.country_code, '16x12') : '';
            const place = [geo.country_name, geo.city].filter(Boolean).join(', ');
            const network = [geo.asn, geo.asn_org].filter(Boolean).join(' ');
            facts.push(['From', `${flag ? `<img class="ui-sec-flag" src="${flag}" alt="" width="16" height="12" onerror="this.remove()">` : ''}<bdi>${escapeHtml(place || 'Unknown place')}</bdi>${network ? ` <span class="ui-muted">&middot; <bdi>${escapeHtml(network)}</bdi></span>` : ''}`]);
        } else if (geo.state !== 'ok') {
            facts.push(['From', `<span class="ui-muted">${escapeHtml(geo.state === 'disabled' ? (geo.reason || 'GeoIP is not set up.') : 'The place could not be read.')}</span>`]);
        }
        const seen = entityCardSeen(data);
        if (seen) facts.push(['Seen', seen]);
    } else if (data.kind === 'address') {
        const mailbox = entitySrc(data, 'mailbox');
        if (entityOk(mailbox) && mailbox.mailbox && mailbox.mailbox.name) facts.push(['Name', `<bdi>${escapeHtml(mailbox.mailbox.name)}</bdi>`]);
        if (entityOk(mailbox) && mailbox.alias && mailbox.alias.goto) {
            const targets = String(mailbox.alias.goto).split(',').map(s => s.trim()).filter(Boolean);
            facts.push(['Goes to', targets.slice(0, 6).map(t => entityCardValue('address', t)).join(', ') + (targets.length > 6 ? ` <span class="ui-muted">and ${targets.length - 6} more</span>` : '')]);
        }
        if (data.domain) facts.push(['Domain', entityCardValue('domain', data.domain)]);
        const seen = entityCardSeen(data);
        if (seen) facts.push(['Seen', seen]);
    } else {
        const hosted = data.hosted === true ? 'This mailcow' : data.hosted === false ? 'Elsewhere' : '<span class="ui-muted">Not known yet</span>';
        facts.push(['Hosted', hosted]);
        if (data.display && data.value && data.display !== data.value) facts.push(['ASCII', `<span class="ui-mono">${escapeHtml(data.value)}</span>`]);
    }
    return facts;
}

// The state bar under the facts: one sentence on what matters most about it
function entityCardVerdict(data) {
    if (data.kind === 'ip') {
        const lists = entitySrc(data, 'lists');
        const security = entitySrc(data, 'security');
        const fails = entityOk(security) ? Number(security.rule_matches) || 0 : 0;
        const failNote = fails ? `${entityNum(fails)} failed ${fails === 1 ? 'login' : 'logins'} in ${entityRangeText(data)}.` : '';
        if (entityOk(lists)) {
            if (lists.ban) return { tone: 'fail', text: 'Banned by Fail2ban', note: [`The ban holds ${lists.ban.network}.`, failNote].filter(Boolean).join(' ') };
            if (lists.denylisted_as) return { tone: 'fail', text: 'On the denylist', note: `Listed as ${lists.denylisted_as}.` };
            if (lists.allowlisted_as) return { tone: 'ok', text: 'On the allowlist', note: `Listed as ${lists.allowlisted_as}. Fail2ban never bans it.` };
        }
        // "Not banned" only from lists that were read
        const listsNote = lists.reason || (lists.state === 'disabled' ? 'The Fail2ban lists are turned off.' : 'The Fail2ban lists could not be read.');
        if (fails && !entityOk(lists)) return { tone: 'warn', text: 'To review: ban state not known', note: `${failNote} ${listsNote}` };
        if (fails) return { tone: 'warn', text: 'To review: not banned', note: failNote };
        // "No failed logins" only from a source that answered, never from one that is off or failed
        if (security.state === 'disabled') return { tone: 'info', text: 'Failed logins not known', note: security.reason || 'The Security feature is turned off.' };
        if (security.state !== 'ok') return { tone: 'info', text: 'Failed logins not known', note: security.reason || 'The security events could not be read.' };
        if (!entityOk(lists)) return { tone: 'info', text: 'No failed logins, ban state not known', note: `None in ${entityRangeText(data)}. ${listsNote}` };
        return { tone: 'ok', text: 'No failed logins', note: `None in ${entityRangeText(data)}.` };
    }
    if (data.kind === 'address') {
        const suppression = entitySrc(data, 'suppression');
        const suppressed = entityOk(suppression) && ((suppression.entry && suppression.entry.active) || (suppression.domain_entry && suppression.domain_entry.active));
        const supNote = !entityOk(suppression) ? '' : suppressed
            ? (suppression.entry && suppression.entry.active ? 'On the suppression list.' : 'Its domain is on the suppression list.')
            : 'Not on the suppression list.';
        if (data.excluded) return { tone: 'info', text: 'Excluded address', note: 'Messages does not keep or show its mail.' };
        const mailbox = entitySrc(data, 'mailbox');
        if (entityOk(mailbox) && mailbox.mailbox) {
            const active = mailbox.mailbox.active !== false;
            return { tone: suppressed ? 'warn' : active ? 'ok' : 'warn', text: active ? 'Active mailbox' : 'Inactive mailbox', note: supNote };
        }
        if (entityOk(mailbox) && mailbox.alias) {
            return { tone: suppressed ? 'warn' : 'info', text: mailbox.alias.active === false ? 'Inactive alias' : 'Alias on this mailcow', note: supNote };
        }
        // Not a mailbox here only when the mailboxes could be read
        if (!entityOk(mailbox) && data.hosted_domain !== false) return { tone: 'info', text: 'Mailbox not known', note: [mailbox.reason, supNote].filter(Boolean).join(' ') };
        const text = data.hosted_domain === true ? 'Not a mailbox here' : data.hosted_domain === false ? 'Outside address' : 'Address';
        return { tone: suppressed ? 'warn' : 'info', text, note: supNote };
    }
    const suppression = entitySrc(data, 'suppression');
    const suppressed = entityOk(suppression) && suppression.entry && suppression.entry.active;
    if (suppressed) return { tone: 'warn', text: 'Domain on the suppression list', note: 'Mail to its addresses is not sent.' };
    if (data.hosted === true) {
        const boxes = entitySrc(data, 'mailboxes');
        return { tone: 'ok', text: 'Hosted on this mailcow', note: entityOk(boxes) ? `${uiCountLabel(boxes.mailboxes, 'mailbox', 'mailboxes')}, ${entityNum(boxes.aliases)} aliases.` : '' };
    }
    return { tone: 'info', text: data.hosted === false ? 'Outside domain' : 'Domain', note: '' };
}

// =============================================================================
// ACTIONS
// =============================================================================
// Under the state bar (mockup 01, 02). An action opens a page filtered to this
// value, or changes something through the flow the app already has for it, with
// that flow's own confirmation: banIP and allowIP (app.js), the Add Suppression
// dialog (spam_filter.js). An action whose feature is off is not offered (the
// tile or tab says why); Ban and Allow without the Read-Write key show the locked
// note the Security list shows (security.js renderSecurityOverview). Handlers
// carry no value: entityCardAct reads it from the card shown.
// On a phone the main action stays and the others fold into More (v3 rule MO-6).
// The Watch toggle (layer L5a) goes first, in #entity-card-watch.

let entityRwAsked = false;   // the Read-Write key asked for again once (entityCardLoad)
let entityRblCheck = null;   // this card's check while it runs: { run, value, percent, text, started, poll, asking }
let entityRblRuns = 0;       // each check started; a late answer for an older one is dropped
let entityRblBusy = null;    // the value whose Check now found another check running
// The progress is asked for every second as the Status page does, for 3 minutes at
// most, each request given 5 seconds
const ENTITY_RBL_POLL = { every: 1000, max: 3 * 60000, request: 5000 };

// The card's check is left to the server once the card closes or shows another value
function entityRblStop() {
    if (entityRblCheck) clearInterval(entityRblCheck.poll);
    entityRblCheck = null;
    entityRblBusy = null;
}

const ENTITY_ACTIONS = {
    // kind: the buttons in order ([action, stays on a phone]). Every action is a button;
    // only a phone folds the rest into More (Check now lives in the Blocklists tile)
    ip: { buttons: [['messages'], ['security'], ['ban', true], ['allow']] },
    address: { buttons: [['mailbox', true], ['messages'], ['suppress'], ['security']] },
    domain: { buttons: [['messages', true], ['security']] },
};

const entityRw = () => typeof mailcowRwConfigured !== 'undefined' && !!mailcowRwConfigured;

function entityActionLabel(data, act) {
    return {
        messages: 'Show messages', security: 'Show security events', ban: 'Ban', allow: 'Allow', rbl: 'Check blocklists now',
        mailbox: 'Open mailbox', suppress: 'Add to Suppressions',
    }[act] || act;
}

// The mailbox here an address is or delivers to, as stored (the server resolved
// an alias's target: alias.local_mailbox), else ''
function entityMailboxOf(data) {
    const m = entitySrc(data, 'mailbox');
    if (!entityOk(m)) return '';
    if (m.local === true && m.mailbox && m.mailbox.username) return m.mailbox.username;
    return (m.alias && m.alias.local_mailbox) || '';
}

// Whether the card shown offers an action
function entityCanAct(data, act) {
    const src = name => entitySrc(data, name);
    const on = name => src(name).state !== 'disabled';
    const lists = src('lists');
    switch (act) {
        case 'messages': return on('messages');
        case 'security': return on('security');
        // A list that could not be read leaves both: the ban state reads as not known
        case 'ban': return data.kind === 'ip' && on('lists') && entityRw() && !(entityOk(lists) && lists.denylisted_as);
        case 'allow': return data.kind === 'ip' && on('lists') && entityRw() && !(entityOk(lists) && lists.allowlisted_as);
        case 'rbl': return data.kind === 'ip' && entityOk(src('rbl'));
        // Not on the list yet; an entry there, active or ended, is changed on the Suppressions page
        case 'suppress': return data.kind === 'address' && entityOk(src('suppression')) && !src('suppression').entry;
        // A mailbox here, or an alias that delivers to one: Mailbox Stats shows the mailbox
        case 'mailbox': return data.kind === 'address' && !!entityMailboxOf(data);
        default: return false;
    }
}

function entityCardActionsHtml(data) {
    const plan = ENTITY_ACTIONS[data.kind];
    if (!plan) return '';
    const buttons = plan.buttons.filter(([act]) => entityCanAct(data, act)).map(([act, stays]) => ({ act, stays: !!stays }));
    // A phone keeps one button at least: the first, when the main one is not offered
    if (buttons.length && !buttons.some(b => b.stays)) buttons[0].stays = true;
    // A More for a single action would only hide it behind a tap: then it stays a button
    if (buttons.filter(b => !b.stays).length < 2) buttons.forEach(b => { b.stays = true; });
    // The entry Fail2ban gets, as banIP writes it (app.js fail2banEntry)
    const entry = typeof fail2banEntry === 'function' ? fail2banEntry(data.value) : data.value;
    const titles = {
        ban: `Put ${entry} on the Fail2ban denylist; it stays until removed`,
        allow: `Never ban ${entry}`,
        mailbox: entitySrc(data, 'mailbox').local !== true && entityMailboxOf(data) ? `Open ${entityMailboxOf(data)}, the mailbox this alias delivers to` : '',
    };
    const title = act => (titles[act] ? ` title="${escapeHtml(titles[act])}"` : '');
    // The Security list's pair: Ban in red text, Allow plain (security.js securityRowWhy)
    const button = ({ act, stays }) => `<button type="button" class="ui-btn${act === 'ban' ? ' ui-btn-danger' : ''}${stays ? '' : ' ui-ent-fold'}" data-ent-act="${act}"${title(act)} onclick="entityCardAct('${act}', this)">${escapeHtml(entityActionLabel(data, act))}</button>`;
    const item = (act, phoneOnly) => `<button type="button" role="menuitem"${phoneOnly ? ' class="ui-ent-phone"' : ''} data-ent-act="${act}-menu" onclick="entityCardAct('${act}', this)">${escapeHtml(entityActionLabel(data, act))}</button>`;
    const items = buttons.filter(b => !b.stays).map(b => item(b.act, true)).join('');
    // More holds only what a phone folds away, so only a phone shows it
    const more = items ? `<span class="ui-ent-more-phone">${uiMenu('More', items, { small: false })}</span>` : '';
    const locked = data.kind === 'ip' && entitySrc(data, 'lists').state !== 'disabled' && !entityRw()
        ? `<div class="ui-list-note ui-flush">${uiLocked('Ban and Allow are locked', `Banning or allowing this address from here ${UI_RW_KEY_TEXT}`,
            '<button type="button" class="ui-btn ui-btn-sm" onclick="entityCardSettings()">Open Settings</button>')}</div>` : '';
    return `<div class="ui-ent-acts" id="entity-card-actions"><span id="entity-card-watch" hidden></span>${buttons.map(button).join('')}${more}</div>${locked}`;
}

// The card's period as the pages take it: a preset up to now (the card's own
// range is the last 7 days by default), else its exact start and end
function entityCardPeriod(data) {
    const r = (data && data.range) || {};
    const start = Date.parse(r.start);
    const end = Date.parse(r.end);
    const days = isNaN(start) || isNaN(end) ? 0 : (end - start) / 86400000;
    const preset = [7, 30, 90].find(n => Math.abs(days - n) < 0.001);
    return {
        preset: preset ? `${preset}days` : '', start: r.start || '', end: r.end || '', text: entityRangeText(data),
        startDay: isNaN(start) ? '' : zonedDateString(new Date(start)), endDay: isNaN(end) ? '' : zonedDateString(new Date(end)),
    };
}

// To another page: once it is open, the card closes, with the dialogs under it
// that only show something (as entityCardSettings does)
async function entityCardLeave(moving) {
    if (!(await moving)) return;
    closeEntityCard();
    entityCardCloseViews();
}

// The card read again after an action, when it still shows that value
function entityCardRefreshFor(kind, value) {
    const state = entityCardState;
    if (state && state.data && state.kind === kind && state.data.value === value) entityCardRefresh();
}

async function entityCardAct(act, button) {
    const data = entityCardState && entityCardState.data;
    if (!data || !entityCanAct(data, act)) return;
    const { kind, value } = data;
    const shown = data.display || value;
    const period = entityCardPeriod(data);
    switch (act) {
        case 'messages': {
            const filter = kind === 'ip' ? { ip: shown, exact: true } : kind === 'address' ? { address: shown } : { domain: shown };
            const range = period.preset ? { datePreset: period.preset } : { start: period.start, end: period.end };
            return entityCardLeave(navigateToMessagesWithFilter({ ...filter, ...range }));
        }
        case 'security': {
            const filter = kind === 'ip' ? { ip: shown } : kind === 'address' ? { username: shown } : { domain: shown };
            // A preset runs up to now, so new events come in as the list refreshes
            return entityCardLeave(openSecurityEventsFor({ ...filter, start: period.start, end: period.preset ? '' : period.end, period: period.text }));
        }
        case 'ban':
            if (await banIP(value, button)) entityCardRefreshFor(kind, value);
            return;
        case 'allow':
            if (await allowIP(value, button)) entityCardRefreshFor(kind, value);
            return;
        case 'suppress':
            showAddSuppressionModal(shown, null, { notes: '', onAdded: () => entityCardRefreshFor(kind, value) });
            return;
        case 'rbl':
            return entityCardCheckRbl();
        case 'mailbox': {
            const range = period.preset ? { preset: period.preset } : { startDay: period.startDay, endDay: period.endDay };
            return openMailboxFor(entityMailboxOf(data), { ...range, onMoved: () => { closeEntityCard(); entityCardCloseViews(); } });
        }
        default:
            return;
    }
}

// --------------------------------------------------------------- blocklists

// The Blocklists tile: the last stored check and Check now; while a check runs,
// its progress (the meter of the Status page's check, app.js checkBlacklists)
function entityRblTile(data) {
    const can = entityCanAct(data, 'rbl');
    const run = entityRblCheck && entityRblCheck.value === data.value ? entityRblCheck : null;
    const button = can ? `<button type="button" class="ui-btn ui-btn-sm" data-ent-act="rbl-tile"${run ? ' aria-disabled="true"' : ''} onclick="entityCardAct('rbl', this)">${run ? 'Checking...' : 'Check now'}</button>` : '';
    if (run) {
        const meter = `<span class="ui-meter ui-meter-info ui-ent-meter" role="progressbar" aria-label="Blocklist check" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${run.percent}"><i style="width: ${run.percent}%"></i></span>`;
        return entityTile('Blocklists', { id: 'entity-rbl-tile', value: '<span class="ui-muted">Checking...</span>', note: escapeHtml(run.text), action: meter + button });
    }
    return entitySourceTile('Blocklists', entitySrc(data, 'rbl'), r => {
        let shown;
        if (!r.checked) shown = { value: '<span class="ui-muted">Not checked</span>', note: r.monitored ? 'Waiting for its first check' : 'This address was never checked' };
        else {
            const when = r.checked_at ? `Checked ${uiTime(r.checked_at, formatAgo(r.checked_at), { title: formatTime(r.checked_at) })}` : '';
            if (r.status === 'listed') shown = { value: `Listed on ${entityNum(r.listed_count)} of ${entityNum(r.total_blacklists)}`, tone: 'fail', note: [escapeHtml((r.listed || []).slice(0, 3).join(', ')), when].filter(Boolean).join('. ') };
            else if (r.status === 'error') shown = { value: 'Check failed', tone: 'warn', note: when };
            else shown = { value: 'Not listed', note: [`On none of ${entityNum(r.total_blacklists)}`, when].filter(Boolean).join('. ') };
        }
        // Check now found another check running (from Status, the schedule or another card)
        if (entityRblBusy === data.value) shown.note = `${shown.note}. <span class="ui-text-warn">A blocklist check is already running.</span> Try again when it is done.`;
        return { ...shown, action: button };
    }, '', 'entity-rbl-tile');
}

// The tile drawn again: whole when a check starts, else its meter and line only,
// so the focus stays on its button
function entityRblRedraw(whole = false) {
    const tile = document.getElementById('entity-rbl-tile');
    const data = entityCardState && entityCardState.data;
    if (!tile || !data) return;
    if (whole) {
        const focused = entityCardFocusKey();
        tile.outerHTML = entityRblTile(data);
        entityCardRefocus(focused);
        return;
    }
    const run = entityRblCheck;
    const meter = tile.querySelector('.ui-ent-meter');
    const line = tile.querySelector('small');
    if (!run || !meter) return;
    meter.setAttribute('aria-valuenow', String(run.percent));
    meter.firstElementChild.style.width = `${run.percent}%`;
    if (line) line.textContent = run.text;
}

// Check now: POST /api/blacklist/check with the address and force in the URL,
// its progress read from /api/blacklist/progress every second as the Status
// page's check does; the tile shows the stored result after it. One check at a
// time: the progress is one for the whole app
async function entityCardCheckRbl() {
    const data = entityCardState && entityCardState.data;
    if (!data || data.kind !== 'ip' || entityRblCheck) return;
    const value = data.value;
    entityRblBusy = null;
    const check = { run: ++entityRblRuns, value, percent: 0, text: 'Starting the check...', started: Date.now(), poll: null, asking: false };
    entityRblCheck = check;
    entityRblRedraw(true);
    // Its progress, while this card shows this check: a closed or replaced card
    // stops it (entityRblStop), and so does the time limit; one request at a time
    check.poll = setInterval(async () => {
        if (entityRblCheck !== check) { clearInterval(check.poll); return; }
        if (Date.now() - check.started > ENTITY_RBL_POLL.max) {
            clearInterval(check.poll);
            check.text = 'Still checking. The result shows here when it is done.';
            entityRblRedraw();
            return;
        }
        if (check.asking) return;
        check.asking = true;
        try {
            const response = await authenticatedFetch('/api/blacklist/progress', { timeout: ENTITY_RBL_POLL.request });
            const progress = response.ok ? await response.json() : null;
            if (entityRblCheck !== check || !progress || !progress.total) return;
            check.percent = Math.max(0, Math.min(100, Number(progress.percent) || 0));
            check.text = `${Number(progress.current) || 0} of ${Number(progress.total)} lists checked`;
            entityRblRedraw();
        } catch (e) {
            // The next tick asks again
        } finally {
            check.asking = false;
        }
    }, ENTITY_RBL_POLL.every);
    let result = null;
    let problem = '';
    try {
        const response = await authenticatedFetch(`/api/blacklist/check?host=${encodeURIComponent(value)}&force=true`, { method: 'POST' });
        const body = await response.json().catch(() => null);
        if (!response.ok) problem = uiApiErrorText(body, `The server answered ${response.status}.`);
        else result = body;
    } catch (e) {
        problem = 'The server could not be reached.';
    } finally {
        clearInterval(check.poll);
    }
    // The card closed, or shows something else, since: the check is the server's now
    if (entityRblCheck !== check) return;
    entityRblCheck = null;
    if (result && result.status === 'busy') {
        // Nothing was started: another check runs (the Status page's, the schedule's)
        entityRblBusy = value;
        showToast(result.message || 'A blocklist check is already running. Try again when it is done.', 'warning');
        entityRblRedraw(true);
        return;
    }
    if (!result || result.status === 'error') {
        showToast(`Could not check ${value} against the blocklists. ${problem || (result && result.error) || ''}`.trim(), 'error');
    } else {
        showToast(`Blocklist check done for ${value}`, 'success');
    }
    entityCardRefresh();
}

// =============================================================================
// TABS
// =============================================================================

function entityCardTabList(data) {
    const s = name => entitySrc(data, name);
    const timeline = data.timeline && Array.isArray(data.timeline.items) ? data.timeline : null;
    const tabs = [['overview', 'Overview', null]];
    if (data.kind !== 'domain' && timeline) tabs.push(['timeline', 'Timeline', { state: 'ok', n: timeline.items.length, more: timeline.truncated }]);
    tabs.push(['messages', 'Messages', { ...s('messages'), n: s('messages').count }]);
    tabs.push(['security', 'Security', { ...s('security'), n: s('security').events }]);
    tabs.push(['devices', 'Devices', { ...s('devices'), n: s('devices').count }]);
    if (data.kind === 'ip') tabs.push(['dmarc', 'DMARC', { ...s('dmarc'), n: s('dmarc').messages }]);
    if (data.kind === 'domain') tabs.push(['dmarc', 'DMARC', { ...s('dmarc'), n: s('dmarc').reports }]);
    return tabs;
}

function entityTabCount(info) {
    if (!info) return '';
    if (info.state === 'disabled') return ' <span class="ui-tab-n" title="Turned off">Off</span>';
    if (info.state === 'error') return ' <span class="ui-tab-n is-fail" title="Could not be read">Error</span>';
    const n = Number(info.n) || 0;
    return n ? ` <span class="ui-tab-n">${n.toLocaleString()}${info.more ? '+' : ''}</span>` : '';
}

function entityCardDrawTabs() {
    const tabs = document.getElementById('entity-card-tabs');
    const state = entityCardState;
    if (!tabs || !state || !state.data) return;
    tabs.innerHTML = entityCardTabList(state.data).map(([id, label, info]) =>
        `<button type="button" id="entity-tab-${id}" class="modal-tab" role="tab" aria-selected="false" aria-controls="entity-card-content" onclick="entityCardTab('${id}')"><span>${escapeHtml(label)}</span>${entityTabCount(info)}</button>`).join('');
}

function entityCardTab(tab) {
    if (!entityCardState || !entityCardState.data) return;
    entityCardShowTab(tab);
    // Scrolled past the header, the new tab starts right under the pinned tabs
    const body = document.getElementById('entity-card-body');
    const header = document.getElementById('entity-card-header');
    if (body && header && body.scrollTop > header.offsetHeight) body.scrollTop = header.offsetHeight;
}

function entityCardShowTab(tab) {
    const state = entityCardState;
    if (!state || !state.data) return;
    state.tab = tab;
    document.querySelectorAll('#entity-card-tabs .modal-tab').forEach(btn => {
        const on = btn.id === `entity-tab-${tab}`;
        btn.classList.toggle('active', on);
        btn.setAttribute('aria-selected', String(on));
    });
    const content = document.getElementById('entity-card-content');
    if (!content) return;
    const draw = {
        overview: entityOverview, timeline: entityTimeline, messages: entityMessages,
        security: entitySecurity, devices: entityDevices, dmarc: entityDmarc,
    }[tab] || entityOverview;
    content.innerHTML = draw(state.data);
}

// A source that is off or failed, in place of its content
function entitySourceState(src, what) {
    if (src && src.state === 'disabled') {
        const inSettings = /turned off|not set up/i.test(src.reason || '');
        return uiLocked(inSettings ? 'Disabled in Settings' : 'Not shown', escapeHtml(src.reason || `${what} is turned off.`),
            inSettings ? '<button type="button" class="ui-btn ui-btn-sm" onclick="entityCardSettings()">Open Settings</button>' : '');
    }
    return `<div class="ui-empty" role="status"><b class="ui-text-fail">Could not read ${escapeHtml(what.toLowerCase())}</b>${escapeHtml(src && src.reason ? src.reason : 'The details are in the container log.')}</div>`;
}

// =============================================================================
// OVERVIEW
// =============================================================================

// One tile; a tile that has a tab opens it. action: a button under it (such a
// tile opens no tab: a button holds no other button); id: to draw it again alone
function entityTile(label, { value = '', note = '', tone = '', tab = '', off = false, action = '', id = '' } = {}) {
    const open = tab && !off && !action;
    const tag = open ? `button type="button" onclick="entityCardTab('${tab}')"` : 'div';
    return `<${tag}${id ? ` id="${id}"` : ''} class="ui-st-card${off ? ' is-off' : ''}"><span class="ui-st-card-label">${escapeHtml(label)}</span><b${tone ? ` class="ui-${tone}"` : ''}>${value}</b>${note ? `<small>${note}</small>` : ''}${action ? `<span class="ui-ent-tile-act">${action}</span>` : ''}</${open ? 'button' : 'div'}>`;
}

// A tile for a source: its figures when ok, else what is wrong, quietly
function entitySourceTile(label, src, ok, tab = '', id = '') {
    if (!src || src.state === 'error') return entityTile(label, { value: 'Could not be read', note: escapeHtml(src && src.reason ? src.reason : ''), tone: 'fail', off: true, id });
    if (src.state === 'disabled') {
        const inSettings = /turned off|not set up/i.test(src.reason || '');
        return entityTile(label, { value: `<span class="ui-muted">${inSettings ? 'Disabled in Settings' : 'Not shown'}</span>`, note: escapeHtml(src.reason || ''), off: true, id });
    }
    return entityTile(label, { ...ok(src), tab, id });
}

// What the newest messages ended as, when the list holds all of them
function entityMessageOutcomes(src) {
    const items = Array.isArray(src.items) ? src.items : [];
    if (!items.length || items.length < (Number(src.count) || 0)) return '';
    const counts = {};
    items.forEach(m => { const s = m.final_status || 'pending'; counts[s] = (counts[s] || 0) + 1; });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([s, n]) => `${n} ${s}`).join(', ');
}

function entityOverview(data) {
    const s = name => entitySrc(data, name);
    const days = entityRangeShort(data);
    let tiles = [];
    if (data.kind === 'ip') {
        tiles = [
            entitySourceTile(`Messages, ${days}`, s('messages'), m => ({ value: entityNum(m.count), note: escapeHtml(entityMessageOutcomes(m) || 'Sent from this address') }), 'messages'),
            entitySourceTile(`Security events, ${days}`, s('security'), e => ({ value: entityNum(e.events), note: `${uiCountLabel(e.rule_matches, 'failed login', 'failed logins')}, ${uiCountLabel(e.bans, 'ban', 'bans')}` }), 'security'),
            entitySourceTile('Protection catches', s('protection'), p => ({ value: entityNum(p.count), note: p.count ? `${entityNum(p.open)} open` : 'None' }), 'security'),
            entitySourceTile('Allowlist and denylist', s('lists'), l => (
                l.ban ? { value: 'Banned', tone: 'fail', note: `Fail2ban bans ${escapeHtml(l.ban.network)}` }
                    : l.denylisted_as ? { value: 'On the denylist', tone: 'fail', note: `As ${escapeHtml(l.denylisted_as)}` }
                        : l.allowlisted_as ? { value: 'On the allowlist', note: `As ${escapeHtml(l.allowlisted_as)}` }
                            : { value: 'Not listed', note: 'On neither list' })),
            entityRblTile(data),
            entitySourceTile('DMARC reports', s('dmarc'), d => ({ value: entityNum(d.messages), note: d.reports ? `Messages in ${uiCountLabel(d.reports, 'report', 'reports')} for ${uiCountLabel(d.domains, 'domain', 'domains')}` : 'No report names it' }), 'dmarc'),
        ];
    } else if (data.kind === 'address') {
        const supTile = entitySourceTile('Suppressions', s('suppression'), sup => {
            if (sup.entry) return { value: sup.entry.active ? 'Suppressed' : 'Suppression ended', tone: sup.entry.active ? 'warn' : '', note: `<bdi>${escapeHtml(sup.entry.reason || sup.entry.source || '')}</bdi>` };
            if (sup.domain_entry && sup.domain_entry.active) return { value: 'Domain suppressed', tone: 'warn', note: `${escapeHtml(sup.domain_entry.email)} is on the list` };
            return { value: 'Not suppressed', note: 'Mail to it is sent' };
        });
        tiles = [
            entitySourceTile(`Sent, ${days}`, s('messages'), m => ({ value: entityNum(m.sent), note: 'Messages from it' }), 'messages'),
            entitySourceTile(`Received, ${days}`, s('messages'), m => ({ value: entityNum(m.received), note: 'Messages to it' }), 'messages'),
            entitySourceTile(`Failed logins, ${days}`, s('security'), e => ({ value: entityNum(e.rule_matches), note: e.ips ? `From ${entityNum(e.ips)} ${e.ips === 1 ? 'address' : 'addresses'}` : 'None' }), 'security'),
            entitySourceTile('Devices', s('devices'), d => ({ value: entityNum(d.count), note: `Seen in ${entityRangeText(data)}` }), 'devices'),
            entitySourceTile('Protection catches', s('protection'), p => ({ value: entityNum(p.count), note: p.count ? `${entityNum(p.open)} open` : 'None' }), 'security'),
            supTile,
        ];
    } else {
        tiles = [
            entitySourceTile(`Messages, ${days}`, s('messages'), m => ({ value: entityNum(m.count), note: `${entityNum(m.sent)} sent, ${entityNum(m.received)} received` }), 'messages'),
            entitySourceTile(`Failed logins, ${days}`, s('security'), e => ({ value: entityNum(e.rule_matches), note: e.ips ? `From ${entityNum(e.ips)} ${e.ips === 1 ? 'address' : 'addresses'}` : 'None' }), 'security'),
            entitySourceTile('Mailboxes', s('mailboxes'), b => ({ value: entityNum(b.mailboxes), note: `${entityNum(b.active_mailboxes)} active, ${uiCountLabel(b.aliases, 'alias', 'aliases')}` })),
            entitySourceTile(`DMARC reports, ${days}`, s('dmarc'), d => ({ value: entityNum(d.reports), note: d.messages ? `${Math.round((Number(d.dmarc_pass) || 0) * 100 / d.messages)}% of ${entityNum(d.messages)} messages passed` : 'No messages reported' }), 'dmarc'),
            entitySourceTile('DNS check', s('dns'), d => {
                if (!d.checked) return { value: '<span class="ui-muted">Not checked</span>', note: 'No DNS check stored' };
                const checks = Object.values(d.checks || {}).filter(Boolean);
                const errors = checks.filter(c => c === 'error').length;
                const warnings = checks.filter(c => c === 'warning').length;
                const when = d.checked_at ? `Checked ${uiTime(d.checked_at, formatAgo(d.checked_at), { title: formatTime(d.checked_at) })}` : '';
                if (errors) return { value: `${errors} ${errors === 1 ? 'error' : 'errors'}`, tone: 'fail', note: when };
                if (warnings) return { value: `${warnings} ${warnings === 1 ? 'warning' : 'warnings'}`, tone: 'warn', note: when };
                return { value: 'All good', note: when };
            }),
            entitySourceTile('Suppressions', s('suppression'), sup => (sup.entry
                ? { value: sup.entry.active ? 'Suppressed' : 'Suppression ended', tone: sup.entry.active ? 'warn' : '', note: `<bdi>${escapeHtml(sup.entry.reason || sup.entry.source || '')}</bdi>` }
                : { value: 'Not suppressed', note: 'Mail to it is sent' })),
        ];
    }
    return `<div class="ui-md-stack"><div class="ui-st-cards ui-ent-tiles">${tiles.join('')}</div>${entityRecent(data)}</div>`;
}

// The newest few events, from the timeline (the domain card has none: its newest messages)
function entityRecent(data) {
    if (data.kind === 'domain') {
        const m = entitySrc(data, 'messages');
        if (!entityOk(m) || !Array.isArray(m.items) || !m.items.length) return '';
        const rows = m.items.slice(0, ENTITY_RECENT).map(msg => entityRecentRow(msg.first_seen, entityEvent({
            kind: 'message', sender: msg.sender, recipient: msg.recipient, subject: msg.subject, status: msg.final_status,
        }, data)));
        return `<section><div class="ui-md-card-head"><h4 class="ui-md-h">Recent messages</h4><button type="button" class="ui-link-row ui-link ui-ent-link" onclick="entityCardTab('messages')">Open messages</button></div><div class="ui-ent-recent">${rows.join('')}</div></section>`;
    }
    const items = data.timeline && Array.isArray(data.timeline.items) ? data.timeline.items : [];
    if (!items.length) return `<section><div class="ui-md-card-head"><h4 class="ui-md-h">Recent</h4></div><p class="ui-muted ui-ent-note">${escapeHtml(entityNothingText(data))}</p></section>`;
    const rows = items.slice(0, ENTITY_RECENT).map(item => entityRecentRow(item.time, entityEvent(item, data)));
    const left = entityLeftOut(data);
    const missing = left.length ? `<p class="ui-muted ui-ent-note">Not included, because they are turned off or could not be read: ${escapeHtml(left.join(', '))}.</p>` : '';
    return `<section><div class="ui-md-card-head"><h4 class="ui-md-h">Recent</h4><button type="button" class="ui-link-row ui-link ui-ent-link" onclick="entityCardTab('timeline')">Open timeline</button></div><div class="ui-ent-recent">${rows.join('')}</div>${missing}</section>`;
}

function entityRecentRow(time, ev) {
    return `<div class="ui-sec-ev">${uiTime(time, formatAgo(time), { title: formatTime(time) })}<span>${ev.title}${ev.short ? `<span class="ui-muted">: ${ev.short}</span>` : ''}</span>${ev.tag}</div>`;
}

// =============================================================================
// TIMELINE
// =============================================================================

const ENTITY_STATUS_WORDS = { delivered: 'Delivered', sent: 'Sent', deferred: 'Deferred', bounced: 'Bounced', rejected: 'Rejected', spam: 'Spam', expired: 'Expired' };
const ENTITY_CATCH_WORDS = {
    watching: 'The rule is watching, so nothing was banned.', pending: 'Waiting for a ban.', alert: 'An alert was sent.',
    banned: 'Banned by the rule.', dismissed: 'Dismissed.', ended: 'Ended.',
};

// One stored event in words: its title, a detail line, its tone and its tag.
// A device row never says "login": only when a device was first or last seen is stored
function entityEvent(item, data) {
    const kind = data.kind;
    const v = (k, value) => entityCardValue(k, value);
    switch (item.kind) {
        case 'message': {
            const word = ENTITY_STATUS_WORDS[item.status] || 'Message';
            return {
                title: `${escapeHtml(word)}: ${v('address', item.sender)} to ${v('address', item.recipient)}`,
                detail: escapeHtml(item.subject || 'No subject'), detailDir: true, short: '',
                tone: UI_STATUS_TONE[item.status] || '', tag: item.status ? uiStatusTag(item.status) : uiTag('Message', ''),
            };
        }
        case 'security':
            return {
                title: kind === 'ip' ? (item.username ? `Failed login as ${v('address', item.username)}` : 'Failed login') : `Failed login from ${v('ip', item.ip)}`,
                detail: escapeHtml(item.service || ''), short: escapeHtml(item.service || ''), tone: 'warn', tag: uiTag('Security', 'warn'),
            };
        case 'ban':
            return { title: kind === 'ip' ? 'Banned by Fail2ban' : `${v('ip', item.ip)} banned by Fail2ban`, detail: escapeHtml(item.service || ''), short: '', tone: 'fail', tag: uiTag('Banned', 'fail') };
        case 'unban':
            return { title: kind === 'ip' ? 'Unbanned' : `${v('ip', item.ip)} unbanned`, detail: '', short: '', tone: 'ok', tag: uiTag('Unbanned', 'ok') };
        case 'protection': {
            const rule = typeof securityRuleName === 'function' ? securityRuleName(item.rule) : (item.rule || 'a rule');
            return {
                title: kind === 'ip' ? `Caught by ${escapeHtml(rule)}` : `${v('ip', item.ip)} caught by ${escapeHtml(rule)}`,
                detail: escapeHtml(ENTITY_CATCH_WORDS[item.status] || item.status || ''), short: '',
                tone: item.status === 'banned' ? 'fail' : 'warn', tag: uiTag(item.status === 'watching' ? 'Watching' : (item.status || 'Protection'), item.status === 'banned' ? 'fail' : 'info'),
            };
        }
        case 'device_first_seen':
        case 'device_last_seen': {
            const first = item.kind === 'device_first_seen';
            const device = `<bdi>${escapeHtml(item.device_type || 'Unknown device')}</bdi>`;
            const whose = kind === 'ip' ? ` of ${v('address', item.username)}` : (item.ip ? ` from ${v('ip', item.ip)}` : '');
            return {
                title: `Device ${first ? 'first' : 'last'} seen: ${device}${whose}`,
                detail: item.device_id ? `Device ID ${escapeHtml(item.device_id)}` : '', short: '',
                tone: first ? 'info' : '', tag: first ? uiTag('New device', 'info') : uiTag('Device', ''),
            };
        }
        default:
            return { title: escapeHtml(item.label || item.kind || 'Event'), detail: '', short: '', tone: '', tag: '' };
    }
}

function entityCardFilter(group) {
    if (!entityCardState || !entityCardState.data) return;
    entityCardState.filter = group;
    const content = document.getElementById('entity-card-content');
    if (content) content.innerHTML = entityTimeline(entityCardState.data);
}

// The day an event belongs to, as a heading: Today, Yesterday, or the date
function entityDayLabel(dayKey) {
    const today = zonedDateString();
    if (dayKey === today) return 'Today';
    if (dayKey === addDaysToDateString(today, -1)) return `Yesterday, ${formatDayKey(dayKey)}`;
    return formatDayKey(dayKey, { weekday: 'long' });
}

function entityTimeline(data) {
    const timeline = data.timeline;
    if (!timeline || !Array.isArray(timeline.items)) return '<p class="ui-empty">No timeline for this card.</p>';
    const items = timeline.items.filter(i => i && i.time);
    const filter = (entityCardState && entityCardState.filter) || 'all';
    const counts = { all: items.length };
    items.forEach(i => { const g = ENTITY_TIMELINE_GROUP[i.kind]; if (g) counts[g] = (counts[g] || 0) + 1; });
    const chips = ENTITY_TIMELINE_GROUPS.filter(([id]) => id === 'all' || counts[id])
        .map(([id, label]) => `<button type="button" class="ui-chip" aria-pressed="${id === filter}" onclick="entityCardFilter('${id}')">${escapeHtml(label)} <small>${(counts[id] || 0).toLocaleString()}</small></button>`).join('');
    const shown = filter === 'all' ? items : items.filter(i => ENTITY_TIMELINE_GROUP[i.kind] === filter);
    const days = [];
    shown.forEach(item => {
        const key = zonedDateString(new Date(item.time));
        const last = days[days.length - 1];
        if (last && last.key === key) last.items.push(item);
        else days.push({ key, items: [item] });
    });
    const notes = [];
    if (timeline.truncated) notes.push(`Only the newest ${items.length} events are shown; more happened in ${entityRangeText(data)}.`);
    const left = entityLeftOut(data);
    const missing = left.length ? `<p class="ui-muted ui-ent-note" role="note">Not included, because they are turned off or could not be read: ${escapeHtml(left.join(', '))}.</p>` : '';
    notes.push(`Shows what is stored for ${entityRangeText(data)}: messages, security events and bans, protection catches and when a device was seen.`);
    const body = days.length ? days.map(day => `
        <section class="ui-ent-day"><h4 class="ui-md-h">${escapeHtml(entityDayLabel(day.key))}</h4><ol class="ui-steps">${day.items.map(item => {
            const ev = entityEvent(item, data);
            const kindTag = `<span class="ui-tag ui-tag-line ui-ent-kind">${escapeHtml(item.label || ENTITY_TIMELINE_GROUP[item.kind] || item.kind)}</span>`;
            return `
            <li class="${ev.tone ? `ui-step-${ev.tone}` : ''}">
                ${uiTime(item.time, formatClock(item.time), { title: formatTime(item.time), cls: 'ui-step-time' })}
                <b>${ev.title} ${kindTag}</b>
                ${ev.detail ? `<span${ev.detailDir ? ' dir="auto"' : ''}>${ev.detail}</span>` : ''}
            </li>`;
        }).join('')}</ol></section>`).join('')
        : `<p class="ui-empty">${escapeHtml(left.length ? 'Nothing found in the sources that could be read.' : `Nothing stored in ${entityRangeText(data)}.`)}</p>`;
    return `<div class="ui-md-stack">
        ${items.length ? `<div class="ui-chip-row" role="group" aria-label="Show">${chips}</div>` : ''}
        ${missing}
        ${body}
        ${notes.map(n => `<p class="ui-muted ui-ent-note">${escapeHtml(n)}</p>`).join('')}
    </div>`;
}

// =============================================================================
// MESSAGES, SECURITY, DEVICES, DMARC
// =============================================================================

// The count above a list, in the frame of the search's "See all" bar
// (search.js gsRender). act: it opens the list on its page, as that action does
function entitySummary(html, act = '') {
    if (act) {
        const label = { messages: 'Open in Messages', security: 'Open in Security' }[act];
        return `<button type="button" class="ui-gs-more ui-ent-go" data-ent-act="${act}-bar" onclick="entityCardAct('${act}', this)"><span>${html}</span><span class="ui-link">${label}</span></button>`;
    }
    return `<div class="ui-gs-more ui-ent-sum"><span>${html}</span></div>`;
}

function entityMessages(data) {
    const src = entitySrc(data, 'messages');
    if (!entityOk(src)) return `<div class="ui-md-stack">${entitySourceState(src, 'Messages')}</div>`;
    const items = Array.isArray(src.items) ? src.items : [];
    const count = Number(src.count) || 0;
    const what = data.kind === 'ip' ? 'from this address' : data.kind === 'address' ? 'from or to this address' : 'from or to this domain';
    const split = data.kind !== 'ip' && (src.sent !== undefined || src.received !== undefined) ? ` (${entityNum(src.sent)} sent, ${entityNum(src.received)} received)` : '';
    if (!count) return `<div class="ui-md-stack">${entitySummary(`No messages ${what} in ${escapeHtml(entityRangeText(data))}`)}</div>`;
    return `<div class="ui-md-stack">
        ${entitySummary(`<b>${entityNum(count)}</b> ${count === 1 ? 'message' : 'messages'} ${what} in ${escapeHtml(entityRangeText(data))}${split}`, entityCanAct(data, 'messages') ? 'messages' : '')}
        <div class="ui-panel ui-ent-flush">${items.map(renderMessageRow).join('')}</div>
        ${items.length < count ? `<p class="ui-muted ui-ent-note">The newest ${items.length} are shown.</p>` : ''}
    </div>`;
}

function entitySecurityRow(item, data) {
    const who = data.kind === 'ip'
        ? (item.username ? entityCardValue('address', item.username) : '<span class="ui-muted">-</span>')
        : entityCardValue('ip', item.ip, { mono: true });
    const action = item.rule_id !== null && item.rule_id !== undefined ? uiTag('Failed login', 'warn') : uiActionTag(item.action || 'info');
    const tone = item.rule_id !== null && item.rule_id !== undefined ? 'warn' : uiActionTone(item.action);
    return `
        <div class="ui-ev-row ui-msg-${tone} ui-ent-ev">
            ${uiTime(item.time, formatListTime(item.time), { title: formatTime(item.time), cls: 'ui-muted' })}
            <span class="ui-ev-account">${who}</span>
            <span>${action}</span>
            <span class="ui-ev-msg ui-mono" title="${escapeHtml(item.message || '')}">${escapeHtml(item.message || item.service || '-')}</span>
        </div>`;
}

function entityCatchRows(src, data) {
    if (!entityOk(src) || !Array.isArray(src.items) || !src.items.length) return '';
    const rows = src.items.map(c => {
        const rule = typeof securityRuleName === 'function' ? securityRuleName(c.rule) : c.rule;
        const who = data.kind === 'ip' ? `<bdi>${escapeHtml(c.reason || '')}</bdi>` : `${entityCardValue('ip', c.ip, { mono: true })}${c.reason ? ` <span class="ui-muted"><bdi>${escapeHtml(c.reason)}</bdi></span>` : ''}`;
        return `<div class="ui-sec-ev">${uiTime(c.last_seen || c.first_seen, formatAgo(c.last_seen || c.first_seen), { title: formatTime(c.last_seen || c.first_seen) })}<span><b>${escapeHtml(rule)}</b> ${who}</span>${c.status ? uiTag(c.status === 'watching' ? 'Watching' : c.status, c.status === 'banned' ? 'fail' : 'info') : ''}</div>`;
    }).join('');
    return `<section><div class="ui-md-card-head"><h4 class="ui-md-h">Protection catches <span class="ui-muted">${entityNum(src.count)}</span></h4></div><div class="ui-ent-recent">${rows}</div></section>`;
}

function entitySecurity(data) {
    const src = entitySrc(data, 'security');
    const catches = entityCatchRows(entitySrc(data, 'protection'), data);
    if (!entityOk(src)) return `<div class="ui-md-stack">${entitySourceState(src, 'Security events')}${catches}</div>`;
    const items = Array.isArray(src.items) ? src.items : [];
    const count = Number(src.events) || 0;
    const parts = [uiCountLabel(src.rule_matches, 'failed login', 'failed logins'), uiCountLabel(src.bans, 'ban', 'bans')];
    if (data.kind !== 'ip' && src.ips) parts.push(`from ${entityNum(src.ips)} ${src.ips === 1 ? 'address' : 'addresses'}`);
    if (!count) return `<div class="ui-md-stack">${entitySummary(`No security events in ${escapeHtml(entityRangeText(data))}`)}${catches}</div>`;
    return `<div class="ui-md-stack">
        ${entitySummary(`<b>${entityNum(count)}</b> security ${count === 1 ? 'event' : 'events'} in ${escapeHtml(entityRangeText(data))} (${parts.join(', ')})`, entityCanAct(data, 'security') ? 'security' : '')}
        <div class="ui-panel ui-ent-flush"><div class="ui-ev-list">
            <div class="ui-ev-row ui-ev-head ui-ent-ev"><span>When</span><span>${data.kind === 'ip' ? 'Account' : 'Address'}</span><span>Action</span><span>Log line</span></div>
            ${items.map(item => entitySecurityRow(item, data)).join('')}
        </div></div>
        ${items.length < count ? `<p class="ui-muted ui-ent-note">The newest ${items.length} are shown.</p>` : ''}
        ${catches}
    </div>`;
}

function entityDevices(data) {
    const src = entitySrc(data, 'devices');
    if (!entityOk(src)) return `<div class="ui-md-stack">${entitySourceState(src, 'Devices')}</div>`;
    const items = Array.isArray(src.items) ? src.items : [];
    const note = data.kind === 'ip' ? 'ActiveSync devices whose last request came from this address.'
        : data.kind === 'address' ? 'ActiveSync devices of this mailbox.' : 'ActiveSync devices of the mailboxes on this domain.';
    if (!items.length) return `<div class="ui-md-stack"><p class="ui-muted ui-ent-note">${escapeHtml(note)}</p>${entitySummary(`No devices seen in ${escapeHtml(entityRangeText(data))}`)}</div>`;
    const newAfter = Date.now() - ENTITY_DAYS_NEW * 86400000;
    const staleBefore = Date.now() - ENTITY_DAYS_STALE * 86400000;
    return `<div class="ui-md-stack"><p class="ui-muted ui-ent-note">${escapeHtml(note)}</p>
        <div class="ui-panel ui-ent-flush"><div class="ui-table ui-stack ui-ent-dev" data-sort-icon="off" style="--ui-cols: minmax(200px, 1.6fr) minmax(170px, 1.4fr) minmax(120px, 1fr) minmax(120px, 1fr) 100px 100px; --ui-table-min: 880px">
            <div class="ui-tr ui-tr-head"><span>User</span><span>Device</span><span>Last IP</span><span>Last request</span><span>First seen</span><span>Last seen</span></div>
            ${items.map(d => renderDeviceRow(d, newAfter, staleBefore)).join('')}
        </div></div>
        ${items.length < (Number(src.count) || 0) ? `<p class="ui-muted ui-ent-note">The ${items.length} seen most recently are shown.</p>` : ''}
    </div>`;
}

const entityPct = (part, whole) => (whole ? `${Math.round((Number(part) || 0) * 100 / whole)}%` : '-');

function entityDmarc(data) {
    const src = entitySrc(data, 'dmarc');
    if (!entityOk(src)) return `<div class="ui-md-stack">${entitySourceState(src, 'DMARC reports')}</div>`;
    if (data.kind === 'domain') {
        const last = src.last_received ? `Last stored ${uiTime(src.last_received, formatAgo(src.last_received), { title: formatTime(src.last_received) })}` : 'No report stored';
        return `<div class="ui-md-stack"><div class="ui-st-cards ui-ent-tiles">
            ${entityTile('Reports', { value: entityNum(src.reports), note: last })}
            ${entityTile('Messages reported', { value: entityNum(src.messages), note: `From ${entityNum(src.sources)} sending ${src.sources === 1 ? 'address' : 'addresses'}` })}
            ${entityTile('Passed DMARC', { value: entityPct(src.dmarc_pass, src.messages), note: `SPF ${entityPct(src.spf_pass, src.messages)}, DKIM ${entityPct(src.dkim_pass, src.messages)}` })}
        </div><p class="ui-muted ui-ent-note">Reports whose period overlaps ${escapeHtml(entityRangeText(data))}.</p></div>`;
    }
    const byDomain = Array.isArray(src.by_domain) ? src.by_domain : [];
    const records = Array.isArray(src.records) ? src.records : [];
    if (!byDomain.length) return `<div class="ui-md-stack">${entitySummary(`No DMARC report names this address in ${escapeHtml(entityRangeText(data))}`)}</div>`;
    const domainRows = byDomain.map(d => `
        <div class="ui-tr">
            <span class="ui-td">${entityCardValue('domain', d.domain)}</span>
            <span class="ui-td"><small class="ui-sec-unit">Messages </small>${entityNum(d.messages)}</span>
            <span class="ui-td"><small class="ui-sec-unit">DMARC </small>${entityPct(d.dmarc_pass, d.messages)}</span>
            <span class="ui-td"><small class="ui-sec-unit">SPF </small>${entityPct(d.spf_pass, d.messages)}</span>
            <span class="ui-td"><small class="ui-sec-unit">DKIM </small>${entityPct(d.dkim_pass, d.messages)}</span>
            <span class="ui-td"><small class="ui-sec-unit">Last report </small>${d.last_period_end ? uiTime(d.last_period_end, formatDay(d.last_period_end), { title: formatTime(d.last_period_end) }) : '-'}</span>
        </div>`).join('');
    const recordRows = records.slice(0, 20).map(r => `
        <div class="ui-sec-ev">${uiTime(r.period_end, formatDay(r.period_end), { title: `Period ${formatTime(r.period_begin)} to ${formatTime(r.period_end)}` })}<span>${entityNum(r.count)} for ${entityCardValue('domain', r.domain)} <span class="ui-muted">reported by <bdi>${escapeHtml(r.org_name || '-')}</bdi>, SPF ${escapeHtml(r.spf_result || '-')}, DKIM ${escapeHtml(r.dkim_result || '-')}</span></span>${r.disposition ? uiTag(r.disposition, r.disposition === 'none' ? '' : 'warn') : ''}</div>`).join('');
    return `<div class="ui-md-stack">
        ${entitySummary(`<b>${entityNum(src.messages)}</b> messages from this address in ${uiCountLabel(src.reports, 'DMARC report', 'DMARC reports')} for ${entityNum(src.domains)} ${src.domains === 1 ? 'domain' : 'domains'}`)}
        <div class="ui-panel ui-ent-flush"><div class="ui-table ui-stack ui-ent-dm" data-sort-icon="off">
            <div class="ui-tr ui-tr-head"><span>Domain</span><span>Messages</span><span>DMARC pass</span><span>SPF pass</span><span>DKIM pass</span><span>Last report</span></div>
            ${domainRows}
        </div></div>
        ${recordRows ? `<section><div class="ui-md-card-head"><h4 class="ui-md-h">Newest records</h4></div><div class="ui-ent-recent">${recordRows}</div></section>` : ''}
        <p class="ui-muted ui-ent-note">By report period; a report names the period it covers and arrives later.</p>
    </div>`;
}

document.addEventListener('DOMContentLoaded', function () {
    const card = document.getElementById('entity-card');
    if (!card) return;
    // A click on the backdrop (not in the card) closes it
    card.addEventListener('click', function (e) {
        if (uiBackdropClick(e)) closeEntityCard();
    });
});
