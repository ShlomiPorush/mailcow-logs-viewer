// =============================================================================
// DOMAINS - domain list, DNS validation (SPF/DKIM/DMARC checks)
// =============================================================================
// Split out of app.js (phase 5). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

// =============================================================================
// DOMAINS TAB - Domains management with DNS validation
// =============================================================================

const DNS_CHECKS = [['SPF', 'spf'], ['DKIM', 'dkim'], ['DMARC', 'dmarc'], ['DNSSEC', 'dnssec'], ['DANE', 'tlsa'], ['MTA-STS', 'mta_sts']];
// On a phone an open domain shows its DNS checks or its details, one tab at a time
const domainTabs = {};
const DNS_TAG = {
    success: ['OK', 'ok'],
    warning: ['Warning', 'warn'],
    error: ['Error', 'fail'],
};

// The answer the list shows, to tell whether a refresh brings anything new
let domainsShownJson = null;

async function loadDomains() {
    const loading = document.getElementById('domains-loading');
    const content = document.getElementById('domains-content');

    if (!loading || !content) {
        console.error('Domains elements not found');
        return;
    }

    loading.classList.remove('hidden');
    content.classList.add('hidden');

    try {
        const response = await authenticatedFetch('/api/domains/all');

        if (!response.ok) {
            throw await responseError(response);
        }

        const data = await response.json();

        domainsShownJson = JSON.stringify(data);
        renderDomains(content, data);

        loading.classList.add('hidden');
        content.classList.remove('hidden');

    } catch (error) {
        console.error('Failed to load domains:', error);
        loading.innerHTML = `
            <div class="ui-empty ui-panel">
                <p class="ui-text-fail">Failed to load domains</p>
                <p>${escapeHtml(error.message)}</p>
                <p><button type="button" class="ui-btn ui-btn-sm" onclick="loadDomains()">Try again</button></p>
            </div>
        `;
    }
}

// A domain has DNS issues when SPF, DKIM or DMARC reports an error or a warning
function domainHasIssues(domain) {
    const dns = domain.dns_checks || {};
    return ['spf', 'dkim', 'dmarc'].some(key => dns[key] && (dns[key].status === 'error' || dns[key].status === 'warning'));
}

function domainRowId(domainName) {
    return `domain-${String(domainName).replace(/[^A-Za-z0-9_-]/g, '-')}`;
}

// The refresh, every five minutes: only what changed is drawn again. The search,
// the issues filter, the open domains and the row in view stay as they are. A
// first load that failed is tried again
async function refreshDomains() {
    const content = document.getElementById('domains-content');
    if (!content || dnsCheckInProgress) return;
    if (domainsShownJson === null || content.classList.contains('hidden')) return loadDomains();
    const response = await authenticatedFetch('/api/domains/all', { timeout: PAGE_REFRESH_TIMEOUT });
    if (!response.ok) return;
    const data = await response.json();
    const json = JSON.stringify(data);
    const list = document.getElementById('domains-list');
    // A DNS check redraws its row by itself; text selected in the list waits for the next refresh
    if (json === domainsShownJson || dnsCheckInProgress || (list && uiTextHeld(list))) return;
    domainsShownJson = json;
    const domains = data.domains || [];
    if (!list || !domains.length) {
        renderDomains(content, data);
        return;
    }
    renderDomainsHead(data);
    window.domainsData = domains;
    filterDomains();
}

// The line under the title and the summary
function renderDomainsHead(data) {
    const domains = data.domains || [];
    const dnsCheckInfo = document.getElementById('dns-check-info');
    if (dnsCheckInfo) {
        const lastCheck = data.last_dns_check ? formatTime(data.last_dns_check) : 'Never';
        // When the DNS was last checked sits on a line under the page title
        const lastChecked = document.getElementById('domains-last-checked');
        if (lastChecked) {
            if (data.last_dns_check) uiAgo(lastChecked, data.last_dns_check, 'Updated ');
            else lastChecked.textContent = 'Not checked yet';
        }
    }

    const summary = document.getElementById('domains-summary');
    if (summary) {
        const total = data.total || domains.length;
        const inactive = (data.total || 0) - (data.active || 0);
        const issues = domains.filter(domainHasIssues).length;
        summary.textContent = `${total} ${total === 1 ? 'domain' : 'domains'}${inactive > 0 ? `, ${inactive} inactive` : ''}. ${issues ? `${issues} ${issues === 1 ? 'needs' : 'need'} a DNS change.` : 'DNS looks right.'}`;
    }
}

function renderDomains(container, data) {
    const domains = data.domains || [];
    renderDomainsHead(data);

    if (domains.length === 0) {
        container.innerHTML = '<p class="ui-empty ui-panel">No domains found</p>';
        return;
    }

    container.innerHTML = `
        <div class="ui-panel ui-table-card">
        <section class="ui-panel ui-filters ui-fbar ui-domain-tools">
            <div class="ui-fbar-row">
            <label class="ui-search">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                <input type="text" id="domain-search-input" placeholder="Search domains..." aria-label="Search domains" oninput="filterDomains()">
            </label>
            <label class="ui-check-label">
                <input type="checkbox" id="filter-issues-only" class="ui-check" onchange="filterDomains()">
                Show only domains with issues
            </label>
            </div>
        </section>
        <p class="ui-list-summary"><span id="domain-count-badge" class="ui-count">${uiCountLabel(domains.length, 'domain', 'domains')}</span><button type="button" class="ui-clear-filters hidden" onclick="clearDomainFilters()">Clear filters</button></p>
        <div id="domains-list" class="ui-table ui-stack ui-domain-table" data-sort-at="domain-search-input" data-sort-name="domains">
            ${renderDomainRows(domains)}
        </div>
        </div>
    `;

    // Store domains data for filtering
    window.domainsData = domains;
    uiFilterBarSync();
}

function clearDomainFilters() {
    const search = document.getElementById('domain-search-input');
    const issues = document.getElementById('filter-issues-only');
    if (search) search.value = '';
    if (issues) issues.checked = false;
    filterDomains();
}

function renderDomainRows(domains, open = new Set()) {
    return `
        <div class="ui-tr ui-tr-head"><span data-sort-kind="text">Domain</span>${DNS_CHECKS.map(([label]) => `<span data-sort-kind="text">${label}</span>`).join('')}<span class="ui-td-end" data-sort-kind="number">Storage</span></div>
        ${domains.map(domain => renderDomainAccordionRow(domain, open.has(domainRowId(domain.domain_name)))).join('')}`;
}

// What the user opened in the rows: domains, alias domains and the DNS
// details, to open again when the rows are drawn again
function domainsOpened(list) {
    const detailsKey = el => {
        const row = el.closest('[data-domain-row]');
        return row ? `${row.dataset.domainRow}|${[...row.querySelectorAll('details.ui-dns-more')].indexOf(el)}` : '';
    };
    return {
        rows: new Set([...list.querySelectorAll('.ui-domain-details:not(.hidden)')].map(el => el.id.replace(/-details$/, ''))),
        aliases: new Set([...list.querySelectorAll('[id^="alias-domain-"]:not(.hidden)')].map(el => el.id)),
        details: new Set([...list.querySelectorAll('details.ui-dns-more[open]')].map(detailsKey)),
        reopen() {
            this.aliases.forEach(id => document.getElementById(id)?.classList.remove('hidden'));
            list.querySelectorAll('details.ui-dns-more').forEach(el => { if (this.details.has(detailsKey(el))) el.open = true; });
        },
    };
}

// Filter domains based on search input and issues checkbox
function filterDomains() {
    const searchInput = document.getElementById('domain-search-input');
    const issuesFilter = document.getElementById('filter-issues-only');
    const domainsList = document.getElementById('domains-list');
    const countBadge = document.getElementById('domain-count-badge');

    if (!searchInput || !domainsList || !window.domainsData) return;

    const searchTerm = searchInput.value.toLowerCase().trim();
    const showIssuesOnly = issuesFilter ? issuesFilter.checked : false;

    const filteredDomains = window.domainsData.filter(domain =>
        domain.domain_name.toLowerCase().includes(searchTerm) && (!showIssuesOnly || domainHasIssues(domain)));

    if (countBadge) {
        countBadge.textContent = uiCountLabel(filteredDomains.length, 'domain', 'domains');
    }
    uiFilterBarSync();

    if (filteredDomains.length === 0) {
        const noResultsMessage = showIssuesOnly && searchTerm === ''
            ? 'No domains with DNS issues found'
            : `No domains found matching "${escapeHtml(searchTerm)}"`;
        domainsList.innerHTML = `<p class="ui-empty">${noResultsMessage}</p>`;
    } else {
        // Open rows stay open, the row in view stays where it was, and the focus on its row
        const opened = domainsOpened(domainsList);
        uiKeepRowInView(domainsList, '[data-domain-row]', 'data-domain-row', () => uiKeepFocus(domainsList, 'data-domain-row', () => {
            domainsList.innerHTML = renderDomainRows(filteredDomains, opened.rows);
            opened.reopen();
        }));
    }
}

// On a phone a result in the list is an icon with its own shape (check, exclamation mark,
// cross), so it reads without the colour and three fit a line; wider screens show the word.
// The icon carries the name of the result for screen readers.
const DNS_ICON = {
    ok: '<path d="M5 12.5l4.5 4.5L19 7.5"/>',
    warn: '<path d="M12 6v7.5"/><path d="M12 18h.01"/>',
    fail: '<path d="M7 7l10 10M17 7L7 17"/>',
};

function dnsStatusTag(label, check) {
    const [text, tone] = DNS_TAG[check.status] || ['Not checked', ''];
    const result = tone
        ? `${uiTag(text, tone)}<span class="ui-dns-icon ui-tag-${tone}" role="img" aria-label="${escapeHtml(`${label}: ${text}`)}"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${DNS_ICON[tone]}</svg></span>`
        : `<span class="ui-muted" role="img" aria-label="${escapeHtml(`${label}: ${text}`)}">-</span>`;
    return `<span class="ui-td ui-dns-cell" title="${escapeHtml(`${label}: ${check.message || 'Not checked'}`)}"><small class="ui-sec-unit" aria-hidden="true">${label} </small>${result}</span>`;
}

function renderDomainDnsSection(domain) {
    const dns = domain.dns_checks || {};
    const checks = DNS_CHECKS.map(([label, key]) => renderDNSCheck(label, dns[key] || { status: 'unknown', message: 'Not checked' })).join('');
    return `
        <div class="ui-list-head">
            <h4 class="ui-md-h">DNS Security Records</h4>
            <span class="ui-muted ui-head-actions" title="${dns.checked_at ? escapeHtml(formatTime(dns.checked_at)) : ''}">${dns.checked_at ? `Updated ${formatAgo(dns.checked_at)}` : 'Not checked yet'}</span>
            <button data-domain="${escapeHtml(domain.domain_name)}"
                onclick="event.stopPropagation(); checkSingleDomainDNS(this.dataset.domain)"
                class="ui-btn ui-btn-sm" title="Check DNS for this domain">Check</button>
        </div>
        <div class="ui-dns-grid">${checks}</div>
        ${(domain.alias_domains || []).length ? `
            <div class="ui-subsection">
                <h4 class="ui-md-h">Alias domains</h4>
                <p class="ui-muted ui-dns-note">These domains deliver to the same mailboxes and send with their own DNS records</p>
                ${domain.alias_domains.map(ad => renderAliasDomain(ad)).join('')}
            </div>
        ` : ''}`;
}

function renderDomainAccordionRow(domain, open = false) {
    const dns = domain.dns_checks || {};
    const domainId = domainRowId(domain.domain_name);
    const issues = domainHasIssues(domain);
    // On a phone a fact with a short note keeps it on the value's line
    const fact = (label, value, note) => `<div class="ui-md-fact${note ? ' ui-md-fact-inline' : ''}"><span>${label}</span><div>${escapeHtml(value)}</div>${note ? `<small class="ui-muted">${escapeHtml(note)}</small>` : ''}</div>`;

    return `
        <div class="ui-tr ui-domain-row" data-domain-row="${escapeHtml(domain.domain_name)}" data-sort-id="${escapeHtml(domain.domain_name)}" onclick="if (!uiRowHeld(event)) toggleDomainDetails('${escapeJsArg(domainId)}')">
            <div class="ui-td ui-q-who">
                <div>
                    <button type="button" class="ui-row-chev" aria-expanded="${open}" aria-controls="${domainId}-details" aria-label="Details of ${escapeHtml(domain.domain_name)}" onclick="event.stopPropagation(); toggleDomainDetails('${escapeJsArg(domainId)}')"><svg id="${domainId}-icon-desktop" class="ui-domain-chevron" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"${open ? ' style="transform: rotate(90deg)"' : ''}><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg></button>
                    ${uiEntity('domain', domain.domain_name)}
                    ${domain.active ? '' : uiTag('Inactive', '')}
                </div>
                <small>${escapeHtml(String(domain.mboxes_in_domain))} mailboxes, ${escapeHtml(String(domain.aliases_in_domain))} aliases${issues ? ', needs a DNS change' : ''}</small>
            </div>
            ${DNS_CHECKS.map(([label, key]) => dnsStatusTag(label, dns[key] || { status: 'unknown' })).join('')}
            <span class="ui-td ui-td-end ui-domain-storage"><small class="ui-sec-unit">Storage </small>${formatBytes(domain.bytes_total)}</span>
            <div id="${domainId}-details" class="ui-domain-details${open ? '' : ' hidden'}" data-tab="${domainTabs[domainId] || 'dns'}" onclick="event.stopPropagation()">
                <div class="ui-tabs ui-domain-tabs" role="tablist" aria-label="Domain">
                    ${[['dns', 'DNS checks'], ['info', 'Details']].map(([tab, label]) => `<button type="button" class="modal-tab${(domainTabs[domainId] || 'dns') === tab ? ' active' : ''}" role="tab" aria-selected="${(domainTabs[domainId] || 'dns') === tab}" onclick="domainShowTab('${escapeJsArg(domainId)}', '${tab}')">${label}</button>`).join('')}
                </div>
                <div class="ui-md-ids">
                    ${fact('Mailboxes', `${domain.mboxes_in_domain} / ${domain.max_num_mboxes_for_domain}`, `${domain.mboxes_left} available`)}
                    ${fact('Aliases', `${domain.aliases_in_domain} / ${domain.max_num_aliases_for_domain}`, `${domain.aliases_left} available`)}
                    ${fact('Storage Used', formatBytes(domain.bytes_total), domain.max_quota_for_domain > 0 ? `${formatBytes(domain.max_quota_for_domain)} max` : 'Unlimited')}
                    ${fact('Total Messages', Number(domain.msgs_total || 0).toLocaleString())}
                    ${fact('Created Date', domain.created ? formatDate(domain.created) : 'N/A')}
                    ${fact('Backup MX', domain.backupmx == 1 ? 'Yes' : 'No')}
                    ${fact('Relay All Recipients', domain.relay_all_recipients == 1 ? 'Yes' : 'No')}
                    ${fact('Relay Unknown Only', domain.relay_unknown_only == 1 ? 'Yes' : 'No')}
                </div>
                <div class="ui-dns-section">${renderDomainDnsSection(domain)}</div>
            </div>
        </div>
    `;
}

function domainShowTab(domainId, tab) {
    domainTabs[domainId] = tab;
    const details = document.getElementById(`${domainId}-details`);
    if (!details) return;
    details.dataset.tab = tab;
    details.querySelectorAll('.ui-domain-tabs .modal-tab').forEach((button, i) => {
        const on = (i === 0 ? 'dns' : 'info') === tab;
        button.classList.toggle('active', on);
        button.setAttribute('aria-selected', String(on));
    });
}

// Toggle domain details accordion
function toggleDomainDetails(domainId) {
    const details = document.getElementById(`${domainId}-details`);
    const icon = document.getElementById(`${domainId}-icon-desktop`);
    if (!details) return;
    const opening = details.classList.contains('hidden');
    details.classList.toggle('hidden', !opening);
    if (icon) icon.style.transform = opening ? 'rotate(90deg)' : 'rotate(0deg)';
    icon?.closest('.ui-row-chev')?.setAttribute('aria-expanded', String(opening));
}

// Label for an SPF checked_ips[].source value (per-check IP sources)
function spfIpSourceLabel(source) {
    if (source === 'configured') return 'Configured';
    if (source === 'auto-detected') return 'Auto-detected WAN';
    if (source === 'transport') return 'Transport';
    if (source === 'relayhost') return 'Relay host';
    if (source === 'dmarc-history') return 'DMARC history';
    return source || 'Unknown';
}

// Expandable list of the IPs validated against the SPF record.
// Cached DNS checks from before this field existed lack checked_ips.
function renderSpfCheckedIps(check) {
    const checkedIps = check.checked_ips;
    if (!Array.isArray(checkedIps) || checkedIps.length === 0) return '';

    const rows = checkedIps.map(entry => `
        <div class="ui-dns-ip">
            <div>
                <code>${uiEntity('ip', entry.ip || '', { mono: true })}</code>
                <small class="ui-muted">${escapeHtml(spfIpSourceLabel(entry.source))}</small>
            </div>
            ${entry.authorized ? uiTag('Authorized', 'ok') : uiTag('Not authorized', 'fail')}
        </div>
    `).join('');

    return `
        <details class="ui-dns-more" data-testid="spf-checked-ips">
            <summary>Checked IPs (${checkedIps.length})</summary>
            <div class="ui-dns-ips">${rows}</div>
        </details>
    `;
}

function renderAliasDomain(aliasDomain) {
    const dns = aliasDomain.dns_checks || {};
    const detailsId = `alias-domain-${aliasDomain.domain_name.replace(/[^a-z0-9]/gi, '-')}`;
    const checks = DNS_CHECKS.map(([label, key]) => [label, dns[key] || { status: 'unknown', message: 'Not checked yet' }]);

    return `
        <div class="ui-alias-domain">
            <button type="button" class="ui-alias-head" onclick="document.getElementById('${detailsId}').classList.toggle('hidden')">
                <span><b>${copyableText(aliasDomain.domain_name)}</b> ${uiTag('alias', 'info')}</span>
                <span class="ui-alias-checks">${checks.map(([label, check]) => `<span>${label} ${getAliasStatusIcon(check.status)}</span>`).join('')}</span>
            </button>
            <div id="${detailsId}" class="hidden ui-dns-grid">
                ${checks.map(([label, check]) => renderDNSCheck(label, check)).join('')}
            </div>
        </div>
    `;
}

function getAliasStatusIcon(status) {
    const [text, tone] = DNS_TAG[status] || ['?', ''];
    return `<i class="ui-mdot${tone ? ` ui-mdot-${tone}` : ''}" title="${escapeHtml(text)}" role="img" aria-label="${escapeHtml(text)}"></i>`;
}

function renderDNSCheck(type, check) {
    const status = check.status || 'unknown';
    const [text, tone] = DNS_TAG[status] || ['Not checked', ''];

    return `
        <div class="ui-dns-card${tone ? ` ui-dns-${tone}` : ''}">
            <div class="ui-dns-card-head"><b>${type}</b>${uiTag(text, tone)}</div>
            <p class="ui-dns-message">${escapeHtml(check.message || 'No information')}</p>

            ${check.record || check.actual_record ? `
                <details class="ui-dns-more">
                    <summary>View Record</summary>
                    <div class="ui-dns-code">
                        ${check.dkim_domain ? `<p><span class="ui-muted">Record Name:</span> <code>${copyableText(check.dkim_domain, 'ui-copy-wrap')}</code></p>` : ''}
                        <code>${copyableText(check.record || check.actual_record, 'ui-copy-wrap')}</code>
                    </div>
                </details>
            ` : ''}

            ${renderSpfCheckedIps(check)}

            ${check.warnings && check.warnings.length > 0 ? `
                <ul class="ui-dns-warnings">
                    ${check.warnings.map(warning => `<li>${escapeHtml(warning)}</li>`).join('')}
                </ul>
            ` : ''}

            ${check.info && check.info.length > 0 ? `
                <ul class="ui-dns-info">
                    ${check.info.map(info => `<li>${escapeHtml(info)}</li>`).join('')}
                </ul>
            ` : ''}

            ${check.status === 'error' && check.expected_record ? `
                <details class="ui-dns-more">
                    <summary>Expected Value</summary>
                    <div class="ui-dns-code"><code>${copyableText(check.expected_record, 'ui-copy-wrap')}</code></div>
                </details>
            ` : ''}
        </div>
    `;
}

let dnsCheckInProgress = false;

async function checkAllDomainsDNS() {
    if (dnsCheckInProgress) {
        showToast('DNS check already in progress', 'warning');
        return;
    }

    const button = document.getElementById('check-all-dns-btn');
    if (button) {
        button.disabled = true;
    }

    dnsCheckInProgress = true;

    try {
        const response = await authenticatedFetch('/api/domains/check-all-dns', {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'success') {
            showToast(`Checked ${result.domains_checked} domains`, 'success');
            setTimeout(() => loadDomains(), 1000);
        } else {
            showToast('DNS check failed', 'error');
        }
    } catch (error) {
        console.error('Failed:', error);
        showToast('Failed to check DNS', 'error');
    } finally {
        dnsCheckInProgress = false;
        if (button) {
            button.disabled = false;
        }
    }
}

async function checkSingleDomainDNS(domainName) {
    if (dnsCheckInProgress) {
        showToast('DNS check already in progress', 'warning');
        return;
    }

    dnsCheckInProgress = true;
    showToast(`Checking DNS for ${domainName}...`, 'info');

    try {
        const response = await authenticatedFetch(`/api/domains/${encodeURIComponent(domainName)}/check-dns`, {
            method: 'POST'
        });

        const result = await response.json();

        if (result.status === 'success') {
            showToast(`DNS checked for ${domainName}`, 'success');

            // Re-render only this domain's row, still open, with the new results
            const domainsResponse = await authenticatedFetch('/api/domains/all');
            const domainsData = await domainsResponse.json();
            const updatedDomain = (domainsData.domains || []).find(d => d.domain_name === domainName);
            const row = [...document.querySelectorAll('[data-domain-row]')].find(el => el.dataset.domainRow === domainName);
            if (updatedDomain) {
                if (Array.isArray(window.domainsData)) {
                    const index = window.domainsData.findIndex(d => d.domain_name === domainName);
                    if (index >= 0) window.domainsData[index] = updatedDomain;
                }
                if (row) row.outerHTML = renderDomainAccordionRow(updatedDomain, true);
            }
        } else {
            showToast(`Failed to check DNS for ${domainName}`, 'error');
        }
    } catch (error) {
        console.error('Failed:', error);
        showToast('Failed to check DNS', 'error');
    } finally {
        dnsCheckInProgress = false;
    }
}
