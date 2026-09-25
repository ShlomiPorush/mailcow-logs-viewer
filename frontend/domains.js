// =============================================================================
// DOMAINS - domain list, DNS validation (SPF/DKIM/DMARC checks)
// =============================================================================
// Split out of app.js (phase 5). Classic script sharing the global scope;
// loaded after utils.js and app.js in index.html.

// =============================================================================
// DOMAINS TAB - Domains management with DNS validation
// =============================================================================

const DNS_CHECKS = [['SPF', 'spf'], ['DKIM', 'dkim'], ['DMARC', 'dmarc'], ['TLSA', 'tlsa'], ['MTA-STS', 'mta_sts']];
const DNS_TAG = {
    success: ['OK', 'ok'],
    warning: ['Warning', 'warn'],
    error: ['Error', 'fail'],
};

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
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        renderDomains(content, data);

        loading.classList.add('hidden');
        content.classList.remove('hidden');

    } catch (error) {
        console.error('Failed to load domains:', error);
        loading.innerHTML = `
            <div class="ui-empty ui-panel">
                <p class="ui-text-fail">Failed to load domains</p>
                <p>${escapeHtml(error.message)}</p>
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
    return `domain-${escapeHtml(domainName).replace(/\./g, '-')}`;
}

function renderDomains(container, data) {
    const domains = data.domains || [];

    const dnsCheckInfo = document.getElementById('dns-check-info');
    if (dnsCheckInfo) {
        const lastCheck = data.last_dns_check ? formatTime(data.last_dns_check) : 'Never';
        dnsCheckInfo.innerHTML = `
            <span class="ui-muted" title="${data.last_dns_check ? escapeHtml(formatTime(data.last_dns_check)) : ''}">Last checked: ${data.last_dns_check ? formatAgo(data.last_dns_check) : escapeHtml(lastCheck)}</span>
            <button id="check-all-dns-btn" onclick="checkAllDomainsDNS()" class="ui-btn ui-btn-primary">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path></svg>
                Check Now
            </button>
        `;
    }

    const summary = document.getElementById('domains-summary');
    if (summary) {
        const total = data.total || domains.length;
        const inactive = (data.total || 0) - (data.active || 0);
        const issues = domains.filter(domainHasIssues).length;
        summary.textContent = `${total} ${total === 1 ? 'domain' : 'domains'}${inactive > 0 ? `, ${inactive} inactive` : ''}. ${issues ? `${issues} ${issues === 1 ? 'needs' : 'need'} a DNS change.` : 'DNS looks right.'}`;
    }

    if (domains.length === 0) {
        container.innerHTML = '<p class="ui-empty ui-panel">No domains found</p>';
        return;
    }

    container.innerHTML = `
        <div class="ui-list-head ui-domain-tools">
            <label class="ui-search">
                <svg width="16" height="16" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg>
                <input type="text" id="domain-search-input" placeholder="Search domains..." aria-label="Search domains" oninput="filterDomains()">
            </label>
            <span id="domain-count-badge" class="ui-count">${domains.length} domains</span>
            <label class="ui-check-label">
                <input type="checkbox" id="filter-issues-only" class="ui-check" onchange="filterDomains()">
                Show only domains with issues
            </label>
        </div>
        <div id="domains-list" class="ui-table ui-stack ui-domain-table">
            ${renderDomainRows(domains)}
        </div>
    `;

    // Store domains data for filtering
    window.domainsData = domains;
}

function renderDomainRows(domains) {
    return `
        <div class="ui-tr ui-tr-head"><span>Domain</span>${DNS_CHECKS.map(([label]) => `<span>${label}</span>`).join('')}<span class="ui-td-end">Storage</span></div>
        ${domains.map(domain => renderDomainAccordionRow(domain)).join('')}`;
}

// Filter domains based on search input and issues checkbox
function filterDomains() {
    const searchInput = document.getElementById('domain-search-input');
    const issuesCheckbox = document.getElementById('filter-issues-only');
    const domainsList = document.getElementById('domains-list');
    const countBadge = document.getElementById('domain-count-badge');

    if (!searchInput || !domainsList || !window.domainsData) return;

    const searchTerm = searchInput.value.toLowerCase().trim();
    const showIssuesOnly = issuesCheckbox ? issuesCheckbox.checked : false;

    const filteredDomains = window.domainsData.filter(domain =>
        domain.domain_name.toLowerCase().includes(searchTerm) && (!showIssuesOnly || domainHasIssues(domain)));

    if (countBadge) {
        countBadge.textContent = `${filteredDomains.length} domain${filteredDomains.length !== 1 ? 's' : ''}`;
    }

    if (filteredDomains.length === 0) {
        const noResultsMessage = showIssuesOnly && searchTerm === ''
            ? 'No domains with DNS issues found'
            : `No domains found matching "${escapeHtml(searchTerm)}"`;
        domainsList.innerHTML = `<p class="ui-empty">${noResultsMessage}</p>`;
    } else {
        domainsList.innerHTML = renderDomainRows(filteredDomains);
    }
}

function dnsStatusTag(label, check) {
    const [text, tone] = DNS_TAG[check.status] || ['-', ''];
    return `<span class="ui-td" title="${escapeHtml(`${label}: ${check.message || 'Not checked'}`)}"><small class="ui-sec-unit">${label} </small>${tone ? uiTag(text, tone) : '<span class="ui-muted">-</span>'}</span>`;
}

function renderDomainDnsSection(domain) {
    const dns = domain.dns_checks || {};
    const checks = DNS_CHECKS.map(([label, key]) => renderDNSCheck(label, dns[key] || { status: 'unknown', message: 'Not checked' })).join('');
    return `
        <div class="ui-list-head">
            <h4 class="ui-md-h">DNS Security Records</h4>
            <span class="ui-muted ui-head-actions" title="${dns.checked_at ? escapeHtml(formatTime(dns.checked_at)) : ''}">Last checked: ${dns.checked_at ? formatAgo(dns.checked_at) : 'Not checked'}</span>
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
    const fact = (label, value, note) => `<div class="ui-md-fact"><span>${label}</span><div>${value}</div>${note ? `<small class="ui-muted">${note}</small>` : ''}</div>`;

    return `
        <div class="ui-tr ui-domain-row" data-domain-row="${escapeHtml(domain.domain_name)}" onclick="toggleDomainDetails('${domainId}')">
            <div class="ui-td ui-q-who">
                <div>
                    <svg id="${domainId}-icon-desktop" class="ui-domain-chevron" width="14" height="14" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true"${open ? ' style="transform: rotate(90deg)"' : ''}><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"></path></svg>
                    ${escapeHtml(domain.domain_name)}
                    ${domain.active ? '' : uiTag('Inactive', '')}
                </div>
                <small>${domain.mboxes_in_domain} mailboxes, ${domain.aliases_in_domain} aliases${issues ? ', needs a DNS change' : ''}</small>
            </div>
            ${DNS_CHECKS.map(([label, key]) => dnsStatusTag(label, dns[key] || { status: 'unknown' })).join('')}
            <span class="ui-td ui-td-end"><small class="ui-sec-unit">Storage </small>${formatBytes(domain.bytes_total)}</span>
            <div id="${domainId}-details" class="ui-domain-details${open ? '' : ' hidden'}" onclick="event.stopPropagation()">
                <div class="ui-md-ids">
                    ${fact('Mailboxes', `${domain.mboxes_in_domain} / ${domain.max_num_mboxes_for_domain}`, `${domain.mboxes_left} available`)}
                    ${fact('Aliases', `${domain.aliases_in_domain} / ${domain.max_num_aliases_for_domain}`, `${domain.aliases_left} available`)}
                    ${fact('Storage Used', formatBytes(domain.bytes_total), domain.max_quota_for_domain > 0 ? `${formatBytes(domain.max_quota_for_domain)} max` : 'Unlimited')}
                    ${fact('Total Messages', (domain.msgs_total || 0).toLocaleString())}
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

// Toggle domain details accordion
function toggleDomainDetails(domainId) {
    const details = document.getElementById(`${domainId}-details`);
    const icon = document.getElementById(`${domainId}-icon-desktop`);
    if (!details) return;
    const opening = details.classList.contains('hidden');
    details.classList.toggle('hidden', !opening);
    if (icon) icon.style.transform = opening ? 'rotate(90deg)' : 'rotate(0deg)';
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
                <code>${escapeHtml(entry.ip || '')}</code>
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
                <span><b>${escapeHtml(aliasDomain.domain_name)}</b> ${uiTag('alias', 'info')}</span>
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
    return `<i class="ui-mdot${tone ? ` ui-mdot-${tone}` : ''}" title="${escapeHtml(text)}"></i>`;
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
                        ${check.dkim_domain ? `<p><span class="ui-muted">Record Name:</span> <code>${escapeHtml(check.dkim_domain)}</code></p>` : ''}
                        <code>${escapeHtml(check.record || check.actual_record)}</code>
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
                    <div class="ui-dns-code"><code>${escapeHtml(check.expected_record)}</code></div>
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
            showToast(`✓ Checked ${result.domains_checked} domains`, 'success');
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
            showToast(`✓ DNS checked for ${domainName}`, 'success');

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
