// =============================================================================
// DEVICES - ActiveSync phones and tablets, recorded by the eas_devices job from
// SOGo's access log (/api/devices). The list is paged on the server, so its
// column headers sort there, like the suppression list.
// =============================================================================

let devicesPage = 1;
let devicesSort = { by: 'last_seen', dir: 'desc' };
let devicesRequest = 0;

function devicesSortAttr(key) {
    return ` data-sort-key="${key}" aria-sort="${devicesSort.by === key ? (devicesSort.dir === 'asc' ? 'ascending' : 'descending') : 'none'}"`;
}

function devicesSortBy(key, dir) {
    devicesSort = { by: key, dir };
    loadDevices(1);
}

function applyDevicesFilters() {
    loadDevices(1);
}

function resetDevicesFilters() {
    document.getElementById('devices-search').value = '';
    document.getElementById('devices-type-filter').value = '';
    document.getElementById('devices-seen-filter').value = 'all';
    devicesSort = { by: 'last_seen', dir: 'desc' };
    loadDevices(1);
}

async function loadDevices(page) {
    devicesPage = page || devicesPage || 1;
    const request = ++devicesRequest;
    const container = document.getElementById('devices-list');
    const search = document.getElementById('devices-search').value.trim();
    const type = document.getElementById('devices-type-filter').value;
    const seen = document.getElementById('devices-seen-filter').value;

    const params = new URLSearchParams({ page: devicesPage, per_page: 50, seen, sort_by: devicesSort.by, sort_dir: devicesSort.dir });
    if (search) params.append('search', search);
    if (type) params.append('device_type', type);

    try {
        const response = await authenticatedFetch(`/api/devices?${params}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        // A slower answer to an older filter must not replace a newer one
        if (request !== devicesRequest) return;
        renderDevicesSummary(data);
        renderDevicesTypes(data.device_types, type);
        renderDevicesList(container, data);
    } catch (error) {
        if (request !== devicesRequest) return;
        console.error('Failed to load devices:', error);
        container.innerHTML = `<p class="ui-empty ui-text-fail">Could not load the devices: ${escapeHtml(error.message)}. Try again in a moment.</p>`;
    }
}

function renderDevicesSummary(data) {
    const s = data.summary;
    document.getElementById('devices-kpi-total').textContent = s.devices.toLocaleString();
    document.getElementById('devices-kpi-users').textContent = `${s.users.toLocaleString()} ${s.users === 1 ? 'user' : 'users'}`;
    document.getElementById('devices-kpi-recent').textContent = s.recent.toLocaleString();
    document.getElementById('devices-kpi-new').textContent = s.new.toLocaleString();
    document.getElementById('devices-kpi-stale').textContent = s.stale.toLocaleString();
    document.getElementById('devices-kpi-retention').textContent = data.retention_days > 0
        ? `Removed after ${data.retention_days} days` : 'Kept forever';

    const note = document.getElementById('devices-last-update');
    if (data.last_status === 'failed') {
        note.innerHTML = '<span class="ui-text-warn">The last check failed. See Status → Background Jobs.</span>';
    } else {
        note.textContent = data.last_run ? `Checked ${formatAgo(data.last_run)}` : 'Not checked yet';
        note.title = data.last_run ? formatTime(data.last_run) : '';
    }
}

// Keep the picked type even when the list of types changes under it
function renderDevicesTypes(types, picked) {
    const select = document.getElementById('devices-type-filter');
    const all = [...new Set([...(types || []), ...(picked ? [picked] : [])])];
    select.innerHTML = '<option value="">All device types</option>'
        + all.map(t => `<option value="${escapeHtml(t)}">${escapeHtml(t)}</option>`).join('');
    select.value = picked;
}

function renderDevicesList(container, data) {
    const pager = document.getElementById('devices-pager');
    document.getElementById('devices-count').textContent = `${data.total.toLocaleString()} ${data.total === 1 ? 'device' : 'devices'}`;
    pager.innerHTML = data.total_pages > 1 ? `
        <nav class="ui-pager" aria-label="Device pages">
            ${data.page > 1 ? `<button onclick="loadDevices(${data.page - 1})" class="ui-btn ui-btn-sm">← Prev</button>` : ''}
            <span class="ui-muted">Page ${data.page}/${data.total_pages}</span>
            ${data.page < data.total_pages ? `<button onclick="loadDevices(${data.page + 1})" class="ui-btn ui-btn-sm">Next →</button>` : ''}
        </nav>` : '';

    if (!data.items.length) {
        container.innerHTML = data.summary.devices === 0 ? `
            <div class="ui-empty">
                <p><b>No ActiveSync devices yet</b></p>
                <p>A phone, tablet or Outlook appears here after its first sync over ActiveSync. The SOGo log is read every minute.</p>
            </div>` : `
            <div class="ui-empty">
                <p><b>No devices match these filters</b></p>
                <p><button onclick="resetDevicesFilters()" class="ui-btn ui-btn-sm">Reset filters</button></p>
            </div>`;
        return;
    }

    // Locked, not hidden: say what the location needs instead of leaving it out
    const geoNote = data.geoip ? '' : `<div class="ui-list-note ui-flush">${uiLocked('Location needs GeoIP',
        'The country, city and network of each address come from the MaxMind GeoIP databases. Add the MaxMind keys in Settings → MaxMind.')}</div>`;
    const newAfter = Date.now() - data.thresholds.new_days * 86400000;
    const staleBefore = Date.now() - data.thresholds.stale_days * 86400000;
    container.innerHTML = `${geoNote}
        <div class="ui-table ui-stack" data-sort-handler="devicesSortBy" style="--ui-cols: minmax(200px, 1.6fr) minmax(170px, 1.4fr) minmax(120px, 1fr) minmax(120px, 1fr) 100px 100px; --ui-table-min: 880px">
            <div class="ui-tr ui-tr-head"><span${devicesSortAttr('username')}>User</span><span${devicesSortAttr('device_type')}>Device</span><span${devicesSortAttr('last_ip')}>Last IP</span><span${devicesSortAttr('last_command')}>Last request</span><span${devicesSortAttr('first_seen')}>First seen</span><span${devicesSortAttr('last_seen')}>Last seen</span></div>
            ${data.items.map(d => renderDeviceRow(d, newAfter, staleBefore)).join('')}
        </div>`;
}

function deviceStatusTag(status) {
    if (!status || status < 400) return '';
    const label = status === 401 ? 'Sign-in failed' : status === 403 ? 'Refused' : `Error ${status}`;
    return `<span class="ui-tag ui-tag-fail" title="SOGo answered HTTP ${Number(status)}">${label}</span>`;
}

// Flag, then "Country, City"; the network (ASN) in the tooltip
function deviceLocation(d) {
    const place = [d.country_name, d.city].filter(Boolean).join(', ');
    if (!place) return '';
    const flag = d.country_code ? getFlagUrl(d.country_code, '16x12') : '';
    const network = [d.asn, d.asn_org].filter(Boolean).join(' ');
    return `<small${network ? ` title="${escapeHtml(network)}"` : ''}>${flag ? `<img class="ui-sec-flag" src="${flag}" alt="" width="16" height="12" onerror="this.remove()">` : ''}${escapeHtml(place)}</small>`;
}

function renderDeviceRow(d, newAfter, staleBefore) {
    const isNew = new Date(d.first_seen).getTime() >= newAfter;
    const isStale = new Date(d.last_seen).getTime() < staleBefore;
    return `
        <div class="ui-tr">
            <span class="ui-td">${copyableText(d.username)}</span>
            <div class="ui-td ui-q-who">
                <div><bdi>${escapeHtml(d.device_type || 'Unknown device')}</bdi> ${isNew ? uiTag('New', 'info') : ''}</div>
                <small>${copyableText(d.device_id, 'ui-mono')}</small>
            </div>
            <div class="ui-td ui-q-who"><div><small class="ui-sec-unit">IP </small>${d.last_ip ? copyableText(d.last_ip, 'ui-mono') : '<span class="ui-muted">-</span>'}</div>${deviceLocation(d)}</div>
            <span class="ui-td ui-td-wrap"><small class="ui-sec-unit">Last request </small>${escapeHtml(d.last_command || '-')} ${deviceStatusTag(d.last_status)}</span>
            <span class="ui-td" title="${escapeHtml(formatTime(d.first_seen))}"><small class="ui-sec-unit">First seen </small>${formatAgo(d.first_seen)}</span>
            <span class="ui-td${isStale ? ' ui-muted' : ''}" title="${escapeHtml(formatTime(d.last_seen))}"><small class="ui-sec-unit">Last seen </small>${formatAgo(d.last_seen)}</span>
        </div>`;
}
