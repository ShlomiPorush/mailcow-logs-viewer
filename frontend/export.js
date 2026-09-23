// =============================================================================
// EXPORT CSV
// =============================================================================

async function exportCSV(type) {
    try {
        const filters = currentFilters[type] || {};
        const params = new URLSearchParams();
        for (const [key, value] of Object.entries(filters)) {
            if (value == null || (typeof value === 'string' && !value.trim())) continue;
            params.set(key, value);
        }

        const response = await authenticatedFetch(`/api/export/${type}/csv?${params}`, { method: 'HEAD' });
        if (!response.ok) {
            const message = response.status === 404
                ? 'No data to export. Try different filters.'
                : response.status === 422
                    ? 'Could not export CSV. Check the filters and try again.'
                    : 'Could not export CSV. Please try again.';
            throw new Error(message);
        }
        if (response.headers.get('content-type')?.split(';')[0].trim().toLowerCase() !== 'text/csv') {
            throw new Error('Could not export CSV. Refresh the page and try again.');
        }
        // The browser streams the file directly to its download manager.
        // Failures after this preflight are handled by the browser.
        const link = document.createElement('a');
        link.href = `/api/export/${type}/csv?${params}`;
        link.download = '';
        document.body.appendChild(link);
        link.click();
        link.remove();
        showToast('Download started.', 'success');
    } catch (error) {
        console.error('Failed to export CSV:', error);
        showToast(error.message || 'Could not export CSV. Please try again.', 'error');
    }
}

