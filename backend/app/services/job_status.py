from datetime import datetime, timezone

job_status = {
    'fetch_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'complete_correlations': {'last_run': None, 'status': 'idle', 'error': None},
    'update_final_status': {'last_run': None, 'status': 'idle', 'error': None},
    'expire_correlations': {'last_run': None, 'status': 'idle', 'error': None},
    'feature_data_sweep': {'last_run': None, 'status': 'idle', 'error': None},
    'trend_samples': {'last_run': None, 'status': 'idle', 'error': None},
    'correlate_dovecot': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_dmarc_reports': {'last_run': None, 'status': 'idle', 'error': None},
    'check_app_version': {'last_run': None, 'status': 'idle', 'error': None},
    'dns_check': {'last_run': None, 'status': 'idle', 'error': None},
    'update_geoip': {'last_run': None, 'status': 'idle', 'error': None},
    'check_credentials': {'last_run': None, 'status': 'idle', 'error': None},
    'dmarc_imap_sync': {'last_run': None, 'status': 'idle', 'error': None},
    'mailbox_stats': {'last_run': None, 'status': 'idle', 'error': None},
    'alias_stats': {'last_run': None, 'status': 'idle', 'error': None},
    'blacklist_check': {'last_run': None, 'status': 'idle', 'error': None},
    'send_weekly_summary': {'last_run': None, 'status': 'idle', 'error': None},
    'sync_transports': {'last_run': None, 'status': 'idle', 'error': None},
    'fetch_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_raw_logs': {'last_run': None, 'status': 'idle', 'error': None},
    'detect_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'sync_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'expire_suppressions': {'last_run': None, 'status': 'idle', 'error': None},
    'process_quarantine_rules': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_deferred_queue': {'last_run': None, 'status': 'idle', 'error': None},
    'anomaly_detection': {'last_run': None, 'status': 'idle', 'error': None},
    'smtp_abuse': {'last_run': None, 'status': 'idle', 'error': None},
    'protection_rules': {'last_run': None, 'status': 'idle', 'error': None},
    'eas_devices': {'last_run': None, 'status': 'idle', 'error': None},
    'cleanup_eas_devices': {'last_run': None, 'status': 'idle', 'error': None},
}


def update_job_status(job_name: str, status: str, error: str = None, retryable: bool = False) -> dict:
    entry = {
        'last_run': datetime.now(timezone.utc),
        'status': status,
        'error': error,
        'retryable': retryable,
    }
    job_status[job_name] = entry
    return entry
