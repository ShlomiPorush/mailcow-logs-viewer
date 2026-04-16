"""
Mailcow API client for fetching logs
Handles authentication and API calls to mailcow instance
"""
import httpx
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings

logger = logging.getLogger(__name__)


class MailcowAPIError(Exception):
    """Custom exception for mailcow API errors"""
    pass


class MailcowAPI:
    """Client for interacting with mailcow API"""
    
    def __init__(self):
        self._update_config()
        logger.info(f"mailcow API client initialized for {self.base_url} (SSL verification: {self.verify_ssl})")
    
    def _update_config(self):
        """Update configuration from settings (supports dynamic reload)"""
        self.base_url = settings.mailcow_url
        self.api_key = settings.mailcow_api_key
        self.api_key_rw = settings.mailcow_api_key_rw
        self.timeout = settings.mailcow_api_timeout
        self.verify_ssl = settings.mailcow_api_verify_ssl
        
        # Setup headers for read-only operations
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        
        # Setup headers for read-write operations
        if self.api_key_rw:
            self.headers_rw = {
                "X-API-Key": self.api_key_rw,
                "Content-Type": "application/json"
            }
        else:
            self.headers_rw = None
    
    def reload_config(self):
        """Reload configuration from settings (call after settings are updated)"""
        old_url = self.base_url
        self._update_config()
        if old_url != self.base_url:
            logger.info(f"mailcow API client configuration reloaded: {old_url} -> {self.base_url}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _make_request(self, endpoint: str, method: str = "GET", **kwargs) -> Any:
        """
        Make HTTP request to mailcow API with retry logic
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments for httpx
        
        Returns:
            JSON response from API
        
        Raises:
            MailcowAPIError: If request fails
        """
        url = f"{self.base_url}{endpoint}"
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            try:
                response = await client.request(
                    method=method,
                    url=url,
                    headers=self.headers,
                    **kwargs
                )
                response.raise_for_status()
                return response.json()
                
            except httpx.HTTPStatusError as e:
                logger.error(f"HTTP error {e.response.status_code} for {url}: {e}")
                raise MailcowAPIError(f"API returned status {e.response.status_code}")
            except httpx.RequestError as e:
                logger.error(f"Request error for {url}: {e}")
                raise MailcowAPIError(f"Failed to connect to mailcow API: {e}")
            except Exception as e:
                logger.error(f"Unexpected error for {url}: {e}")
                raise MailcowAPIError(f"Unexpected error: {e}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    async def _make_rw_request(self, endpoint: str, method: str = "POST", **kwargs) -> Any:
        """
        Make HTTP request to mailcow API using the Read-Write API key.
        Used exclusively for edit/update operations.
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method (POST, PUT, DELETE, etc.)
            **kwargs: Additional arguments for httpx
        
        Returns:
            JSON response from API
        
        Raises:
            MailcowAPIError: If request fails or RW key is not configured
        """
        if not self.headers_rw:
            raise MailcowAPIError(
                "Read-Write API key (MAILCOW_API_KEY_RW) is not configured. "
                "Edit operations require a separate API key with write permissions."
            )
        
        url = f"{self.base_url}{endpoint}"
        
        async with httpx.AsyncClient(timeout=self.timeout, verify=self.verify_ssl) as client:
            try:
                response = await client.request(
                    method,
                    url,
                    headers=self.headers_rw,
                    **kwargs
                )
                
                if response.status_code == 401:
                    raise MailcowAPIError("Read-Write API key authentication failed (401)")
                
                if response.status_code == 403:
                    raise MailcowAPIError("Read-Write API key does not have sufficient permissions (403)")
                
                response.raise_for_status()
                
                if response.headers.get('content-type', '').startswith('application/json'):
                    return response.json()
                return response.text
                
            except httpx.HTTPStatusError as e:
                raise MailcowAPIError(f"RW API request failed with status {e.response.status_code}: {e.response.text}")
            except httpx.RequestError as e:
                raise MailcowAPIError(f"RW API request failed: {str(e)}")

    async def get_postfix_logs(self, count: int = 500) -> List[Dict[str, Any]]:
        """
        Fetch Postfix logs from mailcow
        
        Args:
            count: Number of logs to fetch
        
        Returns:
            List of log entries
        """
        logger.info(f"Fetching {count} Postfix logs")
        try:
            data = await self._make_request(f"/api/v1/get/logs/postfix/{count}")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected Postfix response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} Postfix logs")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Postfix logs: {e}")
            return []
    
    async def get_rspamd_logs(self, count: int = 500) -> List[Dict[str, Any]]:
        """
        Fetch Rspamd history from mailcow
        
        Args:
            count: Number of logs to fetch
        
        Returns:
            List of log entries
        """
        logger.info(f"Fetching {count} Rspamd logs")
        try:
            data = await self._make_request(f"/api/v1/get/logs/rspamd-history/{count}")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected Rspamd response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} Rspamd logs")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Rspamd logs: {e}")
            return []
    
    async def get_netfilter_logs(self, count: int = 500) -> List[Dict[str, Any]]:
        """
        Fetch Netfilter logs from mailcow
        
        Args:
            count: Number of logs to fetch
        
        Returns:
            List of log entries
        """
        logger.info(f"Fetching {count} Netfilter logs")
        try:
            data = await self._make_request(f"/api/v1/get/logs/netfilter/{count}")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected Netfilter response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} Netfilter logs")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Netfilter logs: {e}")
            return []
    
    # Allowed services for the raw logs viewer
    ALLOWED_RAW_LOG_SERVICES = frozenset([
        "acme", "api", "autodiscover", "dovecot", "netfilter",
        "postfix", "ratelimited", "rspamd-history", "sogo", "watchdog"
    ])

    async def get_raw_logs(self, service: str, count: int = 1000) -> List[Dict[str, Any]]:
        """
        Fetch raw logs for any mailcow service.
        Used by the Raw Logs Worker for background ingestion.
        
        Args:
            service: Service name (e.g., 'postfix', 'dovecot', 'sogo')
            count: Number of logs to fetch
        
        Returns:
            List of raw log entries as returned by the mailcow API
        """
        if service not in self.ALLOWED_RAW_LOG_SERVICES:
            logger.warning(f"Unknown raw log service requested: {service}")
            return []
        
        logger.debug(f"Fetching {count} raw logs for service: {service}")
        try:
            data = await self._make_request(f"/api/v1/get/logs/{service}/{count}")
            
            if isinstance(data, dict):
                # Some services return a dict when no logs exist (e.g., {"type":"error"})
                # This is normal — not all services have logs on every mailcow instance
                logger.debug(f"Service '{service}' returned dict (no logs available), skipping")
                return []
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected {service} raw log response format: {type(data)}")
                return []
            
            logger.debug(f"Retrieved {len(data)} raw logs for {service}")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch raw logs for {service}: {e}")
            return []
    
    async def get_queue(self) -> List[Dict[str, Any]]:
        """
        Fetch current mail queue from mailcow (real-time)
        
        Returns:
            List of queued messages
        """
        logger.info("Fetching mail queue")
        try:
            data = await self._make_request("/api/v1/get/mailq/all")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected queue response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} queue entries")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch queue: {e}")
            return []

    async def edit_queue(self, item_ids: List[str], action: str) -> Any:
        """
        Edit mail queue items on mailcow using the Read-Write API key.
        
        Args:
            item_ids: List of queue item IDs (queue_id) or ["mailqitems-all"] for bulk
            action: Action to perform - deliver, hold, unhold, flush
        
        Returns:
            Response from mailcow API
        """
        logger.info(f"Editing queue items: {item_ids} with action: {action}")
        payload = {
            "items": item_ids,
            "attr": {
                "action": action
            }
        }
        data = await self._make_rw_request(
            "/api/v1/edit/mailq",
            method="POST",
            json=payload
        )
        logger.info(f"Queue edit response: {data}")
        return data

    async def delete_queue(self, item_ids: List[str]) -> Any:
        """
        Delete mail queue items on mailcow using the Read-Write API key.
        
        Args:
            item_ids: List of queue item IDs (queue_id) or ["mailqitems-all"] with super_delete
        
        Returns:
            Response from mailcow API
        """
        logger.info(f"Deleting queue items: {item_ids}")
        data = await self._make_rw_request(
            "/api/v1/delete/mailq",
            method="POST",
            json=item_ids
        )
        logger.info(f"Queue delete response: {data}")
        return data
    
    async def get_quarantine(self) -> List[Dict[str, Any]]:
        """
        Fetch quarantined messages from mailcow (real-time)
        
        Returns:
            List of quarantined messages
        """
        logger.info("Fetching quarantine")
        try:
            data = await self._make_request("/api/v1/get/quarantine/all")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected quarantine response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} quarantine entries")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch quarantine: {e}")
            return []

    async def get_status_containers(self) -> List[Dict[str, Any]]:
        """
        Fetch container status from mailcow
        
        mailcow API returns: [{"container1": {...}, "container2": {...}}]
        
        Returns:
            List of container status information
        """
        logger.info("Fetching container status")
        try:
            data = await self._make_request("/api/v1/get/status/containers")
            
            # mailcow returns: [{ "watchdog-mailcow": {...}, "acme-mailcow": {...}, ... }]
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                # Extract the first dict from the list
                containers_dict = data[0]
                logger.info(f"Retrieved status for {len(containers_dict)} containers")
                return [containers_dict]  # Return as-is wrapped in list
            elif isinstance(data, dict):
                # If it's already a dict, wrap it
                logger.info(f"Retrieved status for {len(data)} containers (dict format)")
                return [data]
            else:
                logger.warning(f"Unexpected containers response: {type(data)}")
                return []
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch container status: {e}")
            return []

    async def get_status_vmail(self) -> Dict[str, Any]:
        """
        Fetch vmail disk usage from mailcow
        
        mailcow API returns: [{"type": "info", "disk": "/dev/sdb1", ...}]
        
        Returns:
            Dictionary with disk usage information
        """
        logger.info("Fetching vmail status")
        try:
            data = await self._make_request("/api/v1/get/status/vmail")
            
            # mailcow returns: [{"type": "info", "disk": "/dev/sdb1", "used": "14G", ...}]
            if isinstance(data, list) and len(data) > 0:
                logger.info("Retrieved vmail status")
                return data[0]  # Return first element
            elif isinstance(data, dict):
                logger.info("Retrieved vmail status (dict format)")
                return data
            else:
                logger.warning(f"Unexpected vmail response: {type(data)}")
                return {}
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch vmail status: {e}")
            return {}
    
    async def get_status_version(self) -> str:
        """
        Fetch mailcow version
        
        Returns:
            Version string
        """
        logger.info("Fetching mailcow version")
        try:
            data = await self._make_request("/api/v1/get/status/version")
            
            # Handle different response formats
            if isinstance(data, str):
                return data.strip()
            
            if isinstance(data, dict):
                return data.get('version', 'unknown')
                
            if isinstance(data, list):
                if len(data) > 0:
                    if isinstance(data[0], dict):
                        return data[0].get('version', 'unknown')
                    return str(data[0])
            
            logger.warning(f"Unexpected version response format: {type(data)} - {data}")
            return 'unknown'
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch version: {e}")
            return 'unknown'
    
    async def get_domains(self) -> List[Dict[str, Any]]:
        """
        Fetch all domains from mailcow
        
        Returns:
            List of domains
        """
        logger.info("Fetching domains")
        try:
            data = await self._make_request("/api/v1/get/domain/all")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected domains response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} domains")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch domains: {e}")
            return []
    
    async def get_active_domains(self) -> List[str]:
        """
        Fetch active domains from mailcow and return domain names only
        
        Returns:
            List of active domain names (where active=1)
        """
        logger.info("Fetching active domains")
        try:
            domains = await self.get_domains()
            
            # Filter active domains and extract domain_name
            active_domains = [
                domain.get('domain_name', '')
                for domain in domains
                if domain.get('active') == 1 and domain.get('domain_name')
            ]
            
            logger.info(f"Found {len(active_domains)} active domains: {', '.join(active_domains)}")
            return active_domains
            
        except Exception as e:
            logger.error(f"Failed to fetch active domains: {e}")
            return []
    
    async def get_alias_domains(self) -> List[str]:
        """
        Fetch active alias domains from mailcow (alias_domain -> target_domain).
        Returns list of alias domain names that are
        configured as alias of a primary domain. Used so mail from these is
        treated as outbound/local.
        
        Returns:
            List of active alias domain names
        """
        logger.info("Fetching alias domains")
        try:
            data = await self._make_request("/api/v1/get/alias-domain/all")
            if isinstance(data, dict):
                if not data:
                    logger.info("No alias domains found (empty dict)")
                    return []
                logger.warning(f"Unexpected alias-domain dict response: {data}")
                return []
            if not isinstance(data, list):
                logger.warning(f"Unexpected alias-domain response format: {type(data)}")
                return []
            active = [
                item.get('alias_domain', '')
                for item in data
                if item.get('active', 0) == 1 and item.get('alias_domain')
            ]
            if active:
                logger.info(f"Found {len(active)} active alias domains: {', '.join(active)}")
            return active
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch alias domains: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to fetch alias domains: {e}")
            return []
    
    async def get_mailboxes(self) -> List[Dict[str, Any]]:
        """
        Fetch all mailboxes from mailcow
        
        Returns:
            List of mailboxes
        """
        logger.info("Fetching mailboxes")
        try:
            data = await self._make_request("/api/v1/get/mailbox/all")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected mailboxes response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} mailboxes")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch mailboxes: {e}")
            return []
    
    async def get_aliases(self) -> List[Dict[str, Any]]:
        """
        Fetch all aliases from mailcow
        
        Returns:
            List of aliases
        """
        logger.info("Fetching aliases")
        try:
            data = await self._make_request("/api/v1/get/alias/all")
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected aliases response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} aliases")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch aliases: {e}")
            return []
    
    async def test_connection(self) -> bool:
        """
        Test connection to mailcow API
        
        Returns:
            True if connection successful, False otherwise
        """
        logger.info("Testing mailcow API connection")
        try:
            # Try to fetch a small number of logs to test
            await self._make_request("/api/v1/get/logs/postfix/1")
            logger.info("mailcow API connection test: SUCCESS")
            return True
        except MailcowAPIError as e:
            logger.error(f"mailcow API connection test: FAILED - {e}")
            return False
    
    async def get_status_host_ip(self) -> Optional[str]:
        """
        Fetch server IP address from mailcow
        
        Returns:
            IPv4 address string or None if not found
        """
        logger.info("Fetching server IP address")
        try:
            data = await self._make_request("/api/v1/get/status/host/ip")
            
            # Handle different response formats
            if isinstance(data, list) and len(data) > 0:
                ip = data[0].get('ipv4')
                if ip:
                    logger.info(f"Retrieved server IP: {ip}")
                    return ip
            elif isinstance(data, dict):
                ip = data.get('ipv4')
                if ip:
                    logger.info(f"Retrieved server IP: {ip}")
                    return ip
            
            logger.warning("API response missing 'ipv4' field")
            return None
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch server IP: {e}")
            return None
    
    async def get_dkim(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Fetch DKIM configuration for a domain
        
        Args:
            domain: Domain name
            
        Returns:
            DKIM configuration dictionary or None if not found
        """
        logger.info(f"Fetching DKIM configuration for {domain}")
        try:
            data = await self._make_request(f"/api/v1/get/dkim/{domain}")
            
            # Handle different response formats
            if isinstance(data, dict):
                logger.info(f"Retrieved DKIM configuration for {domain}")
                return data
            elif isinstance(data, list):
                if len(data) > 0:
                    logger.info(f"Retrieved DKIM configuration for {domain}")
                    return data[0]
                else:
                    logger.warning(f"DKIM not configured in mailcow for {domain}")
                    return None
            else:
                logger.warning(f"Unexpected DKIM response format: {type(data)}")
                return None
                
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch DKIM configuration for {domain}: {e}")
            return None
    
    async def get_transports(self) -> List[Dict[str, Any]]:
        """
        Fetch all transports from mailcow
        
        Returns:
            List of transports
        """
        logger.info("Fetching transports")
        try:
            data = await self._make_request("/api/v1/get/transport/all")
            
            # Handle different response formats
            if isinstance(data, list):
                logger.info(f"Retrieved {len(data)} transports")
                return data
            elif isinstance(data, dict):
                # API may return empty dict {} when no transports exist
                if not data:
                    logger.info("No transports found (empty dict)")
                    return []
                # If dict has a key containing list, extract it
                # Check common patterns
                for key in ['transports', 'data', 'items']:
                    if key in data and isinstance(data[key], list):
                        logger.info(f"Retrieved {len(data[key])} transports from dict")
                        return data[key]
                # If dict is not empty but doesn't contain expected list, log warning
                logger.warning(f"Transports API returned dict but no list found: {data}")
                return []
            else:
                logger.warning(f"Unexpected transports response format: {type(data)}")
                return []
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch transports: {e}")
            return []
    
    async def get_relayhosts(self) -> List[Dict[str, Any]]:
        """
        Fetch all relayhosts from mailcow
        
        Returns:
            List of relayhosts
        """
        logger.info("Fetching relayhosts")
        try:
            data = await self._make_request("/api/v1/get/relayhost/all")
            
            # Handle different response formats
            if isinstance(data, list):
                logger.info(f"Retrieved {len(data)} relayhosts")
                return data
            elif isinstance(data, dict):
                # API may return empty dict {} when no relayhosts exist
                if not data:
                    logger.info("No relayhosts found (empty dict)")
                    return []
                # If dict has a key containing list, extract it
                # Check common patterns
                for key in ['relayhosts', 'data', 'items']:
                    if key in data and isinstance(data[key], list):
                        logger.info(f"Retrieved {len(data[key])} relayhosts from dict")
                        return data[key]
                # If dict is not empty but doesn't contain expected list, log warning
                logger.warning(f"Relayhosts API returned dict but no list found: {data}")
                return []
            else:
                logger.warning(f"Unexpected relayhosts response format: {type(data)}")
                return []
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch relayhosts: {e}")
            return []


    async def get_fail2ban(self) -> Optional[Dict[str, Any]]:
        """
        Fetch Fail2Ban configuration from mailcow
        
        Returns:
            Dictionary with Fail2Ban settings or None if not available
        """
        logger.info("Fetching Fail2Ban configuration")
        try:
            data = await self._make_request("/api/v1/get/fail2ban")
            
            # API returns a list with one element
            if isinstance(data, list) and len(data) > 0:
                logger.info("Retrieved Fail2Ban configuration")
                return data[0]
            elif isinstance(data, dict):
                logger.info("Retrieved Fail2Ban configuration (dict format)")
                return data
            else:
                logger.warning(f"Unexpected Fail2Ban response format: {type(data)}")
                return None
                
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Fail2Ban configuration: {e}")
            return None

    async def edit_fail2ban(self, attrs: Dict[str, Any]) -> Dict[str, Any]:
        """
        Update Fail2Ban configuration on mailcow using the Read-Write API key.
        
        Args:
            attrs: Dictionary of Fail2Ban attributes to update.
                   Must include ALL parameters (not just changed ones).
        
        Returns:
            Response from mailcow API
        
        Raises:
            MailcowAPIError: If request fails or RW key is not configured
        """
        logger.info("Updating Fail2Ban configuration")
        payload = {"attr": attrs}
        data = await self._make_rw_request(
            "/api/v1/edit/fail2ban",
            method="POST",
            json=payload
        )
        logger.info(f"Fail2Ban update response: {data}")
        return data

    async def unban_fail2ban(self, ip: str) -> Dict[str, Any]:
        """
        Unban an IP address in Fail2Ban on mailcow using the Read-Write API key.
        
        Args:
            ip: IP address to unban
        
        Returns:
            Response from mailcow API
        
        Raises:
            MailcowAPIError: If request fails or RW key is not configured
        """
        logger.info(f"Unbanning IP {ip} from Fail2Ban")
        payload = {"attr": {"ip": ip}}
        data = await self._make_rw_request(
            "/api/v1/delete/fail2ban",
            method="POST",
            json=payload
        )
        logger.info(f"Fail2Ban unban response: {data}")
        return data

    async def release_quarantine(self, item_ids: List[str]) -> Any:
        """
        Release quarantined messages on mailcow using the Read-Write API key.
        
        Args:
            item_ids: List of quarantine item ID strings to release
        
        Returns:
            Response from mailcow API
        
        Raises:
            MailcowAPIError: If request fails or RW key is not configured
        """
        logger.info(f"Releasing quarantine items: {item_ids}")
        payload = {
            "items": item_ids,
            "attr": {
                "action": "release"
            }
        }
        data = await self._make_rw_request(
            "/api/v1/edit/qitem",
            method="POST",
            json=payload
        )
        logger.info(f"Quarantine release response: {data}")
        return data

    async def delete_quarantine(self, item_ids: List[str]) -> Any:
        """
        Delete quarantined messages on mailcow using the Read-Write API key.
        
        Args:
            item_ids: List of quarantine item ID strings to delete
        
        Returns:
            Response from mailcow API
        
        Raises:
            MailcowAPIError: If request fails or RW key is not configured
        """
        logger.info(f"Deleting quarantine items: {item_ids}")
        data = await self._make_rw_request(
            "/api/v1/delete/qitem",
            method="POST",
            json=item_ids
        )
        logger.info(f"Quarantine delete response: {data}")
        return data

    @property
    def has_rw_key(self) -> bool:
        """Check if a Read-Write API key is configured."""
        return self.headers_rw is not None


mailcow_api = MailcowAPI()
