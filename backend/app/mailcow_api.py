"""
Mailcow API client for fetching logs
Handles authentication and API calls to mailcow instance
"""
import asyncio
import httpx
import logging
import weakref
from http.cookiejar import CookieJar, DefaultCookiePolicy
from urllib.parse import quote
from typing import List, Dict, Any, Optional
from datetime import datetime
from tenacity import retry, retry_if_not_exception_type, stop_after_attempt, wait_exponential, RetryError

from .config import settings

logger = logging.getLogger(__name__)


def _forget_security_addresses() -> None:
    """Fail2ban changed: the Security page's lists are read again on the next request."""
    from .services import security_addresses
    security_addresses.forget()


class MailcowAPIError(Exception):
    """Custom exception for mailcow API errors"""
    pass


class MailcowRwKeyError(MailcowAPIError):
    """mailcow refused the Read-Write key: 'rejected' (401) or 'read_only' (403).

    Final, so never retried; the API answers it with a message that says what to fix.
    """
    MESSAGES = {
        "rejected": "mailcow rejected the Read-Write API key. Check in mailcow under System → API "
                    "that the key is correct and active, and that the IP address of this server is allowed. "
                    "Settings → Mailcow can check the key.",
        "read_only": "The Read-Write API key is a read-only key in mailcow. "
                     "Put the Read-Write key from System → API in Settings → Mailcow.",
    }

    def __init__(self, code: str):
        self.code = code
        super().__init__(self.MESSAGES[code])


class MailcowAPI:
    """Client for interacting with mailcow API"""
    
    def __init__(self):
        # One persistent HTTP client per event loop (issue #84): a fresh
        # client per request meant a fresh TCP connection - and a fresh
        # A/AAAA lookup of the mailcow host - for every single API call.
        # Keyed weakly by loop because manually triggered jobs run in their
        # own short-lived loop; a client must never be shared across loops.
        self._clients = weakref.WeakKeyDictionary()
        self._update_config()
        logger.info(f"mailcow API client initialized for {self.base_url} (SSL verification: {self.verify_ssl})")

    def _get_client(self) -> httpx.AsyncClient:
        """Return the persistent client for the running event loop."""
        loop = asyncio.get_running_loop()
        client = self._clients.get(loop)
        if client is None or client.is_closed:
            client = httpx.AsyncClient(
                timeout=self.timeout,
                verify=self.verify_ssl,
                # Every request carries the API key, so mailcow's session
                # cookie is never kept: a session mailcow stopped honouring
                # would otherwise ride along on every later call
                cookies=CookieJar(policy=DefaultCookiePolicy(allowed_domains=[])),
                # Keep idle connections long enough to bridge the polling
                # jobs (raw logs every ~60s, log fetch every ~30s), so
                # steady-state polling reuses one connection instead of
                # resolving and reconnecting every time
                limits=httpx.Limits(max_connections=20,
                                    max_keepalive_connections=10,
                                    keepalive_expiry=300),
            )
            self._clients[loop] = client
        return client

    def _discard_client(self, client: httpx.AsyncClient) -> None:
        """Stop using a client mailcow refused (401, 403) or dropped, so the next
        try opens new connections. It is closed a little later, once requests
        still on it are done."""
        loop = asyncio.get_running_loop()
        if self._clients.get(loop) is client:
            del self._clients[loop]
            loop.call_later(30, lambda: loop.create_task(client.aclose()))

    def _drop_clients(self):
        """Close all cached clients (config changed). Safe from any thread."""
        for loop, client in list(self._clients.items()):
            try:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(
                        lambda c=client, l=loop: l.create_task(c.aclose()))
            except RuntimeError:
                pass
        self._clients = weakref.WeakKeyDictionary()

    async def aclose(self):
        """Close the client of the current loop (app shutdown)."""
        loop = asyncio.get_running_loop()
        client = self._clients.pop(loop, None)
        if client is not None and not client.is_closed:
            await client.aclose()
    
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
        old_conn = (self.timeout, self.verify_ssl)
        self._update_config()
        if old_conn != (self.timeout, self.verify_ssl) or old_url != self.base_url:
            self._drop_clients()
        if old_url != self.base_url:
            logger.info(f"mailcow API client configuration reloaded: {old_url} -> {self.base_url}")
    
    @property
    def has_rw_key(self) -> bool:
        """Check if a Read-Write API key is configured."""
        return self.headers_rw is not None
    
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
        
        client = self._get_client()
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
            if e.response.status_code in (401, 403):
                self._discard_client(client)
            raise MailcowAPIError(f"API returned status {e.response.status_code}")
        except httpx.RequestError as e:
            logger.error(f"Request error for {url}: {e}")
            self._discard_client(client)
            raise MailcowAPIError(f"Failed to connect to mailcow API: {e}")
        except Exception as e:
            logger.error(f"Unexpected error for {url}: {e}")
            raise MailcowAPIError(f"Unexpected error: {e}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        # A refused key stays refused, and every try is a failed login for Fail2ban
        retry=retry_if_not_exception_type(MailcowRwKeyError),
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
        
        client = self._get_client()
        try:
            response = await client.request(
                method,
                url,
                headers=self.headers_rw,
                **kwargs
            )
                
            if response.status_code == 401:
                self._discard_client(client)
                raise MailcowRwKeyError("rejected")
                
            if response.status_code == 403:
                self._discard_client(client)
                raise MailcowRwKeyError("read_only")
                
            response.raise_for_status()
                
            if response.headers.get('content-type', '').startswith('application/json'):
                # Some mailcow delete endpoints (delete/rlhash) answer 200 with
                # an empty body - that is a success, not something to parse
                if not response.text.strip():
                    return None
                return response.json()
            return response.text

        except httpx.HTTPStatusError as e:
            raise MailcowAPIError(f"RW API request failed with status {e.response.status_code}: {e.response.text}")
        except httpx.RequestError as e:
            self._discard_client(client)
            raise MailcowAPIError(f"RW API request failed: {str(e)}")

    async def check_rw_key(self) -> Dict[str, Any]:
        """Check that mailcow accepts the Read-Write key for writes, changing nothing.

        POSTs to an edit route that does not exist. mailcow checks the key and
        its allowed IPs before routing, so the answer tells the cases apart:
        404 "route not found" = accepted for writes, 403 = a read-only key,
        401 = wrong or inactive key, or this server's IP is not allowed.
        No retry: a rejected key is a final answer, and every rejection is
        also a failed login for mailcow's Fail2ban.
        """
        if not self.headers_rw:
            return {"configured": False, "valid": False, "error": None}
        client = self._get_client()
        try:
            response = await client.post(f"{self.base_url}/api/v1/edit/mlv-key-check",
                                         headers=self.headers_rw, json={"items": [], "attr": {}})
        except httpx.RequestError as e:
            self._discard_client(client)
            logger.warning(f"Read-Write API key check could not reach mailcow: {e}")
            return {"configured": True, "valid": False, "error": "connection"}
        status = response.status_code
        if status == 404:
            return {"configured": True, "valid": True, "error": None}
        if status in (401, 403):
            self._discard_client(client)
        error = {401: "rejected", 403: "read_only"}.get(status, "unexpected")
        logger.warning(f"Read-Write API key check failed: HTTP {status}")
        return {"configured": True, "valid": False, "error": error, "http_status": status}

    def _rspamd_url(self, endpoint: str) -> str:
        """Where an Rspamd controller endpoint ('/rspamd/...') is reached: through
        the mailcow proxy, or straight at RSPAMD_URL when that is set."""
        rspamd_base = (settings.rspamd_url or '').strip().rstrip('/')
        if not rspamd_base:
            return f"{self.base_url}{endpoint}"
        direct_endpoint = endpoint
        if direct_endpoint.startswith('/rspamd'):
            direct_endpoint = direct_endpoint[len('/rspamd'):] or '/'
        return f"{rspamd_base}{direct_endpoint}"

    async def check_rspamd_password(self) -> Dict[str, Any]:
        """Check that Rspamd accepts the password, the way its web UI logs in.

        GET /auth answers 200 with "auth": "ok" for a good password and 401 or
        403 otherwise; it changes nothing. A redirect means a proxy answered
        before Rspamd saw the password. No retry: a wrong password is a failed
        login for mailcow's Fail2ban.
        """
        if not settings.rspamd_password:
            return {"configured": False, "valid": False, "error": None}
        client = self._get_client()
        try:
            response = await client.get(self._rspamd_url("/rspamd/auth"),
                                        headers={"Password": settings.rspamd_password})
        except httpx.RequestError as e:
            logger.warning(f"Rspamd password check could not reach Rspamd: {e}")
            return {"configured": True, "valid": False, "error": "connection"}
        status = response.status_code
        if status == 200:
            try:
                accepted = response.json().get("auth") == "ok"
            except ValueError:
                accepted = False
            if accepted:
                return {"configured": True, "valid": True, "error": None}
        if status in (401, 403):
            error = "rejected"
        elif status in (301, 302, 303, 307, 308):
            error = "redirected"
        else:
            error = "unexpected"
        logger.warning(f"Rspamd password check failed: HTTP {status}")
        return {"configured": True, "valid": False, "error": error, "http_status": status}

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
    
    async def get_postfix_logs_page(self, page_size: int, offset: int) -> List[Dict[str, Any]]:
        """
        Fetch a specific page of Postfix logs using mailcow's range syntax.
        
        Args:
            page_size: Number of logs per page
            offset: Starting offset (0-based). 
                     offset=0 → /api/v1/get/logs/postfix/{page_size}
                     offset=2000 → /api/v1/get/logs/postfix/2001-4000
        
        Returns:
            List of log entries for this page
        """
        if offset == 0:
            # First page: simple count
            endpoint = f"/api/v1/get/logs/postfix/{page_size}"
        else:
            # Subsequent pages: range syntax (1-based)
            start = offset + 1
            end = offset + page_size
            endpoint = f"/api/v1/get/logs/postfix/{start}-{end}"
        
        logger.info(f"Fetching Postfix logs page (offset={offset}, size={page_size}): {endpoint}")
        try:
            data = await self._make_request(endpoint)
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected Postfix page response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} Postfix logs (offset={offset})")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Postfix logs page (offset={offset}): {e}")
            return []
    
    async def get_rspamd_logs_page(self, page_size: int, offset: int) -> List[Dict[str, Any]]:
        """
        Fetch a specific page of Rspamd logs using mailcow's range syntax.
        
        Args:
            page_size: Number of logs per page
            offset: Starting offset (0-based).
                     offset=0 → /api/v1/get/logs/rspamd-history/{page_size}
                     offset=500 → /api/v1/get/logs/rspamd-history/501-1000
        
        Returns:
            List of log entries for this page
        """
        if offset == 0:
            # First page: simple count
            endpoint = f"/api/v1/get/logs/rspamd-history/{page_size}"
        else:
            # Subsequent pages: range syntax (1-based)
            start = offset + 1
            end = offset + page_size
            endpoint = f"/api/v1/get/logs/rspamd-history/{start}-{end}"
        
        logger.info(f"Fetching Rspamd logs page (offset={offset}, size={page_size}): {endpoint}")
        try:
            data = await self._make_request(endpoint)
            
            if not isinstance(data, list):
                logger.warning(f"Unexpected Rspamd page response format: {type(data)}")
                return []
            
            logger.info(f"Retrieved {len(data)} Rspamd logs (offset={offset})")
            return data
            
        except MailcowAPIError as e:
            logger.error(f"Failed to fetch Rspamd logs page (offset={offset}): {e}")
            return []
    
    async def get_raw_logs_range(self, service: str, offset: int, page_size: int) -> List[Dict[str, Any]]:
        """
        Fetch one page of raw logs for a service by position, newest first.

        Used by the raw logs worker to page deeper than the newest N when it has
        to catch up (first start, downtime, a burst larger than one page).

        The range form is 1-based on the Redis-list services (1-4 equals the
        newest 4) but 0-based on rspamd-history (1-4 starts at the second newest,
        and 0-x is rejected); verified against a live instance. Requesting
        start = offset, where offset is the number of lines already taken from
        the head, never skips a line on either base: at worst it repeats the
        previous page's last line, which the caller's hash dedup removes.

        Args:
            service: Service name from ALLOWED_RAW_LOG_SERVICES
            offset: Number of lines already taken from the head (>= 1)
            page_size: Lines to request

        Returns:
            List of raw log entries, or an empty list past the end of the list.

        Raises:
            ValueError for a bad service or offset.
            MailcowAPIError when the request fails after the client's retries.
        """
        if service not in self.ALLOWED_RAW_LOG_SERVICES:
            raise ValueError(f"Unknown raw log service: {service}")
        if offset < 1 or page_size < 1:
            raise ValueError("offset and page_size must be positive")

        start = offset
        end = offset + page_size - 1
        endpoint = f"/api/v1/get/logs/{service}/{start}-{end}"
        logger.debug(f"Fetching raw log range for {service}: {start}-{end}")
        try:
            data = await self._make_request(endpoint)
        except RetryError as e:
            # _make_request's retry decorator does not re-raise the original
            # exception, so callers would otherwise have to know about tenacity.
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Range fetch failed for {service} {start}-{end}: {last}") from e

        if isinstance(data, list):
            return data
        # mailcow answers {} past the end of the list and when a service has no logs
        return []

    async def probe_log_position(self, log_type: str, position: int) -> bool:
        """
        Check if a log exists at the given position.
        Uses range syntax N-N to request a single log entry.
        
        Args:
            log_type: 'postfix' or 'rspamd-history'
            position: 1-based log position to probe
        
        Returns:
            True if a log exists at that position, False otherwise
        """
        endpoint = f"/api/v1/get/logs/{log_type}/{position}-{position}"
        try:
            data = await self._make_request(endpoint)
            return isinstance(data, list) and len(data) > 0
        except asyncio.CancelledError:
            raise  # Let cancellation propagate
        except MailcowAPIError:
            return False
        except Exception:
            return False
    
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
                # This is normal - not all services have logs on every mailcow instance
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

    async def get_alias_domain_map(self) -> Dict[str, str]:
        """
        Fetch active alias domains WITH their targets: {alias_domain: target_domain}.

        get_alias_domains() above returns only the names (enough for direction
        classification); mailbox attribution and the Domains page need to know
        which primary domain each alias points at.
        """
        logger.info("Fetching alias domain map")
        try:
            data = await self._make_request("/api/v1/get/alias-domain/all")
            if not isinstance(data, list):
                return {}
            return {
                item['alias_domain'].lower(): item['target_domain'].lower()
                for item in data
                if item.get('active', 0) == 1
                and item.get('alias_domain') and item.get('target_domain')
            }
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

    async def edit_mailbox(self, mailbox: str, attributes: Dict[str, Any]) -> Any:
        """
        Update mailbox attributes (Read-Write API key required).

        Args:
            mailbox: Mailbox address
            attributes: Attributes to set, e.g. {"smtp_access": "0"}
        """
        return await self._make_rw_request(
            "/api/v1/edit/mailbox",
            method="POST",
            json={"attr": attributes, "items": [mailbox]}
        )

    async def get_app_passwords(self, mailbox: str) -> List[Dict[str, Any]]:
        """List app passwords for a mailbox."""
        data = await self._make_request(
            f"/api/v1/get/app-passwd/all/{quote(mailbox, safe='@')}"
        )
        return data if isinstance(data, list) else []

    async def delete_app_passwords(self, ids: List[str]) -> Any:
        """Delete app passwords by id (Read-Write API key required)."""
        if not ids:
            return []
        return await self._make_rw_request(
            "/api/v1/delete/app-passwd",
            method="POST",
            json=ids
        )

    # ---- Rate limits ----------------------------------------------------
    # mailcow enforces sender rate limits in rspamd, counting against a Redis
    # key per mailbox/domain. The limit itself is configuration (rl_value per
    # rl_frame); the counter that is currently blocking a sender is a separate
    # Redis hash, released by deleting it.

    async def get_rl_mbox(self, mailbox: str) -> Dict[str, Any]:
        """
        Fetch the configured rate limit of a single mailbox.

        Args:
            mailbox: Mailbox address

        Returns:
            {"value": "100", "frame": "m"} - an empty dict when no limit is set

        Raises:
            MailcowAPIError: If the request fails
        """
        endpoint = f"/api/v1/get/rl-mbox/{quote(mailbox, safe='@')}"
        logger.debug(f"Fetching rate limit for mailbox {mailbox}")
        try:
            data = await self._make_request(endpoint)
        except RetryError as e:
            # _make_request's retry decorator does not re-raise the original
            # exception, so callers would otherwise have to know about tenacity.
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Rate limit fetch failed for mailbox {mailbox}: {last}") from e

        if not isinstance(data, dict):
            logger.warning(f"Unexpected rl-mbox response format for {mailbox}: {type(data)}")
            return {}
        return data

    async def get_rl_domain(self, domain: str) -> Dict[str, Any]:
        """
        Fetch the configured rate limit of a single domain.

        Args:
            domain: Domain name

        Returns:
            {"value": "500", "frame": "h"} - an empty dict when no limit is set

        Raises:
            MailcowAPIError: If the request fails
        """
        endpoint = f"/api/v1/get/rl-domain/{quote(domain, safe='')}"
        logger.debug(f"Fetching rate limit for domain {domain}")
        try:
            data = await self._make_request(endpoint)
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Rate limit fetch failed for domain {domain}: {last}") from e

        if not isinstance(data, dict):
            logger.warning(f"Unexpected rl-domain response format for {domain}: {type(data)}")
            return {}
        return data

    async def edit_rl_mbox(self, mailbox: str, value: Any, frame: str) -> Any:
        """
        Set the rate limit of a mailbox (Read-Write API key required).

        A value of "0" (or an empty value) removes the limit.

        Args:
            mailbox: Mailbox address
            value: Messages allowed per frame
            frame: Time frame - s (second), m (minute), h (hour), d (day)

        Returns:
            Response from mailcow API

        Raises:
            MailcowAPIError: If the request fails or no RW key is configured
        """
        logger.info(f"Setting rate limit for mailbox {mailbox}: {value}/{frame}")
        payload = {
            "items": [mailbox],
            "attr": {
                "rl_value": str(value),
                "rl_frame": frame
            }
        }
        try:
            data = await self._make_rw_request(
                "/api/v1/edit/rl-mbox/",
                method="POST",
                json=payload
            )
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Rate limit update failed for mailbox {mailbox}: {last}") from e

        logger.info(f"Mailbox rate limit response for {mailbox}: {data}")
        return data

    async def edit_rl_mboxes(self, mailboxes: List[str], value: Any, frame: str) -> Any:
        """
        Set the same rate limit on many mailboxes (Read-Write API key required).

        mailcow's edit endpoint takes a list of items, so applying one limit to
        a whole filtered selection is a single request no matter how many
        mailboxes it covers.

        A value of "0" (or an empty value) removes the limit.

        Args:
            mailboxes: Mailbox addresses
            value: Messages allowed per frame
            frame: Time frame - s (second), m (minute), h (hour), d (day)

        Returns:
            Response from mailcow API

        Raises:
            MailcowAPIError: If the request fails or no RW key is configured
        """
        items = list(mailboxes or [])
        logger.info(f"Setting rate limit for {len(items)} mailboxes: {value}/{frame}")
        payload = {
            "items": items,
            "attr": {
                "rl_value": str(value),
                "rl_frame": frame
            }
        }
        try:
            data = await self._make_rw_request(
                "/api/v1/edit/rl-mbox/",
                method="POST",
                json=payload
            )
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(
                f"Rate limit update failed for {len(items)} mailboxes: {last}") from e

        logger.info(f"Mailbox rate limit response for {len(items)} mailboxes: {data}")
        return data

    async def edit_rl_domain(self, domain: str, value: Any, frame: str) -> Any:
        """
        Set the rate limit of a domain (Read-Write API key required).

        A value of "0" (or an empty value) removes the limit.

        Args:
            domain: Domain name
            value: Messages allowed per frame
            frame: Time frame - s (second), m (minute), h (hour), d (day)

        Returns:
            Response from mailcow API

        Raises:
            MailcowAPIError: If the request fails or no RW key is configured
        """
        logger.info(f"Setting rate limit for domain {domain}: {value}/{frame}")
        payload = {
            "items": [domain],
            "attr": {
                "rl_value": str(value),
                "rl_frame": frame
            }
        }
        try:
            data = await self._make_rw_request(
                "/api/v1/edit/rl-domain/",
                method="POST",
                json=payload
            )
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Rate limit update failed for domain {domain}: {last}") from e

        logger.info(f"Domain rate limit response for {domain}: {data}")
        return data

    async def edit_rl_domains(self, domains: List[str], value: Any, frame: str) -> Any:
        """
        Set the same rate limit on many domains (Read-Write API key required).

        One request for the whole list, exactly like edit_rl_mboxes.

        A value of "0" (or an empty value) removes the limit.

        Args:
            domains: Domain names
            value: Messages allowed per frame
            frame: Time frame - s (second), m (minute), h (hour), d (day)

        Returns:
            Response from mailcow API

        Raises:
            MailcowAPIError: If the request fails or no RW key is configured
        """
        items = list(domains or [])
        logger.info(f"Setting rate limit for {len(items)} domains: {value}/{frame}")
        payload = {
            "items": items,
            "attr": {
                "rl_value": str(value),
                "rl_frame": frame
            }
        }
        try:
            data = await self._make_rw_request(
                "/api/v1/edit/rl-domain/",
                method="POST",
                json=payload
            )
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(
                f"Rate limit update failed for {len(items)} domains: {last}") from e

        logger.info(f"Domain rate limit response for {len(items)} domains: {data}")
        return data

    async def delete_rl_hash(self, rl_hash: str) -> Any:
        """
        Release an active rate limit counter (Read-Write API key required).

        This deletes the Redis hash rspamd counts against, so the sender can
        send again immediately without the configured limit being changed.

        Args:
            rl_hash: The RL hash from the ratelimited log (e.g. "RLwhscgno...")

        Returns:
            Response from mailcow API

        Raises:
            MailcowAPIError: If the request fails or no RW key is configured
        """
        logger.info(f"Releasing rate limit counter {rl_hash}")
        try:
            data = await self._make_rw_request(
                "/api/v1/delete/rlhash",
                method="POST",
                json=[rl_hash]
            )
        except RetryError as e:
            last = e.last_attempt.exception() if e.last_attempt else None
            raise MailcowAPIError(f"Rate limit release failed for {rl_hash}: {last}") from e

        logger.info(f"Rate limit release response for {rl_hash}: {data}")
        return data

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
                
        except (MailcowAPIError, RetryError) as e:
            # RetryError: _make_request's retry decorator does not re-raise the
            # original exception, and the Security page must still load without it
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
        # mailcow turns "manage external" off on any edit that leaves it out:
        # keep what is set unless the caller sets it
        if "manage_external" not in attrs:
            current = await self.get_fail2ban()
            if current is not None:
                attrs = {**attrs, "manage_external": "1" if current.get("manage_external") in (True, 1, "1") else "0"}
        payload = {"attr": attrs}
        data = await self._make_rw_request(
            "/api/v1/edit/fail2ban",
            method="POST",
            json=payload
        )
        logger.info(f"Fail2Ban update response: {data}")
        _forget_security_addresses()
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
        # mailcow has no delete/fail2ban: an unban is an edit with action "unban"
        # and the networks as items. mailcow handles it before its settings code,
        # so nothing else is sent or changed.
        network = ip if "/" in ip else f"{ip}/128" if ":" in ip else f"{ip}/32"
        payload = {"items": [network], "attr": {"action": "unban"}}
        data = await self._make_rw_request(
            "/api/v1/edit/fail2ban",
            method="POST",
            json=payload
        )
        logger.info(f"Fail2Ban unban response: {data}")
        _forget_security_addresses()
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

    async def learnham_quarantine(self, item_ids: List[str]) -> Any:
        """
        Release quarantined messages and train Rspamd that they are NOT spam (ham).
        Sends POST to /api/v1/edit/qitem with action=learnham.
        This releases the email AND teaches the Rspamd Bayes classifier + fuzzy hashes.
        """
        logger.info(f"Learn ham for quarantine items: {item_ids}")
        payload = {
            "items": item_ids,
            "attr": {
                "action": "learnham"
            }
        }
        data = await self._make_rw_request(
            "/api/v1/edit/qitem",
            method="POST",
            json=payload
        )
        logger.info(f"Quarantine learnham response: {data}")
        return data

    async def learnspam_quarantine(self, item_ids: List[str]) -> Any:
        """
        Delete quarantined messages and train Rspamd that they ARE spam.
        Sends POST to /api/v1/edit/qitem with action=learnspam.
        This deletes the email AND teaches the Rspamd Bayes classifier + fuzzy hashes.
        """
        logger.info(f"Learn spam for quarantine items: {item_ids}")
        payload = {
            "items": item_ids,
            "attr": {
                "action": "learnspam"
            }
        }
        data = await self._make_rw_request(
            "/api/v1/edit/qitem",
            method="POST",
            json=payload
        )
        logger.info(f"Quarantine learnspam response: {data}")
        return data

    async def get_quarantine_details(self, item_id: str) -> Any:
        """
        Get detailed quarantine item information by proxying to qitem_details.php.
        Returns Rspamd symbols, email content (text/html), recipients, and more.
        
        Args:
            item_id: Quarantine item ID
            
        Returns:
            Parsed JSON response with detailed quarantine info
        """
        url = f"{self.base_url}/inc/ajax/qitem_details.php?id={item_id}"
        
        client = self._get_client()
        try:
            response = await client.get(
                url,
                headers=self.headers
            )
            response.raise_for_status()
                
            data = response.json()
            # The response is a list with a single element
            if isinstance(data, list) and len(data) > 0:
                return data[0]
            return data
                
        except httpx.HTTPStatusError as e:
            raise MailcowAPIError(f"Failed to get quarantine details: HTTP {e.response.status_code}")
        except Exception as e:
            raise MailcowAPIError(f"Failed to get quarantine details: {str(e)}")

    async def _make_rspamd_request(self, endpoint: str, method: str = "GET", extra_headers: dict = None, **kwargs) -> Any:
        """
        Make HTTP request to Rspamd API (via mailcow proxy at /rspamd/).
        Uses Password header for authentication instead of X-API-Key.
        
        Args:
            endpoint: Rspamd API endpoint (e.g., '/rspamd/maps')
            method: HTTP method
            extra_headers: Additional headers (e.g., map ID)
            **kwargs: Additional arguments for httpx
            
        Returns:
            Response from Rspamd API (varies by endpoint)
            
        Raises:
            MailcowAPIError: If request fails or rspamd password not configured
        """
        rspamd_pw = settings.rspamd_password
        if not rspamd_pw:
            raise MailcowAPIError(
                "Rspamd password (RSPAMD_PASSWORD) is not configured. "
                "Set the Rspamd UI password in Settings to use Rspamd map features."
            )
        
        # By default Rspamd is reached through the mailcow proxy
        # (MAILCOW_URL/rspamd/...). Some deployments - typically when this app
        # runs outside mailcow's Docker network, behind another reverse proxy -
        # get a 302 from that proxy before the Password header is ever checked.
        # RSPAMD_URL points straight at the Rspamd controller instead.
        rspamd_base = (settings.rspamd_url or '').strip().rstrip('/')
        url = self._rspamd_url(endpoint)

        headers = {"Password": rspamd_pw}
        if extra_headers:
            headers.update(extra_headers)
        
        client = self._get_client()
        try:
            response = await client.request(method, url, headers=headers, **kwargs)
                
            if response.status_code == 401 or response.status_code == 403:
                raise MailcowAPIError("Rspamd password authentication failed. Check RSPAMD_PASSWORD setting.")
                
            response.raise_for_status()
            return response
                
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (301, 302, 303, 307, 308) and not rspamd_base:
                raise MailcowAPIError(
                    f"Rspamd API request was redirected ({e.response.status_code}) by the mailcow proxy "
                    "before authentication. Set RSPAMD_URL to reach the Rspamd controller directly, "
                    "e.g. http://rspamd-mailcow:11334"
                )
            raise MailcowAPIError(f"Rspamd API request failed with status {e.response.status_code}")
        except httpx.RequestError as e:
            raise MailcowAPIError(f"Rspamd API request failed: {str(e)}")

    async def get_rspamd_maps(self) -> List[Dict[str, Any]]:
        """
        List all Rspamd map files.
        
        GET /rspamd/maps
        Header: Password
        
        Returns:
            List of map metadata dicts with keys: map (id), description, uri, type, editable, loaded, cached
        """
        response = await self._make_rspamd_request("/rspamd/maps")
        data = response.json()
        if not isinstance(data, list):
            logger.warning(f"Unexpected Rspamd maps response format: {type(data)}")
            return []
        return data

    async def get_rspamd_map_content(self, map_id: int) -> str:
        """
        Read the content of a specific Rspamd map file.
        
        GET /rspamd/getmap
        Headers: Password, map (map ID)
        
        Args:
            map_id: The numeric map identifier from get_rspamd_maps()
            
        Returns:
            Raw map content as text
        """
        response = await self._make_rspamd_request(
            "/rspamd/getmap",
            extra_headers={"map": str(map_id)}
        )
        return response.text

    async def find_rspamd_map_id(self, map_filename: str) -> Optional[int]:
        """
        Find the numeric map ID for a given map filename.
        
        Args:
            map_filename: Filename to search for (e.g., 'global_rcpt_blacklist.map')
            
        Returns:
            Map ID if found, None otherwise
        """
        maps = await self.get_rspamd_maps()
        for m in maps:
            uri = m.get("uri", "")
            if map_filename in uri:
                return m.get("map")
        return None

    async def edit_rspamd_map(self, map_filename: str, map_data: str) -> Any:
        """
        Update the content of an Rspamd map file via mailcow API.
        
        POST /api/v1/edit/rspamd-map
        Uses Read-Write API key (X-API-Key header).
        
        Args:
            map_filename: The map file name (e.g., 'global_rcpt_blacklist.map')
            map_data: The full map content to write
            
        Returns:
            Response from mailcow API
        """
        payload = {
            "items": [map_filename],
            "attr": {"rspamd_map_data": map_data}
        }
        return await self._make_rw_request(
            "/api/v1/edit/rspamd-map",
            method="POST",
            json=payload
        )

    @property
    def has_rw_key(self) -> bool:
        """Check if a Read-Write API key is configured."""
        return self.headers_rw is not None


mailcow_api = MailcowAPI()
