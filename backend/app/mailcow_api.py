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
        self.base_url = settings.mailcow_url
        self.api_key = settings.mailcow_api_key
        self.timeout = settings.mailcow_api_timeout
        
        # Setup headers
        self.headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json"
        }
        
        logger.info(f"mailcow API client initialized for {self.base_url}")
    
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
        
        async with httpx.AsyncClient(timeout=self.timeout) as client:
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
            
            if isinstance(data, list) and len(data) > 0:
                return data[0].get('version', 'unknown')
            
            logger.warning(f"Unexpected version response format: {type(data)}")
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


mailcow_api = MailcowAPI()