"""
Generic OAuth2/OIDC Client Service
Supports OIDC discovery and manual endpoint configuration
Works with any standard OAuth2/OIDC provider
"""
import logging
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urljoin

from ..config import settings

logger = logging.getLogger(__name__)


class OAuth2ClientError(Exception):
    """Custom exception for OAuth2 client errors"""
    pass


class OAuth2Client:
    """Generic OAuth2/OIDC client"""
    
    def __init__(self):
        self._update_config()
        
    def _update_config(self):
        """Update configuration from settings (supports dynamic reload)"""
        self.issuer_url = settings.oauth2_issuer_url
        self.client_id = settings.oauth2_client_id
        self.client_secret = settings.oauth2_client_secret
        self.redirect_uri = settings.oauth2_redirect_uri
        self.scopes = settings.oauth2_scopes.split()
        
        # Endpoints (will be populated by discovery or manual config)
        self.authorization_url: Optional[str] = settings.oauth2_authorization_url
        self.token_url: Optional[str] = settings.oauth2_token_url
        self.userinfo_url: Optional[str] = settings.oauth2_userinfo_url
        
        # OIDC discovery cache
        self._discovery_cache: Optional[Dict[str, Any]] = None

    def reload_config(self):
        """Reload configuration from settings (call after settings are updated via UI)"""
        self._update_config()
        logger.info("OAuth2 client configuration reloaded")
        
    async def discover_endpoints(self) -> Dict[str, Any]:
        """
        Perform OIDC discovery to get endpoints
        
        Returns:
            Discovery document with endpoints
        """
        if not self.issuer_url:
            raise OAuth2ClientError("Issuer URL not configured")
        
        if self._discovery_cache:
            return self._discovery_cache
        
        discovery_url = urljoin(self.issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                discovery = response.json()
                
                self._discovery_cache = discovery
                
                # Extract endpoints
                self.authorization_url = discovery.get('authorization_endpoint')
                self.token_url = discovery.get('token_endpoint')
                self.userinfo_url = discovery.get('userinfo_endpoint')
                
                logger.info(f"OIDC discovery successful for {self.issuer_url}")
                logger.debug(f"Authorization: {self.authorization_url}")
                logger.debug(f"Token: {self.token_url}")
                logger.debug(f"UserInfo: {self.userinfo_url}")
                
                return discovery
                
        except httpx.HTTPError as e:
            logger.error(f"OIDC discovery failed: {e}")
            raise OAuth2ClientError(f"Failed to discover OIDC endpoints: {e}")
        except Exception as e:
            logger.error(f"OIDC discovery error: {e}")
            raise OAuth2ClientError(f"OIDC discovery error: {e}")
    
    def get_authorization_url(self, state: str, code_challenge: Optional[str] = None) -> str:
        """
        Get authorization URL for OAuth2 flow
        
        Args:
            state: CSRF state token
            code_challenge: PKCE S256 code_challenge (RFC 7636). Providers
                without PKCE support ignore it, as RFC 6749 requires for
                unknown parameters.
            
        Returns:
            Authorization URL
        """
        if not self.authorization_url:
            raise OAuth2ClientError("Authorization URL not configured. Set OAUTH2_AUTHORIZATION_URL or OAUTH2_ISSUER_URL")
        
        if not self.client_id:
            raise OAuth2ClientError("Client ID not configured")
        
        if not self.redirect_uri:
            raise OAuth2ClientError("Redirect URI not configured")
        
        # Build authorization URL
        from urllib.parse import urlencode
        
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(self.scopes),
            'state': state,
        }
        if code_challenge:
            params['code_challenge'] = code_challenge
            params['code_challenge_method'] = 'S256'
        
        query_string = urlencode(params)
        return f"{self.authorization_url}?{query_string}"
    
    async def exchange_code_for_token(self, code: str, code_verifier: Optional[str] = None) -> Dict[str, Any]:
        """
        Exchange authorization code for access token
        
        Args:
            code: Authorization code from callback
            code_verifier: PKCE code_verifier matching the code_challenge
                sent with the authorization request
            
        Returns:
            Token response with access_token, etc.
        """
        if not self.token_url:
            raise OAuth2ClientError("Token URL not configured. Set OAUTH2_TOKEN_URL or OAUTH2_ISSUER_URL")
        
        if not self.client_id or not self.client_secret:
            raise OAuth2ClientError("Client credentials not configured")
        
        if not self.redirect_uri:
            raise OAuth2ClientError("Redirect URI not configured")
        
        # Prepare token request
        data = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri,
            'client_id': self.client_id,
            'client_secret': self.client_secret,
        }
        if code_verifier:
            data['code_verifier'] = code_verifier
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.post(
                    self.token_url,
                    data=data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                response.raise_for_status()
                token_data = response.json()
                
                logger.debug("Token exchange successful")
                return token_data
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Token exchange failed: {e.response.status_code} - {e.response.text}")
            raise OAuth2ClientError(f"Token exchange failed: {e.response.status_code}")
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            raise OAuth2ClientError(f"Token exchange error: {e}")
    
    async def get_user_info(self, access_token: str) -> Dict[str, Any]:
        """
        Get user information from UserInfo endpoint
        
        Args:
            access_token: OAuth2 access token
            
        Returns:
            User information dictionary
        """
        if not self.userinfo_url:
            raise OAuth2ClientError("UserInfo URL not configured. Set OAUTH2_USERINFO_URL or OAUTH2_ISSUER_URL")
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    self.userinfo_url,
                    headers={'Authorization': f'Bearer {access_token}'}
                )
                response.raise_for_status()
                user_info = response.json()
                
                logger.debug(f"UserInfo retrieved: {user_info.get('email', 'unknown')}")
                return user_info
                
        except httpx.HTTPStatusError as e:
            logger.error(f"UserInfo request failed: {e.response.status_code} - {e.response.text}")
            raise OAuth2ClientError(f"UserInfo request failed: {e.response.status_code}")
        except Exception as e:
            logger.error(f"UserInfo request error: {e}")
            raise OAuth2ClientError(f"UserInfo request error: {e}")
    
    def is_configured(self) -> bool:
        """Check if OAuth2 client is properly configured"""
        if not self.client_id or not self.client_secret:
            return False
        
        if not self.redirect_uri:
            return False
        
        # Need either issuer URL (for discovery) or all endpoints manually configured
        if self.issuer_url:
            return True
        
        if self.authorization_url and self.token_url and self.userinfo_url:
            return True
        
        return False
    
    async def initialize(self) -> None:
        """Initialize OAuth2 client (perform discovery if needed)"""
        if not self.is_configured():
            logger.warning("OAuth2 client not fully configured")
            return
        
        # If issuer URL is provided and discovery is enabled, perform discovery
        if self.issuer_url and settings.oauth2_use_oidc_discovery:
            try:
                await self.discover_endpoints()
            except Exception as e:
                logger.warning(f"OIDC discovery failed, using manual endpoints if configured: {e}")
                # If discovery fails, fall back to manually configured endpoints
                if not (self.authorization_url and self.token_url and self.userinfo_url):
                    raise OAuth2ClientError(
                        "OIDC discovery failed and manual endpoints not configured. "
                        "Set OAUTH2_AUTHORIZATION_URL, OAUTH2_TOKEN_URL, and OAUTH2_USERINFO_URL"
                    )


# Global OAuth2 client instance
oauth2_client = OAuth2Client()
