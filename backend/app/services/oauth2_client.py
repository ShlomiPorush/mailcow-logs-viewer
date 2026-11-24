import logging
import threading
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urljoin

from ..config import settings

logger = logging.getLogger(__name__)


class OAuth2ClientError(Exception):
    pass


class OAuth2Client:

    def __init__(self):
        # Held across the network request, it would stall the event loop and every settings save until the provider answers.
        self._config_lock = threading.Lock()
        self._config_version = 0
        self._update_config()

    def _update_config(self):
        with self._config_lock:
            self._config_version += 1
            self.issuer_url = settings.oauth2_issuer_url
            self.client_id = settings.oauth2_client_id
            self.client_secret = settings.oauth2_client_secret
            self.redirect_uri = settings.oauth2_redirect_uri
            self.scopes = settings.oauth2_scopes.split()

            self.authorization_url: Optional[str] = settings.oauth2_authorization_url
            self.token_url: Optional[str] = settings.oauth2_token_url
            self.userinfo_url: Optional[str] = settings.oauth2_userinfo_url

            self._discovery_cache: Optional[Dict[str, Any]] = None

    def reload_config(self):
        self._update_config()
        logger.info("OAuth2 client configuration reloaded")

    async def discover_endpoints(self) -> Dict[str, Any]:
        with self._config_lock:
            issuer_url, version, cached = self.issuer_url, self._config_version, self._discovery_cache
        if not issuer_url:
            raise OAuth2ClientError("Issuer URL not configured")

        if cached:
            return cached

        discovery_url = urljoin(issuer_url.rstrip('/') + '/', '.well-known/openid-configuration')

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(discovery_url)
                response.raise_for_status()
                discovery = response.json()

                # Without the version check, a discovery answer from before a settings change replaces the new provider's endpoints.
                with self._config_lock:
                    if version != self._config_version:
                        raise OAuth2ClientError("The OAuth2 settings changed during discovery")
                    self._discovery_cache = discovery

                    self.authorization_url = discovery.get('authorization_endpoint')
                    self.token_url = discovery.get('token_endpoint')
                    self.userinfo_url = discovery.get('userinfo_endpoint')

                logger.info(f"OIDC discovery successful for {issuer_url}")
                logger.debug(f"Authorization: {discovery.get('authorization_endpoint')}")
                logger.debug(f"Token: {discovery.get('token_endpoint')}")
                logger.debug(f"UserInfo: {discovery.get('userinfo_endpoint')}")

                return discovery

        except OAuth2ClientError:
            raise
        except httpx.HTTPError as e:
            logger.error(f"OIDC discovery failed: {e}")
            raise OAuth2ClientError(f"Failed to discover OIDC endpoints: {e}")
        except Exception as e:
            logger.error(f"OIDC discovery error: {e}")
            raise OAuth2ClientError(f"OIDC discovery error: {e}")

    def get_authorization_url(self, state: str, code_challenge: Optional[str] = None) -> str:
        if not self.authorization_url:
            raise OAuth2ClientError("Authorization URL not configured. Set OAUTH2_AUTHORIZATION_URL or OAUTH2_ISSUER_URL")
        
        if not self.client_id:
            raise OAuth2ClientError("Client ID not configured")
        
        if not self.redirect_uri:
            raise OAuth2ClientError("Redirect URI not configured")
        
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
        if not self.token_url:
            raise OAuth2ClientError("Token URL not configured. Set OAUTH2_TOKEN_URL or OAUTH2_ISSUER_URL")
        
        if not self.client_id or not self.client_secret:
            raise OAuth2ClientError("Client credentials not configured")
        
        if not self.redirect_uri:
            raise OAuth2ClientError("Redirect URI not configured")
        
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
        if not self.client_id or not self.client_secret:
            return False
        
        if not self.redirect_uri:
            return False
        
        if self.issuer_url:
            return True
        
        if self.authorization_url and self.token_url and self.userinfo_url:
            return True
        
        return False
    
    async def initialize(self) -> None:
        if not self.is_configured():
            logger.warning("OAuth2 client not fully configured")
            return
        
        if self.issuer_url and settings.oauth2_use_oidc_discovery:
            try:
                await self.discover_endpoints()
            except Exception as e:
                logger.warning(f"OIDC discovery failed, using manual endpoints if configured: {e}")
                if not (self.authorization_url and self.token_url and self.userinfo_url):
                    raise OAuth2ClientError(
                        "OIDC discovery failed and manual endpoints not configured. "
                        "Set OAUTH2_AUTHORIZATION_URL, OAUTH2_TOKEN_URL, and OAUTH2_USERINFO_URL"
                    )


oauth2_client = OAuth2Client()
