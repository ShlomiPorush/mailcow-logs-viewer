from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
import httpx
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

GITHUB_DOCS_BASE_URL = "https://raw.githubusercontent.com/ShlomiPorush/mailcow-logs-viewer/main/documentation/HelpDocs"

ALLOWED_DOCS = {
    "Domains": "Domains.md",
    "DMARC": "DMARC.md",
    "Mailbox_Stats": "Mailbox_Stats.md",
    "IP_Blacklist_Monitor": "IP_Blacklist_Monitor.md",
    "Spam_Filter": "Spam_Filter.md",
    "Quarantine": "Quarantine.md",
    "Abuse_Protection": "Abuse_Protection.md",
    "Rate_Limits": "Rate_Limits.md",
}

@router.get("/docs/{doc_name}", response_class=PlainTextResponse)
async def get_documentation(doc_name: str):
    if doc_name not in ALLOWED_DOCS:
        raise HTTPException(status_code=404, detail="Documentation not found")
    
    filename = ALLOWED_DOCS[doc_name]
    url = f"{GITHUB_DOCS_BASE_URL}/{filename}"
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except httpx.HTTPStatusError as e:
        logger.error(f"Failed to fetch documentation {doc_name}: HTTP {e.response.status_code}")
        raise HTTPException(status_code=404, detail="Documentation not found")
    except httpx.RequestError as e:
        logger.error(f"Failed to fetch documentation {doc_name}: {e}")
        raise HTTPException(status_code=503, detail="Failed to fetch documentation")