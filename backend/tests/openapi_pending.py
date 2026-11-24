"""API operations left out of /openapi.json on purpose, with the reason.

test_openapi_coverage.py fails when an entry here is in the document, or gone.
"""

HIDDEN = {
    ("GET", "/api/auth/logout"): "Always answers 405: signing out is POST /api/auth/logout",
}
