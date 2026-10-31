"""API operations whose answers are not documented yet, by the layer that will document them.

test_openapi_coverage.py fails when an operation is neither documented nor
listed here, and when an entry here is stale (documented already, or gone).
Each layer of the work removes its entries; the list ends empty.
"""

PENDING = {
}

# Operations left out of /openapi.json on purpose, with the reason
HIDDEN = {
    ("GET", "/api/auth/logout"): "Always answers 405: signing out is POST /api/auth/logout",
}
