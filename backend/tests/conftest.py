"""
Test configuration.

Sets required environment variables BEFORE any app module import so that
app.config.Settings() can construct without a real deployment environment.
"""
import os
import sys
import pathlib

os.environ.setdefault("MAILCOW_URL", "https://mail.example.com")
os.environ.setdefault("MAILCOW_API_KEY", "test-key")
os.environ.setdefault("POSTGRES_USER", "test")
os.environ.setdefault("POSTGRES_PASSWORD", "test")
os.environ.setdefault("POSTGRES_DB", "test")

# Make `app` importable when running pytest from the repo root or backend/
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
