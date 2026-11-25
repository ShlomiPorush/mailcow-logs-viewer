import os
from pathlib import Path

def get_version() -> str:
    possible_paths = [
        Path("/app/VERSION"),
        Path(__file__).parent.parent.parent / "VERSION",
        Path(__file__).parent.parent.parent.parent / "VERSION",
    ]
    
    for version_path in possible_paths:
        if version_path.exists():
            try:
                with open(version_path, "r") as f:
                    version = f.read().strip()
                    if version:
                        return version
            except Exception as e:
                print(f"Error reading VERSION file from {version_path}: {e}")
                continue
    
    return "1.4.2"

__version__ = get_version()

