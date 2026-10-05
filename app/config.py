"""Runtime configuration (environment driven)."""
from __future__ import annotations

import os
from dataclasses import dataclass

#: Default development secret. Override with ANON_SECRET in any real deployment;
#: the secret feeds the HMAC keys behind UID mapping, date shifting and tag
#: hashing, so changing it changes every anonymized output.
DEFAULT_SECRET = "dicom-anon-dev-secret"


@dataclass(frozen=True)
class Settings:
    data_dir: str
    secret: str


def get_settings() -> Settings:
    return Settings(
        data_dir=os.environ.get("DATA_DIR", "./data"),
        secret=os.environ.get("ANON_SECRET", DEFAULT_SECRET),
    )
