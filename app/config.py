"""Runtime configuration (environment driven)."""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

#: Default development secret. Override with ANON_SECRET in any real deployment;
#: the secret feeds the HMAC keys behind UID mapping, date shifting and tag
#: hashing, so changing it changes every anonymized output.
DEFAULT_SECRET = "dicom-anon-dev-secret"

#: Domain-separated prefix for the non-reversible secret fingerprint.
FINGERPRINT_PREFIX = "dicom-anon-key-fingerprint:v1"


def secret_fingerprint(secret: str) -> str:
    """SHA-256 fingerprint of *secret* (64 hex chars); the secret itself is
    never persisted.

    The fingerprint is the "key scope" of a job: it is part of the idempotent
    job id and is stored alongside each job, so deduplication always agrees
    with the HMAC key the engine actually uses. Rotating the secret yields a
    different fingerprint (therefore a separate job, audit and output hash),
    while the digest cannot be reversed back into the secret.
    """
    return hashlib.sha256(f"{FINGERPRINT_PREFIX}|{secret}".encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Settings:
    data_dir: str
    secret: str

    @property
    def key_fingerprint(self) -> str:
        return secret_fingerprint(self.secret)


def get_settings() -> Settings:
    return Settings(
        data_dir=os.environ.get("DATA_DIR", "./data"),
        secret=os.environ.get("ANON_SECRET", DEFAULT_SECRET),
    )
