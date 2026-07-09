"""
Environment discovery — finds distinct deployment.environment values in the org,
filtering out junk/scan artifacts and deduplicating case variants.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

# Patterns that identify scanner/injection artifacts, not real environment names
_JUNK_PATTERNS = [
    r"sleep\s*\(",          # SQL sleep()
    r"pg_sleep",            # PostgreSQL sleep
    r"/\*",                 # SQL comment
    r"\|\|",                # SQL concatenation
    r"bmt=",                # Scanner marker
    r"<bmt>",               # Scanner marker
    r"://",                 # URL
    r"\[\[",                # Template injection
    r"\]\]",
    r"\{[0-9]",             # Math expression injection
    r"[^\x20-\x7e]",       # Non-printable / non-ASCII
]
_JUNK_RE = re.compile("|".join(_JUNK_PATTERNS), re.IGNORECASE)


def _is_valid_env(value: str) -> bool:
    if not value or not value.strip():
        return False
    if len(value) > 60:
        return False
    if _JUNK_RE.search(value):
        return False
    return True


def _api_get(api_base: str, token: str, path: str, params: dict | None = None) -> dict:
    qs = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v is not None})
    url = f"{api_base}{path}" + (f"?{qs}" if qs else "")
    req = urllib.request.Request(url, headers={"X-SF-Token": token, "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTP {e.code}: {(e.read() or b'')[:300].decode()}")
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Request failed: {e}")


def discover_environments(
    realm: str,
    token: str,
    max_envs: int = 20,
) -> list[str]:
    """
    Return a sorted, deduplicated list of real environment names from the org.

    Uses deployment.environment as primary source, falls back to sf_environment.
    Filters junk/scanner artifacts and deduplicates case-insensitive variants
    (e.g. 'prod' and 'PROD' → keeps one).
    """
    api_base = f"https://api.{realm}.signalfx.com"

    envs: list[str] = []
    for key in ("deployment.environment", "sf_environment"):
        try:
            data = _api_get(api_base, token, "/v2/dimension", {
                "query": f"key:{key}",
                "limit": 200,
            })
            raw = [r.get("value", "").strip('"').strip("'") for r in (data.get("results") or [])]
            clean = [v for v in raw if _is_valid_env(v)]
            if clean:
                envs = clean
                logger.info("Discovered %d environments from %s", len(clean), key)
                break
        except RuntimeError as e:
            logger.warning("Could not query dimension %s: %s", key, e)

    if not envs:
        return []

    # Deduplicate case-insensitive variants, keeping the lowercase form
    seen: dict[str, str] = {}  # lower → canonical
    for val in sorted(envs, key=str.lower):
        lower = val.lower()
        if lower not in seen:
            # Prefer the lowercase form for consistency
            seen[lower] = lower if val != lower else val

    deduped = sorted(seen.values())
    if len(deduped) > max_envs:
        logger.warning(
            "Found %d environments, capping at %d (use --max-environments to increase)",
            len(deduped), max_envs,
        )
        deduped = deduped[:max_envs]

    return deduped
