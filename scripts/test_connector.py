#!/usr/bin/env python3
"""Developer utility: smoke-test the Cloudflare connector against a live zone.

This script calls ``CloudflareConnector`` with credentials from the environment,
prints a summary of every DNS record returned, and exits 0 on success.  It is
intended for quick, manual verification during development — not for CI.

Usage
-----
    export CLOUDFLARE_API_TOKEN=your_api_token_here
    export CLOUDFLARE_ZONE_ID=your_zone_id_here
    python scripts/test_connector.py

Optional flags (set as environment variables)
---------------------------------------------
    VALIDATE_ONLY=1
        Run only ``validate_credentials()`` — do not fetch all records.
        Useful for quickly confirming that a token is valid.

    VERBOSE=1
        Print the full normalised dict for every record, not just the summary.

Exit codes
----------
    0   Success
    1   Error (credentials missing, authentication failure, API error, etc.)
"""

from __future__ import annotations

import json
import os
import sys

# Allow running from the repo root without installing the package.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_REPO_ROOT, "backend"))

from app.connectors.cloudflare import CloudflareConnector
from app.connectors.exceptions import (
    AuthenticationError,
    ConnectorError,
    NetworkError,
    RateLimitError,
)


def main() -> int:
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    zone_id = os.environ.get("CLOUDFLARE_ZONE_ID", "").strip()
    validate_only = os.environ.get("VALIDATE_ONLY", "").strip() == "1"
    verbose = os.environ.get("VERBOSE", "").strip() == "1"

    if not api_token or not zone_id:
        print(
            "ERROR: Both CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID must be set.\n",
            file=sys.stderr,
        )
        print(
            "Usage:\n"
            "    export CLOUDFLARE_API_TOKEN=<token>\n"
            "    export CLOUDFLARE_ZONE_ID=<zone_id>\n"
            "    python scripts/test_connector.py",
            file=sys.stderr,
        )
        return 1

    connector = CloudflareConnector()
    credentials = {"api_token": api_token, "zone_id": zone_id}

    # ── Step 1: validate credentials ────────────────────────────────────────
    print(f"Validating credentials for zone {zone_id!r} ...", end=" ", flush=True)
    try:
        connector.validate_credentials(credentials)
        print("OK")
    except AuthenticationError as exc:
        print(f"FAILED\n  AuthenticationError: {exc}", file=sys.stderr)
        return 1
    except (ConnectorError, NetworkError) as exc:
        print(f"FAILED\n  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    if validate_only:
        print("VALIDATE_ONLY=1 — skipping full record fetch.")
        return 0

    # ── Step 2: fetch all DNS records ────────────────────────────────────────
    print("Fetching all DNS records ...", end=" ", flush=True)
    try:
        records = connector.fetch(credentials)
    except AuthenticationError as exc:
        print(f"FAILED\n  AuthenticationError: {exc}", file=sys.stderr)
        return 1
    except RateLimitError as exc:
        print(f"FAILED\n  RateLimitError: {exc}", file=sys.stderr)
        return 1
    except (ConnectorError, NetworkError) as exc:
        print(f"FAILED\n  {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"OK — {len(records)} record(s) returned\n")

    if not records:
        print("No DNS records found in this zone.")
        return 0

    # ── Step 3: print summary ────────────────────────────────────────────────
    by_type: dict[str, int] = {}
    for r in records:
        rtype = r.get("record_type", "UNKNOWN")
        by_type[rtype] = by_type.get(rtype, 0) + 1

    print("Record counts by type:")
    for rtype, count in sorted(by_type.items()):
        print(f"  {rtype:<12}  {count}")

    if verbose:
        print("\nAll records (normalised):")
        for r in records:
            print(json.dumps(r, indent=2, default=str))
    else:
        print("\nFirst record (normalised):")
        print(json.dumps(records[0], indent=2, default=str))
        if len(records) > 1:
            print(f"\n  … and {len(records) - 1} more.  Set VERBOSE=1 to see all.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
