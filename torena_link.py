#!/usr/bin/env python3
"""Generate Torena Sim Veteran-import links from trained_chara_data.json."""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TORENA_IMPORT_URL = "https://torena-sim.pages.dev/runners"
TORENA_IMPORT_PARAM = "from"
TORENA_IMPORT_VERSION = 1
TORENA_MAX_VALUE_LENGTH = 15_000


def encode_trained_chara_payload(trained_charas: Sequence[dict[str, Any]]) -> str:
    """Encode trained-character JSON using the Torena Sim v1 contract."""
    envelope = {"v": TORENA_IMPORT_VERSION, "data": trained_charas}
    compact_json = json.dumps(envelope, ensure_ascii=False, separators=(",", ":"))
    value = base64.urlsafe_b64encode(compact_json.encode("utf-8")).decode("ascii").rstrip("=")
    if len(value) > TORENA_MAX_VALUE_LENGTH:
        raise ValueError(
            "Torena Sim link exceeds the 15,000-character browser-safe limit. "
            "Select fewer Veterans with --trained-chara-id, or import trained_chara_data.json directly."
        )
    return value


def build_torena_import_url(
        trained_charas: Sequence[dict[str, Any]],
        base_url: str = TORENA_IMPORT_URL) -> str:
    """Build a canonical Torena Sim Veteran-import URL."""
    value = encode_trained_chara_payload(trained_charas)
    split = urlsplit(base_url)
    query = [(key, item) for key, item in parse_qsl(split.query, keep_blank_values=True)
             if key != TORENA_IMPORT_PARAM]
    query.append((TORENA_IMPORT_PARAM, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(query), split.fragment))


def load_trained_charas(path: Path, trained_chara_ids: set[int]) -> list[dict[str, Any]]:
    """Load an export and optionally retain only requested trained-character IDs."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read trained-character JSON: {exc}") from exc

    if not isinstance(payload, list):
        raise ValueError("Expected trained_chara_data.json to contain a JSON array.")

    trained_charas = [item for item in payload if isinstance(item, dict)]
    if trained_chara_ids:
        trained_charas = [item for item in trained_charas
                          if item.get("trained_chara_id") in trained_chara_ids]

    if not trained_charas:
        raise ValueError("No trained characters matched the requested import.")
    return trained_charas


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
            description="Generate a Torena Sim Veteran-import link from trained_chara_data.json")
    parser.add_argument("json_path", nargs="?", type=Path, default=Path("trained_chara_data.json"),
                        help="Export path (default: trained_chara_data.json)")
    parser.add_argument("--trained-chara-id", action="append", type=int, default=[],
                        help="Include one trained_chara_id; repeat to select multiple Veterans")
    parser.add_argument("--open", action="store_true",
                        help="Open the generated link in the default browser")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        trained_charas = load_trained_charas(args.json_path, set(args.trained_chara_id))
        url = build_torena_import_url(trained_charas)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    print(url)
    if args.open:
        import webbrowser
        if not webbrowser.open(url, new=2):
            raise SystemExit("The browser could not be opened. Copy the printed Torena Sim link instead.")


if __name__ == "__main__":
    main()
