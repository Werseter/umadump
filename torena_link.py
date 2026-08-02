#!/usr/bin/env python3
"""Generate Torena Sim Veteran-import links from trained_chara_data.json."""
from __future__ import annotations

import argparse
from pathlib import Path
import json
from typing import Any, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TORENA_IMPORT_URL = "https://torena-sim.pages.dev/runners"
TORENA_IMPORT_PARAM = "from"
TORENA_MAX_VALUE_LENGTH = 15_000

_BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_MAGIC = 0x5544  # ASCII "UD"
_VERSION = 1
_MAX_20_BIT_VALUE = 0x0F_FFFF
_MAX_VETERANS = 0xFF_FF
_MAX_SKILLS = 0xFF
_MAX_MEMO_BYTES = 0xFF_FF

_STAT_FIELDS = ("speed", "stamina", "power", "guts", "wiz")
_APTITUDE_FIELDS = (
    "proper_distance_short",
    "proper_distance_mile",
    "proper_distance_middle",
    "proper_distance_long",
    "proper_ground_turf",
    "proper_ground_dirt",
    "proper_running_style_nige",
    "proper_running_style_senko",
    "proper_running_style_sashi",
    "proper_running_style_oikomi",
)


class _BitWriter:
    def __init__(self) -> None:
        self._bits: list[int] = []

    def write(self, value: int, bit_length: int) -> None:
        if value < 0 or value >= 1 << bit_length:
            raise ValueError(f"value {value} does not fit in {bit_length} bits")
        self._bits.extend((value >> bit) & 1 for bit in range(bit_length - 1, -1, -1))

    def to_base64url(self) -> str:
        self._bits.extend([0] * (-len(self._bits) % 6))
        encoded: list[str] = []
        for offset in range(0, len(self._bits), 6):
            index = 0
            for bit in self._bits[offset:offset + 6]:
                index = (index << 1) | bit
            encoded.append(_BASE64URL_ALPHABET[index])
        return "".join(encoded)


def _require_int(entry: dict[str, Any], key: str, minimum: int, maximum: int) -> int:
    value = entry.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{key} must be an integer from {minimum} to {maximum}")
    return value


def _optional_int(
        entry: dict[str, Any], key: str, minimum: int, maximum: int) -> int | None:
    if entry.get(key) is None:
        return None
    return _require_int(entry, key, minimum, maximum)


def _write_entry(writer: _BitWriter, entry: dict[str, Any]) -> None:
    writer.write(_require_int(entry, "card_id", 1, _MAX_20_BIT_VALUE), 20)

    for field in _STAT_FIELDS:
        writer.write(_require_int(entry, field, 0, 2047), 11)

    for field in _APTITUDE_FIELDS:
        writer.write(_require_int(entry, field, 1, 8) - 1, 3)

    writer.write(_optional_int(entry, "running_style", 1, 5) or 0, 3)

    rank_score = _optional_int(entry, "rank_score", 0, _MAX_20_BIT_VALUE)
    writer.write(0 if rank_score is None else 1, 1)
    if rank_score is not None:
        writer.write(rank_score, 20)

    writer.write(_optional_int(entry, "talent_level", 1, 5) or 0, 3)

    skills = entry.get("skill_array")
    if not isinstance(skills, list) or len(skills) > _MAX_SKILLS:
        raise ValueError(f"skill_array must contain at most {_MAX_SKILLS} skills")
    writer.write(len(skills), 8)
    for skill in skills:
        if not isinstance(skill, dict):
            raise ValueError("skill_array entries must be objects")
        writer.write(_require_int(skill, "skill_id", 1, _MAX_20_BIT_VALUE), 20)
        level_key = "skill_level" if skill.get("level") is None else "level"
        writer.write(_require_int(skill, level_key, 1, 7), 3)

    memo = entry.get("memo") if isinstance(entry.get("memo"), str) else ""
    memo_bytes = memo.encode("utf-8")
    if len(memo_bytes) > _MAX_MEMO_BYTES:
        raise ValueError(f"memo must be at most {_MAX_MEMO_BYTES} UTF-8 bytes")
    writer.write(len(memo_bytes), 16)
    for byte in memo_bytes:
        writer.write(byte, 8)


def encode_trained_chara_payload(trained_charas: Sequence[dict[str, Any]]) -> str:
    """Encode Torena's Cygames-shaped Veteran projection as a BitVector."""
    if len(trained_charas) > _MAX_VETERANS:
        raise ValueError(f"trained character data must contain at most {_MAX_VETERANS} entries")

    writer = _BitWriter()
    writer.write(_MAGIC, 16)
    writer.write(_VERSION, 8)
    writer.write(len(trained_charas), 16)
    for entry in trained_charas:
        if not isinstance(entry, dict):
            raise ValueError("trained character entries must be objects")
        _write_entry(writer, entry)

    value = writer.to_base64url()
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
