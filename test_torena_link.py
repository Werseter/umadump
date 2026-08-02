from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from torena_link import (TORENA_IMPORT_PARAM, TORENA_MAX_VALUE_LENGTH,
                         build_torena_import_url, encode_trained_chara_payload,
                         load_trained_charas)

_EXAMPLE_PATH = Path(__file__).parent / "examples" / "trained_chara_data.json"
_KNOWN_V1_PAYLOAD = "VUQBAAEYgxe2b1MBbC6ba55EGA6VICGGyUYbnEAC01lbW9FeGFtcGxl"


def _example_trained_chara() -> dict[str, object]:
    payload = json.loads(_EXAMPLE_PATH.read_text(encoding="utf-8"))
    return payload[0]


class TorenaLinkTest(unittest.TestCase):
    def test_builds_known_v1_bitvector_link(self) -> None:
        url = build_torena_import_url([_example_trained_chara()])
        encoded = parse_qs(urlsplit(url).query)[TORENA_IMPORT_PARAM][0]

        self.assertEqual(encoded, _KNOWN_V1_PAYLOAD)
        self.assertLess(len(encoded), 100)
        self.assertNotIn("=", encoded)

    def test_rejects_values_outside_lossless_ranges(self) -> None:
        trained_chara = {**_example_trained_chara(), "speed": 2048}

        with self.assertRaisesRegex(ValueError, "speed must be an integer from 0 to 2047"):
            encode_trained_chara_payload([trained_chara])

    def test_rejects_links_above_contract_limit(self) -> None:
        trained_chara = {**_example_trained_chara(), "memo": "x" * TORENA_MAX_VALUE_LENGTH}

        with self.assertRaisesRegex(ValueError, "15,000-character"):
            encode_trained_chara_payload([trained_chara])

    def test_load_filters_requested_trained_character_ids(self) -> None:
        payload = [
            {"trained_chara_id": 1, "card_id": 100101},
            {"trained_chara_id": 2, "card_id": 100201},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trained_chara_data.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            selected = load_trained_charas(path, {2})

        self.assertEqual(selected, [payload[1]])


if __name__ == "__main__":
    unittest.main()
