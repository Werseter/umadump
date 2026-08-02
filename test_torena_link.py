from __future__ import annotations

import base64
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from torena_link import (TORENA_IMPORT_PARAM, TORENA_MAX_VALUE_LENGTH,
                         build_torena_import_url, encode_trained_chara_payload,
                         load_trained_charas)


class TorenaLinkTest(unittest.TestCase):
    def test_builds_v1_base64url_link_with_utf8_json(self) -> None:
        trained_charas = [{"trained_chara_id": 7, "memo": "日本語 memo"}]

        url = build_torena_import_url(trained_charas)
        encoded = parse_qs(urlsplit(url).query)[TORENA_IMPORT_PARAM][0]
        padding = "=" * (-len(encoded) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(encoded + padding).decode("utf-8"))

        self.assertEqual(decoded, {"v": 1, "data": trained_charas})
        self.assertNotIn("=", encoded)

    def test_rejects_links_above_contract_limit(self) -> None:
        with self.assertRaisesRegex(ValueError, "15,000-character"):
            encode_trained_chara_payload([{"memo": "x" * TORENA_MAX_VALUE_LENGTH}])

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
