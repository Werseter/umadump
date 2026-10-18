"""Immutable gacha evidence."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from gacha_postprocess import collate_gacha_history
from json_encoders.gacha import GachaExecPayload, GachaHistoryPayload
from logger import logger


@dataclass(frozen=True)
class GachaCapture:
    viewer_id: int
    banner_id: int
    source: Literal['history', 'exec']
    payload: GachaHistoryPayload | GachaExecPayload


def gacha_output_key(capture: GachaCapture) -> str:
    return f'{capture.viewer_id}/{capture.banner_id}'


def _payload_without_response_time(payload: GachaHistoryPayload | GachaExecPayload) -> str:
    """Ignore response time for repeat detection; collation uses it for matching and ordering."""
    contents: dict[str, object] = dict(payload)
    if 'extra_data' in payload:
        details = cast(GachaExecPayload, payload)['extra_data']
        contents['extra_data'] = {key: value for key, value in details.items() if key != 'last_response_server_time'}
    return json.dumps(contents, ensure_ascii=False, separators=(',', ':'))


def _capture_path(folder: Path, capture: GachaCapture) -> Path | None:
    """Suppress an identical latest report."""
    paths = list(folder.glob(f'{capture.source}_[0-9]*.json')) if folder.is_dir() else []
    revisions = sorted((int(path.stem.rsplit('_', 1)[1]), path) for path in paths
                       if path.stem.rsplit('_', 1)[1].isdecimal())
    if revisions:
        revision, latest = revisions[-1]
        try:
            previous = cast(GachaHistoryPayload | GachaExecPayload, json.loads(latest.read_text(encoding='utf-8')))
            if _payload_without_response_time(previous) == _payload_without_response_time(capture.payload):
                logger.debug('gacha_data: unchanged %s report; retaining %s', capture.source, latest)
                return None
        except (OSError, json.JSONDecodeError):
            logger.warning('gacha_data: unreadable prior capture retained: %s', latest)
        revision += 1
    else:
        revision = 0
    return folder / f'{capture.source}_{revision:03d}.json'


def _write_capture(path: Path, payload: GachaHistoryPayload | GachaExecPayload) -> None:
    """Serialize before exclusive creation; remove the new file if writing fails."""
    contents = json.dumps(payload, ensure_ascii=False, indent=2).encode('utf-8')
    path.parent.mkdir(parents=True, exist_ok=True)
    # Opening is outside cleanup so a collision cannot delete existing evidence.
    stream = path.open('xb')
    try:
        with stream:
            stream.write(contents)
    except OSError:
        path.unlink(missing_ok=True)
        raise


def write_gacha_archive(folder: Path, key: str, capture: GachaCapture) -> None:
    """Retain evidence, then rebuild; failures use the extractor runner's normal retry."""
    banner_folder = folder / key
    account_folder = banner_folder.parent
    path = _capture_path(banner_folder, capture)
    output = account_folder / 'gacha_history.json'
    pending = account_folder / '.collation_pending'
    if path is None and not pending.exists() and output.exists():
        return
    account_folder.mkdir(parents=True, exist_ok=True)
    # Persist one dirty flag so failures remain retryable after restarting.
    pending.touch(exist_ok=True)
    if path is not None:
        _write_capture(path, capture.payload)
        logger.info('gacha_data: wrote JSON to %s', path)
    collate_gacha_history(account_folder, output)
    pending.unlink()
