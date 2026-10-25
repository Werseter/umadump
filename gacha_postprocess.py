"""Reconcile immutable exec reports with authoritative, single-account history."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import NamedTuple, cast

from json_encoders.common import timestamp_to_str
from json_encoders.gacha import (GachaExecPayload, GachaExecutionRecord, GachaHistoryPayload, GachaPullReward,
                                 GachaRewardRecord)
from logger import logger


class _GachaBatch(NamedTuple):
    execution: GachaExecutionRecord
    rewards: list[GachaRewardRecord]


def _capture_paths(capture_folder: Path) -> list[Path]:
    paths: list[Path] = []
    for banner in capture_folder.iterdir():
        if not banner.is_dir() or not banner.name.isdecimal():
            continue
        for path in banner.glob('*.json'):
            source, _, revision = path.stem.rpartition('_')
            if not revision.isdecimal():
                continue
            if source in ('history', 'exec'):
                paths.append(path)
    return sorted(paths, key=lambda path: (path.stat().st_mtime_ns, str(path)))


def _validate_batch(batch: _GachaBatch) -> None:
    positions = [reward['disp_order'] for reward in batch.rewards]
    count = len(positions)
    if not positions or batch.execution['draw_num'] != count or positions != list(range(1, count + 1)):
        raise ValueError(f'Incomplete gacha execution {batch.execution["exec_history_id"]}')


def _validate_capture(payload: GachaHistoryPayload, banner: int) -> list[_GachaBatch]:
    """Assemble complete batches; reject invalid identities, missing rewards, and orphan rewards."""
    rewards: dict[int, list[GachaRewardRecord]] = {}
    for reward in payload['gacha_reward_history_array']:
        rewards.setdefault(reward['exec_history_id'], []).append(reward)
    batches: list[_GachaBatch] = []
    ids: set[int] = set()
    for execution in payload['gacha_exec_history_array']:
        key = execution['exec_history_id']
        if type(key) is not int or key <= 0 or key in ids or execution['gacha_id'] != banner:
            raise ValueError('Invalid gacha execution identity')
        ids.add(key)
        batch_rewards = sorted(rewards.get(key, []), key=lambda row: row['disp_order'])
        batch = _GachaBatch(execution, batch_rewards)
        _validate_batch(batch)
        batches.append(batch)
    if rewards.keys() - ids:
        raise ValueError('Gacha rewards have no parent execution')
    return batches


def _load_pull(path: Path) -> GachaExecPayload:
    pull = cast(GachaExecPayload, json.loads(path.read_text(encoding='utf-8')))
    if pull['limit_item_info']['gacha_id'] != int(path.parent.name) or not pull['gacha_result_list']:
        raise ValueError(f'Invalid gacha exec report: {path}')
    return pull


def _check_history_conflict(previous: _GachaBatch, current: _GachaBatch, path: Path) -> None:
    if previous.execution != current.execution:
        raise ValueError(f'Conflicting gacha execution {current.execution["exec_history_id"]}: {path}')
    # Both batches have the same validated count and display positions.
    for before, after in zip(previous.rewards, current.rewards):
        if before != after:
            key = (after['exec_history_id'], after['disp_order'])
            raise ValueError(f'Conflicting gacha reward {key}: {path}')


def _load_captures(capture_folder: Path) -> tuple[list[_GachaBatch], list[GachaExecPayload]]:
    """Load immutable evidence, rejecting conflicting history and grouping each execution's rewards once."""
    batches: dict[int, _GachaBatch] = {}
    pulls: list[GachaExecPayload] = []
    for path in _capture_paths(capture_folder):
        if path.stem.startswith('exec_'):
            pulls.append(_load_pull(path))
            continue
        payload = cast(GachaHistoryPayload, json.loads(path.read_text(encoding='utf-8')))
        for batch in _validate_capture(payload, int(path.parent.name)):
            key = batch.execution['exec_history_id']
            if key in batches:
                _check_history_conflict(batches[key], batch, path)
            batches[key] = batch
    return list(batches.values()), pulls


def _pull_rewards(payload: GachaExecPayload) -> list[GachaRewardRecord]:
    """Unanchored exec rewards use history ID 0 and retain their within-pull order."""
    return [GachaRewardRecord(
            exec_history_id=0,
            disp_order=position,
            card_type=row['card_type'],
            card_id=row['card_id'],
            piece_id=row['piece_id'],
            common_item_category=row['common_item_category'],
            common_item_id=row['common_item_id'],
            convert_piece_num=row['convert_piece_num'],
            convert_common_item_num=row['convert_common_item_num'],
            additional_piece_num=row['additional_piece_num'],
    ) for position, row in enumerate(payload['gacha_result_list'], 1)]


def _comparable_reward(row: GachaPullReward | GachaRewardRecord) -> tuple[int, ...]:
    """Compare fields retained by both sources without modifying either record."""
    # Live results discard convert_piece_num; new_flag and win_prize are exec-only.
    return (row['card_type'], row['card_id'], row['piece_id'], row['common_item_category'], row['common_item_id'],
            row['convert_common_item_num'], row['additional_piece_num'])


def _pull_execution(payload: GachaExecPayload) -> GachaExecutionRecord:
    """Build the same history metadata for matching and unanchored output."""
    rows = payload['gacha_result_list']
    details = payload['extra_data']
    return GachaExecutionRecord(
            exec_history_id=0, gacha_id=payload['limit_item_info']['gacha_id'], gacha_card_type=rows[0]['card_type'],
            draw_type=details['draw_type'], draw_num=len(rows), cost_id=details['cost_id'],
            cost_count=details['cost_count'],
            create_time=timestamp_to_str(details['last_response_server_time']),
    )


def _execution_request(row: GachaExecutionRecord) -> tuple[int, ...]:
    """Banner, draw size/type, and in-game draw cost; never IDs or exchange-point balances."""
    return (row['gacha_id'], row['gacha_card_type'], row['draw_num'], row['draw_type'], row['cost_id'],
            row['cost_count'])


def _matching_history_ids(payload: GachaExecPayload, history: list[_GachaBatch],
                          *, match_time: bool = True) -> list[int]:
    """Match ordered rewards and draw cost, normally at the exact response-header second."""
    expected = _pull_execution(payload)
    request = _execution_request(expected)
    rewards = [_comparable_reward(row) for row in payload['gacha_result_list']]
    candidates: list[int] = []
    for batch in history:
        execution = batch.execution
        if _execution_request(execution) != request:
            continue

        if match_time and execution['create_time'] != expected['create_time']:
            continue

        actual = [_comparable_reward(row) for row in batch.rewards]
        if rewards == actual:
            candidates.append(execution['exec_history_id'])
    return candidates


def _clock_recovery_bounds(history: list[_GachaBatch], anchors: set[int]) -> dict[int, tuple[str, str]]:
    """Bracket a history session only with its immediately adjacent, exact-matched banner sessions."""
    banners: dict[int, list[GachaExecutionRecord]] = {}
    for batch in history:
        row = batch.execution
        banners.setdefault(row['gacha_id'], []).append(row)

    bounds: dict[int, tuple[str, str]] = {}
    for sessions in banners.values():
        sessions.sort(key=lambda row: (row['create_time'], row['exec_history_id']))
        for before, current, after in zip(sessions, sessions[1:], sessions[2:]):
            if before['exec_history_id'] not in anchors or after['exec_history_id'] not in anchors:
                continue

            if before['create_time'] < current['create_time'] < after['create_time']:
                bounds[current['exec_history_id']] = before['create_time'], after['create_time']
    return bounds


def _reconciled_pull_ids(pulls: list[GachaExecPayload], history: list[_GachaBatch]) -> list[int | None]:
    """Prefer exact-second matches; conservatively recover old captures with mixed account/response state."""
    candidates = [_matching_history_ids(pull, history) for pull in pulls]
    contenders = Counter(key for ids in candidates for key in ids)
    matches = [ids[0] if len(ids) == 1 and contenders[ids[0]] == 1 else None for ids in candidates]
    # Only pulls without exact candidates are eligible for clock recovery.
    if all(candidates):
        return matches

    if not (bounds := _clock_recovery_bounds(history, {key for key in matches if key is not None})):
        return matches

    # Never relax an ambiguous exact match or use a recovered match as another anchor.
    # The complete shared reward sequence and request must be unique in both directions,
    # including across saved history windows.
    # This repairs isolated clock gaps, not arbitrary missing or repeated pulls.
    contents = [_matching_history_ids(pull, history, match_time=False) for pull in pulls]
    claims = Counter(key for ids in contents for key in ids)
    for index, ids in enumerate(contents):
        if candidates[index] or len(ids) != 1 or claims[ids[0]] != 1 or ids[0] not in bounds:
            continue

        lower, upper = bounds[ids[0]]
        observed = _pull_execution(pulls[index])['create_time']
        if lower <= observed <= upper:
            matches[index] = ids[0]
    return matches


def _collated_history(batches: list[_GachaBatch]) -> GachaHistoryPayload:
    """Order whole batches before flattening: ID 0 does not identify one batch."""
    chronological = sorted(batches, key=lambda batch: (batch.execution['create_time'],
                                                       batch.execution['exec_history_id']))
    # Executions are newest first within each card type; rewards are oldest first.
    return GachaHistoryPayload(
            gacha_exec_history_array=sorted((batch.execution for batch in reversed(chronological)),
                                            key=lambda row: row['gacha_card_type']),
            gacha_reward_history_array=[reward for batch in chronological for reward in batch.rewards],
    )


def _publish_history(payload: GachaHistoryPayload, output_path: Path) -> None:
    """Suppress unchanged output; publish changes only after the complete payload is written."""
    contents = json.dumps(payload, indent=2, ensure_ascii=False)
    if output_path.exists() and output_path.read_text(encoding='utf-8') == contents:
        return
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_suffix('.json.tmp')
    try:
        temporary.write_text(contents, encoding='utf-8')
        temporary.replace(output_path)
    finally:
        temporary.unlink(missing_ok=True)


def collate_gacha_history(capture_folder: Path, output_path: Path) -> GachaHistoryPayload:
    """Collate one viewer's banner folders; unmatched execs use response time with ID 0.

    Matched pulls always use the authoritative history record, including its timestamp.
    Both arrays retain complete batches in their respective chronological order; known IDs break same-second ties.
    """
    history, pulls = _load_captures(capture_folder)
    matches = _reconciled_pull_ids(pulls, history)
    batches = list(history)
    matched = 0
    for pull, key in zip(pulls, matches):
        if key is not None:
            matched += 1
            continue
        batches.append(_GachaBatch(_pull_execution(pull), _pull_rewards(pull)))
    combined = _collated_history(batches)
    _publish_history(combined, output_path)
    logger.info('Collated %d history records and %d unanchored pulls to %s', len(history), len(pulls) - matched,
                output_path)
    return combined
