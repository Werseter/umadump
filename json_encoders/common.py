"""JSON decoders for umadump output."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

from game_structs.race import RaceRewardDataObject
from game_structs.skills import SkillDataObject

JST = timezone(timedelta(hours=9), "JST")


def timestamp_to_str(timestamp: int, tz: timezone = UTC, use_zero_time: bool = True) -> str:
    if not timestamp:
        return "0000-00-00 00:00:00" if use_zero_time else "1970-01-01 00:00:00"
    return str(datetime.fromtimestamp(timestamp, tz=tz).replace(tzinfo=None))


def decode_skill_data(entry: SkillDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "skill_id": f.skill_id,
        "level": f.level,
    }


def decode_race_reward_item(entry: RaceRewardDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "item_type": f.item_type,
        "item_id": f.item_id,
        "item_num": f.item_num,
    }
