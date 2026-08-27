"""JSON decoders for umadump output."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

JST = timezone(timedelta(hours=9), "JST")


def timestamp_to_str(timestamp: int, tz: timezone = UTC, use_zero_time: bool = True) -> str:
    if not timestamp:
        return "0000-00-00 00:00:00" if use_zero_time else "1970-01-01 00:00:00"
    return str(datetime.fromtimestamp(timestamp, tz=tz).replace(tzinfo=None))
