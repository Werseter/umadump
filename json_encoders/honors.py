"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from game_structs.honors import WorkHonorDataHonorObject
from logger import logger
from .common import timestamp_to_str

if TYPE_CHECKING:
    from extractors.honors import HonorListExtractionData


# ---------------------------------------------------------------------------
# Honor list extraction
# ---------------------------------------------------------------------------

def _decode_honor_list_entry(honor: WorkHonorDataHonorObject) -> dict[str, Any]:
    fields = honor.fields
    return {
        "honor_id": fields.id,
        "create_time": timestamp_to_str(fields.createTime, use_zero_time=False),
    }


def decode_honor_list(data: HonorListExtractionData) -> dict[str, Any]:
    """Decode the available WorkHonorData fields in honor/index API shape."""

    honors = [_decode_honor_list_entry(honor.contents) for honor in data.honor_list if honor]
    logger.debug("WorkHonorData: honor_list=%d", len(honors))
    return {
        "honor_list": honors,
        "last_checked_time": data.last_checked_time,
    }
