"""JSON decoder for Event Gallery data."""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from logger import logger
from .common import timestamp_to_str

if TYPE_CHECKING:
    from extractors.gallery import EventGalleryExtractionData


# ---------------------------------------------------------------------------
# Event Gallery extraction
# ---------------------------------------------------------------------------

def decode_event_gallery_data(data: EventGalleryExtractionData) -> dict[str, Any]:
    """Decode WorkGalleryData's persisted event lists in LoginResponse API shape."""

    event_data_array = [
        {
            "chara_id": entry.key,
            "data_id": event_id.value,
            "create_time": timestamp_to_str(0),
            "new_flag": 0,
        }
        for entry in data.event_data
        if entry.value
        for event_id in entry.value.contents
    ]
    logger.debug("WorkGalleryData: event_data_array=%d", len(event_data_array))
    return {"event_data_array": event_data_array}
