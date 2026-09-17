"""JSON decoder for Event Gallery data."""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from logger import logger
from .common import timestamp_to_str

if TYPE_CHECKING:
    from extractors.gallery import EventGalleryExtractionData
    from extractors.talk_gallery import TalkGalleryExtractionData


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


# ---------------------------------------------------------------------------
# Talk Gallery extraction
# ---------------------------------------------------------------------------

def decode_talk_gallery_data(data: TalkGalleryExtractionData) -> dict[str, Any]:
    """Decode persisted Talk Gallery trigger IDs in LoginResponse row shape."""

    talk_gallery_list = [
        {"home_story_trigger_id": trigger_id.value, "new_flag": 0}
        for trigger_id in data.read_home_story_ids.contents
    ]

    talk_gallery_list += [
        {"home_story_trigger_id": new_info_item.contents.fields.id, "new_flag": 1}
        for new_info_item in data.new_info.contents if new_info_item
    ]

    talk_gallery_list.sort(key=lambda x: x["home_story_trigger_id"])
    logger.debug("TalkGallery: talk_gallery_list=%d", len(talk_gallery_list))
    return {"talk_gallery_list": talk_gallery_list}
