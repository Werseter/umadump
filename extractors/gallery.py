from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from game_structs.collections import GenericDictionary
from game_structs.gallery import GalleryEventDataDictionaryEntry
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.gallery import decode_event_gallery_data
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, dictionary_fingerprint


@dataclass(frozen=True)
class EventGalleryExtractionData:
    event_data: GenericDictionary[GalleryEventDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        return "event_gallery_data", dictionary_fingerprint(self.event_data)


def resolve_event_gallery_extraction_data(wdm: WorkDataManagerObject) -> Optional[EventGalleryExtractionData]:
    """Resolve the persisted Event Gallery story IDs."""

    if not (gallery_data_ptr := wdm.fields.galleryData):
        logger.warning("WorkDataManager.galleryData is null")
        return None

    fields = gallery_data_ptr.contents.fields
    if not (event_data_ptr := fields.eventDataDict):
        logger.warning("WorkGalleryData.eventDataDict is null")
        return None

    return EventGalleryExtractionData(event_data_ptr.contents)


def resolve_event_gallery(context: ExtractorContext) -> Optional[EventGalleryExtractionData]:
    return resolve_event_gallery_extraction_data(context.work_data_manager)


def extract_event_gallery(data: EventGalleryExtractionData) -> dict[str, object]:
    event_data = decode_event_gallery_data(data)
    logger.info("Decoded %d Event Gallery entries", len(event_data["event_data_array"]))
    return event_data
