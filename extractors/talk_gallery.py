"""Talk Gallery extraction"""
from __future__ import annotations

from ctypes import c_int32
from dataclasses import dataclass
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.collections import GenericList
from game_structs.gallery import WorkTalkGalleryDataNewTriigerObject
from json_encoders.gallery import decode_talk_gallery_data
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, list_fingerprint, object_list_fingerprint


@dataclass(frozen=True)
class TalkGalleryExtractionData:
    """Persisted Talk Gallery trigger IDs."""

    new_info: C_Ptr[GenericList[C_Ptr[WorkTalkGalleryDataNewTriigerObject]]]
    read_home_story_ids: C_Ptr[GenericList[c_int32]]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "talk_gallery_data",
            object_list_fingerprint("new_info", self.new_info),
            list_fingerprint(self.read_home_story_ids.contents),
        )


def resolve_talk_gallery(context: ExtractorContext) -> Optional[TalkGalleryExtractionData]:
    """Resolve the persisted Talk Gallery trigger IDs."""

    if not (talk_data_ptr := context.work_data_manager.fields.talkGalleryData):
        logger.debug("WorkDataManager.talkGalleryData is null")
        return None
    if not (new_info_ptr := talk_data_ptr.contents.fields.newInfoList):
        logger.debug("WorkTalkGalleryData.newInfoList is null")
        return None

    if not (already_read_ptr := context.work_data_manager.fields.alreadyReadData):
        logger.debug("WorkDataManager.alreadyReadData is null")
        return None
    if not (read_home_story_ids_ptr := already_read_ptr.contents.fields.readHomeStoryIdList):
        logger.debug("WorkAlreadyReadData.readHomeStoryIdList is null")
        return None

    return TalkGalleryExtractionData(new_info=new_info_ptr, read_home_story_ids=read_home_story_ids_ptr)


def extract_talk_gallery(data: TalkGalleryExtractionData) -> dict[str, object]:
    talk_gallery_data = decode_talk_gallery_data(data)
    logger.info("Decoded %d Talk Gallery entries", len(talk_gallery_data["talk_gallery_list"]))
    return talk_gallery_data
