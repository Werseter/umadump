from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.collections import GenericList
from game_structs.honors import WorkHonorDataHonorObject
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.honors import decode_honor_list
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, first_object_fingerprint, list_fingerprint


@dataclass(frozen=True)
class HonorListExtractionData:
    honor_list: GenericList[C_Ptr[WorkHonorDataHonorObject]]
    last_checked_time: int

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "honor_list",
            list_fingerprint(self.honor_list),
            first_object_fingerprint("first_honor", self.honor_list),
            self.last_checked_time,
        )


def resolve_honor_list_extraction_data(wdm: WorkDataManagerObject) -> Optional[HonorListExtractionData]:
    """Resolve the player's obtained honors and last check time."""

    if not (honor_data_ptr := wdm.fields.honorData):
        logger.warning("WorkDataManager.honorData is null")
        return None

    fields = honor_data_ptr.contents.fields
    if not (honor_list_ptr := fields.honorList):
        logger.warning("WorkHonorData.honorList is null")
        return None

    return HonorListExtractionData(
            honor_list=honor_list_ptr.contents,
            last_checked_time=fields.lastCheckTime,
    )


def resolve_honor_list(context: ExtractorContext) -> Optional[HonorListExtractionData]:
    return resolve_honor_list_extraction_data(context.work_data_manager)


def extract_honor_list(data: HonorListExtractionData) -> dict[str, object]:
    honors = decode_honor_list(data)
    logger.info("Decoded %d honor entries", len(honors["honor_list"]))
    return honors
