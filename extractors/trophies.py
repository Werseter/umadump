from __future__ import annotations

from ctypes import c_int32
from dataclasses import dataclass
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.collections import GenericDictionary, GenericList
from game_structs.trophies import TrophyDataCharaIdListDictionaryEntry, TrophyDataDictionaryEntry
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.trophies import decode_trophy_data
from logger import logger
from .common import (ExtractorContext, ExtractorFingerprint, dictionary_fingerprint, first, first_object,
                     list_fingerprint)


@dataclass(frozen=True)
class TrophyDataExtractionData:
    entries: GenericDictionary[TrophyDataDictionaryEntry]

    def _first_trophy_entry_probe(self) -> ExtractorFingerprint:
        trophy = first_object(entry.value for entry in self.entries)
        if trophy is None:
            return "first_trophy", 0

        f = trophy.contents.fields
        return (
            "first_trophy",
            trophy.address,
            self._trophy_chara_id_list_probe(f.charaIdList),
            self._trophy_race_chara_data_dic_probe(f.raceCharaDataDic),
        )

    @staticmethod
    def _trophy_chara_id_list_probe(chara_id_list: C_Ptr[GenericList[c_int32]]) -> ExtractorFingerprint:
        if not chara_id_list:
            return "chara_id_list", 0
        chara_ids = chara_id_list.contents
        first_chara_id = first(chara_ids)
        return (
            "chara_id_list",
            list_fingerprint(chara_ids),
            first_chara_id.value if first_chara_id is not None else 0,
        )

    @staticmethod
    def _trophy_race_chara_data_dic_probe(
            race_chara_data_dic: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryEntry]],
    ) -> ExtractorFingerprint:
        if not race_chara_data_dic:
            return "race_chara_data_dic", 0
        race_entries = race_chara_data_dic.contents
        first_race = first_object(entry.value for entry in race_entries)
        if first_race is None:
            return "race_chara_data_dic", dictionary_fingerprint(race_entries), ("first_race", 0)

        chara_entries = first_race.contents
        first_chara = first_object(entry.value for entry in chara_entries)
        if first_chara is None:
            return (
                "race_chara_data_dic",
                dictionary_fingerprint(race_entries),
                ("first_race", first_race.address),
                dictionary_fingerprint(chara_entries),
                ("first_chara", 0),
            )

        return (
            "race_chara_data_dic",
            dictionary_fingerprint(race_entries),
            ("first_race", first_race.address),
            dictionary_fingerprint(chara_entries),
            ("first_chara", first_chara.address),
        )

    def fingerprint(self) -> ExtractorFingerprint:
        return "trophy_data", dictionary_fingerprint(self.entries), self._first_trophy_entry_probe()


def resolve_trophy_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[TrophyDataExtractionData]:
    """Resolve trophy data pointer."""

    trophy_data_ptr = wdm.fields.trophy
    if not trophy_data_ptr:
        logger.warning("WorkDataManager.trophy is null")
        return None

    dictionary_ptr = trophy_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkTrophyData.dataDic is null")
        return None

    return TrophyDataExtractionData(entries=dictionary_ptr.contents)


def resolve_trophy_data(context: ExtractorContext) -> Optional[TrophyDataExtractionData]:
    return resolve_trophy_data_extraction_data(context.work_data_manager)


def extract_trophy_data(data: TrophyDataExtractionData) -> list[dict[str, object]]:
    trophies = decode_trophy_data(data)
    logger.info("Decoded trophy data with %d trophy entries", len(trophies))
    return trophies
