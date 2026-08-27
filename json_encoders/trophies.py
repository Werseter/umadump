"""JSON decoders for umadump output."""
from __future__ import annotations

from ctypes import c_int32
from typing import Any, TYPE_CHECKING

from game_structs.collections import GenericDictionary, GenericList
from game_structs.trophies import TrophyDataCharaIdListDictionaryEntry, TrophyDataDictionaryEntry
from logger import logger
from .common import timestamp_to_str

if TYPE_CHECKING:
    from extractors.trophies import TrophyDataExtractionData


# ---------------------------------------------------------------------------
# Trophies extraction
# ---------------------------------------------------------------------------

def _build_trophy_room_race_instance_info_array(
        race_chara_data_dic: GenericDictionary[TrophyDataCharaIdListDictionaryEntry]) -> list[dict[str, Any]]:
    return [
        {
            "race_instance_id": race_chara_data_entry.key,
            "trophy_chara_info_array": [
                {
                    "chara_id": race_chara_entry.value.contents.fields.charaId.value,
                    "win_count": race_chara_entry.value.contents.fields.winCount.value,
                } for race_chara_entry in race_chara_data_entry.value.contents
                if race_chara_entry.value
            ] if race_chara_data_entry.value else [],
        } for race_chara_data_entry in race_chara_data_dic
    ]


def _build_limited_trophy_race_instance_info_array(chara_id_list: GenericList[c_int32]) -> list[dict[str, Any]]:
    return [
        {
            "race_instance_id": 0,
            "trophy_chara_info_array": [
                {
                    "chara_id": x.value,
                    "win_count": 0,
                } for x in chara_id_list
            ]
        }
    ]


def _decode_work_trophy_data_entry(entry: TrophyDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    if f.raceCharaDataDic and f.raceCharaDataDic.contents.fields.count != 0:
        race_instance_info_array = _build_trophy_room_race_instance_info_array(f.raceCharaDataDic.contents)
    elif f.charaIdList and f.charaIdList.contents.fields.size != 0:
        race_instance_info_array = _build_limited_trophy_race_instance_info_array(f.charaIdList.contents)
    else:
        return {}

    return {
        "trophy_id": f.trophyId.value,
        "create_time": timestamp_to_str(0),  # timestamp data not stored, comply to formatting
        "race_instance_info_array": race_instance_info_array,
    }


def decode_trophy_data(data: TrophyDataExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkTrophyData"""
    trophy_data = data.entries
    logger.debug("WorkTrophyData dictionary: count=%d", trophy_data.fields.count)

    return [_decode_work_trophy_data_entry(entry) for entry in trophy_data]
