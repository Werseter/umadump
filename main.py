#!/usr/bin/env python3
"""
WorkDataManager singleton resolver.

Supports live mode (process memory reads) and offline mode (full-memory minidump).
Walks Il2CppMetadataRegistration to locate Gallop.Singleton<WorkDataManager>._instance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import time
from ctypes import c_int32
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Optional, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs import (AcquiredSkillObject, CardDataDictionaryEntry, ChampionsRaceInfoObject,
                          ChampionsRoomInfoObject, ChampionsRoomUserObject, ChampionsUserCharaObject, FactorDataObject,
                          FavoriteDataDictionaryEntry, FriendDataObject, GenericDictionary, GenericList,
                          HintLevelDictionaryEntry, RaceHistoryInfoObject, RaceHorseDataObject,
                          RaceHorseDataRaceResultObject, SkillDataObject, SuccessionCharaDataObject,
                          SuccessionCharaObject, SuccessionHistoryObject, SupportCardDataDictionaryEntry,
                          TeamStadiumRaceCharaResultObject, TeamStadiumRaceResultObject,
                          TeamStadiumResultBonusDataObject, TeamStadiumResultObject, TeamStadiumResultScoreDataObject,
                          TempDataObject, TempDataSingletonStaticFields, TrainedCharaDataDictionaryEntry,
                          TrainedCharaDataObject, TrainedCharaObject, TrainedCharaRaceResultObject,
                          TrainedCharaSupportCardDataObject, TrainedCharaSupportCardListObject,
                          TrophyDataCharaIdListDictionaryEntry, TrophyDataDictionaryEntry, WorkDataManagerObject,
                          WorkDataManagerSingletonStaticFields, WorkFriendDataObject, WorkTeamStadiumDataObject,
                          WorkTeamStadiumOpponentDataObject)
from il2cpp_structs import (RuntimeIl2CppClass, RuntimeIl2CppGenericClass, RuntimeIl2CppGenericInst,
                            RuntimeIl2CppMetadataRegistration, RuntimeIl2CppType)
from il2cpp_utils import Il2CppResolutionManager, default_metadata_path_from_exe, parse_minimal_metadata
from logger import configure_logging, logger
from memory import MemoryReader, MinidumpMemory, POINTER_SIZE, TARGET_MODULE
from schema_validation import validate_registered_classes
from update_check import CURRENT_VERSION, notify_if_update_available

ProcessMemory: type[MemoryReader]
if os.name == "nt":
    # noinspection PyTypeChecker
    from memory import WindowsProcessMemory as ProcessMemory
else:
    # noinspection PyTypeChecker
    from memory import LinuxProcessMemory as ProcessMemory


# ---------------------------------------------------------------------------
# Registration scanner
# ---------------------------------------------------------------------------

class Il2CppRegistrationResolver:
    """Scans a process module for Il2CppMetadataRegistration."""

    def __init__(self, mem: MemoryReader, module_base: int, module_size: int) -> None:
        self.mem = mem
        self.module_base = module_base
        self.module_size = module_size

    def _in_module(self, va: int) -> bool:
        return self.module_base <= va < self.module_base + self.module_size

    def _value_bytes(self, value: int) -> bytes:
        return value.to_bytes(POINTER_SIZE, "little", signed=False)

    def _read_ptr_table(self, ptr: int, count: int) -> list[int]:
        if not ptr or count == 0:
            return []
        return list(struct.unpack(f"<{count}Q", self.mem.read(ptr, count * POINTER_SIZE)))

    def _find_registration(self, pattern_re: re.Pattern[bytes], overlap: int,
                           array_ptr_offset: int, array_count: int,
                           name: str, offset_adjustment: int) -> Optional[int]:
        logger.info("Scanning for %s", name)
        for match_va in self.mem.scan(self.module_base, self.module_size, pattern_re, overlap):
            array_ptr_va = self.mem.read_pointer(match_va + array_ptr_offset)
            if not self._in_module(array_ptr_va):
                continue

            pointers = self._read_ptr_table(array_ptr_va, array_count)
            if not all(self._in_module(x) for x in pointers):
                continue

            result = match_va + offset_adjustment
            logger.info("Found %s", name)
            return result

        logger.warning("%s was not found in the module scan range", name)
        return None

    def find_metadata_registration(self, type_def_count: int) -> Optional[int]:
        """
        Locate Il2CppMetadataRegistration by scanning for the
        (fieldOffsetsCount, …, typeDefinitionsSizesCount) pair.
        """
        # ---------------------------------------------------------------------------
        # Il2CppMetadataRegistration scan constants (x64).
        #
        # The struct alternates (int32_count, ptr) pairs.  On x64 each int32
        # is followed by 4 bytes of alignment padding, so every "slot"
        # occupies exactly POINTER_SIZE (8) bytes.  The slot numbering
        # below therefore counts 8-byte slots, not C fields:
        #
        #   [0] genericClassesCount      [1] genericClasses
        #   [2] genericInstsCount        [3] genericInsts
        #   [4] genericMethodTableCount  [5] genericMethodTable
        #   [6] typesCount               [7] types
        #   [8] methodSpecsCount         [9] methodSpecs
        #  [10] fieldOffsetsCount ← pattern anchor (= type_def_count)
        #  [11] fieldOffsets      ← wildcard
        #  [12] typeDefinitionsSizesCount ← second anchor (= type_def_count)
        #  [13] typeDefinitionsSizes ← validated pointer array
        #
        # _value_pattern() emits 8-byte patterns (value + zero padding)
        # which match the (int32 + pad) layout.
        # ---------------------------------------------------------------------------
        META_REG_SLOTS_BEFORE_ANCHOR = 10  # slots 0-9 precede fieldOffsetsCount
        META_REG_ARRAY_PTR_SLOT = 3  # typeDefinitionsSizes relative to anchor

        anchor = re.escape(self._value_bytes(type_def_count))
        pattern_re = re.compile(anchor + (b"." * POINTER_SIZE) + anchor, re.DOTALL)
        pattern_width = (POINTER_SIZE * 3)
        return self._find_registration(
                pattern_re=pattern_re,
                overlap=pattern_width - 1,
                array_ptr_offset=POINTER_SIZE * META_REG_ARRAY_PTR_SLOT,
                array_count=type_def_count,
                name="MetadataRegistration",
                offset_adjustment=-(POINTER_SIZE * META_REG_SLOTS_BEFORE_ANCHOR),
        )


# ---------------------------------------------------------------------------
# Misc Utils
# ---------------------------------------------------------------------------
def _timestamp_to_str(timestamp: int) -> str:
    if not timestamp:
        return "0000-00-00 00:00:00"
    return str(datetime.fromtimestamp(timestamp, tz=UTC).replace(tzinfo=None))


def _write_json_file(name: str, output_path: Path, payload: Any) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pretty_json = json.dumps(payload, indent=2, ensure_ascii=False)
    output_path.write_text(pretty_json, encoding="utf-8")
    logger.info("%s: wrote JSON to %s", name, output_path)


def _write_multi_output_json(output_folder: Path, key: str, payload: Any) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, payload)


# ---------------------------------------------------------------------------
# Support card extraction
# ---------------------------------------------------------------------------

def _support_card_entries_ptr_and_sizes(wdm: WorkDataManagerObject) \
        -> Optional[GenericDictionary[SupportCardDataDictionaryEntry]]:
    """Resolve support-card entries pointer and dictionary sizes."""
    support_card_data_ptr = wdm.fields.supportCardData
    if not support_card_data_ptr:
        logger.warning("WorkDataManager.SupportCardData is null")
        return None

    dictionary_ptr = support_card_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkSupportCardData.dataDic is null")
        return None

    dictionary = dictionary_ptr.contents
    return dictionary


def _decode_support_card_entry(entry: SupportCardDataDictionaryEntry) -> Optional[dict[str, Any]]:
    if entry.hashCode < 0 or not entry.value:
        return None
    f = entry.value.contents.fields
    return {
        "viewer_id": 0,
        "support_card_id": f.supportCardId.value,
        "exp": f.exp.value,
        "limit_break_count": f.limitBreakCount.value,
        "favorite_flag": int(f.isFavoriteLock.value),
        "stock": f.stock.value,
        "possess_time": 0,
        "create_time": _timestamp_to_str(f.createTime.value),
        "extra_data": {
            "level": f.level.value,
            "max_level": f.maxLevel.value,
            "best_training": f.bestTraining,
        }
    }


def decode_support_card_dictionary(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkSupportCardData -> Dictionary<int, SupportCardData>."""
    result: list[dict[str, Any]] = []

    support_card_data_dict = _support_card_entries_ptr_and_sizes(wdm)
    if support_card_data_dict is None:
        return result

    logger.debug("SupportCard dictionary: count=%d", support_card_data_dict.fields.count)

    for entry in support_card_data_dict:
        decoded = _decode_support_card_entry(entry)
        if decoded is None:
            continue
        result.append(decoded)

    return result


# ---------------------------------------------------------------------------
# Trained Chara extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrainedCharaEntriesInfo:
    entries: GenericDictionary[TrainedCharaDataDictionaryEntry]
    favorite_entries: GenericDictionary[FavoriteDataDictionaryEntry]


def _trained_chara_entries_ptr_and_sizes(wdm: WorkDataManagerObject) -> Optional[TrainedCharaEntriesInfo]:
    """Resolve trained-chara entries pointer and dictionary sizes."""
    trained_chara_data_ptr = wdm.fields.trainedCharaData
    if not trained_chara_data_ptr:
        logger.warning("WorkDataManager.trainedCharaData is null")
        return None

    dictionary_ptr = trained_chara_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkTrainedCharaData.dataDic is null")
        return None

    fav_dictionary_ptr = trained_chara_data_ptr.contents.fields.favoriteDataDict
    if not fav_dictionary_ptr:
        logger.warning("WorkTrainedCharaData.favoriteDataDict is null")
        return None

    dictionary = dictionary_ptr.contents
    fav_dictionary = fav_dictionary_ptr.contents
    return TrainedCharaEntriesInfo(dictionary, fav_dictionary)


def _decode_acquired_skill_entry(entry: AcquiredSkillObject) -> dict[str, int]:
    f = entry.fields
    return {
        "skill_id": f.masterId.value,
        "level": f.level.value,
    }


def _decode_trained_chara_support_card_data_entry(entry: TrainedCharaSupportCardDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "position": f.position.value,
        "support_card_id": f.supportCardId.value,
        "exp": f.exp.value,
        "limit_break_count": f.limitBreakCount.value
    }


def _decode_race_history_entry(entry: RaceHistoryInfoObject) -> dict[str, int]:
    f = entry.fields
    return {
        "turn": f.turn.value,
        "program_id": f.programId.value,
        "weather": f.weather.value,
        "ground_condition": f.groundCondition.value,
        "running_style": f.runningStyle.value,
        "popularity": 0,
        "result_rank": f.resultRank.value,
        "result_time": 0,
        "prize_money": 0
    }


def _decode_factor_entry(entry: FactorDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "factor_id": f.factorId.value,
        "level": f.factorLv.value,
    }


def _decode_succession_chara_entry(entry: SuccessionCharaDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "position_id": f.positionId.value,
        "card_id": f.cardId.value,
        "rank": f.rank.value,
        "rarity": f.rarity.value,
        "talent_level": f.level.value,
        "factor_id_array": [x.contents.fields.factorId.value for x in f.factorDataArray],
        "factor_info_array": [_decode_factor_entry(x.contents) for x in f.factorDataArray],
        "win_saddle_id_array": [x.value for x in f.winSaddleIdArray],
        "owner_viewer_id": f.ownerViewerId.value
    }


def _decode_succession_history_entry(entry: SuccessionHistoryObject) -> dict[str, Any]:
    f = entry.fields

    return {
        "id": f.id,
        "viewer_id": f.viewer_id,
        "trained_chara_id": f.trained_chara_id,
        "history_type": f.hisotry_type,
        "succession_card_id": f.succession_card_id,
        "date": f.date,
        "rental_viewer_id": 0,
        "user_name": f.user_name.value,
        "circle_name": f.circle_name.value
    }


def _decode_trained_chara_entry(entry: TrainedCharaDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    return {
        "viewer_id": f.viewerId.value,
        "trained_chara_id": f.id.value,
        "owner_viewer_id": f.ownerViewerId.value,
        "owner_trained_chara_id": 0,
        "single_mode_chara_id": 0,
        "chara_seed": 0,
        "card_id": f.cardId.value,
        "succession_trained_chara_id_1": 0,
        "succession_trained_chara_id_2": 0,
        "use_type": f.useType,
        "speed": f.speed.value,
        "stamina": f.stamina.value,
        "power": f.power.value,
        "wiz": f.wiz.value,
        "guts": f.guts.value,
        "fans": f.fans.value,
        "rank_score": f.rankScore.value,
        "rank": f.rank.value,
        "scenario_id": f.scenarioId.value,
        "route_id": 0,
        "arrive_route_race_id": 0,
        "proper_ground_turf": f.properGroundTurf.value,
        "proper_ground_dirt": f.properGroundDirt.value,
        "proper_running_style_nige": f.properRunningStyleNige.value,
        "proper_running_style_senko": f.properRunningStyleSenko.value,
        "proper_running_style_sashi": f.properRunningStyleSashi.value,
        "proper_running_style_oikomi": f.properRunningStyleOikomi.value,
        "proper_distance_short": f.properDistanceShort.value,
        "proper_distance_mile": f.properDistanceMile.value,
        "proper_distance_middle": f.properDistanceMiddle.value,
        "proper_distance_long": f.properDistanceLong.value,
        "succession_num": f.successionCount.value,
        "rarity": f.rarity.value,
        "is_saved": int(f.isSaved.value),
        "is_locked": int(f.isLock.value),
        "talent_level": f.talentLevel.value,
        "race_cloth_id": 0,
        "chara_grade": f.charaGrade.value,
        "running_style": f.runningStyle.value,
        "nickname_id": f.nickNameId.value,
        "wins": f.singleWinNum.value,
        "register_time": f.createTime.value,
        "create_time": f.createTime.value,
        "skill_array": [
            _decode_acquired_skill_entry(x.contents) for x in f.acquiredSkillArray],
        "support_card_list": [
            _decode_trained_chara_support_card_data_entry(x.contents) for x in f.supportCardArray],
        "race_result_list": [
            _decode_race_history_entry(x.contents) for x in f.singleModeRaceResultArray],
        "win_saddle_id_array": [x.value for x in f.winSaddleIdArray],
        "nickname_id_array": [x.value for x in f.nickNameIdArray],
        "factor_id_array": [x.contents.fields.factorId.value for x in f.factorDataArray],
        "factor_info_array": [_decode_factor_entry(x.contents) for x in f.factorDataArray],
        "succession_chara_array": [
            _decode_succession_chara_entry(x.contents) for x in f.successionCharaList.contents],
        "succession_history_array": [
            _decode_succession_history_entry(x.contents) for x in f.successionHistoryList.contents],
        "icon_type": f.favoriteData.contents.fields.type if f.favoriteData else 0,
        "memo": f.favoriteData.contents.fields.memo.value if f.favoriteData else "",
    }


def _decode_favorite_entry(entry: FavoriteDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    return {
        "trained_chara_id": f.trainedCharaId,
        "type": f.type,
        "memo": f.memo.value,
    }


def decode_trained_chara_dictionary(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkTrainedCharaData -> Dictionary<int, TrainedCharaData>."""
    result: dict[int, dict[str, Any]] = {}

    entries_info = _trained_chara_entries_ptr_and_sizes(wdm)
    if entries_info is None:
        return []

    logger.debug("TrainedChara dictionary: count=%d, favorite_count=%d",
                 entries_info.entries.fields.count, entries_info.favorite_entries.fields.count)

    for entry in entries_info.entries:
        decoded = _decode_trained_chara_entry(entry)
        trained_chara_id: int = decoded['trained_chara_id']
        result[trained_chara_id] = decoded

    for fav_entry in entries_info.favorite_entries:
        decoded = _decode_favorite_entry(fav_entry)
        trained_chara_id = decoded['trained_chara_id']
        if trained_chara_id in result:
            result[trained_chara_id]['icon_type'] = decoded['type']
            result[trained_chara_id]['memo'] = decoded['memo']

    return list(result.values())


# ---------------------------------------------------------------------------
# Chara/card extraction
# ---------------------------------------------------------------------------

def _card_data_entries_ptr_and_sizes(wdm: WorkDataManagerObject) \
        -> Optional[GenericDictionary[CardDataDictionaryEntry]]:
    """Resolve chara/card-data entries pointer and dictionary sizes."""
    card_data_data_ptr = wdm.fields.cardData
    if not card_data_data_ptr:
        logger.warning("WorkDataManager.cardData is null")
        return None

    dictionary_ptr = card_data_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkCardData.dataDic is null")
        return None

    dictionary = dictionary_ptr.contents
    return dictionary


def _decode_hint_level_dictionary_entry(entry: HintLevelDictionaryEntry) -> dict[str, int]:
    return {
        "skill_id": entry.key.value,
        "level": entry.value.value,
    }


def _decode_card_data_entry(entry: CardDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    return {
        "card_id": f.cardId.value,
        "rarity": f.rarity.value,
        "talent_level": f.talentLevel.value,
        "create_time": _timestamp_to_str(f.createTime.value),
        "skill_data_array": [
            _decode_hint_level_dictionary_entry(x) for x in f.hintLevelDic.contents
        ] if f.hintLevelDic else []
    }


def decode_card_data_dictionary(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkCardData -> Dictionary<int, CardData>."""
    result: list[dict[str, Any]] = []

    card_data_dict = _card_data_entries_ptr_and_sizes(wdm)
    if card_data_dict is None:
        return []

    logger.debug("CardData dictionary: count=%d", card_data_dict.fields.count)

    for entry in card_data_dict:
        decoded = _decode_card_data_entry(entry)
        result.append(decoded)

    return result


# ---------------------------------------------------------------------------
# Friends extraction
# ---------------------------------------------------------------------------

def _resolve_work_friend_data_ptr(wdm: WorkDataManagerObject) -> Optional[WorkFriendDataObject]:
    """Resolve friend data pointer"""
    friend_data_data_ptr = wdm.fields.friendData
    if not friend_data_data_ptr:
        logger.warning("WorkDataManager.friendData is null")
        return None

    data = friend_data_data_ptr.contents

    if not data.fields.followList:
        logger.warning("WorkFriendData.followList is null")
        return None

    if not data.fields.followerList:
        logger.warning("WorkFriendData.followerList is null")
        return None

    if not data.fields.recommendList:
        logger.warning("WorkFriendData.recommendList is null")
        return None

    return data


def _decode_follow_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "friend_viewer_id": f.viewerId.value,
        "state": f.friendState.value,
        "follow_time": _timestamp_to_str(f.followUnixTime.value),
        "follower_time": _timestamp_to_str(f.followerUnixTime.value)
    }


def _decode_follower_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    # kinda just need swapped order to match API exactly
    return {
        "friend_viewer_id": f.viewerId.value,
        "state": f.friendState.value,
        "follower_time": _timestamp_to_str(f.followerUnixTime.value),
        "follow_time": _timestamp_to_str(f.followUnixTime.value)
    }


def _decode_recommend_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "friend_viewer_id": f.viewerId.value,
        "state": f.friendState.value,
        "follow_time": "",
        "follower_time": ""
    }


def _decode_friend_trained_chara_entry(entry: TrainedCharaDataObject) -> dict[str, Any]:
    f = entry.fields

    return {
        "viewer_id": f.viewerId.value,
        "trained_chara_id": 0,
        "card_id": f.cardId.value,
        "rank_score": f.rankScore.value,
        "rank": f.rank.value,
        "proper_ground_turf": f.properGroundTurf.value,
        "proper_ground_dirt": f.properGroundDirt.value,
        "proper_running_style_nige": f.properRunningStyleNige.value,
        "proper_running_style_senko": f.properRunningStyleSenko.value,
        "proper_running_style_sashi": f.properRunningStyleSashi.value,
        "proper_running_style_oikomi": f.properRunningStyleOikomi.value,
        "proper_distance_short": f.properDistanceShort.value,
        "proper_distance_mile": f.properDistanceMile.value,
        "proper_distance_middle": f.properDistanceMiddle.value,
        "proper_distance_long": f.properDistanceLong.value,
        "rarity": f.rarity.value,
        "talent_level": f.talentLevel.value,
        "register_time": f.createTime.value,
        "factor_id_array": [x.contents.fields.factorId.value for x in f.factorDataArray],
        "factor_info_array": [_decode_factor_entry(x.contents) for x in f.factorDataArray],
        "skill_count": len(list(f.acquiredSkillArray))
    }


def _decode_user_info_summary_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    last_login_time = f.lastLoginTime.value or _timestamp_to_str(f.lastLoginUnixTime.value)

    user_trained_chara = None
    if f.virtualTrainedCharaData:
        user_trained_chara = _decode_friend_trained_chara_entry(f.virtualTrainedCharaData.contents)

    return {
        "viewer_id": f.viewerId.value,
        "name": f.name.value,
        "honor_id": f.honorId.value,
        "last_login_time": last_login_time,
        "leader_chara_id": 0,
        "leader_chara_dress_id": 0,
        "support_card_id": f.supportCardId.value,
        "partner_chara_id": 0,
        "comment": f.comment.value,
        "fan": f.fan.value,
        "rank_score": 0,
        "team_stadium_win_count": 0,
        "single_mode_play_count": 0,
        "team_evaluation_point": 0,
        "user_support_card": {
            "support_card_id": f.supportCardId.value,
            "exp": f.supportCardExp.value,
            "limit_break_count": f.supportCardLimitBreakCount.value
        },
        "user_trained_chara": user_trained_chara,
        "circle_info": {
            "circle_id": f.circleId.value,
            "name": f.circleName.value
        } if f.circleId.value else None,
        "circle_user": {
            "viewer_id": f.viewerId.value,
            "circle_id": f.circleId.value,
            "membership": 0,
            "join_time": "",
            "penalty_end_time": "",
            "item_request_end_time": "",
            "last_check_post_id": 0,
            "ranking_result_check_time": ""
        },
        "friend_state": f.friendState.value
    }


def _decode_follower_info_summary_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    last_login_time = f.lastLoginTime.value or _timestamp_to_str(f.lastLoginUnixTime.value)

    return {
        "viewer_id": f.viewerId.value,
        "honor_id": f.honorId.value,
        "name": f.name.value,
        "last_login_time": last_login_time,
        "support_card_id": f.supportCardId.value,
        "user_support_card": {
            "support_card_id": f.supportCardId.value,
            "exp": f.supportCardExp.value,
            "limit_break_count": f.supportCardLimitBreakCount.value
        }
    }


def _decode_work_friend_data(friend_data: WorkFriendDataObject) -> dict[str, Any]:
    f = friend_data.fields
    follows = f.followList.contents
    # filter to skip emitting mutuals twice
    followers = [x for x in f.followerList.contents if x.contents.fields.friendState.value != 3]
    recommends = f.recommendList.contents
    return {
        "last_friend_checked_time": _timestamp_to_str(f.lastCheckedTime.value),
        "friend_list": [
            *[_decode_follow_list_entry(x.contents) for x in follows],
            *[_decode_follower_list_entry(x.contents) for x in followers]
        ],
        "recommend_list": [_decode_recommend_list_entry(x.contents) for x in recommends],
        # NOTE: Ordering scheme for user_info_summary_list and follower_info_summary_list is not known
        "user_info_summary_list": [
            *[_decode_user_info_summary_list_entry(x.contents) for x in follows],
            *[_decode_user_info_summary_list_entry(x.contents) for x in recommends]
        ],
        "follower_info_summary_list": [_decode_follower_info_summary_list_entry(x.contents) for x in followers],
        "follower_num": f.followerNum.value
    }


def decode_friend_data(wdm: WorkDataManagerObject) -> dict[str, Any]:
    """Descend WorkDataManager -> WorkFriendData"""
    friend_data = _resolve_work_friend_data_ptr(wdm)
    if friend_data is None:
        return {}

    logger.debug("FriendData: follows=%d, followers=%d",
                 friend_data.fields.followList.contents.fields.size,
                 friend_data.fields.followerList.contents.fields.size)

    result = _decode_work_friend_data(friend_data)
    return result


# ---------------------------------------------------------------------------
# Trophies extraction
# ---------------------------------------------------------------------------

def _resolve_work_trophy_data_ptr(wdm: WorkDataManagerObject) -> Optional[GenericDictionary[TrophyDataDictionaryEntry]]:
    """Resolve trophy data pointer"""
    trophy_data_ptr = wdm.fields.trophy
    if not trophy_data_ptr:
        logger.warning("WorkDataManager.trophy is null")
        return None

    dictionary_ptr = trophy_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkTrophyData.dataDic is null")
        return None

    return dictionary_ptr.contents


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
        "create_time": _timestamp_to_str(0),  # timestamp data not stored, comply to formatting
        "race_instance_info_array": race_instance_info_array,
    }


def decode_trophy_data(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkTrophyData"""
    trophy_data = _resolve_work_trophy_data_ptr(wdm)
    if trophy_data is None:
        return []

    logger.debug("WorkTrophyData dictionary: count=%d", trophy_data.fields.count)

    return [_decode_work_trophy_data_entry(entry) for entry in trophy_data]


# ---------------------------------------------------------------------------
# Race replay extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RaceReplayOutput:
    key: str
    payload: dict[str, Any]


def _team_stadium_match_key(race_result_array: list[dict[str, Any]]) -> str:
    race_scenario_digest_source = "|".join(race_result["race_scenario"] for race_result in race_result_array)
    race_scenario_digest = hashlib.sha1(race_scenario_digest_source.encode("utf-8")).hexdigest()[:12]
    return f"team_stadium/{race_scenario_digest}"


def _decode_team_stadium_result_bonus_data(entry: TeamStadiumResultBonusDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "score_bonus_id": f.score_bonus_id,
        "bonus_score": f.bonus_score,
        "condition_type": f.condition_type,
        "condition_value_1": f.condition_value_1,
        "condition_value_2": f.condition_value_2,
        "score_rate": f.score_rate,
    }


def _decode_team_stadium_result_score_data(entry: TeamStadiumResultScoreDataObject) -> dict[str, Any]:
    f = entry.fields
    bonus_array = [_decode_team_stadium_result_bonus_data(x.contents) for x in f.bonus_array]

    return {
        "raw_score_id": f.raw_score_id,
        "num": f.num,
        "score": f.score,
        "bonus_num": sum(1 for bonus in bonus_array if bonus["condition_type"] != 4),
        "bonus_array": bonus_array,
    }


def _decode_team_stadium_race_chara_result(entry: TeamStadiumRaceCharaResultObject) -> dict[str, Any]:
    f = entry.fields

    return {
        "frame_order": f.frame_order,
        "viewer_id": f.viewer_id,
        "trained_chara_id": f.trained_chara_id,
        "team_id": f.team_id,
        "finish_order": f.finish_order,
        "finish_time": f.finish_time,
        "score_array": [_decode_team_stadium_result_score_data(x.contents) for x in f.score_array]
    }


def _decode_team_stadium_race_result(race_result_obj: TeamStadiumRaceResultObject,
                                     *,
                                     self_evaluate: int,
                                     opponent_evaluate: int) -> Optional[tuple[dict[str, Any], dict[str, Any]]]:
    f = race_result_obj.fields
    race_horse_data_array = [_decode_race_horse_data_entry(x.contents) for x in f.raceHorseDataArray]
    race_horse_data_array.sort(key=lambda x: (x["mob_id"], x["team_id"], x["team_member_id"]))

    race_start_params = {
        "round": f.round.value,
        "race_instance_id": f.raceInstanceId.value,
        "season": f.season.value,
        "weather": f.weather.value,
        "ground_condition": f.groundCondition.value,
        "random_seed": f.randomSeed.value,
        "race_horse_data_array": race_horse_data_array,
        "self_evaluate": self_evaluate,
        "opponent_evaluate": opponent_evaluate,
    }
    race_result = {
        "distance_type": f.raceNum.value,
        "race_scenario": f.raceScenario.value,
        "round": f.round.value,
        "team_total_score": f.teamTotalScore.value,
        "team_score_array": [_decode_team_stadium_result_score_data(x.contents) for x in f.teamScoreArray],
        "win_type": f.roundResult,
        "current_consecutive_win_count": f.currentConsecutiveWinCount.value,
        "bonus_rate_by_next_win": f.bonusRateByNextWin.value,
        "chara_result_array": [_decode_team_stadium_race_chara_result(x.contents) for x in f.charaResultArray],
    }

    return race_start_params, race_result


def _decode_team_stadium_replays(
        team_stadium_data: WorkTeamStadiumDataObject,
        team_stadium_opponent_data: WorkTeamStadiumOpponentDataObject,
        team_stadium_result: TeamStadiumResultObject) -> list[RaceReplayOutput]:
    support_card_bonus = 0
    if support_card_bonus_info_ptr := team_stadium_data.fields.teamStadiumSupportCardBonusInfo:
        support_card_bonus = support_card_bonus_info_ptr.contents.fields.totalSupportCardBonus

    race_start_params_array: list[dict[str, Any]] = []
    race_result_array: list[dict[str, Any]] = []
    for race_result_ptr in team_stadium_result.fields.raceResultArray:
        if not race_result_ptr:
            continue
        decoded = _decode_team_stadium_race_result(
                race_result_ptr.contents,
                self_evaluate=0,  # weighed sum of each team member's evaluationPoint, but not stored in WorkDataManager
                opponent_evaluate=team_stadium_opponent_data.fields.evaluationPoint.value,
        )
        if decoded is not None:
            race_start_params, race_result = decoded
            race_start_params_array.append(race_start_params)
            race_result_array.append(race_result)

    if not race_start_params_array:
        return []

    match_payload = {
        "use_item_id_array": [x.value for x in team_stadium_result.fields.useItemIdArray],
        "race_start_params_array": race_start_params_array,
        "race_result_array": race_result_array,
        "rp_info": {},
        "item_info_array": [],
        "is_include_unsupported_race": bool(team_stadium_result.fields.isIncludeUnsupportedRace),
        "winning_reward_info_array": [],
        "winning_reward_guarantee_status": team_stadium_opponent_data.fields.winningRewardGuaranteeStatus.value,
        "last_checked_round": 0,
        "support_card_bonus": support_card_bonus,
        "user_team_data_array_copy": [],
        "user_trained_chara_array_copy": [],
        "opponent_info_copy": {},
        "opponent_chara_info_array_latest_copy": [],
    }
    return [RaceReplayOutput(
            key=_team_stadium_match_key(race_result_array),
            # payload={"data": match_payload}, -- envelope skipped for TT races
            payload=match_payload,
    )]


def decode_race_replays(wdm: WorkDataManagerObject) -> list[RaceReplayOutput]:
    """Collect API-like race replay payloads from known WorkDataManager sub-structures."""
    if not (team_stadium_data_ptr := wdm.fields.teamStadiumData):
        return []
    team_stadium_data = team_stadium_data_ptr.contents

    if not (team_stadium_status_ptr := team_stadium_data.fields.teamStadiumStatus):
        return []
    team_stadium_status = team_stadium_status_ptr.contents

    if not (team_stadium_opponent_data_ptr := team_stadium_status.fields.opponentData):
        return []
    team_stadium_opponent_data = team_stadium_opponent_data_ptr.contents

    if not (team_stadium_result_ptr := team_stadium_status_ptr.contents.fields.result):
        return []
    team_stadium_result = team_stadium_result_ptr.contents

    return _decode_team_stadium_replays(team_stadium_data, team_stadium_opponent_data, team_stadium_result)


# ---------------------------------------------------------------------------
# Champions Meeting race extraction
# ---------------------------------------------------------------------------

def _resolve_champions_race_info(temp_data: TempDataObject) -> Optional[ChampionsRaceInfoObject]:
    champions_data = temp_data.fields.championsData
    if not champions_data:
        logger.warning("TempData.championsData is null")
        return None

    race_info = champions_data.contents.fields.raceInfo
    if not race_info:
        logger.warning("TempData.ChampionsTempData.raceInfo is null")
        return None

    return race_info.contents


def _decode_champions_room_info(room: ChampionsRoomInfoObject) -> dict[str, Any]:
    f = room.fields
    return {
        "room_id": f.room_id,
        "user_entry_num": f.user_entry_num,
        "race_instance_id": f.race_instance_id,
        "season": f.season,
        "weather": f.weather,
        "ground_condition": f.ground_condition,
        "random_seed": f.random_seed,
        "race_scenario": f.race_scenario.value,
    }


def _decode_champions_user_chara_entry(entry: ChampionsUserCharaObject) -> dict[str, int]:
    f = entry.fields
    return {
        "team_member_id": f.team_member_id,
        "race_cloth_id": f.race_cloth_id,
        "nickname_id": f.nick_name_id,
        "chara_id": f.chara_id,
    }


def _decode_champions_room_user_entry(entry: ChampionsRoomUserObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "room_id": f.room_id,
        "viewer_id": f.viewer_id,
        "name": f.name.value,
        "honor_id": f.honor_id,
        "team_id": f.team_id,
        "entry_chara_array": [_decode_champions_user_chara_entry(x.contents) for x in f.entry_chara_array],
    }


def _decode_skill_data_entry(entry: SkillDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "skill_id": f.skill_id,
        "level": f.level,
    }


def _decode_race_horse_result_entry(entry: RaceHorseDataRaceResultObject) -> dict[str, int]:
    f = entry.fields
    return {
        "turn": f.turn,
        "program_id": f.program_id,
        "weather": 0,
        "ground_condition": 0,
        "running_style": 0,
        "popularity": 0,
        "result_rank": f.result_rank,
        "result_time": 0,
        "prize_money": 0,
    }


def _decode_race_horse_data_entry(entry: RaceHorseDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "frame_order": f.frame_order,
        "viewer_id": f.viewer_id,
        "trainer_name": f.trainer_name.value if f.viewer_id else None,
        "owner_viewer_id": f.owner_viewer_id,
        "owner_trainer_name": f.owner_trainer_name.value if f.owner_viewer_id else "",
        "single_mode_chara_id": f.single_mode_chara_id,
        "trained_chara_id": f.trained_chara_id,
        "nickname_id": f.nickname_id,
        "chara_id": f.chara_id,
        "card_id": f.card_id,
        "mob_id": f.mob_id,
        "rarity": f.rarity,
        "talent_level": f.talent_level,
        "skill_array": [_decode_skill_data_entry(x.contents) for x in f.skill_array],
        "stamina": f.stamina,
        "speed": f.speed,
        "pow": f.pow,
        "guts": f.guts,
        "wiz": f.wiz,
        "running_style": f.running_style,
        "race_dress_id": f.race_dress_id,
        "chara_color_type": f.chara_color_type,
        "npc_type": f.npc_type,
        "final_grade": f.final_grade,
        "popularity": f.popularity,
        "popularity_mark_rank_array": [x.value for x in f.popularity_mark_rank_array],
        "proper_distance_short": f.proper_distance_short,
        "proper_distance_mile": f.proper_distance_mile,
        "proper_distance_middle": f.proper_distance_middle,
        "proper_distance_long": f.proper_distance_long,
        "proper_running_style_nige": f.proper_running_style_nige,
        "proper_running_style_senko": f.proper_running_style_senko,
        "proper_running_style_sashi": f.proper_running_style_sashi,
        "proper_running_style_oikomi": f.proper_running_style_oikomi,
        "proper_ground_turf": f.proper_ground_turf,
        "proper_ground_dirt": f.proper_ground_dirt,
        "motivation": f.motivation,
        "win_saddle_id_array": [x.value for x in f.win_saddle_id_array],
        "race_result_array": [_decode_race_horse_result_entry(x.contents) for x in f.race_result_array],
        "team_id": f.team_id,
        "team_member_id": f.team_member_id,
        "team_rank": f.team_rank,
        "single_mode_win_count": f.single_mode_win_count,
        "item_id_array": [x.value for x in f.item_id_array],
        "motivation_change_flag": f.motivation_change_flag,
        "frame_order_change_flag": f.frame_order_change_flag,
    }


def _decode_trained_chara_support_card_list_entry(entry: TrainedCharaSupportCardListObject) -> dict[str, int]:
    f = entry.fields
    return {
        "position": f.position,
        "support_card_id": f.support_card_id,
        "exp": f.exp,
        "limit_break_count": f.limit_break_count,
    }


def _decode_trained_chara_race_result_entry(entry: TrainedCharaRaceResultObject) -> dict[str, int]:
    f = entry.fields
    return {
        "turn": f.turn,
        "program_id": f.program_id,
        "weather": f.weather,
        "ground_condition": f.ground_condition,
        "running_style": f.running_style,
        "popularity": 0,
        "result_rank": f.result_rank,
        "result_time": 0,
        "prize_money": 0,
    }


def _decode_succession_chara_temp_entry(entry: SuccessionCharaObject) -> dict[str, Any]:
    f = entry.fields
    factor_ids = [x.value for x in f.factor_id_array]
    return {
        "position_id": f.position_id,
        "card_id": f.card_id,
        "rank": f.rank,
        "rarity": f.rarity,
        "talent_level": f.talent_level,
        "owner_viewer_id": f.owner_viewer_id,
        "factor_id_array": factor_ids,
        "factor_info_array": [{"factor_id": factor_id, "level": 0} for factor_id in factor_ids],
        "win_saddle_id_array": [x.value for x in f.win_saddle_id_array],
    }


def _decode_champions_trained_chara_entry(entry: TrainedCharaObject,
                                          race_horse_by_trained_id: dict[int, dict[str, Any]]) -> dict[str, Any]:
    f = entry.fields
    trained_chara_id = f.trained_chara_id
    race_horse = race_horse_by_trained_id.get(trained_chara_id, {})
    factor_ids = [x.value for x in f.factor_id_array]
    return {
        "viewer_id": f.viewer_id,
        "trained_chara_id": trained_chara_id,
        "owner_viewer_id": f.owner_viewer_id,
        "owner_trained_chara_id": 0,
        "single_mode_chara_id": 0,
        "card_id": f.card_id,
        "speed": f.speed,
        "stamina": f.stamina,
        "power": f.power,
        "wiz": f.wiz,
        "guts": f.guts,
        "fans": f.fans,
        "rank_score": f.rank_score,
        "rank": f.rank,
        "proper_ground_turf": f.proper_ground_turf,
        "proper_ground_dirt": f.proper_ground_dirt,
        "proper_running_style_nige": f.proper_running_style_nige,
        "proper_running_style_senko": f.proper_running_style_senko,
        "proper_running_style_sashi": f.proper_running_style_sashi,
        "proper_running_style_oikomi": f.proper_running_style_oikomi,
        "proper_distance_short": f.proper_distance_short,
        "proper_distance_mile": f.proper_distance_mile,
        "proper_distance_middle": f.proper_distance_middle,
        "proper_distance_long": f.proper_distance_long,
        "succession_num": f.succession_num,
        "rarity": f.rarity,
        "is_saved": f.is_saved,
        "is_locked": f.is_locked,
        "talent_level": f.talent_level,
        "race_cloth_id": race_horse.get("race_dress_id", 0),
        "running_style": f.running_style,
        "nickname_id": f.nickname_id,
        "wins": f.wins,
        "create_time": f.create_time.value,
        "skill_array": [_decode_skill_data_entry(x.contents) for x in f.skill_array],
        "support_card_list": [
            _decode_trained_chara_support_card_list_entry(x.contents) for x in f.support_card_list],
        "race_result_list": [_decode_trained_chara_race_result_entry(x.contents) for x in f.race_result_list],
        "win_saddle_id_array": [x.value for x in f.win_saddle_id_array],
        "factor_id_array": factor_ids,
        "factor_info_array": [{"factor_id": factor_id, "level": 0} for factor_id in factor_ids],
        "succession_history_array": [_decode_succession_history_entry(x.contents) for x in f.succession_history_array],
        "succession_chara_array": [_decode_succession_chara_temp_entry(x.contents) for x in f.succession_chara_array],
        "nickname_id_array": [x.value for x in f.nickname_id_array],
        "team_member_id": race_horse.get("team_member_id", 0),
        "race_running_style": race_horse.get("running_style", f.running_style),
        "scenario_id": f.scenario_id,
    }


def order_champions_race_horses(room_user_array: list[dict[str, Any]],
                                race_horse_data_array: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order horse rows to match room-user ordering and each user's entry sequence."""
    room_user_order = {user["viewer_id"]: idx for idx, user in enumerate(room_user_array)}
    room_user_team_order: dict[tuple[int, int], int] = {}
    for user in room_user_array:
        viewer_id = user["viewer_id"]
        for team_idx, chara in enumerate(user.get("entry_chara_array", [])):
            team_member_id = chara.get("team_member_id", 0)
            room_user_team_order[(viewer_id, team_member_id)] = team_idx

    return sorted(
            race_horse_data_array,
            key=lambda horse: (
                room_user_order.get(horse.get("viewer_id", 0), len(room_user_order)),
                room_user_team_order.get(
                        (horse.get("viewer_id", 0), horse.get("team_member_id", 0)),
                        horse.get("team_member_id", 0),
                ),
                horse.get("frame_order", 0),
            )
    )


def decode_champions_meeting_race_data(temp_data: TempDataObject) -> dict[str, Any]:
    """Descend TempData -> ChampionsTempData -> ChampionsRaceInfo and normalize the data payload."""
    race_info_obj = _resolve_champions_race_info(temp_data)
    if race_info_obj is None:
        return {}

    race_info = race_info_obj.fields
    if not race_info.isSet:
        logger.info("No Champions Meeting race replay available for extraction")
        return {}

    room_info: dict[str, Any] = {}
    if race_info.roomInfo:
        room_info = _decode_champions_room_info(race_info.roomInfo.contents)

    room_user_array = [_decode_champions_room_user_entry(x.contents) for x in race_info.roomUserArray]
    race_horse_data_array = [_decode_race_horse_data_entry(x.contents) for x in race_info.raceHorseDataArray]
    race_horse_data_array = order_champions_race_horses(room_user_array, race_horse_data_array)

    race_horse_by_trained_id: dict[int, dict[str, Any]] = {
        x.get("trained_chara_id", 0): x for x in race_horse_data_array if x.get("trained_chara_id", 0) > 0
    }
    trained_chara_array = [
        _decode_champions_trained_chara_entry(x.contents, race_horse_by_trained_id) for x in race_info.trainedCharaArray
    ]

    return {
        "room_info": room_info,
        "room_user_array": room_user_array,
        "race_horse_data_array": race_horse_data_array,
        "trained_chara_array": trained_chara_array,
    }


def decode_champions_meeting_race(temp_data: TempDataObject) -> dict[str, Any]:
    """Public wrapper preserving the existing API payload shape."""
    data = decode_champions_meeting_race_data(temp_data)
    return {"data": data} if data else {}


# ---------------------------------------------------------------------------
# Singleton resolution
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GenericClassCollection:
    """Collected RuntimeIl2CppGenericClass pointers plus dereferenced cache by address."""

    ptrs: list[C_Ptr[RuntimeIl2CppGenericClass]]
    by_addr: dict[int, RuntimeIl2CppGenericClass]


def _collect_generic_classes(meta_reg: RuntimeIl2CppMetadataRegistration) -> GenericClassCollection:
    """Read and dereference ``MetadataRegistration.genericClasses`` into fast lookup form."""

    gc_ptrs = list(meta_reg.genericClasses.as_span(meta_reg.genericClassesCount))
    gc_addrs = [ptr.address for ptr in gc_ptrs if ptr]
    gc_values = C_Ptr[RuntimeIl2CppGenericClass].deref_many_at(gc_addrs)
    gc_by_addr: dict[int, RuntimeIl2CppGenericClass] = {addr: gc for addr, gc in zip(gc_addrs, gc_values)}
    return GenericClassCollection(ptrs=gc_ptrs, by_addr=gc_by_addr)


@dataclass(frozen=True)
class SingletonGenericClassMatch:
    seq: int
    class_ptr: C_Ptr[RuntimeIl2CppClass]


@dataclass(frozen=True)
class SingletonSpec[TSingletonObject: StructOrSimple]:
    name: str
    target_type: str
    static_fields_type: type[Any]
    output_type: type[TSingletonObject]
    namespace: str = "Gallop"
    singleton_class: str = "Singleton`1"
    singleton_namespace: str = "Gallop"


WORKDATAMANAGER_SINGLETON_SPEC = SingletonSpec(
        name="workdatamanager",
        target_type="WorkDataManager",
        static_fields_type=WorkDataManagerSingletonStaticFields,
        output_type=WorkDataManagerObject,
)

TEMPDATA_SINGLETON_SPEC = SingletonSpec(
        name="tempdata",
        target_type="TempData",
        static_fields_type=TempDataSingletonStaticFields,
        output_type=TempDataObject,
)

SINGLETON_SPEC_REGISTRY: dict[str, SingletonSpec[Any]] = {
    spec.name: spec for spec in (
        WORKDATAMANAGER_SINGLETON_SPEC,
        TEMPDATA_SINGLETON_SPEC,
    )
}


def _build_singleton_generic_index(meta_reg: RuntimeIl2CppMetadataRegistration) \
        -> dict[tuple[int, int], SingletonGenericClassMatch]:
    """Build ``(generic-definition-type-ptr, arg0-type-ptr) -> matched class`` index."""
    generic_classes = _collect_generic_classes(meta_reg)

    gc_by_seq: dict[int, RuntimeIl2CppGenericClass] = {}
    inst_addrs: list[int] = []
    for seq, gc_ptr in enumerate(generic_classes.ptrs):
        if not gc_ptr:
            continue
        gc = generic_classes.by_addr[gc_ptr.address]
        if not gc.context.class_inst:
            continue
        gc_by_seq[seq] = gc
        inst_addrs.append(gc.context.class_inst.address)

    inst_values = C_Ptr[RuntimeIl2CppGenericInst].deref_many_at(inst_addrs)
    inst_by_addr = {addr: inst for addr, inst in zip(inst_addrs, inst_values)}

    argv0_ptr_addrs: list[int] = []
    argv0_index_by_inst_addr: dict[int, int] = {}
    for inst_addr, inst in inst_by_addr.items():
        if inst.type_argc < 1 or not inst.type_argv:
            continue
        argv0_index_by_inst_addr[inst_addr] = len(argv0_ptr_addrs)
        argv0_ptr_addrs.append(inst.type_argv.address)

    argv0_ptrs = C_Ptr[C_Ptr[RuntimeIl2CppType]].deref_many_at(argv0_ptr_addrs)
    argv0_type_ptr_by_inst_addr = {
        inst_addr: argv0_ptrs[idx].address
        for inst_addr, idx in argv0_index_by_inst_addr.items()
    }

    by_key: dict[tuple[int, int], SingletonGenericClassMatch] = {}
    for seq, gc in gc_by_seq.items():
        arg0_type_ptr = argv0_type_ptr_by_inst_addr.get(gc.context.class_inst.address)
        if arg0_type_ptr is None or not gc.cached_class or not gc.type:
            continue
        generic_type_addr = gc.type.address
        if generic_type_addr is None:
            continue
        if not isinstance(generic_type_addr, int) or not isinstance(arg0_type_ptr, int):
            continue
        key = (generic_type_addr, arg0_type_ptr)
        by_key.setdefault(key, SingletonGenericClassMatch(seq=seq, class_ptr=gc.cached_class))
    return by_key


def resolve_singleton[TSingletonObject: StructOrSimple](
        resolver: Il2CppResolutionManager,
        spec: SingletonSpec[TSingletonObject],
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> Optional[C_Ptr[TSingletonObject]]:
    meta_reg = resolver.meta_reg
    if not meta_reg.genericClasses:
        logger.warning("MetadataRegistration genericClasses pointer is missing")
        return None

    singleton_typedef = resolver.require_type_def_index([spec.singleton_class], spec.singleton_namespace)
    target_typedef = resolver.require_type_def_index([spec.target_type], spec.namespace)
    singleton_type_ptr = resolver.require_runtime_type_ptr_for_typedef(singleton_typedef)
    target_type_ptr = resolver.require_runtime_type_ptr_for_typedef(target_typedef)
    resolver.require_static_field_local_index(singleton_typedef, "_instance")

    matched = singleton_index.get((singleton_type_ptr, target_type_ptr))
    if matched is None:
        type_string = f"{spec.singleton_namespace}::{spec.singleton_class}[{spec.namespace}{spec.target_type}]"
        logger.warning("No %s instantiation found", type_string)
        return None

    logger.debug("Matched singleton generic instantiation at index %d", matched.seq)
    static_fields_type = spec.static_fields_type
    # noinspection PyTypeHints
    static_fields_ptr_type = C_Ptr[static_fields_type]  # type: ignore[valid-type]
    static_fields_ptr = static_fields_ptr_type(int(matched.class_ptr.contents.static_fields))
    # noinspection PyTypeChecker
    return type_cast(C_Ptr[TSingletonObject], static_fields_ptr.contents._instance)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Extractor definitions
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Extractor[TExtractorInput, TMultiOutputPayload]:
    """
    Unified extractor definition.

    Single-file mode:  set ``output_path``; the extracted payload is serialised directly.
    Multi-file mode:   set ``output_folder``, ``key_fn`` (and optionally ``writer``);
                       the payload is written to ``output_folder/<key>.json``.
    """
    name: str
    extract: Callable[[TExtractorInput], Any]
    output_path: Optional[Path] = None
    output_folder: Optional[Path] = None
    key_fn: Optional[Callable[[TMultiOutputPayload], str]] = None
    writer: Optional[Callable[[Path, str, TMultiOutputPayload], None]] = None


def _run_extractors(extractors: tuple[Extractor[Any, Any], ...], data: Any) -> None:
    """Run a sequence of extractors against *data*, writing output as configured."""
    for extractor in extractors:
        logger.info("Running extractor: %s", extractor.name)
        try:
            payload = extractor.extract(data)
            if extractor.output_path is not None:
                _write_json_file(extractor.name, extractor.output_path, payload)
            elif extractor.output_folder is not None and extractor.key_fn is not None:
                extractor.output_folder.mkdir(parents=True, exist_ok=True)
                writer = extractor.writer or _write_multi_output_json
                payloads = payload if isinstance(payload, list) else [payload]
                for item in payloads:
                    key = extractor.key_fn(item)
                    if not key:
                        continue
                    writer(extractor.output_folder, key, item)
        except Exception:
            logger.exception("Error in extractor %s", extractor.name)


def _extract_support_cards(wdm: WorkDataManagerObject) -> Any:
    support_cards = decode_support_card_dictionary(wdm)
    logger.info("Decoded %d support cards", len(support_cards))
    return support_cards


def _extract_trained_chara_data(wdm: WorkDataManagerObject) -> Any:
    trained_charas = decode_trained_chara_dictionary(wdm)
    logger.info("Decoded %d trained chara entries", len(trained_charas))
    return trained_charas


def _extract_card_data(wdm: WorkDataManagerObject) -> Any:
    cards = decode_card_data_dictionary(wdm)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    logger.info("Decoded %d owned character entries", len(cards))
    return cards


def _extract_friend_data(wdm: WorkDataManagerObject) -> dict[str, Any]:
    friends = decode_friend_data(wdm)
    logger.info("Decoded friend data with %d friend entries", len(friends.get('friend_list', [])))
    return friends


def _extract_trophy_data(wdm: WorkDataManagerObject) -> list[dict[str, Any]]:
    trophies = decode_trophy_data(wdm)
    logger.info("Decoded trophy data with %d trophy entries", len(trophies))
    return trophies


def _extract_race_replays(wdm: WorkDataManagerObject) -> list[RaceReplayOutput]:
    replays = decode_race_replays(wdm)
    logger.info("Decoded %d race replay payloads", len(replays))
    return replays


def _race_replay_key(replay: RaceReplayOutput) -> str:
    return replay.key


def _write_race_replay_json(output_folder: Path, key: str, replay: RaceReplayOutput) -> None:
    output_path = output_folder / f"{key}.json"
    _write_json_file(f"{output_folder.name}[{key}]", output_path, replay.payload)


WORKDATA_EXTRACTORS: tuple[Extractor[Any, Any], ...] = (
    Extractor(
            name="support_cards",
            output_path=Path("support_card_data.json"),
            extract=_extract_support_cards,
    ),
    Extractor(
            name="trained_chara_data",
            output_path=Path("trained_chara_data.json"),
            extract=_extract_trained_chara_data,
    ),
    Extractor(
            name="card_data",
            output_path=Path("card_data.json"),
            extract=_extract_card_data,
    ),
    Extractor(
            name="friend_data",
            output_path=Path("friend_data.json"),
            extract=_extract_friend_data
    ),
    Extractor(
            name="trophy_data",
            output_path=Path("trophy_data.json"),
            extract=_extract_trophy_data,
    ),
    Extractor(
            name="race_replays",
            output_folder=Path("race_replays"),
            extract=_extract_race_replays,
            key_fn=_race_replay_key,
            writer=_write_race_replay_json,
    ),
)


def _champions_meeting_race_room_id(payload: dict[str, Any]) -> str:
    room_id = payload.get("data", {}).get("room_info", {}).get("room_id", 0)
    if not room_id:
        logger.debug("Champions meeting race has no room_id, skipping folder extraction")
        return ""
    return str(room_id)


TEMPDATA_EXTRACTORS: tuple[Extractor[Any, Any], ...] = (
    Extractor(
            name="champions_meeting_race_folder",
            output_folder=Path("champions_meeting_race"),
            extract=decode_champions_meeting_race,
            key_fn=_champions_meeting_race_room_id,
            writer=_write_multi_output_json,
    ),
)


@dataclass(frozen=True)
class SingletonExtractorSet:
    """A singleton root plus the extractors that consume it."""

    spec: SingletonSpec[Any]
    extractors: tuple[Extractor[Any, Any], ...]


SINGLETON_EXTRACTOR_SETS: tuple[SingletonExtractorSet, ...] = (
    SingletonExtractorSet(WORKDATAMANAGER_SINGLETON_SPEC, WORKDATA_EXTRACTORS),
    SingletonExtractorSet(TEMPDATA_SINGLETON_SPEC, TEMPDATA_EXTRACTORS),
)

ResolvedSingletonRoots = dict[str, Optional[C_Ptr[Any]]]


def _resolve_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> ResolvedSingletonRoots:
    """Resolve singleton roots once so reload passes can skip the metadata/generic scan."""
    roots: ResolvedSingletonRoots = {}
    for extractor_set in SINGLETON_EXTRACTOR_SETS:
        spec = extractor_set.spec
        roots[spec.name] = resolve_singleton(resolver, spec, singleton_index)
    return roots


def _dump_singleton_root(extractor_set: SingletonExtractorSet, instance: Optional[C_Ptr[Any]]) -> None:
    """Run configured extractors from an already-resolved singleton root."""
    spec = extractor_set.spec
    if not instance:
        logger.warning("%s not resolved", spec.target_type)
        return

    _run_extractors(extractor_set.extractors, instance.contents)


def _dump_from_singleton_roots(roots: ResolvedSingletonRoots) -> float:
    """Run all extractors from already-resolved singleton roots and return elapsed seconds."""
    t_start = time.perf_counter()
    for extractor_set in SINGLETON_EXTRACTOR_SETS:
        _dump_singleton_root(extractor_set, roots.get(extractor_set.spec.name))
    return time.perf_counter() - t_start


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """Parse CLI flags for live/minidump mode and optional validation-only run."""

    parser = argparse.ArgumentParser(
            description="Resolve Gallop.WorkDataManager from a live process or an offline minidump")
    parser.add_argument("--version", action="version", version=f"%(prog)s {CURRENT_VERSION}")
    parser.add_argument("--minidump", help="Path to full-memory minidump (offline mode)")
    parser.add_argument("--metadata-path", help="global-metadata.dat path; required with --minidump")
    parser.add_argument("--no-update-check", action="store_true",
                        help="Skip the startup GitHub release check")
    parser.add_argument("--validate-only", action="store_true",
                        help="Only validate registered classes and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()
    if args.minidump and not args.metadata_path:
        parser.error("--metadata-path is required when using --minidump")
    return args


@dataclass(frozen=True)
class SetupContext:
    mem: MemoryReader
    metadata_path: Path


def _setup(args: argparse.Namespace) -> SetupContext:
    """Build memory interface and metadata path from CLI args."""
    mem: MemoryReader
    if args.minidump:
        logger.info("Offline mode from minidump: %s", args.minidump)
        mem = MinidumpMemory(args.minidump)
        metadata_path = Path(args.metadata_path)
    else:
        logger.info("Live mode from process memory")
        mem = ProcessMemory()
        metadata_path = Path(args.metadata_path) if args.metadata_path else default_metadata_path_from_exe(
                mem.exe_path())

    return SetupContext(mem=mem, metadata_path=metadata_path)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def _build_resolver(mem: MemoryReader, metadata_path: Path) -> Il2CppResolutionManager:
    """Create ``Il2CppResolutionManager`` and run schema validation for registered wrappers."""

    metadata = parse_minimal_metadata(metadata_path)
    logger.info("Parsed metadata: type_defs=%d", len(metadata.type_defs))

    base, size = mem.module_info(TARGET_MODULE)

    reg_va = Il2CppRegistrationResolver(mem, base, size).find_metadata_registration(len(metadata.type_defs))
    if reg_va is None:
        raise RuntimeError("Could not locate Il2CppMetadataRegistration")
    meta_reg = C_Ptr[RuntimeIl2CppMetadataRegistration](reg_va).contents

    resolver = Il2CppResolutionManager(mem, metadata, meta_reg)
    validate_registered_classes(resolver)
    return resolver


def _run_live_reload_loop(mem: MemoryReader, roots: ResolvedSingletonRoots) -> None:
    """Repeatedly rerun extractors using fixed singleton roots and fresh memory reads."""
    pass_num = 1
    while True:
        if not mem.is_alive():
            logger.info("Target process has exited; stopping live reload")
            return

        if pass_num > 1:
            logger.info("Clearing memory cache before reload pass %d", pass_num)
            mem.clear_cache()

        logger.info("Reload extractor pass %d", pass_num)
        elapsed = _dump_from_singleton_roots(roots)
        logger.info("Reload extractor pass %d completed in %.2fs", pass_num, elapsed)

        try:
            response = input("Press Enter to rescan, or type q then Enter to exit...")
        except EOFError:
            return

        if response.strip().lower() in {"q", "quit", "exit"}:
            return

        pass_num += 1


def main() -> None:
    args = _parse_args()
    configure_logging(args.verbose)
    t_start = time.perf_counter()

    logger.info("umadump %s", CURRENT_VERSION)
    if not args.no_update_check:
        notify_if_update_available(CURRENT_VERSION)

    setup = _setup(args)
    logger.info("Metadata path: %s", setup.metadata_path)

    with setup.mem:
        try:
            resolver = _build_resolver(setup.mem, setup.metadata_path)

            if args.validate_only:
                return

            logger.info("Scanning %d generic class instantiations...", resolver.meta_reg.genericClassesCount)
            singleton_index = _build_singleton_generic_index(resolver.meta_reg)
            roots = _resolve_singleton_roots(resolver, singleton_index)
            if not args.minidump:
                _run_live_reload_loop(setup.mem, roots)
            else:
                elapsed = _dump_from_singleton_roots(roots)
                logger.info("Extractor pass completed in %.2fs", elapsed)
        finally:
            logger.info("Total time: %.2fs", time.perf_counter() - t_start)
    if args.minidump and sys.stdin.isatty():
        try:
            input("Press Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    main()
