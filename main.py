#!/usr/bin/env python3
"""
WorkDataManager singleton resolver.

Supports live mode (process memory reads) and offline mode (full-memory minidump).
Walks Il2CppMetadataRegistration to locate Gallop.Singleton<WorkDataManager>._instance.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import struct
import time
import traceback
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable, Optional, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs import (AcquiredSkillObject, CardDataDictionaryEntry, ChampionsRaceInfoObject,
                          ChampionsRoomInfoObject, ChampionsRoomUserObject, ChampionsUserCharaObject,
                          FactorDataObject, FavoriteDataDictionaryEntry, FriendDataObject, GenericDictionary,
                          HintLevelDictionaryEntry, RaceHistoryInfoObject, RaceHorseDataObject,
                          RaceHorseDataRaceResultObject, SkillDataObject, SuccessionCharaDataObject,
                          SuccessionCharaObject, SuccessionHistoryObject, SupportCardDataDictionaryEntry,
                          TempDataObject, TempDataSingletonStaticFields, TrainedCharaDataDictionaryEntry,
                          TrainedCharaDataObject, TrainedCharaObject, TrainedCharaRaceResultObject,
                          TrainedCharaSupportCardDataObject, TrainedCharaSupportCardListObject, WorkDataManagerObject,
                          WorkDataManagerSingletonStaticFields, WorkFriendDataObject)
from il2cpp_structs import (RuntimeIl2CppClass, RuntimeIl2CppGenericClass, RuntimeIl2CppGenericInst,
                            RuntimeIl2CppMetadataRegistration, RuntimeIl2CppType)
from il2cpp_utils import Il2CppResolutionManager, default_metadata_path_from_exe, parse_minimal_metadata
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
        print(f"Scanning for {name}")
        for match_va in self.mem.scan(self.module_base, self.module_size, pattern_re, overlap):
            array_ptr_va = self.mem.read_pointer(match_va + array_ptr_offset)
            if not self._in_module(array_ptr_va):
                continue

            pointers = self._read_ptr_table(array_ptr_va, array_count)
            if not all(self._in_module(x) for x in pointers):
                continue

            result = match_va + offset_adjustment
            print(f"Found {name}")
            return result

        print(f"{name} was not found in the module scan range")
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
    pretty_json = json.dumps(payload, indent=2, ensure_ascii=False)
    output_path.write_text(pretty_json, encoding="utf-8")
    print(f"{name}: wrote JSON to {output_path}")


def _write_multi_output_json(output_folder: Path, key: str, payload: Any) -> None:
    _write_json_file(f"{output_folder.name}[{key}]", output_folder / f"{key}.json", payload)


# ---------------------------------------------------------------------------
# Support card extraction
# ---------------------------------------------------------------------------


def _support_card_entries_ptr_and_sizes(wdm: WorkDataManagerObject) \
        -> Optional[GenericDictionary[SupportCardDataDictionaryEntry]]:
    """Resolve support-card entries pointer and dictionary sizes."""
    support_card_data_ptr = wdm.fields.supportCardData
    if not support_card_data_ptr:
        print("WorkDataManager.SupportCardData is null")
        return None

    dictionary_ptr = support_card_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        print("WorkSupportCardData.dataDic is null")
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

    print(f"SupportCard dictionary: count={support_card_data_dict.fields.count}")

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
        print("WorkDataManager.trainedCharaData is null")
        return None

    dictionary_ptr = trained_chara_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        print("WorkTrainedCharaData.dataDic is null")
        return None

    fav_dictionary_ptr = trained_chara_data_ptr.contents.fields.favoriteDataDict
    if not fav_dictionary_ptr:
        print("WorkTrainedCharaData.favoriteDataDict is null")
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

    print(f"TrainedChara dictionary: "
          f"count={entries_info.entries.fields.count}, favorite_count={entries_info.favorite_entries.fields.count}")

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
        print("WorkDataManager.cardData is null")
        return None

    dictionary_ptr = card_data_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        print("WorkCardData.dataDic is null")
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

    print(f"CardData dictionary: count={card_data_dict.fields.count}")

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
        print("WorkDataManager.friendData is null")
        return None

    data = friend_data_data_ptr.contents

    if not data.fields.followList:
        print("WorkFriendData.followList is null")
        return None

    if not data.fields.followerList:
        print("WorkFriendData.followerList is null")
        return None

    if not data.fields.recommendList:
        print("WorkFriendData.recommendList is null")
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

    print(f"FriendData: follows={friend_data.fields.followList.contents.fields.size}, "
          f"followers={friend_data.fields.followerList.contents.fields.size}")

    result = _decode_work_friend_data(friend_data)
    return result


# ---------------------------------------------------------------------------
# Champions Meeting race extraction
# ---------------------------------------------------------------------------


def _resolve_champions_race_info(temp_data: TempDataObject) -> Optional[ChampionsRaceInfoObject]:
    champions_data = temp_data.fields.championsData
    if not champions_data:
        print("TempData.championsData is null")
        return None

    race_info = champions_data.contents.fields.raceInfo
    if not race_info:
        print("TempData.ChampionsTempData.raceInfo is null")
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
        "trainer_name": f.trainer_name.value,
        "owner_viewer_id": f.owner_viewer_id,
        "owner_trainer_name": f.owner_trainer_name.value,
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
        print("TempData.ChampionsTempData.raceInfo is not set")
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
        print("MetadataRegistration genericClasses pointer is missing")
        return None

    singleton_typedef = resolver.require_type_def_index([spec.singleton_class], spec.singleton_namespace)
    target_typedef = resolver.require_type_def_index([spec.target_type], spec.namespace)
    singleton_type_ptr = resolver.require_runtime_type_ptr_for_typedef(singleton_typedef)
    target_type_ptr = resolver.require_runtime_type_ptr_for_typedef(target_typedef)
    resolver.require_static_field_local_index(singleton_typedef, "_instance")

    matched = singleton_index.get((singleton_type_ptr, target_type_ptr))
    if matched is None:
        type_string = f"{spec.singleton_namespace}::{spec.singleton_class}[{spec.namespace}{spec.target_type}]"
        print(f"No {type_string} instantiation found")
        return None

    print(f"  … matched at index {matched.seq}")
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
        print(f"Running extractor: {extractor.name}")
        try:
            payload = extractor.extract(data)
            if extractor.output_path is not None:
                _write_json_file(extractor.name, extractor.output_path, payload)
            elif extractor.output_folder is not None and extractor.key_fn is not None:
                key = extractor.key_fn(payload)
                if not key:
                    continue
                extractor.output_folder.mkdir(parents=True, exist_ok=True)
                writer = extractor.writer or _write_multi_output_json
                writer(extractor.output_folder, key, payload)
        except Exception as e:
            print(f"Error in extractor {extractor.name}: {e}")
            print("Full traceback:")
            print(traceback.format_exc())


def _extract_support_cards(wdm: WorkDataManagerObject) -> Any:
    support_cards = decode_support_card_dictionary(wdm)
    print(f"Decoded {len(support_cards)} support cards")
    return support_cards


def _extract_trained_chara_data(wdm: WorkDataManagerObject) -> Any:
    trained_charas = decode_trained_chara_dictionary(wdm)
    print(f"Decoded {len(trained_charas)} trained chara entries")
    return trained_charas


def _extract_card_data(wdm: WorkDataManagerObject) -> Any:
    cards = decode_card_data_dictionary(wdm)
    # game calls the owned character data "card" data, making a distinction between alternate costume variants this way
    print(f"Decoded {len(cards)} owned character entries")  # game
    return cards


def _extract_friend_data(wdm: WorkDataManagerObject) -> dict[str, Any]:
    friends = decode_friend_data(wdm)
    print(f"Decoded friend data with {len(friends.get('friend_list', []))} friend entries")
    return friends


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
)


def _resolve_and_dump_workdatamanager(resolver: Il2CppResolutionManager,
                                      singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> None:
    """Resolve WorkDataManager singleton and run all configured extractors."""

    spec = SINGLETON_SPEC_REGISTRY["workdatamanager"]
    instance = resolve_singleton(resolver, spec, singleton_index)
    if not instance:
        print(f"{spec.target_type} not resolved")
        return

    _run_extractors(WORKDATA_EXTRACTORS, instance.contents)


def _champions_meeting_race_room_id(payload: dict[str, Any]) -> str:
    room_id = payload.get("data", {}).get("room_info", {}).get("room_id", 0)
    if not room_id:
        print("Warning: champions meeting race has no room_id, skipping folder extraction")
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


def _resolve_and_dump_tempdata(resolver: Il2CppResolutionManager,
                               singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> None:
    """Resolve TempData singleton and run all configured extractors."""

    spec = SINGLETON_SPEC_REGISTRY["tempdata"]
    instance = resolve_singleton(resolver, spec, singleton_index)
    if not instance:
        print(f"{spec.target_type} not resolved")
        return

    _run_extractors(TEMPDATA_EXTRACTORS, instance.contents)


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
        print(f"Offline mode from minidump: {args.minidump}")
        mem = MinidumpMemory(args.minidump)
        metadata_path = Path(args.metadata_path)
    else:
        print("Live mode from process memory")
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
    print(f"Parsed metadata: type_defs={len(metadata.type_defs)}")

    base, size = mem.module_info(TARGET_MODULE)

    reg_va = Il2CppRegistrationResolver(mem, base, size).find_metadata_registration(len(metadata.type_defs))
    if reg_va is None:
        raise RuntimeError("Could not locate Il2CppMetadataRegistration")
    meta_reg = C_Ptr[RuntimeIl2CppMetadataRegistration](reg_va).contents

    resolver = Il2CppResolutionManager(mem, metadata, meta_reg)
    validate_registered_classes(resolver)
    return resolver


def main() -> None:
    args = _parse_args()
    t_start = time.perf_counter()

    print(f"umadump {CURRENT_VERSION}")
    if not args.no_update_check:
        notify_if_update_available(CURRENT_VERSION)

    setup = _setup(args)
    print(f"Metadata path: {setup.metadata_path}")

    with setup.mem:
        try:
            resolver = _build_resolver(setup.mem, setup.metadata_path)

            if args.validate_only:
                return

            print(f"Scanning {resolver.meta_reg.genericClassesCount} generic class instantiations...")
            singleton_index = _build_singleton_generic_index(resolver.meta_reg)
            _resolve_and_dump_workdatamanager(resolver, singleton_index)
            _resolve_and_dump_tempdata(resolver, singleton_index)
        finally:
            print(f"Total time: {time.perf_counter() - t_start:.2f}s")
    input("Press Enter to exit...")


if __name__ == "__main__":
    main()
