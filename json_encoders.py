"""JSON decoders for umadump output."""
from __future__ import annotations

import re
from ctypes import c_int32
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from typing import Any, Iterator, Optional, Protocol

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs import (AcquiredSkillObject, BgSeason, CardDataDictionaryEntry, CardRarity, CharaGradeType,
                          CharaRaceRewardObject, CourseDistanceType, DefeatType, EvaluationInfoObject, FactorDataObject,
                          FactorDataUpgradeHistoryObject, FactorInfoObject, FavoriteDataDictionaryEntry,
                          FriendDataObject, GenericArrayPtr, GenericDictionary, GenericList, GroupOutingInfoObject,
                          GuestOutingInfoObject, HintLevelDictionaryEntry, HorseDataObject,
                          IdleSingleModeRaceHistoryObject, InitialLaneType, MainStoryRaceGimmickType,
                          ObscuredCharaEffectLogObject, ObscuredFactorInfoObject, ObscuredIdleSingleModeGainInfoObject,
                          ObscuredIdleSingleModeProgressLogInfoObject, ObscuredIdleSingleModeSignedIntObject,
                          ObscuredIdleSingleModeSuccessionFactorGainInfoObject,
                          ObscuredIdleSingleModeSupportCardGainInfoObject, ProperGrade, RaceCourseSetObject,
                          RaceDifficulty, RaceGroundCondition, RaceHistoryInfoObject, RaceHorseDataObject,
                          RaceHorseDataRaceResultObject, RaceInfoObject, RaceManagerStaticFields, RaceMotivation,
                          RaceParameterObject, RaceRewardDataObject, RaceRewardLimitDataObject, RaceRunningType,
                          RaceTime, RaceType, RaceWeather, ResultBoardConditionType, Rotation, RunningStyleEx,
                          SingleModeCharaObject, SingleModeSkillUpgradeObject, SingleModeSupportCardObject,
                          SingleRaceHistoryObject, SkillDataObject, SkillTipsObject, SuccessionCharaDataObject,
                          SuccessionCharaPosition, SuccessionHistoryObject, SupportCardDataDictionaryEntry,
                          TeamStadiumRaceCharaResultObject, TeamStadiumRaceResultObject,
                          TeamStadiumResultBonusDataObject, TeamStadiumResultScoreDataObject,
                          TrainedCharaDataDictionaryEntry, TrainedCharaDataObject, TrainedCharaSupportCardDataObject,
                          TrainingLevelInfoObject, TrophyDataCharaIdListDictionaryEntry, TrophyDataDictionaryEntry,
                          TurfVisionType, WorkDataManagerObject)
from logger import logger

JST = timezone(timedelta(hours=9), "JST")

ExtractorFingerprint = tuple[object, ...]


class FingerprintableExtractionData(Protocol):
    def fingerprint(self) -> ExtractorFingerprint:
        ...


def _dictionary_fingerprint(dictionary: GenericDictionary[Any]) -> ExtractorFingerprint:
    fields = dictionary.fields
    return "dict", fields.entries.inner_ptr.address, fields.count, fields.version


def _list_fingerprint(items: GenericList[Any]) -> ExtractorFingerprint:
    fields = items.fields
    return "list", fields.items.inner_ptr.address, fields.size, fields.version


def _array_fingerprint(items: GenericArrayPtr[Any]) -> ExtractorFingerprint:
    if not items.inner_ptr:
        return "array", 0, 0
    return "array", items.inner_ptr.address, items.inner_ptr.contents.max_length


def _pointer_fingerprint(ptr: C_Ptr[Any]) -> ExtractorFingerprint:
    return "ptr", ptr.address


def _timestamp_to_str(timestamp: int, tz: timezone = UTC) -> str:
    if not timestamp:
        return "0000-00-00 00:00:00"
    return str(datetime.fromtimestamp(timestamp, tz=tz).replace(tzinfo=None))


# ---------------------------------------------------------------------------
# Support card extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SupportCardExtractionData:
    entries: GenericDictionary[SupportCardDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        return "support_cards", _dictionary_fingerprint(self.entries)


def resolve_support_card_extraction_data(wdm: WorkDataManagerObject) -> Optional[SupportCardExtractionData]:
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
    return SupportCardExtractionData(entries=dictionary)


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


def decode_support_card_dictionary(data: SupportCardExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkSupportCardData -> Dictionary<int, SupportCardData>."""
    result: list[dict[str, Any]] = []

    support_card_data_dict = data.entries
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
class TrainedCharaExtractionData:
    entries: GenericDictionary[TrainedCharaDataDictionaryEntry]
    favorite_entries: GenericDictionary[FavoriteDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "trained_chara_data",
            _dictionary_fingerprint(self.entries),
            _dictionary_fingerprint(self.favorite_entries),
        )


def resolve_trained_chara_extraction_data(wdm: WorkDataManagerObject) -> Optional[TrainedCharaExtractionData]:
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
    return TrainedCharaExtractionData(entries=dictionary, favorite_entries=fav_dictionary)


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


def _decode_factor_data_entry(entry: FactorDataObject) -> dict[str, int]:
    f = entry.fields
    return {
        "factor_id": f.factorId.value,
        "level": f.factorLv.value,
    }


def _decode_factor_info_entry(entry: FactorInfoObject) -> dict[str, int]:
    f = entry.fields
    return {
        "factor_id": f.factor_id,
        "level": f.level,
    }


def _decode_factor_extend_history_entry(position_id: SuccessionCharaPosition | int, base_factor_id: int,
                                        entry: FactorDataUpgradeHistoryObject) -> dict[str, int | str]:
    f = entry.fields
    return {
        "position_id": int(position_id),
        "base_factor_id": base_factor_id,
        "factor_id": f.factorId.value,
        "register_time": _timestamp_to_str(f.upgradeDate.value, tz=JST),
    }


def _decode_factor_extend_array(
        position_id: SuccessionCharaPosition | int,
        factor_data_array: GenericArrayPtr[C_Ptr[FactorDataObject]]) -> list[dict[str, int | str]]:
    factor_extend_array: list[dict[str, int | str]] = []
    for factor_ptr in factor_data_array:
        factor = factor_ptr.contents.fields
        if not factor.upgradeHistoryList:
            continue
        base_factor_id = factor.baseFactorId.value
        factor_extend_array.extend(
                _decode_factor_extend_history_entry(position_id, base_factor_id, history_ptr.contents)
                for history_ptr in factor.upgradeHistoryList.contents
        )
    return factor_extend_array


def _decode_succession_chara_entry(entry: SuccessionCharaDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "position_id": f.positionId.value,
        "card_id": f.cardId.value,
        "rank": f.rank.value,
        "rarity": f.rarity.value,
        "talent_level": f.level.value,
        "factor_info_array": [_decode_factor_data_entry(x.contents) for x in f.factorDataArray],
        "factor_extend_array": _decode_factor_extend_array(f.positionId.value, f.factorDataArray),
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


def _decode_trained_chara_entry(entry: TrainedCharaDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "viewer_id": f.viewerId.value,
        "trained_chara_id": f.id.value,
        "owner_viewer_id": f.ownerViewerId.value,
        "owner_trained_chara_id": f.ownerTrainedCharaId.value,
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
        "factor_info_array": [_decode_factor_data_entry(x.contents) for x in f.factorDataArray],
        "factor_extend_array": _decode_factor_extend_array(SuccessionCharaPosition.SELF, f.factorDataArray),
        "succession_chara_array": [
            _decode_succession_chara_entry(x.contents) for x in f.successionCharaList.contents],
        "icon_type": f.favoriteData.contents.fields.type if f.favoriteData else 0,
        "memo": f.favoriteData.contents.fields.memo.value if f.favoriteData else "",
    }


def _decode_raw_factor_data(entry: FactorDataObject) -> dict[str, Any]:
    """Decode reflected factor data without applying the external API schema."""
    f = entry.fields
    return {
        "factorLv": f.factorLv.value,
        "factorId": f.factorId.value,
        "baseFactorId": f.baseFactorId.value,
        "upgradeHistoryList": [],
    }


def _decode_raw_succession_chara_data(entry: SuccessionCharaDataObject) -> dict[str, Any]:
    """Decode reflected succession data without applying the external API schema."""
    f = entry.fields
    return {
        "positionId": f.positionId.value,
        "cardId": f.cardId.value,
        "rarity": f.rarity.value,
        "level": f.level.value,
        "rank": f.rank.value,
        "factorDataArray": [_decode_raw_factor_data(item.contents) for item in f.factorDataArray],
        "sortedFactorList": [],
        "sortedFactorListForProfileCard": [],
        "ownerViewerId": f.ownerViewerId.value,
        "isPlayer": bool(f.isPlayer),
        "winSaddleArray": [],
        "winSaddleIdArray": [item.value for item in f.winSaddleIdArray],
    }


def _decode_raw_trained_chara_data(entry: TrainedCharaDataObject) -> dict[str, Any]:
    """Decode reflected trained chara data without applying the external API schema."""
    f = entry.fields
    return {
        "id": f.id.value,
        "isSaved": f.isSaved.value,
        "viewerId": f.viewerId.value,
        "ownerViewerId": f.ownerViewerId.value,
        "ownerTrainedCharaId": f.ownerTrainedCharaId.value,
        "useType": int(f.useType),
        "cardId": f.cardId.value,
        "nickNameId": f.nickNameId.value,
        "nickNameIdArray": [item.value for item in f.nickNameIdArray],
        "stamina": f.stamina.value,
        "speed": f.speed.value,
        "power": f.power.value,
        "guts": f.guts.value,
        "wiz": f.wiz.value,
        "fans": f.fans.value,
        "rank": f.rank.value,
        "rankScore": f.rankScore.value,
        "runningStyle": f.runningStyle.value,
        "properGroundTurf": f.properGroundTurf.value,
        "properGroundDirt": f.properGroundDirt.value,
        "properDistanceShort": f.properDistanceShort.value,
        "properDistanceMile": f.properDistanceMile.value,
        "properDistanceMiddle": f.properDistanceMiddle.value,
        "properDistanceLong": f.properDistanceLong.value,
        "properRunningStyleNige": f.properRunningStyleNige.value,
        "properRunningStyleSenko": f.properRunningStyleSenko.value,
        "properRunningStyleSashi": f.properRunningStyleSashi.value,
        "properRunningStyleOikomi": f.properRunningStyleOikomi.value,
        "successionCount": f.successionCount.value,
        "factorDataArray": [_decode_raw_factor_data(item.contents) for item in f.factorDataArray],
        "createTime": f.createTime.value,
        "scenarioId": f.scenarioId.value,
        "talentLevel": f.talentLevel.value,
        "charaGrade": f.charaGrade.value,
        "rarity": f.rarity.value,
        "isLock": f.isLock.value,
        "favoriteData": {},
        "cachedCreateTimeTimeStamp": f.cachedCreateTimeTimeStamp.value,
        "sortedFactorList": [],
        "sortedFactorProfileCardList": [],
        "factorListIncludingSuccession": [],
        "successionCharaList": [
            _decode_raw_succession_chara_data(item.contents) for item in f.successionCharaList.contents],
        "isSuccessionHistoryInitialized": False,
        "successionHistoryList": [],
        "acquiredSkillArray": [
            {
                "masterId": item.contents.fields.masterId.value,
                "level": item.contents.fields.level.value,
                "master": {},
            } for item in f.acquiredSkillArray
        ],
        "supportCardArray": [
            {
                "position": item.contents.fields.position.value,
                "supportCardId": item.contents.fields.supportCardId.value,
                "limitBreakCount": item.contents.fields.limitBreakCount.value,
                "exp": item.contents.fields.exp.value,
            } for item in f.supportCardArray
        ],
        "singleModeRaceResultArray": [
            {
                "turn": item.contents.fields.turn.value,
                "programId": item.contents.fields.programId.value,
                "raceInstanceId": 0,
                "frameOrder": 0,
                "npcCount": 0,
                "weather": item.contents.fields.weather.value,
                "groundCondition": item.contents.fields.groundCondition.value,
                "runningStyle": item.contents.fields.runningStyle.value,
                "resultRank": item.contents.fields.resultRank.value,
                "scenarioId": 0,
            } for item in f.singleModeRaceResultArray
        ],
        "winSaddleArray": [],
        "winSaddleIdArray": [item.value for item in f.winSaddleIdArray],
        "cacheCharaId": f.cacheCharaId.value,
        "masterCardData": {},
        "masterCharaData": {},
        "masterCardRarityData": {},
        "singleTotalRaceNum": f.singleTotalRaceNum,
        "singleWinNum": f.singleWinNum.value,
        "trainedCharaDataAccessor": {},
    }


def _decode_favorite_entry(entry: FavoriteDataDictionaryEntry) -> dict[str, Any]:
    f = entry.value.contents.fields
    return {
        "trained_chara_id": f.trainedCharaId,
        "type": f.type,
        "memo": f.memo.value,
    }


def decode_trained_chara_dictionary(data: TrainedCharaExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkTrainedCharaData -> Dictionary<int, TrainedCharaData>."""
    result: dict[int, dict[str, Any]] = {}

    logger.debug("TrainedChara dictionary: count=%d, favorite_count=%d",
                 data.entries.fields.count, data.favorite_entries.fields.count)

    for entry in data.entries:
        decoded = _decode_trained_chara_entry(entry.value.contents)
        trained_chara_id: int = decoded['trained_chara_id']
        result[trained_chara_id] = decoded

    for fav_entry in data.favorite_entries:
        decoded = _decode_favorite_entry(fav_entry)
        trained_chara_id = decoded['trained_chara_id']
        if trained_chara_id in result:
            result[trained_chara_id]['icon_type'] = decoded['type']
            result[trained_chara_id]['memo'] = decoded['memo']

    return list(result.values())


# ---------------------------------------------------------------------------
# Chara/card extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CardDataExtractionData:
    entries: GenericDictionary[CardDataDictionaryEntry]

    def fingerprint(self) -> ExtractorFingerprint:
        return "card_data", _dictionary_fingerprint(self.entries)


def resolve_card_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[CardDataExtractionData]:
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
    return CardDataExtractionData(entries=dictionary)


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


def decode_card_data_dictionary(data: CardDataExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkCardData -> Dictionary<int, CardData>."""
    result: list[dict[str, Any]] = []

    card_data_dict = data.entries
    logger.debug("CardData dictionary: count=%d", card_data_dict.fields.count)

    for entry in card_data_dict:
        decoded = _decode_card_data_entry(entry)
        result.append(decoded)

    return result


# ---------------------------------------------------------------------------
# Friends extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class FriendDataExtractionData:
    follow_list: GenericList[C_Ptr[FriendDataObject]]
    follower_list: GenericList[C_Ptr[FriendDataObject]]
    recommend_list: GenericList[C_Ptr[FriendDataObject]]
    last_checked_time: int
    follower_num: int

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "friend_data",
            _list_fingerprint(self.follow_list),
            _list_fingerprint(self.follower_list),
            _list_fingerprint(self.recommend_list),
            self.last_checked_time,
            self.follower_num,
        )


def resolve_friend_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[FriendDataExtractionData]:
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

    return FriendDataExtractionData(
            follow_list=data.fields.followList.contents,
            follower_list=data.fields.followerList.contents,
            recommend_list=data.fields.recommendList.contents,
            last_checked_time=data.fields.lastCheckedTime.value,
            follower_num=data.fields.followerNum.value,
    )


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
        "factor_info_array": [_decode_factor_data_entry(x.contents) for x in f.factorDataArray],
        "factor_extend_array": _decode_factor_extend_array(SuccessionCharaPosition.SELF, f.factorDataArray),
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
        "honor_id": f.honorData.contents.fields.honor_id,
        "honor_data": {
            "honor_id": f.honorData.contents.fields.honor_id,
        },
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
        "honor_id": f.honorData.contents.fields.honor_id,
        "honor_data": {
            "honor_id": f.honorData.contents.fields.honor_id,
        },
        "name": f.name.value,
        "last_login_time": last_login_time,
        "support_card_id": f.supportCardId.value,
        "user_support_card": {
            "support_card_id": f.supportCardId.value,
            "exp": f.supportCardExp.value,
            "limit_break_count": f.supportCardLimitBreakCount.value
        }
    }


def _decode_work_friend_data(data: FriendDataExtractionData) -> dict[str, Any]:
    follows = data.follow_list
    # filter to skip emitting mutuals twice
    followers = [x for x in data.follower_list if x.contents.fields.friendState.value != 3]
    recommends = data.recommend_list
    return {
        "last_friend_checked_time": _timestamp_to_str(data.last_checked_time),
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
        "follower_num": data.follower_num
    }


def decode_friend_data(data: FriendDataExtractionData) -> dict[str, Any]:
    """Descend WorkDataManager -> WorkFriendData"""
    logger.debug("FriendData: follows=%d, followers=%d",
                 data.follow_list.fields.size,
                 data.follower_list.fields.size)

    result = _decode_work_friend_data(data)
    return result


# ---------------------------------------------------------------------------
# Trophies extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TrophyDataExtractionData:
    entries: GenericDictionary[TrophyDataDictionaryEntry]

    def _trophy_entries_fingerprint(self) -> ExtractorFingerprint:
        return tuple(self._trophy_entry_fingerprint(entry) for entry in self.entries if entry.value)

    def _trophy_entry_fingerprint(self, entry: TrophyDataDictionaryEntry) -> ExtractorFingerprint:
        f = entry.value.contents.fields
        return (
            entry.key,
            f.trophyId.value,
            self._trophy_chara_id_list_fingerprint(f.charaIdList),
            self._trophy_race_chara_data_dic_fingerprint(f.raceCharaDataDic),
        )

    def _trophy_chara_id_list_fingerprint(self, chara_id_list: C_Ptr[GenericList[c_int32]]) -> ExtractorFingerprint:
        if not chara_id_list:
            return "chara_id_list", 0
        return "chara_id_list", _list_fingerprint(chara_id_list.contents)

    def _trophy_race_chara_data_dic_fingerprint(
            self,
            race_chara_data_dic: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryEntry]]) \
            -> ExtractorFingerprint:
        if not race_chara_data_dic:
            return "race_chara_data_dic", 0
        return "race_chara_data_dic", _dictionary_fingerprint(race_chara_data_dic.contents)

    def fingerprint(self) -> ExtractorFingerprint:
        return "trophy_data", _dictionary_fingerprint(self.entries), self._trophy_entries_fingerprint()


def resolve_trophy_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[TrophyDataExtractionData]:
    """Resolve trophy data pointer"""
    trophy_data_ptr = wdm.fields.trophy
    if not trophy_data_ptr:
        logger.warning("WorkDataManager.trophy is null")
        return None

    dictionary_ptr = trophy_data_ptr.contents.fields.dataDic
    if not dictionary_ptr:
        logger.warning("WorkTrophyData.dataDic is null")
        return None

    return TrophyDataExtractionData(entries=dictionary_ptr.contents)


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


def decode_trophy_data(data: TrophyDataExtractionData) -> list[dict[str, Any]]:
    """Descend WorkDataManager -> WorkTrophyData"""
    trophy_data = data.entries
    logger.debug("WorkTrophyData dictionary: count=%d", trophy_data.fields.count)

    return [_decode_work_trophy_data_entry(entry) for entry in trophy_data]


# ---------------------------------------------------------------------------
# Race replay extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RaceReplayOutput:
    key: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class TeamStadiumReplayExtractionData:
    use_item_id_array: GenericArrayPtr[c_int32]
    race_result_array: GenericArrayPtr[C_Ptr[TeamStadiumRaceResultObject]]
    is_include_unsupported_race: bool
    opponent_evaluate: int
    winning_reward_guarantee_status: int
    support_card_bonus: int

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "team_stadium_replay",
            _array_fingerprint(self.use_item_id_array),
            _array_fingerprint(self.race_result_array),
            self.opponent_evaluate,
        )


def _team_stadium_match_key() -> str:
    return f"team_stadium/TT-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}"


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


def _decode_team_stadium_replay_data(data: TeamStadiumReplayExtractionData) -> Optional[RaceReplayOutput]:
    race_start_params_array: list[dict[str, Any]] = []
    race_result_array: list[dict[str, Any]] = []
    for race_result_ptr in data.race_result_array:
        if not race_result_ptr:
            continue
        decoded = _decode_team_stadium_race_result(
                race_result_ptr.contents,
                self_evaluate=0,  # weighed sum of each team member's evaluationPoint, but not stored in WorkDataManager
                opponent_evaluate=data.opponent_evaluate,
        )
        if decoded is not None:
            race_start_params, race_result = decoded
            race_start_params_array.append(race_start_params)
            race_result_array.append(race_result)

    if not race_start_params_array:
        return None

    match_payload = {
        "use_item_id_array": [x.value for x in data.use_item_id_array],
        "race_start_params_array": race_start_params_array,
        "race_result_array": race_result_array,
        "rp_info": {},
        "item_info_array": [],
        "is_include_unsupported_race": data.is_include_unsupported_race,
        "winning_reward_info_array": [],
        "winning_reward_guarantee_status": data.winning_reward_guarantee_status,
        "last_checked_round": 0,
        "support_card_bonus": data.support_card_bonus,
        "user_team_data_array_copy": [],
        "user_trained_chara_array_copy": [],
        "opponent_info_copy": {},
        "opponent_chara_info_array_latest_copy": [],
    }
    return RaceReplayOutput(
            key=_team_stadium_match_key(),
            payload=match_payload,
    )


def resolve_team_stadium_replay_extraction_data(wdm: WorkDataManagerObject) \
        -> Optional[TeamStadiumReplayExtractionData]:
    if not (team_stadium_data_ptr := wdm.fields.teamStadiumData):
        return None
    team_stadium_data = team_stadium_data_ptr.contents

    if not (team_stadium_status_ptr := team_stadium_data.fields.teamStadiumStatus):
        return None
    team_stadium_status = team_stadium_status_ptr.contents

    if not (team_stadium_opponent_data_ptr := team_stadium_status.fields.opponentData):
        return None
    team_stadium_opponent_data = team_stadium_opponent_data_ptr.contents

    if not (team_stadium_result_ptr := team_stadium_status.fields.result):
        return None
    team_stadium_result = team_stadium_result_ptr.contents

    support_card_bonus = 0
    if support_card_bonus_info_ptr := team_stadium_data.fields.teamStadiumSupportCardBonusInfo:
        support_card_bonus = support_card_bonus_info_ptr.contents.fields.totalSupportCardBonus

    return TeamStadiumReplayExtractionData(
            use_item_id_array=team_stadium_result.fields.useItemIdArray,
            race_result_array=team_stadium_result.fields.raceResultArray,
            is_include_unsupported_race=bool(team_stadium_result.fields.isIncludeUnsupportedRace),
            opponent_evaluate=team_stadium_opponent_data.fields.evaluationPoint.value,
            winning_reward_guarantee_status=team_stadium_opponent_data.fields.winningRewardGuaranteeStatus.value,
            support_card_bonus=support_card_bonus,
    )


def decode_team_stadium_replay(data: TeamStadiumReplayExtractionData) -> Optional[RaceReplayOutput]:
    """Decode the resident WorkDataManager TeamStadium replay payload, if present."""
    return _decode_team_stadium_replay_data(data)


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


def _decode_race_course_set(value: RaceCourseSetObject) -> dict[str, int]:
    f = value.fields

    return {
        "id": f.id,
        "raceTrackId": f.raceTrackId,
        "distance": f.distance,
        "ground": f.ground,
        "inout": f.inout,
        "turn": f.turn,
        "fenceSet": f.fenceSet,
        "floatLaneMax": f.floatLaneMax,
        "courseSetStatusId": f.courseSetStatusId,
        "finishTimeMin": f.finishTimeMin,
        "finishTimeMinRandomRange": f.finishTimeMinRandomRange,
        "finishTimeMax": f.finishTimeMax,
        "finishTimeMaxRandomRange": f.finishTimeMaxRandomRange,
    }


def _decode_race_parameter(value: RaceParameterObject) -> dict[str, int | float | str]:
    f = value.fields

    return {
        "rawSpeed": f.rawSpeed,
        "rawStamina": f.rawStamina,
        "rawPow": f.rawPow,
        "rawGuts": f.rawGuts,
        "rawWiz": f.rawWiz,
        "baseSpeed": f.baseSpeed,
        "baseStamina": f.baseStamina,
        "basePow": f.basePow,
        "baseGuts": f.baseGuts,
        "baseWiz": f.baseWiz,
        "motivation": RaceMotivation.value_to_name(f.motivation),
        "motivationCoef": f.motivationCoef,
    }


def _decode_horse_data_entry(entry: HorseDataObject) -> dict[str, Any]:
    f = entry.fields

    return {
        "horseIndex": f.horseIndex,
        "postNumber": f.postNumber,
        "charaId": f.charaId,
        "charaName": f.charaName.value,
        "finishOrder": f.finishOrder,
        "finishTimeRaw": f.finishTimeRaw,
        "finishTimeScaled": f.finishTimeScaled,
        "finishDiffTimeFromPrev": f.finishDiffTimeFromPrev,
        "raceParam": _decode_race_parameter(f.raceParam.contents),
        "responseHorseData": _decode_race_horse_data_entry(f.responseHorseData.contents),
        "popularity": f.popularity,
        "popularityRankLeft": f.popularityRankLeft,
        "popularityRankCenter": f.popularityRankCenter,
        "popularityRankRight": f.popularityRankRight,
        "gateInPopularity": f.gateInPopularity,
        "rarity": CardRarity.value_to_name(f.rarity),
        "trainerName": f.trainerName.value if f.responseHorseData.contents.fields.viewer_id != 0 else "",
        "isGhost": bool(f.isGhost),
        "isRunningStyleExInitialized": bool(f.isRunningStyleExInitialized),
        "runningStyleEx": RunningStyleEx.value_to_name(f.runningStyleEx),
        "defeat": DefeatType.value_to_name(f.defeat),
        "raceDressId": f.raceDressId,
        "raceDressIdWithOption": f.raceDressIdWithOption,
        "runningType": RaceRunningType.value_to_name(f.runningType),
        "activeProperDistance": ProperGrade.value_to_name(f.activeProperDistance),
        "activeProperGroundType": ProperGrade.value_to_name(f.activeProperGroundType),
        "mobId": f.mobId,
        "raceRecord": {},
        "finishOrderRawScore": f.finishOrderRawScore,
        "trainedCharaData": _decode_raw_trained_chara_data(f.trainedCharaData.contents) if f.trainedCharaData else {},
    }


def decode_race_info(race_info_obj: RaceInfoObject) -> dict[str, Any]:
    f = race_info_obj.fields

    return {
        "raceType": RaceType.value_to_name(f.raceType),
        "isExistPlayerRace": bool(f.isExistPlayerRace),
        "isExistGhostRace": bool(f.isExistGhostRace),
        "isExistFollowRace": bool(f.isExistFollowRace),
        "isMultiplePlayerRace": bool(f.isMultiplePlayerRace),
        "randomSeed": f.randomSeed,
        "singleRaceProgramId": f.singleRaceProgramId,
        "opponentEvaluate": f.opponentEvaluate,
        "selfEvaluate": f.selfEvaluate,
        "supportCardScoreBonus": f.supportCardScoreBonus,
        "scoreCalcTeamId": f.scoreCalcTeamId,
        "raceNo": f.raceNo,
        "raceCourseSet": _decode_race_course_set(f.raceCourseSet.contents),
        "fenceSet": {},
        "raceTrack": {},
        "goalGate": f.goalGate,
        "goalGateFlower": f.goalGateFlower,
        "initialLaneType": InitialLaneType.value_to_name(f.initialLaneType),
        "rotationCategory": Rotation.value_to_name(f.rotationCategory),
        "resultBoardConditionType": ResultBoardConditionType.value_to_name(f.resultBoardConditionType),
        "courseSectionDistance": f.courseSectionDistance,
        "courseDistanceType": CourseDistanceType.value_to_name(f.courseDistanceType),
        "courseFurlongNum": f.courseFurlongNum,
        "isHalfGate": bool(f.isHalfGate),
        "isHorseNumVariationGate": bool(f.isHorseNumVariationGate),
        "turfVisionType": TurfVisionType.value_to_name(f.turfVisionType),
        "groundCondition": RaceGroundCondition.value_to_name(f.groundCondition),
        "weather": RaceWeather.value_to_name(f.weather),
        "season": BgSeason.value_to_name(f.season),
        "time": RaceTime.value_to_name(f.time),
        "baseSpeed": f.baseSpeed,
        "borderTimeScaled": f.borderTimeScaled,
        "challengeMatchDifficulty": RaceDifficulty.value_to_name(f.challengeMatchDifficulty),
        "numRaceHorses": f.numRaceHorses,
        "postNumberMax": f.postNumberMax,
        "playerHorseIndex": f.playerHorseIndex,
        "overridePlayerHorseIndex": f.overridePlayerHorseIndex,
        "playerTeamMemberArray": [_decode_horse_data_entry(x.contents) for x in f.playerTeamMemberArray],
        "playerTeamTopFinishOrderHorse": _decode_horse_data_entry(f.playerTeamTopFinishOrderHorse.contents),
        "isGateInPopularityInitialized": bool(f.isGateInPopularityInitialized),
        "raceHorse": [_decode_horse_data_entry(x.contents) for x in f.raceHorse],
        "raceBibMaster": {},
        "raceMaster": {},
        "raceInstanceMaster": {},
        "simDataBase64": f.simDataBase64.value,
        "simData": {},
        "simReader": {},
        "episodeRaceReplayId": f.episodeRaceReplayId,
        "isNotSimulateExport": bool(f.isNotSimulateExport),
        "laneDistanceMax": f.laneDistanceMax,
        "replayCheckInfo": {},
        "replayCheckInfoDaily": {},
        "replayCheckInfoLegend": {},
        "isDailyLegendRace": bool(f.isDailyLegendRace),
        "replayCheckInfoChallengeMatch": {},
        "raceRewardSingle": {},
        "resultHorseIndex": f.resultHorseIndex,
        "prevGradeType": CharaGradeType.value_to_name(f.prevGradeType),
        "mainStoryRaceGimmickType": MainStoryRaceGimmickType.value_to_name(f.mainStoryRaceGimmickType),
        "isMainStoryRaceMatchGimmick": bool(f.isMainStoryRaceMatchGimmick),
        "unlockFlags": f.unlockFlags,
        "phaseCalculator": {},
        "horseIndexByFinishOrder": [x.value for x in f.horseIndexByFinishOrder],
        "horseIndexByPopularity": [x.value for x in f.horseIndexByPopularity],
    }


def _safe_filename_component(name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9 -]+", "_", name).strip()
    return safe_name or "Unknown"


def _race_type_folder(race_type: object) -> str:
    return f"{re.sub(r'(?<!^)(?=[A-Z])', '_', str(race_type or 'Other')).lower()}_race"


def _race_info_replay_key(payload: dict[str, Any], winner: dict[str, Any]) -> str:
    folder = _race_type_folder(payload["raceType"])
    name = str(winner["charaName"]) or "Unknown"
    raw_time = float(winner["finishTimeRaw"])
    date_str = datetime.now().strftime("%Y%m%d")
    return f"{folder}/{_safe_filename_component(name)}-{raw_time:.4f}s-{date_str}"


@dataclass(frozen=True)
class RaceInfoReplayExtractionData:
    race_info: C_Ptr[RaceInfoObject]
    race_type: int
    random_seed: int
    race_horse_trained_chara_pointers: tuple[tuple[int, int], ...]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "race_info_replay",
            _pointer_fingerprint(self.race_info),
            self.race_type,
            self.random_seed,
            self.race_horse_trained_chara_pointers,
        )


def _race_horse_trained_chara_pointer_signature(race_info: RaceInfoObject) -> tuple[tuple[int, int], ...]:
    return tuple(
            (horse.address, horse.contents.fields.trainedCharaData.address) if horse else (0, 0)
            for horse in race_info.fields.raceHorse
    )


def resolve_race_info_replay_extraction_data(
        race_manager_static: RaceManagerStaticFields) -> Optional[RaceInfoReplayExtractionData]:
    if not race_manager_static.raceInfo:
        return None
    race_info = race_manager_static.raceInfo.contents
    f = race_info.fields
    if not f.simDataBase64.inner_ptr:
        logger.debug("RaceInfo replay data is not ready: simDataBase64 is null")
        return None
    race_horse_trained_chara_pointers = _race_horse_trained_chara_pointer_signature(race_info)
    return RaceInfoReplayExtractionData(
            race_info=race_manager_static.raceInfo,
            race_type=f.raceType,
            random_seed=f.randomSeed,
            race_horse_trained_chara_pointers=race_horse_trained_chara_pointers,
    )


def decode_race_info_replay(data: RaceInfoReplayExtractionData) -> RaceReplayOutput:
    """Decode the current live RaceInfo replay."""

    payload = decode_race_info(data.race_info.contents)
    winner = next(horse for horse in payload["raceHorse"] if horse["finishOrder"] == 0)

    return RaceReplayOutput(key=_race_info_replay_key(payload, winner), payload=payload)


# ---------------------------------------------------------------------------
# Independent training results extraction
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IdleSingleModeOutput:
    key: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class IdleSingleModeExtractionData:
    charaInfo: C_Ptr[SingleModeCharaObject]
    startTime: int
    endTime: int
    progressLogInfo: C_Ptr[ObscuredIdleSingleModeProgressLogInfoObject]

    def fingerprint(self) -> ExtractorFingerprint:
        return (
            "idle_single_mode",
            _pointer_fingerprint(self.charaInfo),
            self.startTime,
            self.endTime,
            _pointer_fingerprint(self.progressLogInfo),
        )


def resolve_idle_single_mode(wdm: WorkDataManagerObject) -> Optional[IdleSingleModeExtractionData]:
    idle_ptr = wdm.fields.idleSingleModeData
    if not idle_ptr:
        logger.debug("WorkDataManager.idleSingleModeData is null")
        return None

    c = idle_ptr.contents.fields
    checks = [
        (c.charaInfo, "charaInfo"),
        (c.startTime, "startTime"),
        (c.endTime, "endTime"),
        (c.progressLogInfo, "progressLogInfo"),
    ]
    for (f, name) in checks:
        if not f:
            logger.debug(
                    f"Idle single mode data is not ready: WorkDataManager.idleSingleModeData.{name} is null or zero")
            return None

    return IdleSingleModeExtractionData(
            charaInfo=c.charaInfo,
            startTime=c.startTime,
            endTime=c.endTime,
            progressLogInfo=c.progressLogInfo,
    )


def _idle_single_mode_key(chara: SingleModeCharaObject, start_time: int) -> str:
    dt = _timestamp_to_str(start_time)
    return f"{chara.fields.single_mode_chara_id} {_safe_filename_component(dt)} {chara.fields.card_id}"


def _decode_skill_tip_entry(s: SkillTipsObject) -> dict[str, Any]:
    f = s.fields
    return {
        "group_id": f.group_id,
        "rarity": f.rarity,
        "level": f.level,
    }


def _decode_single_mode_support_card(s: SingleModeSupportCardObject) -> dict[str, Any]:
    f = s.fields
    return {
        "position": f.position,
        "support_card_id": f.support_card_id,
        "limit_break_count": f.limit_break_count,
        "exp": f.exp,
        "training_partner_state": f.training_partner_state,
        "owner_viewer_id": f.owner_viewer_id,
        "rental_type": f.rental_type,
    }


def _decode_group_outing_info_entry(go: GroupOutingInfoObject) -> dict[str, Any]:
    f = go.fields
    return {
        "chara_id": f.chara_id,
        "is_outing": f.is_outing,
        "story_step": f.story_step,
    }


def _decode_evaluation_info_entry(e: EvaluationInfoObject) -> dict[str, Any]:
    f = e.fields
    return {
        "target_id": f.target_id,
        "evaluation": f.evaluation,
        "is_outing": f.is_outing,
        "story_step": f.story_step,
        "is_appear": f.is_appear,
        "group_outing_info_array": [_decode_group_outing_info_entry(go.contents) for go in f.group_outing_info_array],
    }


def _decode_training_level_info_entry(t: TrainingLevelInfoObject) -> dict[str, Any]:
    f = t.fields
    return {
        "command_id": f.command_id,
        "level": f.level,
    }


def _decode_guest_outing_info_entry(o: GuestOutingInfoObject) -> dict[str, Any]:
    f = o.fields
    return {
        "support_card_id": f.support_card_id,
        "story_step": f.story_step,
        "GroupOutingInfoList": [_decode_group_outing_info_entry(go.contents) for go in f.group_outing_info_array]
    }


def _decode_skill_upgrade_info_entry(u: SingleModeSkillUpgradeObject) -> dict[str, Any]:
    f = u.fields
    return {
        "condition_id": f.condition_id,
        "total_count": f.total_count,
        "current_count": f.current_count,
    }


def _safe_clist[T: StructOrSimple](l: GenericArrayPtr[T]) -> Iterator[T]:
    if l.inner_ptr:
        return iter(l)
    return iter([])


def _decode_single_mode_chara(chara: SingleModeCharaObject) -> dict[str, Any]:
    f = chara.fields
    return {
        "single_mode_chara_id": f.single_mode_chara_id,
        "card_id": f.card_id,
        "chara_grade": f.chara_grade,
        "speed": f.speed,
        "stamina": f.stamina,
        "power": f.power,
        "wiz": f.wiz,
        "guts": f.guts,
        "vital": f.vital,
        "max_speed": f.max_speed,
        "max_stamina": f.max_stamina,
        "max_power": f.max_power,
        "max_wiz": f.max_wiz,
        "max_guts": f.max_guts,
        "default_max_speed": f.default_max_speed,
        "default_max_stamina": f.default_max_stamina,
        "default_max_power": f.default_max_power,
        "default_max_wiz": f.default_max_wiz,
        "default_max_guts": f.default_max_guts,
        "max_vital": f.max_vital,
        "motivation": f.motivation,
        "fans": f.fans,
        "rarity": f.rarity,
        "race_program_id": f.race_program_id,
        "reserve_race_program_id": f.reserve_race_program_id,
        "race_running_style": f.race_running_style,
        "is_short_race": f.is_short_race,
        "talent_level": f.talent_level,
        "skill_array": [_decode_skill_data_entry(s.contents) for s in _safe_clist(f.skill_array)],
        "disable_skill_id_array": list(_safe_clist(f.disable_skill_id_array)),
        "skill_tips_array": [_decode_skill_tip_entry(s.contents) for s in _safe_clist(f.skill_tips_array)],
        "support_card_array": [_decode_single_mode_support_card(s.contents) for s in _safe_clist(f.support_card_array)],
        "succession_trained_chara_id_1": f.succession_trained_chara_id_1,
        "succession_trained_chara_id_2": f.succession_trained_chara_id_2,
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
        "turn": f.turn,
        "skill_point": f.skill_point,
        "short_cut_state": f.short_cut_state,
        "state": f.state,
        "playing_state": f.playing_state,
        "scenario_id": f.scenario_id,
        "route_id": f.route_id,
        "start_time": f.start_time.value if f.start_time.inner_ptr else "",
        "evaluation_info_array": [
            _decode_evaluation_info_entry(e.contents) for e in _safe_clist(f.evaluation_info_array)],
        "training_level_info_array": [
            _decode_training_level_info_entry(t.contents) for t in _safe_clist(f.training_level_info_array)],
        "nickname_id_array": list(_safe_clist(f.nickname_id_array)),
        "chara_effect_id_array": list(_safe_clist(f.chara_effect_id_array)),
        "route_race_id_array": [x.value for x in _safe_clist(f.route_race_id_array)],
        "guest_outing_info_array": [
            _decode_guest_outing_info_entry(o.contents) for o in _safe_clist(f.guest_outing_info_array)],
        "skill_upgrade_info_array": [
            _decode_skill_upgrade_info_entry(u.contents) for u in _safe_clist(f.skill_upgrade_info_array)],
    }


def _decode_obscured_chara_effect_log_entry(e: ObscuredCharaEffectLogObject) -> dict[str, Any]:
    f = e.fields
    return {
        "charaEffectId": f.charaEffectId.value,
        "isActive": f.isActive.value,
    }


def _decode_idle_single_mode_signed_int(v: ObscuredIdleSingleModeSignedIntObject) -> dict[str, Any]:
    f = v.fields
    return {
        "sign": f.sign.value,
        "value": f.value.value,
    }


def _decode_idle_single_mode_gain_info_entry(g: ObscuredIdleSingleModeGainInfoObject) -> dict[str, Any]:
    f = g.fields
    return {
        "speed": _decode_idle_single_mode_signed_int(f.speed.contents),
        "stamina": _decode_idle_single_mode_signed_int(f.stamina.contents),
        "power": _decode_idle_single_mode_signed_int(f.power.contents),
        "wiz": _decode_idle_single_mode_signed_int(f.wiz.contents),
        "guts": _decode_idle_single_mode_signed_int(f.guts.contents),
        "maxSpeed": f.maxSpeed.value,
        "maxStamina": f.maxStamina.value,
        "maxPower": f.maxPower.value,
        "maxWiz": f.maxWiz.value,
        "maxGuts": f.maxGuts.value,
        "properDistanceShort": f.properDistanceShort.value,
        "properDistanceMile": f.properDistanceMile.value,
        "properDistanceMiddle": f.properDistanceMiddle.value,
        "properDistanceLong": f.properDistanceLong.value,
        "properRunningStyleNige": f.properRunningStyleNige.value,
        "properRunningStyleSenko": f.properRunningStyleSenko.value,
        "properRunningStyleSashi": f.properRunningStyleSashi.value,
        "properRunningStyleOikomi": f.properRunningStyleOikomi.value,
        "properGroundTurf": f.properGroundTurf.value,
        "properGroundDirt": f.properGroundDirt.value,
        "skillPoint": f.skillPoint.value,
        "skillTips": [_decode_skill_tip_entry(s.contents) for s in f.skillTipsArray],
    }


def _decode_idle_single_mode_support_card_gain_info_entry(g: ObscuredIdleSingleModeSupportCardGainInfoObject) \
        -> dict[str, Any]:
    f = g.fields
    return {
        "supportCardId": f.supportCardId.value,
        "gainInfo": _decode_idle_single_mode_gain_info_entry(f.gainInfo.contents),
    }


def _decode_obscured_factor_info_entry(i: ObscuredFactorInfoObject) -> dict[str, Any]:
    f = i.fields
    return {
        "factorId": f.factorId.value,
        "level": f.level.value,
    }


def _decode_idle_single_mode_succession_factor_gain(sf: ObscuredIdleSingleModeSuccessionFactorGainInfoObject) \
        -> dict[str, Any]:
    f = sf.fields
    return {
        "year": f.year.value,
        "gainFactorInfoArray": [_decode_obscured_factor_info_entry(i.contents) for i in f.gainFactorInfoArray],
    }


def _decode_single_race_history_entry(h: SingleRaceHistoryObject) -> dict[str, Any]:
    f = h.fields
    return {
        "turn": f.turn,
        "program_id": f.program_id,
        "weather": f.weather,
        "ground_condition": f.ground_condition,
        "running_style": f.running_style,
        "result_rank": f.result_rank,
        "frame_order": f.frame_order,
        "npc_count": f.npc_count,
    }


def _decode_race_reward_data_entry(rd: RaceRewardDataObject) -> dict[str, Any]:
    f = rd.fields
    return {
        "item_type": f.item_type,
        "item_id": f.item_id,
        "item_num": f.item_num,
    }


def _decode_race_reward_limit_data_entry(ld: RaceRewardLimitDataObject) -> dict[str, Any]:
    f = ld.fields
    return {
        "reward_id": f.reward_id,
        "item_type": f.item_type,
        "item_id": f.item_id,
        "item_num": f.item_num,
        "rest_count": f.rest_count,
    }


def _decode_chara_race_reward(rr: CharaRaceRewardObject) -> dict[str, Any]:
    f = rr.fields
    return {
        "result_rank": f.result_rank,
        "result_time": f.result_time,
        "race_reward": [_decode_race_reward_data_entry(rd.contents) for rd in f.race_reward],
        "race_reward_bonus": [_decode_race_reward_data_entry(rd.contents) for rd in f.race_reward_bonus],
        "race_reward_plus_bonus": [_decode_race_reward_data_entry(rd.contents) for rd in f.race_reward_plus_bonus],
        "race_reward_bonus_win": [_decode_race_reward_data_entry(rd.contents) for rd in f.race_reward_bonus_win],
        "race_reward_limit": [] if not f.race_reward_limit.inner_ptr else [
            _decode_race_reward_limit_data_entry(ld.contents) for ld in f.race_reward_limit],
        "gained_fans": f.gained_fans,
        "campaign_id_array": [x.value for x in f.campaign_id_array],
    }


def _decode_idle_single_mode_race_history_entry(r: IdleSingleModeRaceHistoryObject) -> dict[str, Any]:
    f = r.fields
    return {
        "race_history": _decode_single_race_history_entry(f.race_history.contents),
        "race_reward_info": _decode_chara_race_reward(f.race_reward_info.contents),
        "lose_tips_id": f.lose_tips_id,
    }


def _decode_obscured_idle_single_mode_progress_log_info(progress: ObscuredIdleSingleModeProgressLogInfoObject) \
        -> dict[str, Any]:
    f = progress.fields
    return {
        "charaEffectLog": [_decode_obscured_chara_effect_log_entry(e.contents) for e in f.charaEffectLogArray],
        "supportCardGainInfo": [
            _decode_idle_single_mode_support_card_gain_info_entry(g.contents) for g in f.supportCardGainInfoArray],
        "eventGainInfo": _decode_idle_single_mode_gain_info_entry(f.eventGainInfo.contents),
        "successionGainInfo": _decode_idle_single_mode_gain_info_entry(f.successionGainInfo.contents),
        "successionFactorGainArray": [
            _decode_idle_single_mode_succession_factor_gain(sf.contents) for sf in f.successionFactorGainArray],
        "raceHistoryArray": [_decode_idle_single_mode_race_history_entry(r.contents) for r in f.raceHistoryArray],
        "gainSkillIdArray": [id.value for id in f.gainSkillIdArray],
        "totalSkillPoint": f.totalSkillPoint.value,
    }


def _decode_idle_single_mode_data(data: IdleSingleModeExtractionData) -> dict[str, Any]:
    return {
        "charaInfo": _decode_single_mode_chara(data.charaInfo.contents),
        "startTime": data.startTime,
        "endTime": data.endTime,
        "progressLogInfo": _decode_obscured_idle_single_mode_progress_log_info(data.progressLogInfo.contents),
    }


def decode_idle_single_mode(data: IdleSingleModeExtractionData) -> IdleSingleModeOutput:
    return IdleSingleModeOutput(
            key=_idle_single_mode_key(data.charaInfo.contents, data.startTime),
            payload=_decode_idle_single_mode_data(data)
    )
