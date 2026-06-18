"""JSON decoders for API-shaped umadump output."""
from __future__ import annotations

import hashlib
from ctypes import c_int32
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Optional

from game_structs import (AcquiredSkillObject, CardDataDictionaryEntry, ChampionsRaceInfoObject,
                          ChampionsRoomInfoObject, ChampionsRoomUserObject, ChampionsUserCharaObject, FactorDataObject,
                          FavoriteDataDictionaryEntry, FriendDataObject, GenericDictionary, GenericList,
                          HintLevelDictionaryEntry, RaceHistoryInfoObject, RaceHorseDataObject,
                          RaceHorseDataRaceResultObject, SkillDataObject, SuccessionCharaDataObject,
                          SuccessionCharaObject, SuccessionHistoryObject, SupportCardDataDictionaryEntry,
                          TeamStadiumRaceCharaResultObject, TeamStadiumRaceResultObject,
                          TeamStadiumResultBonusDataObject, TeamStadiumResultObject, TeamStadiumResultScoreDataObject,
                          TempDataObject, TrainedCharaDataDictionaryEntry, TrainedCharaDataObject, TrainedCharaObject,
                          TrainedCharaRaceResultObject, TrainedCharaSupportCardDataObject,
                          TrainedCharaSupportCardListObject, TrophyDataCharaIdListDictionaryEntry,
                          TrophyDataDictionaryEntry, WorkDataManagerObject, WorkFriendDataObject,
                          WorkTeamStadiumDataObject, WorkTeamStadiumOpponentDataObject)
from logger import logger


def _timestamp_to_str(timestamp: int) -> str:
    if not timestamp:
        return "0000-00-00 00:00:00"
    return str(datetime.fromtimestamp(timestamp, tz=UTC).replace(tzinfo=None))


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
