"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from ctypes_utils import C_Ptr
from game_structs.collections import GenericArrayPtr
from game_structs.enums import SuccessionCharaPosition
from game_structs.skills import AcquiredSkillObject
from game_structs.trained_chara import (FactorDataObject, FactorDataUpgradeHistoryObject, FactorInfoObject,
                                        FavoriteDataDictionaryEntry, RaceHistoryInfoObject, SuccessionCharaDataObject,
                                        SuccessionHistoryObject, TrainedCharaDataObject,
                                        TrainedCharaSupportCardDataObject)
from logger import logger
from .common import JST, timestamp_to_str

if TYPE_CHECKING:
    from extractors.trained_chara import TrainedCharaExtractionData


# ---------------------------------------------------------------------------
# Trained Chara extraction
# ---------------------------------------------------------------------------

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
        "register_time": timestamp_to_str(f.upgradeDate.value, tz=JST),
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
