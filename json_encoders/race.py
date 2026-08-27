"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any

from game_structs.enums import (BgSeason, CardRarity, CharaGradeType, CourseDistanceType, DefeatType, InitialLaneType,
                                MainStoryRaceGimmickType, ProperGrade, RaceDifficulty, RaceGroundCondition,
                                RaceMotivation, RaceRunningType, RaceTime, RaceType, RaceWeather,
                                ResultBoardConditionType, Rotation, RunningStyleEx, TurfVisionType)
from game_structs.master_data import RaceCourseSetObject
from game_structs.race import (HorseDataObject, RaceHorseDataObject, RaceHorseDataRaceResultObject, RaceInfoObject,
                               RaceParameterObject)
from game_structs.skills import SkillDataObject
from .trained_chara import _decode_raw_trained_chara_data


# ---------------------------------------------------------------------------
# Race replay extraction
# ---------------------------------------------------------------------------

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
        "isGhost": f.isGhost,
        "isRunningStyleExInitialized": f.isRunningStyleExInitialized,
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
        "isExistPlayerRace": f.isExistPlayerRace,
        "isExistGhostRace": f.isExistGhostRace,
        "isExistFollowRace": f.isExistFollowRace,
        "isMultiplePlayerRace": f.isMultiplePlayerRace,
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
        "isHalfGate": f.isHalfGate,
        "isHorseNumVariationGate": f.isHorseNumVariationGate,
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
        "isGateInPopularityInitialized": f.isGateInPopularityInitialized,
        "raceHorse": [_decode_horse_data_entry(x.contents) for x in f.raceHorse],
        "raceBibMaster": {},
        "raceMaster": {},
        "raceInstanceMaster": {},
        "simDataBase64": f.simDataBase64.value,
        "simData": {},
        "simReader": {},
        "episodeRaceReplayId": f.episodeRaceReplayId,
        "isNotSimulateExport": f.isNotSimulateExport,
        "laneDistanceMax": f.laneDistanceMax,
        "replayCheckInfo": {},
        "replayCheckInfoDaily": {},
        "replayCheckInfoLegend": {},
        "isDailyLegendRace": f.isDailyLegendRace,
        "replayCheckInfoChallengeMatch": {},
        "raceRewardSingle": {},
        "resultHorseIndex": f.resultHorseIndex,
        "prevGradeType": CharaGradeType.value_to_name(f.prevGradeType),
        "mainStoryRaceGimmickType": MainStoryRaceGimmickType.value_to_name(f.mainStoryRaceGimmickType),
        "isMainStoryRaceMatchGimmick": f.isMainStoryRaceMatchGimmick,
        "unlockFlags": f.unlockFlags,
        "phaseCalculator": {},
        "horseIndexByFinishOrder": [x.value for x in f.horseIndexByFinishOrder],
        "horseIndexByPopularity": [x.value for x in f.horseIndexByPopularity],
    }
