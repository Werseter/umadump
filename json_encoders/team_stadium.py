"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any, Optional, TYPE_CHECKING

from game_structs.team_stadium import (TeamStadiumRaceCharaResultObject, TeamStadiumRaceResultObject,
                                       TeamStadiumResultBonusDataObject, TeamStadiumResultScoreDataObject)
from .race import _decode_race_horse_data_entry

if TYPE_CHECKING:
    from extractors.team_stadium import TeamStadiumReplayExtractionData


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


def decode_team_stadium_replay(data: TeamStadiumReplayExtractionData) -> Optional[dict[str, Any]]:
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
    return match_payload
