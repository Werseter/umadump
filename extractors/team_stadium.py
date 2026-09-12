from __future__ import annotations

from ctypes import c_int32
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.collections import GenericArrayPtr
from game_structs.team_stadium import TeamStadiumRaceResultObject
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.team_stadium import decode_team_stadium_replay
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, array_fingerprint, first_object_fingerprint
from .race import RaceReplayOutput


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
            array_fingerprint(self.use_item_id_array),
            array_fingerprint(self.race_result_array),
            first_object_fingerprint("first_race_result", self.race_result_array),
            self.opponent_evaluate,
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
            is_include_unsupported_race=team_stadium_result.fields.isIncludeUnsupportedRace,
            opponent_evaluate=team_stadium_opponent_data.fields.evaluationPoint.value,
            winning_reward_guarantee_status=team_stadium_opponent_data.fields.winningRewardGuaranteeStatus.value,
            support_card_bonus=support_card_bonus,
    )


def resolve_team_stadium_replay(context: ExtractorContext) -> Optional[TeamStadiumReplayExtractionData]:
    return resolve_team_stadium_replay_extraction_data(context.work_data_manager)


def extract_team_stadium_replay(data: TeamStadiumReplayExtractionData) -> Optional[RaceReplayOutput]:
    payload = decode_team_stadium_replay(data)
    if payload is None:
        replay = None
    else:
        key = f"team_stadium/TT-{datetime.now().strftime('%Y%m%d_%H%M%S_%f')[:-3]}"
        replay = RaceReplayOutput(key=key, payload=payload)
    logger.info("Decoded %d Team Stadium replay payloads", 1 if replay else 0)
    return replay
