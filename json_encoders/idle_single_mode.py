"""JSON decoders for umadump output."""
from __future__ import annotations

from itertools import chain
from typing import Any, TYPE_CHECKING

from game_structs.enums import ItemCategory
from game_structs.idle_single_mode import (IdleSingleModeRaceHistoryObject, ObscuredCharaEffectLogObject,
                                           ObscuredFactorInfoObject, ObscuredIdleSingleModeGainInfoObject,
                                           ObscuredIdleSingleModeProgressLogInfoObject,
                                           ObscuredIdleSingleModeSignedIntObject,
                                           ObscuredIdleSingleModeSuccessionFactorGainInfoObject,
                                           ObscuredIdleSingleModeSupportCardGainInfoObject)
from game_structs.race import CharaRaceRewardObject, SingleRaceHistoryObject
from .career import decode_resume_factor_select
from .common import decode_race_reward_item, timestamp_to_str
from .single_mode_chara import decode_single_mode_chara, decode_skill_tip
from .trained_chara import _decode_trained_chara_entry

if TYPE_CHECKING:
    from extractors.idle_single_mode import IdleSingleModeExtractionData


# ---------------------------------------------------------------------------
# Independent training results extraction
# ---------------------------------------------------------------------------

def _decode_obscured_chara_effect_log_entry(e: ObscuredCharaEffectLogObject) -> dict[str, Any]:
    f = e.fields
    return {
        "chara_effect_id": f.charaEffectId.value,
        "is_active": f.isActive.value,
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
        "max_speed": f.maxSpeed.value,
        "max_stamina": f.maxStamina.value,
        "max_power": f.maxPower.value,
        "max_wiz": f.maxWiz.value,
        "max_guts": f.maxGuts.value,
        "proper_distance_short": f.properDistanceShort.value,
        "proper_distance_mile": f.properDistanceMile.value,
        "proper_distance_middle": f.properDistanceMiddle.value,
        "proper_distance_long": f.properDistanceLong.value,
        "proper_running_style_nige": f.properRunningStyleNige.value,
        "proper_running_style_senko": f.properRunningStyleSenko.value,
        "proper_running_style_sashi": f.properRunningStyleSashi.value,
        "proper_running_style_oikomi": f.properRunningStyleOikomi.value,
        "proper_ground_turf": f.properGroundTurf.value,
        "proper_ground_dirt": f.properGroundDirt.value,
        "skill_point": f.skillPoint.value,
        "skill_tips_array": [decode_skill_tip(s.contents) for s in f.skillTipsArray],
    }


def _decode_idle_single_mode_support_card_gain_info_entry(g: ObscuredIdleSingleModeSupportCardGainInfoObject) \
        -> dict[str, Any]:
    f = g.fields
    return {
        "support_card_id": f.supportCardId.value,
        "gain_info": _decode_idle_single_mode_gain_info_entry(f.gainInfo.contents),
    }


def _decode_obscured_factor_info_entry(i: ObscuredFactorInfoObject) -> dict[str, Any]:
    f = i.fields
    return {
        "factor_id": f.factorId.value,
        "level": f.level.value,
    }


def _decode_idle_single_mode_succession_factor_gain(sf: ObscuredIdleSingleModeSuccessionFactorGainInfoObject) \
        -> dict[str, Any]:
    f = sf.fields
    return {
        "year": f.year.value,
        "gain_factor_info_array": [_decode_obscured_factor_info_entry(i.contents) for i in f.gainFactorInfoArray],
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


def _decode_idle_single_mode_progress_info(data: IdleSingleModeExtractionData) -> dict[str, Any]:
    return {
        "chara_info": decode_single_mode_chara(data.chara_info.contents),
        "start_time": timestamp_to_str(data.start_time),
        "end_time": timestamp_to_str(data.end_time),
        "dress_id": 0,
        "story_event_mission_list": [],
        "story_event_chara_bonus_list": [],
    }


def _decode_chara_race_reward(rr: CharaRaceRewardObject) -> dict[str, Any]:
    f = rr.fields
    return {
        "result_rank": f.result_rank,
        "result_time": f.result_time,
        "race_reward": [decode_race_reward_item(rd.contents) for rd in f.race_reward],
        "race_reward_bonus": [decode_race_reward_item(rd.contents) for rd in f.race_reward_bonus],
        "gained_fans": f.gained_fans,
        "campaign_id_array": [x.value for x in f.campaign_id_array],
        "race_reward_plus_bonus": [decode_race_reward_item(rd.contents) for rd in f.race_reward_plus_bonus],
        "race_reward_bonus_win": [decode_race_reward_item(rd.contents) for rd in f.race_reward_bonus_win],
    }


def _decode_idle_reward_items(rewards: list[dict[str, int]]) -> list[dict[str, int]]:
    counts: dict[int, int] = {}
    for reward in rewards:
        item_id = reward["item_id"]
        counts[item_id] = counts.get(item_id, 0) + reward["item_num"]
    return [{"item_id": item_id, "number": number} for item_id, number in counts.items()]


def _decode_idle_reward_pieces(rewards: list[dict[str, int]]) -> list[dict[str, int]]:
    return [{"piece_id": reward["item_id"], "piece_num": reward["item_num"]} for reward in rewards]


def _decode_idle_single_mode_race_reward_summary(
        progress: ObscuredIdleSingleModeProgressLogInfoObject) -> dict[str, Any]:
    """Separate pieces and free jewels; retain all other awards as item totals."""
    reward_groups: dict[int, list[tuple[int, dict[str, int]]]] = {}
    reward_count = 0
    for history in progress.fields.raceHistoryArray:
        if not (reward_info := history.contents.fields.race_reward_info):
            continue
        race_fields = reward_info.contents.fields
        for reward_array in (race_fields.race_reward, race_fields.race_reward_bonus,
                             race_fields.race_reward_plus_bonus, race_fields.race_reward_bonus_win):
            for reward_ptr in reward_array:
                reward: dict[str, int] = decode_race_reward_item(reward_ptr.contents)
                # Retain encounter order when regrouping categories into API sections.
                reward_groups.setdefault(reward["item_type"], []).append((reward_count, reward))
                reward_count += 1

    piece_rewards = [reward for _, reward in reward_groups.pop(ItemCategory.CARD_PIECE, [])]
    free_carrots = sum(reward["item_num"] for _, reward in reward_groups.pop(ItemCategory.FREE_CARROT, []))
    item_rewards = [reward for _, reward in sorted(chain.from_iterable(reward_groups.values()))]
    return {
        "add_item_list": _decode_idle_reward_items(item_rewards),
        "add_piece_list": _decode_idle_reward_pieces(piece_rewards),
        "add_card_list": [],
        "add_card_bonus_info": None,
        "add_support_card_list": [],
        "add_support_card_num_array": [],
        "add_honor_list": [],
        "add_chara_list": [],
        "add_cloth_list": [],
        "add_music_list": [],
        "add_story_id_array": [],
        "add_fcoin": free_carrots,
        "add_present_num": 0,
        "add_total_fan": 0,
        "new_chara_profile_array": [],
        "force_update_honor_id": 0,
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
        "chara_effect_log_array": [_decode_obscured_chara_effect_log_entry(e.contents) for e in f.charaEffectLogArray],
        "support_card_gain_info_array": [
            _decode_idle_single_mode_support_card_gain_info_entry(g.contents) for g in f.supportCardGainInfoArray],
        "event_gain_info": _decode_idle_single_mode_gain_info_entry(f.eventGainInfo.contents),
        "succession_gain_info": _decode_idle_single_mode_gain_info_entry(f.successionGainInfo.contents),
        "succession_factor_gain_array": [
            _decode_idle_single_mode_succession_factor_gain(sf.contents) for sf in f.successionFactorGainArray],
        "race_history_array": [_decode_idle_single_mode_race_history_entry(r.contents) for r in f.raceHistoryArray],
        "gain_skill_id_array": [id.value for id in f.gainSkillIdArray],
        "total_skill_point": f.totalSkillPoint.value,
    }


def decode_idle_single_mode(data: IdleSingleModeExtractionData) -> dict[str, Any]:
    progress_log_info = data.progress_log_info.contents
    trained_chara = _decode_trained_chara_entry(data.finalized_veteran.contents) if data.finalized_veteran else None
    return {
        "progress_info": _decode_idle_single_mode_progress_info(data),
        "progress_log_info": _decode_obscured_idle_single_mode_progress_log_info(progress_log_info),
        "end_info": {
            "chara_info": decode_single_mode_chara(data.finalized_chara_info.contents),
            "race_condition_array": [],
            "unchecked_event_array": [],
            "home_info": None,
            "win_saddle_id_array": [],
            "effected_factor_array": [],
            "race_start_info": None,
            "race_scenario": None,
            "add_trophy_info": None,
            "trophy_reward_info": None,
            "prev_chara_grade": None,
            "race_add_reward_info": [],
            "reserved_race_info": None,
            "mission_list": [],
            "story_event_mission_list": [],
            "story_event_chara_bonus_list": [],
            "start_dress_info": [],
            "resume_factor_select": decode_resume_factor_select(data.resume_factor_select, data.factor_sources()),
            "race_random_program_array": [],
            "race_reward_limit_more_list": [],
            "skill_filter_setting_array": [],
            "reward_summary_info": _decode_idle_single_mode_race_reward_summary(progress_log_info),
            "is_umaplan": False
        },
        "extra_data": {
            "viewer_id": data.viewer_id,
            "trained_chara": trained_chara,
        }
    }
