from __future__ import annotations

from typing import Any

from game_structs.single_mode_chara import (EvaluationInfoObject, GroupOutingInfoObject, GuestOutingInfoObject,
                                            SingleModeCharaObject, SingleModeSkillUpgradeObject,
                                            SingleModeSupportCardObject, TrainingLevelInfoObject)
from game_structs.skills import SkillTipsObject
from .common import decode_skill_data


def decode_skill_tip(s: SkillTipsObject) -> dict[str, Any]:
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
        "owner_viewer_id": f.owner_viewer_id,
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
        "training_partner_id": f.target_id,
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
        "group_outing_info_array": [_decode_group_outing_info_entry(go.contents) for go in f.group_outing_info_array],
    }


def _decode_skill_upgrade_info_entry(u: SingleModeSkillUpgradeObject) -> dict[str, Any]:
    f = u.fields
    return {
        "condition_id": f.condition_id,
        "total_count": f.total_count,
        "current_count": f.current_count,
    }


def decode_single_mode_chara(chara: SingleModeCharaObject) -> dict[str, Any]:
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
        "talent_level": f.talent_level,
        "skill_array": [decode_skill_data(s.contents) for s in f.skill_array],
        "disable_skill_id_array": [x.value for x in f.disable_skill_id_array],
        "skill_tips_array": [decode_skill_tip(s.contents) for s in f.skill_tips_array],
        "support_card_array": [_decode_single_mode_support_card(s.contents) for s in f.support_card_array],
        "succession_trained_chara_id_1": f.succession_trained_chara_id_1,
        "succession_trained_chara_id_2": f.succession_trained_chara_id_2,
        "turn": f.turn,
        "skill_point": f.skill_point,
        "short_cut_state": f.short_cut_state,
        "state": f.state,
        "playing_state": f.playing_state,
        "scenario_id": f.scenario_id,
        "route_id": f.route_id,
        "start_time": f.start_time.value_or(),
        "evaluation_info_array": [_decode_evaluation_info_entry(e.contents) for e in f.evaluation_info_array],
        "training_level_info_array": [
            _decode_training_level_info_entry(t.contents) for t in f.training_level_info_array],
        "nickname_id_array": [x.value for x in f.nickname_id_array],
        "chara_effect_id_array": [x.value for x in f.chara_effect_id_array],
        "route_race_id_array": [x.value for x in f.route_race_id_array],
        "guest_outing_info_array": [_decode_guest_outing_info_entry(o.contents) for o in f.guest_outing_info_array],
        "skill_upgrade_info_array": [_decode_skill_upgrade_info_entry(u.contents) for u in f.skill_upgrade_info_array],
    }
