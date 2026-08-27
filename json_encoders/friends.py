"""JSON decoders for umadump output."""
from __future__ import annotations

from typing import Any, TYPE_CHECKING

from game_structs.enums import SuccessionCharaPosition
from game_structs.friends import FriendDataObject
from game_structs.trained_chara import TrainedCharaDataObject
from logger import logger
from .common import timestamp_to_str
from .trained_chara import _decode_factor_data_entry, _decode_factor_extend_array

if TYPE_CHECKING:
    from extractors.friends import FriendDataExtractionData


# ---------------------------------------------------------------------------
# Friends extraction
# ---------------------------------------------------------------------------

def _decode_follow_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    return {
        "friend_viewer_id": f.viewerId.value,
        "state": f.friendState.value,
        "follow_time": timestamp_to_str(f.followUnixTime.value),
        "follower_time": timestamp_to_str(f.followerUnixTime.value)
    }


def _decode_follower_list_entry(entry: FriendDataObject) -> dict[str, Any]:
    f = entry.fields
    # kinda just need swapped order to match API exactly
    return {
        "friend_viewer_id": f.viewerId.value,
        "state": f.friendState.value,
        "follower_time": timestamp_to_str(f.followerUnixTime.value),
        "follow_time": timestamp_to_str(f.followUnixTime.value)
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
    last_login_time = f.lastLoginTime.value or timestamp_to_str(f.lastLoginUnixTime.value)

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
    last_login_time = f.lastLoginTime.value or timestamp_to_str(f.lastLoginUnixTime.value)

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
        "last_friend_checked_time": timestamp_to_str(data.last_checked_time),
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
