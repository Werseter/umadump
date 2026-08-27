from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from ctypes_utils import C_Ptr
from game_structs.collections import GenericList
from game_structs.friends import FriendDataObject
from game_structs.work_data_manager import WorkDataManagerObject
from json_encoders.friends import decode_friend_data
from logger import logger
from .common import ExtractorContext, ExtractorFingerprint, first, list_fingerprint


@dataclass(frozen=True)
class FriendDataExtractionData:
    follow_list: GenericList[C_Ptr[FriendDataObject]]
    follower_list: GenericList[C_Ptr[FriendDataObject]]
    recommend_list: GenericList[C_Ptr[FriendDataObject]]
    last_checked_time: int
    follower_num: int

    def fingerprint(self) -> ExtractorFingerprint:
        first_follow = first(entry for entry in self.follow_list if entry)
        first_follower = first(entry for entry in self.follower_list if entry)
        first_recommend = first(entry for entry in self.recommend_list if entry)
        if first_follow is not None:
            _ = first_follow.contents.fields
        if first_follower is not None:
            _ = first_follower.contents.fields
        if first_recommend is not None:
            _ = first_recommend.contents.fields
        return (
            "friend_data",
            list_fingerprint(self.follow_list),
            ("first_follow", first_follow.address if first_follow is not None else 0),
            list_fingerprint(self.follower_list),
            ("first_follower", first_follower.address if first_follower is not None else 0),
            list_fingerprint(self.recommend_list),
            ("first_recommend", first_recommend.address if first_recommend is not None else 0),
            self.last_checked_time,
            self.follower_num,
        )


def resolve_friend_data_extraction_data(wdm: WorkDataManagerObject) -> Optional[FriendDataExtractionData]:
    """Resolve friend data pointer."""

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


def resolve_friend_data(context: ExtractorContext) -> Optional[FriendDataExtractionData]:
    return resolve_friend_data_extraction_data(context.work_data_manager)


def extract_friend_data(data: FriendDataExtractionData) -> dict[str, object]:
    friends = decode_friend_data(data)
    logger.info("Decoded friend data with %d friend entries", len(friends.get('friend_list', [])))
    return friends
