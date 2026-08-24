from __future__ import annotations

from ctypes import c_int32

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.cards import SupportCardDataObject
from game_structs.collections import GenericList
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong, ObscuredStringPtr, ObscuredULong
from game_structs.trained_chara import TrainedCharaDataObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkFriendData.FriendData
# ---------------------------------------------------------------------------

class HonorDataFields(CStructureDataclass):
    honor_id: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: step
    _ignored_2: C_UDeclPtr  # omitted: createTime


class HonorDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: HonorDataFields


class FriendDataFields(CStructureDataclass):
    viewerId: ObscuredLong
    name: ObscuredStringPtr
    friendState: ObscuredInt
    honorData: C_Ptr[HonorDataObject]
    lastLoginTime: ObscuredStringPtr
    lastLoginUnixTime: ObscuredLong
    followUnixTime: ObscuredLong
    followerUnixTime: ObscuredLong
    supportCardId: ObscuredInt
    supportCardLimitBreakCount: ObscuredInt
    supportCardExp: ObscuredInt
    comment: ObscuredStringPtr
    fan: ObscuredULong
    isNewFollower: ObscuredBool
    circleName: ObscuredStringPtr
    circleId: ObscuredInt
    circleMonthlyRank: ObscuredInt
    virtualSupportCardData: C_Ptr[SupportCardDataObject]
    virtualTrainedCharaData: C_Ptr[TrainedCharaDataObject]


@register_runtime_validatable('Gallop::WorkFriendData.FriendData')
class FriendDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FriendDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkFriendData
# ---------------------------------------------------------------------------

class WorkFriendDataFields(CStructureDataclass):
    followList: C_Ptr[GenericList[C_Ptr[FriendDataObject]]]
    followerList: C_Ptr[GenericList[C_Ptr[FriendDataObject]]]
    recommendList: C_Ptr[GenericList[C_Ptr[FriendDataObject]]]
    lastCheckedTime: ObscuredLong
    followerNum: ObscuredInt


@register_runtime_validatable('Gallop::WorkFriendData')
class WorkFriendDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkFriendDataFields
