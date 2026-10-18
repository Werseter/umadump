"""Gallop.TempData singleton and its retained subsystem state."""
from __future__ import annotations

from ctypes import c_bool, c_float, c_int32, c_int64
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Ptr, C_UDeclPtr
from game_structs.gacha import GachaResultTempDataObject
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.TempData object hierarchy
# ---------------------------------------------------------------------------

class TempDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # omitted: championsClearMissionIdList … championsRewardInfoArray
    serverTime: ObscuredLong  # latest data_headers.servertime, in Unix seconds
    _ignored_2: c_int64  # omitted: deviceStartUpTime
    _ignored_3: ArrayType[C_UDeclPtr, L[4]]  # omitted: clickButtonPosData … cardEventSkillDictionary
    _ignored_4: c_bool  # omitted: newGachaFlag
    _ignored_5: ObscuredInt  # omitted: missionClearNum
    _ignored_6: C_UDeclPtr  # omitted: missionNoticeQueue
    _ignored_7: ArrayType[c_int32, L[2]]  # omitted: missionViewLatestTabMissionType, viewLimitedMissionNum
    _ignored_8: ArrayType[ObscuredInt, L[2]]  # omitted: missionRecmmendedCardId, presentNotReceivedNum
    _ignored_9: ObscuredBool  # omitted: existNewInfomation
    _ignored_10: c_int64  # omitted: infomationUpDateTime
    _ignored_11: ObscuredBool  # omitted: isPaymentMaintenance
    _ignored_12: ArrayType[C_UDeclPtr, L[2]]  # omitted: storyCommonData, episodeData
    _ignored_13: c_bool  # omitted: isInMainStory
    _ignored_14: ArrayType[C_UDeclPtr, L[8]]  # omitted: singleModeData … transitionSetPassCallback
    _ignored_15: ObscuredInt  # omitted: friendNewFollowerNum
    _ignored_16: ArrayType[C_UDeclPtr, L[12]]  # omitted: raceData … practiceRaceData
    _ignored_17: c_bool  # omitted: playFirstTransitionDefalutBgm
    _ignored_18: ArrayType[C_UDeclPtr, L[2]]  # omitted: jukeboxMusicCueSheetName, jukeboxMusicCueName
    _ignored_19: c_float  # omitted: jukeboxMusicStartTimeOffset
    _ignored_20: c_bool  # omitted: showLikeFromOthers
    _ignored_21: ArrayType[C_UDeclPtr, L[6]]  # omitted: jukeboxSetListPlayingInfo … collectRaidEpisodeData
    _ignored_22: ArrayType[c_int32, L[3]]  # omitted: currentBgmMusicId … currentBgmMusicSizeSteamUI
    _ignored_23: c_bool  # omitted: isJukeboxMusicDeleted
    _ignored_24: C_UDeclPtr  # omitted: gachaData
    gachaResult: C_Ptr[GachaResultTempDataObject]
    _ignored_25: ArrayType[C_UDeclPtr, L[3]]  # omitted: shopData … shopLimitedSalesItemListData
    _ignored_26: c_int32  # omitted: lastPlayLimitedSalesCloseVoiceOpenCount
    _ignored_27: C_UDeclPtr  # omitted: trainingChallengeData


@register_runtime_validatable('Gallop::TempData')
class TempDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TempDataFields


class TempDataSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[TempDataObject]
