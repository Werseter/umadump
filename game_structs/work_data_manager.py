from __future__ import annotations

from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Ptr, C_UDeclPtr
from game_structs.cards import WorkCardDataObject, WorkSupportCardDataObject
from game_structs.friends import WorkFriendDataObject
from game_structs.gallery import WorkAlreadyReadDataObject, WorkGalleryDataObject, WorkTalkGalleryDataObject
from game_structs.honors import WorkHonorDataObject
from game_structs.idle_single_mode import WorkIdleSingleModeDataObject
from game_structs.single_mode import WorkSingleModeDataObject
from game_structs.team_stadium import WorkTeamStadiumDataObject
from game_structs.trained_chara import WorkTrainedCharaDataObject
from game_structs.trophies import WorkTrophyDataObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkDataManager object hierarchy
# ---------------------------------------------------------------------------

class WorkDataManagerFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: userData
    friendData: C_Ptr[WorkFriendDataObject]
    cardData: C_Ptr[WorkCardDataObject]
    supportCardData: C_Ptr[WorkSupportCardDataObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[4]]  # omitted: charaData … itemData
    trainedCharaData: C_Ptr[WorkTrainedCharaDataObject]
    singleMode: C_Ptr[WorkSingleModeDataObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[8]]  # omitted: paymentItemData … circleData
    trophy: C_Ptr[WorkTrophyDataObject]
    _ignored_4: ArrayType[C_UDeclPtr, L[4]]  # omitted: exchange, homeFavorite, loginBonusData, announceData
    teamStadiumData: C_Ptr[WorkTeamStadiumDataObject]
    _ignored_5: ArrayType[C_UDeclPtr, L[5]]  # omitted: directoryData … dailyLegendRaceData
    honorData: C_Ptr[WorkHonorDataObject]
    _ignored_6: C_UDeclPtr  # omitted: limitedSalesData
    alreadyReadData: C_Ptr[WorkAlreadyReadDataObject]
    _ignored_7: ArrayType[C_UDeclPtr, L[6]]  # omitted: lastCheckTime … challengeMatchData
    galleryData: C_Ptr[WorkGalleryDataObject]
    talkGalleryData: C_Ptr[WorkTalkGalleryDataObject]
    _ignored_8: ArrayType[C_UDeclPtr, L[15]]  # omitted: roomMatchData … optionData
    idleSingleModeData: C_Ptr[WorkIdleSingleModeDataObject]


@register_runtime_validatable('Gallop::WorkDataManager')
class WorkDataManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkDataManagerFields


class WorkDataManagerSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[WorkDataManagerObject]


@register_runtime_validatable('Gallop::Singleton`1<Gallop::WorkDataManager>')
class WorkDataManagerSingleton(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
