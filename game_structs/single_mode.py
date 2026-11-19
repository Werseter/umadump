from __future__ import annotations

from ctypes import c_bool, c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Enum, C_EnumIn, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import (GenericArrayPtr, GenericDictionary, GenericDictionaryEntry,
                                      GenericIntDictionaryEntry, GenericList)
from game_structs.enums import (CharaGradeType, FinalTrainingRank, SingleModeCommandType,
                                SingleModeEventContentsInfoType, SingleModeEventPlayTiming, SingleModeLogGroupType,
                                SingleModeParameterType, SingleModePlayingState, SingleModeState, StoryLogInfoSoundType,
                                StoryLogInfoType)
from game_structs.master_data import MasterSingleModeWinsSaddleSingleModeWinsSaddleObject
from game_structs.obscured import ObscuredBool, ObscuredInt, ObscuredLong
from game_structs.race import CharaRaceRewardObject, RaceRewardDataObject, SingleRaceStartInfoObject
from game_structs.single_mode_chara import SingleModeCharaObject
from game_structs.single_mode_scenarios import (SingleModeFreeCommandInfoObject,
                                                WorkSingleModeScenarioLivePerformanceDataObject)
from game_structs.strings import SystemStringObjectPtr
from game_structs.trained_chara import FactorInfoObject, RaceHistoryInfoObject
from game_structs.trophies import LoginUserTrophyInfoObject
from game_structs.work_single_mode_chara import WorkSingleModeCharaDataObject
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeChangeParameterInfo
# ---------------------------------------------------------------------------

class WorkSingleModeChangeParameterInfoFields(CStructureDataclass):
    _ignored_1: ArrayType[ObscuredInt, L[15]]  # omitted: speed … maxHp
    _ignored_2: ArrayType[C_UDeclPtr, L[10]]  # omitted: properGroundTurf … properRunStyleOikomi
    _ignored_3: ObscuredInt  # omitted: charaGrade
    _ignored_4: ArrayType[C_UDeclPtr, L[17]]  # omitted: disableCommandIdList … appearCharaIdList
    _ignored_5: ArrayType[ObscuredInt, L[2]]  # omitted: deletedRouteRaceId, forcedRunStyle
    _ignored_6: ArrayType[C_UDeclPtr, L[16]]  # omitted: limitStatusTypeList … teamRaceLeaveMemberList
    _ignored_7: ArrayType[ObscuredInt, L[2]]  # omitted: teamRaceRankingUp, teamRaceRankingDown
    _ignored_8: C_UDeclPtr  # omitted: teamRaceTeamStatusUpDictionary
    _ignored_9: ObscuredInt  # omitted: teamRaceTotalPower
    _ignored_10: ArrayType[C_UDeclPtr, L[2]]  # omitted: scenarioFreeUseItemIdList, scenarioFreeEventShopItemAddList
    _ignored_11: ObscuredInt  # omitted: tscRankingUpDown
    scenarioFreeCommandInfo: C_Ptr[GenericList[C_Ptr[SingleModeFreeCommandInfoObject]]]
    performance: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    performanceMax: C_Ptr[WorkSingleModeScenarioLivePerformanceDataObject]
    limitPerformanceTypeList: C_Ptr[GenericList[ObscuredInt]]
    _ignored_12: ObscuredInt  # omitted: liveGetMusicId
    _ignored_13: ArrayType[C_UDeclPtr, L[2]]  # omitted: liveMemberJoinCharaIdList, scenarioVenusSpiritInfoList
    _ignored_14: ArrayType[ObscuredBool, L[2]]  # omitted: appearVenus, scenarioVenusUsedSpirit
    _ignored_15: ObscuredInt  # omitted: scenarioVenusInfoLevelUp


@register_runtime_validatable('Gallop::WorkSingleModeChangeParameterInfo')
class WorkSingleModeChangeParameterInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeChangeParameterInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.ParamsIncDecInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataParamsIncDecInfoFields(CStructureDataclass):
    value: ObscuredInt
    bonusValue: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.ParamsIncDecInfo')
class WorkSingleModeDataParamsIncDecInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataParamsIncDecInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.ParamsIncDecInfoDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeDataParamsIncDecInfoDictionaryEntry(GenericDictionaryEntry):
    key: C_Enum[SingleModeParameterType]
    value: C_Ptr[WorkSingleModeDataParamsIncDecInfoObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.TrainingHorse
# ---------------------------------------------------------------------------

class WorkSingleModeDataTrainingHorseFields(CStructureDataclass):
    positionId: ObscuredInt
    isTips: ObscuredBool
    isVersusEvent: ObscuredBool
    isGuide: ObscuredBool
    isSoulExplode: ObscuredBool
    isSpSoulExplode: ObscuredBool


@register_runtime_validatable('Gallop::WorkSingleModeData.TrainingHorse')
class WorkSingleModeDataTrainingHorseObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataTrainingHorseFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.LivePerformanceIncDecInfoDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry(GenericIntDictionaryEntry):
    value: C_Int[c_int32]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.TurnInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataTurnInfoFields(CStructureDataclass):
    _ignored_1: ObscuredInt  # omitted: commandType
    commandId: ObscuredInt
    isEnable: ObscuredBool
    paramIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
    bonusParamIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataParamsIncDecInfoDictionaryEntry]]
    trainingFailureRate: C_Int[c_int32]
    trainingHorseList: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataTrainingHorseObject]]]
    livePerformanceIncDecInfoDic: C_Ptr[GenericDictionary[WorkSingleModeDataLivePerformanceIncDecInfoDictionaryEntry]]
    _ignored_2: C_UDeclPtr  # omitted: venusSpiritEffectInfoList
    _ignored_3: ObscuredInt  # omitted: venusId


@register_runtime_validatable('Gallop::WorkSingleModeData.TurnInfo')
class WorkSingleModeDataTurnInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataTurnInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeHomeInfo.TurnInfoListDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeHomeInfoTurnInfoListDictionaryEntry(GenericDictionaryEntry):
    key: C_Enum[SingleModeCommandType]
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataTurnInfoObject]]]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeHomeInfo
# ---------------------------------------------------------------------------

class WorkSingleModeHomeInfoFields(CStructureDataclass):
    turnInfoListDic: C_Ptr[GenericDictionary[WorkSingleModeHomeInfoTurnInfoListDictionaryEntry]]
    disableCommandIdList: C_Ptr[GenericList[ObscuredInt]]
    availableContinueNum: ObscuredInt
    availableFreeContinueNum: ObscuredInt
    freeContinueNum: ObscuredInt
    prevFreeContinueTime: ObscuredLong
    shortenedRaceState: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeHomeInfo')
class WorkSingleModeHomeInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeHomeInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.RaceCondition
# ---------------------------------------------------------------------------

class WorkSingleModeDataRaceConditionFields(CStructureDataclass):
    programId: ObscuredInt
    weather: ObscuredInt
    groundCondition: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.RaceCondition')
class WorkSingleModeDataRaceConditionObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataRaceConditionFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.SuccessionEventInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataSuccessionEventInfoFields(CStructureDataclass):
    eventId: ObscuredInt
    charaId: ObscuredInt
    effectType: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.SuccessionEventInfo')
class WorkSingleModeDataSuccessionEventInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataSuccessionEventInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.RaceStartResultInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataRaceStartResultInfoFields(CStructureDataclass):
    startInfo: C_Ptr[SingleRaceStartInfoObject]
    raceScenario: SystemStringObjectPtr
    rewardInfo: C_Ptr[CharaRaceRewardObject]
    charaInfo: C_Ptr[SingleModeCharaObject]
    addTrophyInfo: C_Ptr[LoginUserTrophyInfoObject]
    trophyRewardInfo: C_Ptr[RaceRewardDataObject]
    prevGradeType: C_Enum[CharaGradeType]


@register_runtime_validatable('Gallop::WorkSingleModeData.RaceStartResultInfo')
class WorkSingleModeDataRaceStartResultInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataRaceStartResultInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.EventInfo
# ---------------------------------------------------------------------------

class WorkSingleModeDataEventInfoFields(CStructureDataclass):
    eventId: ObscuredInt
    charaId: ObscuredInt
    storyId: ObscuredInt
    contentsInfoSupportCardId: ObscuredInt
    selectIndexArray: GenericArrayPtr[ObscuredInt]
    receiveItemIdArray: GenericArrayPtr[ObscuredInt]
    targetRaceIdArray: GenericArrayPtr[ObscuredInt]
    gainSelectIdIndexArray: GenericArrayPtr[ObscuredInt]
    selectIconArray: GenericArrayPtr[ObscuredInt]
    playTiming: C_EnumIn[SingleModeEventPlayTiming, ObscuredInt]
    contentsInfoShowClear: ObscuredInt
    contentsInfoShowClearSortId: ObscuredInt
    isEffectedMultiChara: ObscuredBool
    tipsTrainingPartnerId: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.EventInfo')
class WorkSingleModeDataEventInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataEventInfoFields


class WorkSingleModeDataStoryInfoListDictionaryEntry(GenericDictionaryEntry):
    key: C_Enum[SingleModeEventPlayTiming]
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataEventInfoObject]]]


# ---------------------------------------------------------------------------
# Retained career event
# ---------------------------------------------------------------------------

class SingleModeEventAccesorFields(CStructureDataclass):
    eventInfo: C_Ptr[WorkSingleModeDataEventInfoObject]


@register_runtime_validatable('Gallop::SingleModeEventAccesor')
class SingleModeEventAccesorObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeEventAccesorFields


class SingleModeChangeViewManagerFields(CStructureDataclass):
    _ignored_1: c_int32  # omitted: nowStateId
    eventInfoAccesor: C_Ptr[SingleModeEventAccesorObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[4]]  # omitted: lastCheckRaceAlertDialog … messageCharaIDList


@register_runtime_validatable('Gallop::SingleModeChangeViewManager')
class SingleModeChangeViewManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeChangeViewManagerFields


class SingleModeChangeViewManagerSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[SingleModeChangeViewManagerObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData.EventChoiceReward
# ---------------------------------------------------------------------------

class WorkSingleModeEventChoiceRewardGainParamFields(CStructureDataclass):
    displayId: ObscuredInt
    effectValue0: ObscuredInt
    effectValue1: ObscuredInt
    effectValue2: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeData.EventChoiceRewardGainParam')
class WorkSingleModeEventChoiceRewardGainParamObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeEventChoiceRewardGainParamFields


class WorkSingleModeEventChoiceBranchRewardFields(CStructureDataclass):
    gainParamArray: GenericArrayPtr[C_Ptr[WorkSingleModeEventChoiceRewardGainParamObject]]


@register_runtime_validatable('Gallop::WorkSingleModeData.EventChoiceBranchReward')
class WorkSingleModeEventChoiceBranchRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeEventChoiceBranchRewardFields


class WorkSingleModeEventChoiceRewardFields(CStructureDataclass):
    branchRewardArray: GenericArrayPtr[C_Ptr[WorkSingleModeEventChoiceBranchRewardObject]]


@register_runtime_validatable('Gallop::WorkSingleModeData.EventChoiceReward')
class WorkSingleModeEventChoiceRewardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeEventChoiceRewardFields


class WorkSingleModeEventChoiceRewardDictionaryEntry(GenericDictionaryEntry):
    key: ObscuredInt
    value: C_Ptr[WorkSingleModeEventChoiceRewardObject]


# ---------------------------------------------------------------------------
# Gallop.FactorSelectInfo
# ---------------------------------------------------------------------------

class FactorSelectInfoFields(CStructureDataclass):
    lottery_id: C_Int[c_int32]
    factor_info_array: GenericArrayPtr[C_Ptr[FactorInfoObject]]


@register_runtime_validatable('Gallop::FactorSelectInfo')
class FactorSelectInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorSelectInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeFactorSelectCommon
# ---------------------------------------------------------------------------

class SingleModeFactorSelectCommonFields(CStructureDataclass):
    rank_score: C_Int[c_int32]
    rank: C_Int[c_int32]
    lottery_remain_num: C_Int[c_int32]
    lottery_count: C_Int[c_int32]
    select_lottery_id: C_Int[c_int32]
    factor_select_info_array: GenericArrayPtr[C_Ptr[FactorSelectInfoObject]]


@register_runtime_validatable('Gallop::SingleModeFactorSelectCommon')
class SingleModeFactorSelectCommonObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeFactorSelectCommonFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeLogPool.SingleModeLogPoolInfoSubstance
# ---------------------------------------------------------------------------

class SingleModeLogSubstanceFields(CStructureDataclass):
    charaIdList: C_Ptr[GenericList[c_int32]]
    name: SystemStringObjectPtr
    text: SystemStringObjectPtr
    colorText: SystemStringObjectPtr
    logType: C_Enum[StoryLogInfoType]
    sheetId: SystemStringObjectPtr
    voiceIndex: C_Int[c_int32]
    selectorLabel: SystemStringObjectPtr
    soundType: C_Enum[StoryLogInfoSoundType]
    isResult: C_Bool[c_bool]
    forceSetMobIcon: C_Bool[c_bool]
    analyzeResultIconId: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeLogPool.SingleModeLogPoolInfoSubstance')
class SingleModeLogSubstanceObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeLogSubstanceFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeLogPool.SingleModeLogPoolInfoGroup
# ---------------------------------------------------------------------------

class SingleModeLogGroupFields(CStructureDataclass):
    groupType: C_Enum[SingleModeLogGroupType]
    eventTitle: SystemStringObjectPtr
    dressId: C_Int[c_int32]
    genderId: C_Int[c_int32]
    trainingLev: C_Int[c_int32]
    trainingKind: C_Int[c_int32]
    supportCardId: C_Int[c_int32]
    talkerId: C_Int[c_int32]
    substList: C_Ptr[GenericList[C_Ptr[SingleModeLogSubstanceObject]]]


@register_runtime_validatable('Gallop::SingleModeLogPool.SingleModeLogPoolInfoGroup')
class SingleModeLogGroupObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeLogGroupFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeLogPool
# ---------------------------------------------------------------------------

class SingleModeLogPoolFields(CStructureDataclass):
    logGroupPool: C_Ptr[GenericList[C_Ptr[SingleModeLogGroupObject]]]
    currentGroup: C_Ptr[SingleModeLogGroupObject]
    currentEventInfoType: C_Enum[SingleModeEventContentsInfoType]
    eventTitleName: SystemStringObjectPtr
    _ignored_1: c_bool  # omitted: privateForceMergeTextToPrev
    _ignored_2: C_UDeclPtr  # omitted: tmpStrBuild


@register_runtime_validatable('Gallop::SingleModeLogPool')
class SingleModeLogPoolObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeLogPoolFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeData
# ---------------------------------------------------------------------------

class WorkSingleModeDataFields(CStructureDataclass):
    storyInfoListDic: C_Ptr[GenericDictionary[WorkSingleModeDataStoryInfoListDictionaryEntry]]
    isExistPlayingData: C_Bool[c_bool]
    isPlaying: C_Bool[c_bool]
    totalTurnNum: ObscuredInt
    character: C_Ptr[WorkSingleModeCharaDataObject]
    raceConditions: C_Ptr[GenericList[C_Ptr[WorkSingleModeDataRaceConditionObject]]]
    homeInfo: C_Ptr[WorkSingleModeHomeInfoObject]
    _ignored_1: ObscuredInt  # omitted: addMusicId
    state: C_EnumIn[SingleModeState, ObscuredInt]
    playingState: C_EnumIn[SingleModePlayingState, ObscuredInt]
    _ignored_2: ArrayType[C_UDeclPtr, L[2]]  # omitted: scenarioIdList, difficultyInfoList
    changeParameterInfo: C_Ptr[WorkSingleModeChangeParameterInfoObject]
    raceHistoryInfoList: C_Ptr[GenericList[C_Ptr[RaceHistoryInfoObject]]]
    winSaddleArray: GenericArrayPtr[C_Ptr[MasterSingleModeWinsSaddleSingleModeWinsSaddleObject]]
    groupLogPool: C_Ptr[SingleModeLogPoolObject]
    _ignored_3: ArrayType[ObscuredBool, L[4]]  # omitted: isStepTurn … isForceChangeViewMonthStartView
    _ignored_4: ArrayType[ObscuredInt, L[2]]  # omitted: selectedTrainingCommandId, rentalCount
    _ignored_5: ObscuredLong  # omitted: prevFreeRentalTime
    successionEventInfo: C_Ptr[WorkSingleModeDataSuccessionEventInfoObject]
    raceStartResultInfoData: C_Ptr[WorkSingleModeDataRaceStartResultInfoObject]
    _ignored_6: ArrayType[C_UDeclPtr, L[2]]  # omitted: racePieceCampaignInfoList, storyEventBonusDict
    resumeFactorSelect: C_Ptr[SingleModeFactorSelectCommonObject]
    _ignored_7: C_UDeclPtr  # omitted: skillUpgradeFactorSelect
    eventChoiceRewardDict: C_Ptr[GenericDictionary[WorkSingleModeEventChoiceRewardDictionaryEntry]]
    cachedRewardEventId: C_Int[c_int32]
    _ignored_8: C_UDeclPtr  # omitted: defaultRunningStyleArray
    _ignored_9: ObscuredBool  # omitted: isUmaplan
    _ignored_10: C_UDeclPtr  # omitted: logAdditiveBuffer


@register_runtime_validatable('Gallop::WorkSingleModeData')
class WorkSingleModeDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeDataFields


# ---------------------------------------------------------------------------
# Gallop.PartsSingleModeResultFactorModel
# ---------------------------------------------------------------------------

class PartsSingleModeResultFactorModelFields(CStructureDataclass):
    _ignored_1: c_int32  # omitted: lotteryRemainNum
    factorSelectInfoList: C_Ptr[GenericList[C_Ptr[FactorSelectInfoObject]]]
    _ignored_2: C_UDeclPtr  # omitted: singleModeResultDataContainer


@register_runtime_validatable('Gallop::PartsSingleModeResultFactorModel')
class PartsSingleModeResultFactorModelObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: PartsSingleModeResultFactorModelFields


# ---------------------------------------------------------------------------
# Gallop.PartsSingleModeResultFactorSelectModel
# ---------------------------------------------------------------------------

class PartsSingleModeResultFactorSelectModelFields(CStructureDataclass):
    factorSelectInfoList: C_Ptr[GenericList[C_Ptr[FactorSelectInfoObject]]]
    _ignored_1: c_int32  # omitted: currentScrollIndex


@register_runtime_validatable('Gallop::PartsSingleModeResultFactorSelectModel')
class PartsSingleModeResultFactorSelectModelObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: PartsSingleModeResultFactorSelectModelFields


# ---------------------------------------------------------------------------
# Gallop.PartsSingleModeResultFactorSelect
# ---------------------------------------------------------------------------

class PartsSingleModeResultFactorSelectFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[5]]  # omitted: m_CachedPtr … skipButton
    _ignored_2: c_bool  # omitted: completeSequence
    _ignored_3: ArrayType[C_UDeclPtr, L[14]]  # omitted: fadeInSequenceList … fadeInSequence
    model: C_Ptr[PartsSingleModeResultFactorSelectModelObject]
    _ignored_4: ArrayType[C_UDeclPtr, L[9]]  # omitted: onHide … verticalNormalizedPositionDictionary


@register_runtime_validatable('Gallop::PartsSingleModeResultFactorSelect')
class PartsSingleModeResultFactorSelectObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: PartsSingleModeResultFactorSelectFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeResultSequence.SingleModeResultSequenceParts
# ---------------------------------------------------------------------------

class SingleModeResultSequencePartsFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[4]]  # omitted: trainedCharacterDetail … factorLottery
    factorSelect: C_Ptr[PartsSingleModeResultFactorSelectObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[10]]  # omitted: trainerStatus … collectRaid


@register_runtime_validatable('Gallop::SingleModeResultSequence.SingleModeResultSequenceParts')
class SingleModeResultSequencePartsObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeResultSequencePartsFields


# ---------------------------------------------------------------------------
# Gallop.PartsSingleModeResultRankScoreModel
# ---------------------------------------------------------------------------

class PartsSingleModeResultRankScoreModelFields(CStructureDataclass):
    characterId: C_Int[c_int32]
    trainingRank: C_Enum[FinalTrainingRank]
    rankScore: C_Int[c_int32]


@register_runtime_validatable('Gallop::PartsSingleModeResultRankScoreModel')
class PartsSingleModeResultRankScoreModelObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: PartsSingleModeResultRankScoreModelFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeResultSequence
# ---------------------------------------------------------------------------

class SingleModeResultSequenceFields(CStructureDataclass):
    _ignored_1: c_int32  # omitted: step
    _ignored_2: C_UDeclPtr  # omitted: coroutine
    _ignored_3: c_bool  # omitted: canChangeStep
    _ignored_4: ArrayType[C_UDeclPtr, L[6]]  # omitted: stepActionDic … charaViewer
    sequenceParts: C_Ptr[SingleModeResultSequencePartsObject]
    _ignored_5: ArrayType[C_UDeclPtr, L[3]]  # omitted: commonUIParts … singleModeFinishRequest
    rankScoreModel: C_Ptr[PartsSingleModeResultRankScoreModelObject]
    factorModel: C_Ptr[PartsSingleModeResultFactorModelObject]


@register_runtime_validatable('Gallop::SingleModeResultSequence')
class SingleModeResultSequenceObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeResultSequenceFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeResultViewController
# ---------------------------------------------------------------------------

class ViewControllerBaseStorage(CStructureDataclass):
    _ignored_1: c_int32  # omitted: viewId
    _ignored_2: ArrayType[C_UDeclPtr, L[3]]  # omitted: view, viewInfo, parentSceneController


class SingleModeResultViewControllerFields(CStructureDataclass):
    _ignored_1: c_bool  # omitted: isSendFinishAPI
    _ignored_2: C_UDeclPtr  # omitted: charaViewer
    sequence: C_Ptr[SingleModeResultSequenceObject]


@register_runtime_validatable('Gallop::SingleModeResultViewController')
class SingleModeResultViewControllerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    _view_controller_base: ViewControllerBaseStorage
    fields: SingleModeResultViewControllerFields
