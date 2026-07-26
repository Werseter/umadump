#!/usr/bin/env python3
"""
Game-specific struct definitions and ObscuredType decoders.

Contains:
  - ObscuredType value-type structs
  - WorkDataManager object hierarchy (partial — through SupportCardData)
  - Dictionary<int, SupportCardData> entry layout
"""
from __future__ import annotations

from ctypes import c_bool, c_float, c_int32, c_int64, c_uint16, c_uint32, c_uint64, c_uint8
from typing import Annotated, Iterator, Literal as L, cast as type_cast

from ctypes_utils import (ArrayType, CStructureDataclass, C_Float, C_Int, C_Ptr, C_UDeclPtr, C_VoidPtr,
                          RuntimeGenericMixin, SafeIntEnum, Span, StructOrSimple)
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_enum_validatable, register_runtime_validatable


# ---------------------------------------------------------------------------
# Game enums
# ---------------------------------------------------------------------------

@register_enum_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.UseType')
class TrainedCharaUseType(SafeIntEnum):
    NONE = 0
    RENTAL = 1
    GHOST = 2


@register_enum_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaPosition')
class SuccessionCharaPosition(SafeIntEnum):
    SELF = 1
    FIRST_1 = 10
    FIRST_2 = 20
    SECOND_1_1 = 11
    SECOND_1_2 = 12
    SECOND_2_1 = 21
    SECOND_2_2 = 22


@register_enum_validatable('Gallop::GameDefine.FinalTrainingRank')
class FinalTrainingRank(SafeIntEnum):
    NONE = 0
    G = 1
    G_PLUS = 2
    F = 3
    F_PLUS = 4
    E = 5
    E_PLUS = 6
    D = 7
    D_PLUS = 8
    C = 9
    C_PLUS = 10
    B = 11
    B_PLUS = 12
    A = 13
    A_PLUS = 14
    S = 15
    S_PLUS = 16
    SS = 17
    SS_PLUS = 18
    UG = 19
    UG1 = 20
    UG2 = 21
    UG3 = 22
    UG4 = 23
    UG5 = 24
    UG6 = 25
    UG7 = 26
    UG8 = 27
    UG9 = 28
    UF = 29
    UF1 = 30
    UF2 = 31
    UF3 = 32
    UF4 = 33
    UF5 = 34
    UF6 = 35
    UF7 = 36
    UF8 = 37
    UF9 = 38
    UE = 39
    UE1 = 40
    UE2 = 41
    UE3 = 42
    UE4 = 43
    UE5 = 44
    UE6 = 45
    UE7 = 46
    UE8 = 47
    UE9 = 48
    UD = 49
    UD1 = 50
    UD2 = 51
    UD3 = 52
    UD4 = 53
    UD5 = 54
    UD6 = 55
    UD7 = 56
    UD8 = 57
    UD9 = 58
    UC = 59
    UC1 = 60
    UC2 = 61
    UC3 = 62
    UC4 = 63
    UC5 = 64
    UC6 = 65
    UC7 = 66
    UC8 = 67
    UC9 = 68
    UB = 69
    UB1 = 70
    UB2 = 71
    UB3 = 72
    UB4 = 73
    UB5 = 74
    UB6 = 75
    UB7 = 76
    UB8 = 77
    UB9 = 78
    UA = 79
    UA1 = 80
    UA2 = 81
    UA3 = 82
    UA4 = 83
    UA5 = 84
    UA6 = 85
    UA7 = 86
    UA8 = 87
    UA9 = 88
    US = 89
    US1 = 90
    US2 = 91
    US3 = 92
    US4 = 93
    US5 = 94
    US6 = 95
    US7 = 96
    US8 = 97
    US9 = 98
    MIN = 1
    MAX = 98


@register_enum_validatable('Gallop::GameDefine.FactorRarity')
class FactorRarity(SafeIntEnum):
    NONE = 0
    RARE_1 = 1
    RARE_2 = 2
    RARE_3 = 3


@register_enum_validatable('Gallop::RaceDefine.RaceType')
class RaceType(SafeIntEnum):
    NONE = 0
    PvP = 1
    Tutorial = 2
    Story = 3
    StoryCondition = 4
    Champions = 5
    Single = 6
    SingleModeScenarioTeamRace = 7
    RoomMatch = 8
    Practice = 9
    Daily = 10
    TeamBuilding = 11
    Legend = 12
    ChallengeMatch = 13
    TeamStadium = 14
    Heroes = 16


@register_enum_validatable('Gallop::GameDefine.CardRarity')
class CardRarity(SafeIntEnum):
    NONE = 0
    Rare1 = 1
    Rare2 = 2
    Rare3 = 3
    Rare4 = 4
    Rare5 = 5


@register_enum_validatable('Gallop::HorseInitialLaneCalculator.InitialLaneType')
class InitialLaneType(SafeIntEnum):
    ExtraSpaceAfter9 = 1
    Equidistant = 2
    ExtraSpaceAfter14 = 3
    ExtraSpaceAfter8 = 4


@register_enum_validatable('Gallop::RaceDefine.Rotation')
class Rotation(SafeIntEnum):
    Right = 1
    Left = 2
    StraightRight = 3
    StraightLeft = 4


@register_enum_validatable('Gallop::RaceDefine.ResultBoardConditionType')
class ResultBoardConditionType(SafeIntEnum):
    Turf_None = 1
    Turf_Dirt = 2
    Dirt_None = 3
    Dirt_Turf = 4


@register_enum_validatable('Gallop::RaceDefine.CourseDistanceType')
class CourseDistanceType(SafeIntEnum):
    Short = 1
    Mile = 2
    Middle = 3
    Long = 4


@register_enum_validatable('Gallop::RaceDefine.TurfVisionType')
class TurfVisionType(SafeIntEnum):
    URA = 1
    NAU = 2
    Stand = 3


@register_enum_validatable('Gallop::RaceDefine.GroundCondition')
class RaceGroundCondition(SafeIntEnum):
    Good = 1
    Soft = 2
    Hard = 3
    Bad = 4


@register_enum_validatable('Gallop::RaceDefine.Weather')
class RaceWeather(SafeIntEnum):
    NONE = 0
    Sunny = 1
    Cloudy = 2
    Rainy = 3
    Snow = 4
    Max = 5
    Min = 0


@register_enum_validatable('Gallop::GameDefine.BgSeason')
class BgSeason(SafeIntEnum):
    NONE = 0
    Spring = 1
    Summer = 2
    Fall = 3
    Winter = 4
    CherryBlossom = 5
    Max = 6
    Min = 0


@register_enum_validatable('Gallop::RaceDefine.Time')
class RaceTime(SafeIntEnum):
    NONE = 0
    Morning = 1
    Daytime = 2
    Evening = 3
    Night = 4
    Max = 5
    Min = 0


@register_enum_validatable('Gallop::RaceDefine.RunningStyleEx')
class RunningStyleEx(SafeIntEnum):
    NONE = 0
    Oonige = 1


@register_enum_validatable('Gallop::RaceDefine.Motivation')
class RaceMotivation(SafeIntEnum):
    NONE = 0
    Min = 1
    Low = 2
    Middle = 3
    High = 4
    Max = 5


@register_enum_validatable('Gallop::RaceDefine.DefeatType')
class DefeatType(SafeIntEnum):
    Null = 0
    Win = 1
    Lose = 2
    RunningStyleMany = 3
    Temptaion = 4
    GutsOrder = 5
    Stamina = 6
    LastSpurtFalse = 7
    LastSpurtTargetSpeedDec = 8
    PassiveSkillNum = 9
    BlockFrontTime = 10
    Speed = 11
    ProperDistance = 12
    ProperGround = 13
    Motivation = 14


@register_enum_validatable('Gallop::ModelLoader.RaceRunningType')
class RaceRunningType(SafeIntEnum):
    Base = 1
    Pitch = 2
    Stride = 3


@register_enum_validatable('Gallop::RaceDefine.ProperGrade')
class ProperGrade(SafeIntEnum):
    Null = 0
    G = 1
    F = 2
    E = 3
    D = 4
    C = 5
    B = 6
    A = 7
    S = 8


@register_enum_validatable('Gallop::RaceDefine.Difficulty')
class RaceDifficulty(SafeIntEnum):
    Easy = 1
    Normal = 2
    Hard = 3
    VeryHard = 4
    Extreme = 5


@register_enum_validatable('Gallop::SingleModeDefine.CharaGradeType')
class CharaGradeType(SafeIntEnum):
    NONE = 0
    Debut = 1
    NoWin = 2
    Open = 3
    G3Silver = 4
    G3Gold = 5
    G2Silver = 6
    G2Gold = 7
    G1Bronze = 8
    G1Silver = 9
    G1Gold = 10
    Max = 10


@register_enum_validatable('Gallop::MainStoryDefine.RaceGimmickType')
class MainStoryRaceGimmickType(SafeIntEnum):
    NONE = 0
    Special_00 = 1


# ---------------------------------------------------------------------------
# System-namespace Miscellaneous Structs
# ---------------------------------------------------------------------------

class SystemStringFields(CStructureDataclass):
    stringLength: C_Int[c_int32]
    firstChar: C_Int[c_uint16]


class SystemStringObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SystemStringFields


class SystemStringObjectPtr(CStructureDataclass):
    """Pointer wrapper for ``System.String`` with UTF-16 decoding helper."""

    inner_ptr: C_Ptr[SystemStringObject]

    @property
    def value(self) -> str:
        """Decode managed ``System.String`` contents into a Python ``str``."""

        if not self.inner_ptr:
            raise ValueError("Cannot get string from null SystemStringObject pointer")
        length = self.inner_ptr.contents.fields.stringLength
        if length <= 0:
            return ''
        chars_ptr = (int(self.inner_ptr) + int(getattr(SystemStringObject, 'fields').offset)
                     + int(getattr(SystemStringFields, 'firstChar').offset))
        chars_array_ptr = C_Ptr[c_uint16](chars_ptr)
        return ''.join(chr(x.value) for x in chars_array_ptr.as_span(length))


# ---------------------------------------------------------------------------
# Generic Managed Containers
# ---------------------------------------------------------------------------

class GenericArray[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``System.Array`` layout with flexible ``m_items`` tail."""

    _il2cpp_obj: RuntimeIl2CppObject
    _ignored_1: C_UDeclPtr  # bounds
    max_length: C_Int[c_uint64]
    m_items: ArrayType[CDT, L[0]]


class GenericArrayPtr[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Typed pointer to ``GenericArray[T]`` with span/iteration helpers."""

    inner_ptr: C_Ptr[GenericArray[CDT]]

    def span(self) -> Span[CDT]:
        """Return a ``Span`` over the array payload (``m_items``)."""

        if not self.inner_ptr.contents:
            raise ValueError("Cannot get span of null GenericArray pointer")
        count = self.inner_ptr.contents.max_length
        item_type = self._resolve_class_target_type()
        m_items_ptr = int(self.inner_ptr) + int(getattr(GenericArray, 'm_items').offset)
        # noinspection PyTypeHints
        items_ptr = C_Ptr[item_type](m_items_ptr)  # type: ignore[valid-type]
        return items_ptr.as_span(count)

    def __iter__(self) -> Iterator[CDT]:
        return iter(self.span())

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


class GenericListFields[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    items: GenericArrayPtr[CDT]
    size: C_Int[c_int32]
    version: C_Int[c_int32]
    _ignored_1: C_UDeclPtr  # _syncRoot


class GenericList[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``List<T>`` wrapper with size-limited iteration."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericListFields[CDT]

    def span(self) -> Span[CDT]:
        if self.fields.size == 0:
            return Span(self.fields.items.inner_ptr, 0)  # type: ignore[arg-type]
        return self.fields.items.span()

    def __iter__(self) -> Iterator[CDT]:
        """Iterate list items up to logical ``size`` (not array capacity)."""

        cnt = 0
        for entry in iter(self.span()):
            if cnt >= self.fields.size:
                break
            yield entry
            cnt += 1

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


class GenericDictionaryEntry(CStructureDataclass):
    """
    Single entry in Dictionary<TKey, TVal>.m_items

    Depending on the generic sharing strategy used by Il2Cpp, the actual layout of the entry may vary.
    Data may be inlined directly in the entry on runtime.
    Use dedicated subclasses for specific TKey/TValue if layout uses specialized types instead of Il2CppObject pointers.
    """
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_VoidPtr
    value: C_VoidPtr


class GenericDictionaryFields[CDT: StructOrSimple = GenericDictionaryEntry](CStructureDataclass,
                                                                            RuntimeGenericMixin[CDT]):
    _ignored_1: C_UDeclPtr  # buckets
    entries: GenericArrayPtr[CDT]
    count: C_Int[c_int32]
    _ignored_2: ArrayType[c_int32, L[2]]  # freeList, freeCount
    version: C_Int[c_int32]
    _ignored_3: ArrayType[C_UDeclPtr, L[4]]  # comparer, keys, values, syncRoot


class GenericDictionary[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``Dictionary<TKey, TValue>`` wrapper over entry array storage."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericDictionaryFields[CDT]

    def span(self) -> Span[CDT]:
        if self.fields.count == 0:
            return Span(self.fields.entries.inner_ptr, 0)  # type: ignore[arg-type]
        return self.fields.entries.span()

    def __iter__(self) -> Iterator[CDT]:
        """Yield entries with valid hash codes and warn on count mismatch."""

        valid = 0
        for entry in iter(self.span()):
            # noinspection PyUnnecessaryCast
            if type_cast(GenericDictionaryEntry, entry).hashCode > 0:
                valid += 1
                yield entry

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


# ---------------------------------------------------------------------------
# ObscuredTypes value-type structs
# ---------------------------------------------------------------------------

class ObscuredBool(CStructureDataclass):
    currentCryptoKey: C_Int[c_uint8]
    hiddenValue: C_Int[c_int32]
    _ignored_1: c_bool  # inited
    _ignored_2: c_bool  # fakeValue
    _ignored_3: c_bool  # fakeValueActive

    @property
    def value(self) -> bool:
        false_sentinel = 0xB5
        decoded = int(self.currentCryptoKey) ^ int(self.hiddenValue)
        return decoded != false_sentinel


class ObscuredInt(CStructureDataclass):
    currentCryptoKey: C_Int[c_int32]
    hiddenValue: C_Int[c_int32]
    _ignored_1: c_bool  # inited
    _ignored_2: c_int32  # fakeValue
    _ignored_3: c_bool  # fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredLong(CStructureDataclass):
    currentCryptoKey: C_Int[c_int64]
    hiddenValue: C_Int[c_int64]
    _ignored_1: c_bool  # inited
    _ignored_2: c_int64  # fakeValue
    _ignored_3: c_bool  # fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredULong(CStructureDataclass):
    currentCryptoKey: C_Int[c_uint64]
    hiddenValue: C_Int[c_uint64]
    _ignored_1: c_bool  # inited
    _ignored_2: c_uint64  # fakeValue
    _ignored_3: c_bool  # fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredString(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    currentCryptoKey: SystemStringObjectPtr
    hiddenValue: GenericArrayPtr[c_uint8]
    _ignored_1: c_bool  # inited
    _ignored_2: SystemStringObjectPtr  # fakeValue
    _ignored_3: c_bool  # fakeValueActive

    @property
    def value(self) -> str:
        key_str = self.currentCryptoKey.value
        key_len = len(key_str)
        if key_len == 0:
            return ''
        raw_bytes = bytes(b.value for b in self.hiddenValue)
        enc_str = raw_bytes.decode('utf-16le')
        dec_str = ''.join(chr(ord(c) ^ ord(key_str[i % key_len])) for i, c in enumerate(enc_str))
        return dec_str.rstrip('\x00')  # strip null terminator if present


class ObscuredStringPtr(CStructureDataclass):
    """Pointer wrapper for ``ObscuredString`` with integrated null check"""

    inner_ptr: C_Ptr[ObscuredString]

    @property
    def value(self) -> str:
        if not self.inner_ptr:
            raise ValueError("Cannot get string from null ObscuredString pointer")
        return self.inner_ptr.contents.value


# ---------------------------------------------------------------------------
# Gallop.WorkSkillData.SkillDataBase
# ---------------------------------------------------------------------------

class SkillDataBaseFields(CStructureDataclass):
    masterId: ObscuredInt
    level: ObscuredInt
    _ignored_1: C_UDeclPtr  # master


@register_runtime_validatable('Gallop::WorkSkillData.SkillDataBase')
class SkillDataBaseObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SkillDataBaseFields


# ---------------------------------------------------------------------------
# Gallop.WorkSkillData.AcquiredSkill
# ---------------------------------------------------------------------------

class AcquiredSkillFields(SkillDataBaseFields):
    pass


@register_runtime_validatable('Gallop::WorkSkillData.AcquiredSkill')
class AcquiredSkillObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: AcquiredSkillFields


# ---------------------------------------------------------------------------
# Gallop.WorkSkillData.AcquirableSkill
# ---------------------------------------------------------------------------

class AcquirableSkillFields(SkillDataBaseFields):
    _ignored_1: C_UDeclPtr  # skillSet


@register_runtime_validatable('Gallop::WorkSkillData.AcquirableSkill')
class AcquirableSkillObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: AcquirableSkillFields


# ---------------------------------------------------------------------------
# Gallop.WorkCardData.CardData
# ---------------------------------------------------------------------------

class HintLevelDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: ObscuredInt
    value: ObscuredInt


class CardDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # masterCard … masterChara / masterDataPtrs
    cardId: ObscuredInt
    talentLevel: ObscuredInt
    rarity: ObscuredInt
    hintLevelDic: C_Ptr[GenericDictionary[HintLevelDictionaryEntry]]
    _ignored_2: ObscuredInt  # changedModelDressId
    createTime: ObscuredLong
    _ignored_3: ArrayType[ObscuredInt, L[5]]  # speed … wiz
    uniqueSkill: C_Ptr[AcquiredSkillObject]
    acquirableSkillArray: GenericArrayPtr[C_Ptr[AcquirableSkillObject]]


@register_runtime_validatable('Gallop::WorkCardData.CardData')
class CardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: CardDataFields


class CardDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[CardDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkCardData
# ---------------------------------------------------------------------------

class WorkCardDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[CardDataDictionaryEntry]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # releaseCardIdList, BackableStateStack


@register_runtime_validatable('Gallop::WorkCardData')
class WorkCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkCardDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSupportCardData.SupportCardData
# ---------------------------------------------------------------------------

class SupportCardDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[6]]  # masterSupportCard … masterUniqueEffect
    supportCardId: ObscuredInt
    level: ObscuredInt
    limitBreakCount: ObscuredInt
    maxLevel: ObscuredInt
    createTime: ObscuredLong
    exp: ObscuredInt
    stock: ObscuredInt
    isFavoriteLock: ObscuredBool
    bestTraining: C_Int[c_int32]
    _ignored_2: C_UDeclPtr  # SkillTriggerTagArray


@register_runtime_validatable('Gallop::WorkSupportCardData.SupportCardData')
class SupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SupportCardDataFields


class SupportCardDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[SupportCardDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkSupportCardData
# ---------------------------------------------------------------------------

class WorkSupportCardDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[SupportCardDataDictionaryEntry]]
    _ignored_1: C_UDeclPtr  # BackableStateStack


@register_runtime_validatable('Gallop::WorkSupportCardData')
class WorkSupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSupportCardDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData.UpgradeHistory
# ---------------------------------------------------------------------------

class FactorDataUpgradeHistoryFields(CStructureDataclass):
    factorId: ObscuredInt
    upgradeDate: ObscuredLong


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData'
                              '.FactorData.UpgradeHistory')
class FactorDataUpgradeHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorDataUpgradeHistoryFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData
# ---------------------------------------------------------------------------

class FactorDataFields(CStructureDataclass):
    factorLv: ObscuredInt
    factorId: ObscuredInt
    baseFactorId: ObscuredInt
    upgradeHistoryList: C_Ptr[GenericList[C_Ptr[FactorDataUpgradeHistoryObject]]]


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData')
class FactorDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.FavoriteData
# ---------------------------------------------------------------------------

class FavoriteDataFields(CStructureDataclass):
    trainedCharaId: C_Int[c_int32]
    type: C_Int[c_int32]
    memo: SystemStringObjectPtr


@register_runtime_validatable('Gallop::WorkTrainedCharaData.FavoriteData')
class FavoriteDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FavoriteDataFields


class FavoriteDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[FavoriteDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData
# ---------------------------------------------------------------------------

class SuccessionCharaDataFields(CStructureDataclass):
    positionId: Annotated[ObscuredInt, SuccessionCharaPosition]
    cardId: ObscuredInt
    rarity: ObscuredInt
    level: ObscuredInt
    rank: Annotated[ObscuredInt, FinalTrainingRank]
    factorDataArray: GenericArrayPtr[C_Ptr[FactorDataObject]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # _sortedFactorList, _sortedFactorListForProfileCard / masterDataPtrs
    ownerViewerId: ObscuredLong
    isPlayer: C_Int[c_bool]
    _ignored_2: C_UDeclPtr  # winSaddleArray / masterDataPtr
    winSaddleIdArray: GenericArrayPtr[ObscuredInt]


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData')
class SuccessionCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SuccessionCharaDataFields


# ---------------------------------------------------------------------------
# Gallop.SuccessionHistory
# ---------------------------------------------------------------------------

class SuccessionHistoryFields(CStructureDataclass):
    id: C_Int[c_int32]
    viewer_id: C_Int[c_int64]
    trained_chara_id: C_Int[c_int32]
    hisotry_type: C_Int[c_int32]
    succession_card_id: C_Int[c_int32]
    date: C_Int[c_int32]
    user_name: SystemStringObjectPtr
    circle_name: SystemStringObjectPtr


@register_runtime_validatable('Gallop::SuccessionHistory')
class SuccessionHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SuccessionHistoryFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.SupportCardData
# ---------------------------------------------------------------------------

class TrainedCharaSupportCardDataFields(CStructureDataclass):
    position: ObscuredInt
    supportCardId: ObscuredInt
    limitBreakCount: ObscuredInt
    exp: ObscuredInt


@register_runtime_validatable('Gallop::WorkTrainedCharaData.SupportCardData')
class TrainedCharaSupportCardDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaSupportCardDataFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeUtils.RaceHistoryInfo
# ---------------------------------------------------------------------------

class RaceHistoryInfoFields(CStructureDataclass):
    turn: ObscuredInt
    programId: ObscuredInt
    _ignored_1: ObscuredInt  # raceInstanceId
    _ignored_2: ObscuredInt  # frameOrder
    _ignored_3: ObscuredInt  # npcCount
    weather: ObscuredInt
    groundCondition: ObscuredInt
    runningStyle: ObscuredInt
    resultRank: ObscuredInt
    _ignored_4: ObscuredInt  # scenarioId


@register_runtime_validatable('Gallop::SingleModeUtils.RaceHistoryInfo')
class RaceHistoryInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHistoryInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData.TrainedCharaData
# ---------------------------------------------------------------------------

class TrainedCharaDataFields(CStructureDataclass):
    id: ObscuredInt
    isSaved: ObscuredBool
    viewerId: ObscuredLong
    ownerViewerId: ObscuredLong
    ownerTrainedCharaId: ObscuredInt
    useType: Annotated[C_Int[c_int32], TrainedCharaUseType]
    cardId: ObscuredInt
    nickNameId: ObscuredInt
    nickNameIdArray: GenericArrayPtr[ObscuredInt]
    stamina: ObscuredInt
    speed: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    fans: ObscuredInt
    rank: Annotated[ObscuredInt, FinalTrainingRank]
    rankScore: ObscuredInt
    runningStyle: ObscuredInt
    properGroundTurf: ObscuredInt
    properGroundDirt: ObscuredInt
    properDistanceShort: ObscuredInt
    properDistanceMile: ObscuredInt
    properDistanceMiddle: ObscuredInt
    properDistanceLong: ObscuredInt
    properRunningStyleNige: ObscuredInt
    properRunningStyleSenko: ObscuredInt
    properRunningStyleSashi: ObscuredInt
    properRunningStyleOikomi: ObscuredInt
    successionCount: ObscuredInt
    factorDataArray: GenericArrayPtr[C_Ptr[FactorDataObject]]
    createTime: ObscuredStringPtr
    scenarioId: ObscuredInt
    talentLevel: ObscuredInt
    charaGrade: ObscuredInt
    rarity: ObscuredInt
    isLock: ObscuredBool
    favoriteData: C_Ptr[FavoriteDataObject]
    cachedCreateTimeTimeStamp: ObscuredLong
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # sortedFactorList … sortedFactorProfileCardList / masterDataPtrs
    successionCharaList: C_Ptr[GenericList[C_Ptr[SuccessionCharaDataObject]]]
    _ignored_2: c_bool  # isSuccessionHistoryInitialized
    _ignored_3: C_UDeclPtr  # successionHistoryList
    acquiredSkillArray: GenericArrayPtr[C_Ptr[AcquiredSkillObject]]
    supportCardArray: GenericArrayPtr[C_Ptr[TrainedCharaSupportCardDataObject]]
    singleModeRaceResultArray: GenericArrayPtr[C_Ptr[RaceHistoryInfoObject]]
    _ignored_4: C_UDeclPtr  # winSaddleArray / masterDataPtr
    winSaddleIdArray: GenericArrayPtr[ObscuredInt]
    cacheCharaId: ObscuredInt
    _ignored_5: ArrayType[C_UDeclPtr, L[3]]  # masterCardData, masterCharaData, masterCardRarityData / masterDataPtrs
    singleTotalRaceNum: C_Int[c_int32]
    singleWinNum: ObscuredInt
    _ignored_6: C_UDeclPtr  # trainedCharaDataAccessor


@register_runtime_validatable('Gallop::WorkTrainedCharaData.TrainedCharaData')
class TrainedCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaDataFields


class TrainedCharaDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrainedCharaDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrainedCharaData
# ---------------------------------------------------------------------------

class WorkTrainedCharaDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[TrainedCharaDataDictionaryEntry]]
    allDataDic: C_Ptr[GenericDictionary[TrainedCharaDataDictionaryEntry]]
    _ignored_1: C_UDeclPtr  # list
    favoriteDataDict: C_Ptr[GenericDictionary[FavoriteDataDictionaryEntry]]


@register_runtime_validatable('Gallop::WorkTrainedCharaData')
class WorkTrainedCharaDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTrainedCharaDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkFriendData.FriendData
# ---------------------------------------------------------------------------

class HonorDataFields(CStructureDataclass):
    honor_id: C_Int[c_int32]
    _ignored_1: c_int32  # step
    _ignored_2: C_UDeclPtr  # create_time


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


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData.CharaIdList
# ---------------------------------------------------------------------------

class TrophyDataCharaIdListFields(CStructureDataclass):
    charaId: ObscuredInt
    winCount: ObscuredInt


@register_runtime_validatable('Gallop::WorkTrophyData.CharaIdList')
class TrophyDataCharaIdListObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrophyDataCharaIdListFields


class TrophyDataCharaIdListDictionaryInnerEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrophyDataCharaIdListObject]


class TrophyDataCharaIdListDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryInnerEntry]]


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData.TrophyData
# ---------------------------------------------------------------------------

class TrophyDataFields(CStructureDataclass):
    trophyId: ObscuredInt
    charaIdList: C_Ptr[GenericList[c_int32]]
    raceCharaDataDic: C_Ptr[GenericDictionary[TrophyDataCharaIdListDictionaryEntry]]
    _ignored_1: c_bool  # isNew


@register_runtime_validatable('Gallop::WorkTrophyData.TrophyData')
class TrophyDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrophyDataFields


class TrophyDataDictionaryEntry(CStructureDataclass):
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_Int[c_int32]
    value: C_Ptr[TrophyDataObject]


# ---------------------------------------------------------------------------
# Gallop.WorkTrophyData
# ---------------------------------------------------------------------------

class WorkTrophyDataFields(CStructureDataclass):
    dataDic: C_Ptr[GenericDictionary[TrophyDataDictionaryEntry]]
    _ignored_1: c_bool  # isNew


@register_runtime_validatable('Gallop::WorkTrophyData')
class WorkTrophyDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTrophyDataFields


# ---------------------------------------------------------------------------
# Gallop.SkillData
# ---------------------------------------------------------------------------

class SkillDataFields(CStructureDataclass):
    skill_id: C_Int[c_int32]
    level: C_Int[c_int32]


@register_runtime_validatable('Gallop::SkillData')
class SkillDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SkillDataFields


# ---------------------------------------------------------------------------
# Gallop.RaceHorseDataRaceResult
# ---------------------------------------------------------------------------

class RaceHorseDataRaceResultFields(CStructureDataclass):
    turn: C_Int[c_int32]
    program_id: C_Int[c_int32]
    result_rank: C_Int[c_int32]


@register_runtime_validatable('Gallop::RaceHorseDataRaceResult')
class RaceHorseDataRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHorseDataRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.RaceHorseData
# ---------------------------------------------------------------------------

class RaceHorseDataFields(CStructureDataclass):
    viewer_id: C_Int[c_int64]
    owner_viewer_id: C_Int[c_int64]
    trainer_name: SystemStringObjectPtr
    owner_trainer_name: SystemStringObjectPtr
    single_mode_chara_id: C_Int[c_int32]
    trained_chara_id: C_Int[c_int32]
    nickname_id: C_Int[c_int32]
    card_id: C_Int[c_int32]
    chara_id: C_Int[c_int32]
    rarity: C_Int[c_int32]
    talent_level: C_Int[c_int32]
    frame_order: C_Int[c_int32]
    skill_array: GenericArrayPtr[C_Ptr[SkillDataObject]]
    stamina: C_Int[c_int32]
    speed: C_Int[c_int32]
    pow: C_Int[c_int32]
    guts: C_Int[c_int32]
    wiz: C_Int[c_int32]
    running_style: C_Int[c_int32]
    race_dress_id: C_Int[c_int32]
    chara_color_type: C_Int[c_int32]
    npc_type: C_Int[c_int32]
    final_grade: C_Int[c_int32]
    popularity: C_Int[c_int32]
    popularity_mark_rank_array: GenericArrayPtr[c_int32]
    proper_distance_short: C_Int[c_int32]
    proper_distance_mile: C_Int[c_int32]
    proper_distance_middle: C_Int[c_int32]
    proper_distance_long: C_Int[c_int32]
    proper_running_style_nige: C_Int[c_int32]
    proper_running_style_senko: C_Int[c_int32]
    proper_running_style_sashi: C_Int[c_int32]
    proper_running_style_oikomi: C_Int[c_int32]
    proper_ground_turf: C_Int[c_int32]
    proper_ground_dirt: C_Int[c_int32]
    motivation: C_Int[c_int32]
    mob_id: C_Int[c_int32]
    win_saddle_id_array: GenericArrayPtr[c_int32]
    race_result_array: GenericArrayPtr[C_Ptr[RaceHorseDataRaceResultObject]]
    team_id: C_Int[c_int32]
    team_member_id: C_Int[c_int32]
    item_id_array: GenericArrayPtr[c_int32]
    motivation_change_flag: C_Int[c_int32]
    frame_order_change_flag: C_Int[c_int32]
    team_rank: C_Int[c_int32]
    single_mode_win_count: C_Int[c_int32]
    fan_count: C_Int[c_int32]


@register_runtime_validatable('Gallop::RaceHorseData')
class RaceHorseDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceHorseDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumResultBonusData
# ---------------------------------------------------------------------------

class TeamStadiumResultBonusDataFields(CStructureDataclass):
    score_bonus_id: C_Int[c_int32]
    bonus_score: C_Int[c_int32]
    condition_type: C_Int[c_int32]
    condition_value_1: C_Int[c_int32]
    condition_value_2: C_Int[c_int32]
    score_rate: C_Int[c_int32]


@register_runtime_validatable('Gallop::TeamStadiumResultBonusData')
class TeamStadiumResultBonusDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultBonusDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumResultScoreData
# ---------------------------------------------------------------------------

class TeamStadiumResultScoreDataFields(CStructureDataclass):
    raw_score_id: C_Int[c_int32]
    num: C_Int[c_int32]
    score: C_Int[c_int32]
    bonus_array: GenericArrayPtr[C_Ptr[TeamStadiumResultBonusDataObject]]


@register_runtime_validatable('Gallop::TeamStadiumResultScoreData')
class TeamStadiumResultScoreDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultScoreDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumRaceCharaResult
# ---------------------------------------------------------------------------

class TeamStadiumRaceCharaResultFields(CStructureDataclass):
    viewer_id: C_Int[c_int64]
    frame_order: C_Int[c_int32]
    trained_chara_id: C_Int[c_int32]
    team_id: C_Int[c_int32]
    finish_order: C_Int[c_int32]
    finish_time: C_Int[c_int32]
    score_array: GenericArrayPtr[C_Ptr[TeamStadiumResultScoreDataObject]]


@register_runtime_validatable('Gallop::TeamStadiumRaceCharaResult')
class TeamStadiumRaceCharaResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumRaceCharaResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.OpponentData
# ---------------------------------------------------------------------------

class WorkTeamStadiumOpponentDataFields(CStructureDataclass):
    _ignored_1: ObscuredLong  # opponentViewerId
    evaluationPoint: ObscuredInt
    _ignored_2: ArrayType[C_UDeclPtr, L[2]]  # userData, deckInfo
    winningRewardGuaranteeStatus: ObscuredInt
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # serverData, trainedCharaDic


@register_runtime_validatable('Gallop::WorkTeamStadiumData.OpponentData')
class WorkTeamStadiumOpponentDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTeamStadiumOpponentDataFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumSupportCardBonusInfo
# ---------------------------------------------------------------------------

class TeamStadiumSupportCardBonusInfoFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # supportCardBonusList
    totalSupportCardBonus: C_Int[c_int32]


@register_runtime_validatable('Gallop::TeamStadiumSupportCardBonusInfo')
class TeamStadiumSupportCardBonusInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumSupportCardBonusInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.TeamStadiumResult.RaceResult
# ---------------------------------------------------------------------------

class TeamStadiumRaceResultFields(CStructureDataclass):
    raceNum: ObscuredInt
    round: ObscuredInt
    raceInstanceId: ObscuredInt
    weather: ObscuredInt
    season: ObscuredInt
    groundCondition: ObscuredInt
    randomSeed: ObscuredInt
    raceScenario: ObscuredStringPtr
    teamTotalScore: ObscuredInt
    raceHorseDataArray: GenericArrayPtr[C_Ptr[RaceHorseDataObject]]
    charaResultArray: GenericArrayPtr[C_Ptr[TeamStadiumRaceCharaResultObject]]
    teamScoreArray: GenericArrayPtr[C_Ptr[TeamStadiumResultScoreDataObject]]
    roundResult: C_Int[c_int32]
    currentConsecutiveWinCount: ObscuredInt
    bonusRateByNextWin: ObscuredInt


@register_runtime_validatable('Gallop::WorkTeamStadiumData.TeamStadiumResult.RaceResult')
class TeamStadiumRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData.TeamStadiumResult
# ---------------------------------------------------------------------------

class TeamStadiumResultFields(CStructureDataclass):
    useItemIdArray: GenericArrayPtr[c_int32]
    raceResultArray: GenericArrayPtr[C_Ptr[TeamStadiumRaceResultObject]]
    isIncludeUnsupportedRace: C_Int[c_bool]
    _ignored_1: C_UDeclPtr  # winningRewardInfoArray


@register_runtime_validatable('Gallop::WorkTeamStadiumData.TeamStadiumResult')
class TeamStadiumResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumResultFields


# ---------------------------------------------------------------------------
# Gallop.TeamStadiumStatus
# ---------------------------------------------------------------------------

class TeamStadiumStatusFields(CStructureDataclass):
    _ignored_1: c_int32  # currentState
    _ignored_2: C_UDeclPtr  # myDeckInfo
    opponentData: C_Ptr[WorkTeamStadiumOpponentDataObject]
    result: C_Ptr[TeamStadiumResultObject]
    _ignored_3: ArrayType[c_int32, L[2]]  # supportCartBonus, simulateRaceRound


@register_runtime_validatable('Gallop::TeamStadiumStatus')
class TeamStadiumStatusObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TeamStadiumStatusFields


# ---------------------------------------------------------------------------
# Gallop.WorkTeamStadiumData
# ---------------------------------------------------------------------------

class WorkTeamStadiumDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # teamStadiumInfo, teamStadiumDeckInfo
    teamStadiumStatus: C_Ptr[TeamStadiumStatusObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[6]]  # opponentDataList … teamStadiumMenuBgmInfo
    teamStadiumSupportCardBonusInfo: C_Ptr[TeamStadiumSupportCardBonusInfoObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # teamEvaluationUpdateRankRewardArray, updateTeamRankInfo
    _ignored_4: c_bool  # needNotifyBadge
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # stadiumRaceCharaIdArray, prevMemberList


@register_runtime_validatable('Gallop::WorkTeamStadiumData')
class WorkTeamStadiumDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTeamStadiumDataFields


# ---------------------------------------------------------------------------
# Gallop.SkillTips
# ---------------------------------------------------------------------------

class SkillTipsFields(CStructureDataclass):
    group_id: c_int32
    rarity: c_int32
    level: c_int32


@register_runtime_validatable('Gallop::SkillTips')
class SkillTipsObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SkillTipsFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeSupportCard
# ---------------------------------------------------------------------------

class SingleModeSupportCardFields(CStructureDataclass):
    position: c_int32
    support_card_id: c_int32
    limit_break_count: c_int32
    exp: c_int32
    training_partner_state: c_int32
    owner_viewer_id: c_int64
    rental_type: c_int32


@register_runtime_validatable('Gallop::SingleModeSupportCard')
class SingleModeSupportCardObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeSupportCardFields


# ---------------------------------------------------------------------------
# Gallop.GroupOutingInfo
# ---------------------------------------------------------------------------

class GroupOutingInfoFields(CStructureDataclass):
    chara_id: c_int32
    is_outing: c_int32
    story_step: c_int32


@register_runtime_validatable('Gallop::GroupOutingInfo')
class GroupOutingInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GroupOutingInfoFields


# ---------------------------------------------------------------------------
# Gallop.EvaluationInfo
# ---------------------------------------------------------------------------

class EvaluationInfoFields(CStructureDataclass):
    target_id: c_int32
    evaluation: c_int32
    is_outing: c_int32
    story_step: c_int32
    is_appear: c_int32
    group_outing_info_array: GenericArrayPtr[C_Ptr[GroupOutingInfoObject]]


@register_runtime_validatable('Gallop::EvaluationInfo')
class EvaluationInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: EvaluationInfoFields


# ---------------------------------------------------------------------------
# Gallop.TrainingLevelInfo
# ---------------------------------------------------------------------------

class TrainingLevelInfoFields(CStructureDataclass):
    command_id: c_int32
    level: c_int32


@register_runtime_validatable('Gallop::TrainingLevelInfo')
class TrainingLevelInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainingLevelInfoFields


# ---------------------------------------------------------------------------
# Gallop.GuestOutingInfo
# ---------------------------------------------------------------------------

class GuestOutingInfoFields(CStructureDataclass):
    support_card_id: c_int32
    story_step: c_int32
    group_outing_info_array: GenericArrayPtr[C_Ptr[GroupOutingInfoObject]]


@register_runtime_validatable('Gallop::GuestOutingInfo')
class GuestOutingInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: GuestOutingInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeSkillUpgrade
# ---------------------------------------------------------------------------

class SingleModeSkillUpgradeFields(CStructureDataclass):
	condition_id: c_int32
	total_count: c_int32
	current_count: c_int32


@register_runtime_validatable('Gallop::SingleModeSkillUpgrade')
class SingleModeSkillUpgradeObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeSkillUpgradeFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeChara
# ---------------------------------------------------------------------------

class SingleModeCharaFields(CStructureDataclass):
    single_mode_chara_id: c_int32
    card_id: c_int32
    chara_grade: c_int32
    speed: c_int32
    stamina: c_int32
    power: c_int32
    wiz: c_int32
    guts: c_int32
    vital: c_int32
    max_speed: c_int32
    max_stamina: c_int32
    max_power: c_int32
    max_wiz: c_int32
    max_guts: c_int32
    default_max_speed: c_int32
    default_max_stamina: c_int32
    default_max_power: c_int32
    default_max_wiz: c_int32
    default_max_guts: c_int32
    max_vital: c_int32
    motivation: c_int32
    fans: c_int32
    rarity: c_int32
    race_program_id: c_int32
    reserve_race_program_id: c_int32
    race_running_style: c_int32
    is_short_race: c_int32
    talent_level: c_int32
    skill_array: GenericArrayPtr[C_Ptr[SkillDataObject]]
    disable_skill_id_array: GenericArrayPtr[c_int32]
    skill_tips_array: GenericArrayPtr[C_Ptr[SkillTipsObject]]
    support_card_array: GenericArrayPtr[C_Ptr[SingleModeSupportCardObject]]
    succession_trained_chara_id_1: c_int32
    succession_trained_chara_id_2: c_int32
    proper_distance_short: c_int32
    proper_distance_mile: c_int32
    proper_distance_middle: c_int32
    proper_distance_long: c_int32
    proper_running_style_nige: c_int32
    proper_running_style_senko: c_int32
    proper_running_style_sashi: c_int32
    proper_running_style_oikomi: c_int32
    proper_ground_turf: c_int32
    proper_ground_dirt: c_int32
    turn: c_int32
    skill_point: c_int32
    short_cut_state: c_int32
    state: c_int32
    playing_state: c_int32
    scenario_id: c_int32
    route_id: c_int32
    start_time: SystemStringObjectPtr
    evaluation_info_array: GenericArrayPtr[C_Ptr[EvaluationInfoObject]]
    training_level_info_array: GenericArrayPtr[C_Ptr[TrainingLevelInfoObject]]
    nickname_id_array: GenericArrayPtr[c_int32]
    chara_effect_id_array: GenericArrayPtr[c_int32]
    route_race_id_array: GenericArrayPtr[c_int32]
    guest_outing_info_array: GenericArrayPtr[C_Ptr[GuestOutingInfoObject]]
    skill_upgrade_info_array: GenericArrayPtr[C_Ptr[SingleModeSkillUpgradeObject]]


@register_runtime_validatable('Gallop::SingleModeChara')
class SingleModeCharaObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeCharaFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredCharaEffectLog
# ---------------------------------------------------------------------------

class ObscuredCharaEffectLogFields(CStructureDataclass):
    charaEffectId: ObscuredInt
    isActive: ObscuredBool


@register_runtime_validatable('Gallop::ObscuredCharaEffectLog')
class ObscuredCharaEffectLogObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredCharaEffectLogFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSignedInt
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSignedIntFields(CStructureDataclass):
    sign: ObscuredInt
    value: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSignedInt')
class ObscuredIdleSingleModeSignedIntObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSignedIntFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeGainInfoFields(CStructureDataclass):
    speed: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    stamina: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    power: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    wiz: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    guts: C_Ptr[ObscuredIdleSingleModeSignedIntObject]
    maxSpeed: ObscuredInt
    maxStamina: ObscuredInt
    maxPower: ObscuredInt
    maxWiz: ObscuredInt
    maxGuts: ObscuredInt
    properDistanceShort: ObscuredInt
    properDistanceMile: ObscuredInt
    properDistanceMiddle: ObscuredInt
    properDistanceLong: ObscuredInt
    properRunningStyleNige: ObscuredInt
    properRunningStyleSenko: ObscuredInt
    properRunningStyleSashi: ObscuredInt
    properRunningStyleOikomi: ObscuredInt
    properGroundTurf: ObscuredInt
    properGroundDirt: ObscuredInt
    skillPoint: ObscuredInt
    skillTipsArray: GenericArrayPtr[C_Ptr[SkillTipsObject]]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeGainInfo')
class ObscuredIdleSingleModeGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeGainInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSupportCardGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSupportCardGainInfoFields(CStructureDataclass):
    supportCardId: ObscuredInt
    gainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSupportCardGainInfo')
class ObscuredIdleSingleModeSupportCardGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSupportCardGainInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredFactorInfo
# ---------------------------------------------------------------------------

class ObscuredFactorInfoFields(CStructureDataclass):
    factorId: ObscuredInt
    level: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredFactorInfo')
class ObscuredFactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredFactorInfoFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeSuccessionFactorGainInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeSuccessionFactorGainInfoFields(CStructureDataclass):
    year: ObscuredInt
    gainFactorInfoArray: GenericArrayPtr[C_Ptr[ObscuredFactorInfoObject]]


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeSuccessionFactorGainInfo')
class ObscuredIdleSingleModeSuccessionFactorGainInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeSuccessionFactorGainInfoFields


# ---------------------------------------------------------------------------
# Gallop.SingleRaceHistory
# ---------------------------------------------------------------------------

class SingleRaceHistoryFields(CStructureDataclass):
    turn: c_int32
    program_id: c_int32
    weather: c_int32
    ground_condition: c_int32
    running_style: c_int32
    result_rank: c_int32
    frame_order: c_int32
    npc_count: c_int32


@register_runtime_validatable('Gallop::SingleRaceHistory')
class SingleRaceHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleRaceHistoryFields


# ---------------------------------------------------------------------------
# Gallop.IdleSingleModeRaceHistory
# ---------------------------------------------------------------------------

class IdleSingleModeRaceHistoryFields(CStructureDataclass):
    race_history: C_Ptr[SingleRaceHistoryObject]
    _ignored_1: C_UDeclPtr  # race_reward_info
    lose_tips_id: ObscuredInt


@register_runtime_validatable('Gallop::IdleSingleModeRaceHistory')
class IdleSingleModeRaceHistoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: IdleSingleModeRaceHistoryFields


# ---------------------------------------------------------------------------
# Gallop.ObscuredIdleSingleModeProgressLogInfo
# ---------------------------------------------------------------------------

class ObscuredIdleSingleModeProgressLogInfoFields(CStructureDataclass):
    charaEffectLogArray: GenericArrayPtr[C_Ptr[ObscuredCharaEffectLogObject]]
    supportCardGainInfoArray: GenericArrayPtr[C_Ptr[ObscuredIdleSingleModeSupportCardGainInfoObject]]
    eventGainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]
    successionGainInfo: C_Ptr[ObscuredIdleSingleModeGainInfoObject]
    successionFactorGainArray: GenericArrayPtr[C_Ptr[ObscuredIdleSingleModeSuccessionFactorGainInfoObject]]
    raceHistoryArray: GenericArrayPtr[C_Ptr[IdleSingleModeRaceHistoryObject]]
    gainSkillIdArray: GenericArrayPtr[ObscuredInt]
    totalSkillPoint: ObscuredInt


@register_runtime_validatable('Gallop::ObscuredIdleSingleModeProgressLogInfo')
class ObscuredIdleSingleModeProgressLogInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ObscuredIdleSingleModeProgressLogInfoFields


# ---------------------------------------------------------------------------
# Gallop.WorkIdleSingleMode
# ---------------------------------------------------------------------------

class WorkIdleSingleModeDataFields(CStructureDataclass):
    _ignored_1: ObscuredInt  # state
    charaInfo: C_Ptr[SingleModeCharaObject]
    startTime: c_int64
    endTime: c_int64
    _ignored_2: ObscuredInt  # singleModePlayingState
    progressLogInfo: C_Ptr[ObscuredIdleSingleModeProgressLogInfoObject]
    _ignored_3: C_UDeclPtr  # workCharaData is always null


@register_runtime_validatable('Gallop::WorkIdleSingleModeData')
class WorkIdleSingleModeDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkIdleSingleModeDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkDataManager object hierarchy
# ---------------------------------------------------------------------------

class WorkDataManagerFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # userData
    friendData: C_Ptr[WorkFriendDataObject]
    cardData: C_Ptr[WorkCardDataObject]
    supportCardData: C_Ptr[WorkSupportCardDataObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[4]]  # charaData … itemData
    trainedCharaData: C_Ptr[WorkTrainedCharaDataObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[9]]  # singleMode … announceData
    trophy: C_Ptr[WorkTrophyDataObject]
    _ignored_4: ArrayType[C_UDeclPtr, L[4]]
    teamStadiumData: C_Ptr[WorkTeamStadiumDataObject]
    _ignored_5: ArrayType[C_UDeclPtr, L[31]]  # directoryData … optionData
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


# ---------------------------------------------------------------------------
# Gallop.FactorInfo
# ---------------------------------------------------------------------------

class FactorInfoFields(CStructureDataclass):
    factor_id: C_Int[c_int32]
    level: C_Int[c_int32]


@register_runtime_validatable('Gallop::FactorInfo')
class FactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorInfoFields


# ---------------------------------------------------------------------------
# Gallop.FactorExtend
# ---------------------------------------------------------------------------

class FactorExtendFields(CStructureDataclass):
    position_id: Annotated[C_Int[c_int32], SuccessionCharaPosition]
    base_factor_id: C_Int[c_int32]
    factor_id: C_Int[c_int32]
    register_time: SystemStringObjectPtr


@register_runtime_validatable('Gallop::FactorExtend')
class FactorExtendObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorExtendFields


# ---------------------------------------------------------------------------
# Gallop.HorseData
# ---------------------------------------------------------------------------

class RaceParameterFields(CStructureDataclass):
    rawSpeed: C_Int[c_int32]
    rawStamina: C_Int[c_int32]
    rawPow: C_Int[c_int32]
    rawGuts: C_Int[c_int32]
    rawWiz: C_Int[c_int32]
    baseSpeed: C_Float[c_float]
    baseStamina: C_Float[c_float]
    basePow: C_Float[c_float]
    baseGuts: C_Float[c_float]
    baseWiz: C_Float[c_float]
    motivation: Annotated[C_Int[c_int32], RaceMotivation]
    motivationCoef: C_Float[c_float]


@register_runtime_validatable('Gallop::RaceParameter')
class RaceParameterObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceParameterFields


class HorseDataFields(CStructureDataclass):
    horseIndex: C_Int[c_int32]
    postNumber: C_Int[c_int32]
    charaId: C_Int[c_int32]
    charaName: SystemStringObjectPtr
    finishOrder: C_Int[c_int32]
    finishTimeRaw: C_Float[c_float]
    finishTimeScaled: C_Float[c_float]
    finishDiffTimeFromPrev: C_Float[c_float]
    raceParam: C_Ptr[RaceParameterObject]
    responseHorseData: C_Ptr[RaceHorseDataObject]
    popularity: C_Int[c_int32]
    popularityRankLeft: C_Int[c_int32]
    popularityRankCenter: C_Int[c_int32]
    popularityRankRight: C_Int[c_int32]
    gateInPopularity: C_Int[c_int32]
    rarity: Annotated[C_Int[c_int32], CardRarity]
    trainerName: SystemStringObjectPtr
    isGhost: C_Int[c_bool]
    isRunningStyleExInitialized: C_Int[c_bool]
    runningStyleEx: Annotated[C_Int[c_int32], RunningStyleEx]
    defeat: Annotated[C_Int[c_int32], DefeatType]
    raceDressId: C_Int[c_int32]
    raceDressIdWithOption: C_Int[c_int32]
    runningType: Annotated[C_Int[c_int32], RaceRunningType]
    activeProperDistance: Annotated[C_Int[c_int32], ProperGrade]
    activeProperGroundType: Annotated[C_Int[c_int32], ProperGrade]
    mobId: C_Int[c_int32]
    _ignored_1: C_UDeclPtr  # raceRecord
    finishOrderRawScore: C_Int[c_int32]
    trainedCharaData: C_Ptr[TrainedCharaDataObject]


@register_runtime_validatable('Gallop::HorseData')
class HorseDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: HorseDataFields


# ---------------------------------------------------------------------------
# Gallop.MasterRaceCourseSet.RaceCourseSet
# ---------------------------------------------------------------------------

class RaceCourseSetFields(CStructureDataclass):
    id: C_Int[c_int32]
    raceTrackId: C_Int[c_int32]
    distance: C_Int[c_int32]
    ground: C_Int[c_int32]
    inout: C_Int[c_int32]
    turn: C_Int[c_int32]
    fenceSet: C_Int[c_int32]
    floatLaneMax: C_Int[c_int32]
    courseSetStatusId: C_Int[c_int32]
    finishTimeMin: C_Int[c_int32]
    finishTimeMinRandomRange: C_Int[c_int32]
    finishTimeMax: C_Int[c_int32]
    finishTimeMaxRandomRange: C_Int[c_int32]


@register_runtime_validatable('Gallop::MasterRaceCourseSet.RaceCourseSet')
class RaceCourseSetObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceCourseSetFields


# ---------------------------------------------------------------------------
# Gallop.RaceInfo
# ---------------------------------------------------------------------------

class RaceInfoFields(CStructureDataclass):
    raceType: Annotated[C_Int[c_int32], RaceType]
    isExistPlayerRace: C_Int[c_bool]
    isExistGhostRace: C_Int[c_bool]
    isExistFollowRace: C_Int[c_bool]
    isMultiplePlayerRace: C_Int[c_bool]
    randomSeed: C_Int[c_int32]
    singleRaceProgramId: C_Int[c_int32]
    opponentEvaluate: C_Int[c_int32]
    selfEvaluate: C_Int[c_int32]
    supportCardScoreBonus: C_Int[c_int32]
    scoreCalcTeamId: C_Int[c_int32]
    raceNo: C_Int[c_int32]
    raceCourseSet: C_Ptr[RaceCourseSetObject]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # fenceSet, raceTrack
    goalGate: C_Int[c_int32]
    goalGateFlower: C_Int[c_int32]
    initialLaneType: Annotated[C_Int[c_int32], InitialLaneType]
    rotationCategory: Annotated[C_Int[c_int32], Rotation]
    resultBoardConditionType: Annotated[C_Int[c_int32], ResultBoardConditionType]
    courseSectionDistance: C_Float[c_float]
    courseDistanceType: Annotated[C_Int[c_int32], CourseDistanceType]
    courseFurlongNum: C_Int[c_int32]
    isHalfGate: C_Int[c_bool]
    isHorseNumVariationGate: C_Int[c_bool]
    turfVisionType: Annotated[C_Int[c_int32], TurfVisionType]
    groundCondition: Annotated[C_Int[c_int32], RaceGroundCondition]
    weather: Annotated[C_Int[c_int32], RaceWeather]
    season: Annotated[C_Int[c_int32], BgSeason]
    time: Annotated[C_Int[c_int32], RaceTime]
    baseSpeed: C_Float[c_float]
    borderTimeScaled: C_Float[c_float]
    challengeMatchDifficulty: Annotated[C_Int[c_int32], RaceDifficulty]
    numRaceHorses: C_Int[c_int32]
    postNumberMax: C_Int[c_int32]
    playerHorseIndex: C_Int[c_int32]
    overridePlayerHorseIndex: C_Int[c_int32]
    playerTeamMemberArray: GenericArrayPtr[C_Ptr[HorseDataObject]]
    playerTeamTopFinishOrderHorse: C_Ptr[HorseDataObject]
    isGateInPopularityInitialized: C_Int[c_bool]
    raceHorse: GenericArrayPtr[C_Ptr[HorseDataObject]]
    _ignored_2: ArrayType[C_UDeclPtr, L[3]]  # raceBibMaster, raceMaster, raceInstanceMaster
    simDataBase64: SystemStringObjectPtr
    _ignored_3: ArrayType[C_UDeclPtr, L[2]]  # simData, simReader
    episodeRaceReplayId: C_Int[c_int32]
    isNotSimulateExport: C_Int[c_bool]
    laneDistanceMax: C_Float[c_float]
    _ignored_4: ArrayType[C_UDeclPtr, L[3]]  # replayCheckInfo, replayCheckInfoDaily, replayCheckInfoLegend
    isDailyLegendRace: C_Int[c_bool]
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # replayCheckInfoChallengeMatch, raceRewardSingle
    resultHorseIndex: C_Int[c_int32]
    prevGradeType: Annotated[C_Int[c_int32], CharaGradeType]
    mainStoryRaceGimmickType: Annotated[C_Int[c_int32], MainStoryRaceGimmickType]
    isMainStoryRaceMatchGimmick: C_Int[c_bool]
    unlockFlags: C_Int[c_uint32]
    _ignored_6: C_UDeclPtr  # phaseCalculator
    horseIndexByFinishOrder: GenericArrayPtr[c_int32]
    horseIndexByPopularity: GenericArrayPtr[c_int32]


@register_runtime_validatable('Gallop::RaceInfo')
class RaceInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceInfoFields


# ---------------------------------------------------------------------------
# Gallop.RaceManager object hierarchy
# ---------------------------------------------------------------------------

class RaceManagerStaticFields(CStructureDataclass):
    raceInfo: C_Ptr[RaceInfoObject]


class RaceManagerFields(CStructureDataclass):
    pass  # stub - we don't need fields for now


@register_runtime_validatable('Gallop::RaceManager')
class RaceManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: RaceManagerFields


class RaceManagerSingletonStaticFields(CStructureDataclass):
    _isApplicationQuit: C_Int[c_bool]
    _instance: C_Ptr[RaceManagerObject]
    _parentObject: C_UDeclPtr


@register_runtime_validatable('Gallop::MonoSingleton`1<Gallop::RaceManager>')
class RaceManagerSingleton(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
