#!/usr/bin/env python3
"""
Game-specific struct definitions and ObscuredType decoders.

Contains:
  - ObscuredType value-type structs
  - WorkDataManager object hierarchy (partial — through SupportCardData)
  - Dictionary<int, SupportCardData> entry layout
"""
from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64, c_uint16, c_uint64, c_uint8
from typing import Iterator, Literal as L, cast as type_cast

from ctypes_utils import (ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr, C_VoidPtr, RuntimeGenericMixin,
                          Span, StructOrSimple)
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


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

    def as_str(self) -> str:
        """Decode managed ``System.String`` contents into a Python ``str``."""

        if not self.inner_ptr.contents:
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


class GenericListFields[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    items: GenericArrayPtr[CDT]
    size: C_Int[c_int32]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # _version, _syncRoot


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
    _ignored_2: ArrayType[c_int32, L[3]]  # freeList, freeCount, version
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
        if valid < self.fields.count:
            print(f"Warning: iterated over GenericDictionary with {self.fields.count} entries, "
                  f"but only {valid} have valid hash codes")


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
    _ignored_4: ArrayType[C_UDeclPtr, L[2]]  # uniqueSkill, acquirableSkillArray


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
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData
# ---------------------------------------------------------------------------


class FactorDataFields(CStructureDataclass):
    factorId: ObscuredInt
    factorLv: ObscuredInt


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
    positionId: ObscuredInt
    cardId: ObscuredInt
    rarity: ObscuredInt
    level: ObscuredInt
    rank: ObscuredInt
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
# Gallop.WorkSkillData.AcquiredSkill
# ---------------------------------------------------------------------------


class AcquiredSkillFields(CStructureDataclass):
    masterId: ObscuredInt
    level: ObscuredInt
    _ignored_1: C_UDeclPtr  # master


@register_runtime_validatable('Gallop::WorkSkillData.AcquiredSkill')
class AcquiredSkillObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: AcquiredSkillFields


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
    weather: ObscuredInt
    groundCondition: ObscuredInt
    runningStyle: ObscuredInt
    resultRank: ObscuredInt
    _ignored_3: ObscuredInt  # scenarioId


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
    useType: C_Int[c_int32]
    cardId: ObscuredInt
    nickNameId: ObscuredInt
    nickNameIdArray: GenericArrayPtr[ObscuredInt]
    stamina: ObscuredInt
    speed: ObscuredInt
    power: ObscuredInt
    guts: ObscuredInt
    wiz: ObscuredInt
    fans: ObscuredInt
    rank: ObscuredInt
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
    createTime: C_UDeclPtr  # C_Ptr[ObscuredString]
    scenarioId: ObscuredInt
    talentLevel: ObscuredInt
    charaGrade: ObscuredInt
    rarity: ObscuredInt
    isLock: ObscuredBool
    favoriteData: C_Ptr[FavoriteDataObject]
    cachedCreateTimeTimeStamp: ObscuredLong
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # sortedFactorList … sortedFactorProfileCardList / masterDataPtrs
    successionCharaList: C_Ptr[GenericList[C_Ptr[SuccessionCharaDataObject]]]
    successionHistoryList: C_Ptr[GenericList[C_Ptr[SuccessionHistoryObject]]]
    acquiredSkillArray: GenericArrayPtr[C_Ptr[AcquiredSkillObject]]
    supportCardArray: GenericArrayPtr[C_Ptr[TrainedCharaSupportCardDataObject]]
    singleModeRaceResultArray: GenericArrayPtr[C_Ptr[RaceHistoryInfoObject]]
    _ignored_2: C_UDeclPtr  # winSaddleArray / masterDataPtr
    winSaddleIdArray: GenericArrayPtr[ObscuredInt]
    cacheCharaId: ObscuredInt
    _ignored_3: ArrayType[C_UDeclPtr, L[3]]  # masterCardData, masterCharaData, masterCardRarityData / masterDataPtrs
    singleTotalRaceNum: C_Int[c_int32]
    singleWinNum: ObscuredInt
    _ignored_4: C_UDeclPtr  # trainedCharaDataAccessor


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
# Gallop.WorkDataManager object hierarchy
# ---------------------------------------------------------------------------


class WorkDataManagerFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # UserData, FriendData
    cardData: C_Ptr[WorkCardDataObject]
    supportCardData: C_Ptr[WorkSupportCardDataObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[4]]  # CharaData … WorkItemData
    trainedCharaData: C_Ptr[WorkTrainedCharaDataObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[39]]  # WorkSingleModeData … TeamBuildingData


@register_runtime_validatable('Gallop::WorkDataManager')
class WorkDataManagerObject(CStructureDataclass):
    """Root game singleton payload used by all extractors in ``main.py``."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkDataManagerFields


class WorkDataManagerSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[WorkDataManagerObject]


@register_runtime_validatable('Gallop::Singleton`1<Gallop::WorkDataManager>')
class WorkDataManagerSingleton(CStructureDataclass):
    """Marker wrapper for the singleton generic class used to resolve static fields."""

    _il2cpp_obj: RuntimeIl2CppObject
    # we don't actually retrieve the object of this type at any point - it lives in app memory
    # we only retrieve the inner klass from il2cpp owned memory
