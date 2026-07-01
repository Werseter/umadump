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
from logger import logger
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
            logger.warning("Iterated over GenericDictionary with %d entries, but only %d have valid hash codes",
                           self.fields.count, valid)

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
# Gallop.WorkTrainedCharaData.TrainedCharaData.SuccessionCharaData.FactorData
# ---------------------------------------------------------------------------

class FactorDataFields(CStructureDataclass):
    factorLv: ObscuredInt
    factorId: ObscuredInt
    _ignored_1: ObscuredInt  # _baseFactorId
    _ignored_2: C_UDeclPtr  # _upgradeHistoryList


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
    isSuccessionHistoryInitialized: C_Int[c_bool]
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
# Gallop.WorkFriendData.FriendData
# ---------------------------------------------------------------------------

class HonorDataFields(CStructureDataclass):
    honor_id: C_Int[c_int32]
    step: C_Int[c_int32]
    create_time: SystemStringObjectPtr


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

    @property
    def honorId(self) -> C_Int[c_int32]:
        if not self.honorData:
            return C_Int[c_int32](0)
        return self.honorData.contents.fields.honor_id


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
    _ignored_3: ArrayType[C_Int[c_int32], L[2]]  # supportCartBonus, simulateRaceRound


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
    _ignored_3: C_UDeclPtr  # teamEvaluationUpdateRankRewardArray
    _ignored_4: c_bool  # needNotifyBadge
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # stadiumRaceCharaIdArray, prevMemberList


@register_runtime_validatable('Gallop::WorkTeamStadiumData')
class WorkTeamStadiumDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkTeamStadiumDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkDataManager object hierarchy
# ---------------------------------------------------------------------------

class WorkDataManagerFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # UserData
    friendData: C_Ptr[WorkFriendDataObject]
    cardData: C_Ptr[WorkCardDataObject]
    supportCardData: C_Ptr[WorkSupportCardDataObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[4]]  # CharaData … CircleData
    trainedCharaData: C_Ptr[WorkTrainedCharaDataObject]
    _ignored_3: ArrayType[C_UDeclPtr, L[9]]  # WorkSingleModeData … WorkAnnounceData
    trophy: C_Ptr[WorkTrophyDataObject]
    _ignored_4: ArrayType[C_UDeclPtr, L[4]]
    teamStadiumData: C_Ptr[WorkTeamStadiumDataObject]
    _ignored_5: ArrayType[C_UDeclPtr, L[24]]  # WorkDirectoryData … TeamBuildingData


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
# Gallop.ChampionsRoomInfo
# ---------------------------------------------------------------------------

class ChampionsRoomInfoFields(CStructureDataclass):
    room_id: C_Int[c_int64]
    user_entry_num: C_Int[c_int32]
    race_start_time: SystemStringObjectPtr
    race_instance_id: C_Int[c_int32]
    season: C_Int[c_int32]
    weather: C_Int[c_int32]
    ground_condition: C_Int[c_int32]
    random_seed: C_Int[c_int32]
    race_scenario: SystemStringObjectPtr


@register_runtime_validatable('Gallop::ChampionsRoomInfo')
class ChampionsRoomInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ChampionsRoomInfoFields


# ---------------------------------------------------------------------------
# Gallop.ChampionsUserChara
# ---------------------------------------------------------------------------

class ChampionsUserCharaFields(CStructureDataclass):
    chara_id: C_Int[c_int32]
    race_cloth_id: C_Int[c_int32]
    nick_name_id: C_Int[c_int32]
    team_member_id: C_Int[c_int32]


@register_runtime_validatable('Gallop::ChampionsUserChara')
class ChampionsUserCharaObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ChampionsUserCharaFields


# ---------------------------------------------------------------------------
# Gallop.ChampionsRoomUser
# ---------------------------------------------------------------------------

class ChampionsRoomUserFields(CStructureDataclass):
    room_id: C_Int[c_int64]
    viewer_id: C_Int[c_int64]
    name: SystemStringObjectPtr
    honor_data: C_Ptr[HonorDataObject]
    team_id: C_Int[c_int32]
    entry_chara_array: GenericArrayPtr[C_Ptr[ChampionsUserCharaObject]]

    @property
    def honor_id(self) -> C_Int[c_int32]:
        if not self.honor_data:
            return C_Int[c_int32](0)
        return self.honor_data.contents.fields.honor_id


@register_runtime_validatable('Gallop::ChampionsRoomUser')
class ChampionsRoomUserObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ChampionsRoomUserFields


# ---------------------------------------------------------------------------
# Gallop.TrainedCharaSupportCardList
# ---------------------------------------------------------------------------

class TrainedCharaSupportCardListFields(CStructureDataclass):
    position: C_Int[c_int32]
    support_card_id: C_Int[c_int32]
    exp: C_Int[c_int32]
    limit_break_count: C_Int[c_int32]


@register_runtime_validatable('Gallop::TrainedCharaSupportCardList')
class TrainedCharaSupportCardListObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaSupportCardListFields


# ---------------------------------------------------------------------------
# Gallop.TrainedCharaRaceResult
# ---------------------------------------------------------------------------

class TrainedCharaRaceResultFields(CStructureDataclass):
    turn: C_Int[c_int32]
    program_id: C_Int[c_int32]
    weather: C_Int[c_int32]
    ground_condition: C_Int[c_int32]
    running_style: C_Int[c_int32]
    result_rank: C_Int[c_int32]


@register_runtime_validatable('Gallop::TrainedCharaRaceResult')
class TrainedCharaRaceResultObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaRaceResultFields


# ---------------------------------------------------------------------------
# Gallop.SuccessionChara
# ---------------------------------------------------------------------------

class FactorInfoFields(CStructureDataclass):
    factor_id: C_Int[c_int32]
    level: C_Int[c_int32]


class FactorInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: FactorInfoFields


class SuccessionCharaFields(CStructureDataclass):
    position_id: C_Int[c_int32]
    card_id: C_Int[c_int32]
    rank: C_Int[c_int32]
    rarity: C_Int[c_int32]
    talent_level: C_Int[c_int32]
    factor_info_array: GenericArrayPtr[C_Ptr[FactorInfoObject]]
    win_saddle_id_array: GenericArrayPtr[c_int32]
    owner_viewer_id: C_Int[c_int64]
    _ignored_2: C_UDeclPtr  # user_info_summary

    @property
    def factor_id_array(self) -> list[C_Int[c_int32]]:
        if not self.factor_info_array.inner_ptr:
            return []
        return [factor.contents.fields.factor_id for factor in self.factor_info_array]


@register_runtime_validatable('Gallop::SuccessionChara')
class SuccessionCharaObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SuccessionCharaFields


# ---------------------------------------------------------------------------
# Gallop.TrainedChara
# ---------------------------------------------------------------------------

class TrainedCharaFields(CStructureDataclass):
    viewer_id: C_Int[c_int64]
    trained_chara_id: C_Int[c_int32]
    owner_viewer_id: C_Int[c_int64]
    owner_trained_chara_id: C_Int[c_int32]
    use_type: C_Int[c_int32]
    card_id: C_Int[c_int32]
    name: SystemStringObjectPtr
    stamina: C_Int[c_int32]
    speed: C_Int[c_int32]
    power: C_Int[c_int32]
    guts: C_Int[c_int32]
    wiz: C_Int[c_int32]
    fans: C_Int[c_int32]
    rank_score: C_Int[c_int32]
    rank: C_Int[c_int32]
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
    succession_num: C_Int[c_int32]
    is_locked: C_Int[c_int32]
    rarity: C_Int[c_int32]
    talent_level: C_Int[c_int32]
    chara_grade: C_Int[c_int32]
    running_style: C_Int[c_int32]
    nickname_id: C_Int[c_int32]
    wins: C_Int[c_int32]
    skill_array: GenericArrayPtr[C_Ptr[SkillDataObject]]
    support_card_list: GenericArrayPtr[C_Ptr[TrainedCharaSupportCardListObject]]
    is_saved: C_Int[c_int32]
    race_result_list: GenericArrayPtr[C_Ptr[TrainedCharaRaceResultObject]]
    win_saddle_id_array: GenericArrayPtr[c_int32]
    nickname_id_array: GenericArrayPtr[c_int32]
    factor_info_array: GenericArrayPtr[C_Ptr[FactorInfoObject]]
    factor_extend_array: C_UDeclPtr
    succession_chara_array: GenericArrayPtr[C_Ptr[SuccessionCharaObject]]
    scenario_id: C_Int[c_int32]
    create_time: SystemStringObjectPtr

    @property
    def factor_id_array(self) -> list[C_Int[c_int32]]:
        if not self.factor_info_array.inner_ptr:
            return []
        return [factor.contents.fields.factor_id for factor in self.factor_info_array]


@register_runtime_validatable('Gallop::TrainedChara')
class TrainedCharaObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TrainedCharaFields


# ---------------------------------------------------------------------------
# Gallop.TempData.ChampionsRaceInfo
# ---------------------------------------------------------------------------

class ChampionsRaceInfoFields(CStructureDataclass):
    isSet: C_Int[c_bool]
    raceNum: C_Int[c_int32]
    roomInfo: C_Ptr[ChampionsRoomInfoObject]
    roomUserArray: GenericArrayPtr[C_Ptr[ChampionsRoomUserObject]]
    raceHorseDataArray: GenericArrayPtr[C_Ptr[RaceHorseDataObject]]
    trainedCharaArray: GenericArrayPtr[C_Ptr[TrainedCharaObject]]


@register_runtime_validatable('Gallop::TempData.ChampionsRaceInfo')
class ChampionsRaceInfoObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ChampionsRaceInfoFields


# ---------------------------------------------------------------------------
# Gallop.TempData.ChampionsTempData
# ---------------------------------------------------------------------------

class ChampionsTempDataFields(CStructureDataclass):
    isReplay: C_Int[c_bool]
    raceInfo: C_Ptr[ChampionsRaceInfoObject]
    _ignored_1: ArrayType[c_int32, L[2]]  # raceTitleResourceId, raceSubTitleResourceId
    _ignored_2: c_bool  # isOpenScheduleChangeErrorDialog


@register_runtime_validatable('Gallop::TempData.ChampionsTempData')
class ChampionsTempDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: ChampionsTempDataFields


# ---------------------------------------------------------------------------
# Gallop.TempData object hierarchy
# ---------------------------------------------------------------------------

class TempDataFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # championsClearMissionIdList
    championsData: C_Ptr[ChampionsTempDataObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[1]]  # TODO: precise mapping


@register_runtime_validatable('Gallop::TempData')
class TempDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: TempDataFields


class TempDataSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[TempDataObject]


@register_runtime_validatable('Gallop::Singleton`1<Gallop::TempData>')
class TempDataSingleton(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
