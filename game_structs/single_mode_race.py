from __future__ import annotations

from ctypes import c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericIntDictionaryEntry, GenericList
from game_structs.obscured import ObscuredInt
from game_structs.strings import SystemStringObjectPtr
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData.LotteryProgramData
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataLotteryProgramDataFields(CStructureDataclass):
    programId: ObscuredInt
    turn: ObscuredInt


@register_runtime_validatable('Gallop::WorkSingleModeRaceData.LotteryProgramData')
class WorkSingleModeRaceDataLotteryProgramDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeRaceDataLotteryProgramDataFields


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData.LotteryProgramDataDictionaryEntry
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataLotteryProgramDataDictionaryEntry(GenericIntDictionaryEntry):
    value: C_Ptr[GenericList[C_Ptr[WorkSingleModeRaceDataLotteryProgramDataObject]]]


# ---------------------------------------------------------------------------
# Gallop.WorkSingleModeRaceData
# ---------------------------------------------------------------------------

class WorkSingleModeRaceDataFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: character, cachePrograms
    lotteryProgramDataDict: C_Ptr[GenericDictionary[WorkSingleModeRaceDataLotteryProgramDataDictionaryEntry]]


@register_runtime_validatable('Gallop::WorkSingleModeRaceData')
class WorkSingleModeRaceDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkSingleModeRaceDataFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeReservedRace
# ---------------------------------------------------------------------------

class SingleModeReservedRaceFields(CStructureDataclass):
    year: C_Int[c_int32]
    program_id: C_Int[c_int32]


@register_runtime_validatable('Gallop::SingleModeReservedRace')
class SingleModeReservedRaceObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeReservedRaceFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeReservedRaceDeck
# ---------------------------------------------------------------------------

class SingleModeReservedRaceDeckFields(CStructureDataclass):
    deck_num: C_Int[c_int32]
    deck_name: SystemStringObjectPtr
    race_array: GenericArrayPtr[C_Ptr[SingleModeReservedRaceObject]]


@register_runtime_validatable('Gallop::SingleModeReservedRaceDeck')
class SingleModeReservedRaceDeckObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeReservedRaceDeckFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserveDeckEntity
# ---------------------------------------------------------------------------

class SingleModeRaceReserveDeckEntityFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # omitted: reserveDict … programIdGetter
    deckInfo: C_Ptr[SingleModeReservedRaceDeckObject]
    _ignored_2: c_int32  # omitted: deckIndex
    _ignored_3: C_UDeclPtr  # omitted: deckName
    _ignored_4: c_int32  # omitted: reservedRaceCount


@register_runtime_validatable('Gallop::SingleModeRaceReserveDeckEntity')
class SingleModeRaceReserveDeckEntityObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveDeckEntityFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserveRepository
# ---------------------------------------------------------------------------

class SingleModeRaceReserveRepositoryFields(CStructureDataclass):
    entities: GenericArrayPtr[C_Ptr[SingleModeRaceReserveDeckEntityObject]]
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # omitted: conditionalProgramIdGetter, onUpdateEvent


@register_runtime_validatable('Gallop::SingleModeRaceReserveRepository')
class SingleModeRaceReserveRepositoryObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveRepositoryFields


# ---------------------------------------------------------------------------
# Gallop.SingleModeRaceReserve.Context
# ---------------------------------------------------------------------------

class SingleModeRaceReserveContextFields(CStructureDataclass):
    _ignored_1: C_UDeclPtr  # omitted: entryViewModel
    reserveRepository: C_Ptr[SingleModeRaceReserveRepositoryObject]
    _ignored_2: ArrayType[C_UDeclPtr, L[6]]  # omitted: turnRepository … temp


@register_runtime_validatable('Gallop.SingleModeRaceReserve::Context')
class SingleModeRaceReserveContextObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SingleModeRaceReserveContextFields
