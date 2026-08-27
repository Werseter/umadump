"""Master-data ABI declarations."""
from __future__ import annotations

from ctypes import c_int32
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Int
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


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
# Gallop.MasterSingleModeWinsSaddle.SingleModeWinsSaddle
# ---------------------------------------------------------------------------

class MasterSingleModeWinsSaddleSingleModeWinsSaddleFields(CStructureDataclass):
    id: C_Int[c_int32]
    _ignored_1: ArrayType[c_int32, L[12]]  # omitted: priority … raceInstanceId8


@register_runtime_validatable('Gallop::MasterSingleModeWinsSaddle.SingleModeWinsSaddle')
class MasterSingleModeWinsSaddleSingleModeWinsSaddleObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: MasterSingleModeWinsSaddleSingleModeWinsSaddleFields
