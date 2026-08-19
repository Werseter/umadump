from __future__ import annotations

from ctypes import c_int32, c_int64

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr
from game_structs.collections import GenericList
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


# ---------------------------------------------------------------------------
# Gallop.WorkHonorData.Honor
# ---------------------------------------------------------------------------

class WorkHonorDataHonorFields(CStructureDataclass):
    id: C_Int[c_int32]
    _ignored_1: c_int32  # step
    createTime: C_Int[c_int64]


@register_runtime_validatable('Gallop::WorkHonorData.Honor')
class WorkHonorDataHonorObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkHonorDataHonorFields


# ---------------------------------------------------------------------------
# Gallop.WorkHonorData
# ---------------------------------------------------------------------------

class WorkHonorDataFields(CStructureDataclass):
    honorList: C_Ptr[GenericList[C_Ptr[WorkHonorDataHonorObject]]]
    _ignored_1: C_UDeclPtr  # honorProgressList
    lastCheckTime: C_Int[c_int64]


@register_runtime_validatable('Gallop::WorkHonorData')
class WorkHonorDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: WorkHonorDataFields
