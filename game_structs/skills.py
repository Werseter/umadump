from __future__ import annotations

from ctypes import c_int32

from ctypes_utils import CStructureDataclass, C_Int, C_UDeclPtr
from game_structs.obscured import ObscuredInt
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import register_runtime_validatable


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
# Gallop.SkillTips
# ---------------------------------------------------------------------------

class SkillTipsFields(CStructureDataclass):
    group_id: C_Int[c_int32]
    rarity: C_Int[c_int32]
    level: C_Int[c_int32]


@register_runtime_validatable('Gallop::SkillTips')
class SkillTipsObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SkillTipsFields
