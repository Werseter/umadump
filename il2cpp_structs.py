#!/usr/bin/env python3
"""
Il2Cpp struct definitions and global-metadata.dat parser.

Contains:
  - CStructureDataclass metaclass infrastructure for proprietary type-hinted ctypes usage (ArrayType, CDataclassMeta, …)
  - Minimal required set of Il2Cpp metadata and runtime ctypes struct definitions
"""
from __future__ import annotations

from ctypes import c_int32, c_uint16, c_uint32, c_uint64, c_uint8
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_CharPtr, C_Int, C_Ptr, C_UDeclPtr, C_VoidPtr


class HasTokenMixin:
    token: int

    def get_token_type(self) -> int:
        return self.token & 0xFF000000

    def get_token_row_id(self) -> int:
        return self.token & 0x00FFFFFF


# ---------------------------------------------------------------------------
# Il2Cpp metadata structs (global-metadata.dat layout, v31)
# ---------------------------------------------------------------------------

# @formatter:off
class Il2CppGlobalMetadataHeader(CStructureDataclass):
    sanity: C_Int[c_uint32]                                    # [0]
    version: C_Int[c_int32]                                    # [1]
    _ignored_1: ArrayType[c_int32, L[4]]                       # [2–5]  stringLiteralOffset … stringLiteralDataSize
    stringOffset: C_Int[c_int32]                               # [6]
    stringSize: C_Int[c_int32]                                 # [7]
    _ignored_2: ArrayType[c_int32, L[4]]                       # [8-11] events, properties
    methodsOffset: C_Int[c_int32]                              # [12]
    methodsSize: C_Int[c_int32]                                # [13]
    _ignored_3: ArrayType[c_int32, L[2]]                       # [14-15] parameterDefaultValuesOffset/Size
    fieldDefaultValuesOffset: C_Int[c_int32]                   # [16]
    fieldDefaultValuesSize: C_Int[c_int32]                     # [17]
    fieldAndParameterDefaultValueDataOffset: C_Int[c_int32]    # [18]
    fieldAndParameterDefaultValueDataSize: C_Int[c_int32]      # [19]
    _ignored_4: ArrayType[c_int32, L[4]]                       # [20-23] fieldMarshaledSizes/parameters
    fieldsOffset: C_Int[c_int32]                               # [24]
    fieldsSize: C_Int[c_int32]                                 # [25]
    _ignored_5: ArrayType[c_int32, L[14]]                      # [26-39] genericParameters … interfaceOffsets
    typeDefinitionsOffset: C_Int[c_int32]                      # [40]
    typeDefinitionsSize: C_Int[c_int32]                        # [41]
    imagesOffset: C_Int[c_int32]                               # [42]
    imagesSize: C_Int[c_int32]                                 # [43]
    _ignored_6: ArrayType[c_int32, L[13]]                      # [44-56] assemblies … unresolvedRangesOffset
    unresolvedIndirectCallParameterRangesSize: C_Int[c_int32]  # [57]
    _ignored_7: ArrayType[c_int32, L[6]]                       # [58–63] windowsRuntime … exportedTypeDefinitionsSize
# @formatter:on


class Il2CppMethodDefinition(CStructureDataclass, HasTokenMixin):
    nameIndex: C_Int[c_int32]
    declaringType: C_Int[c_int32]
    returnType: C_Int[c_int32]
    _ignored_1: c_uint32  # returnParameterToken
    _ignored_2: ArrayType[c_int32, L[2]]  # parameterStart, genericContainerIndex
    token: C_Int[c_uint32]
    _ignored_3: ArrayType[c_uint16, L[3]]  # flags, iflags, slot
    parameterCount: C_Int[c_uint16]


class Il2CppFieldDefinition(CStructureDataclass):
    nameIndex: C_Int[c_int32]
    typeIndex: C_Int[c_int32]
    _ignored_1: c_uint32  # token


class Il2CppFieldDefaultValue(CStructureDataclass):
    fieldIndex: C_Int[c_int32]
    typeIndex: C_Int[c_int32]
    dataIndex: C_Int[c_int32]


class Il2CppImageDefinition(CStructureDataclass, HasTokenMixin):
    nameIndex: C_Int[c_int32]
    _ignored_1: c_int32  # assemblyIndex
    typeStart: C_Int[c_int32]
    typeCount: C_Int[c_uint32]
    _ignored_2: ArrayType[c_int32, L[3]]  # exportedTypeStart, exportedTypeCount, entryPointIndex
    token: C_Int[c_uint32]
    _ignored_3: ArrayType[c_uint32, L[2]]  # customAttributeStart, customAttributeCount


class Il2CppTypeDefinition(CStructureDataclass, HasTokenMixin):
    nameIndex: C_Int[c_int32]
    namespaceIndex: C_Int[c_int32]
    byvalTypeIndex: C_Int[c_int32]
    declaringTypeIndex: C_Int[c_int32]
    parentIndex: C_Int[c_int32]
    elementTypeIndex: C_Int[c_int32]
    _ignored_1: c_int32  # genericContainerIndex
    _ignored_2: c_uint32  # flags
    fieldStart: C_Int[c_int32]
    methodStart: C_Int[c_int32]
    _ignored_3: ArrayType[c_int32, L[6]]  # eventStart … interfaceOffsetsStart
    method_count: C_Int[c_uint16]
    _ignored_4: c_uint16  # property_count
    field_count: C_Int[c_uint16]
    _ignored_5: ArrayType[c_uint16, L[5]]  # event_count … interface_offsets_count
    bitfield: C_Int[c_uint32]
    token: C_Int[c_uint32]


class Il2CppMetadataRange(CStructureDataclass):
    _ignored_1: ArrayType[c_uint32, L[2]]  # start, length


# ---------------------------------------------------------------------------
# Runtime Il2Cpp structs (in-process layout, x64)
# ---------------------------------------------------------------------------

class RuntimeIl2CppType(CStructureDataclass):
    data: C_VoidPtr
    bits: C_Int[c_uint32]

    def get_attrs_bits(self) -> int:
        return self.bits & 0xFFFF

    def get_type_bits(self) -> int:
        return (self.bits >> 16) & 0xFF


class RuntimeIl2CppGenericInst(CStructureDataclass):
    type_argc: C_Int[c_uint32]
    type_argv: C_Ptr[C_Ptr[RuntimeIl2CppType]]


class RuntimeIl2CppGenericContext(CStructureDataclass):
    class_inst: C_Ptr[RuntimeIl2CppGenericInst]
    _ignored_1: C_UDeclPtr  # method_inst


class FieldInfo(CStructureDataclass):
    name: C_CharPtr
    type: C_Ptr[RuntimeIl2CppType]
    _ignored_1: C_Ptr['RuntimeIl2CppClass']  # parent
    offset: C_Int[c_int32]
    _ignored_2: c_uint32  # token


class VirtualInvokeData(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # methodPtr, method


class RuntimeIl2CppClass(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[2]]  # image, gc_desc
    name: C_CharPtr
    namespaze: C_CharPtr
    _ignored_2: ArrayType[RuntimeIl2CppType, L[2]]  # byval_arg, this_arg  (each 16 bytes)
    _ignored_3: ArrayType[C_UDeclPtr, L[3]]  # element_class, castClass, declaringType
    _parent: C_VoidPtr
    _ignored_4: C_UDeclPtr  # generic_class
    typeMetadataHandle: C_Ptr[Il2CppTypeDefinition]
    _ignored_5: ArrayType[C_UDeclPtr, L[2]]  # interopData, klass
    fields: C_Ptr[FieldInfo]
    _ignored_6: ArrayType[C_UDeclPtr, L[6]]  # events … interfaceOffsets
    static_fields: C_VoidPtr
    _ignored_7: ArrayType[C_UDeclPtr, L[4]]  # rgctx_data … initializationExceptionGCHandle
    _ignored_8: ArrayType[c_uint32, L[2]]  # cctor_started, cctor_finished_or_no_cctor
    _ignored_9: c_uint64  # cctor_thread
    _ignored_10: C_UDeclPtr  # genericContainerHandle
    _ignored_11: ArrayType[c_uint32, L[4]]  # instance_size … element_size
    _ignored_12: c_int32  # native_size
    _ignored_13: ArrayType[c_uint32, L[2]]  # static_fields_size, thread_static_fields_size
    _ignored_14: c_int32  # thread_static_fields_offset
    _ignored_15: ArrayType[c_uint32, L[2]]  # flags, token
    _ignored_16: ArrayType[c_uint16, L[2]]  # method_count, property_count
    field_count: C_Int[c_uint16]
    _ignored_17: ArrayType[c_uint16, L[5]]  # event_count … interface_offsets_count
    _ignored_18: ArrayType[c_uint8, L[7]]  # typeHierarchyDepth … bitflags2
    _ignored_19: ArrayType[VirtualInvokeData, L[0]]  # vtable (flexible array member)

    @property
    def parent(self) -> C_Ptr[RuntimeIl2CppClass]:
        return C_Ptr[RuntimeIl2CppClass](int(self._parent))

    def static_fields_as[TStaticFields](self, static_fields_type: type[TStaticFields]) \
            -> C_Ptr[TStaticFields]:  # type: ignore[type-var]
        # noinspection PyTypeHints
        return C_Ptr[static_fields_type](int(self.static_fields))  # type: ignore[valid-type]


class RuntimeIl2CppGenericClass(CStructureDataclass):
    type: C_Ptr[RuntimeIl2CppType]
    context: RuntimeIl2CppGenericContext
    cached_class: C_Ptr[RuntimeIl2CppClass]


class RuntimeIl2CppCodeGenModule(CStructureDataclass):
    moduleName: C_CharPtr
    methodPointerCount: C_Int[c_uint32]
    methodPointers: C_Ptr[C_UDeclPtr]
    _ignored_1: c_uint32  # adjustorThunkCount
    _ignored_2: ArrayType[C_UDeclPtr, L[2]]  # adjustorThunks, invokerIndices
    _ignored_3: c_uint32  # reversePInvokeWrapperCount
    _ignored_4: C_UDeclPtr  # reversePInvokeWrapperIndices
    _ignored_5: c_uint32  # rgctxRangesCount
    _ignored_6: C_UDeclPtr  # rgctxRanges
    _ignored_7: c_uint32  # rgctxsCount
    _ignored_8: C_UDeclPtr  # rgctxs
    _ignored_9: ArrayType[C_UDeclPtr, L[5]]  # debuggerMetadata … codeRegistaration


class RuntimeIl2CppCodeRegistration(CStructureDataclass):
    _ignored_1: c_uint32  # reversePInvokeWrapperCount
    _ignored_2: C_UDeclPtr  # reversePInvokeWrappers
    _ignored_3: c_uint32  # genericMethodPointersCount
    _ignored_4: ArrayType[C_UDeclPtr, L[2]]  # genericMethodPointers, genericAdjustorThunks
    _ignored_5: c_uint32  # invokerPointersCount
    _ignored_6: C_UDeclPtr  # invokerPointers
    unresolvedIndirectCallCount: C_Int[c_uint32]
    _ignored_7: ArrayType[C_UDeclPtr, L[3]]  # unresolvedVirtual/Instance/StaticCallPointers
    _ignored_8: c_uint32  # interopDataCount
    _ignored_9: C_UDeclPtr  # interopData
    _ignored_10: c_uint32  # windowsRuntimeFactoryCount
    _ignored_11: C_UDeclPtr  # windowsRuntimeFactoryTable
    codeGenModulesCount: C_Int[c_uint32]
    codeGenModules: C_Ptr[C_Ptr[RuntimeIl2CppCodeGenModule]]


class RuntimeIl2CppMetadataRegistration(CStructureDataclass):
    genericClassesCount: C_Int[c_int32]
    genericClasses: C_Ptr[C_Ptr[RuntimeIl2CppGenericClass]]
    _ignored_1: c_int32  # genericInstsCount
    _ignored_2: C_UDeclPtr  # genericInsts
    _ignored_3: c_int32  # genericMethodTableCount
    _ignored_4: C_UDeclPtr  # genericMethodTable
    typesCount: C_Int[c_int32]
    types: C_Ptr[C_Ptr[RuntimeIl2CppType]]
    _ignored_5: c_int32  # methodSpecsCount
    _ignored_6: C_UDeclPtr  # methodSpecs
    fieldOffsetsCount: C_Int[c_int32]  # fieldOffsetsCount
    fieldOffsets: C_Ptr[C_Ptr[c_int32]]
    _ignored_7: c_int32  # typeDefinitionsSizesCount
    _ignored_8: C_UDeclPtr  # typeDefinitionsSizes
    _ignored_9: c_uint64  # metadataUsagesCount
    _ignored_10: C_UDeclPtr  # metadataUsages


class RuntimeIl2CppObject(CStructureDataclass):
    klass: C_Ptr[RuntimeIl2CppClass]
    monitor: C_UDeclPtr  # MonitorData
