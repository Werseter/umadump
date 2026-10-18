"""Rooted scene/dialog access and the small native Unity component bridge."""
from __future__ import annotations

from ctypes import c_bool, c_float, c_int32, c_uint64
from typing import Literal as L

from ctypes_utils import ArrayType, CStructureDataclass, C_Bool, C_Int, C_Ptr, C_UDeclPtr, Span
from game_structs.collections import GenericList
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import TransientContainerStateError, register_runtime_validatable


# ---------------------------------------------------------------------------
# NativeUnityGameObject
# ---------------------------------------------------------------------------

class NativeUnityComponent(CStructureDataclass):
    """UnityPlayer native Object prefix followed by Component's owning GameObject."""
    _ignored_1: ArrayType[C_UDeclPtr, L[5]]  # vtable … allocator/header state
    managed: C_Ptr[RuntimeIl2CppObject]
    owner: C_UDeclPtr


class NativeUnityComponentEntry(CStructureDataclass):
    _ignored_1: c_uint64  # native type/tag
    component: C_Ptr[NativeUnityComponent]


class NativeUnityGameObject(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[5]]  # native Object header
    managed: C_Ptr[RuntimeIl2CppObject]
    entries: C_Ptr[NativeUnityComponentEntry]
    _ignored_2: c_uint64  # vector allocator label
    count: C_Int[c_uint64]
    capacity: C_Int[c_uint64]

    def components(self) -> Span[NativeUnityComponentEntry]:
        if self.count > self.capacity or (self.count and not self.entries):
            raise TransientContainerStateError('Unity components', self.count, self.entries.address, self.capacity)
        return self.entries.as_span(self.count)


# ---------------------------------------------------------------------------
# UnityEngine.GameObject
# ---------------------------------------------------------------------------

class UnityGameObjectFields(CStructureDataclass):
    m_CachedPtr: C_Ptr[NativeUnityGameObject]


@register_runtime_validatable('UnityEngine::GameObject')
class UnityGameObjectObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: UnityGameObjectFields


# ---------------------------------------------------------------------------
# Gallop.DialogCommonBaseData
# ---------------------------------------------------------------------------

class DialogCommonBaseDataFields(CStructureDataclass):
    _ignored_1: c_int32  # omitted: formType
    _ignored_2: C_UDeclPtr  # omitted: title
    contentsObject: C_Ptr[UnityGameObjectObject]
    _ignored_3: C_UDeclPtr  # omitted: dialog


@register_runtime_validatable('Gallop::DialogCommonBaseData')
class DialogCommonBaseDataObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: DialogCommonBaseDataFields


# ---------------------------------------------------------------------------
# Gallop.DialogCommonBase
# ---------------------------------------------------------------------------

class DialogCommonBaseFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[5]]  # omitted: m_CachedPtr … contentsRoot
    data: C_Ptr[DialogCommonBaseDataObject]


@register_runtime_validatable('Gallop::DialogCommonBase')
class DialogCommonBaseObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: DialogCommonBaseFields


# ---------------------------------------------------------------------------
# Gallop.DialogManager object hierarchy
# ---------------------------------------------------------------------------

class NullableVector3Storage(CStructureDataclass):
    has_value: C_Bool[c_bool]
    value: ArrayType[c_float, L[3]]


class DialogManagerFields(CStructureDataclass):
    _ignored_1: c_int32  # omitted: showErrorDialogCount
    _ignored_2: NullableVector3Storage  # omitted: prevClickedButtonPosition
    _ignored_3: ArrayType[c_bool, L[2]]  # omitted: isShowLongTapInfoPop, autoUIImageEffect
    _ignored_4: ArrayType[C_UDeclPtr, L[3]]  # omitted: commonDialogPrefab … dialogBgPrefab
    dialogList: C_Ptr[GenericList[C_Ptr[DialogCommonBaseObject]]]
    _ignored_5: ArrayType[C_UDeclPtr, L[3]]  # omitted: dialogBgList … dialogSteam
    _ignored_6: ArrayType[c_bool, L[2]]  # omitted: isManualEnableBlur, isNeedExtraBlur


@register_runtime_validatable('Gallop::DialogManager')
class DialogManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: DialogManagerFields


class DialogManagerSingletonStaticFields(CStructureDataclass):
    _instance: C_Ptr[DialogManagerObject]


# ---------------------------------------------------------------------------
# Gallop.SceneManager object hierarchy
# ---------------------------------------------------------------------------

class SceneManagerFields(CStructureDataclass):
    _ignored_1: ArrayType[C_UDeclPtr, L[3]]  # omitted: currentSceneController … tmpLoadSceneBase
    currentViewController: C_Ptr[RuntimeIl2CppObject]
    _ignored_2: C_UDeclPtr  # omitted: currentViewBase
    _ignored_3: ArrayType[c_int32, L[3]]  # omitted: prevSceneId … nextViewId
    _ignored_4: C_UDeclPtr  # omitted: backableStateStack
    _ignored_5: ArrayType[c_bool, L[2]]  # omitted: isRunChangeView, isRunChangeInHubView
    _ignored_6: C_UDeclPtr  # omitted: changeViewEnumerator
    _ignored_7: c_bool  # omitted: isRunChangeScene
    _ignored_8: c_int32  # omitted: updateEnableState
    _ignored_9: ArrayType[C_UDeclPtr, L[5]]  # omitted: changeViewExecutor … photoLibraryObject
    _ignored_10: c_bool  # omitted: whileTutorialOverrideChangeViewId
    _ignored_11: c_int32  # omitted: tutorialOverrideViewId
    _ignored_12: ArrayType[C_UDeclPtr, L[3]]  # omitted: tutorialOverrideViewInfo … additiveBackendViewBase


@register_runtime_validatable('Gallop::SceneManager')
class SceneManagerObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    # MonoSingleton's generic parent is outside the declared SceneManager fields.
    _mono_behaviour: ArrayType[C_UDeclPtr, L[2]]  # m_CachedPtr, m_CancellationTokenSource
    fields: SceneManagerFields


class SceneManagerSingletonStaticFields(CStructureDataclass):
    _ignored_1: c_bool  # omitted: isApplicationQuit
    _instance: C_Ptr[SceneManagerObject]
    _ignored_2: C_UDeclPtr  # omitted: parentObject
