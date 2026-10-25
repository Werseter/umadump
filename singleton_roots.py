"""Typed singleton anchors, per-pass instance snapshots, and extractor context."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, cast as type_cast, overload

from ctypes_utils import C_Ptr
from game_structs.race import RaceManagerObject, RaceManagerSingletonStaticFields, RaceManagerStaticFields
from game_structs.single_mode import SingleModeChangeViewManagerObject, SingleModeChangeViewManagerSingletonStaticFields
from game_structs.temp_data import TempDataObject, TempDataSingletonStaticFields
from game_structs.ui import (DialogManagerObject, DialogManagerSingletonStaticFields, SceneManagerObject,
                             SceneManagerSingletonStaticFields)
from game_structs.work_data_manager import WorkDataManagerObject, WorkDataManagerSingletonStaticFields
from il2cpp_structs import (RuntimeIl2CppClass, RuntimeIl2CppGenericClass, RuntimeIl2CppGenericInst,
                            RuntimeIl2CppMetadataRegistration, RuntimeIl2CppType)
from il2cpp_utils import Il2CppResolutionManager
from logger import logger
from schema_validation import RuntimeValidatableIl2CppClassManager


@dataclass(frozen=True)
class GenericClassCollection:
    """Collected RuntimeIl2CppGenericClass pointers plus dereferenced cache by address."""

    ptrs: list[C_Ptr[RuntimeIl2CppGenericClass]]
    by_addr: dict[int, RuntimeIl2CppGenericClass]


def _collect_generic_classes(meta_reg: RuntimeIl2CppMetadataRegistration) -> GenericClassCollection:
    """Read and dereference ``MetadataRegistration.genericClasses`` into fast lookup form."""

    gc_ptrs = list(meta_reg.genericClasses.as_span(meta_reg.genericClassesCount))
    gc_addrs = [ptr.address for ptr in gc_ptrs if ptr]
    gc_values = C_Ptr[RuntimeIl2CppGenericClass].deref_many_at(gc_addrs)
    gc_by_addr: dict[int, RuntimeIl2CppGenericClass] = {addr: gc for addr, gc in zip(gc_addrs, gc_values)}
    return GenericClassCollection(ptrs=gc_ptrs, by_addr=gc_by_addr)


@dataclass(frozen=True)
class SingletonGenericClassMatch:
    seq: int
    class_ptr: C_Ptr[RuntimeIl2CppClass]


type SingletonGenericIndex = dict[tuple[int, int], SingletonGenericClassMatch]
type SingletonStaticFields = (WorkDataManagerSingletonStaticFields | RaceManagerSingletonStaticFields
                              | SingleModeChangeViewManagerSingletonStaticFields | TempDataSingletonStaticFields
                              | DialogManagerSingletonStaticFields | SceneManagerSingletonStaticFields)
type SingletonObject = (WorkDataManagerObject | RaceManagerObject | SingleModeChangeViewManagerObject | TempDataObject |
                        DialogManagerObject | SceneManagerObject)
type SingletonStaticPointer = (C_Ptr[WorkDataManagerSingletonStaticFields] | C_Ptr[RaceManagerSingletonStaticFields]
                               | C_Ptr[SingleModeChangeViewManagerSingletonStaticFields]
                               | C_Ptr[TempDataSingletonStaticFields] | C_Ptr[DialogManagerSingletonStaticFields]
                               | C_Ptr[SceneManagerSingletonStaticFields])
type SingletonInstancePointer = (C_Ptr[WorkDataManagerObject] | C_Ptr[RaceManagerObject]
                                 | C_Ptr[SingleModeChangeViewManagerObject] | C_Ptr[TempDataObject]
                                 | C_Ptr[DialogManagerObject] | C_Ptr[SceneManagerObject])


@dataclass(frozen=True)
class SingletonSpec[TStaticFields: SingletonStaticFields, TSingletonObject: SingletonObject]:
    name: str
    target_type: str
    static_fields_type: type[TStaticFields]
    output_type: type[TSingletonObject]
    namespace: str = "Gallop"
    singleton_class: str = "Singleton`1"
    singleton_namespace: str = "Gallop"


type WorkDataManagerSingletonSpec = SingletonSpec[WorkDataManagerSingletonStaticFields, WorkDataManagerObject]
type RaceManagerSingletonSpec = SingletonSpec[RaceManagerSingletonStaticFields, RaceManagerObject]
type SingleModeChangeViewManagerSingletonSpec = \
    SingletonSpec[SingleModeChangeViewManagerSingletonStaticFields, SingleModeChangeViewManagerObject]
type TempDataSingletonSpec = SingletonSpec[TempDataSingletonStaticFields, TempDataObject]
type DialogManagerSingletonSpec = SingletonSpec[DialogManagerSingletonStaticFields, DialogManagerObject]
type SceneManagerSingletonSpec = SingletonSpec[SceneManagerSingletonStaticFields, SceneManagerObject]
type RegisteredSingletonSpec = (WorkDataManagerSingletonSpec | RaceManagerSingletonSpec
                                | SingleModeChangeViewManagerSingletonSpec | TempDataSingletonSpec
                                | DialogManagerSingletonSpec | SceneManagerSingletonSpec)

WORKDATAMANAGER_SINGLETON_SPEC: WorkDataManagerSingletonSpec = SingletonSpec(
        name="workdatamanager",
        target_type="WorkDataManager",
        static_fields_type=WorkDataManagerSingletonStaticFields,
        output_type=WorkDataManagerObject,
)

RACEMANAGER_SINGLETON_SPEC: RaceManagerSingletonSpec = SingletonSpec(
        name="racemanager",
        target_type="RaceManager",
        static_fields_type=RaceManagerSingletonStaticFields,
        output_type=RaceManagerObject,
        singleton_class="MonoSingleton`1",
)

SINGLEMODECHANGEVIEW_SINGLETON_SPEC: SingleModeChangeViewManagerSingletonSpec = SingletonSpec(
        name="singlemodechangeview",
        target_type="SingleModeChangeViewManager",
        static_fields_type=SingleModeChangeViewManagerSingletonStaticFields,
        output_type=SingleModeChangeViewManagerObject,
)

TEMPDATA_SINGLETON_SPEC: TempDataSingletonSpec = SingletonSpec(
        name="tempdata",
        target_type="TempData",
        static_fields_type=TempDataSingletonStaticFields,
        output_type=TempDataObject,
)

DIALOGMANAGER_SINGLETON_SPEC: DialogManagerSingletonSpec = SingletonSpec(
        name="dialogmanager",
        target_type="DialogManager",
        static_fields_type=DialogManagerSingletonStaticFields,
        output_type=DialogManagerObject,
)

SCENEMANAGER_SINGLETON_SPEC: SceneManagerSingletonSpec = SingletonSpec(
        name="scenemanager",
        target_type="SceneManager",
        static_fields_type=SceneManagerSingletonStaticFields,
        output_type=SceneManagerObject,
        singleton_class="MonoSingleton`1",
)

SINGLETON_SPEC_REGISTRY: dict[str, RegisteredSingletonSpec] = {
    spec.name: spec for spec in (
        WORKDATAMANAGER_SINGLETON_SPEC,
        RACEMANAGER_SINGLETON_SPEC,
        SINGLEMODECHANGEVIEW_SINGLETON_SPEC,
        TEMPDATA_SINGLETON_SPEC,
        DIALOGMANAGER_SINGLETON_SPEC,
        SCENEMANAGER_SINGLETON_SPEC,
    )
}


def build_singleton_generic_index(meta_reg: RuntimeIl2CppMetadataRegistration) \
        -> SingletonGenericIndex:
    """Build ``(generic-definition-type-ptr, arg0-type-ptr) -> matched class`` index."""
    generic_classes = _collect_generic_classes(meta_reg)

    gc_by_seq: dict[int, RuntimeIl2CppGenericClass] = {}
    inst_addrs: list[int] = []
    for seq, gc_ptr in enumerate(generic_classes.ptrs):
        if not gc_ptr:
            continue
        gc = generic_classes.by_addr[gc_ptr.address]
        if not gc.context.class_inst:
            continue
        gc_by_seq[seq] = gc
        inst_addrs.append(gc.context.class_inst.address)

    inst_values = C_Ptr[RuntimeIl2CppGenericInst].deref_many_at(inst_addrs)
    inst_by_addr = {addr: inst for addr, inst in zip(inst_addrs, inst_values)}

    argv0_ptr_addrs: list[int] = []
    argv0_index_by_inst_addr: dict[int, int] = {}
    for inst_addr, inst in inst_by_addr.items():
        if inst.type_argc < 1 or not inst.type_argv:
            continue
        argv0_index_by_inst_addr[inst_addr] = len(argv0_ptr_addrs)
        argv0_ptr_addrs.append(inst.type_argv.address)

    argv0_ptrs = C_Ptr[C_Ptr[RuntimeIl2CppType]].deref_many_at(argv0_ptr_addrs)
    argv0_type_ptr_by_inst_addr = {
        inst_addr: argv0_ptrs[idx].address
        for inst_addr, idx in argv0_index_by_inst_addr.items()
    }

    by_key: SingletonGenericIndex = {}
    for seq, gc in gc_by_seq.items():
        arg0_type_ptr = argv0_type_ptr_by_inst_addr.get(gc.context.class_inst.address)
        if arg0_type_ptr is None or not gc.cached_class or not gc.type:
            continue
        generic_type_addr = gc.type.address
        if generic_type_addr is None:
            continue
        if not isinstance(generic_type_addr, int) or not isinstance(arg0_type_ptr, int):
            continue
        key = (generic_type_addr, arg0_type_ptr)
        by_key.setdefault(key, SingletonGenericClassMatch(seq=seq, class_ptr=gc.cached_class))
    return by_key


# Concrete overloads preserve each static-pointer type when the registry supplies a union of specs.
@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: WorkDataManagerSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[WorkDataManagerSingletonStaticFields]]:
    ...


@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: RaceManagerSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[RaceManagerSingletonStaticFields]]:
    ...


@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: SingleModeChangeViewManagerSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[SingleModeChangeViewManagerSingletonStaticFields]]:
    ...


@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: TempDataSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[TempDataSingletonStaticFields]]:
    ...


@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: DialogManagerSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[DialogManagerSingletonStaticFields]]:
    ...


@overload
def resolve_singleton_static_fields(
        resolver: Il2CppResolutionManager, spec: SceneManagerSingletonSpec,
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[SceneManagerSingletonStaticFields]]:
    ...


def resolve_singleton_static_fields[TStaticFields: SingletonStaticFields, TSingletonObject: SingletonObject](
        resolver: Il2CppResolutionManager,
        spec: SingletonSpec[TStaticFields, TSingletonObject],
        singleton_index: SingletonGenericIndex) -> Optional[C_Ptr[TStaticFields]]:
    """Resolve the stable storage containing a singleton's mutable ``_instance`` slot."""
    meta_reg = resolver.meta_reg
    if not meta_reg.genericClasses:
        logger.warning("MetadataRegistration genericClasses pointer is missing")
        return None

    singleton_typedef = resolver.require_type_def_index([spec.singleton_class], spec.singleton_namespace)
    target_typedef = resolver.require_type_def_index([spec.target_type], spec.namespace)
    singleton_type_ptr = resolver.require_runtime_type_ptr_for_typedef(singleton_typedef)
    target_type_ptr = resolver.require_runtime_type_ptr_for_typedef(target_typedef)
    resolver.require_static_field_local_index(singleton_typedef, "_instance")

    matched = singleton_index.get((singleton_type_ptr, target_type_ptr))
    if matched is None:
        type_string = f"{spec.singleton_namespace}::{spec.singleton_class}[{spec.namespace}{spec.target_type}]"
        logger.warning("No %s instantiation found", type_string)
        return None

    static_fields_ptr = matched.class_ptr.contents.static_fields_as(spec.static_fields_type)
    if not static_fields_ptr:
        return None
    return static_fields_ptr


@dataclass
class ResolvedSingletonRoots:
    """Stable singleton storage and the current instance pointers for one memory pass."""

    singleton_statics: dict[str, Optional[SingletonStaticPointer]] = field(default_factory=dict)
    instances: dict[str, Optional[SingletonInstancePointer]] = field(default_factory=dict)
    race_manager_static: Optional[C_Ptr[RaceManagerStaticFields]] = None


@dataclass(frozen=True)
class ExtractionContext:
    roots: ResolvedSingletonRoots

    @property
    def work_data_manager(self) -> WorkDataManagerObject:
        return self.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)

    @property
    def race_manager_static(self) -> Optional[RaceManagerStaticFields]:
        root = self.roots.race_manager_static
        return root.contents if root else None

    @property
    def single_mode_change_view(self) -> C_Ptr[SingleModeChangeViewManagerObject] | None:
        return self.singleton(SINGLEMODECHANGEVIEW_SINGLETON_SPEC)

    @property
    def temp_data(self) -> TempDataObject:
        return self.require_singleton(TEMPDATA_SINGLETON_SPEC)

    @property
    def dialog_manager(self) -> DialogManagerObject:
        return self.require_singleton(DIALOGMANAGER_SINGLETON_SPEC)

    @property
    def scene_manager(self) -> SceneManagerObject:
        return self.require_singleton(SCENEMANAGER_SINGLETON_SPEC)

    def singleton[TStaticFields: SingletonStaticFields, TSingletonObject: SingletonObject](
            self, spec: SingletonSpec[TStaticFields, TSingletonObject]) -> Optional[C_Ptr[TSingletonObject]]:
        # noinspection PyTypeChecker
        return type_cast(Optional[C_Ptr[TSingletonObject]], self.roots.instances.get(spec.name))

    def require_singleton[TStaticFields: SingletonStaticFields, TSingletonObject: SingletonObject](
            self, spec: SingletonSpec[TStaticFields, TSingletonObject]) -> TSingletonObject:
        """Read a required singleton without caching its object snapshot."""
        instance = self.singleton(spec)
        if not instance:
            raise RuntimeError(f"{spec.target_type} not resolved")
        return instance.contents


def _invalidate_singleton_roots(roots: ResolvedSingletonRoots) -> None:
    roots.singleton_statics.clear()
    roots.instances.clear()
    roots.race_manager_static = None


def _refresh_singleton_instances(roots: ResolvedSingletonRoots) -> bool:
    """Read current instance slots once per pass, validating their runtime classes."""
    for spec in SINGLETON_SPEC_REGISTRY.values():
        try:
            anchor = roots.singleton_statics.get(spec.name)
            root = anchor.contents._instance if anchor else None
            roots.instances[spec.name] = root
            if not root:
                continue

            expected_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(spec.output_type)
            if expected_handle is None:
                continue

            runtime_class = root.contents._il2cpp_obj.klass
            actual_handle = runtime_class.contents.typeMetadataHandle.address if runtime_class else 0
            if actual_handle and actual_handle != expected_handle:
                if RuntimeValidatableIl2CppClassManager.runtime_class_is_or_inherits_from(
                        runtime_class, expected_handle):
                    continue
        except Exception as exc:
            logger.debug("%s singleton root validation failed: %s", spec.name, exc)
            return False

        if actual_handle != expected_handle:
            logger.info(
                    "%s singleton root is stale; refreshing anchors (expected=0x%X, actual=%s)",
                    spec.name,
                    expected_handle,
                    f"0x{actual_handle:X}" if actual_handle else "null",
            )
            return False

    return True


def refresh_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: SingletonGenericIndex,
        roots: ResolvedSingletonRoots) -> None:
    """Resolve missing static anchors; an empty instance slot does not invalidate them."""
    for spec in SINGLETON_SPEC_REGISTRY.values():
        if not roots.singleton_statics.get(spec.name):
            anchor = resolve_singleton_static_fields(resolver, spec, singleton_index)
            roots.singleton_statics[spec.name] = anchor
            roots.instances[spec.name] = anchor.contents._instance if anchor else None

    if roots.race_manager_static is not None:
        return

    roots.race_manager_static = resolver.static_fields_from_instance_or_typeinfo_method(
            roots.instances.get(RACEMANAGER_SINGLETON_SPEC.name),
            "Gallop",
            "RaceManager",
            RaceManagerStaticFields,
            "get_RaceInfo",
    )


def refresh_live_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: SingletonGenericIndex,
        roots: ResolvedSingletonRoots) -> None:
    if not _refresh_singleton_instances(roots):
        _invalidate_singleton_roots(roots)
    refresh_singleton_roots(resolver, singleton_index, roots)
