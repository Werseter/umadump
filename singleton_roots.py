"""Singleton resolution, cached roots, and the typed extractor context."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs.race import RaceManagerObject, RaceManagerSingletonStaticFields, RaceManagerStaticFields
from game_structs.single_mode import SingleModeChangeViewManagerObject, SingleModeChangeViewManagerSingletonStaticFields
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


@dataclass(frozen=True)
class SingletonSpec[TSingletonObject: StructOrSimple]:
    name: str
    target_type: str
    static_fields_type: type[Any]
    output_type: type[TSingletonObject]
    namespace: str = "Gallop"
    singleton_class: str = "Singleton`1"
    singleton_namespace: str = "Gallop"


WORKDATAMANAGER_SINGLETON_SPEC = SingletonSpec(
        name="workdatamanager",
        target_type="WorkDataManager",
        static_fields_type=WorkDataManagerSingletonStaticFields,
        output_type=WorkDataManagerObject,
)

RACEMANAGER_SINGLETON_SPEC = SingletonSpec(
        name="racemanager",
        target_type="RaceManager",
        static_fields_type=RaceManagerSingletonStaticFields,
        output_type=RaceManagerObject,
        singleton_class="MonoSingleton`1",
)

SINGLEMODECHANGEVIEW_SINGLETON_SPEC = SingletonSpec(
        name="singlemodechangeview",
        target_type="SingleModeChangeViewManager",
        static_fields_type=SingleModeChangeViewManagerSingletonStaticFields,
        output_type=SingleModeChangeViewManagerObject,
)

SINGLETON_SPEC_REGISTRY: dict[str, SingletonSpec[Any]] = {
    spec.name: spec for spec in (
        WORKDATAMANAGER_SINGLETON_SPEC,
        RACEMANAGER_SINGLETON_SPEC,
        SINGLEMODECHANGEVIEW_SINGLETON_SPEC,
    )
}


def build_singleton_generic_index(meta_reg: RuntimeIl2CppMetadataRegistration) \
        -> dict[tuple[int, int], SingletonGenericClassMatch]:
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

    by_key: dict[tuple[int, int], SingletonGenericClassMatch] = {}
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


def resolve_singleton[TSingletonObject: StructOrSimple](
        resolver: Il2CppResolutionManager,
        spec: SingletonSpec[TSingletonObject],
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch]) -> Optional[C_Ptr[TSingletonObject]]:
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

    static_fields_type = spec.static_fields_type
    # noinspection PyTypeHints
    static_fields_ptr_type = C_Ptr[static_fields_type]  # type: ignore[valid-type]
    static_fields_ptr = static_fields_ptr_type(int(matched.class_ptr.contents.static_fields))
    if not static_fields_ptr:
        return None
    # noinspection PyTypeChecker
    return type_cast(C_Ptr[TSingletonObject], static_fields_ptr.contents._instance)  # type: ignore[attr-defined]


ResolvedSingletonRoots = dict[str, Optional[C_Ptr[Any]]]
RACEMANAGER_STATIC_ROOT = "racemanager_static"


@dataclass(frozen=True)
class ExtractionContext:
    roots: ResolvedSingletonRoots

    @property
    def work_data_manager(self) -> WorkDataManagerObject:
        return self.require_singleton(WORKDATAMANAGER_SINGLETON_SPEC)

    @property
    def race_manager_static(self) -> Optional[RaceManagerStaticFields]:
        root = self.roots.get(RACEMANAGER_STATIC_ROOT)
        return type_cast(Optional[RaceManagerStaticFields], root.contents if root else None)

    @property
    def single_mode_change_view(self) -> C_Ptr[SingleModeChangeViewManagerObject] | None:
        return self.singleton(SINGLEMODECHANGEVIEW_SINGLETON_SPEC)

    def singleton[TSingletonObject: StructOrSimple](self, spec: SingletonSpec[TSingletonObject]) \
            -> Optional[C_Ptr[TSingletonObject]]:
        # noinspection PyTypeChecker
        return type_cast(Optional[C_Ptr[TSingletonObject]], self.roots.get(spec.name))

    def require_singleton[TSingletonObject: StructOrSimple](self, spec: SingletonSpec[TSingletonObject]) \
            -> TSingletonObject:
        instance = self.singleton(spec)
        if not instance:
            raise RuntimeError(f"{spec.target_type} not resolved")
        return instance.contents


def init_singleton_roots() -> ResolvedSingletonRoots:
    roots: ResolvedSingletonRoots = {spec.name: None for spec in SINGLETON_SPEC_REGISTRY.values()}
    roots[RACEMANAGER_STATIC_ROOT] = None
    return roots


def _invalidate_singleton_roots(roots: ResolvedSingletonRoots) -> None:
    for name in roots:
        roots[name] = None


def _root_type_metadata_handle(root: C_Ptr[Any]) -> Optional[int]:
    if not root:
        return None
    klass = root.contents._il2cpp_obj.klass
    if not klass:
        return None
    type_metadata_handle = klass.contents.typeMetadataHandle.address
    return int(type_metadata_handle) if type_metadata_handle else None


def _cached_singleton_roots_are_valid(roots: ResolvedSingletonRoots) -> bool:
    for spec in SINGLETON_SPEC_REGISTRY.values():
        root = roots.get(spec.name)
        if not root:
            continue

        expected_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(spec.output_type)
        if expected_handle is None:
            continue

        try:
            actual_handle = _root_type_metadata_handle(root)
        except Exception as exc:
            logger.debug("%s singleton root validation failed: %s", spec.name, exc)
            return False

        if actual_handle != expected_handle:
            logger.info(
                    "%s singleton root is stale; refreshing anchors (expected=0x%X, actual=%s)",
                    spec.name,
                    expected_handle,
                    f"0x{actual_handle:X}" if actual_handle is not None else "null",
            )
            return False

    return True


def refresh_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots) -> None:
    """Retry absent/null instances, leaving established non-null anchors unchanged."""
    for spec in SINGLETON_SPEC_REGISTRY.values():
        if not roots.get(spec.name):
            roots[spec.name] = resolve_singleton(resolver, spec, singleton_index)

    if roots.get(RACEMANAGER_STATIC_ROOT) is not None:
        return

    roots[RACEMANAGER_STATIC_ROOT] = resolver.static_fields_from_instance_or_typeinfo_method(
            roots.get(RACEMANAGER_SINGLETON_SPEC.name),
            "Gallop",
            "RaceManager",
            RaceManagerStaticFields,
            "get_RaceInfo",
    )


def refresh_live_singleton_roots(
        resolver: Il2CppResolutionManager,
        singleton_index: dict[tuple[int, int], SingletonGenericClassMatch],
        roots: ResolvedSingletonRoots) -> None:
    if not _cached_singleton_roots_are_valid(roots):
        _invalidate_singleton_roots(roots)
    refresh_singleton_roots(resolver, singleton_index, roots)
