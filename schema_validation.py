#!/usr/bin/env python3
"""
Schema and runtime validation for Il2Cpp wrapper classes.

Two-phase validation is provided:

Schema validation (metadata-time)
    Runs once at startup against parsed ``global-metadata.dat`` and the runtime
    ``MetadataRegistration`` field-offset tables.  For every class decorated with
    ``@register_schema_validatable`` or ``@register_runtime_validatable``, the
    field names and byte offsets declared in the Python ctypes wrapper are cross-
    checked against the corresponding Il2Cpp type definition (including the full
    *base-to-leaf* inheritance chain).  A mismatch prints a Warning so the
    developer can catch offset regressions after a game update without running a
    full dump.

Runtime validation (access-time)
    Classes decorated with ``@register_runtime_validatable`` additionally get a
    patched ``__getattribute__`` that verifies the ``typeMetadataHandle`` of every
    live Il2Cpp object before any public attribute access.  This catches stale
    pointers or wrong-type casts early.

Public decorators
-----------------
``@register_schema_validatable(il2cpp_name)``
    Opt into metadata field-layout cross-check only.

``@register_runtime_validatable(il2cpp_name)``
    Opt into both metadata cross-check *and* per-access ``typeMetadataHandle``
    guard.

Public function
---------------
``validate_registered_classes(resolver)``
    Call once after the ``Il2CppResolutionManager`` is ready to run all schema
    checks for registered classes.
"""
from __future__ import annotations

import re
from ctypes import c_int32
from typing import Any, Callable, ClassVar, Optional, Protocol

from ctypes_utils import C_Ptr
from il2cpp_structs import Il2CppFieldDefinition, RuntimeIl2CppClass, RuntimeIl2CppObject, RuntimeIl2CppType
from il2cpp_utils import Il2CppResolutionManager
from memory import MemoryReader


class RuntimeValidatableIl2CppClass(Protocol):
    """Protocol for Il2Cpp object wrappers that carry a live ``_il2cpp_obj`` pointer."""

    _il2cpp_obj: RuntimeIl2CppObject


class CtypesFieldDescriptor(Protocol):
    """Minimal descriptor shape used by ctypes field introspection."""

    offset: int


def _nested_fields_type(cls: type[Any]) -> type[Any] | None:
    """Return the ctypes type declared for the conventional ``fields`` member."""

    for field_name, field_type in getattr(cls, "_fields_", ()):
        if field_name == "fields":
            return field_type
    return None


class RuntimeValidatableIl2CppClassManager:
    """
    Central registry for Il2Cpp wrapper classes that need schema or runtime validation.

    Schema-validatable classes are cross-checked against ``global-metadata.dat``
    field layouts at startup via ``validate_registered_classes()``.

    Runtime-validatable classes additionally get a per-access ``typeMetadataHandle``
    guard installed on their ``__getattribute__``.
    """
    _registered_schema_classes: ClassVar[dict[str, type[Any]]] = dict()
    _runtime_validatable_class_names: ClassVar[set[str]] = set()
    _expected_type_metadata_handle_by_class: ClassVar[dict[type[Any], int]] = dict()

    @classmethod
    def register_schema_validatable(cls, il2cpp_name: str, wrapper_cls: type[Any]) -> None:
        """Register *wrapper_cls* for metadata field-layout cross-check only."""
        cls._registered_schema_classes[il2cpp_name] = wrapper_cls

    @classmethod
    def register_runtime_validatable(cls, il2cpp_name: str, wrapper_cls: type[RuntimeValidatableIl2CppClass]) -> None:
        """Register *wrapper_cls* for both schema cross-check and runtime ``typeMetadataHandle`` guard."""
        cls.register_schema_validatable(il2cpp_name, wrapper_cls)
        cls._runtime_validatable_class_names.add(il2cpp_name)

    @classmethod
    def is_runtime_validatable_name(cls, il2cpp_name: str) -> bool:
        return il2cpp_name in cls._runtime_validatable_class_names

    @classmethod
    def set_expected_type_metadata_handle(cls, wrapper_cls: type[Any], type_metadata_handle: int) -> None:
        cls._expected_type_metadata_handle_by_class[wrapper_cls] = int(type_metadata_handle)

    @classmethod
    def get_expected_type_metadata_handle(cls, wrapper_cls: type[Any]) -> int | None:
        return cls._expected_type_metadata_handle_by_class.get(wrapper_cls)


def _runtime_validate_type_metadata_handle_access(instance: RuntimeValidatableIl2CppClass, attr_name: str) -> None:
    inst_type = type(instance)
    if not instance._il2cpp_obj.klass:
        raise RuntimeError(f"{inst_type.__name__} has null _il2cpp_obj.klass while accessing '{attr_name}'")
    runtime_type_metadata_handle = instance._il2cpp_obj.klass.contents.typeMetadataHandle.address
    if runtime_type_metadata_handle == 0:
        raise RuntimeError(
                f"{inst_type.__name__} has null _il2cpp_obj.klass.typeMetadataHandle "
                f"while accessing '{attr_name}'"
        )
    expected_type_metadata_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(inst_type)
    if expected_type_metadata_handle is not None and runtime_type_metadata_handle != expected_type_metadata_handle:
        raise RuntimeError(
                f"{inst_type.__name__} typeMetadataHandle mismatch while accessing '{attr_name}': "
                f"expected=0x{expected_type_metadata_handle:X}, actual=0x{runtime_type_metadata_handle:X}"
        )


def _should_validate_attr_access(name: str) -> bool:
    return not (name.startswith("_") or (name.startswith("__") and name.endswith("__")))


def _install_runtime_validating_getattribute(cls: type[RuntimeValidatableIl2CppClass]) -> None:
    if bool(getattr(cls, "_runtime_validation_getattribute_patched", False)):
        return

    existing = cls.__dict__.get("__getattribute__")
    if existing is not None and existing is not object.__getattribute__:
        print(f"Warning: class {cls.__name__} already has custom __getattribute__, skipping validation wrapper")
        return

    original_getattribute = cls.__getattribute__

    def __getattribute__(self: RuntimeValidatableIl2CppClass, name: str) -> Any:
        if _should_validate_attr_access(name):
            _runtime_validate_type_metadata_handle_access(self, name)
        # noinspection PyTypeChecker
        return original_getattribute(self, name)

    setattr(cls, "__getattribute__", __getattribute__)
    setattr(cls, "_runtime_validation_getattribute_patched", True)


def register_schema_validatable(il2cpp_name: str) -> Callable[[type[Any]], type[Any]]:
    """Register wrapper for metadata-schema validation only (no runtime __getattribute__ checks)."""

    def _decorator(cls: type[Any]) -> type[Any]:
        RuntimeValidatableIl2CppClassManager.register_schema_validatable(il2cpp_name, cls)
        return cls

    return _decorator


def register_runtime_validatable[TValidatable: type[RuntimeValidatableIl2CppClass]](il2cpp_name: str) \
        -> Callable[[TValidatable], TValidatable]:
    def _decorator(cls: TValidatable) -> TValidatable:
        RuntimeValidatableIl2CppClassManager.register_runtime_validatable(il2cpp_name, cls)
        _install_runtime_validating_getattribute(cls)
        return cls

    return _decorator


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------


def _normalize_field_name(raw_name: str) -> str:
    """
    Canonicalise an Il2Cpp field name to camelCase for comparison with Python wrapper names.

    Strips leading underscores and unwraps auto-property backing-field notation
    (``<PropName>k__BackingField`` → ``propName``).
    """
    name = raw_name.lstrip("_")
    if not name:
        return ""

    backing_match = re.match(r"^<(?P<prop>[^>]+)>k__BackingField$", name)
    if backing_match is not None:
        name = backing_match.group("prop")

    # Final canonical form is camelCase.
    return name[0].lower() + name[1:] if name else ""


def _is_instance_field_from_metadata(resolver: Il2CppResolutionManager, field_def: Il2CppFieldDefinition) -> bool:
    """Return ``True`` if *field_def* is a non-static (instance) field.

    Looks up the field's type entry in ``MetadataRegistration.types`` and tests
    the ``FIELD_ATTRIBUTE_STATIC`` bit.  Returns ``True`` permissively when the
    runtime type pointer cannot be resolved so validation stays non-fatal.
    """
    FIELD_ATTRIBUTE_STATIC = 0x0010

    type_index = int(field_def.typeIndex)
    runtime_type_ptr = resolver.runtime_type_ptr_for_type_index(type_index)
    if runtime_type_ptr == 0:
        print(f"Warning: could not resolve runtime type pointer for field type index {type_index}")
        # Keep validation permissive when runtime type resolution is unavailable.
        return True
    field_type = C_Ptr[RuntimeIl2CppType](runtime_type_ptr).contents
    return (field_type.get_attrs_bits() & FIELD_ATTRIBUTE_STATIC) == 0


def _build_type_index_to_typedef_index(resolver: Il2CppResolutionManager) -> list[int]:
    """Build a ``typeIndex → typedefIndex`` lookup table using ``byvalTypeIndex``.

    The returned list is indexed by ``MetadataRegistration`` type-index; entries
    that could not be mapped are ``-1``.
    """
    type_index_to_typedef = [-1] * int(resolver.meta_reg.typesCount)
    for typedef_index, typedef in enumerate(resolver.metadata.type_defs):
        byval_type_index = int(typedef.byvalTypeIndex)
        if len(type_index_to_typedef) > byval_type_index >= 0 > type_index_to_typedef[byval_type_index]:
            type_index_to_typedef[byval_type_index] = typedef_index
    return type_index_to_typedef


def _iter_typedef_chain_base_to_leaf(resolver: Il2CppResolutionManager, leaf_typedef_index: int) -> list[int]:
    """Return the typedef-index chain from the root base class down to *leaf_typedef_index*.

    Follows ``Il2CppTypeDefinition.parentIndex`` upward, then reverses the result
    so callers receive indices in base-first order.  A cycle-guard prevents
    infinite loops in malformed metadata.  Returns an empty list when
    *leaf_typedef_index* is out of range.
    """
    type_defs = resolver.metadata.type_defs
    if leaf_typedef_index < 0 or leaf_typedef_index >= len(type_defs):
        return []

    type_index_to_typedef = _build_type_index_to_typedef_index(resolver)
    chain_leaf_to_base: list[int] = []
    seen_typedef_indices: set[int] = set()
    current_typedef_index = leaf_typedef_index

    while True:
        if current_typedef_index in seen_typedef_indices:
            break
        seen_typedef_indices.add(current_typedef_index)
        chain_leaf_to_base.append(current_typedef_index)

        parent_type_index = int(type_defs[current_typedef_index].parentIndex)
        if parent_type_index < 0 or parent_type_index >= len(type_index_to_typedef):
            break

        parent_typedef_index = type_index_to_typedef[parent_type_index]
        if parent_typedef_index < 0:
            break
        current_typedef_index = parent_typedef_index

    chain_leaf_to_base.reverse()
    return chain_leaf_to_base


def _read_metadata_instance_fields_by_offset(resolver: Il2CppResolutionManager, typedef_index: int) \
        -> Optional[dict[int, set[str]]]:
    """Collect all instance fields for *typedef_index* and its base classes.

    Walks the full inheritance chain (base → leaf) using
    ``_iter_typedef_chain_base_to_leaf`` and reads per-typedef field-offset tables
    from ``MetadataRegistration.fieldOffsets``.  Field byte offsets are normalised
    relative to the *first instance field encountered in the chain* so that the
    resulting map is directly comparable to ctypes wrapper offsets (which are also
    zero-based from the first field, not from the Il2Cpp object header).

    Returns
    -------
    dict mapping normalised byte offset → set of camelCase field names, or
    ``None`` when field-offset data is unavailable.
    """
    if not resolver.meta_reg.fieldOffsets:
        return None

    typedef_chain = _iter_typedef_chain_base_to_leaf(resolver, typedef_index)
    if not typedef_chain:
        return None

    field_offsets_count = int(resolver.meta_reg.fieldOffsetsCount)
    by_offset: dict[int, set[str]] = {}
    instance_base_offset: int | None = None

    for chain_typedef_index in typedef_chain:
        if chain_typedef_index < 0 or chain_typedef_index >= field_offsets_count:
            continue

        typedef = resolver.metadata.type_defs[chain_typedef_index]
        if typedef.field_count == 0:
            continue

        per_type_offsets_ptr = resolver.meta_reg.fieldOffsets.deref(chain_typedef_index)
        if not per_type_offsets_ptr:
            continue

        field_offsets_span = C_Ptr[c_int32](int(per_type_offsets_ptr)).as_span(typedef.field_count)
        for local_index, field_offset_raw in enumerate(field_offsets_span):
            field_def = resolver.metadata.field_defs[typedef.fieldStart + local_index]

            field_offset = int(field_offset_raw.value)
            if field_offset < 0:
                continue

            if not _is_instance_field_from_metadata(resolver, field_def):
                continue

            if instance_base_offset is None:
                # Normalize once across the full inheritance chain.
                instance_base_offset = field_offset
            normalized_offset = field_offset - instance_base_offset

            normalized = _normalize_field_name(resolver.metadata.strings.get(field_def.nameIndex, ""))
            if not normalized:
                continue
            by_offset.setdefault(normalized_offset, set()).add(normalized)

    return by_offset


def _iter_expected_registered_fields(cls: type[Any]) -> list[tuple[str, int]]:
    """Return ``(field_name, byte_offset)`` pairs declared by the Python ctypes wrapper *cls*.

    Two wrapper shapes are supported:

    * **Object wrappers** – expose a nested ``fields`` ctypes struct (e.g.
      ``Il2CppObject`` subclass with a ``fields`` member).  Only the fields of that
      nested type are used; the enclosing object header is excluded.
    * **Value-type / sparse wrappers** – declare ``_fields_`` directly on *cls*.

    Private fields (names starting with ``_``) are excluded.  An empty list is
    returned for wrappers with no declared fields, which causes validation to be
    skipped (sparse / intentionally unvalidated classes).
    """
    expected: list[tuple[str, int]] = []

    # Object wrappers usually expose instance data through `fields`.
    cls_fields: Optional[CtypesFieldDescriptor] = getattr(cls, "fields", None)
    nested_fields_type = _nested_fields_type(cls)
    if cls_fields is not None and nested_fields_type is not None:
        for field_name, _field_type in getattr(nested_fields_type, "_fields_", ()):
            if field_name.startswith("_"):
                continue
            field_desc = getattr(nested_fields_type, field_name)
            expected.append((field_name, int(field_desc.offset)))
        return expected

    # Value-type wrappers (or sparse wrappers) can still be validated from top-level fields.
    for field_name, _field_type in getattr(cls, "_fields_", ()):
        if field_name.startswith("_"):
            continue
        field_desc = getattr(cls, field_name)
        expected.append((field_name, int(field_desc.offset)))

    return expected


def _validate_registered_class(resolver: Il2CppResolutionManager, typedef_index: int, full_name: str,
                               cls: type[Any]) -> None:
    """Cross-check the Python ctypes wrapper *cls* against metadata field offsets.

    For each public field declared in the wrapper, verifies that a metadata
    instance field with a matching camelCase name exists at the same normalised
    byte offset in the typedef's *full* inheritance chain.  Prints a Warning for
    each mismatch and a summary line on success.  Skips wrappers with no public
    fields (sparse / marker classes).
    """
    # noinspection PyTypeChecker
    expected_fields = _iter_expected_registered_fields(cls)
    if not expected_fields:
        # Sparse validation: classes without a concrete wrapper layout are intentionally skipped.
        return

    metadata_fields_by_offset = _read_metadata_instance_fields_by_offset(resolver, typedef_index)
    if metadata_fields_by_offset is None:
        print(f"Warning: could not read field-offset table for {full_name}")
        return
    if not metadata_fields_by_offset:
        print(f"Warning: registered class {full_name} has no instance fields in metadata")
        return

    checked_public = 0
    for field_name, field_offset in expected_fields:
        checked_public += 1
        normalized_py_name = _normalize_field_name(field_name)
        metadata_names = metadata_fields_by_offset.get(field_offset, set())
        if normalized_py_name not in metadata_names:
            metadata_hint = ", ".join(sorted(metadata_names)) if metadata_names else "<none>"
            print(f"Warning: {full_name} field '{field_name}' (offset={field_offset}) "
                  f"not found in metadata at same offset (metadata={metadata_hint})")

    print(f"Validated registered class in metadata: {full_name} (public fields checked={checked_public})")


def _update_expected_runtime_type_metadata_handle(resolver: Il2CppResolutionManager,
                                                  typedef_index: int,
                                                  full_name: str,
                                                  cls: type[Any]) -> None:
    """Cache the ``typeMetadataHandle`` address for *cls* from the runtime type pointer table.

    The stored handle is later used by ``_runtime_validate_type_metadata_handle_access``
    to verify live object identity on every ``__getattribute__`` call.  Prints a
    Warning and skips caching when the runtime type pointer cannot be resolved.
    """
    try:
        runtime_type_ptr = resolver.require_runtime_type_ptr_for_typedef(typedef_index)
    except RuntimeError as exc:
        print(f"Warning: could not resolve runtime type pointer for {full_name}: {exc}")
        return

    runtime_type = C_Ptr[RuntimeIl2CppType](runtime_type_ptr).contents
    type_metadata_handle = int(runtime_type.data)
    if type_metadata_handle == 0:
        print(f"Warning: runtime type data pointer is null for {full_name}")
        return

    RuntimeValidatableIl2CppClassManager.set_expected_type_metadata_handle(cls, type_metadata_handle)


def validate_registered_classes(resolver: Il2CppResolutionManager) -> None:
    """Run schema validation for all classes registered via the decorator API.

    For each registered class:

    1. Parses the Il2Cpp name (``Namespace::Outer.Inner<Generics>``) and locates
       the corresponding ``Il2CppTypeDefinition`` index in metadata.
    2. For runtime-validatable classes, caches the expected ``typeMetadataHandle``
       address from the live ``MetadataRegistration.types`` table.
    3. Cross-checks the Python ctypes wrapper field layout against the *full*
       inherited metadata field-offset table (base class fields are included).

    Should be called once after ``Il2CppResolutionManager`` is constructed and
    before any live object access.
    """
    name_pattern = re.compile(
            r"^(?:(?P<namespace>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)::)?"
            r"(?P<classchain>[A-Za-z_]\w*(?:`\d+)?(?:\.[A-Za-z_]\w*(?:`\d+)?)*)"
            r"(?:<(?P<generics>(?:[^<>]+|<[^<>]*>)+)>)?$"
    )
    for full_name, cls in RuntimeValidatableIl2CppClassManager._registered_schema_classes.items():
        if (match := name_pattern.match(full_name)) is None:
            print(f"Warning: invalid class name format for registered class: {full_name}")
            continue
        namespace, raw_class_chain, generics = match.groups(default="")
        class_chain = raw_class_chain.split(".")
        typedef_index = resolver.find_type_def_index(class_chain, namespace)
        if typedef_index is None:
            print(f"Warning: registered class {full_name} not found in metadata")
            continue
        if RuntimeValidatableIl2CppClassManager.is_runtime_validatable_name(full_name):
            _update_expected_runtime_type_metadata_handle(resolver, typedef_index, full_name, cls)
        # noinspection PyTypeChecker
        _validate_registered_class(resolver, typedef_index, full_name, cls)


# ---------------------------------------------------------------------------
# Runtime validation
# ---------------------------------------------------------------------------

def _runtime_class_full_name(mem: MemoryReader,
                             klass_ptr: C_Ptr[RuntimeIl2CppClass]) -> Optional[tuple[str, RuntimeIl2CppClass]]:
    if not klass_ptr:
        return None

    runtime_class = klass_ptr.contents
    if not runtime_class.name:
        return None

    class_name = mem.read_cstring(int(runtime_class.name))
    namespace = mem.read_cstring(int(runtime_class.namespaze)) if runtime_class.namespaze else ""
    full_name = f"{namespace}.{class_name}" if namespace else class_name
    return full_name, runtime_class


def _validate_runtime_class_layout(mem: MemoryReader, instance_ptr: int, expected_full_name: str) -> None:
    runtime_obj = C_Ptr[RuntimeIl2CppObject](instance_ptr).contents
    runtime_info = _runtime_class_full_name(mem, runtime_obj.klass)
    if runtime_info is None:
        print("Warning: could not resolve runtime class metadata for singleton instance")
        return

    runtime_full_name, runtime_class = runtime_info
    if runtime_full_name != expected_full_name:
        print(f"Warning: runtime class-name mismatch: expected {expected_full_name}, got {runtime_full_name}")
        return

    registered_cls = RuntimeValidatableIl2CppClassManager._registered_schema_classes.get(expected_full_name)
    if registered_cls is None:
        print(f"Warning: class {expected_full_name} is not registered for validation")
        return

    print(f"Validated runtime class name: {expected_full_name}")

    fields_layout = None
    for field_name, field_type in getattr(registered_cls, "_fields_", ()):  # object wrapper layout
        if field_name == "fields":
            fields_layout = field_type
            break
    if fields_layout is None:
        return

    expected_field_count = len(getattr(fields_layout, "_fields_", ()))
    actual_field_count = int(runtime_class.field_count)
    if expected_field_count != actual_field_count:
        print(
                f"Warning: field-count mismatch for {expected_full_name}: "
                f"runtime={actual_field_count}, registered={expected_field_count}"
        )
        return
    print(f"Validated field count for {expected_full_name}: {actual_field_count}")
