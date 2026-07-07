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

    ``@register_enum_validatable`` additionally cross-checks local ``IntEnum``
    member names and numeric values against Il2Cpp enum field metadata.

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

``@register_enum_validatable(il2cpp_name)``
    Opt an ``IntEnum`` into metadata member-name cross-checks.

Public function
---------------
``validate_registered_classes(resolver)``
    Call once after the ``Il2CppResolutionManager`` is ready to run all schema
    checks for registered classes.
"""
from __future__ import annotations

import re
from ctypes import CField, c_int32
from enum import IntEnum
from typing import Any, Callable, ClassVar, Optional, Protocol, get_type_hints

from ctypes_utils import CStructureDataclass, C_Ptr
from il2cpp_structs import Il2CppFieldDefinition, RuntimeIl2CppClass, RuntimeIl2CppObject, RuntimeIl2CppType
from il2cpp_utils import Il2CppResolutionManager
from logger import logger


class RuntimeValidatableIl2CppClass(Protocol):
    """Protocol for Il2Cpp object wrappers that carry a live ``_il2cpp_obj`` pointer."""

    _il2cpp_obj: RuntimeIl2CppObject


class RuntimeValidatableIl2CppClassManager:
    """
    Central registry for Il2Cpp wrapper classes that need schema or runtime validation.

    Schema-validatable classes are cross-checked against ``global-metadata.dat``
    field layouts at startup via ``validate_registered_classes()``.

    Runtime-validatable classes additionally get a per-access ``typeMetadataHandle``
    guard installed on their ``__getattribute__``.
    """
    _registered_schema_classes: ClassVar[dict[str, type[Any]]] = dict()
    _registered_enum_classes: ClassVar[dict[str, type[IntEnum]]] = dict()
    _runtime_validatable_class_names: ClassVar[set[str]] = set()
    _expected_type_metadata_handle_by_class: ClassVar[dict[type[Any], int]] = dict()
    _subtype_match_cache: ClassVar[dict[tuple[int, int], bool]] = dict()

    @classmethod
    def register_schema_validatable(cls, il2cpp_name: str, wrapper_cls: type[Any]) -> None:
        """Register *wrapper_cls* for metadata field-layout cross-check only."""
        cls._registered_schema_classes[il2cpp_name] = wrapper_cls

    @classmethod
    def register_enum_validatable(cls, il2cpp_name: str, enum_cls: type[IntEnum]) -> None:
        """Register *enum_cls* for metadata enum-member cross-check."""
        cls._registered_enum_classes[il2cpp_name] = enum_cls

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

    @classmethod
    def get_cached_subtype_match(cls, expected_handle: int, actual_handle: int) -> bool | None:
        return cls._subtype_match_cache.get((int(expected_handle), int(actual_handle)))

    @classmethod
    def set_cached_subtype_match(cls, expected_handle: int, actual_handle: int, is_match: bool) -> None:
        cls._subtype_match_cache[(int(expected_handle), int(actual_handle))] = is_match


def _runtime_validate_type_metadata_handle_access(instance: RuntimeValidatableIl2CppClass, attr_name: str) -> None:
    inst_type = type(instance)
    if not instance._il2cpp_obj.klass:
        raise RuntimeError(f"{inst_type.__name__} has null _il2cpp_obj.klass while accessing '{attr_name}'")
    runtime_class_ptr = instance._il2cpp_obj.klass
    runtime_type_metadata_handle = runtime_class_ptr.contents.typeMetadataHandle.address
    if runtime_type_metadata_handle == 0:
        raise RuntimeError(
                f"{inst_type.__name__} has null _il2cpp_obj.klass.typeMetadataHandle "
                f"while accessing '{attr_name}'"
        )
    expected_type_metadata_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(inst_type)
    if expected_type_metadata_handle is not None and runtime_type_metadata_handle != expected_type_metadata_handle:
        if not _runtime_class_is_or_inherits_from(runtime_class_ptr, expected_type_metadata_handle):
            raise RuntimeError(
                    f"{inst_type.__name__} typeMetadataHandle mismatch while accessing '{attr_name}': "
                    f"expected=0x{expected_type_metadata_handle:X}, actual=0x{runtime_type_metadata_handle:X}"
            )


def _runtime_class_is_or_inherits_from(klass_ptr: C_Ptr[RuntimeIl2CppClass], expected_handle: int) -> bool:
    """Return whether runtime class *klass_ptr* is *expected_handle* or derives from it.

    This is intentionally resolved lazily on first access mismatch. Most runtime
    objects match exactly; only derived instances pay for walking the parent chain.
    """
    if not klass_ptr:
        return False

    expected_handle = int(expected_handle)
    actual_handle = int(klass_ptr.contents.typeMetadataHandle.address)
    cached = RuntimeValidatableIl2CppClassManager.get_cached_subtype_match(expected_handle, actual_handle)
    if cached is not None:
        return cached

    current = klass_ptr
    while current:
        current_class = current.contents
        current_handle = int(current_class.typeMetadataHandle.address)
        if current_handle == expected_handle:
            RuntimeValidatableIl2CppClassManager.set_cached_subtype_match(expected_handle, actual_handle, True)
            return True

        current = current_class.parent

    RuntimeValidatableIl2CppClassManager.set_cached_subtype_match(expected_handle, actual_handle, False)
    return False


def _should_validate_attr_access(name: str) -> bool:
    return not (name.startswith("_") or (name.startswith("__") and name.endswith("__")))


def _install_runtime_validating_getattribute(cls: type[RuntimeValidatableIl2CppClass]) -> None:
    if bool(getattr(cls, "_runtime_validation_getattribute_patched", False)):
        return

    existing = cls.__dict__.get("__getattribute__")
    if existing is not None and existing is not object.__getattribute__:
        logger.warning("Class %s already has custom __getattribute__, skipping validation wrapper", cls.__name__)
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


def register_enum_validatable[TEnum: type[IntEnum]](il2cpp_name: str) -> Callable[[TEnum], TEnum]:
    """Register an ``IntEnum`` for metadata enum-member validation."""

    def _decorator(cls: TEnum) -> TEnum:
        RuntimeValidatableIl2CppClassManager.register_enum_validatable(il2cpp_name, cls)
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

    backing_match = re.match(r"^<_?(?P<prop>[^>]+)>k__BackingField$", name)
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
        logger.warning("Could not resolve runtime type pointer for field type index %d", type_index)
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


def _iter_expected_registered_fields(cls: type[Any]) -> list[tuple[str, int, object | None, object | None]]:
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
    expected: list[tuple[str, int, object | None, object | None]] = []

    # Object wrappers usually expose instance data through `fields`.
    cls_fields: Optional[CField[CStructureDataclass, Any, Any]] = getattr(cls, "fields", None)
    if cls_fields is not None:
        nested_fields_type = cls_fields.type
        storage_hints = get_type_hints(nested_fields_type)
        for field_name, _field_type in getattr(nested_fields_type, "_fields_", ()):
            if field_name.startswith("_"):
                continue
            field_desc = getattr(nested_fields_type, field_name)
            expected.append((field_name, int(field_desc.offset), storage_hints.get(field_name), field_desc.type))
        return expected

    # Value-type wrappers (or sparse wrappers) can still be validated from top-level fields.
    storage_hints = get_type_hints(cls)
    for field_name, _field_type in getattr(cls, "_fields_", ()):
        if field_name.startswith("_"):
            continue
        field_desc = getattr(cls, field_name)
        expected.append((field_name, int(field_desc.offset), storage_hints.get(field_name), field_desc.type))

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
        logger.warning("Could not read field-offset table for %s", full_name)
        return
    if not metadata_fields_by_offset:
        logger.warning("Registered class %s has no instance fields in metadata", full_name)
        return

    checked_public = 0
    for field_name, field_offset, expected_storage_type, actual_storage_type in expected_fields:
        checked_public += 1
        normalized_py_name = _normalize_field_name(field_name)
        metadata_names = metadata_fields_by_offset.get(field_offset, set())
        if normalized_py_name not in metadata_names:
            metadata_hint = ", ".join(sorted(metadata_names)) if metadata_names else "<none>"
            logger.warning("%s field '%s' (offset=%d) not found in metadata at same offset (metadata=%s)",
                           full_name, field_name, field_offset, metadata_hint)
        if (expected_storage_type is not None and actual_storage_type is not None
                and expected_storage_type is not actual_storage_type):
            logger.warning("%s field '%s' storage type mismatch: annotation=%s, ctypes=%s",
                           full_name, field_name, expected_storage_type, actual_storage_type)

    logger.debug("Validated registered class in metadata: %s (public fields checked=%d)", full_name, checked_public)


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
        logger.warning("Could not resolve runtime type pointer for %s: %s", full_name, exc)
        return

    runtime_type = C_Ptr[RuntimeIl2CppType](runtime_type_ptr).contents
    type_metadata_handle = int(runtime_type.data)
    if type_metadata_handle == 0:
        logger.warning("Runtime type data pointer is null for %s", full_name)
        return

    RuntimeValidatableIl2CppClassManager.set_expected_type_metadata_handle(cls, type_metadata_handle)


def _schema_name_pattern() -> re.Pattern[str]:
    return re.compile(
            r"^(?:(?P<namespace>[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)::)?"
            r"(?P<classchain>[A-Za-z_]\w*(?:`\d+)?(?:\.[A-Za-z_]\w*(?:`\d+)?)*)"
            r"(?:<(?P<generics>(?:[^<>]+|<[^<>]*>)+)>)?$"
    )


def _registered_typedef_index(resolver: Il2CppResolutionManager, full_name: str,
                              registration_kind: str = "class") -> int | None:
    if (match := _schema_name_pattern().match(full_name)) is None:
        logger.warning("Invalid %s name format for registered %s: %s",
                       registration_kind, registration_kind, full_name)
        return None
    namespace, raw_class_chain, _generics = match.groups(default="")
    class_chain = raw_class_chain.split(".")
    typedef_index = resolver.find_type_def_index(class_chain, namespace)
    if typedef_index is None:
        logger.warning("Registered %s %s not found in metadata", registration_kind, full_name)
    return typedef_index


def _validate_registered_classes(resolver: Il2CppResolutionManager) -> None:
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
    for full_name, cls in RuntimeValidatableIl2CppClassManager._registered_schema_classes.items():
        typedef_index = _registered_typedef_index(resolver, full_name)
        if typedef_index is None:
            continue
        if RuntimeValidatableIl2CppClassManager.is_runtime_validatable_name(full_name):
            _update_expected_runtime_type_metadata_handle(resolver, typedef_index, full_name, cls)
        # noinspection PyTypeChecker
        _validate_registered_class(resolver, typedef_index, full_name, cls)


def _normalize_enum_member_name(name: str) -> str:
    return name.replace("_", "").lower()


def _metadata_enum_member_values(resolver: Il2CppResolutionManager, typedef_index: int) -> dict[str, int | None]:
    typedef = resolver.metadata.type_defs[typedef_index]
    values: dict[str, int | None] = {}
    for local_index in range(typedef.field_count):
        field_index = typedef.fieldStart + local_index
        field_def = resolver.metadata.field_defs[typedef.fieldStart + local_index]
        name = resolver.metadata.strings.get(field_def.nameIndex, "")
        if name == "value__":
            continue
        values[name] = resolver.metadata.int32_field_defaults_by_field_index.get(field_index)
    return values


def _validate_registered_enum(resolver: Il2CppResolutionManager, typedef_index: int, full_name: str,
                              enum_cls: type[IntEnum]) -> None:
    metadata_values = _metadata_enum_member_values(resolver, typedef_index)
    expected_by_normalized = {
        _normalize_enum_member_name(member_name): (member_name, int(member.value))
        for member_name, member in enum_cls.__members__.items()
    }
    metadata_by_normalized = {
        _normalize_enum_member_name(member_name): (member_name, value)
        for member_name, value in metadata_values.items()
    }

    missing = sorted(
            expected_by_normalized[name][0] for name in expected_by_normalized.keys() - metadata_by_normalized.keys())
    extra = sorted(
            metadata_by_normalized[name][0] for name in metadata_by_normalized.keys() - expected_by_normalized.keys())
    value_mismatches: list[str] = []
    unresolved_values: list[str] = []
    for normalized_name in expected_by_normalized.keys() & metadata_by_normalized.keys():
        expected_name, expected_value = expected_by_normalized[normalized_name]
        metadata_name, metadata_value = metadata_by_normalized[normalized_name]
        if metadata_value is None:
            unresolved_values.append(metadata_name)
        elif expected_value != metadata_value:
            value_mismatches.append(f"{expected_name}: local={expected_value}, metadata={metadata_value}")

    if missing:
        logger.warning("%s enum members not found in metadata: %s", full_name, ", ".join(missing))
    if extra:
        logger.warning("%s metadata enum members not represented locally: %s", full_name, ", ".join(extra))
    if unresolved_values:
        logger.warning("%s enum member values could not be decoded from metadata: %s",
                       full_name, ", ".join(sorted(unresolved_values)))
    if value_mismatches:
        logger.warning("%s enum member value mismatches: %s", full_name, "; ".join(sorted(value_mismatches)))
    if not missing and not extra and not unresolved_values and not value_mismatches:
        logger.debug("Validated registered enum in metadata: %s (members checked=%d)",
                     full_name, len(expected_by_normalized))


def _validate_registered_enums(resolver: Il2CppResolutionManager) -> None:
    for full_name, enum_cls in RuntimeValidatableIl2CppClassManager._registered_enum_classes.items():
        typedef_index = _registered_typedef_index(resolver, full_name, "enum")
        if typedef_index is None:
            continue
        _validate_registered_enum(resolver, typedef_index, full_name, enum_cls)


def validate_registered_schema(resolver: Il2CppResolutionManager) -> None:
    _validate_registered_enums(resolver)
    _validate_registered_classes(resolver)
