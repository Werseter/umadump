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

    ``@register_enum`` additionally cross-checks local ``IntEnum`` member
    names, numeric values, and fixed-width ``value__`` storage against Il2Cpp
    enum metadata.  Direct ``C_Enum`` fields are checked against the exact
    reflected enum type, rather than only their byte offset.

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

``@register_enum(il2cpp_name, storage_type=c_int32)``
    Register an ``IntEnum`` with its exact IL2CPP storage.

Public function
---------------
``validate_registered_schema(resolver)``
    Call once after the ``Il2CppResolutionManager`` is ready to run all schema
    checks for registered classes.
"""
from __future__ import annotations

import re
from ctypes import CField, c_int32, sizeof
from dataclasses import dataclass
from struct import error as StructError
from typing import Any, Callable, ClassVar, NamedTuple, Optional, Protocol, cast as type_cast, get_type_hints

from ctypes_utils import CStructureDataclass, C_Ptr, EnumFieldBinding, EnumStorageManager, EnumStorageType, SafeIntEnum
from il2cpp_structs import Il2CppFieldDefinition, RuntimeIl2CppClass, RuntimeIl2CppObject, RuntimeIl2CppType
from il2cpp_utils import Il2CppResolutionManager, Il2CppTypeEnum, decode_integer_field_default
from logger import logger


class RuntimeValidatableIl2CppClass(Protocol):
    """Protocol for Il2Cpp object wrappers that carry a live ``_il2cpp_obj`` pointer."""

    _il2cpp_obj: RuntimeIl2CppObject


class RuntimeValidationError(RuntimeError):
    """Base error raised when a live Il2Cpp object fails runtime validation."""


class TransientRuntimeValidationError(RuntimeValidationError):
    """Raised when runtime validation observes an Il2Cpp object mid-update."""


class RuntimeTypeMetadataHandleMismatchError(RuntimeValidationError):
    """A live pointer does not name the expected Il2Cpp object type.

    This can be a pointer observed during a lifecycle update or a persistent reflection
    defect. Callers must keep it distinct from an unambiguously transient read failure.
    """


class RuntimeValidatableIl2CppClassManager:
    """
    Central registry for Il2Cpp wrapper classes that need schema or runtime validation.

    Schema-validatable classes are cross-checked against ``global-metadata.dat``
    field layouts at startup via ``validate_registered_classes()``.

    Runtime-validatable classes additionally get a per-access ``typeMetadataHandle``
    guard installed on their ``__getattribute__``.
    """
    _registered_schema_classes: ClassVar[dict[str, type[object]]] = dict()
    _registered_enum_classes: ClassVar[dict[str, type[SafeIntEnum]]] = dict()
    _registered_enum_name_by_class: ClassVar[dict[type[SafeIntEnum], str]] = dict()
    _runtime_validatable_class_names: ClassVar[set[str]] = set()
    _expected_type_metadata_handle_by_class: ClassVar[dict[type[object], int]] = dict()
    _subtype_match_cache: ClassVar[dict[tuple[int, int], bool]] = dict()

    @classmethod
    def register_schema_validatable(cls, il2cpp_name: str, wrapper_cls: type[object]) -> None:
        """Register *wrapper_cls* for metadata field-layout cross-check only."""
        cls._registered_schema_classes[il2cpp_name] = wrapper_cls

    @classmethod
    def register_enum(cls, il2cpp_name: str, enum_cls: type[SafeIntEnum], storage_type: EnumStorageType) -> None:
        """Register an enum's IL2CPP name and fixed-width storage declaration."""
        existing_name = cls._registered_enum_name_by_class.get(enum_cls)
        if existing_name is not None and existing_name != il2cpp_name:
            raise RuntimeError(f"{enum_cls.__name__} is already registered as {existing_name}")
        EnumStorageManager.configure_storage(enum_cls, storage_type)
        cls._registered_enum_classes[il2cpp_name] = enum_cls
        cls._registered_enum_name_by_class[enum_cls] = il2cpp_name

    @classmethod
    def registered_enum_name(cls, enum_cls: type[SafeIntEnum]) -> str | None:
        return cls._registered_enum_name_by_class.get(enum_cls)

    @classmethod
    def register_runtime_validatable(cls, il2cpp_name: str, wrapper_cls: type[RuntimeValidatableIl2CppClass]) -> None:
        """Register *wrapper_cls* for both schema cross-check and runtime ``typeMetadataHandle`` guard."""
        cls.register_schema_validatable(il2cpp_name, wrapper_cls)
        cls._runtime_validatable_class_names.add(il2cpp_name)

    @classmethod
    def is_runtime_validatable_name(cls, il2cpp_name: str) -> bool:
        return il2cpp_name in cls._runtime_validatable_class_names

    @classmethod
    def set_expected_type_metadata_handle(cls, wrapper_cls: type[object], type_metadata_handle: int) -> None:
        cls._expected_type_metadata_handle_by_class[wrapper_cls] = int(type_metadata_handle)

    @classmethod
    def get_expected_type_metadata_handle(cls, wrapper_cls: type[object]) -> int | None:
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
        raise TransientRuntimeValidationError(
                f"{inst_type.__name__} has null _il2cpp_obj.klass while accessing '{attr_name}'"
        )
    runtime_class_ptr = instance._il2cpp_obj.klass
    runtime_type_metadata_handle = runtime_class_ptr.contents.typeMetadataHandle.address
    if runtime_type_metadata_handle == 0:
        raise TransientRuntimeValidationError(
                f"{inst_type.__name__} has null _il2cpp_obj.klass.typeMetadataHandle "
                f"while accessing '{attr_name}'"
        )
    expected_type_metadata_handle = RuntimeValidatableIl2CppClassManager.get_expected_type_metadata_handle(inst_type)
    if expected_type_metadata_handle is not None and runtime_type_metadata_handle != expected_type_metadata_handle:
        if not _runtime_class_is_or_inherits_from(runtime_class_ptr, expected_type_metadata_handle):
            raise RuntimeTypeMetadataHandleMismatchError(
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
    enum_accessor_installed = bool(cls.__dict__.get("_ctypes_enum_getattribute_patched", False))
    if existing is not None and existing is not object.__getattribute__ and not enum_accessor_installed:
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


def register_schema_validatable[TWrapper: type[object]](il2cpp_name: str) -> Callable[[TWrapper], TWrapper]:
    """Register wrapper for metadata-schema validation only (no runtime __getattribute__ checks)."""

    def _decorator(cls: TWrapper) -> TWrapper:
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


_DEFAULT_ENUM_STORAGE_TYPE: EnumStorageType = type_cast(EnumStorageType, c_int32)


def register_enum[TEnum: SafeIntEnum](il2cpp_name: str, *, storage_type: EnumStorageType = _DEFAULT_ENUM_STORAGE_TYPE) \
        -> Callable[[type[TEnum]], type[TEnum]]:
    """Register an IL2CPP enum and the fixed-width storage used by ``value__``."""

    def _decorator(cls: type[TEnum]) -> type[TEnum]:
        RuntimeValidatableIl2CppClassManager.register_enum(il2cpp_name, cls, storage_type)
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


@dataclass(frozen=True)
class MetadataInstanceField:
    """Instance-field metadata retained for layout and enum identity validation."""

    metadata_field_index: int
    raw_name: str
    normalized_name: str
    type_index: int


def _read_metadata_instance_fields_by_offset(resolver: Il2CppResolutionManager, typedef_index: int) \
        -> Optional[dict[int, list[MetadataInstanceField]]]:
    """Collect all instance fields for *typedef_index* and its base classes.

    Walks the full inheritance chain (base → leaf) using
    ``_iter_typedef_chain_base_to_leaf`` and reads per-typedef field-offset tables
    from ``MetadataRegistration.fieldOffsets``.  Field byte offsets are normalized
    relative to the *first instance field encountered in the chain* so that the
    resulting map is directly comparable to ctypes wrapper offsets (which are also
    zero-based from the first field, not from the Il2Cpp object header).

    Returns
    -------
    dict mapping normalized byte offset → metadata fields, or ``None`` when
    field-offset data is unavailable.  The original type index lets direct
    ``C_Enum`` declarations be checked against the reflected enum typedef.
    """
    if not resolver.meta_reg.fieldOffsets:
        return None

    typedef_chain = _iter_typedef_chain_base_to_leaf(resolver, typedef_index)
    if not typedef_chain:
        return None

    field_offsets_count = int(resolver.meta_reg.fieldOffsetsCount)
    by_offset: dict[int, list[MetadataInstanceField]] = {}
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
            metadata_field_index = int(typedef.fieldStart) + local_index
            field_def = resolver.metadata.field_defs[metadata_field_index]

            field_offset = int(field_offset_raw.value)
            if field_offset < 0:
                continue

            if not _is_instance_field_from_metadata(resolver, field_def):
                continue

            if instance_base_offset is None:
                # Normalize once across the full inheritance chain.
                instance_base_offset = field_offset
            normalized_offset = field_offset - instance_base_offset

            raw_name = resolver.metadata.strings.get(field_def.nameIndex, "")
            normalized = _normalize_field_name(raw_name)
            if not normalized:
                continue
            by_offset.setdefault(normalized_offset, []).append(MetadataInstanceField(
                    metadata_field_index, raw_name, normalized, int(field_def.typeIndex)))

    return by_offset


class RegisteredFieldExpectation(NamedTuple):
    """One public ctypes field expected to correspond to reflected metadata.

    ``declared_type`` is the resolved source annotation when available;
    ``ctypes_type`` is the materialized carrier that controls layout.
    """

    name: str
    offset: int
    declared_type: object | None
    ctypes_type: object | None
    enum_binding: EnumFieldBinding | None


def _iter_expected_registered_fields(cls: type[CStructureDataclass]) -> list[RegisteredFieldExpectation]:
    """Return public ctypes field expectations declared by wrapper *cls*.

    Two wrapper shapes are supported:

    * **Object wrappers** – expose a nested ``fields`` ctypes struct (e.g.
      ``Il2CppObject`` subclass with a ``fields`` member).  Only the fields of that
      nested type are used; the enclosing object header is excluded.
    * **Value-type / sparse wrappers** – declare ``_fields_`` directly on *cls*.

    Private fields (names starting with ``_``) are excluded.  An empty list is
    returned for wrappers with no declared fields, which causes validation to be
    skipped (sparse / intentionally unvalidated classes).
    """
    expected: list[RegisteredFieldExpectation] = []

    # Object wrappers usually expose instance data through `fields`.
    cls_fields: Optional[CField[CStructureDataclass, Any, Any]] = getattr(cls, "fields", None)
    if cls_fields is not None:
        nested_fields_type = cls_fields.type
        storage_hints = get_type_hints(nested_fields_type)
        for field_name, _field_type in getattr(nested_fields_type, "_fields_", ()):
            if field_name.startswith("_"):
                continue
            field_desc = getattr(nested_fields_type, field_name)
            binding = (
                    EnumStorageManager.field_binding_for_instance_field(nested_fields_type, field_name)
                    or EnumStorageManager.field_binding_for_type(field_desc.type)
            )
            expected.append(RegisteredFieldExpectation(
                    field_name, int(field_desc.offset), storage_hints.get(field_name), field_desc.type, binding))
        return expected

    # Value-type wrappers (or sparse wrappers) can still be validated from top-level fields.
    storage_hints = get_type_hints(cls)
    for field_name, _field_type in getattr(cls, "_fields_", ()):
        if field_name.startswith("_"):
            continue
        field_desc = getattr(cls, field_name)
        binding = (
                EnumStorageManager.field_binding_for_instance_field(cls, field_name)
                or EnumStorageManager.field_binding_for_type(field_desc.type)
        )
        expected.append(RegisteredFieldExpectation(
                field_name, int(field_desc.offset), storage_hints.get(field_name), field_desc.type, binding))

    return expected


def _registered_instance_fields_type(cls: type[object]) -> type[CStructureDataclass] | None:
    cls_fields: Optional[CField[CStructureDataclass, Any, Any]] = getattr(cls, "fields", None)
    if cls_fields is not None:
        return cls_fields.type
    if getattr(cls, "_fields_", ()):
        return type_cast(type[CStructureDataclass], cls)
    return None


def _registered_field_storage_tail_offset(fields_type: type[CStructureDataclass]) -> int | None:
    tail_offset: int | None = None
    for field_name, _field_type in getattr(fields_type, "_fields_", ()):
        field_desc = getattr(fields_type, field_name)
        field_offset = int(field_desc.offset)
        field_storage_type = field_desc.type
        array_length = getattr(field_storage_type, "_length_", None)
        array_item_type = getattr(field_storage_type, "_type_", None)
        if isinstance(array_length, int) and array_length > 0 and array_item_type is not None:
            # noinspection PyTypeChecker
            field_tail_offset = field_offset + (array_length - 1) * sizeof(array_item_type)
        else:
            field_tail_offset = field_offset
        tail_offset = field_tail_offset if tail_offset is None else max(tail_offset, field_tail_offset)
    return tail_offset


def _validate_registered_layout_covers_metadata_tail(
        full_name: str, cls: type[object], metadata_fields_by_offset: dict[int, list[MetadataInstanceField]]) -> None:
    fields_type = _registered_instance_fields_type(cls)
    if fields_type is None:
        return

    wrapper_size = sizeof(fields_type)
    max_metadata_offset = max(metadata_fields_by_offset.keys())
    if max_metadata_offset >= wrapper_size:
        logger.debug(
                "%s metadata has instance fields beyond registered ctypes layout size %d "
                "(metadata_tail_offset=%d)",
                full_name,
                wrapper_size,
                max_metadata_offset,
        )

    wrapper_tail_offset = _registered_field_storage_tail_offset(fields_type)
    if wrapper_tail_offset is not None and wrapper_tail_offset > max_metadata_offset:
        logger.debug(
                "%s ctypes layout has fields beyond metadata tail offset %d "
                "(wrapper_tail_offset=%d)",
                full_name,
                max_metadata_offset,
                wrapper_tail_offset,
        )


def _validate_direct_enum_field(resolver: Il2CppResolutionManager, full_name: str, field_name: str,
                                metadata_field: MetadataInstanceField, binding: EnumFieldBinding) -> None:
    """Verify that a direct ``C_Enum`` field names the enum reflected in metadata."""
    if not binding.direct:
        # C_EnumIn describes semantic content in an outer value type such as
        # ObscuredInt; the field correctly reflects that outer type instead.
        return

    enum_full_name = RuntimeValidatableIl2CppClassManager.registered_enum_name(binding.enum_cls)
    if enum_full_name is None:
        logger.warning("%s field '%s' uses C_Enum[%s] but that enum is not registered",
                       full_name, field_name, binding.enum_cls.__name__)
        return

    expected_typedef_index = _registered_typedef_index(resolver, enum_full_name, "enum")
    if expected_typedef_index is None:
        return
    maybe_actual_typedef_index = resolver.typedef_index_for_runtime_type_index(metadata_field.type_index)
    if maybe_actual_typedef_index is None:
        logger.warning("%s enum field '%s' could not resolve metadata type index %d (expected %s)",
                       full_name, field_name, metadata_field.type_index, enum_full_name)
        return
    actual_typedef_index = maybe_actual_typedef_index
    if actual_typedef_index != expected_typedef_index:
        logger.warning(
                "%s enum field '%s' type mismatch: expected %s (typedef=%d), metadata type=%s "
                "(typedef=%d, typeIndex=%d)",
                full_name, field_name, enum_full_name, expected_typedef_index,
                resolver.full_name_for_typedef(actual_typedef_index), actual_typedef_index, metadata_field.type_index,
        )


def _validate_unbound_metadata_enum_field(
        resolver: Il2CppResolutionManager, full_name: str, field_name: str, metadata_field: MetadataInstanceField,
        registered_enums_by_typedef: dict[int, tuple[str, type[SafeIntEnum]]]) -> None:
    """Report a matched numeric field that metadata identifies as an enum."""
    metadata_typedef_index = resolver.typedef_index_for_runtime_type_index(metadata_field.type_index)
    if metadata_typedef_index is None or not resolver.is_enum_typedef(metadata_typedef_index):
        return
    registered = registered_enums_by_typedef.get(metadata_typedef_index)
    if registered is not None:
        enum_full_name, enum_cls = registered
        logger.warning("%s field '%s' reflects registered enum %s but has no C_Enum binding; use C_Enum[%s]",
                       full_name, field_name, enum_full_name, enum_cls.__name__)
        return
    logger.warning("%s field '%s' reflects unregistered enum %s; register it and use C_Enum[...]",
                   full_name, field_name, resolver.full_name_for_typedef(metadata_typedef_index))


def _validate_registered_class(
        resolver: Il2CppResolutionManager, typedef_index: int, full_name: str, cls: type[object],
        registered_enums_by_typedef: dict[int, tuple[str, type[SafeIntEnum]]]) -> None:
    """Cross-check the Python ctypes wrapper *cls* against metadata field offsets.

    For each public field declared in the wrapper, verifies that a metadata
    instance field with a matching camelCase name exists at the same normalized
    byte offset in the typedef's *full* inheritance chain.  Prints a Warning for
    each mismatch and a summary line on success.  Skips wrappers with no public
    fields (sparse / marker classes).
    """
    expected_fields = _iter_expected_registered_fields(type_cast(type[CStructureDataclass], cls))
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
    for expected_field in expected_fields:
        field_name = expected_field.name
        field_offset = expected_field.offset
        declared_type = expected_field.declared_type
        ctypes_type = expected_field.ctypes_type
        enum_binding = expected_field.enum_binding
        checked_public += 1
        normalized_py_name = _normalize_field_name(field_name)
        metadata_fields = metadata_fields_by_offset.get(field_offset, [])
        metadata_names = {metadata_field.normalized_name for metadata_field in metadata_fields}
        if normalized_py_name not in metadata_names:
            metadata_hint = ", ".join(sorted(metadata_names)) if metadata_names else "<none>"
            logger.warning("%s field '%s' (offset=%d) not found in metadata at same offset (metadata=%s)",
                           full_name, field_name, field_offset, metadata_hint)
        else:
            metadata_field = next(metadata_field for metadata_field in metadata_fields
                                  if metadata_field.normalized_name == normalized_py_name)
            if enum_binding is not None:
                _validate_direct_enum_field(resolver, full_name, field_name, metadata_field, enum_binding)
            else:
                _validate_unbound_metadata_enum_field(
                        resolver, full_name, field_name, metadata_field, registered_enums_by_typedef)
        if declared_type is not None and ctypes_type is not None and declared_type is not ctypes_type:
            logger.warning("%s field '%s' storage type mismatch: annotation=%s, ctypes=%s",
                           full_name, field_name, declared_type, ctypes_type)

    _validate_registered_layout_covers_metadata_tail(full_name, cls, metadata_fields_by_offset)
    logger.debug("Validated registered class in metadata: %s (public fields checked=%d)", full_name, checked_public)


def _update_expected_runtime_type_metadata_handle(resolver: Il2CppResolutionManager,
                                                  typedef_index: int,
                                                  full_name: str,
                                                  cls: type[object]) -> None:
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


def _validate_registered_classes(resolver: Il2CppResolutionManager,
                                 registered_enums_by_typedef: dict[int, tuple[str, type[SafeIntEnum]]]) -> None:
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
        _validate_registered_class(resolver, typedef_index, full_name, cls, registered_enums_by_typedef)


def _normalize_enum_member_name(name: str) -> str:
    return name.replace("_", "").lower()


def _metadata_enum_member_values(resolver: Il2CppResolutionManager, typedef_index: int,
                                 storage_type: EnumStorageType) -> dict[str, int | None]:
    typedef = resolver.metadata.type_defs[typedef_index]
    values: dict[str, int | None] = {}
    for local_index in range(typedef.field_count):
        field_index = typedef.fieldStart + local_index
        field_def = resolver.metadata.field_defs[typedef.fieldStart + local_index]
        name = resolver.metadata.strings.get(field_def.nameIndex, "")
        if name == "value__":
            continue
        raw_data = resolver.metadata.field_default_data_by_field_index.get(field_index)
        if raw_data is None:
            values[name] = None
            continue
        try:
            values[name] = EnumStorageManager.normalize_value(
                    decode_integer_field_default(raw_data, storage_type), storage_type)
        except (TypeError, ValueError, StructError):
            values[name] = None
    return values


def _validate_registered_enum_storage(resolver: Il2CppResolutionManager, typedef_index: int, full_name: str,
                                      enum_cls: type[SafeIntEnum]) -> EnumStorageType | None:
    """Check a local enum's declared storage against the reflected ``value__`` field."""
    typedef = resolver.metadata.type_defs[typedef_index]
    value_field: Il2CppFieldDefinition | None = None
    field_start = int(typedef.fieldStart)
    for local_index in range(int(typedef.field_count)):
        candidate = resolver.metadata.field_defs[field_start + local_index]
        if resolver.metadata.strings.get(int(candidate.nameIndex), "") == "value__":
            value_field = candidate
            break
    if value_field is None:
        logger.warning("%s enum has no value__ storage field in metadata", full_name)
        return None

    enum_runtime_type = resolver.runtime_type_for_type_index(int(typedef.byvalTypeIndex))
    if enum_runtime_type is None:
        logger.warning("%s enum runtime type could not be resolved", full_name)
    elif enum_runtime_type.get_type_bits() != Il2CppTypeEnum.VALUETYPE:
        logger.warning("%s registered enum has unexpected IL2CPP type bits 0x%X (expected VALUETYPE)",
                       full_name, enum_runtime_type.get_type_bits())

    maybe_metadata_storage_type = resolver.integer_ctype_for_type_index(int(value_field.typeIndex))
    if maybe_metadata_storage_type is None:
        logger.warning("%s enum value__ has unsupported or unresolved primitive type index %d",
                       full_name, int(value_field.typeIndex))
        return None

    metadata_storage_type = maybe_metadata_storage_type
    declared_storage_type = EnumStorageManager.storage_type(enum_cls)
    if metadata_storage_type is not declared_storage_type:
        logger.warning("%s enum storage mismatch: local=%s, metadata=%s (value__ typeIndex=%d)",
                       full_name, declared_storage_type.__name__, metadata_storage_type.__name__,
                       int(value_field.typeIndex))
    return metadata_storage_type


def _validate_registered_enum(resolver: Il2CppResolutionManager, typedef_index: int, full_name: str,
                              enum_cls: type[SafeIntEnum]) -> None:
    declared_storage_type = EnumStorageManager.storage_type(enum_cls)
    metadata_storage_type = _validate_registered_enum_storage(resolver, typedef_index, full_name, enum_cls)
    # Decode by the reflected storage where available: U1/U2/U4/U8 defaults do
    # not share I4's compressed signed representation.
    metadata_values = _metadata_enum_member_values(
            resolver, typedef_index, metadata_storage_type or declared_storage_type)
    expected_by_normalized = {
        _normalize_enum_member_name(member_name): (
            member_name, EnumStorageManager.normalize_value(int(member.value), declared_storage_type))
        for member_name, member in enum_cls.__members__.items()
    }
    metadata_by_normalized = {
        _normalize_enum_member_name(member_name): (member_name, value) for member_name, value in metadata_values.items()
    }

    missing = sorted(
            expected_by_normalized[name][0] for name in expected_by_normalized.keys() - metadata_by_normalized.keys())
    extra = sorted(
            metadata_by_normalized[name][0] for name in metadata_by_normalized.keys() - expected_by_normalized.keys())
    value_mismatches: list[str] = []
    unresolved_values: list[str] = []
    noncanonical_local_values: list[str] = []
    for member_name, member in enum_cls.__members__.items():
        raw_value = int(member.value)
        normalized_value = EnumStorageManager.normalize_value(raw_value, declared_storage_type)
        if raw_value != normalized_value:
            noncanonical_local_values.append(f"{member_name}: local={raw_value}, canonical={normalized_value}")
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
    if noncanonical_local_values:
        logger.warning("%s enum members outside declared storage range: %s",
                       full_name, "; ".join(sorted(noncanonical_local_values)))
    storage_matches = metadata_storage_type is declared_storage_type
    if (not missing and not extra and not unresolved_values and not value_mismatches and not noncanonical_local_values
            and storage_matches):
        logger.debug("Validated registered enum in metadata: %s (members checked=%d)",
                     full_name, len(expected_by_normalized))


def _validate_registered_enums(resolver: Il2CppResolutionManager) -> dict[int, tuple[str, type[SafeIntEnum]]]:
    """Validate enums and return their resolved typedef identities for field checks."""
    registered_enums_by_typedef: dict[int, tuple[str, type[SafeIntEnum]]] = {}
    for full_name, enum_cls in RuntimeValidatableIl2CppClassManager._registered_enum_classes.items():
        typedef_index = _registered_typedef_index(resolver, full_name, "enum")
        if typedef_index is None:
            continue
        _validate_registered_enum(resolver, typedef_index, full_name, enum_cls)
        registered_enums_by_typedef[typedef_index] = (full_name, enum_cls)
    return registered_enums_by_typedef


def validate_registered_schema(resolver: Il2CppResolutionManager) -> None:
    registered_enums_by_typedef = _validate_registered_enums(resolver)
    _validate_registered_classes(resolver, registered_enums_by_typedef)
