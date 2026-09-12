#!/usr/bin/env python3
"""
Low-level ctypes infrastructure for Il2Cpp struct definitions.

Contains no Il2Cpp-specific types — only the generic building blocks used by
both il2cpp_structs (struct definitions) and il2cpp_utils (resolution logic):
  - ExplicitStructure / StructOrSimple
  - ArrayType, C_Bool, C_Int, C_Enum, C_EnumIn
  - RemappablePointerValue, set_pointer_reader, Span, C_Ptr, C_VoidPtr, C_UDeclPtr
  - CDataclassMeta, CStructureDataclassMeta, CStructureDataclass
"""
from __future__ import annotations

import ctypes
from ctypes import (Array, Structure, c_bool, c_char, c_double, c_float, c_int16, c_int32, c_int64, c_int8, c_uint16,
                    c_uint32, c_uint64, c_uint8, c_void_p, sizeof)
from dataclasses import dataclass, fields
from enum import IntEnum
from typing import (Any, Callable, ClassVar, Generic, Iterator, Literal as L, Optional, Self, Sequence, TYPE_CHECKING,
                    TypeAlias, TypeVar, cast as type_cast, get_args, get_origin, get_type_hints, no_type_check)

if TYPE_CHECKING:
    from _ctypes import _CDataType, _CData, _PyCSimpleType, _SimpleCData

    # Customized ctypes.Structure and _PyCStructType annotation stub that don't return Any
    # in getattr/setattr (which are part of the typeshed's stubs). This is accomplished by using _PyCSimpleType as a
    # metaclass for ExplicitStructure instead of _PyCStructType even if it's not entirely accurate

    # This is needed to root out invalid accesses to non-existent fields in the struct definitions,
    # which would otherwise be silently accepted by the default signatures
    # (since _fields_ are handled at runtime). It also allows for Protocol-based structure validation.
    _ExplicitPyCStructType = _PyCSimpleType


    class ExplicitStructure(_CData, metaclass=_ExplicitPyCStructType):
        _fields_: ClassVar[list[tuple[str, type[_CDataType]]]]
        _pack_: ClassVar[int]
        _anonymous_: ClassVar[list[str]]
        _align_: ClassVar[int]

else:
    _SimpleCData = ctypes.c_uint64.__base__
    _ExplicitPyCStructType = type(Structure)
    ExplicitStructure = Structure

StructOrSimple: TypeAlias = ExplicitStructure | _SimpleCData  # type: ignore[type-arg]
type EnumStorageType = type[c_int8 | c_uint8 | c_int16 | c_uint16 | c_int32 | c_uint32 | c_int64 | c_uint64]
type ScalarStorageType = EnumStorageType | type[c_bool | c_float | c_double]


class SafeIntEnum(IntEnum):
    """``IntEnum`` that tolerates game values introduced after our declarations."""

    @classmethod
    def _missing_(cls, value: object) -> Self | None:
        """Represent a newly introduced numeric value without losing its enum type."""
        if not isinstance(value, int):
            return None
        return SafeIntEnumManager.resolve_unknown_member(cls, value)

    @classmethod
    def value_to_name(cls, value: int) -> str:
        member = cls(value)
        return member.name if member.name is not None else "UNKNOWN"


@dataclass(frozen=True)
class EnumFieldBinding:
    """Semantic enum information retained beside a materialized ctypes field."""

    enum_cls: type[SafeIntEnum]
    storage_type: EnumStorageType
    direct: bool


class SafeIntEnumManager:
    """Own validation and pseudo-members for the project's enum classes."""

    _unknown_members: ClassVar[dict[tuple[type[SafeIntEnum], int], SafeIntEnum]] = dict()

    @staticmethod
    def require_enum_class(enum_cls: type[SafeIntEnum]) -> type[SafeIntEnum]:
        if not issubclass(enum_cls, SafeIntEnum):
            raise TypeError(f"C_Enum requires a SafeIntEnum, got {enum_cls!r}")
        return enum_cls

    @classmethod
    def resolve_unknown_member[E: SafeIntEnum](cls, enum_cls: type[E], value: int) -> E:
        """Return the stable pseudo-member for an unknown value of *enum_cls*."""
        existing = cls._unknown_members.get((enum_cls, value))
        if existing is not None:
            return type_cast(E, existing)
        # noinspection PyTypeChecker
        pseudo_member: E = int.__new__(enum_cls, value)
        object.__setattr__(pseudo_member, "_name_", None)
        object.__setattr__(pseudo_member, "_value_", value)
        cls._unknown_members[enum_cls, value] = pseudo_member
        return pseudo_member


class EnumStorageManager:
    """Own enum storage declarations and their materialized ctypes field types."""

    SUPPORTED_STORAGE_TYPES: ClassVar[frozenset[EnumStorageType]] = frozenset({
        c_int8, c_uint8, c_int16, c_uint16, c_int32, c_uint32, c_int64, c_uint64,
    })
    _storage_by_class: ClassVar[dict[type[SafeIntEnum], EnumStorageType]] = dict()
    _direct_field_type_cache: ClassVar[dict[type[SafeIntEnum], EnumStorageType]] = dict()
    _embedded_field_type_cache: ClassVar[
        dict[tuple[type[SafeIntEnum], type[StructOrSimple]], type[StructOrSimple]]
    ] = dict()

    @classmethod
    def _require_supported_storage_type(cls, storage_type: EnumStorageType) -> EnumStorageType:
        if storage_type not in cls.SUPPORTED_STORAGE_TYPES:
            supported = ", ".join(t.__name__ for t in cls.SUPPORTED_STORAGE_TYPES)
            raise TypeError(f"Unsupported enum storage type {storage_type!r}; expected one of {supported}")
        return storage_type

    @classmethod
    def _storage_type_for_safe_enum(cls, enum_cls: type[SafeIntEnum]) -> EnumStorageType:
        storage_type = cls._storage_by_class.get(enum_cls, c_int32)
        return cls._require_supported_storage_type(storage_type)

    @classmethod
    def storage_type(cls, enum_cls: type[SafeIntEnum]) -> EnumStorageType:
        """Return the fixed-width ctypes storage declared for *enum_cls*."""
        return cls._storage_type_for_safe_enum(SafeIntEnumManager.require_enum_class(enum_cls))

    @classmethod
    def configure_storage(cls, enum_cls: type[SafeIntEnum], storage_type: EnumStorageType) -> None:
        """Register storage before a layout materializes the enum's field type."""
        safe_enum_cls = SafeIntEnumManager.require_enum_class(enum_cls)
        storage_type = cls._require_supported_storage_type(storage_type)
        current_storage_type = cls._storage_type_for_safe_enum(safe_enum_cls)
        is_materialized = safe_enum_cls in cls._direct_field_type_cache or any(
                cache_key[0] is safe_enum_cls for cache_key in cls._embedded_field_type_cache
        )
        if is_materialized and current_storage_type is not storage_type:
            raise RuntimeError(
                    f"Cannot change {safe_enum_cls.__name__} enum storage from {current_storage_type.__name__} "
                    f"to {storage_type.__name__} after it has been used in a ctypes layout"
            )
        cls._storage_by_class[safe_enum_cls] = storage_type

    @classmethod
    def normalize_value(cls, value: int, storage_type: EnumStorageType) -> int:
        """Coerce an integer to the signedness and width of *storage_type*."""
        return int(cls._require_supported_storage_type(storage_type)(value).value)

    @staticmethod
    def field_binding_for_type(field_type: object) -> EnumFieldBinding | None:
        """Return semantic enum metadata carried by a materialized field type."""
        binding = getattr(field_type, "__ctypes_enum_field_binding__", None)
        return binding if isinstance(binding, EnumFieldBinding) else None

    @staticmethod
    def field_binding_for_instance_field(wrapper_cls: type[object], field_name: str) -> EnumFieldBinding | None:
        """Return enum metadata for a declared field on a wrapper class."""
        bindings = type_cast(
                dict[str, EnumFieldBinding],
                getattr(wrapper_cls, "__ctypes_enum_field_bindings__", {}),
        )
        return bindings.get(field_name)

    @classmethod
    def configure_class_field_bindings(cls, wrapper_cls: type[object], field_types: dict[str, object]) -> None:
        """Record field bindings and install direct-enum conversion when needed."""
        inherited_bindings: dict[str, EnumFieldBinding] = {}
        # noinspection PyUnresolvedReferences
        for base in reversed(wrapper_cls.__mro__[1:]):
            inherited_bindings.update(getattr(base, "__ctypes_enum_field_bindings__", {}))
        own_bindings = {
            field_name: binding
            for field_name, field_type in field_types.items()
            if (binding := cls.field_binding_for_type(field_type)) is not None
        }
        setattr(wrapper_cls, "__ctypes_enum_field_bindings__", inherited_bindings | own_bindings)
        if own_bindings:
            cls._install_direct_enum_conversion(wrapper_cls)

    @classmethod
    def _install_direct_enum_conversion(cls, wrapper_cls: type[object]) -> None:
        """Install per-class direct-enum conversion without widening its static API."""
        if bool(wrapper_cls.__dict__.get("_ctypes_enum_getattribute_patched", False)):
            return

        existing = wrapper_cls.__dict__.get("__getattribute__")
        if existing is not None and existing is not object.__getattribute__:
            raise TypeError(
                    f"Cannot install enum access conversion on {wrapper_cls.__name__} with custom __getattribute__"
            )
        if bool(getattr(wrapper_cls, "_ctypes_enum_getattribute_patched", False)):
            return

        original_getattribute = type_cast(Callable[[object, str], object], wrapper_cls.__getattribute__)

        def _enum_converting_getattribute(instance: object, name: str) -> object:
            value = original_getattribute(instance, name)
            binding = cls.field_binding_for_instance_field(type(instance), name)
            if binding is None or not binding.direct:
                return value
            raw_value = getattr(value, "value", value)
            if not isinstance(raw_value, int):
                raise TypeError(f"Direct enum field {name!r} has non-integer value {raw_value!r}")
            return binding.enum_cls(cls.normalize_value(raw_value, binding.storage_type))

        setattr(wrapper_cls, "__getattribute__", _enum_converting_getattribute)
        setattr(wrapper_cls, "_ctypes_enum_getattribute_patched", True)

    @staticmethod
    def _materialize_field_type[S: StructOrSimple](name: str, storage_type: type[S],
                                                   binding: EnumFieldBinding) -> type[S]:
        attributes: dict[str, object] = {
            "__module__": binding.enum_cls.__module__,
            "__ctypes_enum_field_binding__": binding,
        }
        return type_cast(type[S], type(name, (storage_type,), attributes))

    @classmethod
    def direct_field_type_for(cls, enum_cls: type[SafeIntEnum]) -> EnumStorageType:
        """Materialize a direct enum field as its concrete ctypes scalar."""
        safe_enum_cls = SafeIntEnumManager.require_enum_class(enum_cls)
        cached = cls._direct_field_type_cache.get(safe_enum_cls)
        if cached is not None:
            return cached
        storage_type = cls._storage_type_for_safe_enum(safe_enum_cls)
        binding = EnumFieldBinding(safe_enum_cls, storage_type, direct=True)
        materialized = type_cast(EnumStorageType, cls._materialize_field_type(
                f"C_Enum[{safe_enum_cls.__name__}]", storage_type, binding,
        ))
        cls._direct_field_type_cache[safe_enum_cls] = materialized
        return materialized

    @classmethod
    def embedded_field_type_for[S: StructOrSimple](cls, enum_cls: type[SafeIntEnum], storage_type: type[S]) -> type[S]:
        """Materialize a layout-preserving enum carrier for an embedded storage type."""
        safe_enum_cls = SafeIntEnumManager.require_enum_class(enum_cls)
        try:
            sizeof(storage_type)
        except TypeError as exc:
            raise TypeError(f"C_EnumIn storage must be a ctypes type, got {storage_type!r}") from exc
        cache_key = type_cast(tuple[type[SafeIntEnum], type[StructOrSimple]], (safe_enum_cls, storage_type))
        cached = cls._embedded_field_type_cache.get(cache_key)
        if cached is not None:
            return type_cast(type[S], cached)
        binding = EnumFieldBinding(safe_enum_cls, cls._storage_type_for_safe_enum(safe_enum_cls), direct=False)
        materialized = cls._materialize_field_type(
                f"C_EnumIn[{safe_enum_cls.__name__}, {getattr(storage_type, '__name__', repr(storage_type))}]",
                storage_type,
                binding,
        )
        cls._embedded_field_type_cache[cache_key] = type_cast(type[StructOrSimple], materialized)
        return materialized


class CDataclassMeta(type):
    """
    Metaclass that auto-applies @dataclass(init=False) and builds ctypes _fields_.

    Python 3.13+ constraint: ctypes requires _fields_ to be assigned *after*
    type.__init__ completes, so field construction lives in __init__, not __new__.
    """

    def __new__(mcs, name: str, bases: tuple[type, ...],
                namespace: dict[str, Any], **kwargs: Any) -> type:
        cls: type = super().__new__(mcs, name, bases, namespace, **kwargs)
        # noinspection PyTypeChecker
        return dataclass(init=False)(cls)

    def __init__(cls, name: str, bases: tuple[type, ...], namespace: dict[str, Any]) -> None:
        super().__init__(name, bases, namespace)
        cls._build_fields()

    def _build_fields(cls) -> None:
        own_annotations = cls.__dict__.get("__annotations__", {})
        if not own_annotations:
            return

        resolved_hints = get_type_hints(cls)
        # Only materialize ctypes fields declared directly on this class.
        # This avoids inherited mixin annotations affecting struct layout.
        type_hints = {k: resolved_hints[k] for k in own_annotations if k in resolved_hints}
        if not type_hints:
            return

        # noinspection PyDataclass
        dc_fields = {f.name: f for f in fields(cls)}  # type: ignore[arg-type]
        filtered = {k: v for k, v in type_hints.items() if k in dc_fields}
        if filtered:
            cls._fields_ = list(tuple(filtered.items()))

        # noinspection PyTypeChecker
        EnumStorageManager.configure_class_field_bindings(cls, filtered)


class CStructureDataclassMeta(CDataclassMeta, _ExplicitPyCStructType):
    pass


class CStructureDataclass(ExplicitStructure, metaclass=CStructureDataclassMeta):
    # Written by ``CDataclassMeta._build_fields``.  This ClassVar deliberately
    # does not contribute to ctypes layout.
    __ctypes_enum_field_bindings__: ClassVar[dict[str, EnumFieldBinding]] = {}


if TYPE_CHECKING:
    # ctypes fields expose these values as Python primitives.  The type aliases
    # provide that access contract while their runtime facades below return the
    # actual ctypes type required to construct the layout.
    type ArrayType[T, _L] = Array[T]
    type StrArrayType[T, _L] = str
    type C_Int[X: StructOrSimple] = int
    type C_Float[X: StructOrSimple] = float
    type C_Bool[X: StructOrSimple] = bool
    type C_Enum[E: SafeIntEnum] = E
    type C_EnumIn[E: SafeIntEnum, S: StructOrSimple] = S
else:
    class ArrayType:
        """Create a fixed-length ctypes array from ``ArrayType[element_type, L[count]]``."""

        @classmethod
        def __class_getitem__[CDT: StructOrSimple](cls, item: tuple[type[CDT], L]) -> type[Array[CDT]]:
            element_type, length = item
            count = type_cast(int, get_args(length)[0])
            if not count:
                return c_void_p * 0
            return element_type * count


    class StrArrayType:
        """Create a fixed-length ctypes array whose field reads as ``str``."""

        @classmethod
        def __class_getitem__[CDT: StructOrSimple](cls, item: tuple[type[CDT], L]) -> type[Array[CDT]]:
            element_type, length = item
            return element_type * type_cast(int, get_args(length)[0])


    # noinspection PyPep8Naming
    class C_Int:
        """Runtime façade for ctypes integer fields exposed as Python ``int``."""

        @classmethod
        def __class_getitem__[CDT: StructOrSimple](cls, item: type[CDT]) -> type[CDT]:
            return item


    # noinspection PyPep8Naming
    class C_Float:
        """Runtime façade for ctypes float fields exposed as Python ``float``."""

        @classmethod
        def __class_getitem__[CDT: StructOrSimple](cls, item: type[CDT]) -> type[CDT]:
            return item


    # noinspection PyPep8Naming
    class C_Bool:
        """Runtime façade for ``c_bool`` fields exposed as Python ``bool``."""

        @classmethod
        def __class_getitem__(cls, item: type[c_bool]) -> type[c_bool]:
            return item


    # noinspection PyPep8Naming
    class C_Enum:
        """Runtime façade that materializes a ctypes scalar for an enum field."""

        @classmethod
        def __class_getitem__(cls, enum_cls: type[SafeIntEnum]) -> EnumStorageType:
            return EnumStorageManager.direct_field_type_for(enum_cls)


    # noinspection PyPep8Naming
    class C_EnumIn:
        """Runtime façade that preserves an enclosing enum carrier's layout."""

        @classmethod
        def __class_getitem__[S: StructOrSimple](cls, item: tuple[type[SafeIntEnum], type[S]]) -> type[S]:
            enum_cls, storage_type = item
            return EnumStorageManager.embedded_field_type_for(enum_cls, storage_type)

PointerReader = Callable[[int, int], bytes]


# noinspection PyClassVar
class RuntimeGenericMixin[CDT: StructOrSimple]:
    """Mixin for pointer types that need to resolve their target type at runtime."""
    _target_type: ClassVar[Optional[type[CDT]]] = None
    _typed_cache: ClassVar[dict[type[CDT], type[RuntimeGenericMixin[CDT]]]] = {}

    # noinspection PyTypeChecker
    @no_type_check
    @classmethod
    def __class_getitem__(cls, item: type[CDT]) -> type[RuntimeGenericMixin[CDT]]:
        if item in cls._typed_cache:
            return cls._typed_cache[item]
        type_name = getattr(item, "__name__", repr(item))
        subtype_dict = {"_target_type": item, "_typed_cache": {}, '__module__': cls.__module__}
        if (cls_annotations := cls._patch_generic_annotations(item)) is not None:
            subtype = cls._patch_generic_subtype(cls_annotations, item, subtype_dict)
        else:
            subtype = type_cast(type[RuntimeGenericMixin],  # type: ignore[type-arg]
                                type(f"{cls.__name__}[{type_name}]", (cls,), subtype_dict))
        cls._typed_cache[item] = subtype
        return subtype

    @classmethod
    def _patch_generic_subtype(cls, cls_annotations: dict[str, Any], item: type[CDT],
                               subtype_dict: dict[str, Any]) -> type[RuntimeGenericMixin[CDT]]:
        # patch has to be sideloaded as CField annotations have already been processed by the base metaclass and
        # won't be re-evaluated for the new subclass, so we need to apply them directly to the new subclass dict
        # before creation. This is done by copying the base class dict and updating the annotations, which also
        # allows us to preserve any existing annotations on the base class (e.g. from mixins) without modifying
        # the original base class.
        type_name = getattr(item, "__name__", repr(item))
        subtype_dict["__annotations__"] = cls_annotations

        # Introspect cls for method descriptors that would be lost when changing to cls.__base__.
        # Extract and transfer them to subtype_dict so sister-types retain these methods.
        for attr_name, attr in cls.__dict__.items():
            if callable(attr) or isinstance(attr, (property, classmethod, staticmethod)):
                subtype_dict[attr_name] = attr

        bases = tuple(b for b in cls.__bases__ if b is not Generic)
        subtype = type_cast(type[RuntimeGenericMixin],  # type: ignore[type-arg]
                            type(f"{cls.__name__}[{type_name}]", bases, subtype_dict))
        return subtype

    @classmethod
    def _has_unresolved_typevars(cls, hint_type: Any) -> bool:
        """Recursively check if a type hint contains any unresolved TypeVars."""
        if isinstance(hint_type, TypeVar):
            return True

        # Check if it's a RuntimeGenericMixin subclass with unresolved _target_type
        try:
            if issubclass(hint_type, RuntimeGenericMixin):
                target = hint_type._target_type
                # Recursively check if the target type has unresolved TypeVars
                return cls._has_unresolved_typevars(target)
        except TypeError:
            pass

        # Check generic args (e.g., Union[CDT, int] or List[CDT])
        args = get_args(hint_type)
        if args:
            return any(cls._has_unresolved_typevars(arg) for arg in args)

        return False

    @classmethod
    def _resolve_hint_with_concrete_type(cls, hint_type: Any, item: type[CDT]) -> Optional[Any]:
        """
        Recursively resolve a type hint by replacing unresolved TypeVars with item.
        Returns the resolved type, or None if no substitution was needed.
        """
        # If it's a plain TypeVar, replace it with item
        if isinstance(hint_type, TypeVar):
            return item

        # Check if it's a RuntimeGenericMixin with unresolved _target_type
        try:
            if issubclass(hint_type, RuntimeGenericMixin):
                hint_type = type_cast(type[RuntimeGenericMixin], hint_type)  # type: ignore[type-arg]
                target = hint_type._target_type
                # Recursively resolve the target type
                resolved_target = cls._resolve_hint_with_concrete_type(target, item)
                if resolved_target is not None:
                    # Re-specialize the pointer/mixin with the resolved target type
                    return hint_type.__base__[resolved_target]
                elif isinstance(target, TypeVar):
                    # Direct TypeVar target: specialize directly
                    return hint_type.__base__[item]
        except TypeError:
            pass

        # If it's a generic type with args, recursively resolve them
        origin = get_origin(hint_type)
        if origin is not None:
            args = get_args(hint_type)
            resolved_args = tuple(cls._resolve_hint_with_concrete_type(arg, item) or arg for arg in args)
            # Only reconstruct if something changed
            if resolved_args != args:
                return origin[resolved_args]

        return None

    @classmethod
    def _patch_generic_annotations(cls, item: type[CDT]) -> Optional[dict[str, Any]]:
        if isinstance(item, TypeVar):
            return None
        # Work on a per-specialization copy; never mutate base class annotations in place.
        # noinspection PyTypeChecker
        cls_annotations: dict[str, Any] = dict(cls.__dict__.get("__annotations__", {}))
        cls_type_hints = {k: v for k, v in get_type_hints(cls).items() if k in cls_annotations}
        patch_required = False
        for hint_name, hint_type in cls_type_hints.items():
            # Check if hint_type is a RuntimeGenericMixin with unresolved TypeVars
            try:
                is_runtime_generic = issubclass(hint_type, RuntimeGenericMixin)
            except TypeError:
                is_runtime_generic = False

            if is_runtime_generic and isinstance(hint_type._target_type, TypeVar):
                # Direct case: hint_type itself has TypeVar target (e.g., GenericArrayPtr[CDT])
                # noinspection PyUnresolvedReferences
                new_hint = hint_type.__base__[item]
                cls_annotations[hint_name] = new_hint
                patch_required = True
            elif cls._has_unresolved_typevars(hint_type):
                # Recursive case: hint_type contains unresolved TypeVars (e.g., C_Ptr[GenericArray[CDT]])
                resolved_hint = cls._resolve_hint_with_concrete_type(hint_type, item)
                if resolved_hint is not None:
                    cls_annotations[hint_name] = resolved_hint
                    patch_required = True
        if not patch_required:
            return None
        return cls_annotations

    @classmethod
    def _resolve_class_target_type(cls) -> type[CDT]:
        resolved = cls._target_type
        if resolved is None:
            raise TypeError("Pointer target type is not specified")
        return resolved


# noinspection PyClassVar
@dataclass
class RemappablePointerValue[CDT: StructOrSimple](c_uint64, RuntimeGenericMixin[CDT]):
    """ctypes scalar pointer with memory mapping and transparent dereference helpers."""

    @staticmethod
    def _missing_pointer_reader(_address: int, _size: int) -> bytes:
        raise RuntimeError("Pointer dereference reader is not configured; initialize a MemoryReader first")

    _reader: ClassVar[PointerReader] = _missing_pointer_reader
    value: int

    @classmethod
    def set_reader(cls, reader: Optional[PointerReader]) -> None:
        cls._reader = reader or RemappablePointerValue._missing_pointer_reader

    @property
    def address(self) -> int:
        return int(self.value)

    @classmethod
    def _read_many_typed(cls, resolved: type[CDT], addresses: Sequence[int]) -> list[CDT]:
        size = sizeof(resolved)
        return [type_cast(CDT, resolved.from_buffer_copy(cls._reader(int(addr), size))) for addr in addresses]

    def deref(self, index: int = 0) -> CDT:
        if self.address == 0:
            raise ValueError("Cannot dereference null pointer")
        resolved = type(self)._resolve_class_target_type()
        size = sizeof(resolved)
        return type(self)._read_many_typed(resolved, [self.address + index * size])[0]

    @classmethod
    def deref_many_at(cls, addresses: Sequence[int]) -> list[CDT]:
        """Dereference an arbitrary sequence of addresses as this pointer's target type."""
        if not addresses:
            return []
        return cls._read_many_typed(cls._resolve_class_target_type(), addresses)

    @property
    def contents(self) -> CDT:
        return self.deref()

    def as_span(self, count: int) -> Span[CDT]:
        return Span(self, count)

    def __getitem__(self, key: int, /) -> CDT:
        return self.deref(key)

    def __int__(self) -> int:
        return self.address

    def __bool__(self) -> bool:
        return self.address != 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (int, RemappablePointerValue)):
            return False
        return self.address == int(other)


def set_pointer_reader(reader: Optional[PointerReader]) -> None:
    RemappablePointerValue.set_reader(reader)


class PointerWrapperMixin:
    """Address-only operations for structures containing a private pointer.

    Truthiness means pointer presence, including non-null empty strings/arrays.
    These operations never dereference the target.
    """

    @property
    def address(self) -> int:
        raise NotImplementedError

    def __bool__(self) -> bool:
        return self.address != 0

    def __int__(self) -> int:
        return self.address


class Span[TSpan: StructOrSimple]:
    """Lightweight view over a pointer and element count."""

    def __init__(self, pointer: RemappablePointerValue[TSpan], count: int) -> None:
        self.pointer = pointer
        self.count = max(0, int(count))

    def __len__(self) -> int:
        return self.count

    def __iter__(self) -> Iterator[TSpan]:
        for i in range(self.count):
            yield self.pointer[i]

    def __getitem__(self, index: int) -> TSpan:
        if index < 0 or index >= self.count:
            raise IndexError(f"Index {index} out of range [0, {self.count})")
        return self.pointer[index]


# noinspection PyTypeChecker, PyPep8Naming
class C_Ptr[CDT: Optional[StructOrSimple]](RemappablePointerValue[CDT]):  # type: ignore[type-var]
    pass


# noinspection PyPep8Naming
class C_CharPtr(C_Ptr[c_char]):
    @property
    def as_string(self) -> str:
        if self.address == 0:
            return ""
        count = 0
        while self[count].value != b"\x00":
            count += 1
        return b"".join(char.value for char in self.as_span(count)).decode("utf-8", errors="replace")


# Alias for void* pointers (type known to be exactly void*)
# noinspection PyTypeChecker
C_VoidPtr = C_Ptr[None]
# Alias for unreflected fields (for documentation purposes only)
C_UDeclPtr = C_VoidPtr
