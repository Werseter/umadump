#!/usr/bin/env python3
"""
Low-level ctypes infrastructure for Il2Cpp struct definitions.

Contains no Il2Cpp-specific types — only the generic building blocks used by
both il2cpp_structs (struct definitions) and il2cpp_utils (resolution logic):
  - ExplicitStructure / StructOrSimple
  - ArrayType, C_Int
  - RemappablePointerValue, set_pointer_reader, Span, C_Ptr, C_VoidPtr, C_UDeclPtr
  - CDataclassMeta, CStructureDataclassMeta, CStructureDataclass
"""
from __future__ import annotations

import ctypes
from ctypes import Array, Structure, c_char, c_uint64, c_void_p, sizeof
from dataclasses import dataclass, fields
from typing import (Any, Callable, ClassVar, Generic, Iterator, Literal as L, Optional, Sequence, TYPE_CHECKING,
                    TypeAlias,
                    TypeVar, cast as type_cast, get_args, get_origin, get_type_hints, no_type_check)

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


class CStructureDataclassMeta(CDataclassMeta, _ExplicitPyCStructType):
    pass


class CStructureDataclass(ExplicitStructure, metaclass=CStructureDataclassMeta):
    pass


class ArrayType[T, _L](list[T]):
    """Creates a fixed-length ctypes array type from ``ArrayType[element_type, L[count]]``."""

    @classmethod
    def __class_getitem__[CDT: StructOrSimple](  # type: ignore[override]
            cls, item: tuple[type[CDT], L]) -> type[Array[CDT]]:  # type: ignore[valid-type]
        if TYPE_CHECKING:
            return Array[CDT]  # type hinting only; never actually used at runtime
        t, n = item  # ArrayType[SomeType, L[5]] → item == (SomeType, 5)
        n = type_cast(int, get_args(n)[0])  # Extract the literal value (e.g. 5) from L[5]
        if not n:
            return c_void_p * 0  # Return a zero-length array type for L[0] to avoid invalid array sizes
        return t * n


class StrArrayType[T, _L](str):
    """
    Creates a fixed-length ctypes array type from ``ArrayType[element_type, L[count]]``,
    exposes the final type as str instead of Array[T]
    """

    @classmethod
    def __class_getitem__[CDT: StructOrSimple](
            cls, item: tuple[type[CDT], L]) -> type[str]:  # type: ignore[valid-type]
        if TYPE_CHECKING:
            return str  # type hinting only; never actually used at runtime
        t, n = item  # ArrayType[SomeType, L[5]] → item == (SomeType, 5)
        n = type_cast(int, get_args(n)[0])  # Extract the literal value (e.g. 5) from L[5]
        return t * n


# noinspection PyPep8Naming
class C_Int[CDT: StructOrSimple](int):
    """
    Wrapper for implicit runtime __ctypes_from_outparam__ conversion of c_int* types to
    Python int on metadata struct fields.
    """

    @classmethod
    def __class_getitem__(cls, item: type[CDT]) -> type[int]:
        if TYPE_CHECKING:
            return int  # type hinting only; never actually used at runtime
        return item  # Just return the type itself (e.g. c_int32) for wrapper purposes


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
