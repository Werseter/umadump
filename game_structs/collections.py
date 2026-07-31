from __future__ import annotations

from ctypes import c_int32, c_uint64
from typing import Iterator, Literal as L, cast as type_cast

from ctypes_utils import (ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr, C_VoidPtr, RuntimeGenericMixin,
                          Span, StructOrSimple)
from il2cpp_structs import RuntimeIl2CppObject


# ---------------------------------------------------------------------------
# Generic Managed Containers
# ---------------------------------------------------------------------------

class GenericArray[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``System.Array`` layout with flexible ``m_items`` tail."""

    _il2cpp_obj: RuntimeIl2CppObject
    _ignored_1: C_UDeclPtr  # bounds
    max_length: C_Int[c_uint64]
    m_items: ArrayType[CDT, L[0]]


class GenericArrayPtr[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Typed pointer to ``GenericArray[T]`` with span/iteration helpers."""

    inner_ptr: C_Ptr[GenericArray[CDT]]

    def span(self) -> Span[CDT]:
        """Return a ``Span`` over the array payload (``m_items``)."""

        if not self.inner_ptr:
            return Span(self.inner_ptr, 0)  # type: ignore[arg-type]
        count = self.inner_ptr.contents.max_length
        item_type = self._resolve_class_target_type()
        m_items_ptr = int(self.inner_ptr) + int(getattr(GenericArray, 'm_items').offset)
        # noinspection PyTypeHints
        items_ptr = C_Ptr[item_type](m_items_ptr)  # type: ignore[valid-type]
        return items_ptr.as_span(count)

    def __iter__(self) -> Iterator[CDT]:
        return iter(self.span())

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


class GenericListFields[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    items: GenericArrayPtr[CDT]
    size: C_Int[c_int32]
    version: C_Int[c_int32]
    _ignored_1: C_UDeclPtr  # _syncRoot


class GenericList[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``List<T>`` wrapper with size-limited iteration."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericListFields[CDT]

    def span(self) -> Span[CDT]:
        if self.fields.size == 0:
            return Span(self.fields.items.inner_ptr, 0)  # type: ignore[arg-type]
        return self.fields.items.span()

    def __iter__(self) -> Iterator[CDT]:
        """Iterate list items up to logical ``size`` (not array capacity)."""

        cnt = 0
        for entry in iter(self.span()):
            if cnt >= self.fields.size:
                break
            yield entry
            cnt += 1

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


class GenericDictionaryEntry(CStructureDataclass):
    """
    Single entry in Dictionary<TKey, TVal>.m_items

    Depending on the generic sharing strategy used by Il2Cpp, the actual layout of the entry may vary.
    Data may be inlined directly in the entry on runtime.
    Use dedicated subclasses for specific TKey/TValue if layout uses specialized types instead of Il2CppObject pointers.
    """
    hashCode: C_Int[c_int32]
    _ignored_1: c_int32  # next
    key: C_VoidPtr
    value: C_VoidPtr


class GenericDictionaryFields[CDT: StructOrSimple = GenericDictionaryEntry](CStructureDataclass,
                                                                            RuntimeGenericMixin[CDT]):
    _ignored_1: C_UDeclPtr  # buckets
    entries: GenericArrayPtr[CDT]
    count: C_Int[c_int32]
    _ignored_2: ArrayType[c_int32, L[2]]  # freeList, freeCount
    version: C_Int[c_int32]
    _ignored_3: ArrayType[C_UDeclPtr, L[4]]  # comparer, keys, values, syncRoot


class GenericDictionary[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``Dictionary<TKey, TValue>`` wrapper over entry array storage."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericDictionaryFields[CDT]

    def span(self) -> Span[CDT]:
        if self.fields.count == 0:
            return Span(self.fields.entries.inner_ptr, 0)  # type: ignore[arg-type]
        return self.fields.entries.span()

    def __iter__(self) -> Iterator[CDT]:
        """Yield entries with valid hash codes and warn on count mismatch."""

        valid = 0
        for entry in iter(self.span()):
            # noinspection PyUnnecessaryCast
            if type_cast(GenericDictionaryEntry, entry).hashCode > 0:
                valid += 1
                yield entry

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))
