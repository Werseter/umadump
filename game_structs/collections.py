from __future__ import annotations

from ctypes import c_int32, c_uint64
from typing import Iterator, Literal as L, Optional, cast as type_cast

from ctypes_utils import (ArrayType, CStructureDataclass, C_Int, C_Ptr, C_UDeclPtr, C_VoidPtr, PointerWrapperMixin,
                          RuntimeGenericMixin, Span, StructOrSimple)
from il2cpp_structs import RuntimeIl2CppObject
from schema_validation import TransientContainerStateError


# ---------------------------------------------------------------------------
# Generic Managed Containers
# ---------------------------------------------------------------------------

class GenericArray[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``System.Array`` layout with flexible ``m_items`` tail."""

    _il2cpp_obj: RuntimeIl2CppObject
    _ignored_1: C_UDeclPtr  # omitted: bounds
    max_length: C_Int[c_uint64]
    m_items: ArrayType[CDT, L[0]]


class GenericArrayPtr[CDT: StructOrSimple](PointerWrapperMixin, CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Typed pointer to ``GenericArray[T]`` with span/iteration helpers."""

    _inner_ptr: C_Ptr[GenericArray[CDT]]

    @property
    def address(self) -> int:
        return self._inner_ptr.address

    def span(self) -> Span[CDT]:
        """Return a ``Span`` over the array payload (``m_items``)."""

        if not self._inner_ptr:
            return Span(C_VoidPtr(0), 0)  # type: ignore[arg-type]
        item_type = self._resolve_class_target_type()
        m_items_ptr = self.address + GenericArray.field_offset('m_items')
        # noinspection PyTypeHints
        items_ptr = C_Ptr[item_type](m_items_ptr)  # type: ignore[valid-type]
        return items_ptr.as_span(len(self))

    def __iter__(self) -> Iterator[CDT]:
        return iter(self.span())

    def __len__(self) -> int:
        """Array capacity from its header; zero for a null pointer."""
        return self._inner_ptr.contents.max_length if self else 0

    def first(self) -> Optional[CDT]:
        """Return the first array item without materializing the payload."""

        return next(iter(self), None)

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


def _container_items_span[CDT: StructOrSimple](container: str, count: int, items: GenericArrayPtr[CDT]) -> Span[CDT]:
    """Validate backing capacity and bound the fresh view to the used storage count."""

    span = items.span()
    capacity = len(span)
    if not 0 <= count <= capacity:
        raise TransientContainerStateError(container, count, items.address, capacity)
    span.count = count
    return span


class GenericListFields[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    items: GenericArrayPtr[CDT]
    size: C_Int[c_int32]
    version: C_Int[c_int32]
    _ignored_1: C_UDeclPtr  # omitted: syncRoot


class GenericList[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Managed ``List<T>`` wrapper with size-limited iteration."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericListFields[CDT]

    def span(self) -> Span[CDT]:
        """Return the validated logical list range, excluding unused capacity."""

        size = len(self)
        if size <= 0:
            return Span(C_VoidPtr(0), 0)  # type: ignore[arg-type]
        return _container_items_span("GenericList", size, self.fields.items)

    def __iter__(self) -> Iterator[CDT]:
        """Iterate list items up to logical ``size`` (not array capacity)."""

        return iter(self.span())

    def __len__(self) -> int:
        size = self.fields.size
        if size < 0:
            items = self.fields.items
            raise TransientContainerStateError("GenericList", size, items.address, len(items))
        return size

    def first(self) -> Optional[CDT]:
        """Return the first logical list item."""

        return next(iter(self), None)

    def last(self) -> Optional[CDT]:
        """Return the logical tail directly, without materializing the list."""

        return next(reversed(self.span()), None)

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))


class GenericDictionaryEntry(CStructureDataclass):
    """Common managed entry header; concrete entries define key/value storage and stride."""

    hashCode: C_Int[c_int32]
    next: C_Int[c_int32]


class GenericIntDictionaryEntry(GenericDictionaryEntry):
    """Default Int32 key storage"""

    key: C_Int[c_int32]


class GenericDictionaryFields[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    buckets: GenericArrayPtr[c_int32]
    entries: GenericArrayPtr[CDT]
    count: C_Int[c_int32]
    _ignored_1: c_int32  # omitted: freeList
    freeCount: C_Int[c_int32]
    version: C_Int[c_int32]
    comparer: C_UDeclPtr
    _ignored_2: ArrayType[C_UDeclPtr, L[3]]  # omitted: keys, values, syncRoot


class GenericDictionary[CDT: StructOrSimple](CStructureDataclass, RuntimeGenericMixin[CDT]):
    """Iterate managed entries; Int32/enum keys also support keyed access."""

    _il2cpp_obj: RuntimeIl2CppObject
    fields: GenericDictionaryFields[CDT]

    def span(self) -> Span[CDT]:
        """Return the validated used storage range, including deleted slots."""

        count = self.fields.count
        live_count = len(self)
        if count == 0:
            return Span(C_VoidPtr(0), 0)  # type: ignore[arg-type]
        entries = _container_items_span("GenericDictionary", count, self.fields.entries)
        if live_count == 0:
            return Span(C_VoidPtr(0), 0)  # type: ignore[arg-type]
        return entries

    def __iter__(self) -> Iterator[CDT]:
        """Yield active entries from the dictionary's used entry range."""

        for entry in self.span():
            typed_entry = type_cast(GenericDictionaryEntry, entry)
            if typed_entry.hashCode >= 0:
                yield entry

    def __reversed__(self) -> Iterator[CDT]:
        """Yield active entries in reverse storage order, without materializing them."""

        for entry in reversed(self.span()):
            if type_cast(GenericDictionaryEntry, entry).hashCode >= 0:
                yield entry

    def _validate_lookup_key(self, key: int) -> None:
        key_field = CStructureDataclass.field_descriptor(self._resolve_class_target_type(), 'key')
        if key_field is None or not issubclass(key_field.type, c_int32):
            raise TypeError("Keyed access requires an Int32 or Int32 enum key")

        if not -(2 ** 31) <= key < 2 ** 31:
            raise OverflowError("Dictionary key is outside Int32")

    def _lookup_buckets(self, entry_count: int) -> Span[c_int32]:
        if self.fields.comparer:
            raise NotImplementedError("Keyed access does not support custom dictionary comparers")

        if not (buckets := self.fields.buckets.span()):
            raise TransientContainerStateError("GenericDictionary buckets", entry_count,
                                               self.fields.buckets.address, 0)
        return buckets

    def _find_in_bucket_chain(self, key: int, entries: Span[CDT]) -> Optional[CDT]:
        buckets = self._lookup_buckets(len(entries))
        hash_code = key & 0x7FFFFFFF
        # Buckets are one-based (0 = empty); collision links are zero-based (-1 = end).
        index = buckets[hash_code % len(buckets)].value - 1
        for _ in range(len(entries)):
            if index == -1:
                return None

            if not 0 <= index < len(entries):
                raise TransientContainerStateError("GenericDictionary entry index", index,
                                                   entries.pointer.address, len(entries))
            entry = entries[index]
            integer_entry = type_cast(GenericIntDictionaryEntry, entry)
            if integer_entry.hashCode < 0:
                raise TransientContainerStateError("GenericDictionary linked free entry", integer_entry.hashCode,
                                                   entries.pointer.address, len(entries))

            if integer_entry.hashCode == hash_code and integer_entry.key == key:
                return entry

            index = integer_entry.next
        if index != -1:
            raise TransientContainerStateError("GenericDictionary collision cycle", index,
                                               entries.pointer.address, len(entries))
        return None

    def get(self, key: int) -> Optional[CDT]:
        """Find an Int32/enum entry by key; return None only when absent."""

        self._validate_lookup_key(key)
        if not (entries := self.span()):
            return None

        return self._find_in_bucket_chain(key, entries)

    def __getitem__(self, key: int) -> CDT:
        """Return an entry by key, not by storage index; raise KeyError when absent."""

        if (entry := self.get(key)) is not None:
            return entry

        raise KeyError(key)

    def __contains__(self, key: int) -> bool:
        return self.get(key) is not None

    def __len__(self) -> int:
        count = self.fields.count
        free_count = self.fields.freeCount
        if not 0 <= free_count <= count:
            items = self.fields.entries
            raise TransientContainerStateError("GenericDictionary", count, items.address, len(items),
                                               free_count=free_count)
        return count - free_count

    def first(self) -> Optional[CDT]:
        """Return the first live dictionary entry."""

        return next(iter(self), None)

    def last(self) -> Optional[CDT]:
        """Return the last active entry in used storage order."""

        return next(reversed(self), None)

    @property
    def value(self) -> list[CDT]:
        return list(iter(self))
