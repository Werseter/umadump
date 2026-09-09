from __future__ import annotations

import re
from typing import Any, Iterable, Optional, Protocol, TYPE_CHECKING, cast as type_cast

from ctypes_utils import C_Ptr, StructOrSimple
from game_structs.collections import GenericArrayPtr, GenericDictionary, GenericList

if TYPE_CHECKING:
    from game_structs.race import RaceManagerStaticFields
    from game_structs.work_data_manager import WorkDataManagerObject

ExtractorFingerprint = tuple[object, ...]


class FingerprintableExtractionData(Protocol):
    def fingerprint(self) -> ExtractorFingerprint:
        ...


class ExtractorContext(Protocol):
    """Singleton roots exposed to domain extractor resolvers."""

    @property
    def work_data_manager(self) -> WorkDataManagerObject:
        ...

    @property
    def race_manager_static(self) -> Optional[RaceManagerStaticFields]:
        ...


def dictionary_fingerprint[T: StructOrSimple](dictionary: GenericDictionary[T]) -> ExtractorFingerprint:
    fields = dictionary.fields
    return "dict", fields.entries.address, fields.count, fields.version


def dictionary_pointer_fingerprint[T: StructOrSimple](dictionary: C_Ptr[GenericDictionary[T]]) -> ExtractorFingerprint:
    if not dictionary:
        return "dict", 0, 0, 0
    return dictionary_fingerprint(dictionary.contents)


def list_fingerprint[T: StructOrSimple](items: GenericList[T]) -> ExtractorFingerprint:
    fields = items.fields
    return "list", fields.items.address, fields.size, fields.version


def list_pointer_fingerprint[T: StructOrSimple](items: C_Ptr[GenericList[T]]) -> ExtractorFingerprint:
    if not items:
        return "list", 0, 0, 0
    return list_fingerprint(items.contents)


def object_list_fingerprint[T: StructOrSimple](name: str, items: C_Ptr[GenericList[C_Ptr[T]]]) -> ExtractorFingerprint:
    if not items:
        return name, list_pointer_fingerprint(items), ("first", ("ptr", 0))
    item = items.contents.first()
    if item:
        _ = type_cast(Any, item.contents).fields
    return name, list_pointer_fingerprint(items), ("first", pointer_fingerprint(item) if item else ("ptr", 0))


def array_fingerprint[T: StructOrSimple](items: GenericArrayPtr[T]) -> ExtractorFingerprint:
    if not items:
        return "array", 0, 0
    return "array", items.address, len(items)


def object_array_fingerprint[T: StructOrSimple](name: str, items: GenericArrayPtr[C_Ptr[T]]) -> ExtractorFingerprint:
    item = items.first()
    if item:
        _ = type_cast(Any, item.contents).fields
    return name, array_fingerprint(items), ("first", pointer_fingerprint(item) if item else ("ptr", 0))


def pointer_fingerprint[T: StructOrSimple](ptr: C_Ptr[T]) -> ExtractorFingerprint:
    return "ptr", ptr.address


def object_pointer_fingerprint[T: StructOrSimple](name: str, ptr: C_Ptr[T]) -> ExtractorFingerprint:
    return name, validated_object_pointer_fingerprint(ptr)


def validated_object_pointer_fingerprint[T: StructOrSimple](ptr: C_Ptr[T]) -> ExtractorFingerprint:
    """Fingerprint an object pointer after validating its registered fields, when present."""

    if ptr:
        _ = type_cast(Any, ptr.contents).fields
    return pointer_fingerprint(ptr)


def first_object[T: StructOrSimple](items: Iterable[C_Ptr[T]]) -> Optional[C_Ptr[T]]:
    """Return and metadata-validate the first non-null object pointer."""

    item = first(item for item in items if item)
    if item is not None:
        _ = type_cast(Any, item.contents).fields
    return item


def first_object_fingerprint[T: StructOrSimple](name: str, items: Iterable[C_Ptr[T]]) -> ExtractorFingerprint:
    item = first_object(items)
    return name, item.address if item is not None else 0


def first[T](items: Iterable[T]) -> Optional[T]:
    """Return the first item from an arbitrary iterable."""

    return next(iter(items), None)


def safe_filename_component(name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9 -]+", "_", name).strip()
    return safe_name or "Unknown"
