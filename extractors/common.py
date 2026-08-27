from __future__ import annotations

import re
from typing import Iterable, Optional, Protocol, TYPE_CHECKING

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
    return "dict", fields.entries.inner_ptr.address, fields.count, fields.version


def list_fingerprint[T: StructOrSimple](items: GenericList[T]) -> ExtractorFingerprint:
    fields = items.fields
    return "list", fields.items.inner_ptr.address, fields.size, fields.version


def array_fingerprint[T: StructOrSimple](items: GenericArrayPtr[T]) -> ExtractorFingerprint:
    if not items.inner_ptr:
        return "array", 0, 0
    return "array", items.inner_ptr.address, items.inner_ptr.contents.max_length


def pointer_fingerprint[T: StructOrSimple](ptr: C_Ptr[T]) -> ExtractorFingerprint:
    return "ptr", ptr.address


def first[T](items: Iterable[T]) -> Optional[T]:
    """Return the first item from an arbitrary iterable."""

    return next(iter(items), None)


def safe_filename_component(name: str) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9 -]+", "_", name).strip()
    return safe_name or "Unknown"
