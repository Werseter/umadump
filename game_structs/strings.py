from __future__ import annotations

from ctypes import c_int32, c_uint16
from typing import overload

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr, PointerWrapperMixin, Span
from il2cpp_structs import RuntimeIl2CppObject


# ---------------------------------------------------------------------------
# System-namespace Miscellaneous Structs
# ---------------------------------------------------------------------------

class SystemStringFields(CStructureDataclass):
    stringLength: C_Int[c_int32]
    firstChar: C_Int[c_uint16]


class SystemStringObject(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    fields: SystemStringFields


class SystemStringObjectPtr(PointerWrapperMixin, CStructureDataclass):
    """Pointer wrapper for ``System.String`` with UTF-16 decoding helper."""

    _inner_ptr: C_Ptr[SystemStringObject]

    @property
    def address(self) -> int:
        return self._inner_ptr.address

    def span(self) -> Span[c_uint16]:
        """Return the managed UTF-16 code-unit view; reject a null string pointer."""

        if not self._inner_ptr:
            raise ValueError("Cannot get string from null SystemStringObject pointer")
        length = self._inner_ptr.contents.fields.stringLength
        chars_ptr = self.address + SystemStringObject.field_offset('fields', 'firstChar')
        return C_Ptr[c_uint16](chars_ptr).as_span(length)

    @property
    def value(self) -> str:
        """Decode managed ``System.String`` contents into a Python ``str``."""

        return bytes(self.span()).decode('utf-16le')

    @overload
    def value_or(self, default: str = '') -> str:
        ...

    @overload
    def value_or(self, default: None) -> str | None:
        ...

    def value_or(self, default: str | None = '') -> str | None:
        """Decode the managed string or return ``default`` for a null pointer."""

        return self.value if self._inner_ptr else default
