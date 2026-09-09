from __future__ import annotations

from ctypes import c_int32, c_uint16

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr, PointerWrapperMixin
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

    @property
    def value(self) -> str:
        """Decode managed ``System.String`` contents into a Python ``str``."""

        if not self._inner_ptr:
            raise ValueError("Cannot get string from null SystemStringObject pointer")
        length = self._inner_ptr.contents.fields.stringLength
        if length <= 0:
            return ''
        chars_ptr = (int(self._inner_ptr) + int(getattr(SystemStringObject, 'fields').offset)
                     + int(getattr(SystemStringFields, 'firstChar').offset))
        chars_array_ptr = C_Ptr[c_uint16](chars_ptr)
        return ''.join(chr(x.value) for x in chars_array_ptr.as_span(length))

    def value_or(self, default: str = '') -> str:
        """Decode the managed string or return ``default`` for a null pointer."""

        return self.value if self._inner_ptr else default
