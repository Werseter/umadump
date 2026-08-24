from __future__ import annotations

from ctypes import c_bool, c_int32, c_int64, c_uint64, c_uint8

from ctypes_utils import CStructureDataclass, C_Int, C_Ptr
from game_structs.collections import GenericArrayPtr
from game_structs.strings import SystemStringObjectPtr
from il2cpp_structs import RuntimeIl2CppObject


# ---------------------------------------------------------------------------
# ObscuredTypes value-type structs
# ---------------------------------------------------------------------------

class ObscuredBool(CStructureDataclass):
    currentCryptoKey: C_Int[c_uint8]
    hiddenValue: C_Int[c_int32]
    _ignored_1: c_bool  # omitted: inited
    _ignored_2: c_bool  # omitted: fakeValue
    _ignored_3: c_bool  # omitted: fakeValueActive

    @property
    def value(self) -> bool:
        false_sentinel = 0xB5
        decoded = int(self.currentCryptoKey) ^ int(self.hiddenValue)
        return decoded != false_sentinel


class ObscuredInt(CStructureDataclass):
    currentCryptoKey: C_Int[c_int32]
    hiddenValue: C_Int[c_int32]
    _ignored_1: c_bool  # omitted: inited
    _ignored_2: c_int32  # omitted: fakeValue
    _ignored_3: c_bool  # omitted: fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredLong(CStructureDataclass):
    currentCryptoKey: C_Int[c_int64]
    hiddenValue: C_Int[c_int64]
    _ignored_1: c_bool  # omitted: inited
    _ignored_2: c_int64  # omitted: fakeValue
    _ignored_3: c_bool  # omitted: fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredULong(CStructureDataclass):
    currentCryptoKey: C_Int[c_uint64]
    hiddenValue: C_Int[c_uint64]
    _ignored_1: c_bool  # omitted: inited
    _ignored_2: c_uint64  # omitted: fakeValue
    _ignored_3: c_bool  # omitted: fakeValueActive

    @property
    def value(self) -> int:
        return int(self.currentCryptoKey) ^ int(self.hiddenValue)


class ObscuredString(CStructureDataclass):
    _il2cpp_obj: RuntimeIl2CppObject
    currentCryptoKey: SystemStringObjectPtr
    hiddenValue: GenericArrayPtr[c_uint8]
    _ignored_1: c_bool  # omitted: inited
    _ignored_2: SystemStringObjectPtr  # omitted: fakeValue
    _ignored_3: c_bool  # omitted: fakeValueActive

    @property
    def value(self) -> str:
        key_str = self.currentCryptoKey.value
        key_len = len(key_str)
        if key_len == 0:
            return ''
        raw_bytes = bytes(b.value for b in self.hiddenValue)
        enc_str = raw_bytes.decode('utf-16le')
        dec_str = ''.join(chr(ord(c) ^ ord(key_str[i % key_len])) for i, c in enumerate(enc_str))
        return dec_str.rstrip('\x00')  # strip null terminator if present


class ObscuredStringPtr(CStructureDataclass):
    """Pointer wrapper for ``ObscuredString`` with integrated null check"""

    inner_ptr: C_Ptr[ObscuredString]

    @property
    def value(self) -> str:
        if not self.inner_ptr:
            raise ValueError("Cannot get string from null ObscuredString pointer")
        return self.inner_ptr.contents.value
