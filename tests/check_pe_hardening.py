"""Check locally built, unsigned development PE files, not third-party downloads."""
from pathlib import Path
import re
import struct
import subprocess
import sys


def check(path):
    data = path.read_bytes()
    assert data[:2] == b"MZ", "Missing DOS header"
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0", "Missing PE header"
    timestamp = struct.unpack_from("<I", data, pe + 8)[0]
    magic = struct.unpack_from("<H", data, pe + 24)[0]
    flags = struct.unpack_from("<H", data, pe + 24 + 70)[0]
    assert magic in (0x10B, 0x20B), "Unexpected executable format"
    assert flags & 0x40 and flags & 0x100, "ASLR or NX missing"
    if magic == 0x20B:
        assert flags & 0x20, "High-entropy ASLR missing on x64"
    assert timestamp == 0, "Linker timestamp is not deterministic"
    prefix = "x86_64-w64-mingw32-" if magic == 0x20B else "i686-w64-mingw32-"
    imports = subprocess.check_output([prefix + "objdump", "-p", str(path)], text=True)
    dlls = re.findall(r"DLL Name:\s*(\S+)", imports)
    assert not any(any(token in dll.lower() for token in (
        "libssp", "libgcc", "libstdc++", "libcrypto", "libssl")) for dll in dlls), dlls
    symbols = subprocess.check_output([prefix + "nm", str(path)], text=True)
    assert "__stack_chk_fail" in symbols, "Stack protector support absent"
    print(f"{path}: ASLR/NX, static stack protector, deterministic PE timestamp, native DLL imports passed")


if __name__ == "__main__":
    for name in sys.argv[1:]:
        check(Path(name))
