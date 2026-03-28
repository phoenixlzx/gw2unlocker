#!/usr/bin/env python3
"""
gw2unlock.py - GW2 Language Unlocker

Unlocks all languages in Guild Wars 2 and preserves the player's language
choice across map transitions using hardware breakpoints.

How it works:
  1. Finds Gw2-64.exe and locates LanguageIsPermitted() by searching for
     its assertion string in the .rdata section, then tracing LEA references
     back to the call site.
  2. Patches LanguageIsPermitted() to always return 1 (mov eax,1; ret).
  3. Sets permitted language bitmasks to 0x3F (all six languages) and
     blocked bitmasks to 0x00. NOPs all instructions that write back to
     the blocked bitmask addresses so the game cannot re-block them.
  4. Attaches as a debugger with a hardware write-breakpoint (DR0) on the
     primary language variable (located at max(permitted_rvas) + 8).
  5. When the server resets the variable to 0 during a map transition,
     the debugger catches the write, restores the variable, and overrides
     the registers (ebx, edi unconditionally; ecx, edx only if <= 5) so
     the function continues with the correct language.
  6. When the player legitimately changes language (new non-zero value),
     the script tracks the new choice.

All patches are in-memory only. They do not modify any files on disk and
must be re-applied each time the game is restarted.

Requires: Windows, Python 3.6+, administrator privileges.
Usage:    python gw2unlock.py

MIT License

Copyright (c) 2026

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import ctypes as C
import struct
import sys
from ctypes import wintypes as W

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------

PROCESS_ALL_ACCESS = 0x1F0FFF
THREAD_ALL_ACCESS = 0x1F03FF
CONTEXT_AMD64 = 0x100000  # CONTEXT_AMD64 base flag

STATUS_BREAKPOINT = 0x80000003
STATUS_SINGLE_STEP = 0x80000004
DBG_CONTINUE = 0x10002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001

# CONTEXT structure layout (AMD64) -- byte offsets into the 1232-byte buffer
CONTEXT_SIZE = 1232
CONTEXT_FLAGS_OFF = 0x30

# Debug registers
DR0_OFF = 0x48
DR6_OFF = 0x68
DR7_OFF = 0x70

# General-purpose registers
RAX_OFF = 0x78
RCX_OFF = 0x80
RDX_OFF = 0x88
RBX_OFF = 0x90
RSP_OFF = 0x98
RBP_OFF = 0xA0
RSI_OFF = 0xA8
RDI_OFF = 0xB0
R8_OFF = 0xB8
RIP_OFF = 0xF8

# Language names for display
LANG_NAMES = {0: "en", 1: "ko", 2: "fr", 3: "de", 4: "es", 5: "chs"}

# ---------------------------------------------------------------------------
# Win32 API handle
# ---------------------------------------------------------------------------

k32 = C.WinDLL("kernel32", use_last_error=True)

# ---------------------------------------------------------------------------
# Toolhelp32 structures for process/thread/module enumeration
# ---------------------------------------------------------------------------


class PROCESSENTRY32(C.Structure):
    """Toolhelp32 process entry."""

    _fields_ = [
        ("dwSize", W.DWORD),
        ("cntUsage", W.DWORD),
        ("th32ProcessID", W.DWORD),
        ("th32DefaultHeapID", C.c_void_p),
        ("th32ModuleID", W.DWORD),
        ("cntThreads", W.DWORD),
        ("th32ParentProcessID", W.DWORD),
        ("pcPriClassBase", C.c_long),
        ("dwFlags", W.DWORD),
        ("szExeFile", C.c_char * 260),
    ]


class THREADENTRY32(C.Structure):
    """Toolhelp32 thread entry."""

    _fields_ = [
        ("dwSize", W.DWORD),
        ("cntUsage", W.DWORD),
        ("th32ThreadID", W.DWORD),
        ("th32OwnerProcessID", W.DWORD),
        ("tpBasePri", C.c_long),
        ("tpDeltaPri", C.c_long),
        ("dwFlags", W.DWORD),
    ]


class MODULEENTRY32(C.Structure):
    """Toolhelp32 module entry."""

    _fields_ = [
        ("dwSize", W.DWORD),
        ("th32ModuleID", W.DWORD),
        ("th32ProcessID", W.DWORD),
        ("GlblcntUsage", W.DWORD),
        ("ProccntUsage", W.DWORD),
        ("modBaseAddr", C.POINTER(C.c_byte)),
        ("modBaseSize", W.DWORD),
        ("hModule", C.c_void_p),
        ("szModule", C.c_char * 256),
        ("szExePath", C.c_char * 260),
    ]


class DEBUG_EVENT(C.Structure):
    """Simplified DEBUG_EVENT -- we only inspect the first few fields."""

    _fields_ = [
        ("code", W.DWORD),
        ("pid", W.DWORD),
        ("tid", W.DWORD),
        ("_pad", W.DWORD),
        ("excCode", W.DWORD),
        ("_rest", C.c_ubyte * 160),
    ]


# ---------------------------------------------------------------------------
# Low-level memory helpers
# ---------------------------------------------------------------------------


def rmem(handle, address, size):
    """Read ``size`` bytes from process memory at ``address``."""
    buf = (C.c_ubyte * size)()
    got = C.c_size_t(0)
    k32.ReadProcessMemory(
        handle, C.c_void_p(address), C.byref(buf), size, C.byref(got)
    )
    return bytes(buf[: int(got.value)])


def r32(handle, address):
    """Read a 32-bit unsigned integer from process memory."""
    data = rmem(handle, address, 4)
    return struct.unpack("<I", data)[0] if len(data) == 4 else 0


def wprot(handle, address, data):
    """Write ``data`` bytes to process memory, temporarily making the page RWX."""
    page = address & ~0xFFF
    old_prot = W.DWORD(0)
    k32.VirtualProtectEx(
        handle, C.c_void_p(page), 0x2000, 0x40, C.byref(old_prot)
    )

    buf = (C.c_ubyte * len(data))(*data)
    got = C.c_size_t(0)
    k32.WriteProcessMemory(
        handle, C.c_void_p(address), C.byref(buf), len(data), C.byref(got)
    )

    tmp = W.DWORD(0)
    k32.VirtualProtectEx(
        handle, C.c_void_p(page), 0x2000, old_prot.value, C.byref(tmp)
    )


# ---------------------------------------------------------------------------
# Process / thread / module enumeration
# ---------------------------------------------------------------------------


def find_pid():
    """Find the PID of Gw2-64.exe using a Toolhelp32 snapshot."""
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    entry = PROCESSENTRY32()
    entry.dwSize = C.sizeof(entry)
    if not k32.Process32First(snap, C.byref(entry)):
        k32.CloseHandle(snap)
        return 0
    while True:
        if entry.szExeFile.lower() == b"gw2-64.exe":
            k32.CloseHandle(snap)
            return entry.th32ProcessID
        if not k32.Process32Next(snap, C.byref(entry)):
            break
    k32.CloseHandle(snap)
    return 0


def get_base(pid):
    """Return ``(base_address, module_size)`` for the Gw2-64.exe module."""
    snap = k32.CreateToolhelp32Snapshot(8, pid)
    entry = MODULEENTRY32()
    entry.dwSize = C.sizeof(entry)
    if not k32.Module32First(snap, C.byref(entry)):
        k32.CloseHandle(snap)
        return 0, 0
    while True:
        if entry.szModule.lower() == b"gw2-64.exe":
            k32.CloseHandle(snap)
            base = C.cast(entry.modBaseAddr, C.c_void_p).value
            return base, entry.modBaseSize
        if not k32.Module32Next(snap, C.byref(entry)):
            break
    k32.CloseHandle(snap)
    return 0, 0


def get_tids(pid):
    """Return a list of thread IDs belonging to the given process."""
    result = []
    snap = k32.CreateToolhelp32Snapshot(4, 0)
    entry = THREADENTRY32()
    entry.dwSize = C.sizeof(entry)
    if not k32.Thread32First(snap, C.byref(entry)):
        k32.CloseHandle(snap)
        return result
    while True:
        if entry.th32OwnerProcessID == pid:
            result.append(entry.th32ThreadID)
        if not k32.Thread32Next(snap, C.byref(entry)):
            break
    k32.CloseHandle(snap)
    return result


# ---------------------------------------------------------------------------
# x86-64 instruction analysis helpers
# ---------------------------------------------------------------------------


def is_rip_modrm(byte):
    """Check if a ModR/M byte encodes RIP-relative addressing (mod=00, r/m=101)."""
    return (byte & 0xC7) == 0x05


def search_mod(handle, base, start, end, pattern):
    """Search module memory for all occurrences of ``pattern``.

    Returns a list of RVAs (relative to module base).
    """
    results = []
    for offset in range(start, end, 0x100000):
        chunk_size = min(0x100000 + len(pattern), end - offset)
        data = rmem(handle, base + offset, chunk_size)
        pos = 0
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            results.append(offset + idx)
            pos = idx + 1
    return results


def find_lea(handle, base, text_start, text_end, target_rva):
    """Find all LEA instructions (with REX.W prefix) that reference
    ``target_rva`` via RIP-relative addressing.

    Returns a list of RVAs of the LEA instructions.
    """
    results = []
    for chunk_off in range(text_start, text_end, 0x100000):
        chunk_size = min(0x100008, text_end - chunk_off)
        data = rmem(handle, base + chunk_off, chunk_size)
        for i in range(len(data) - 6):
            # REX.W prefix (0x48-0x4F) + 0x8D (LEA) + RIP-relative ModR/M
            if (
                0x48 <= data[i] <= 0x4F
                and data[i + 1] == 0x8D
                and is_rip_modrm(data[i + 2])
            ):
                disp = struct.unpack_from("<i", data, i + 3)[0]
                # Instruction length is 7 bytes (REX + opcode + modrm + disp32)
                if chunk_off + i + 7 + disp == target_rva:
                    results.append(chunk_off + i)
    return results


# ---------------------------------------------------------------------------
# LanguageIsPermitted function locator
# ---------------------------------------------------------------------------


def find_lang_permitted(handle, base, module_size):
    """Locate the LanguageIsPermitted() function dynamically.

    Strategy:
      1. Search for the assertion string "LanguageIsPermitted(" in .rdata.
      2. Find LEA instructions that reference that string.
      3. Walk backwards from each LEA to find ``test eax, eax / jz|jnz``
         (the assertion check).
      4. Walk further back to find a CALL instruction -- the call to the
         actual LanguageIsPermitted function.
      5. Resolve the CALL target (E8 rel32) to get the function RVA.

    Returns the function RVA, or 0 if not found.
    """
    text_end = min(module_size, 0x1A00000)

    for string_rva in search_mod(handle, base, 0, module_size,
                                  b"LanguageIsPermitted("):
        for lea_rva in find_lea(handle, base, 0x1000, text_end, string_rva):
            # Read code around the LEA instruction
            region_start = max(lea_rva - 120, 0)
            code = rmem(
                handle, base + region_start, lea_rva - region_start + 16
            )
            lea_local = lea_rva - region_start

            # Walk backwards: test eax, eax (85 C0) + conditional jump
            for i in range(lea_local - 4, max(0, lea_local - 80), -1):
                if (
                    i + 2 > len(code)
                    or code[i] != 0x85
                    or code[i + 1] != 0xC0
                ):
                    continue
                # Must be followed by jz/jnz (short or near)
                is_short_jcc = (
                    i + 3 <= len(code) and code[i + 2] in (0x74, 0x75)
                )
                is_near_jcc = (
                    i + 4 <= len(code)
                    and code[i + 2] == 0x0F
                    and code[i + 3] in (0x84, 0x85)
                )
                if not (is_short_jcc or is_near_jcc):
                    continue

                # Walk further back to find CALL (E8 rel32)
                for j in range(i - 5, max(0, i - 40), -1):
                    if code[j] != 0xE8:
                        continue
                    disp = struct.unpack_from("<i", code, j + 1)[0]
                    func_rva = region_start + j + 5 + disp
                    if 0 < func_rva < module_size:
                        return func_rva
    return 0


# ---------------------------------------------------------------------------
# Bitmask extraction
# ---------------------------------------------------------------------------


def extract_bitmasks(handle, base, func_rva, module_size):
    """Extract the RVAs of permitted and blocked language bitmasks from the
    LanguageIsPermitted function.

    The function references several global variables via RIP-relative
    addressing. These cluster into two groups: permitted bitmasks and
    blocked bitmasks. The group with the lower base address is "permitted",
    the higher is "blocked".

    Returns ``(permitted_rvas, blocked_rvas)`` as sorted lists.
    """
    # Opcodes that use RIP-relative addressing for memory operands
    MEM_OPCODES = {
        0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B,
        0x31, 0x33, 0x39, 0x3B, 0x85, 0x87, 0x89, 0x8B,
    }

    code = rmem(handle, base + func_rva, 160)
    data_lower = module_size // 2
    targets = set()

    for i in range(len(code) - 5):
        candidates = []

        # Plain opcode + RIP-relative ModR/M
        if (
            code[i] in MEM_OPCODES
            and is_rip_modrm(code[i + 1])
            and i + 6 <= len(code)
        ):
            candidates.append((i + 2, i + 6))

        # REX prefix + opcode + RIP-relative ModR/M
        if (
            0x40 <= code[i] <= 0x4F
            and code[i + 1] in MEM_OPCODES
            and is_rip_modrm(code[i + 2])
            and i + 7 <= len(code)
        ):
            candidates.append((i + 3, i + 7))

        # Two-byte opcode (0F xx) + RIP-relative ModR/M
        if (
            code[i] == 0x0F
            and i + 7 <= len(code)
            and is_rip_modrm(code[i + 2])
        ):
            candidates.append((i + 3, i + 7))

        # REX + two-byte opcode (0F xx) + RIP-relative ModR/M
        if (
            0x40 <= code[i] <= 0x4F
            and code[i + 1] == 0x0F
            and i + 8 <= len(code)
            and is_rip_modrm(code[i + 3])
        ):
            candidates.append((i + 4, i + 8))

        for disp_off, instr_len in candidates:
            disp = struct.unpack_from("<i", code, disp_off)[0]
            target = func_rva + instr_len + disp
            if data_lower < target < module_size:
                targets.add(target)

    # Cluster targets by proximity (within 64 bytes = same variable group)
    sorted_targets = sorted(targets)
    clusters = [[sorted_targets[0]]]
    for t in sorted_targets[1:]:
        if t - clusters[-1][-1] <= 64:
            clusters[-1].append(t)
        else:
            clusters.append([t])

    # Two largest clusters; lower address = permitted, higher = blocked
    clusters.sort(key=len, reverse=True)
    a, b = clusters[0], clusters[1]
    return (a, b) if a[0] < b[0] else (b, a)


# ---------------------------------------------------------------------------
# RIP-relative write finder (for NOP patching)
# ---------------------------------------------------------------------------

# Store opcodes that write to memory via RIP-relative addressing
STORE_OPCODES = {
    0x00, 0x01, 0x08, 0x09, 0x10, 0x11, 0x18, 0x19,
    0x20, 0x21, 0x28, 0x29, 0x30, 0x31, 0x88, 0x89,
}


def find_rip_writes(handle, base, search_start, search_end, target_rva):
    """Find all instructions that perform a RIP-relative write to
    ``target_rva``.

    Returns a list of ``(rva, instruction_length)`` tuples.
    Overlapping/adjacent instructions are deduplicated.
    """
    results = []
    for chunk_off in range(search_start, search_end, 0x100000):
        chunk_size = min(0x100010, search_end - chunk_off)
        data = rmem(handle, base + chunk_off, chunk_size)
        for i in range(len(data) - 5):
            b0 = data[i]
            has_rex = 0x40 <= b0 <= 0x4F
            p = 1 if has_rex else 0
            if i + p + 6 > len(data):
                continue
            opcode = data[i + p]
            modrm = data[i + p + 1]
            if opcode not in STORE_OPCODES or not is_rip_modrm(modrm):
                continue
            instr_len = p + 6
            if i + instr_len > len(data):
                continue
            disp = struct.unpack_from("<i", data, i + p + 2)[0]
            if (chunk_off + i + instr_len + disp) & 0xFFFFFFFF == target_rva:
                results.append((chunk_off + i, instr_len))

    # Deduplicate overlapping entries
    results.sort()
    deduped = []
    for r in results:
        if not deduped or r[0] >= deduped[-1][0] + deduped[-1][1]:
            deduped.append(r)
    return deduped


# ---------------------------------------------------------------------------
# Hardware breakpoint management (DR0 write watchpoint)
# ---------------------------------------------------------------------------


def set_wp(tid, address):
    """Set a hardware write-watchpoint (DR0, 4-byte) on ``address`` for
    thread ``tid``.

    DR7 configuration:
      - Bit 0:      local enable for DR0
      - Bits 16-17: condition 01 (write-only)
      - Bits 18-19: length 11 (4 bytes)
    """
    ht = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
    if not ht:
        return False

    k32.SuspendThread(ht)
    ctx = (C.c_ubyte * CONTEXT_SIZE)()
    struct.pack_into("<I", ctx, CONTEXT_FLAGS_OFF, CONTEXT_AMD64 | 0x10)

    if not k32.GetThreadContext(ht, C.byref(ctx)):
        k32.ResumeThread(ht)
        k32.CloseHandle(ht)
        return False

    # DR0 = watched address
    struct.pack_into("<Q", ctx, DR0_OFF, address)

    # DR7: local enable DR0, write condition, 4-byte length
    dr7 = struct.unpack_from("<Q", ctx, DR7_OFF)[0]
    dr7 = (dr7 & ~0xF0003) | 0xD0001
    struct.pack_into("<Q", ctx, DR7_OFF, dr7)

    k32.SetThreadContext(ht, C.byref(ctx))
    k32.ResumeThread(ht)
    k32.CloseHandle(ht)
    return True


def clear_wp(tid):
    """Clear all hardware watchpoints for thread ``tid``."""
    ht = k32.OpenThread(THREAD_ALL_ACCESS, False, tid)
    if not ht:
        return

    k32.SuspendThread(ht)
    ctx = (C.c_ubyte * CONTEXT_SIZE)()
    struct.pack_into("<I", ctx, CONTEXT_FLAGS_OFF, CONTEXT_AMD64 | 0x10)

    if k32.GetThreadContext(ht, C.byref(ctx)):
        for i in range(4):
            struct.pack_into("<Q", ctx, DR0_OFF + i * 8, 0)
        struct.pack_into("<Q", ctx, DR6_OFF, 0)
        struct.pack_into("<Q", ctx, DR7_OFF, 0)
        k32.SetThreadContext(ht, C.byref(ctx))

    k32.ResumeThread(ht)
    k32.CloseHandle(ht)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    print()
    print("  GW2 Language Unlocker")
    print("  " + "=" * 40)
    print("  All patches are in-memory only.")
    print("  Re-run after each game restart.")
    print()

    # -- Find process and module base --

    pid = find_pid()
    if not pid:
        print("  ERROR: Gw2-64.exe not found. Is the game running?")
        return

    base, module_size = get_base(pid)
    if not base:
        print("  ERROR: Could not read module base address.")
        return

    hp = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not hp:
        print("  ERROR: Could not open process (run as administrator).")
        return

    text_end = min(module_size, 0x1A00000)
    print(f"  PID:  {pid}")
    print(f"  Base: 0x{base:X}")
    print(f"  Size: 0x{module_size:X}")

    # -- Locate LanguageIsPermitted function --

    func_rva = find_lang_permitted(hp, base, module_size)
    if not func_rva:
        print("  FAILED: Could not find LanguageIsPermitted function.")
        k32.CloseHandle(hp)
        return

    print(f"  LanguageIsPermitted: RVA 0x{func_rva:08X}")

    # -- Extract bitmask RVAs --

    permitted_rvas, blocked_rvas = extract_bitmasks(
        hp, base, func_rva, module_size
    )
    lang_rva = max(permitted_rvas) + 8
    current_lang = r32(hp, base + lang_rva)
    print(f"  Permitted bitmask RVAs: {len(permitted_rvas)}")
    print(f"  Blocked bitmask RVAs:   {len(blocked_rvas)}")
    lang_name = LANG_NAMES.get(current_lang, "?")
    print(f"  Language variable: RVA 0x{lang_rva:08X} = {current_lang} ({lang_name})")

    # -- Apply unlock patches --

    print()
    print("  Applying patches...")

    # Patch 1: LanguageIsPermitted -> mov eax, 1; ret
    patch_bytes = bytes([0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3])
    if rmem(hp, base + func_rva, 6) != patch_bytes:
        wprot(hp, base + func_rva, patch_bytes)
        print("    Patched LanguageIsPermitted -> always returns 1")

    # Patch 2: Set all permitted bitmasks to 0x3F (all 6 languages)
    patched_perm = 0
    for rva in permitted_rvas:
        if r32(hp, base + rva) != 0x3F:
            wprot(hp, base + rva, struct.pack("<I", 0x3F))
            patched_perm += 1
    if patched_perm:
        print(f"    Set {patched_perm} permitted bitmask(s) to 0x3F")

    # Patch 3: Clear all blocked bitmasks to 0x00
    patched_block = 0
    for rva in blocked_rvas:
        if r32(hp, base + rva) != 0:
            wprot(hp, base + rva, struct.pack("<I", 0))
            patched_block += 1
    if patched_block:
        print(f"    Cleared {patched_block} blocked bitmask(s) to 0x00")

    # Patch 4: NOP all RIP-relative writes to blocked bitmask addresses
    patched_nops = 0
    for target_rva in blocked_rvas:
        for instr_rva, instr_len in find_rip_writes(
            hp, base, 0x1000, text_end, target_rva
        ):
            orig = rmem(hp, base + instr_rva, instr_len)
            if not all(b == 0x90 for b in orig):
                wprot(hp, base + instr_rva, bytes([0x90] * instr_len))
                patched_nops += 1
    if patched_nops:
        print(f"    NOPed {patched_nops} blocked-bitmask write instruction(s)")

    print("  Patches applied.")

    # -- Determine desired language --

    desired = r32(hp, base + lang_rva)
    print()
    desired_name = LANG_NAMES.get(desired, "?")
    print(f"  Current language: {desired} ({desired_name})")
    if desired == 0:
        print("  Select a non-English language in-game. The script will detect it.")

    # -- Attach debugger --

    print()
    print("  Attaching debugger...")
    k32.CloseHandle(hp)

    if not k32.DebugActiveProcess(pid):
        print("  FAILED: Could not attach debugger (run as administrator).")
        return

    k32.DebugSetProcessKillOnExit(False)
    hp = k32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    lang_va = base + lang_rva  # absolute virtual address of language variable

    # -- Debug event loop --

    ev = DEBUG_EVENT()
    initialized = False
    override_count = 0

    try:
        while True:
            if not k32.WaitForDebugEvent(C.byref(ev), 3000):
                continue

            # --- Exception events (code 1) ---
            if ev.code == 1:
                exc = ev.excCode

                # Initial breakpoint: set watchpoints on all threads
                if exc == STATUS_BREAKPOINT and not initialized:
                    initialized = True
                    wp_count = 0
                    for tid in get_tids(pid):
                        if set_wp(tid, lang_va):
                            wp_count += 1
                    print(f"  Watchpoint set on {wp_count} thread(s).")
                    print()
                    print("  Language will be preserved across map transitions.")
                    print("  Keep this window open. Press Ctrl+C to stop.")
                    print()
                    k32.ContinueDebugEvent(ev.pid, ev.tid, DBG_CONTINUE)
                    continue

                # Single-step exception: check if our watchpoint fired
                if exc == STATUS_SINGLE_STEP and initialized:
                    ht = k32.OpenThread(THREAD_ALL_ACCESS, False, ev.tid)
                    if ht:
                        ctx = (C.c_ubyte * CONTEXT_SIZE)()
                        struct.pack_into(
                            "<I", ctx, CONTEXT_FLAGS_OFF,
                            CONTEXT_AMD64 | 0x1F,
                        )
                        k32.GetThreadContext(ht, C.byref(ctx))
                        dr6 = struct.unpack_from("<Q", ctx, DR6_OFF)[0]

                        if dr6 & 1:  # DR0 triggered
                            val = r32(hp, base + lang_rva)

                            if 0 < val <= 5 and val != desired:
                                # Player changed language -- track new choice
                                desired = val
                                name = LANG_NAMES.get(desired, "?")
                                print(f"  Language changed to: {desired} ({name})")

                            elif val == 0 and desired > 0:
                                # Server reset -- override registers to
                                # preserve the language.
                                #
                                # The function is paused AFTER writing 0 to
                                # the variable. Sub-function calls that
                                # propagate the language happen NEXT. We
                                # restore the variable and override registers
                                # so those sub-functions receive the correct
                                # language value.

                                # Restore the language variable
                                wprot(
                                    hp, base + lang_rva,
                                    struct.pack("<I", desired),
                                )

                                # Override ebx (primary variable writes)
                                struct.pack_into("<Q", ctx, RBX_OFF, desired)

                                # Override edi (secondary variable writes)
                                struct.pack_into("<Q", ctx, RDI_OFF, desired)

                                # Override ecx only if it looks like a
                                # language ID (0-5), to avoid corrupting
                                # pointer values in other contexts
                                ecx = struct.unpack_from("<Q", ctx, RCX_OFF)[0]
                                if ecx <= 5:
                                    struct.pack_into("<Q", ctx, RCX_OFF, desired)

                                # Override edx only if <= 5
                                edx = struct.unpack_from("<Q", ctx, RDX_OFF)[0]
                                if edx <= 5:
                                    struct.pack_into("<Q", ctx, RDX_OFF, desired)

                                # Clear DR6 and apply context
                                struct.pack_into("<Q", ctx, DR6_OFF, 0)
                                k32.SetThreadContext(ht, C.byref(ctx))

                                override_count += 1
                                if override_count <= 10:
                                    name = LANG_NAMES.get(desired, "?")
                                    print(
                                        f"  [override #{override_count}]"
                                        f" Restored language variable +"
                                        f" registers -> {desired} ({name})"
                                    )
                                elif override_count == 11:
                                    print(
                                        "  [override]"
                                        " (further messages suppressed)"
                                    )

                                k32.CloseHandle(ht)
                                k32.ContinueDebugEvent(
                                    ev.pid, ev.tid, DBG_CONTINUE
                                )
                                continue

                        # Clear DR6 for any single-step we handled
                        struct.pack_into("<Q", ctx, DR6_OFF, 0)
                        k32.SetThreadContext(ht, C.byref(ctx))
                        k32.CloseHandle(ht)

                    k32.ContinueDebugEvent(ev.pid, ev.tid, DBG_CONTINUE)
                    continue

                # Unhandled exception -- pass to the game
                k32.ContinueDebugEvent(
                    ev.pid, ev.tid, DBG_EXCEPTION_NOT_HANDLED
                )

            # --- New thread (code 2): install watchpoint ---
            elif ev.code == 2:
                set_wp(ev.tid, lang_va)
                k32.ContinueDebugEvent(ev.pid, ev.tid, DBG_CONTINUE)

            # --- Process exit (code 5) ---
            elif ev.code == 5:
                print("  Game exited.")
                k32.ContinueDebugEvent(ev.pid, ev.tid, DBG_CONTINUE)
                break

            # --- All other events ---
            else:
                k32.ContinueDebugEvent(ev.pid, ev.tid, DBG_CONTINUE)

    except KeyboardInterrupt:
        print()
        print("  Interrupted by user.")

    # -- Cleanup --

    print(f"  Total overrides: {override_count}")
    for tid in get_tids(pid):
        clear_wp(tid)
    k32.CloseHandle(hp)
    k32.DebugActiveProcessStop(pid)
    print("  Watchpoints cleared, debugger detached.")
    print()


if __name__ == "__main__":
    main()
