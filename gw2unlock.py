#!/usr/bin/env python3
"""
GW2 Language Unlocker — unlocks all 6 languages on any regional client.

Patches the running Gw2-64.exe process to:
  1. Patch LanguageIsPermitted() → always return true
  2. Set permitted-language bitmasks to 0x3F (all 6 languages)
  3. Clear blocked-language bitmasks (server-set restrictions)

All addresses are found dynamically from the LanguageIsPermitted function
code, so the script survives game updates.

After running, open Options > Language to select any language.

Usage:
  py gw2unlock.py
"""
import ctypes, ctypes.wintypes as wt
import struct, sys

kernel32 = ctypes.windll.kernel32

PROCESS_ALL_ACCESS  = 0x1F0FFF
TH32CS_SNAPPROCESS  = 0x2
TH32CS_SNAPMODULE   = 0x8
TH32CS_SNAPMODULE32 = 0x10
MAX_PATH = 260
PAGE_EXECUTE_READWRITE = 0x40
ALL_PERMITTED = 0x3F  # bits 0-5 = en, ko, fr, de, es, chs


# ── Windows structs ──────────────────────────────────────────────────

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wt.ULONG)),
        ("th32ModuleID", wt.DWORD), ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", wt.LONG), ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_char * MAX_PATH),
    ]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD),
        ("th32ProcessID", wt.DWORD), ("GlblcntUsage", wt.DWORD),
        ("ProccntUsage", wt.DWORD), ("modBaseAddr", ctypes.c_void_p),
        ("modBaseSize", wt.DWORD), ("hModule", wt.HMODULE),
        ("szModule", ctypes.c_char * 256),
        ("szExePath", ctypes.c_char * MAX_PATH),
    ]


# ── Process helpers ──────────────────────────────────────────────────

def find_pid():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    pe = PROCESSENTRY32(); pe.dwSize = ctypes.sizeof(pe)
    if not kernel32.Process32First(snap, ctypes.byref(pe)):
        kernel32.CloseHandle(snap); return None
    while True:
        if pe.szExeFile.decode('ascii', errors='ignore').lower() == 'gw2-64.exe':
            pid = pe.th32ProcessID; kernel32.CloseHandle(snap); return pid
        if not kernel32.Process32Next(snap, ctypes.byref(pe)):
            break
    kernel32.CloseHandle(snap); return None


def get_module_info(pid):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    me = MODULEENTRY32(); me.dwSize = ctypes.sizeof(me)
    if not kernel32.Module32First(snap, ctypes.byref(me)):
        kernel32.CloseHandle(snap); return None, None
    while True:
        if me.szModule.decode('ascii', errors='ignore').lower() == 'gw2-64.exe':
            b, s = me.modBaseAddr, me.modBaseSize
            kernel32.CloseHandle(snap); return b, s
        if not kernel32.Module32Next(snap, ctypes.byref(me)):
            break
    kernel32.CloseHandle(snap); return None, None


def open_gw2():
    pid = find_pid()
    if not pid:
        print("ERROR: Gw2-64.exe not found."); sys.exit(1)
    base, mod_size = get_module_info(pid)
    h = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        print("ERROR: Cannot open process. Run as Administrator."); sys.exit(1)
    return h, base, mod_size, pid


def rmem(h, addr, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    if kernel32.ReadProcessMemory(h, ctypes.c_void_p(addr), buf, n, ctypes.byref(got)):
        return buf.raw[:got.value]
    return None


def wmem(h, addr, data):
    got = ctypes.c_size_t()
    return (kernel32.WriteProcessMemory(h, ctypes.c_void_p(addr),
            data, len(data), ctypes.byref(got)) and got.value == len(data))


def vprotect(h, addr, size, new_prot):
    old = wt.DWORD()
    kernel32.VirtualProtectEx(h, ctypes.c_void_p(addr),
                              ctypes.c_size_t(size),
                              wt.DWORD(new_prot), ctypes.byref(old))
    return old.value


def write_protected(h, addr, data):
    page = addr & ~0xFFF
    old_prot = vprotect(h, page, 0x2000, PAGE_EXECUTE_READWRITE)
    ok = wmem(h, addr, data)
    vprotect(h, page, 0x2000, old_prot)
    return ok


def read_u32(h, addr):
    d = rmem(h, addr, 4)
    return struct.unpack('<I', d)[0] if d else None


def write_u32_protected(h, addr, val):
    return write_protected(h, addr, struct.pack('<I', val))


# ── Binary search helpers ────────────────────────────────────────────

def search_module(h, base, start_rva, end_rva, pattern):
    results = []
    CHUNK = 0x100000
    plen = len(pattern)
    for off in range(start_rva, end_rva, CHUNK):
        cs = min(CHUNK + plen, end_rva - off)
        data = rmem(h, base + off, cs)
        if not data:
            continue
        pos = 0
        while True:
            idx = data.find(pattern, pos)
            if idx == -1:
                break
            rva = off + idx
            if rva not in results:
                results.append(rva)
            pos = idx + 1
    return results


def find_lea_refs(h, base, text_start, text_end, target_rva):
    rip_rm = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}
    refs = []
    CHUNK = 0x100000
    for chunk_off in range(text_start, text_end, CHUNK):
        cs = min(CHUNK + 8, text_end - chunk_off)
        data = rmem(h, base + chunk_off, cs)
        if not data:
            continue
        for i in range(len(data) - 7):
            b0, b1, b2 = data[i], data[i+1], data[i+2]
            if (0x48 <= b0 <= 0x4F) and b1 == 0x8D and b2 in rip_rm:
                disp = struct.unpack_from('<i', data, i + 3)[0]
                inst_rva = chunk_off + i
                if inst_rva + 7 + disp == target_rva:
                    refs.append(inst_rva)
    return refs


# ── Find LanguageIsPermitted ─────────────────────────────────────────

def find_lang_permitted(h, base, mod_size):
    """Find LanguageIsPermitted by tracing from its assertion string."""
    pattern = b"LanguageIsPermitted("
    string_rvas = search_module(h, base, 0, mod_size, pattern)
    if not string_rvas:
        print("  Assertion string not found")
        return None

    text_end = min(mod_size, 0x1A00000)
    all_refs = []
    for sr in string_rvas:
        all_refs.extend(find_lea_refs(h, base, 0x1000, text_end, sr))
    if not all_refs:
        print("  No code references found")
        return None

    for lea_rva in all_refs:
        read_start = max(lea_rva - 120, 0)
        code = rmem(h, base + read_start, lea_rva - read_start + 16)
        if not code:
            continue
        lea_off = lea_rva - read_start
        for i in range(lea_off - 4, max(0, lea_off - 80), -1):
            if i + 2 > len(code) or code[i] != 0x85 or code[i+1] != 0xC0:
                continue
            jmp_ok = (i + 3 <= len(code) and code[i+2] in (0x74, 0x75)) or \
                     (i + 8 <= len(code) and code[i+2] == 0x0F and code[i+3] in (0x84, 0x85))
            if not jmp_ok:
                continue
            for j in range(i - 5, max(0, i - 40), -1):
                if code[j] != 0xE8:
                    continue
                call_rva = read_start + j
                disp = struct.unpack_from('<i', code, j + 1)[0]
                func_rva = call_rva + 5 + disp
                if 0 < func_rva < mod_size:
                    return func_rva
    return None


# ── Extract bitmask RVAs from function code ──────────────────────────

def extract_bitmask_rvas(h, base, func_rva, mod_size):
    """Parse LanguageIsPermitted's machine code to find the 4 bitmask
    global variables it references via RIP-relative addressing.

    Returns (permitted_rvas, blocked_rvas) or (None, None) on failure.
    Works even if the first 6 bytes are already patched (mov eax,1; ret),
    since the data references are all in later instructions."""
    code = rmem(h, base + func_rva, 160)
    if not code:
        return None, None

    # modrm bytes that encode RIP-relative addressing (mod=00, rm=101)
    rip_modrm = {0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D}

    # Single-byte opcodes that use modrm for memory access
    mem_ops = {0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B,
               0x31, 0x33, 0x39, 0x3B, 0x85, 0x87, 0x89, 0x8B}

    # .data section starts well above .text — filter out code-range refs
    data_lo = mod_size // 2

    targets = set()

    for i in range(len(code) - 5):
        # [opcode] [modrm_rip] [disp32]  — 6 bytes, no prefix
        if (code[i] in mem_ops and code[i+1] in rip_modrm
                and i + 6 <= len(code)):
            disp = struct.unpack_from('<i', code, i + 2)[0]
            target = func_rva + i + 6 + disp
            if data_lo < target < mod_size:
                targets.add(target)

        # [REX] [opcode] [modrm_rip] [disp32]  — 7 bytes
        if (0x40 <= code[i] <= 0x4F and code[i+1] in mem_ops
                and code[i+2] in rip_modrm and i + 7 <= len(code)):
            disp = struct.unpack_from('<i', code, i + 3)[0]
            target = func_rva + i + 7 + disp
            if data_lo < target < mod_size:
                targets.add(target)

        # [0F] [opcode2] [modrm_rip] [disp32]  — 7 bytes (BT, CMOVcc, etc.)
        if (code[i] == 0x0F and code[i+2] in rip_modrm
                and i + 7 <= len(code)):
            disp = struct.unpack_from('<i', code, i + 3)[0]
            target = func_rva + i + 7 + disp
            if data_lo < target < mod_size:
                targets.add(target)

        # [REX] [0F] [opcode2] [modrm_rip] [disp32]  — 8 bytes
        if (0x40 <= code[i] <= 0x4F and code[i+1] == 0x0F
                and code[i+3] in rip_modrm and i + 8 <= len(code)):
            disp = struct.unpack_from('<i', code, i + 4)[0]
            target = func_rva + i + 8 + disp
            if data_lo < target < mod_size:
                targets.add(target)

    if len(targets) < 4:
        return None, None

    # Cluster targets within 64 bytes of each other
    sorted_t = sorted(targets)
    clusters = [[sorted_t[0]]]
    for t in sorted_t[1:]:
        if t - clusters[-1][-1] <= 64:
            clusters[-1].append(t)
        else:
            clusters.append([t])

    if len(clusters) < 2:
        return None, None

    # Take the two largest clusters (should be size 2 each)
    clusters.sort(key=lambda c: -len(c))
    pair_a = sorted(clusters[0])
    pair_b = sorted(clusters[1])

    # Lower RVAs = .data (permitted masks), higher = .bss (blocked masks)
    if pair_a[0] < pair_b[0]:
        return pair_a, pair_b
    else:
        return pair_b, pair_a


# ── Patching ─────────────────────────────────────────────────────────

def patch_lang_permitted(h, base, func_rva):
    """Patch LanguageIsPermitted to: mov eax, 1; ret."""
    addr = base + func_rva
    patch = b'\xB8\x01\x00\x00\x00\xC3'
    current = rmem(h, addr, 6)
    if current == patch:
        print("  Already patched")
        return True
    ok = write_protected(h, addr, patch)
    if ok and rmem(h, addr, 6) == patch:
        print("  Patched -> always returns true")
        return True
    print("  Patch FAILED")
    return False


def patch_bitmasks(h, base, permitted_rvas, blocked_rvas):
    """Set permitted masks to 0x3F (all languages), clear blocked masks."""
    ok = True

    print("  Permitted masks -> 0x3F:")
    for rva in permitted_rvas:
        addr = base + rva
        val = read_u32(h, addr)
        if val is None:
            print(f"    RVA 0x{rva:08x}: unreadable"); ok = False; continue
        if val == ALL_PERMITTED:
            print(f"    RVA 0x{rva:08x}: 0x{val:02x} (already set)")
        elif write_u32_protected(h, addr, ALL_PERMITTED):
            print(f"    RVA 0x{rva:08x}: 0x{val:02x} -> 0x3f OK")
        else:
            print(f"    RVA 0x{rva:08x}: FAILED"); ok = False

    print("  Blocked masks -> 0x00:")
    for rva in blocked_rvas:
        addr = base + rva
        val = read_u32(h, addr)
        if val is None:
            print(f"    RVA 0x{rva:08x}: unreadable"); ok = False; continue
        if val == 0:
            print(f"    RVA 0x{rva:08x}: 0x00 (already clear)")
        elif write_u32_protected(h, addr, 0):
            print(f"    RVA 0x{rva:08x}: 0x{val:02x} -> 0x00 OK")
        else:
            print(f"    RVA 0x{rva:08x}: FAILED"); ok = False

    return ok


# ── Main ─────────────────────────────────────────────────────────────

def main():
    print("\n  GW2 Language Unlocker")
    print("  ====================\n")

    h, base, mod_size, pid = open_gw2()
    print(f"  PID {pid}, base 0x{base:016x}\n")

    # Step 1: Find LanguageIsPermitted function
    print("[1/3] Finding LanguageIsPermitted...")
    func_rva = find_lang_permitted(h, base, mod_size)
    if func_rva is None:
        print("  FAILED — cannot locate function")
        kernel32.CloseHandle(h)
        sys.exit(1)
    print(f"  Found at RVA 0x{func_rva:08x}")

    # Step 2: Extract bitmask addresses from the function's code
    print("\n[2/3] Extracting bitmask addresses from function code...")
    permitted, blocked = extract_bitmask_rvas(h, base, func_rva, mod_size)
    if permitted is None:
        print("  FAILED — could not extract bitmask RVAs")
        kernel32.CloseHandle(h)
        sys.exit(1)
    print(f"  Permitted masks: {', '.join(f'0x{r:08x}' for r in permitted)}")
    print(f"  Blocked masks:   {', '.join(f'0x{r:08x}' for r in blocked)}")

    # Step 3: Apply patches
    print("\n[3/3] Applying patches...")
    p1 = patch_lang_permitted(h, base, func_rva)
    p2 = patch_bitmasks(h, base, permitted, blocked)

    kernel32.CloseHandle(h)

    print()
    if p1 and p2:
        print("  All languages unlocked.")
        print("  Go to Options > Language to select any language.")
    else:
        print("  Some patches failed. Try running as Administrator.")
    print()


if __name__ == '__main__':
    main()
