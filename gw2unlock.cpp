/*
 * GW2 Language Unlocker
 *
 * Unlocks all 6 languages on any GW2 regional client by patching
 * LanguageIsPermitted and its permission bitmasks in process memory.
 * All addresses are found dynamically — survives game updates.
 *
 * Run while Gw2-64.exe is running, then go to Options > Language.
 *
 * Compile (MSVC x64 — Visual Studio Developer Command Prompt):
 *   cl /EHsc /O2 gw2unlock.cpp /Fe:gw2unlock.exe
 *
 * Compile (MinGW-w64):
 *   g++ -O2 -o gw2unlock.exe gw2unlock.cpp
 */

#if !defined(_WIN64) && !defined(__x86_64__)
#error "Must compile as 64-bit (target is Gw2-64.exe)"
#endif

#undef UNICODE
#undef _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <set>
#include <algorithm>

// UAC admin elevation is embedded via gw2unlock.rc + gw2unlock.manifest

static const uint32_t ALL_PERMITTED = 0x3F; // bits 0-5 = en,ko,fr,de,es,chs

// ── Memory helpers ──────────────────────────────────────────────

static std::vector<uint8_t> rmem(HANDLE h, uintptr_t addr, size_t n) {
    std::vector<uint8_t> buf(n);
    SIZE_T got = 0;
    if (ReadProcessMemory(h, (LPCVOID)addr, buf.data(), n, &got) && got > 0) {
        buf.resize(got);
        return buf;
    }
    return {};
}

static bool wmem(HANDLE h, uintptr_t addr, const void *data, size_t n) {
    SIZE_T got = 0;
    return WriteProcessMemory(h, (LPVOID)addr, data, n, &got) && got == n;
}

static bool write_protected(HANDLE h, uintptr_t addr, const void *data, size_t n) {
    uintptr_t page = addr & ~(uintptr_t)0xFFF;
    DWORD old_prot = 0;
    VirtualProtectEx(h, (LPVOID)page, 0x2000, PAGE_EXECUTE_READWRITE, &old_prot);
    bool ok = wmem(h, addr, data, n);
    DWORD tmp;
    VirtualProtectEx(h, (LPVOID)page, 0x2000, old_prot, &tmp);
    return ok;
}

static uint32_t read_u32(HANDLE h, uintptr_t addr) {
    uint32_t val = 0;
    SIZE_T got = 0;
    ReadProcessMemory(h, (LPCVOID)addr, &val, 4, &got);
    return val;
}

static bool write_u32_protected(HANDLE h, uintptr_t addr, uint32_t val) {
    return write_protected(h, addr, &val, 4);
}

// ── Process helpers ─────────────────────────────────────────────

static DWORD find_pid() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe;
    memset(&pe, 0, sizeof(pe));
    pe.dwSize = sizeof(pe);
    if (!Process32First(snap, &pe)) { CloseHandle(snap); return 0; }

    do {
        if (_stricmp(pe.szExeFile, "Gw2-64.exe") == 0) {
            DWORD pid = pe.th32ProcessID;
            CloseHandle(snap);
            return pid;
        }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return 0;
}

static bool get_module_info(DWORD pid, uintptr_t &base, uint32_t &mod_size) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return false;

    MODULEENTRY32 me;
    memset(&me, 0, sizeof(me));
    me.dwSize = sizeof(me);
    if (!Module32First(snap, &me)) { CloseHandle(snap); return false; }

    do {
        if (_stricmp(me.szModule, "Gw2-64.exe") == 0) {
            base = (uintptr_t)me.modBaseAddr;
            mod_size = me.modBaseSize;
            CloseHandle(snap);
            return true;
        }
    } while (Module32Next(snap, &me));

    CloseHandle(snap);
    return false;
}

// ── Binary search ───────────────────────────────────────────────

static std::vector<uint32_t> search_module(HANDLE h, uintptr_t base,
    uint32_t start_rva, uint32_t end_rva,
    const uint8_t *pattern, size_t plen)
{
    std::vector<uint32_t> results;
    const uint32_t CHUNK = 0x100000;

    for (uint32_t off = start_rva; off < end_rva; off += CHUNK) {
        size_t cs = (size_t)CHUNK + plen;
        if (off + cs > end_rva) cs = end_rva - off;

        auto data = rmem(h, base + off, cs);
        if (data.size() < plen) continue;

        for (size_t pos = 0; pos + plen <= data.size(); pos++) {
            if (memcmp(data.data() + pos, pattern, plen) == 0) {
                uint32_t rva = off + (uint32_t)pos;
                if (std::find(results.begin(), results.end(), rva) == results.end())
                    results.push_back(rva);
            }
        }
    }
    return results;
}

static bool is_rip_modrm(uint8_t b) {
    return (b & 0xC7) == 0x05;
}

static std::vector<uint32_t> find_lea_refs(HANDLE h, uintptr_t base,
    uint32_t text_start, uint32_t text_end, uint32_t target_rva)
{
    std::vector<uint32_t> refs;
    const uint32_t CHUNK = 0x100000;

    for (uint32_t chunk_off = text_start; chunk_off < text_end; chunk_off += CHUNK) {
        size_t cs = (size_t)CHUNK + 8;
        if (chunk_off + cs > text_end) cs = text_end - chunk_off;

        auto data = rmem(h, base + chunk_off, cs);
        if (data.size() < 8) continue;

        for (size_t i = 0; i + 7 <= data.size(); i++) {
            uint8_t b0 = data[i], b1 = data[i + 1], b2 = data[i + 2];
            if (b0 >= 0x48 && b0 <= 0x4F && b1 == 0x8D && is_rip_modrm(b2)) {
                int32_t disp;
                memcpy(&disp, data.data() + i + 3, 4);
                uint32_t inst_rva = chunk_off + (uint32_t)i;
                if ((uint32_t)(inst_rva + 7 + disp) == target_rva)
                    refs.push_back(inst_rva);
            }
        }
    }
    return refs;
}

// ── Find LanguageIsPermitted ────────────────────────────────────

static uint32_t find_lang_permitted(HANDLE h, uintptr_t base, uint32_t mod_size) {
    const uint8_t pattern[] = "LanguageIsPermitted(";
    auto string_rvas = search_module(h, base, 0, mod_size,
                                     pattern, sizeof(pattern) - 1);
    if (string_rvas.empty()) {
        printf("  Assertion string not found\n");
        return 0;
    }

    uint32_t text_end = mod_size < 0x1A00000u ? mod_size : 0x1A00000u;
    std::vector<uint32_t> all_refs;
    for (auto sr : string_rvas) {
        auto refs = find_lea_refs(h, base, 0x1000, text_end, sr);
        all_refs.insert(all_refs.end(), refs.begin(), refs.end());
    }
    if (all_refs.empty()) {
        printf("  No code references found\n");
        return 0;
    }

    for (auto lea_rva : all_refs) {
        uint32_t read_start = lea_rva > 120 ? lea_rva - 120 : 0;
        size_t read_size = (size_t)(lea_rva - read_start) + 16;
        auto code = rmem(h, base + read_start, read_size);
        if (code.empty()) continue;

        int lea_off = (int)(lea_rva - read_start);

        // Search backward for test eax,eax (85 C0)
        for (int i = lea_off - 4; i >= 0 && i > lea_off - 80; i--) {
            if ((size_t)i + 2 > code.size()) continue;
            if (code[i] != 0x85 || code[i + 1] != 0xC0) continue;

            bool jmp_ok = false;
            if ((size_t)i + 3 <= code.size() &&
                (code[i + 2] == 0x74 || code[i + 2] == 0x75))
                jmp_ok = true;
            else if ((size_t)i + 4 <= code.size() && code[i + 2] == 0x0F &&
                     (code[i + 3] == 0x84 || code[i + 3] == 0x85))
                jmp_ok = true;
            if (!jmp_ok) continue;

            // Search backward for call (E8 disp32)
            for (int j = i - 5; j >= 0 && j > i - 40; j--) {
                if (code[j] != 0xE8) continue;
                uint32_t call_rva = read_start + (uint32_t)j;
                int32_t disp;
                memcpy(&disp, code.data() + j + 1, 4);
                uint32_t func_rva = call_rva + 5 + disp;
                if (func_rva > 0 && func_rva < mod_size)
                    return func_rva;
            }
        }
    }

    printf("  Could not locate function\n");
    return 0;
}

// ── Extract bitmask RVAs from function code ─────────────────────

static bool is_mem_op(uint8_t b) {
    static const uint8_t ops[] = {
        0x01, 0x03, 0x09, 0x0B, 0x21, 0x23, 0x29, 0x2B,
        0x31, 0x33, 0x39, 0x3B, 0x85, 0x87, 0x89, 0x8B
    };
    for (auto o : ops)
        if (b == o) return true;
    return false;
}

struct BitmaskRVAs {
    std::vector<uint32_t> permitted;
    std::vector<uint32_t> blocked;
};

static bool extract_bitmask_rvas(HANDLE h, uintptr_t base,
    uint32_t func_rva, uint32_t mod_size, BitmaskRVAs &out)
{
    auto code = rmem(h, base + func_rva, 160);
    if (code.size() < 20) return false;

    uint32_t data_lo = mod_size / 2; // .data/.bss is in upper half of module
    std::set<uint32_t> targets;

    for (size_t i = 0; i + 5 < code.size(); i++) {
        int32_t disp;
        uint32_t target;

        // [opcode] [modrm_rip] [disp32] — 6 bytes
        if (is_mem_op(code[i]) && is_rip_modrm(code[i + 1])
            && i + 6 <= code.size()) {
            memcpy(&disp, code.data() + i + 2, 4);
            target = func_rva + (uint32_t)i + 6 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [REX] [opcode] [modrm_rip] [disp32] — 7 bytes
        if (code[i] >= 0x40 && code[i] <= 0x4F
            && is_mem_op(code[i + 1]) && is_rip_modrm(code[i + 2])
            && i + 7 <= code.size()) {
            memcpy(&disp, code.data() + i + 3, 4);
            target = func_rva + (uint32_t)i + 7 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [0F] [op2] [modrm_rip] [disp32] — 7 bytes
        if (code[i] == 0x0F && i + 7 <= code.size()
            && is_rip_modrm(code[i + 2])) {
            memcpy(&disp, code.data() + i + 3, 4);
            target = func_rva + (uint32_t)i + 7 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [REX] [0F] [op2] [modrm_rip] [disp32] — 8 bytes
        if (code[i] >= 0x40 && code[i] <= 0x4F && code[i + 1] == 0x0F
            && i + 8 <= code.size() && is_rip_modrm(code[i + 3])) {
            memcpy(&disp, code.data() + i + 4, 4);
            target = func_rva + (uint32_t)i + 8 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }
    }

    if (targets.size() < 4) return false;

    // Cluster targets within 64 bytes of each other
    std::vector<uint32_t> sorted_t(targets.begin(), targets.end());
    std::vector<std::vector<uint32_t>> clusters;
    clusters.push_back({sorted_t[0]});

    for (size_t i = 1; i < sorted_t.size(); i++) {
        if (sorted_t[i] - clusters.back().back() <= 64)
            clusters.back().push_back(sorted_t[i]);
        else
            clusters.push_back({sorted_t[i]});
    }

    if (clusters.size() < 2) return false;

    // Take the two largest clusters
    std::sort(clusters.begin(), clusters.end(),
              [](const std::vector<uint32_t> &a, const std::vector<uint32_t> &b) {
                  return a.size() > b.size();
              });

    auto &a = clusters[0];
    auto &b = clusters[1];

    // Lower RVAs = .data (permitted masks), higher = .bss (blocked masks)
    if (a[0] < b[0]) {
        out.permitted = a;
        out.blocked = b;
    } else {
        out.permitted = b;
        out.blocked = a;
    }
    return true;
}

// ── Patching ────────────────────────────────────────────────────

static bool patch_lang_permitted(HANDLE h, uintptr_t base, uint32_t func_rva) {
    uintptr_t addr = base + func_rva;
    const uint8_t patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3}; // mov eax,1; ret

    auto current = rmem(h, addr, 6);
    if (current.size() == 6 && memcmp(current.data(), patch, 6) == 0) {
        printf("  Already patched\n");
        return true;
    }

    if (!write_protected(h, addr, patch, 6)) {
        printf("  Patch FAILED\n");
        return false;
    }
    auto verify = rmem(h, addr, 6);
    if (verify.size() == 6 && memcmp(verify.data(), patch, 6) == 0) {
        printf("  Patched -> always returns true\n");
        return true;
    }
    printf("  Patch FAILED (verify)\n");
    return false;
}

static bool patch_bitmasks(HANDLE h, uintptr_t base, const BitmaskRVAs &rvas) {
    bool ok = true;

    printf("  Permitted masks -> 0x3F:\n");
    for (auto rva : rvas.permitted) {
        uintptr_t addr = base + rva;
        uint32_t val = read_u32(h, addr);
        if (val == ALL_PERMITTED) {
            printf("    RVA 0x%08x: 0x%02x (already set)\n", rva, val);
        } else if (write_u32_protected(h, addr, ALL_PERMITTED)) {
            printf("    RVA 0x%08x: 0x%02x -> 0x3f OK\n", rva, val);
        } else {
            printf("    RVA 0x%08x: FAILED\n", rva);
            ok = false;
        }
    }

    printf("  Blocked masks -> 0x00:\n");
    for (auto rva : rvas.blocked) {
        uintptr_t addr = base + rva;
        uint32_t val = read_u32(h, addr);
        if (val == 0) {
            printf("    RVA 0x%08x: 0x00 (already clear)\n", rva);
        } else if (write_u32_protected(h, addr, 0)) {
            printf("    RVA 0x%08x: 0x%02x -> 0x00 OK\n", rva, val);
        } else {
            printf("    RVA 0x%08x: FAILED\n", rva);
            ok = false;
        }
    }

    return ok;
}

// ── Main ────────────────────────────────────────────────────────

int main() {
    printf("\n  GW2 Language Unlocker\n");
    printf("  ====================\n\n");

    // Find process
    DWORD pid = find_pid();
    if (!pid) {
        printf("ERROR: Gw2-64.exe not found. Is the game running?\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    uintptr_t base = 0;
    uint32_t mod_size = 0;
    if (!get_module_info(pid, base, mod_size)) {
        printf("ERROR: Could not get module info. Run as Administrator.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) {
        printf("ERROR: Cannot open process. Run as Administrator.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    printf("  PID %u, base 0x%llx\n\n", pid, (unsigned long long)base);

    // Step 1: Find function
    printf("[1/3] Finding LanguageIsPermitted...\n");
    uint32_t func_rva = find_lang_permitted(h, base, mod_size);
    if (!func_rva) {
        printf("  FAILED\n");
        CloseHandle(h);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    printf("  Found at RVA 0x%08x\n", func_rva);

    // Step 2: Extract bitmask addresses
    printf("\n[2/3] Extracting bitmask addresses...\n");
    BitmaskRVAs rvas;
    if (!extract_bitmask_rvas(h, base, func_rva, mod_size, rvas)) {
        printf("  FAILED — could not extract bitmask RVAs\n");
        CloseHandle(h);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    printf("  Permitted masks:");
    for (auto r : rvas.permitted) printf(" 0x%08x", r);
    printf("\n  Blocked masks:  ");
    for (auto r : rvas.blocked) printf(" 0x%08x", r);
    printf("\n");

    // Step 3: Apply patches
    printf("\n[3/3] Applying patches...\n");
    bool p1 = patch_lang_permitted(h, base, func_rva);
    bool p2 = patch_bitmasks(h, base, rvas);

    CloseHandle(h);

    printf("\n");
    if (p1 && p2) {
        printf("  All languages unlocked.\n");
        printf("  Go to Options > Language to select any language.\n");
    } else {
        printf("  Some patches failed. Try running as Administrator.\n");
    }

    printf("\nPress Enter to exit...");
    getchar();
    return (p1 && p2) ? 0 : 1;
}
