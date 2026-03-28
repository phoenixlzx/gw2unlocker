/*
 * GW2 Language Unlocker
 *
 * Unlocks all 6 languages on any GW2 regional client by patching
 * LanguageIsPermitted and its permission bitmasks in process memory,
 * then attaches as a debugger with a hardware write-breakpoint on
 * the primary language variable to intercept server resets.
 *
 * Uses the synchronous debugger approach: DebugActiveProcess +
 * DR0 hardware watchpoint + register override on EXCEPTION_SINGLE_STEP.
 *
 * Run while Gw2-64.exe is running, then go to Options > Language.
 * The program stays running until the game exits.
 *
 * Compile (MSVC x64 -- Visual Studio Developer Command Prompt):
 *   cl /EHsc /O2 gw2unlock.cpp /Fe:gw2unlock.exe
 *
 * UAC admin elevation via gw2unlock.rc + gw2unlock.manifest.
 *
 * License: MIT
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

static const char *LANG_NAMES[] = {"en", "ko", "fr", "de", "es", "chs"};
static const uint32_t ALL_PERMITTED = 0x3F; // bits 0-5 = en,ko,fr,de,es,chs

// ---- Memory helpers --------------------------------------------------------

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

// ---- Process helpers -------------------------------------------------------

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

static std::vector<DWORD> get_thread_ids(DWORD pid) {
    std::vector<DWORD> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;

    THREADENTRY32 te;
    memset(&te, 0, sizeof(te));
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te)) { CloseHandle(snap); return tids; }

    do {
        if (te.th32OwnerProcessID == pid)
            tids.push_back(te.th32ThreadID);
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return tids;
}

// ---- Binary search ---------------------------------------------------------

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

// ---- Find LanguageIsPermitted ----------------------------------------------

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

// ---- Extract bitmask RVAs from function code -------------------------------

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

        // [opcode] [modrm_rip] [disp32] -- 6 bytes
        if (is_mem_op(code[i]) && is_rip_modrm(code[i + 1])
            && i + 6 <= code.size()) {
            memcpy(&disp, code.data() + i + 2, 4);
            target = func_rva + (uint32_t)i + 6 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [REX] [opcode] [modrm_rip] [disp32] -- 7 bytes
        if (code[i] >= 0x40 && code[i] <= 0x4F
            && is_mem_op(code[i + 1]) && is_rip_modrm(code[i + 2])
            && i + 7 <= code.size()) {
            memcpy(&disp, code.data() + i + 3, 4);
            target = func_rva + (uint32_t)i + 7 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [0F] [op2] [modrm_rip] [disp32] -- 7 bytes
        if (code[i] == 0x0F && i + 7 <= code.size()
            && is_rip_modrm(code[i + 2])) {
            memcpy(&disp, code.data() + i + 3, 4);
            target = func_rva + (uint32_t)i + 7 + disp;
            if (target > data_lo && target < mod_size)
                targets.insert(target);
        }

        // [REX] [0F] [op2] [modrm_rip] [disp32] -- 8 bytes
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

// ---- Find code that writes to blocked bitmask addresses --------------------

struct WriteRef {
    uint32_t inst_rva;
    uint8_t  inst_len;
};

static bool is_store_op(uint8_t b) {
    switch (b) {
        case 0x00: case 0x01: case 0x08: case 0x09:
        case 0x10: case 0x11: case 0x18: case 0x19:
        case 0x20: case 0x21: case 0x28: case 0x29:
        case 0x30: case 0x31: case 0x88: case 0x89:
            return true;
    }
    return false;
}

static std::vector<WriteRef> find_rip_writes(HANDLE h, uintptr_t base,
    uint32_t text_start, uint32_t text_end, uint32_t target_rva)
{
    std::vector<WriteRef> results;
    const uint32_t CHUNK = 0x100000;

    for (uint32_t chunk_off = text_start; chunk_off < text_end; chunk_off += CHUNK) {
        size_t cs = (size_t)CHUNK + 16;
        if (chunk_off + cs > text_end) cs = text_end - chunk_off;
        auto data = rmem(h, base + chunk_off, cs);
        if (data.size() < 12) continue;

        for (size_t i = 0; i + 6 <= data.size(); i++) {
            uint8_t b0 = data[i];
            bool rex = (b0 >= 0x40 && b0 <= 0x4F);
            size_t p = rex ? 1 : 0;
            if (i + p + 6 > data.size()) continue;

            uint8_t op    = data[i + p];
            uint8_t modrm = data[i + p + 1];
            if (!is_rip_modrm(modrm)) continue;

            int32_t disp;
            uint32_t irva = chunk_off + (uint32_t)i;
            uint8_t ilen = 0;

            // [REX?] store_op modrm disp32
            if (is_store_op(op)) {
                ilen = (uint8_t)(p + 6);
                memcpy(&disp, data.data() + i + p + 2, 4);
            }
            // [REX?] 80/83 modrm disp32 imm8 (group1 ALU, reg!=7=CMP)
            else if ((op == 0x80 || op == 0x83) && (modrm & 0x38) != 0x38) {
                ilen = (uint8_t)(p + 7);
                if (i + p + 7 > data.size()) continue;
                memcpy(&disp, data.data() + i + p + 2, 4);
            }
            // [REX?] 81 modrm disp32 imm32 (group1 ALU, reg!=7)
            else if (op == 0x81 && (modrm & 0x38) != 0x38) {
                ilen = (uint8_t)(p + 10);
                if (i + p + 10 > data.size()) continue;
                memcpy(&disp, data.data() + i + p + 2, 4);
            }
            // [REX?] C7 /0 modrm disp32 imm32 (MOV [mem], imm32)
            else if (op == 0xC7 && (modrm & 0x38) == 0x00) {
                ilen = (uint8_t)(p + 10);
                if (i + p + 10 > data.size()) continue;
                memcpy(&disp, data.data() + i + p + 2, 4);
            }
            else continue;

            if ((uint32_t)(irva + ilen + disp) == target_rva)
                results.push_back({irva, ilen});
        }
    }

    // Deduplicate overlapping entries
    std::sort(results.begin(), results.end(),
        [](const WriteRef &a, const WriteRef &b) { return a.inst_rva < b.inst_rva; });
    for (size_t i = 1; i < results.size(); ) {
        if (results[i].inst_rva < results[i-1].inst_rva + results[i-1].inst_len)
            results.erase(results.begin() + i);
        else i++;
    }
    return results;
}

// ---- Find primary language variable ----------------------------------------
// The language variable is at a fixed structural offset from the
// permitted bitmask array: max(permitted_rvas) + 8.

static uint32_t find_primary_lang_rva(const BitmaskRVAs &rvas) {
    uint32_t max_perm = 0;
    for (auto r : rvas.permitted)
        if (r > max_perm) max_perm = r;
    return max_perm + 8;
}

// ---- Patching --------------------------------------------------------------

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

// ---- Hardware watchpoint helpers -------------------------------------------

static bool set_watchpoint(DWORD tid, uintptr_t va) {
    HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!ht) return false;

    SuspendThread(ht);
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_FULL;
    if (!GetThreadContext(ht, &ctx)) {
        ResumeThread(ht);
        CloseHandle(ht);
        return false;
    }

    ctx.Dr0 = (DWORD64)va;
    // DR7: bit 0 = L0 enable, bits 16-17 = R/W0 (01 = write), bits 18-19 = LEN0 (11 = 4 bytes)
    ctx.Dr7 = (ctx.Dr7 & ~(DWORD64)0xF0003) | 0xD0001;

    SetThreadContext(ht, &ctx);
    ResumeThread(ht);
    CloseHandle(ht);
    return true;
}

static void clear_watchpoint(DWORD tid) {
    HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
    if (!ht) return;

    SuspendThread(ht);
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(ht, &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr1 = 0;
        ctx.Dr2 = 0;
        ctx.Dr3 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 = 0;
        SetThreadContext(ht, &ctx);
    }
    ResumeThread(ht);
    CloseHandle(ht);
}

// ---- Main ------------------------------------------------------------------

int main() {
    printf("\n  GW2 Language Unlocker (Debugger)\n");
    printf("  ================================\n\n");

    // Step 0: Find process and module
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

    HANDLE hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) {
        printf("ERROR: Cannot open process. Run as Administrator.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    printf("  PID %u, base 0x%llx, size 0x%x\n\n",
           pid, (unsigned long long)base, mod_size);

    uint32_t text_start = 0x1000;
    uint32_t text_end = mod_size < 0x1A00000u ? mod_size : 0x1A00000u;

    // Step 1: Find LanguageIsPermitted
    printf("[1/4] Finding LanguageIsPermitted...\n");
    uint32_t func_rva = find_lang_permitted(hp, base, mod_size);
    if (!func_rva) {
        printf("  FAILED\n");
        CloseHandle(hp);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    printf("  Found at RVA 0x%08x\n", func_rva);

    // Step 2: Extract bitmask addresses
    printf("\n[2/4] Extracting bitmask addresses...\n");
    BitmaskRVAs rvas;
    if (!extract_bitmask_rvas(hp, base, func_rva, mod_size, rvas)) {
        printf("  FAILED -- could not extract bitmask RVAs\n");
        CloseHandle(hp);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    printf("  Permitted masks:");
    for (auto r : rvas.permitted) printf(" 0x%08x", r);
    printf("\n  Blocked masks:  ");
    for (auto r : rvas.blocked) printf(" 0x%08x", r);
    printf("\n");

    uint32_t lang_rva = find_primary_lang_rva(rvas);
    printf("  Primary language var: RVA 0x%08x (value: %u)\n",
           lang_rva, read_u32(hp, base + lang_rva));

    // Step 3: NOP RIP-relative writes to blocked bitmask addresses
    printf("\n[3/4] Neutralizing blocked-mask writers in .text...\n");
    int total_nopped = 0;
    for (auto target_rva : rvas.blocked) {
        auto writes = find_rip_writes(hp, base, text_start, text_end, target_rva);
        printf("  RVA 0x%08x: %zu write(s) found\n", target_rva, writes.size());
        for (auto &w : writes) {
            auto orig = rmem(hp, base + w.inst_rva, w.inst_len);
            bool already = true;
            for (auto b : orig) if (b != 0x90) { already = false; break; }
            if (already) {
                printf("    0x%08x: already NOPed\n", w.inst_rva);
            } else {
                std::vector<uint8_t> nops(w.inst_len, 0x90);
                if (write_protected(hp, base + w.inst_rva, nops.data(), nops.size())) {
                    printf("    0x%08x: ", w.inst_rva);
                    for (auto b : orig) printf("%02x ", b);
                    printf("-> NOPed (%d bytes)\n", w.inst_len);
                    total_nopped++;
                } else {
                    printf("    0x%08x: NOP FAILED\n", w.inst_rva);
                }
            }
        }
    }
    if (total_nopped == 0)
        printf("  (no new writes to neutralize)\n");

    // Step 4: Apply unlock patches
    printf("\n[4/4] Applying unlock patches...\n");
    bool p1 = patch_lang_permitted(hp, base, func_rva);
    bool p2 = patch_bitmasks(hp, base, rvas);

    printf("\n");
    if (p1 && p2) {
        printf("  All languages unlocked.\n");
        printf("  Go to Options > Language to select any language.\n");
    } else {
        printf("  Some patches failed. Try running as Administrator.\n");
    }

    // ---- Debugger attach ---------------------------------------------------

    uint32_t desired = read_u32(hp, base + lang_rva);
    if (desired <= 5)
        printf("\n  Current language: %u (%s)\n", desired, LANG_NAMES[desired]);
    if (desired == 0)
        printf("  Select a non-English language in-game. Auto-detected.\n");

    printf("\n  Attaching debugger...\n");
    CloseHandle(hp); // Must close before DebugActiveProcess

    if (!DebugActiveProcess(pid)) {
        printf("  ERROR: DebugActiveProcess failed (error %lu)\n", GetLastError());
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    DebugSetProcessKillOnExit(FALSE);

    // Re-open process handle after attach
    hp = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hp) {
        printf("  ERROR: Cannot re-open process after attach\n");
        DebugActiveProcessStop(pid);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }

    uintptr_t lang_va = base + lang_rva;
    bool watchpoint_set = false;
    int overrides = 0;

    printf("  Debugger attached. Waiting for initial breakpoint...\n");

    // ---- Debug event loop --------------------------------------------------

    DEBUG_EVENT ev;
    memset(&ev, 0, sizeof(ev));

    while (true) {
        if (!WaitForDebugEvent(&ev, 3000))
            continue;

        DWORD continue_status = DBG_CONTINUE;

        switch (ev.dwDebugEventCode) {

        case EXCEPTION_DEBUG_EVENT: {
            DWORD exc = ev.u.Exception.ExceptionRecord.ExceptionCode;

            // Initial breakpoint: set watchpoint on all threads
            if (exc == EXCEPTION_BREAKPOINT && !watchpoint_set) {
                watchpoint_set = true;
                auto tids = get_thread_ids(pid);
                int ok_count = 0;
                for (auto tid : tids) {
                    if (set_watchpoint(tid, lang_va))
                        ok_count++;
                }
                printf("  Watchpoint set on %d/%zu threads (DR0 = 0x%llx)\n",
                       ok_count, tids.size(), (unsigned long long)lang_va);
                printf("\n  Language will be protected across map transitions.\n");
                printf("  Keep this window open. The program exits when the game exits.\n\n");
                break;
            }

            // Hardware breakpoint hit (write to language variable)
            if (exc == EXCEPTION_SINGLE_STEP && watchpoint_set) {
                HANDLE ht = OpenThread(THREAD_ALL_ACCESS, FALSE, ev.dwThreadId);
                if (ht) {
                    CONTEXT ctx;
                    memset(&ctx, 0, sizeof(ctx));
                    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
                    GetThreadContext(ht, &ctx);

                    if (ctx.Dr6 & 1) { // DR0 triggered
                        uint32_t val = read_u32(hp, base + lang_rva);

                        if (val > 0 && val <= 5 && val != desired) {
                            // User changed language
                            desired = val;
                            printf("  Language changed: %u (%s)\n",
                                   desired, LANG_NAMES[desired]);
                        }
                        else if (val == 0 && desired > 0) {
                            // SERVER RESET DETECTED
                            // The function is paused AFTER writing 0 to the lang var.
                            // Override registers that carry the langId.

                            // Restore primary variable
                            write_u32_protected(hp, base + lang_rva, desired);

                            // Override Rbx (used for primary var writes)
                            ctx.Rbx = (DWORD64)desired;
                            // Override Rdi (used for secondary writes)
                            ctx.Rdi = (DWORD64)desired;
                            // Override Rcx if it looks like a langId (0-5)
                            if (ctx.Rcx <= 5)
                                ctx.Rcx = (DWORD64)desired;
                            // Override Rdx if it looks like a langId (0-5)
                            if (ctx.Rdx <= 5)
                                ctx.Rdx = (DWORD64)desired;

                            // Clear DR6 and apply
                            ctx.Dr6 = 0;
                            SetThreadContext(ht, &ctx);

                            overrides++;
                            if (overrides <= 10)
                                printf("  [override] Server reset -> restored to %u (%s)\n",
                                       desired, LANG_NAMES[desired]);
                            else if (overrides == 11)
                                printf("  [override] (further messages suppressed)\n");

                            CloseHandle(ht);
                            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                            continue;
                        }
                    }

                    // Clear DR6 and continue
                    ctx.Dr6 = 0;
                    SetThreadContext(ht, &ctx);
                    CloseHandle(ht);
                }
                break;
            }

            // Other exceptions: pass to the application
            continue_status = DBG_EXCEPTION_NOT_HANDLED;
            break;
        }

        case CREATE_THREAD_DEBUG_EVENT:
            // Set watchpoint on newly created thread
            if (watchpoint_set) {
                set_watchpoint(ev.dwThreadId, lang_va);
            }
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            printf("  Game exited.\n");
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
            goto done;

        default:
            break;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, continue_status);
    }

done:
    // ---- Cleanup -----------------------------------------------------------

    printf("\n  Total register overrides: %d\n", overrides);

    // Clear watchpoints on all threads
    auto tids = get_thread_ids(pid);
    for (auto tid : tids)
        clear_watchpoint(tid);

    CloseHandle(hp);
    DebugActiveProcessStop(pid);
    printf("  Detached.\n");

    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}
