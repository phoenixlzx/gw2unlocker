# GW2 Language Unlocker

Unlocks all 6 languages (English, Korean, French, German, Spanish, Simplified Chinese) on any Guild Wars 2 regional client and **persists your language choice across map transitions**.

Normally, each regional client only allows a subset of languages, and the server resets your language to the region's default during map loads. This tool removes both restrictions.

## How It Works

### Language Unlocking

Guild Wars 2 uses a function called `LanguageIsPermitted` to control which languages are available. It checks two layers of bitmasks:

1. **Permitted mask** — a bitmask in `.data` where each bit represents a language (bit 0 = English, ..., bit 5 = Chinese). If the bit is not set, the language is hidden.
2. **Blocked mask** — a bitmask in `.bss` that the server sets at runtime to further restrict languages.

The tool patches the running process to:
- **Patch `LanguageIsPermitted`** → always returns `true` (`mov eax, 1; ret`)
- **Set permitted masks to `0x3F`** (all 6 languages enabled)
- **Clear blocked masks to `0x00`** and **NOP their writers** (prevents the server from re-blocking)

### Language Persistence

During map transitions, the server sends a command to reset the client's language to the region default (English on NA/EU). The tool prevents this using a **hardware debug breakpoint**:

1. A **DR0 write-watchpoint** is set on the primary language variable (found dynamically at a fixed structural offset from the permitted bitmasks).
2. When the server writes `0` (English) to this variable, the CPU triggers a debug exception **before the next instruction executes**.
3. The tool's debug handler **overrides the CPU registers** (`ebx`, `edi`, `ecx`, `edx`) that carry the language ID through the setter function, replacing `0` with the player's chosen language.
4. The setter function resumes and applies the **player's language** instead of English — including asset loading and UI refresh.

This is fully synchronous (no polling delay) and does not modify any game code for language persistence.

### Dynamic Address Resolution

All addresses are found dynamically:
- `LanguageIsPermitted` is located via its assertion string reference in `.rdata`
- Bitmask RVAs are extracted by parsing x86-64 machine code for RIP-relative memory operands
- The language variable is at a fixed structural offset from the permitted bitmask array

This means the tool survives game updates without hardcoded offsets.

## Usage

### Pre-built executable (recommended)

1. Start Guild Wars 2 and log in normally.
2. Run `gw2unlock.exe` (requests Administrator automatically).
3. Go to **Options > Language** and select any language.
4. **Keep the tool running** — it protects your language choice across map transitions.
5. Close the tool when done playing (Ctrl+C or close the window).

### Python version

Requires Python 3.6+ and Windows. No third-party packages needed.

```
python gw2unlock.py
```

Must be run as Administrator. Keep it running while playing.

### Building from source

**MSVC (Visual Studio Developer Command Prompt, x64):**
```
rc gw2unlock.rc
cl /EHsc /O2 gw2unlock.cpp gw2unlock.res /Fe:gw2unlock.exe
```

**MinGW-w64:**
```
g++ -O2 -o gw2unlock.exe gw2unlock.cpp
```
Note: MinGW builds won't auto-request admin. Run as Administrator manually.

## Files

| File | Description |
|------|-------------|
| `gw2unlock.cpp` | C++ source (standalone, single file) |
| `gw2unlock.py` | Python version (identical functionality) |
| `gw2unlock.rc` | Resource file for embedding UAC manifest |
| `gw2unlock.manifest` | UAC manifest (requests Administrator) |

## Known Issues

- **Korean may crash** — Korean content may not be served on NA/EU servers.
- **Cannot switch to English** while the tool is running — writes of `0` (English) from the setter region are treated as server resets. Restart the game without the tool to switch back to English. Writes from other code paths are ignored (RIP check ensures only the setter region triggers overrides).
- **In-memory only** — patches do not modify any files on disk. Re-run the tool each time you start the game.
- The tool must stay running (it uses the Windows debug API to intercept language resets in real-time).

## Disclaimer

This tool is provided for educational and personal use. It modifies running process memory and does not alter any game files on disk. Use at your own risk.

This project is not affiliated with, endorsed by, or associated with ArenaNet or NCSOFT. Guild Wars 2 is a trademark of NCSOFT Corporation.

The author is not responsible for any consequences resulting from the use of this tool, including but not limited to account actions or game instability.

## License

MIT License

Copyright (c) 2025

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
