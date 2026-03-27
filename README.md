# GW2 Language Unlocker

Unlocks all 6 languages (English, Korean, French, German, Spanish, Simplified Chinese) on any Guild Wars 2 regional client. Normally, each regional client only allows a subset of languages — this tool removes that restriction.

## How It Works

Guild Wars 2 uses a function called `LanguageIsPermitted` to control which languages are available in each regional client. This function checks two layers of bitmasks:

1. **Permitted mask** — a bitmask in the `.data` section where each bit represents a language (bit 0 = English, bit 1 = Korean, ..., bit 5 = Chinese). If the bit for a language is not set, the client won't offer it.
2. **Blocked mask** — a bitmask in the `.bss` section that the server can set at runtime to further restrict languages. If a language's bit is set here, it is blocked even if permitted above.

The tool patches the running `Gw2-64.exe` process memory to:

1. **Patch `LanguageIsPermitted`** to always return `true` (`mov eax, 1; ret`), bypassing both bitmask checks entirely.
2. **Set permitted masks to `0x3F`** (all 6 language bits set).
3. **Clear blocked masks to `0x00`** (no languages blocked).

All addresses are found **dynamically** by locating the `LanguageIsPermitted` function through its assertion string reference, then parsing its x86-64 machine code to extract the bitmask global variable addresses via RIP-relative addressing. This means the tool should survive game updates without needing hardcoded offsets.

## Usage

### Pre-built executable (recommended)

1. Start Guild Wars 2 and log in normally.
2. Run `gw2unlock.exe` (it will request Administrator privileges automatically).
3. Go to **Options > Language** and select any language.

### Python version

Requires Python 3.6+ and Windows. No third-party packages needed.

```
py gw2unlock.py
```

Must be run as Administrator.

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
| `gw2unlock.rc` | Resource file for embedding UAC manifest |
| `gw2unlock.manifest` | UAC manifest (requests Administrator) |
| `gw2unlock.py` | Python version (identical functionality) |

## Known Issues

- Some languages may crash or not display correctly if the game servers don't serve content for that language on your regional server (e.g., Korean on NA/EU).
- The patch is applied to process memory only — it does not modify any files on disk. You need to re-run the tool each time you start the game.

## Disclaimer

This tool is provided for educational and personal use. It modifies running process memory and does not alter any game files on disk. Use at your own risk.

This project is not affiliated with, endorsed by, or associated with ArenaNet or NCSOFT. Guild Wars 2 is a trademark of NCSOFT Corporation.

The author is not responsible for any consequences resulting from the use of this tool, including but not limited to account actions or game instability.

## License

MIT
