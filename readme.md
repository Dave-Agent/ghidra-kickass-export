# Kick Assembler Export Script for Ghidra

[![GitHub release](https://img.shields.io/github/release/yourusername/ghidra-kickass-export.svg)](https://github.com/yourusername/ghidra-kickass-export/releases) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) [![Ghidra](https://img.shields.io/badge/Ghidra-10.x+-green.svg)](https://ghidra-sre.org/)

Export Ghidra disassembly to Kick Assembler format with comprehensive symbol handling and cross-references. This Python script is designed for reverse engineering and decompilation of retro 6502/6510/65C02 programs, converting analyzed binaries into clean, reassemblable source code that preserves your research and analysis work.

Useful for reverse engineering classic games, firmware analysis, and retro software projects on systems like the Commodore 64, Apple II, NES, Atari 8-bit, and other 6502-based platforms. The tool preserves your Ghidra analysis—including user-defined labels, comments, function boundaries, data structures, and memory maps—while generating proper Kick Assembler syntax with optimized addressing modes and symbol resolution.

The script creates two files: a main assembly file with your program's disassembled code and data, plus a separate symbols file containing labels with cross-reference information. This approach helps organize the output and makes it easier to understand program flow, identify code patterns, and track data usage across the software.

Intended for retro computing enthusiasts, ROM hackers, game preservation projects, and anyone analyzing classic software. Whether you're documenting source code, creating educational materials, analyzing copy protection, or preparing code for modification, this tool converts binary analysis into workable assembly source code.

## Screenshots

### Sample Output Comparison

| Ghidra Disassembly                                 | Kick Assembler Output                                        |
| -------------------------------------------------- | ------------------------------------------------------------ |
| ![Sample Ghidra Code](docs/images/ghidra_code.png) | ![Resulting Kick Assembler](docs/images/kick_assembler_code.png) |

## Features

- ✅ Converts Ghidra disassembly to Kick Assembler syntax
- ✅ Preserves symbols and labels with proper sanitisation
- ✅ Generates separate symbols file with cross-references
- ✅ Handles various 65xx addressing modes
- ✅ Maintains comments and cross-reference information
- ✅ Unified processing of code and data sections
- ✅ Configurable output paths with persistence
- ✅ PETSCII comment generation for data bytes

## Installation

1. **Download the script**: Copy `KickAssemblerExport.py` to your Ghidra scripts directory:
   - **Windows**: `%USERPROFILE%\ghidra_scripts`
   - **Linux/macOS**: `~/ghidra_scripts`
2. **Refresh Ghidra**: In Ghidra's Script Manager (Window → Script Manager → Refresh button)

![Installation Guide](docs/images/script_location.png)

## Usage

### GUI Mode

1. Open your program in Ghidra
2. Run the script via:
   - **Script Manager**: Find "Kick Assembler Export" under "Kick Assembler Tools"
   - **Keyboard**: `Ctrl+Alt+K`
   - **Menu**: Tools → Kick Assembler Export

### Output Files

- `[ProgramName].asm` - Main assembly file with code and data
- `[ProgramName]_Symbols.asm` - Symbols and labels file with cross-references

### Sample Output

**Main Assembly File:**

```assembly
// Disassembly of: C64_Game
// Generated on: 2024-01-15 14:30:22
// Exported from Ghidra to Kick Assembler format

#import "C64_Game_Symbols.asm"

// *** BLOCK START: RAM (0800 - 0FFF) ***
.pc = $0800 "RAM"

start:
  lda #$00                           // [0800:A9 00     LDA #0x0]
  sta BORDER_COLOR                   // [0802:8D 20 D0  STA $d020]
  jmp main_loop                      // [0805:4C 10 08  JMP $0810]
```

**Symbols File:**

```assembly
#importonce

.label BORDER_COLOR = $D020        // XREF[3]: start:0802(W), init:0820(W), cleanup:0845(W)
.label SCREEN_MEMORY = $0400       // XREF[1]: print_text:0830(W)
```

## Configuration

**Default locations:**

- Main files: `~/ghidra_kick_assembler_exports/src/`
- Symbols import: Automatic via `#import` directive
- Path preference: Saved between sessions

## Requirements

- **Ghidra**: 10.x or later
- **Python**: 2.7 (Ghidra's Jython environment)
- **Target**: Designed for 6510/6502/65C02 processors

## What Makes This Different

Unlike basic disassembly exports, this script:

- 🎯 **Smart Symbol Handling**: Prioritizes user-defined labels over auto-generated ones
- 🔗 **Cross-Reference Tracking**: Shows where symbols are used throughout the code
- 📝 **Comment Preservation**: Maintains your analysis comments from Ghidra
- 🏗️ **Structured Output**: Separates code from symbol definitions for cleaner assembly
- ⚡ **Kick Assembler Specific**: Generates syntax specifically for Kick Assembler

## Known Limitations

- Designed primarily for 6510/6502/65C02 processors
- Complex addressing modes may require manual review



## Changelog

### v1.0.0

- Initial release with basic export functionality
- Symbol file generation with cross-references
- Configurable output paths

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and run the test harness (see below)
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### Development Setup

```bash
# Clone the repo
git clone https://github.com/Dave-Agent/ghidra-kickass-export.git

# Symlink the script into Ghidra's scripts directory (pick up changes without copying)
ln -s "$(pwd)/ghidra_scripts/KickAssemblerExport.py" ~/ghidra_scripts/
```

### Testing

The test harness in `tests/` uses Ghidra headless mode to verify that changes produce identical output to the previous version, and optionally round-trips the result through KickAss. Results land in `tests/results/` (git-ignored) and are kept after the run for human review.

#### Prerequisites

- Ghidra installed (set `GHIDRA` env var if not at the default path)
- KickAss.jar available (set `KICKASS` env var if not at the default path)
- A C64 Kernal ROM at `tests/kernal.901227-03.bin` (see below)

#### Kernal ROM

The default test binary is the C64 Kernal ROM, which is copyrighted and not included in the repository. Any revision works (all are 8 KB). Place your copy at:

```
tests/kernal.901227-03.bin
```

That path is in `.gitignore` — it will not be committed.

If you don't have a kernal handy, you can run against the bundled minimal sample instead (see below).

#### Running the tests

```bash
# Default: run against tests/kernal.901227-03.bin at $E000
./tests/test_export.sh

# Run against the bundled minimal sample
./tests/test_export.sh tests/samples/hello.prg 0000

# Run against any raw binary — supply load address (hex, no $)
./tests/test_export.sh /path/to/rom.bin E000

# Override tool paths
GHIDRA=/opt/ghidra/support/analyzeHeadless \
KICKASS=~/tools/KickAss.jar \
./tests/test_export.sh
```

The harness:
1. Imports the binary into a Ghidra project and runs analysis (project reused for both script runs)
2. Runs the `main`-branch script against the saved analysis → **BEFORE** output in `tests/results/before/`
3. Runs the current branch's script against the same analysis → **AFTER** output in `tests/results/after/`
4. Diffs the two outputs — must be identical on `main`; divergence reveals regressions on feature branches
5. Compiles the **AFTER** output with KickAss and reports the result

#### Adding test samples

Place additional raw binary or `.prg` files in `tests/samples/`. The harness accepts any file as its first argument along with an optional load address.

## Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Dave-Agent/ghidra-kickass-export/issues)
- 💡 **Feature Requests**: [GitHub Discussions](https://github.com/Dave-Agent/ghidra-kickass-export/discussions)
- 📖 **Documentation**: [Wiki](https://github.com/Dave-Agent/ghidra-kickass-export/wiki)

When reporting issues, please include:

- Ghidra version
- Operating system
- Sample program (if possible)
- Error messages from console

## Acknowledgments

- Thanks to the Ghidra development team for the excellent reverse engineering platform
- Kick Assembler by Mads Nielsen for the outstanding 6502 assembler
- The reverse engineering community for feedback and testing

------

⭐ **Star this repo** if you find it useful!