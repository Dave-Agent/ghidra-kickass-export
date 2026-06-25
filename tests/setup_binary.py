# -*- coding: utf-8 -*-
# Ghidra pre-script: relocate a raw binary to its real load address and seed
# entry points so that auto-analysis has somewhere to start disassembling.
#
# Run by tests/test_export.sh via:
#   analyzeHeadless ... -preScript setup_binary.py <LOAD_ADDR_HEX>
#
# Arg 1 (optional): load address as hex digits without $ (default: E000)
#
# What it does:
#   1. Moves the imported block from $0000 (Raw Binary loader default) to the
#      real load address.
#   2. If the block ends at $FFFF (i.e. it covers a standard 6502 ROM space),
#      reads the NMI / Reset / IRQ vectors at $FFFA-$FFFF and marks each
#      handler address as a function entry so auto-analysis traces from them.
#   3. Otherwise marks the start of the block as the single entry point.
#
# @category Test Support
# @description Relocate raw binary and mark 6502 entry points before analysis

from ghidra.program.model.symbol import SourceType


def read_le16(mem, space, addr_int):
    """Read a little-endian 16-bit word; mask Java signed bytes to unsigned."""
    lo = mem.getByte(space.getAddress(addr_int)) & 0xFF
    hi = mem.getByte(space.getAddress(addr_int + 1)) & 0xFF
    return (hi << 8) | lo


args = getScriptArgs()
load_hex = (args[0].lstrip("$").upper() if args else "E000")
load_addr = int(load_hex, 16)

space = currentProgram.getAddressFactory().getDefaultAddressSpace()
mem   = currentProgram.getMemory()
sym   = currentProgram.getSymbolTable()

# ── 1. Relocate ────────────────────────────────────────────
for block in list(mem.getBlocks()):
    if block.isInitialized() and block.getStart().getOffset() == 0:
        mem.moveBlock(block, space.getAddress(load_addr), monitor)
        print("setup_binary: moved block to $%04X" % load_addr)
        break

block = mem.getBlock(space.getAddress(load_addr))
if block is None:
    print("setup_binary: ERROR — no block found at $%04X" % load_addr)
    raise Exception("Relocation failed")

block_end = load_addr + block.getSize() - 1

# ── 2. Find entry points ────────────────────────────────────
entries = []

if block_end >= 0xFFFF:
    # Block covers the 6502 vector table — read NMI / Reset / IRQ vectors
    # Suffix _HANDLER to avoid clashing with the architecture-defined symbols
    # that Ghidra places at the vector TABLE addresses ($FFFA=NMI, $FFFE=IRQ).
    for vec_name, vec_addr in [("NMI_HANDLER",   0xFFFA),
                                ("RESET_HANDLER", 0xFFFC),
                                ("IRQ_HANDLER",   0xFFFE)]:
        try:
            target = read_le16(mem, space, vec_addr)
        except Exception:
            continue
        if load_addr <= target <= block_end:
            entries.append((vec_name, target))
            short = vec_name.replace("_HANDLER", "")
            print("setup_binary: %s vector $%04X -> $%04X" % (short, vec_addr, target))

if not entries:
    entries = [("ENTRY", load_addr)]
    print("setup_binary: no vectors in range; using $%04X as entry" % load_addr)

# ── 3. Disassemble and create functions ─────────────────────
for name, addr_int in entries:
    addr = space.getAddress(addr_int)
    sym.createLabel(addr, name, SourceType.USER_DEFINED)
    disassemble(addr)
    createFunction(addr, name)
    print("setup_binary: created function %s at $%04X" % (name, addr_int))
