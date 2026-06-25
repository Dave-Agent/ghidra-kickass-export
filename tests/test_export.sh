#!/bin/bash
# Test harness for KickAssemblerExport.py
#
# Drives Ghidra headless to import a binary, runs both the main-branch and
# current-branch versions of the export script against the same analysed
# program, diffs the output (must be identical for a pure refactor / no
# regressions), and compiles the result with KickAss.
#
# Output is saved to tests/results/ for human review and cleared at the
# start of each run.
#
# Default binary: tests/kernal.901227-03.bin
#   The C64 Kernal ROM is copyrighted and NOT included in the repository.
#   Place your own copy at tests/kernal.901227-03.bin (any revision works).
#   The ROM loads at $E000 with its entry point at the same address.
#
# Usage:
#   ./tests/test_export.sh [binary [load_addr [entry_addr]]]
#
#   binary      path to a raw binary or .prg file
#               (default: tests/kernal.901227-03.bin)
#   load_addr   hex load address without $ prefix  (default: E000)
#   entry_addr  hex entry point address             (default: same as load_addr)
#
# Environment overrides:
#   GHIDRA      path to Ghidra's analyzeHeadless script
#   KICKASS     path to KickAss.jar

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TESTS_DIR="$REPO_ROOT/tests"
RESULTS_DIR="$TESTS_DIR/results"

GHIDRA="${GHIDRA:-/home/dave/ghidra/ghidra_11.3.2_PUBLIC/support/analyzeHeadless}"
KICKASS="${KICKASS:-/home/dave/tools/KickAss.jar}"
SCRIPT_DIR="$REPO_ROOT/ghidra_scripts"
GHIDRA_SCRIPTS="$HOME/ghidra_scripts"
INSTALLED_SCRIPT="$GHIDRA_SCRIPTS/KickAssemblerExport.py"

BIN="${1:-$TESTS_DIR/kernal.901227-03.bin}"
LOAD_ADDR="${2:-}"          # empty = auto-detect for PRG, default E000 for raw binary
ENTRY_ADDR="${3:-}"
PROCESSOR="6502:LE:16:default"

# Derived paths inside results/
PROJ_DIR="$RESULTS_DIR/ghidra_project"
BEFORE_DIR="$RESULTS_DIR/before"
AFTER_DIR="$RESULTS_DIR/after"
PROPS_BEFORE="$RESULTS_DIR/props_before"
PROPS_AFTER="$RESULTS_DIR/props_after"
LOG_DIR="$RESULTS_DIR/logs"

# Ghidra uses the full basename as the program name, so output files are
# e.g. kernal.901227-03.bin.asm / kernal.901227-03.bin_Symbols.asm
BIN_BASE="$(basename "$BIN")"
MAIN_ASM="${BIN_BASE}.asm"
SYMBOLS_ASM="${BIN_BASE}_Symbols.asm"

echo "======================================================"
echo " KickAssemblerExport test harness"
echo " Binary:  $BIN"
echo " Results: $RESULTS_DIR"
echo "======================================================"

# ── Guard: confirm the binary exists ───────────────────────
if [ ! -f "$BIN" ]; then
  echo "ERROR: binary not found: $BIN"
  if [[ "$BIN" == *kernal* ]]; then
    echo ""
    echo "The C64 Kernal ROM is copyrighted and not included in this repository."
    echo "Place your own copy at:"
    echo "  $TESTS_DIR/kernal.901227-03.bin"
    echo ""
    echo "Alternatively, run against the bundled sample:"
    echo "  ./tests/test_export.sh tests/samples/hello.prg 0000"
  fi
  exit 1
fi

# ── Setup: clear results, recreate layout ──────────────────
echo "Clearing results..."
rm -rf "$PROJ_DIR" "$BEFORE_DIR" "$AFTER_DIR" \
       "$PROPS_BEFORE" "$PROPS_AFTER" "$LOG_DIR"
mkdir -p "$PROJ_DIR" "$BEFORE_DIR" "$AFTER_DIR" \
         "$PROPS_BEFORE" "$PROPS_AFTER" "$LOG_DIR"

# ── PRG header detection ────────────────────────────────────
# A C64 .prg file begins with a 2-byte little-endian load address.  Ghidra's
# Raw Binary loader takes the whole file as-is, so those 2 bytes would end up
# as the first data in the program — shifting every address by 2 bytes.
# Strip the header here and use the resulting raw binary for the import so the
# content starts at byte 0 and can be relocated cleanly by setup_binary.py.
BIN_FOR_IMPORT="$BIN"

if [[ "${BIN_BASE##*.}" == "prg" ]]; then
  # Read the 2-byte load address (little-endian)
  LO_DEC=$(od -An -j0 -N1 -tu1 "$BIN" | tr -d ' ')
  HI_DEC=$(od -An -j1 -N1 -tu1 "$BIN" | tr -d ' ')
  PRG_ADDR=$(printf "%02X%02X" "$HI_DEC" "$LO_DEC")
  if [ -z "$LOAD_ADDR" ]; then
    LOAD_ADDR="$PRG_ADDR"
    echo "PRG: load address \$$LOAD_ADDR read from header (override with arg 2)"
  else
    echo "PRG: ignoring header load address \$$PRG_ADDR; using explicit \$$LOAD_ADDR"
  fi
  # Strip the 2-byte header → clean raw binary; keep the same stem for naming
  RAW_STEM="${BIN_BASE%.prg}"
  BIN_FOR_IMPORT="$RESULTS_DIR/${RAW_STEM}.bin"
  dd if="$BIN" of="$BIN_FOR_IMPORT" bs=1 skip=2 2>/dev/null
  echo "PRG: stripped 2-byte header -> $(basename "$BIN_FOR_IMPORT")"
  # Ghidra names the program after the imported file, so update ASM names
  IMPORT_BASE="$(basename "$BIN_FOR_IMPORT")"
  MAIN_ASM="${IMPORT_BASE}.asm"
  SYMBOLS_ASM="${IMPORT_BASE}_Symbols.asm"
fi

# Apply defaults now that PRG auto-detection has had a chance to set LOAD_ADDR
LOAD_ADDR="${LOAD_ADDR:-E000}"
ENTRY_ADDR="${ENTRY_ADDR:-$LOAD_ADDR}"

# Properties: key = "title approveButtonText" (Ghidra headless ask() format)
echo "Select Export Directory Choose: = $BEFORE_DIR" > "$PROPS_BEFORE/KickAssemblerExport.properties"
echo "Select Export Directory Choose: = $AFTER_DIR"  > "$PROPS_AFTER/KickAssemblerExport.properties"

# ── Script swap setup ───────────────────────────────────────
# Ghidra finds scripts via ~/ghidra_scripts. We swap the file between runs
# and restore via a trap so the original symlink is always recovered.
ORIG_SYMLINK_TARGET="$(readlink "$INSTALLED_SCRIPT" 2>/dev/null || echo '')"
restore_script() {
  if [ -n "$ORIG_SYMLINK_TARGET" ]; then
    rm -f "$INSTALLED_SCRIPT"
    ln -s "$ORIG_SYMLINK_TARGET" "$INSTALLED_SCRIPT"
    echo "Restored symlink: $INSTALLED_SCRIPT -> $ORIG_SYMLINK_TARGET"
  fi
}
trap restore_script EXIT

# Install the main-branch script, patching for headless compatibility:
#   (a) UTF-8 coding declaration  — Jython requires this for non-ASCII source
#   (b) state.getTool() guard     — returns None in headless, crashing __init__
rm -f "$INSTALLED_SCRIPT"
git -C "$REPO_ROOT" show main:ghidra_scripts/KickAssemblerExport.py \
  | python3 -c "
import sys
src = sys.stdin.read()
if '# -*- coding' not in src[:80]:
    src = '# -*- coding: utf-8 -*-\n' + src
src = src.replace(
    'self.OUTPUT_PATH = state.getTool().getOptions(options_name).getString(\"LastOutputPath\", default_path)',
    '_tool = state.getTool()\n        self.OUTPUT_PATH = _tool.getOptions(options_name).getString(\"LastOutputPath\", default_path) if _tool else default_path'
)
src = src.replace(
    'state.getTool().getOptions(options_name).setString(\"LastOutputPath\", self.OUTPUT_PATH)',
    '_tool = state.getTool()\n            if _tool: _tool.getOptions(options_name).setString(\"LastOutputPath\", self.OUTPUT_PATH)'
)
print(src, end='')
" > "$INSTALLED_SCRIPT"
echo "Installed main-branch script at $INSTALLED_SCRIPT"

# ── Step 1: Import and analyse ──────────────────────────────
echo ""
echo "── Step 1: Importing $(basename "$BIN_FOR_IMPORT") into Ghidra (load=\$$LOAD_ADDR) ──"
# Try to set load address via the "Raw Binary" loader.
# If Ghidra rejects the loader name, fall back to auto-detection (loads at $0000,
# which still produces valid diff and round-trip tests even if addresses are wrong).
# Import the binary as a raw file (Ghidra loads it at $0000 by default).
# tests/setup_binary.py runs as a pre-script: it relocates the block to the
# real load address and marks 6502 entry points so auto-analysis disassembles
# actual instructions rather than treating everything as data.
"$GHIDRA" "$PROJ_DIR" TestKA \
  -import "$BIN_FOR_IMPORT" \
  -processor "$PROCESSOR" \
  -scriptPath "$TESTS_DIR" \
  -preScript setup_binary.py "$LOAD_ADDR" \
  2>&1 | tee "$LOG_DIR/import.log" | grep -E "REPORT|setup_binary|Loader|address|WARN|ERROR|Exception" || true
echo "Import complete. See $LOG_DIR/import.log"

# ── Step 2: Run main-branch script ─────────────────────────
echo ""
echo "── Step 2: Running MAIN-branch script ──"
"$GHIDRA" "$PROJ_DIR" TestKA \
  -process \
  -noanalysis \
  -postscript KickAssemblerExport.py \
  -propertiesPath "$PROPS_BEFORE" \
  2>&1 | tee "$LOG_DIR/before.log" | grep -E "REPORT|WARN|ERROR|Exception|Starting|Complete|Export path" || true

if [ ! -f "$BEFORE_DIR/${MAIN_ASM}" ]; then
  echo "ERROR: main-branch export did not produce ${MAIN_ASM}"
  echo "See $LOG_DIR/before.log"
  exit 1
fi
echo "Main-branch export: $(wc -l < "$BEFORE_DIR/${MAIN_ASM}") lines — $(ls -lh "$BEFORE_DIR/${MAIN_ASM}" | awk '{print $5}')"

# ── Step 3: Run current-branch script ──────────────────────
rm -f "$INSTALLED_SCRIPT"
cp "$SCRIPT_DIR/KickAssemblerExport.py" "$INSTALLED_SCRIPT"
echo "Installed current-branch script at $INSTALLED_SCRIPT"

echo ""
echo "── Step 3: Running CURRENT-branch script ──"
"$GHIDRA" "$PROJ_DIR" TestKA \
  -process \
  -noanalysis \
  -postscript KickAssemblerExport.py \
  -propertiesPath "$PROPS_AFTER" \
  2>&1 | tee "$LOG_DIR/after.log" | grep -E "REPORT|WARN|ERROR|Exception|Starting|Complete|Export path" || true

if [ ! -f "$AFTER_DIR/${MAIN_ASM}" ]; then
  echo "ERROR: current-branch export did not produce ${MAIN_ASM}"
  echo "See $LOG_DIR/after.log"
  exit 1
fi
echo "Current-branch export: $(wc -l < "$AFTER_DIR/${MAIN_ASM}") lines — $(ls -lh "$AFTER_DIR/${MAIN_ASM}" | awk '{print $5}')"

# ── Step 4: Diff main vs current ───────────────────────────
echo ""
echo "── Step 4: Diffing main vs current output ──"
ASM_DIFF=0
diff -I '^// Generated on:' \
  "$BEFORE_DIR/${MAIN_ASM}" "$AFTER_DIR/${MAIN_ASM}" \
  > "$RESULTS_DIR/asm.diff" 2>&1 || ASM_DIFF=$?
SYM_DIFF=0
diff -I '^// Generated on:' \
  "$BEFORE_DIR/${SYMBOLS_ASM}" "$AFTER_DIR/${SYMBOLS_ASM}" \
  > "$RESULTS_DIR/symbols.diff" 2>&1 || SYM_DIFF=$?

if [ $ASM_DIFF -eq 0 ] && [ $SYM_DIFF -eq 0 ]; then
  echo "PASS: output is identical between main and current branch"
else
  echo "FAIL: output differs (ASM diff=$ASM_DIFF  Symbols diff=$SYM_DIFF)"
  echo "      See $RESULTS_DIR/asm.diff and $RESULTS_DIR/symbols.diff"
  exit 1
fi

# ── Step 5: Compile with KickAss ───────────────────────────
echo ""
echo "── Step 5: Compiling with KickAss ──"
KICKASS_OUT=0
( cd "$AFTER_DIR" && java -jar "$KICKASS" "${MAIN_ASM}" ) \
  2>&1 | tee "$LOG_DIR/kickass.log" || KICKASS_OUT=$?

if [ $KICKASS_OUT -ne 0 ]; then
  echo "WARN: KickAss exited with code $KICKASS_OUT"
  echo "      See $LOG_DIR/kickass.log"
else
  # KickAss strips the last extension and adds .prg
  # kernal.901227-03.bin.asm → kernal.901227-03.bin.prg
  GENERATED="${AFTER_DIR}/${MAIN_ASM%.asm}.prg"   # KickAss strips last ext and adds .prg
  if [ -f "$GENERATED" ]; then
    ORIG_SIZE=$(wc -c < "$BIN_FOR_IMPORT")   # raw content size (no PRG header)
    GEN_SIZE=$(wc -c  < "$GENERATED")
    echo "Original: ${ORIG_SIZE} bytes (raw)    Generated: ${GEN_SIZE} bytes (PRG)"
    # KickAss always writes a 2-byte load-address header; BIN_FOR_IMPORT is always
    # a raw binary (header already stripped for .prg inputs), so skip 2 bytes from
    # the generated file only.
    if cmp -s --ignore-initial=2:0 "$GENERATED" "$BIN_FOR_IMPORT"; then
      echo "PASS: round-trip binary is byte-identical to original"
    else
      echo "INFO: round-trip binary differs — expected unless all bytes are fully disassembled"
    fi
  else
    echo "WARN: KickAss succeeded but no output .prg found (expected at $GENERATED)"
  fi
fi

echo ""
echo "======================================================"
echo " Done."
echo " Output files: $AFTER_DIR/"
echo " Diff files:   $RESULTS_DIR/*.diff"
echo " Logs:         $LOG_DIR/"
echo "======================================================"
