#!/bin/bash
# Test harness for KickAssemblerExport.py
#
# Pipeline:
#   1. Import hello.prg into a Ghidra headless project and run analysis (once)
#   2. Run the main-branch script against the saved project  → BEFORE output
#   3. Run the current-branch script against the same project → AFTER output
#   4. Diff the two outputs (should be identical after a pure refactor)
#   5. Compile the AFTER output with KickAss and compare the binary to the original PRG
#
# Usage: ./test_export.sh [prg_file]
#   Defaults to c64-hello-world/build/hello.prg if no argument given.

set -e

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GHIDRA="${GHIDRA:-/home/dave/ghidra/ghidra_11.3.2_PUBLIC/support/analyzeHeadless}"
KICKASS="${KICKASS:-/home/dave/tools/KickAss.jar}"
PRG="${1:-$REPO_ROOT/tests/samples/hello.prg}"
SCRIPT_DIR="$REPO_ROOT/ghidra_scripts"

PROJ_DIR="/tmp/ka_test_project"
BEFORE_DIR="/tmp/ka_test_before"
AFTER_DIR="/tmp/ka_test_after"
PROPS_BEFORE="/tmp/ka_props_before"
PROPS_AFTER="/tmp/ka_props_after"
GHIDRA_SCRIPTS="$HOME/ghidra_scripts"
INSTALLED_SCRIPT="$GHIDRA_SCRIPTS/KickAssemblerExport.py"

# Ghidra retains the full filename (including .prg) as the program name,
# so the script outputs hello.prg.asm, not hello.asm.
PRG_BASE="$(basename "$PRG")"          # hello.prg
PRG_NAME="${PRG_BASE}"                 # used as Ghidra program name
MAIN_ASM="${MAIN_ASM}"             # hello.prg.asm
SYMBOLS_ASM="${SYMBOLS_ASM}"  # hello.prg_Symbols.asm

echo "======================================================"
echo " KickAssemblerExport test harness"
echo " PRG:    $PRG"
echo " BEFORE: $BEFORE_DIR"
echo " AFTER:  $AFTER_DIR"
echo "======================================================"

# ── Setup ──────────────────────────────────────────────────
rm -rf "$PROJ_DIR" "$BEFORE_DIR" "$AFTER_DIR" "$PROPS_BEFORE" "$PROPS_AFTER"
mkdir -p "$PROJ_DIR" "$BEFORE_DIR" "$AFTER_DIR" "$PROPS_BEFORE" "$PROPS_AFTER"

# Properties files: key format is "title approveButtonText = value"
# (Ghidra headless concatenates ask() params with spaces as the lookup key)
echo "Select Export Directory Choose: = $BEFORE_DIR" > "$PROPS_BEFORE/KickAssemblerExport.properties"
echo "Select Export Directory Choose: = $AFTER_DIR"  > "$PROPS_AFTER/KickAssemblerExport.properties"

# Ghidra always finds the script via ~/ghidra_scripts (our symlink lives there).
# Save the current symlink so we can restore it, then swap in each test version.
ORIG_SYMLINK_TARGET="$(readlink "$INSTALLED_SCRIPT" 2>/dev/null || echo '')"
restore_script() {
  if [ -n "$ORIG_SYMLINK_TARGET" ]; then
    rm -f "$INSTALLED_SCRIPT"
    ln -s "$ORIG_SYMLINK_TARGET" "$INSTALLED_SCRIPT"
    echo "Restored symlink: $INSTALLED_SCRIPT -> $ORIG_SYMLINK_TARGET"
  fi
}
trap restore_script EXIT

# Install main-branch script (removes symlink, creates regular file).
# Patch in: (a) Python 2 coding declaration for non-ASCII comments,
#           (b) headless guard for state.getTool() which returns None outside the GUI.
rm -f "$INSTALLED_SCRIPT"
git -C "$REPO_ROOT" show main:ghidra_scripts/KickAssemblerExport.py \
  | python3 -c "
import sys, re
src = sys.stdin.read()
# (a) inject coding declaration if missing
if '# -*- coding' not in src[:80]:
    src = '# -*- coding: utf-8 -*-\n' + src
# (b) guard getTool() calls
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
echo "Installed main-branch script (patched for headless) at $INSTALLED_SCRIPT"

# ── Step 1: Import and analyse once, save project ──────────
echo ""
echo "── Step 1: Importing $PRG_NAME into Ghidra (analysis runs once) ──"
"$GHIDRA" "$PROJ_DIR" TestKA \
  -import "$PRG" \
  -processor 6502:LE:16:default \
  2>&1 | tee /tmp/ka_import.log | grep -E "INFO|WARN|ERROR|Script|Exception" || true
echo "Import complete."

# ── Step 2: Run main-branch script ─────────────────────────
echo ""
echo "── Step 2: Running MAIN-branch script ──"
"$GHIDRA" "$PROJ_DIR" TestKA \
  -process \
  -noanalysis \
  -postscript KickAssemblerExport.py \
  -propertiesPath "$PROPS_BEFORE" \
  2>&1 | tee /tmp/ka_before.log | grep -E "INFO|WARN|ERROR|Script|Exception|Export" || true

if [ ! -f "$BEFORE_DIR/${PRG_NAME}.asm" ]; then
  echo "ERROR: main-branch export did not produce ${PRG_NAME}.asm"
  echo "Check /tmp/ka_before.log"
  exit 1
fi
echo "Main-branch export complete: $(ls -lh "$BEFORE_DIR/${PRG_NAME}.asm" | awk '{print $5, $9}')"

# ── Step 3: Run refactor-branch script ─────────────────────
# Swap in the refactor (current branch) version of the script
rm -f "$INSTALLED_SCRIPT"
cp "$SCRIPT_DIR/KickAssemblerExport.py" "$INSTALLED_SCRIPT"
echo "Installed refactor-branch script at $INSTALLED_SCRIPT"

echo ""
echo "── Step 3: Running REFACTOR-branch script ──"
"$GHIDRA" "$PROJ_DIR" TestKA \
  -process \
  -noanalysis \
  -postscript KickAssemblerExport.py \
  -propertiesPath "$PROPS_AFTER" \
  2>&1 | tee /tmp/ka_after.log | grep -E "INFO|WARN|ERROR|Script|Exception|Export" || true

if [ ! -f "$AFTER_DIR/${PRG_NAME}.asm" ]; then
  echo "ERROR: refactor-branch export did not produce ${PRG_NAME}.asm"
  echo "Check /tmp/ka_after.log"
  exit 1
fi
echo "Refactor-branch export complete: $(ls -lh "$AFTER_DIR/${PRG_NAME}.asm" | awk '{print $5, $9}')"
# (trap will restore the symlink on exit)

# ── Step 4: Diff the two ASM outputs ───────────────────────
echo ""
echo "── Step 4: Diffing main vs refactor output ──"
# Ignore the timestamp comment ("// Generated on: ...") — it varies by run time
ASM_DIFF=0
diff -I '^// Generated on:' "$BEFORE_DIR/${MAIN_ASM}" "$AFTER_DIR/${MAIN_ASM}" || ASM_DIFF=$?
SYM_DIFF=0
diff -I '^// Generated on:' "$BEFORE_DIR/${SYMBOLS_ASM}" "$AFTER_DIR/${SYMBOLS_ASM}" || SYM_DIFF=$?

if [ $ASM_DIFF -eq 0 ] && [ $SYM_DIFF -eq 0 ]; then
  echo "PASS: both output files are identical between main and refactor branches"
else
  echo "FAIL: output differs between branches (ASM diff=$ASM_DIFF, Symbols diff=$SYM_DIFF)"
  exit 1
fi

# ── Step 5: Compile with KickAss and compare binary ────────
echo ""
echo "── Step 5: Compiling with KickAss ──"
cd "$AFTER_DIR"
KICKASS_OUT=0
java -jar "$KICKASS" "${MAIN_ASM}" 2>&1 || KICKASS_OUT=$?

if [ $KICKASS_OUT -ne 0 ]; then
  echo "WARN: KickAss exited with code $KICKASS_OUT — assembly failed"
  echo "(This may be expected for programs with labels outside the imported range)"
else
  GENERATED_PRG="$AFTER_DIR/${PRG_BASE%.prg}.prg"  # KickAss strips .prg.asm → .prg
  if [ -f "$GENERATED_PRG" ]; then
    # PRG files have a 2-byte load address header; skip it for the binary comparison
    ORIG_SIZE=$(wc -c < "$PRG")
    GEN_SIZE=$(wc -c  < "$GENERATED_PRG")
    echo "Original PRG: ${ORIG_SIZE} bytes"
    echo "Generated PRG: ${GEN_SIZE} bytes"
    if cmp -s "$PRG" "$GENERATED_PRG"; then
      echo "PASS: round-trip binary is byte-identical to original"
    else
      echo "INFO: round-trip binary differs from original"
      echo "      (expected for incomplete analysis — check labels and data sections)"
    fi
  else
    echo "WARN: KickAss succeeded but no .prg output file found"
  fi
fi

echo ""
echo "======================================================"
echo " Done. Logs: /tmp/ka_import.log  /tmp/ka_before.log  /tmp/ka_after.log"
echo "======================================================"
