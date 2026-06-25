# -*- coding: utf-8 -*-
# Ghidra Script to Export Disassembly to Kick Assembler Format
# Includes symbol/label handling, XREFs in code and symbol file,
# comment preservation, improved formatting, and unified byte/code processing.

#@keybinding control alt K
#@menupath Tools.Kick Assembler Export
#@category Kick Assembler Tools

# --- Imports ---
from java.io import File
from ghidra.program.model.listing import CodeUnit, Instruction, Data
from ghidra.program.model.symbol import SymbolType, Symbol, RefType
from ghidra.program.model.address import Address, AddressOutOfBoundsException, AddressOverflowException
from ghidra.util.exception import CancelledException
from ghidra.framework.preferences import Preferences
from ghidra.program.model.scalar import Scalar
import ghidra

import os
import datetime
import re
import traceback


# ==============================================================
# SymbolResolver — address-to-name maps and label queries
# ==============================================================
class SymbolResolver:
    """Builds and queries address-to-symbol-name mappings from Ghidra's symbol table."""

    def __init__(self, program):
        self.program = program
        self.listing = program.getListing()
        self.memory = program.getMemory()
        self.functionManager = program.getFunctionManager()
        self.symbolTable = program.getSymbolTable()
        self.referenceManager = program.getReferenceManager()
        self.addr_factory = program.getAddressFactory()
        self.default_space = self.addr_factory.getDefaultAddressSpace()

        self.address_to_label = {}
        self.symbol_map = {}
        self._labels_colon_cache = {}

    # --- Address Normalization ---

    def normalize_address(self, addr_obj):
        """Converts a Ghidra Address object to a standard string format (uppercase hex, 4 digits)."""
        if not addr_obj or not isinstance(addr_obj, Address):
            return None
        addr_str = addr_obj.toString().split(':')[-1]
        try:
            int_val = int(addr_str, 16)
            norm_str = "{:04X}".format(int_val)
        except ValueError:
            print("Warning: Could not parse address string '{}' from Address object as hex.".format(addr_str))
            norm_str = addr_str.upper().zfill(4)
        return norm_str

    def normalize_address_from_string(self, addr_hex):
        """Normalizes a hex string (e.g., '52' or 'C000') to standard format '0052', 'C000'."""
        if not isinstance(addr_hex, (str, unicode)):
            addr_hex = str(addr_hex)
        try:
            if addr_hex.lower().startswith('0x'): addr_hex = addr_hex[2:]
            int_val = int(addr_hex, 16)
            norm_str = "{:04X}".format(int_val)
        except ValueError:
            print("Warning: Could not parse hex string '{}' for normalization.".format(addr_hex))
            norm_str = addr_hex.upper().zfill(4)
        return norm_str

    # --- Map Building ---

    def build_symbol_map(self):
        """Build a map of normalized addresses to symbols, prioritising user-defined names."""
        print("Building symbol map...")
        self.symbol_map = {}
        unique_symbols = {}

        for symbol in self.symbolTable.getAllSymbols(True):
            address_obj = symbol.getAddress()
            if not address_obj: continue

            is_user_symbol = symbol.getSource() != 0
            is_in_memory = self.memory.contains(address_obj)
            if not is_user_symbol and not is_in_memory:
                continue

            norm_addr = self.normalize_address(address_obj)
            if not norm_addr: continue

            symbol_name = symbol.getName()
            stype, s_src = symbol.getSymbolType(), symbol.getSource()
            current_priority = -1

            # Prioritisation: User Label > Function > Other User > Default (DAT_ etc.)
            if s_src != 0 and stype == SymbolType.LABEL:   new_priority = 3
            elif stype == SymbolType.FUNCTION:              new_priority = 2
            elif s_src != 0:                                new_priority = 1
            else:                                           new_priority = 0

            if norm_addr in unique_symbols:
                current_priority = unique_symbols[norm_addr]['priority']

            if new_priority >= current_priority:
                unique_symbols[norm_addr] = {'name': symbol_name, 'priority': new_priority}

        self.symbol_map = {addr: data['name'] for addr, data in unique_symbols.items()}
        print("Stored {} unique symbols.".format(len(self.symbol_map)))

    def build_label_map(self):
        """Collect all primary flow labels/functions for operand symbol resolution."""
        print("Building label map...")
        self.address_to_label = {}
        symbols = self.symbolTable.getSymbolIterator()
        while symbols.hasNext():
            symbol = symbols.next()
            address_obj = symbol.getAddress()
            if not address_obj: continue

            is_user_symbol = symbol.getSource() != 0
            is_in_memory = self.memory.contains(address_obj)
            if not is_user_symbol and not is_in_memory:
                continue

            is_label = symbol.getSymbolType() == SymbolType.LABEL
            is_func  = symbol.getSymbolType() == SymbolType.FUNCTION

            if (is_label and symbol.getSource() != 0) or is_func:
                norm_addr = self.normalize_address(address_obj)
                if not norm_addr: continue
                if norm_addr not in self.address_to_label or (is_label and symbol.getSource() != 0):
                    self.address_to_label[norm_addr] = symbol.getName()
        print("Found {} flow labels/function entries.".format(len(self.address_to_label)))

    # --- Symbol Queries ---

    def find_symbol_for_address(self, address_obj):
        """Look up the best symbol name for a Ghidra Address object."""
        if not address_obj: return None

        norm_addr = self.normalize_address(address_obj)
        if not norm_addr: return None

        # Priority 1: user-defined label at this exact address
        for symbol in self.symbolTable.getSymbols(address_obj):
            if symbol.getSource() != 0 and symbol.getSymbolType() == SymbolType.LABEL:
                return symbol.getName()

        if norm_addr in self.address_to_label: return self.address_to_label[norm_addr]
        if norm_addr in self.symbol_map:       return self.symbol_map[norm_addr]

        # Last resort: any symbol at the address
        for symbol in self.symbolTable.getSymbols(address_obj):
            return symbol.getName()

        return None

    def get_function_containing(self, address):
        """Return the name of the function that contains the given address, or None."""
        if not address: return None
        try:
            func = self.functionManager.getFunctionContaining(address)
            if func: return func.getName()
        except Exception: pass
        return None

    def format_xref_string(self, ref):
        """Format a single Ghidra Reference as a human-readable XREF token."""
        from_addr = ref.getFromAddress()
        ref_type  = ref.getReferenceType()
        type_char = "?"
        if ref_type.isRead():     type_char = "R"
        elif ref_type.isWrite():  type_char = "W"
        elif ref_type.isCall():   type_char = "c"
        elif ref_type.isJump():   type_char = "j"
        elif ref_type.isComputed(): type_char = "p"
        elif ref_type.isData():   type_char = "d"
        addr_str  = from_addr.toString().split(':')[-1]
        func_name = self.get_function_containing(from_addr)
        xref_detail = "{}({})".format(addr_str, type_char)
        return "{}:{}".format(func_name, xref_detail) if func_name else xref_detail

    def get_labels_at_address(self, address):
        """
        Return a sorted list of label/function names to be emitted as LABEL: definitions
        at this address. Only includes FUNCTION entry points and non-default LABELs that
        point to the start of an Instruction. Results are cached.
        """
        if not address: return []
        norm_addr = self.normalize_address(address)
        if not norm_addr: return []

        if norm_addr in self._labels_colon_cache:
            return self._labels_colon_cache[norm_addr]

        labels_for_colon_def = []
        instruction_at = self.listing.getInstructionAt(address)

        for symbol in self.symbolTable.getSymbols(address):
            symbol_name = symbol.getName()
            symbol_type = symbol.getSymbolType()
            is_non_default = symbol.getSource() != 0
            should_define_with_colon = False

            if symbol_type == SymbolType.FUNCTION:
                should_define_with_colon = True
            elif is_non_default and symbol_type == SymbolType.LABEL:
                if instruction_at is not None and instruction_at.getAddress().equals(address):
                    should_define_with_colon = True

            if should_define_with_colon and symbol_name not in labels_for_colon_def:
                labels_for_colon_def.append(symbol_name)

        result = sorted(labels_for_colon_def)
        self._labels_colon_cache[norm_addr] = result
        return result

    def clear_cache(self):
        """Clear the labels-at-address cache (call before each export pass)."""
        self._labels_colon_cache = {}


# ==============================================================
# AsmFormatter — Ghidra objects → Kick Assembler text
# ==============================================================
class AsmFormatter:
    """Converts Ghidra instructions and data into Kick Assembler source text."""

    # 6502/6510 mnemonics that have a zero-page form for each index mode.
    # When an instruction is 3 bytes but its address is in $0000-$00FF,
    # KickAss would silently assemble the shorter zero-page form instead —
    # breaking byte-exactness. We add .abs to prevent that.
    # Mnemonics absent from a mode (e.g. jsr, jmp, sta/lda with ,y) have
    # no zero-page equivalent so KickAss uses absolute anyway; no .abs needed.
    ZP_CAPABLE = {
        '':   {'adc','and','asl','bit','cmp','cpx','cpy','dec','eor',
               'inc','lda','ldx','ldy','lsr','ora','rol','ror','sbc','sta','stx','sty'},
        ',x': {'adc','and','asl','cmp','dec','eor','inc','lda','ldy',
               'lsr','ora','rol','ror','sbc','sta','sty'},
        ',y': {'ldx','stx'},   # only these two have a zero-page,Y form
    }

    def __init__(self, resolver, comment_column, eol_comment_column):
        self.resolver         = resolver
        self.listing          = resolver.listing
        self.default_space    = resolver.default_space
        self.COMMENT_COLUMN   = comment_column
        self.EOL_COMMENT_COLUMN = eol_comment_column
        self.MAX_RAW_BYTES_PER_LINE = 16

    # --- Formatting Helpers ---

    def convert_to_kick_hex(self, disasm_fragment):
        """Convert Ghidra hex format (0x...) to Kick Assembler format ($...)."""
        frag = disasm_fragment
        frag = re.sub(r'#0x([0-9A-Fa-f]+)(?![0-9A-Fa-f])', r'#$\1', frag)
        frag = re.sub(r'(?<![A-Za-z0-9_])0x([0-9A-Fa-f]+)(?![0-9A-Fa-f])', r'$\1', frag)
        return frag

    def sanitize_label_name(self, name):
        """Replace characters invalid in Kick Assembler labels with underscores."""
        if not name: return "_invalid_name_"
        sanitized = re.sub(r'[^a-zA-Z0-9_@.]', '_', name)
        if sanitized and sanitized[0].isdigit() and not sanitized.startswith('.'):
            sanitized = "_" + sanitized
        sanitized = sanitized.replace("::", "_")
        if not sanitized: return "_invalid_name_"
        sanitized = re.sub(r'_+', '_', sanitized)
        sanitized = sanitized.strip('_')
        if not sanitized: return "_invalid_name_"
        if sanitized in ('.', '@'): return "_invalid_name_"
        return sanitized

    def convert_to_petscii_ascii(self, byte_value):
        """Return the printable ASCII representation of a PETSCII byte, or '.'"""
        if 32 <= byte_value <= 95:
            try: return chr(byte_value)
            except ValueError: return '.'
        return '.'

    def flush_raw_bytes(self, byte_buffer, start_addr, f):
        """Write a buffer of raw bytes as a .byte directive with PETSCII comment."""
        if not byte_buffer:
            return False
        bytes_hex_list = ["${:02x}".format(b) for b in byte_buffer]
        petscii_str    = "".join([self.convert_to_petscii_ascii(b) for b in byte_buffer])
        data_text      = "  .byte {}".format(",".join(bytes_hex_list))
        addr_str       = start_addr.toString().split(':')[-1] if start_addr else "????"
        full_comment   = "[{}] {}".format(addr_str, petscii_str)
        padding        = " " * max(1, self.COMMENT_COLUMN - len(data_text) - 2)
        f.write("{}{}{} {}\n".format(data_text, padding, "//", full_comment))
        return True

    def write_multi_line_comment(self, prefix, comment, f, indent, blank_line_before=False):
        """Write a Ghidra comment block as // lines, optionally preceded by a blank line."""
        if not comment:
            return
        if blank_line_before:
            f.write("\n")
        for i, line in enumerate(comment.splitlines()):
            p = prefix if i == 0 else " " * len(prefix)
            safe_line = line.encode('ascii', 'ignore').decode('ascii')
            f.write("{}// {}{}\n".format(indent, p, safe_line))

    def write_xref_comment(self, f, xrefs, first_line, continuation_indent, line_limit):
        """Write a list of XREF tokens with line-wrapping.

        first_line          — opening text already containing '// XREF[N]: ' prefix.
        continuation_indent — spaces to align continuation lines before '//'.
        line_limit          — wrap before exceeding this length.
        """
        current_line_xrefs = []
        remaining_xrefs    = list(xrefs)
        fl = first_line

        while remaining_xrefs:
            xref = remaining_xrefs.pop(0)
            if not current_line_xrefs:
                test_line = fl + xref if fl else continuation_indent + "//           " + xref
            else:
                test_line = (fl if fl else continuation_indent + "//           ") + ", ".join(current_line_xrefs + [xref])

            if len(test_line) < line_limit or not current_line_xrefs:
                current_line_xrefs.append(xref)
            else:
                if fl:
                    f.write(fl + ", ".join(current_line_xrefs) + "\n")
                    fl = None
                else:
                    f.write("{}{}           {}\n".format(continuation_indent, "//", ", ".join(current_line_xrefs)))
                current_line_xrefs = [xref]

        if fl:
            f.write(fl + ", ".join(current_line_xrefs) + "\n")
        elif current_line_xrefs:
            f.write("{}{}           {}\n".format(continuation_indent, "//", ", ".join(current_line_xrefs)))

    # --- Code / XREF Output ---

    def process_xrefs(self, address, f):
        """Write flow XREF comments before a label definition in the main ASM file."""
        if not address: return
        try:
            refs_to = self.resolver.referenceManager.getReferencesTo(address)
        except Exception as e:
            print("Warning: Error getting references to {}: {}".format(address, e))
            return
        xrefs = []
        for ref in refs_to:
            ref_type = ref.getReferenceType()
            if ref_type.isCall() or ref_type.isJump() or ref_type.isComputed():
                xrefs.append(self.resolver.format_xref_string(ref))
        if xrefs:
            unique_sorted = sorted(list(set(xrefs)))
            xref_indent  = " " * (self.COMMENT_COLUMN - 2)
            first_line   = "{}{} XREF[{}]: ".format(xref_indent, "//", len(unique_sorted))
            self.write_xref_comment(f, unique_sorted, first_line, xref_indent, 80)

    def process_instruction(self, instruction, f):
        """
        Convert a single Ghidra Instruction to Kick Assembler syntax and write it to f.
        Label output (label:) is handled by the main export loop before this is called.
        """
        address       = instruction.getAddress()
        norm_addr_str = self.resolver.normalize_address(address)

        original_asm_for_comment = self.convert_to_kick_hex(instruction.toString())

        try:
            instruction_bytes = instruction.getBytes()
            bytes_list = ["{:02x}".format(b & 0xff) for b in instruction_bytes]
        except Exception as byte_err:
            print("Warning: could not get bytes for instr at {}: {}".format(norm_addr_str, byte_err))
            instruction_bytes = []
            bytes_list = ["??"] * instruction.getLength()

        comment_indent = "  "
        plate_comment  = self.listing.getComment(CodeUnit.PLATE_COMMENT, address)
        pre_comment    = self.listing.getComment(CodeUnit.PRE_COMMENT, address)

        self.write_multi_line_comment("", plate_comment, f, comment_indent, blank_line_before=True)
        self.write_multi_line_comment("", pre_comment,   f, comment_indent)

        mnemonic = instruction.getMnemonicString().lower()

        # Special case: accumulator-mode instructions (ASL A, LSR A, ROL A, ROR A)
        accumulator_opcodes = {0x0A, 0x4A, 0x2A, 0x6A}
        is_accumulator_mode = False
        if instruction_bytes and instruction_bytes[0] in accumulator_opcodes and instruction.getLength() == 1:
            is_accumulator_mode = True
        elif instruction_bytes and instruction_bytes[0] in accumulator_opcodes:
            print("Warning: Opcode {:02X} at {} looks like accumulator mode but length is {} != 1.".format(
                instruction_bytes[0], norm_addr_str, instruction.getLength()))

        kick_disasm    = ""
        operand_strings = []

        if is_accumulator_mode:
            kick_disasm = mnemonic.ljust(3)
        else:
            num_operands = instruction.getNumOperands()
            index_suffix = ""
            for i in range(num_operands):
                op_str      = None
                op_objects  = instruction.getOpObjects(i)
                default_op_rep = instruction.getDefaultOperandRepresentation(i)
                index_suffix   = ""

                if default_op_rep.upper().endswith(",X"): index_suffix = ",x"
                elif default_op_rep.upper().endswith(",Y"): index_suffix = ",y"

                primary_symbol = None

                # --- Primary: resolve via Ghidra Address/Scalar objects ---
                for obj in op_objects:
                    if isinstance(obj, Address):
                        symbol_name = self.resolver.find_symbol_for_address(obj)
                        if symbol_name:
                            primary_symbol = symbol_name
                            break
                    elif isinstance(obj, Scalar):
                        if default_op_rep.startswith('#'):
                            scalar_val = obj.getValue()
                            if abs(scalar_val) <= 0xFF and not mnemonic.startswith('j'):
                                op_str = "#${:02x}".format(scalar_val & 0xff)
                            else:
                                op_str = "#${:04x}".format(scalar_val & 0xffff)
                            break

                if primary_symbol:
                    sanitized_symbol = self.sanitize_label_name(primary_symbol)
                    if default_op_rep.startswith('(') and default_op_rep.upper().endswith(',X)'):
                        op_str = "({},x)".format(sanitized_symbol)
                    elif default_op_rep.startswith('(') and default_op_rep.upper().endswith('),Y'):
                        op_str = "({}),y".format(sanitized_symbol)
                    else:
                        op_str = sanitized_symbol + index_suffix
                elif op_str:
                    pass  # already set by scalar handler above
                else:
                    # --- Fallback A: LABEL+OFFSET or LABEL-OFFSET ---
                    offset_match = re.match(
                        r'^([A-Za-z0-9_@.]+)\s*([+-])\s*(\$?(?:0x)?([0-9A-Fa-f]+))$',
                        default_op_rep, re.IGNORECASE)
                    op_str_built = False

                    if offset_match:
                        base_label     = offset_match.group(1)
                        op_sign        = offset_match.group(2)
                        offset_val_hex = offset_match.group(4)
                        sanitized_base = self.sanitize_label_name(base_label)
                        try:
                            formatted_offset = str(int(offset_val_hex, 16))
                        except ValueError:
                            formatted_offset = "${}".format(offset_val_hex.upper())
                        op_str = "{}{}{}".format(sanitized_base, op_sign, formatted_offset) + index_suffix
                        op_str_built = True

                    # --- Fallback B: parse addressing mode from Ghidra's string ---
                    if not op_str_built:
                        symbol_in_fallback = None
                        indirect_match_y   = re.match(r'\(\$?(?:0x)?([0-9A-Fa-f]+)\),Y$',   default_op_rep, re.IGNORECASE)
                        indirect_match_x   = re.match(r'\(\$?(?:0x)?([0-9A-Fa-f]+),X\)$',   default_op_rep, re.IGNORECASE)
                        absolute_match_xy  = re.match(r'\$?(?:0x)?([0-9A-Fa-f]+),(X|Y)$',   default_op_rep, re.IGNORECASE)
                        absolute_match_plain = re.match(r'\$?(?:0x)?([0-9A-Fa-f]+)$',        default_op_rep, re.IGNORECASE)
                        addr_hex = None
                        norm_addr_fb = None

                        def _lookup_symbol(addr_hex_str):
                            """Resolve a hex address string to a symbol name via all available maps."""
                            na = self.resolver.normalize_address_from_string(addr_hex_str)
                            if not na: return None
                            if na in self.resolver.address_to_label: return self.resolver.address_to_label[na]
                            if na in self.resolver.symbol_map:       return self.resolver.symbol_map[na]
                            addr_obj = self.default_space.getAddress(na)
                            return self.resolver.find_symbol_for_address(addr_obj) if addr_obj else None

                        if indirect_match_y:
                            addr_hex = indirect_match_y.group(1)
                            sym = _lookup_symbol(addr_hex)
                            zp_part = self.sanitize_label_name(sym) if sym else "${}".format(addr_hex)
                            op_str = "({}),y".format(zp_part); op_str_built = True

                        elif indirect_match_x:
                            addr_hex = indirect_match_x.group(1)
                            sym = _lookup_symbol(addr_hex)
                            zp_part = self.sanitize_label_name(sym) if sym else "${}".format(addr_hex)
                            op_str = "({},x)".format(zp_part); op_str_built = True

                        elif absolute_match_xy:
                            addr_hex = absolute_match_xy.group(1)
                            index    = "," + absolute_match_xy.group(2).lower()
                            sym = _lookup_symbol(addr_hex)
                            addr_part = self.sanitize_label_name(sym) if sym else "${}".format(addr_hex)
                            op_str = "{}{}".format(addr_part, index); op_str_built = True

                        elif absolute_match_plain:
                            addr_hex = absolute_match_plain.group(1)
                            sym = _lookup_symbol(addr_hex)
                            op_str = self.sanitize_label_name(sym) if sym else "${}".format(addr_hex)
                            op_str_built = True

                        if not op_str_built:
                            op_str = self.convert_to_kick_hex(default_op_rep)
                            if op_str.endswith(",X"): op_str = op_str[:-2] + ",x"
                            if op_str.endswith(",Y"): op_str = op_str[:-2] + ",y"

                if op_str is None:
                    print("Warning: Operand {} for instruction at {} could not be processed, using Ghidra default: {}".format(
                        i, norm_addr_str, default_op_rep))
                    op_str = self.convert_to_kick_hex(default_op_rep)

                operand_strings.append(op_str)
            # --- End Operand Loop ---

            # Force absolute addressing mode (.abs) when the original instruction
            # is a 3-byte absolute form accessing a zero-page address ($00xx).
            # Without this KickAss would assemble the shorter zero-page opcode,
            # producing different bytes than the original binary.
            needs_abs = (
                instruction.getLength() == 3
                and instruction_bytes and len(instruction_bytes) >= 3
                and (instruction_bytes[2] & 0xff) == 0x00
                and mnemonic in self.ZP_CAPABLE.get(index_suffix, set())
            )
            effective_mnemonic = (mnemonic + ".abs") if needs_abs else mnemonic
            kick_disasm = effective_mnemonic.ljust(3) + (" " + ", ".join(operand_strings) if operand_strings else "")
        # --- End Non-Accumulator Processing ---

        # --- Format and write the instruction line ---
        instruction_text = "  {}".format(kick_disasm)
        bytes_str        = " ".join(bytes_list)
        padded_bytes_str = "{:<8}".format(bytes_str)
        main_comment     = "[{}:{} {}]".format(norm_addr_str, padded_bytes_str, original_asm_for_comment)
        eol_comment      = self.listing.getComment(CodeUnit.EOL_COMMENT, address)
        padding1         = " " * max(1, self.COMMENT_COLUMN - len(instruction_text) - 2)
        line_so_far      = "{}{}// {}".format(instruction_text, padding1, main_comment)

        if not eol_comment:
            f.write(line_so_far + "\n")
        else:
            comment_lines = [l.encode('ascii', 'ignore').decode('ascii') for l in eol_comment.splitlines()]
            current_len   = len(line_so_far)
            if current_len >= self.EOL_COMMENT_COLUMN - 1:
                padding2 = " "
            else:
                padding2 = " " * (self.EOL_COMMENT_COLUMN - 1 - current_len)
            f.write(line_so_far + padding2 + comment_lines[0].strip() + "\n")
            if len(comment_lines) > 1:
                prefix_part1 = " " * (self.COMMENT_COLUMN - 2) + "//"
                prefix_part2 = " " * max(1, self.EOL_COMMENT_COLUMN - 1 - len(prefix_part1) + 2)
                line_prefix  = prefix_part1 + prefix_part2
                for extra_line in comment_lines[1:]:
                    f.write("{}{}\n".format(line_prefix, extra_line.strip()))

        post_comment = self.listing.getComment(CodeUnit.POST_COMMENT, address)
        self.write_multi_line_comment("POST:  ", post_comment, f, comment_indent)


# ==============================================================
# SymbolFileWriter — generates the _Symbols.asm file
# ==============================================================
class SymbolFileWriter:
    """Writes the _Symbols.asm file with .label definitions and XREF comments."""

    def __init__(self, resolver, formatter, symbol_comment_column):
        self.resolver              = resolver
        self.formatter             = formatter
        self.SYMBOL_COMMENT_COLUMN = symbol_comment_column

    def write(self, symbols_file):
        """
        Write symbols to file, with XREF comments.
        Excludes symbols already defined via ':' in the main ASM file.
        Includes user-defined symbols even if outside defined memory blocks.
        """
        program_name = self.resolver.program.getName()
        print("Writing symbols file...")
        symbols_to_write = {}
        processed_addresses_for_xrefs = set()
        symbol_count  = 0
        total_symbols = self.resolver.symbolTable.getNumSymbols()

        for symbol in self.resolver.symbolTable.getAllSymbols(True):
            symbol_count += 1
            if symbol_count % 5000 == 0:
                print("  ...processed ~{}/{} symbols".format(symbol_count, total_symbols))

            symbol_name = symbol.getName()
            address_obj = symbol.getAddress()
            if not address_obj: continue

            is_user_symbol = symbol.getSource() != 0
            is_in_memory   = self.resolver.memory.contains(address_obj)
            if not is_user_symbol and not is_in_memory:
                continue

            will_get_colon_definition = symbol_name in self.resolver.get_labels_at_address(address_obj)
            is_relevant_type          = symbol.getSymbolType() != SymbolType.FUNCTION
            is_non_default            = symbol.getSource() != 0

            should_include = (
                (symbol_name.startswith("DAT_") or is_non_default)
                and is_relevant_type
                and not will_get_colon_definition
            )
            if not should_include:
                continue

            norm_addr = self.resolver.normalize_address(address_obj)
            if not norm_addr: continue

            current_priority = symbols_to_write[norm_addr]['priority'] if norm_addr in symbols_to_write else -1
            new_priority     = 1 if is_non_default else 0

            if new_priority >= current_priority:
                # Carry forward any XREFs already gathered so they aren't lost
                # when a higher-priority symbol wins the name slot.
                existing_xrefs = symbols_to_write[norm_addr]['xrefs'] if norm_addr in symbols_to_write else []
                symbols_to_write[norm_addr] = {
                    'name':     symbol_name,
                    'priority': new_priority,
                    'xrefs':    existing_xrefs,
                }

            if norm_addr not in processed_addresses_for_xrefs:
                processed_addresses_for_xrefs.add(norm_addr)
                try:
                    xref_list = []
                    for ref in self.resolver.referenceManager.getReferencesTo(address_obj):
                        ref_type = ref.getReferenceType()
                        if ref_type.isRead() or ref_type.isWrite() or ref_type.isCall() or \
                           ref_type.isJump() or ref_type.isData() or ref_type.isComputed():
                            xref_list.append(self.resolver.format_xref_string(ref))
                    if norm_addr in symbols_to_write:
                        symbols_to_write[norm_addr]['xrefs'] = sorted(list(set(xref_list)))
                except Exception as xref_e:
                    print("Warning: Error gathering XREFs for {} ({}): {}".format(norm_addr, symbol_name, xref_e))
                    if norm_addr in symbols_to_write:
                        symbols_to_write[norm_addr]['xrefs'] = ["XREF_Error"]

        print("Writing {} symbols to: {}".format(len(symbols_to_write), symbols_file))
        with open(symbols_file, 'w') as f:
            f.write("// Symbols for: {}\n".format(program_name))
            f.write("// Generated on: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("// Includes XREF information (R=Read, W=Write, c=Call, j=Jump, p=Pointer, d=Data)\n")
            f.write("// NOTE: Excludes symbols defined with ':' in the main assembly file.\n")
            f.write("// NOTE: Includes user-defined symbols even if outside defined memory blocks.\n\n")
            f.write("#importonce\n\n")

            try:
                sorted_items = sorted(symbols_to_write.items(), key=lambda item: int(item[0], 16) if item[0] else 0)
            except ValueError:
                print("Error sorting symbols by address; using unsorted order.")
                sorted_items = symbols_to_write.items()

            for norm_addr, data in sorted_items:
                if not norm_addr: continue
                sanitized_name = self.formatter.sanitize_label_name(data['name'])
                if not sanitized_name or sanitized_name == '_':
                    print("Warning: Symbol '{}' at {} has invalid sanitized name. Skipping.".format(data['name'], norm_addr))
                    continue

                label_line = ".label {} = ${}".format(sanitized_name, norm_addr)
                xrefs      = data.get('xrefs', [])

                if not xrefs:
                    f.write(label_line + "\n")
                else:
                    padding          = " " * max(1, self.SYMBOL_COMMENT_COLUMN - len(label_line) - 2)
                    comment_indent   = " " * (self.SYMBOL_COMMENT_COLUMN - 2)
                    first_line       = "{}{}// XREF[{}]: ".format(label_line, padding, len(xrefs))
                    self.formatter.write_xref_comment(f, xrefs, first_line, comment_indent, 90)

        print("Wrote {} symbols with XREFs to: {}".format(len(symbols_to_write), symbols_file))


# ==============================================================
# KickAssemblerExporter — orchestrates the full export
# ==============================================================
class KickAssemblerExporter:
    """Top-level orchestrator: prompts for output path, then writes symbol and main ASM files."""

    def __init__(self, currentProgram):
        self.program      = currentProgram
        self.program_name = currentProgram.getName()
        self.memory       = currentProgram.getMemory()
        self.blocks       = self.memory.getBlocks()

        # Column layout (characters)
        self.COMMENT_COLUMN     = 40   # start of // [ADDR: bytes mnemonic] comment
        self.EOL_COMMENT_COLUMN = 75   # start of user EOL comment
        self.SYMBOL_COMMENT_COLUMN = 50  # start of XREF comment in symbols file

        options_name = "KickAssemblerExport"
        default_path = "~/ghidra_kick_assembler_exports/src"
        _tool = state.getTool()  # None in headless mode
        self.OUTPUT_PATH = _tool.getOptions(options_name).getString("LastOutputPath", default_path) if _tool else default_path

        self.resolver      = SymbolResolver(currentProgram)
        self.formatter     = AsmFormatter(self.resolver, self.COMMENT_COLUMN, self.EOL_COMMENT_COLUMN)
        self.symbol_writer = SymbolFileWriter(self.resolver, self.formatter, self.SYMBOL_COMMENT_COLUMN)

    def build_output_paths(self):
        """Create the output directory and return (main_file, symbols_file) paths."""
        output_dir = os.path.join(os.path.expanduser("~"), self.OUTPUT_PATH)
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print("Created output directory: {}".format(output_dir))
            except OSError as e:
                print("Error creating directory {}: {}".format(output_dir, e))
                return None, None
        safe_name    = re.sub(r'[\\/*?:"<>|]', '_', self.program_name)
        main_file    = os.path.join(output_dir, "{}.asm".format(safe_name))
        symbols_file = os.path.join(output_dir, "{}_Symbols.asm".format(safe_name))
        print("Output files:\n  Main:    {}\n  Symbols: {}".format(main_file, symbols_file))
        return main_file, symbols_file

    def write_header(self, f, symbols_file=None):
        """Write the file header and optional #import directive."""
        f.write("// Disassembly of: {}\n".format(self.program_name))
        f.write("// Generated on: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("// Exported from Ghidra to Kick Assembler format\n")
        if symbols_file:
            f.write("// Symbols file: {}\n".format(os.path.basename(symbols_file)))
            f.write("\n#import \"{}\"\n".format(os.path.basename(symbols_file)))
        f.write("\n")

    def export(self):
        """Prompt for an output directory, then write the symbols file and main ASM file."""
        print("Starting Kick Assembler Export...")
        start_time   = datetime.datetime.now()
        options_name = "KickAssemblerExport"

        try:
            initial_dir = os.path.expanduser(os.path.join("~", self.OUTPUT_PATH))
            if not os.path.exists(initial_dir):
                initial_dir = os.path.expanduser("~")

            selected_dir = askDirectory("Select Export Directory", "Choose:")
            if selected_dir is None:
                print("User cancelled the export.")
                return

            selected_path = selected_dir.getAbsolutePath()
            home_dir      = os.path.expanduser("~")
            if selected_path.startswith(home_dir):
                self.OUTPUT_PATH = os.path.relpath(selected_path, home_dir)
            else:
                self.OUTPUT_PATH = selected_path

            _tool = state.getTool()
            if _tool:
                _tool.getOptions(options_name).setString("LastOutputPath", self.OUTPUT_PATH)
            print("Export path set to: {}".format(self.OUTPUT_PATH))

        except CancelledException:
            print("User cancelled the export.")
            return

        main_file, symbols_file = self.build_output_paths()
        if not main_file or not symbols_file:
            print("ERROR: Could not determine output file paths. Aborting.")
            return

        self.resolver.build_symbol_map()
        self.resolver.build_label_map()
        self.resolver.clear_cache()

        try:
            self.symbol_writer.write(symbols_file)
        except Exception:
            print("ERROR: Unexpected error writing symbols file:")
            traceback.print_exc()
            return

        print("Writing main assembly file...")
        listing = self.resolver.listing
        try:
            with open(main_file, 'w') as f:
                self.write_header(f, symbols_file)

                try:
                    blocks_list = sorted(self.blocks, key=lambda b: b.getStart())
                except Exception:
                    print("Warning: Could not sort memory blocks; using original order.")
                    blocks_list = self.blocks

                for block_idx, block in enumerate(blocks_list):
                    start_addr = block.getStart()
                    end_addr   = block.getEnd()
                    print("  Processing block {}/{}: {} ({} - {}) Size: {}".format(
                        block_idx + 1, len(blocks_list),
                        block.getName(), start_addr, end_addr, block.getSize()))

                    if not block.isInitialized() or block.getSize() <= 0:
                        print("    Skipping empty or uninitialized block.")
                        continue

                    f.write("\n// *** BLOCK START: {} ({} - {}) ***\n".format(block.getName(), start_addr, end_addr))
                    f.write(".pc = ${} \"{}\"\n".format(start_addr.toString().split(':')[-1], block.getName()))

                    current_address    = start_addr
                    raw_byte_buffer    = []
                    buffer_start_address = None

                    while current_address is not None and current_address.compareTo(end_addr) <= 0:
                        processed_length  = 1
                        address_processed = False

                        # --- Emit any labels at this address ---
                        pending_labels = self.resolver.get_labels_at_address(current_address)
                        if pending_labels:
                            if self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                raw_byte_buffer      = []
                                buffer_start_address = None
                            f.write("\n")
                            self.formatter.process_xrefs(current_address, f)
                            for label in pending_labels:
                                sanitized = self.formatter.sanitize_label_name(label)
                                if sanitized:
                                    f.write("{}:\n".format(sanitized))
                                else:
                                    f.write("// Warning: Skipped invalid label '{}' at {}\n".format(label, current_address))

                        # --- Look up what lives at this address (one call, reused below) ---
                        code_unit = listing.getCodeUnitAt(current_address)

                        # --- Plate/Pre comments for non-instruction addresses ---
                        if not isinstance(code_unit, Instruction):
                            plate_comment = listing.getComment(CodeUnit.PLATE_COMMENT, current_address)
                            pre_comment   = listing.getComment(CodeUnit.PRE_COMMENT,   current_address)
                            if plate_comment or pre_comment:
                                if self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                    raw_byte_buffer      = []
                                    buffer_start_address = None
                                self.formatter.write_multi_line_comment("", plate_comment, f, "  ", blank_line_before=True)
                                self.formatter.write_multi_line_comment("", pre_comment,   f, "  ", blank_line_before=True)

                        # --- Instruction ---
                        if isinstance(code_unit, Instruction):
                            if self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                raw_byte_buffer      = []
                                buffer_start_address = None
                            self.formatter.process_instruction(code_unit, f)
                            processed_length  = code_unit.getLength()
                            address_processed = True

                        # --- Defined data → raw byte buffer ---
                        elif isinstance(code_unit, Data):
                            try:
                                temp_addr = current_address
                                for byte_value in code_unit.getBytes():
                                    if buffer_start_address is None:
                                        buffer_start_address = temp_addr
                                    raw_byte_buffer.append(byte_value & 0xff)
                                    if len(raw_byte_buffer) >= self.formatter.MAX_RAW_BYTES_PER_LINE:
                                        self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                        raw_byte_buffer      = []
                                        buffer_start_address = None
                                    try:
                                        temp_addr = temp_addr.addNoWrap(1)
                                    except (AddressOutOfBoundsException, Exception):
                                        temp_addr = None
                                        break
                            except Exception as e:
                                print("Error reading Data unit at {}: {}".format(current_address, e))
                                self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                raw_byte_buffer      = []
                                buffer_start_address = None
                                f.write(" // Error processing Data unit at {}\n".format(current_address))
                            processed_length  = code_unit.getLength()
                            address_processed = True

                        # --- Undefined byte → raw byte buffer ---
                        if not address_processed:
                            try:
                                byte_value = self.memory.getByte(current_address) & 0xff
                                if buffer_start_address is None:
                                    buffer_start_address = current_address
                                raw_byte_buffer.append(byte_value)
                                if len(raw_byte_buffer) >= self.formatter.MAX_RAW_BYTES_PER_LINE:
                                    self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                    raw_byte_buffer      = []
                                    buffer_start_address = None
                            except Exception as e:
                                print("Error reading undefined byte at {}: {}".format(current_address, e))
                                self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                raw_byte_buffer      = []
                                buffer_start_address = None
                                f.write(" // Error reading byte at {}\n".format(current_address))

                        # --- Advance address ---
                        if processed_length <= 0:
                            print("Warning: processed_length <= 0 at {}, advancing by 1.".format(current_address))
                            processed_length = 1
                        if current_address.compareTo(end_addr) >= 0:
                            current_address = None  # processed last address; done
                        else:
                            try:
                                next_address = current_address.addNoWrap(processed_length)
                                if next_address.compareTo(current_address) < 0:
                                    print("Warning: address wrap at {}, stopping block.".format(current_address))
                                    current_address = None
                                else:
                                    current_address = next_address
                            except (AddressOutOfBoundsException, AddressOverflowException):
                                current_address = None  # normal at end of 16-bit address space
                            except Exception as addr_e:
                                print("Error advancing address from {}: {}".format(current_address, addr_e))
                                current_address = None

                    # Flush any trailing bytes at end of block
                    self.formatter.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                    f.write("// *** BLOCK END: {} ***\n".format(block.getName()))

        except IOError as e:
            print("ERROR: Cannot write main assembly file {}: {}".format(main_file, e))
            return
        except Exception:
            print("ERROR: Unexpected error writing main assembly file:")
            traceback.print_exc()
            return

        end_time = datetime.datetime.now()
        print("\nExport Complete.")
        print("  Main:    {}".format(main_file))
        print("  Symbols: {}".format(symbols_file))
        print("  Time:    {}".format(end_time - start_time))


# ==============================================================
# Main
# ==============================================================
if __name__ == "__main__":
    print("="*60)
    print(" Kick Assembler Export Script ")
    print("="*60)
    try:
        try:
            currentProgram = state.getCurrentProgram()
            print("Running in Ghidra GUI mode.")
        except NameError:
            print("Running in potential Headless mode.")
            if 'currentProgram' not in globals() or not currentProgram:
                raise NameError("'currentProgram' not available. Ensure script is run inside Ghidra.")

        if currentProgram:
            KickAssemblerExporter(currentProgram).export()
        else:
            print("ERROR: Script could not access the current program.")
            try:
                from javax.swing import JOptionPane
                JOptionPane.showMessageDialog(None, "Script could not access the current program.", "Export Error", JOptionPane.ERROR_MESSAGE)
            except Exception: pass

    except NameError as ne:
        print("ERROR: Ghidra environment not detected: '{}'".format(ne))
        try:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(None, "Ghidra environment not detected:\n'{}'".format(ne), "Export Error", JOptionPane.ERROR_MESSAGE)
        except Exception: pass
    except Exception as e:
        print("\n--- EXPORT FAILED ---")
        traceback.print_exc()
        print("---------------------")
        try:
            from javax.swing import JOptionPane
            JOptionPane.showMessageDialog(None, "Export failed: {}\n\nSee console log for details.".format(e), "Export Error", JOptionPane.ERROR_MESSAGE)
        except Exception: pass
    finally:
        print("Script finished.")
