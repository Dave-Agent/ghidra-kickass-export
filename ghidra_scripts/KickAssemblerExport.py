# Ghidra Script to Export Disassembly to Kick Assembler Format
# Includes symbol/label handling, XREFs in code and symbol file,
# comment preservation, improved formatting, and unified byte/code processing.

#@keybinding control alt K
#@menupath Tools.Kick Assembler Export
#@category Kick Assembler Tools

# --- Imports ---
from java.io import File
# Import specific Ghidra types needed
from ghidra.program.model.listing import CodeUnit, Instruction, Data
from ghidra.program.model.symbol import SymbolType, Symbol, RefType
from ghidra.program.model.address import Address, AddressOutOfBoundsException
from ghidra.util.exception import CancelledException
from ghidra.framework.preferences import Preferences 
from ghidra.program.model.scalar import Scalar
import ghidra 

import os
import datetime
import re
import traceback 

# --- Exporter Class ---
class KickAssemblerExporter:
    def __init__(self, currentProgram):
        """Initialize the exporter with the current Ghidra program."""
        self.program = currentProgram
        self.program_name = currentProgram.getName()
        self.listing = currentProgram.getListing()
        self.memory = currentProgram.getMemory()
        self.blocks = self.memory.getBlocks()
        self.functionManager = currentProgram.getFunctionManager()
        self.symbolTable = currentProgram.getSymbolTable()
        self.referenceManager = currentProgram.getReferenceManager()
        self.addr_factory = self.program.getAddressFactory()
        self.default_space = self.addr_factory.getDefaultAddressSpace()

        options_name = "KickAssemblerExport"
        default_path = "~/ghidra_kick_assembler_exports/src"
        self.OUTPUT_PATH = state.getTool().getOptions(options_name).getString("LastOutputPath", default_path)

        # Configuration
        self.COMMENT_COLUMN = 40  # Starting column for EOL comments in main ASM file
        self.EOL_COMMENT_COLUMN = 75  # Starting column for user EOL comments in main ASM file
        self.SYMBOL_COMMENT_COLUMN = 50 # Starting column for comments in Symbols file
        self.MAX_RAW_BYTES_PER_LINE = 16 # Max bytes per .byte line for undefined data

        # Internal Maps (built during export)
        self.address_to_label = {} # Map of normalized address string -> primary label name
        self.symbol_map = {} # Map of normalized address string -> primary symbol name
        self.labels_getting_colon_cache = {} # Map of norm_addr -> list of label names

    # --- Helper: Address Normalization ---
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

    # --- Output Path ---
    def build_output_path(self):
        """Alias for build_output_paths for backwards compatibility"""
        return self.build_output_paths()

    def build_output_paths(self):
        """Create output directory and return filenames"""
        output_dir = os.path.join(os.path.expanduser("~"), self.OUTPUT_PATH)
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
                print("Created output directory: {}".format(output_dir))
            except OSError as e:
                print("Error creating directory {}: {}".format(output_dir, e))
                return None, None
        safe_program_name = re.sub(r'[\\/*?:"<>|]', '_', self.program_name)
        main_file = os.path.join(output_dir, "{}.asm".format(safe_program_name))
        symbols_file = os.path.join(output_dir, "{}_Symbols.asm".format(safe_program_name))
        print("Output files will be:")
        print("  Main: {}".format(main_file))
        print("  Symbols: {}".format(symbols_file))
        return main_file, symbols_file

    # --- Map Building (Using Normalized Addresses) ---
    def build_symbol_map(self):
        """Build a map of normalized addresses to symbols."""
        print("Building symbol map (normalized, including user symbols outside memory blocks)...")
        self.symbol_map = {}
        symbols = self.symbolTable.getAllSymbols(True)
        unique_symbols = {} # Temp dict to handle priority if multiple symbols at one address

        for symbol in symbols:
            address_obj = symbol.getAddress()
            # Basic check: Symbol must have an address
            if not address_obj: continue

            is_user_symbol = symbol.getSource() != 0 # Check if user-defined (source != 0)
            is_in_memory = self.memory.contains(address_obj) # Check if address is in defined block

            # Skip processing this symbol ONLY if it is NOT user-defined AND its
            # address is outside Ghidra's defined memory map.
            # This ensures user symbols (like RAM variables) are always included.
            if not is_user_symbol and not is_in_memory:
                # print("Debug build_symbol_map: Skipping non-user symbol {} at {} (outside defined memory)".format(symbol.getName(), address_obj))
                continue

            # Proceed with processing if it's a user symbol OR if it's within defined memory
            norm_addr = self.normalize_address(address_obj)
            # Need a valid normalized address string to use as a map key
            if not norm_addr: continue

            symbol_name = symbol.getName()
            # === END DEBUG ===
            current_priority, new_priority = -1, -1
            stype, s_src = symbol.getSymbolType(), symbol.getSource()

            # Prioritization: User Label > Function > Other User > Default (like DAT_)
            # This priority helps decide which symbol name to use if multiple exist at the same address.
            if s_src != 0 and stype == SymbolType.LABEL: new_priority = 3  # User Label
            elif stype == SymbolType.FUNCTION: new_priority = 2            # Function
            elif s_src != 0: new_priority = 1                              # Other User Symbol
            else: new_priority = 0                                         # Default source symbol (DAT_, etc.)

            # Check if we already have a symbol for this normalized address
            if norm_addr in unique_symbols:
                current_priority = unique_symbols[norm_addr]['priority']

            # Store or update the symbol for this address if the new one has higher or equal priority
            if new_priority >= current_priority:
                unique_symbols[norm_addr] = {'name': symbol_name, 'priority': new_priority}

        # Final map uses the chosen symbol name for each unique normalized address
        self.symbol_map = {addr: data['name'] for addr, data in unique_symbols.items()}
        print("Stored {} unique symbols using normalized addresses.".format(len(self.symbol_map)))

    def build_label_map(self):
        """First pass: collect all primary flow labels/functions using normalized addresses."""
        # NOTE: This function ALSO implicitly benefits if a user adds a flow label (e.g., jump target)
        # outside defined memory, because the modified build_symbol_map would have added it,
        # allowing find_symbol_for_address to potentially find it later.
        # However, this map is primarily built from symbols Ghidra identifies as LABEL/FUNCTION.
        # If you need labels outside defined memory to be added *here* explicitly,
        # this function would need the same modification as build_symbol_map.
        print("Building label map (normalized)...")
        self.address_to_label = {}
        symbols = self.symbolTable.getSymbolIterator()
        while symbols.hasNext():
            symbol = symbols.next()
            address_obj = symbol.getAddress()

            # --- Apply same logic as build_symbol_map for consistency ---
            if not address_obj: continue
            is_user_symbol = symbol.getSource() != 0
            is_in_memory = self.memory.contains(address_obj)
            if not is_user_symbol and not is_in_memory:
                continue

            is_label = symbol.getSymbolType() == SymbolType.LABEL # and symbol.getSource() != 0 # Keep source check here specific to label map purpose?
            is_func = symbol.getSymbolType() == SymbolType.FUNCTION

            # Only add labels potentially used for code flow (operands) here
            if (is_label and symbol.getSource() != 0) or is_func:
                norm_addr = self.normalize_address(address_obj)
                if not norm_addr: continue
                # Prioritize User Labels over Functions if both exist for operand lookup
                if norm_addr not in self.address_to_label or (is_label and symbol.getSource() != 0) :
                     self.address_to_label[norm_addr] = symbol.getName()
        print("Found {} potential flow labels/function entries.".format(len(self.address_to_label)))

    # --- Helper Methods ---
    def convert_to_kick_hex(self, disasm_fragment):
        """Convert Ghidra hex format (0x...) to Kick Assembler format ($...)."""
        frag = disasm_fragment
        frag = re.sub(r'#0x([0-9A-Fa-f]+)(?![0-9A-Fa-f])', r'#$\1', frag)
        frag = re.sub(r'(?<![A-Za-z0-9_])0x([0-9A-Fa-f]+)(?![0-9A-Fa-f])', r'$\1', frag)
        return frag

    def find_symbol_for_address(self, address_obj):
        """Looks up a symbol for a Ghidra Address object using normalized maps."""
        if not address_obj: return None
        
        # Get normalized address string
        norm_addr = self.normalize_address(address_obj)
        if not norm_addr: return None
        
        # First priority: Check user-defined labels (highest priority for display)
        symbols_at_addr = self.symbolTable.getSymbols(address_obj)
        for symbol in symbols_at_addr:
            if symbol.getSource() != 0 and symbol.getSymbolType() == SymbolType.LABEL:
                return symbol.getName()  # Return first user-defined label
        
        # Second priority: Check flow labels map (user labels/functions)
        if norm_addr in self.address_to_label: 
            return self.address_to_label[norm_addr]
        
        # Third priority: Check general symbol map (includes DAT_, etc.)
        if norm_addr in self.symbol_map: 
            return self.symbol_map[norm_addr]
        
        # Final attempt: Look in symbol table for any symbol at this address
        for symbol in symbols_at_addr:
            return symbol.getName()  # Return first available symbol of any type
        
        return None

    def get_function_containing(self, address):
        """Get function containing an address"""
        if not address: return None
        try:
            func = self.functionManager.getFunctionContaining(address)
            if func: return func.getName()
        except Exception: pass
        return None

    def format_xref_string(self, ref):
        """Helper function to format a single XREF for comments."""
        from_addr = ref.getFromAddress()
        ref_type = ref.getReferenceType()
        type_char = "?"
        if ref_type.isRead(): type_char = "R"
        elif ref_type.isWrite(): type_char = "W"
        elif ref_type.isCall(): type_char = "c"
        elif ref_type.isJump(): type_char = "j"
        elif ref_type.isComputed(): type_char = "p"
        elif ref_type.isData(): type_char = "d"
        addr_str = from_addr.toString().split(':')[-1]
        func_name = self.get_function_containing(from_addr)
        xref_detail = "{}({})".format(addr_str, type_char)
        return "{}:{}".format(func_name, xref_detail) if func_name else xref_detail

    def get_labels_at_address(self, address):
        """
        Gets a sorted list of label/function names intended for colon definition (LABEL:)
        at a specific address. Filters to only include FUNCTION entry points and
        non-default LABELs that point directly to the start of an Instruction.
        Excludes DAT_ labels and labels pointing only to data.
        Caches results for performance.
        """
        if not address: return []

        norm_addr = self.normalize_address(address)
        if not norm_addr: return []

        # Check cache first
        if norm_addr in self.labels_getting_colon_cache:
            return self.labels_getting_colon_cache[norm_addr]

        labels_for_colon_def = []
        symbols_here = self.symbolTable.getSymbols(address)
        instruction_at = self.listing.getInstructionAt(address) # Get instruction once

        for symbol in symbols_here:
            symbol_name = symbol.getName()
            symbol_type = symbol.getSymbolType()
            is_non_default = symbol.getSource() != 0

            should_define_with_colon = False

            # Include FUNCTION entry points for colon definition
            if symbol_type == SymbolType.FUNCTION:
                should_define_with_colon = True

            # Include non-default LABELs *only if* they point to an Instruction start
            elif is_non_default and symbol_type == SymbolType.LABEL:
                 # Check if instruction exists AND starts exactly at the label address
                 if instruction_at is not None and instruction_at.getAddress().equals(address):
                      should_define_with_colon = True

            # Add to list if it should be defined with colon and isn't already added
            if should_define_with_colon:
                 if symbol_name not in labels_for_colon_def:
                    labels_for_colon_def.append(symbol_name)

        result = sorted(labels_for_colon_def)
        # Store in cache
        self.labels_getting_colon_cache[norm_addr] = result
        return result

    def convert_to_petscii_ascii(self, byte_value):
        """Converts a byte value to its ASCII representation if common PETSCII, else '.'"""
        # C64 PETSCII Screen code range for printable chars (Uppercase mode)
        if 32 <= byte_value <= 95:
             try: return chr(byte_value)
             except ValueError: return '.'
        else:
            return '.' # Placeholder for control codes, graphics, etc.

    def flush_raw_bytes(self, byte_buffer, start_addr, f):
        """Writes a buffer of raw bytes as a .byte directive with PETSCII comment."""
        if not byte_buffer:
            return False # Indicate nothing flushed

        bytes_hex_list = ["${:02x}".format(b) for b in byte_buffer]
        petscii_str = "".join([self.convert_to_petscii_ascii(b) for b in byte_buffer])

        data_text = "  .byte {}".format(",".join(bytes_hex_list))

        # Comment: [START_ADDR_OF_BUFFER] PETSCII_REPRESENTATION
        addr_str = start_addr.toString().split(':')[-1] if start_addr else "????"
        full_comment = "[{}] {}".format(addr_str, petscii_str)

        padding_len = self.COMMENT_COLUMN - len(data_text) - 2 # -2 for "//"
        padding = " " * max(1, padding_len)

        f.write("{}{}{} {}\n".format(
            data_text, padding, "//", full_comment
        ))
        # Return True indicating bytes were flushed
        return True

    # --- File Writing ---
    def write_header(self, f, symbols_file=None):
        """Write file header information"""
        f.write("// Disassembly of: {}\n".format(self.program_name))
        f.write("// Generated on: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("// Exported from Ghidra to Kick Assembler format\n")
        if symbols_file:
            f.write("// Symbols file: {}\n".format(os.path.basename(symbols_file)))
            f.write("\n#import \"{}\"\n".format(os.path.basename(symbols_file)))
        f.write("\n")


    def sanitize_label_name(self, name):
        """Replaces characters invalid in Kick Assembler labels with underscores."""
        if not name: return "_invalid_name_"
        # Allow '@' character common in KickAss pseudo-labels (like @start)
        # Allow '.' character common in KickAss local labels (.loop)
        sanitized = re.sub(r'[^a-zA-Z0-9_@.]', '_', name)
        # Ensure doesn't start with a digit unless it's part of a local label like .1
        if sanitized and sanitized[0].isdigit() and not sanitized.startswith('.'):
             sanitized = "_" + sanitized
        # C++ scope operator replacement
        sanitized = sanitized.replace("::", "_")
        if not sanitized: return "_invalid_name_"
        # Prevent multiple consecutive underscores that might result from replacements
        sanitized = re.sub(r'_+', '_', sanitized)
        # Remove leading/trailing underscores that might result
        sanitized = sanitized.strip('_')
        # Final check if empty after stripping
        if not sanitized: return "_invalid_name_"
        # If it became just '.' or '@' after stripping, make it invalid
        if sanitized == '.' or sanitized == '@': return "_invalid_name_"

        return sanitized
    # -------------------------------------------------------------

    def write_symbols_file(self, symbols_file):
        """
        Write symbols to a separate file, including XREF comments.
        Filters to include symbols *NOT* defined via ':' in the main ASM file.
        This typically includes data labels (DAT_), user labels on data, etc.
        MODIFIED: Allows user-defined symbols (source != 0) even if their
                  address is outside Ghidra's defined memory blocks.
        """
        print("Writing symbols file (filtered, excluding labels defined via ':')...")
        # Structure: {norm_addr: {'name': symbol_name, 'priority': priority, 'xrefs': [...]}}
        symbols_to_write = {} # Store symbols intended ONLY for the .label file

        ghidra_symbols = self.symbolTable.getAllSymbols(True)
        processed_addresses_for_xrefs = set() # Keep track for XREF processing efficiency
        print("Analyzing symbols for symbol file (filtering out labels getting ':' definition)...")
        symbol_count = 0
        total_symbols = self.symbolTable.getNumSymbols()

        for symbol in ghidra_symbols:
            symbol_count += 1
            if symbol_count % 5000 == 0: print("  ...processed ~{}/{} symbols".format(symbol_count, total_symbols))

            symbol_name = symbol.getName()
            address_obj = symbol.getAddress()

            # Basic validity check: Symbol must have an address
            if not address_obj: continue

            is_user_symbol = symbol.getSource() != 0 # Check if user-defined
            is_in_memory = self.memory.contains(address_obj) # Check if address is in defined block

            # Skip processing this symbol ONLY if it is NOT user-defined AND its
            # address is outside Ghidra's defined memory map.
            # This allows user symbols (like RAM variables) outside defined blocks
            # to be potentially included in the symbol file.
            if not is_user_symbol and not is_in_memory:
                 # Optional Debug:
                 # print("Debug write_symbols_file: Skipping non-user symbol {} for symbol file (outside defined memory)".format(symbol_name, address_obj))
                 continue

            # --- Filtering Logic ---
            # Determine if this specific symbol *will* be defined with a colon (':')
            # by calling the definitive function get_labels_at_address.
            # This call is safe because getInstructionAt(addr) returns None if addr
            # is outside memory or has no instruction, preventing colon definition.
            labels_getting_colon_here = self.get_labels_at_address(address_obj)
            will_get_colon_definition = symbol_name in labels_getting_colon_here

            # Determine if the symbol is potentially relevant for the symbol file
            is_relevant_type = symbol.getSymbolType() != SymbolType.FUNCTION
            is_non_default = symbol.getSource() != 0 # Same as is_user_symbol check above

            # Include DAT_ or user labels (but not functions) IF they won't get a colon
            should_consider_for_symbol_file = (symbol_name.startswith("DAT_") or is_non_default) and is_relevant_type

            # FINAL DECISION: Include in symbols file ONLY if it's relevant AND will NOT get a colon definition
            should_include_in_symbol_file = should_consider_for_symbol_file and not will_get_colon_definition
            # --- End Filtering Logic ---

            if should_include_in_symbol_file:
                norm_addr = self.normalize_address(address_obj)
                if not norm_addr: continue

                # Store info if address is new or this symbol takes priority for the SYMBOL FILE
                current_priority = -1
                # Give user symbols higher priority over DAT_ within the symbol file context
                new_priority = 1 if is_non_default else 0 # is_non_default is equivalent to is_user_symbol here

                if norm_addr in symbols_to_write: current_priority = symbols_to_write[norm_addr]['priority']

                if new_priority >= current_priority:
                    # Overwrite or add the symbol chosen for the symbol file at this address
                    symbols_to_write[norm_addr] = {
                        'name': symbol_name,
                        'priority': new_priority,
                        'xrefs': [] # XREFs will be added below if address hasn't been processed
                    }

                # --- Gather XREFs (only once per address, only for symbols actually included) ---
                # Check if we decided to include *some* symbol at this address in the current pass
                # and if we haven't processed XREFs for this address yet.
                # NOTE: The reference manager should work even if the 'to' address (address_obj)
                # is outside a defined block, as long as the 'from' address is valid.
                if norm_addr in symbols_to_write and norm_addr not in processed_addresses_for_xrefs:
                    processed_addresses_for_xrefs.add(norm_addr)
                    try:
                        # Check memory contains for the 'to' address just as a safeguard,
                        # although the primary filtering happened above. Refs *should* still work.
                        # if self.memory.contains(address_obj): # This check is likely redundant now
                        refs_to = self.referenceManager.getReferencesTo(address_obj)
                        xref_list = []
                        for ref in refs_to:
                             ref_type = ref.getReferenceType()
                             # Include all relevant reference types for symbol file comments
                             if ref_type.isRead() or ref_type.isWrite() or ref_type.isCall() or \
                                ref_type.isJump() or ref_type.isData() or ref_type.isComputed():
                                  xref_list.append(self.format_xref_string(ref))
                         # Ensure the symbol entry still exists (priority logic might have changed it)
                        if norm_addr in symbols_to_write:
                            symbols_to_write[norm_addr]['xrefs'] = sorted(list(set(xref_list)))
                    except Exception as xref_e:
                         print("Warning: Error gathering XREFs for {} (Symbol: {}): {}".format(norm_addr, symbol_name, xref_e))
                         if norm_addr in symbols_to_write: symbols_to_write[norm_addr]['xrefs'] = ["XREF_Error"]


        # --- Writing to file ---
        print("Writing {} filtered symbols to file: {}".format(len(symbols_to_write), symbols_file))
        with open(symbols_file, 'w') as f:
            f.write("// Symbols for: {}\n".format(self.program_name))
            f.write("// Generated on: {}\n".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            f.write("// Includes XREF information (R=Read, W=Write, c=Call, j=Jump, p=Pointer, d=Data)\n")
            f.write("// NOTE: Excludes symbols defined with ':' in the main assembly file.\n")
            f.write("// NOTE: Includes user-defined symbols even if outside defined memory blocks.\n\n") # Added note
            f.write("#importonce\n\n")

            try: sorted_symbol_items = sorted(symbols_to_write.items(), key=lambda item: int(item[0], 16) if item[0] else 0)
            except ValueError as sort_e: print("Error sorting symbols..."); sorted_symbol_items = symbols_to_write.items()

            for norm_addr, data in sorted_symbol_items:
                if not norm_addr: continue
                original_name, xrefs = data['name'], data.get('xrefs', [])
                sanitized_name = self.sanitize_label_name(original_name)

                # Handle potentially empty sanitized names after stripping/replacement
                if not sanitized_name or sanitized_name == '_':
                    print("Warning: Symbol '{}' at {} resulted in invalid sanitized name '{}'. Skipping.".format(original_name, norm_addr, sanitized_name))
                    continue

                label_line = ".label {} = ${}".format(sanitized_name, norm_addr)

                if not xrefs: f.write(label_line + "\n")
                else:
                    padding_len = self.SYMBOL_COMMENT_COLUMN - len(label_line) - 2
                    padding = " " * max(1, padding_len)
                    comment_indent = " " * (self.SYMBOL_COMMENT_COLUMN - 2)
                    first_line = "{}{}// XREF[{}]: ".format(label_line, padding, len(xrefs))
                    line_limit, current_line_xrefs, remaining_xrefs = 90, [], list(xrefs) # Wrap comments nicely
                    while remaining_xrefs:
                        xref = remaining_xrefs.pop(0)
                        if not current_line_xrefs: # First xref on a (potentially new) line
                            test_line = first_line + xref if first_line else comment_indent + "//           " + xref
                        else: # Subsequent xrefs on the current line
                            test_line = (first_line if first_line else comment_indent + "//           ") + ", ".join(current_line_xrefs + [xref])

                        # Check length limit
                        if len(test_line) < line_limit or not current_line_xrefs:
                            current_line_xrefs.append(xref) # Add to current line
                        else:
                            # Write the line that was just filled
                            if first_line:
                                f.write(first_line + ", ".join(current_line_xrefs) + "\n")
                                first_line = None # Clear first line prefix for subsequent lines
                            else:
                                f.write("{}{}           {}\n".format(comment_indent, "//", ", ".join(current_line_xrefs)))
                            # Start new line with the xref that didn't fit
                            current_line_xrefs = [xref]

                    # Write any remaining xrefs from the last line
                    if first_line: # If only one line was needed
                        f.write(first_line + ", ".join(current_line_xrefs) + "\n")
                    elif current_line_xrefs: # If multiple lines, write the last one
                        f.write("{}{}           {}\n".format(comment_indent, "//", ", ".join(current_line_xrefs)))

        print("Wrote {} filtered symbols with XREFs to: {}".format(len(symbols_to_write), symbols_file))


    # --- Core Processing ---
    def process_xrefs(self, address, f):
        """Process cross-references TO an address (for main code file comments before labels)"""
        if not address: return
        try: refs_to = self.referenceManager.getReferencesTo(address)
        except Exception as e: print("Warning: Error getting references to {}: {}".format(address, e)); return
        xrefs = []
        for ref in refs_to:
            ref_type = ref.getReferenceType()
            # Show flow-related XREFs prominently in main code file
            if ref_type.isCall() or ref_type.isJump() or ref_type.isComputed():
                xrefs.append(self.format_xref_string(ref))
        if xrefs:
            unique_sorted_xrefs = sorted(list(set(xrefs)))
            xref_indent = " " * (self.COMMENT_COLUMN - 2)
            line_limit, current_line_xrefs, remaining_xrefs = 80, [], list(unique_sorted_xrefs) # Wrap nicely
            first_line = "{}{} XREF[{}]: ".format(xref_indent, "//", len(unique_sorted_xrefs))
            while remaining_xrefs:
                xref = remaining_xrefs.pop(0)
                if not current_line_xrefs: test_line = first_line + xref if first_line else xref_indent + "//           " + xref
                else: test_line = (first_line if first_line else xref_indent + "//           ") + ", ".join(current_line_xrefs + [xref])
                if len(test_line) < line_limit or not current_line_xrefs: current_line_xrefs.append(xref)
                else:
                    if first_line: f.write(first_line + ", ".join(current_line_xrefs) + "\n"); first_line = None
                    else: f.write("{}{}           {}\n".format(xref_indent, "//", ", ".join(current_line_xrefs)))
                    current_line_xrefs = [xref]
            if first_line: f.write(first_line + ", ".join(current_line_xrefs) + "\n")
            elif current_line_xrefs: f.write("{}{}           {}\n".format(xref_indent, "//", ", ".join(current_line_xrefs)))

    def process_instruction(self, instruction, f):
        """
        Process a single instruction, prioritizing symbols and formatting
        output for Kick Assembler. Includes original assembly and EOL comments,
        aligned appropriately. Handles various addressing modes, including fallbacks.
        NOTE: Label output (e.g., label:) is handled by the main export loop
              BEFORE this method is called.
        """
        address = instruction.getAddress()
        norm_addr_str = self.normalize_address(address) # Used in comments

        # Get original Ghidra disassembly string for the comment
        original_ghidra_disasm = instruction.toString()
        original_asm_for_comment = self.convert_to_kick_hex(original_ghidra_disasm)

        # Get instruction bytes for opcode checks and comment
        try:
            instruction_bytes = instruction.getBytes()
            bytes_list = ["{:02x}".format(b & 0xff) for b in instruction_bytes]
        except Exception as byte_err:
            print("Warning: could not get bytes for instr at {}: {}".format(norm_addr_str, byte_err))
            instruction_bytes = []
            bytes_list = ["??"] * instruction.getLength()

        # --- Handle Multi-Line Comments BEFORE the instruction (PRE, PLATE) ---
        # These are written above the instruction line, indented to the comment column
        comment_indent = "  " # Same indentation as instructions
        plate_comment = self.listing.getComment(CodeUnit.PLATE_COMMENT, address)
        pre_comment = self.listing.getComment(CodeUnit.PRE_COMMENT, address)

        # Helper function to write multi-line comments neatly
        def write_multi_line_comment(prefix, comment, file_handle, indent):
             if comment:
                 lines = comment.splitlines()
                 for i, line in enumerate(lines):
                     # Use prefix only for the first line of the comment type
                     p = prefix if i == 0 else " " * len(prefix)
                     # Remove non-ASCII characters
                     safe_line = line.encode('ascii', 'ignore').decode('ascii')
                     file_handle.write("{}// {}{}\n".format(indent, p, safe_line))

        # Write the comments if they exist (ABOVE the instruction)
        if plate_comment:
            f.write("\n") # Add a blank line before the plate comment
        write_multi_line_comment("", plate_comment, f, comment_indent)
        write_multi_line_comment("", pre_comment, f, comment_indent)

        mnemonic = instruction.getMnemonicString().lower() # Use lowercase mnemonics

        # Special case: Accumulator Addressing (ASL, LSR, ROL, ROR)
        accumulator_opcodes = {0x0A, 0x4A, 0x2A, 0x6A} # Opcodes for accumulator modes
        is_accumulator_mode = False
        if instruction_bytes and instruction_bytes[0] in accumulator_opcodes and instruction.getLength() == 1:
            is_accumulator_mode = True
        elif instruction_bytes and instruction_bytes[0] in accumulator_opcodes:
             # Sanity check warning if opcode matches but length is wrong
             print("Warning: Opcode {:02X} at {} looks like accumulator mode, but length is {} != 1. Processing generically.".format(
                   instruction_bytes[0], norm_addr_str, instruction.getLength()))

        # --- Assemble Instruction Text ---
        kick_disasm = ""
        operand_strings = []

        if is_accumulator_mode:
            # *** CORRECTED: Accumulator mode instructions just use the mnemonic in KickAss ***
            kick_disasm = "{}".format(mnemonic.ljust(3)) # Pad mnemonic, e.g., "asl"
        else:
            # --- Process Operands (Non-Accumulator Mode) ---
            num_operands = instruction.getNumOperands()
            for i in range(num_operands):
                op_str = None # The final string for this operand
                op_objects = instruction.getOpObjects(i)
                default_op_rep = instruction.getDefaultOperandRepresentation(i) # Ghidra's default string
                index_suffix = "" # For ",x" or ",y"

                # Determine index suffix early from default representation
                if default_op_rep.upper().endswith(",X"): index_suffix = ",x"
                elif default_op_rep.upper().endswith(",Y"): index_suffix = ",y"

                primary_symbol = None # Symbol found via Ghidra's Address objects

                # --- Primary Symbol Lookup (using Ghidra operand objects) ---
                for obj in op_objects:
                    if isinstance(obj, Address):
                        # Found an address object, try to find its primary symbol
                        symbol_name = self.find_symbol_for_address(obj)
                        if symbol_name:
                            primary_symbol = symbol_name
                            break # Use the first symbol found for this address object
                    elif isinstance(obj, Scalar):
                        # Handle immediate values directly
                        if default_op_rep.startswith('#'):
                            scalar_val = obj.getValue()
                            # Format based on typical 6502 usage (8-bit unless it's a 16-bit value maybe for pseudo-ops/macros)
                            # Basic heuristic: use 2 hex digits if value fits, else 4. JMP/JSR always use 4.
                            if abs(scalar_val) <= 0xFF and not mnemonic.startswith('j'):
                                op_str = "#${:02x}".format(scalar_val & 0xff)
                            else:
                                op_str = "#${:04x}".format(scalar_val & 0xffff)
                            break # Found scalar, assume this is the whole operand

                # --- Assemble Operand String ---
                if primary_symbol:
                    # Use the symbol found via Ghidra's Address object
                    sanitized_symbol = self.sanitize_label_name(primary_symbol)
                    # Handle indirect indexed addressing with symbols
                    if default_op_rep.startswith('(') and default_op_rep.upper().endswith(',X)'):
                        op_str = "({},x)".format(sanitized_symbol)
                    elif default_op_rep.startswith('(') and default_op_rep.upper().endswith('),Y'):
                        op_str = "({}),y".format(sanitized_symbol)
                    # Handle absolute or absolute indexed addressing with symbols
                    else:
                        op_str = sanitized_symbol + index_suffix
                elif op_str:
                    # Operand string was already set (likely an immediate value)
                    pass
                else:
                    # --- Fallback Logic (using regex on default representation) ---
                    # This runs if getOpObjects didn't yield a usable Address/symbol or Scalar
                    symbol_in_fallback = None
                    op_str_built = False # Flag to track if op_str was successfully built here
                    # Regex patterns to parse common 6502 addressing modes from Ghidra's string output
                    indirect_match_y = re.match(r'\(\$?(?:0x)?([0-9A-Fa-f]+)\),Y$', default_op_rep, re.IGNORECASE) # ($HH),Y
                    indirect_match_x = re.match(r'\(\$?(?:0x)?([0-9A-Fa-f]+),X\)$', default_op_rep, re.IGNORECASE) # ($HH,X)
                    absolute_match_xy = re.match(r'\$?(?:0x)?([0-9A-Fa-f]+),(X|Y)$', default_op_rep, re.IGNORECASE) # $HHHH,X or $HHHH,Y
                    absolute_match_plain = re.match(r'\$?(?:0x)?([0-9A-Fa-f]+)$', default_op_rep, re.IGNORECASE)   # $HHHH
                    addr_hex, norm_addr = None, None # Extracted hex string and normalized version

                    if indirect_match_y:
                        addr_hex = indirect_match_y.group(1); norm_addr = self.normalize_address_from_string(addr_hex)
                        # Try to find a symbol for the zero-page address
                        if norm_addr:
                            if norm_addr in self.address_to_label: symbol_in_fallback = self.address_to_label[norm_addr]
                            elif norm_addr in self.symbol_map: symbol_in_fallback = self.symbol_map[norm_addr]
                            else: # Last resort lookup
                                addr_obj = self.default_space.getAddress(norm_addr)
                                if addr_obj: symbol_in_fallback = self.find_symbol_for_address(addr_obj)
                        sanitized_symbol = self.sanitize_label_name(symbol_in_fallback) if symbol_in_fallback else None
                        # Construct operand string, preferring symbol over hex
                        zp_part = sanitized_symbol if sanitized_symbol else "${}".format(addr_hex)
                        op_str = "({}),y".format(zp_part); op_str_built = True

                    elif indirect_match_x:
                        addr_hex = indirect_match_x.group(1); norm_addr = self.normalize_address_from_string(addr_hex)
                        # Try to find a symbol for the zero-page address
                        if norm_addr:
                            if norm_addr in self.address_to_label: symbol_in_fallback = self.address_to_label[norm_addr]
                            elif norm_addr in self.symbol_map: symbol_in_fallback = self.symbol_map[norm_addr]
                            else: # Last resort lookup
                                 addr_obj = self.default_space.getAddress(norm_addr)
                                 if addr_obj: symbol_in_fallback = self.find_symbol_for_address(addr_obj)
                        sanitized_symbol = self.sanitize_label_name(symbol_in_fallback) if symbol_in_fallback else None
                        # Construct operand string, preferring symbol over hex
                        zp_part = sanitized_symbol if sanitized_symbol else "${}".format(addr_hex)
                        op_str = "({},x)".format(zp_part); op_str_built = True

                    elif absolute_match_xy:
                        addr_hex = absolute_match_xy.group(1); index = "," + absolute_match_xy.group(2).lower()
                        norm_addr = self.normalize_address_from_string(addr_hex)
                        # Try to find symbol using maps first, then fallback lookup
                        if norm_addr:
                            if norm_addr in self.address_to_label: symbol_in_fallback = self.address_to_label[norm_addr]
                            elif norm_addr in self.symbol_map: symbol_in_fallback = self.symbol_map[norm_addr]
                            else: # Last resort lookup
                                addr_obj = self.default_space.getAddress(norm_addr)
                                if addr_obj: symbol_in_fallback = self.find_symbol_for_address(addr_obj)
                        sanitized_symbol = self.sanitize_label_name(symbol_in_fallback) if symbol_in_fallback else None
                        # Construct operand string, preferring symbol over hex
                        addr_part = sanitized_symbol if sanitized_symbol else "${}".format(addr_hex)
                        op_str = "{}{}".format(addr_part, index); op_str_built = True

                    elif absolute_match_plain:
                        addr_hex = absolute_match_plain.group(1); index = ""
                        norm_addr = self.normalize_address_from_string(addr_hex)
                        # Try to find symbol using maps first, then fallback lookup
                        if norm_addr:
                            if norm_addr in self.address_to_label: symbol_in_fallback = self.address_to_label[norm_addr]
                            elif norm_addr in self.symbol_map: symbol_in_fallback = self.symbol_map[norm_addr]
                            else: # Last resort lookup
                                addr_obj = self.default_space.getAddress(norm_addr)
                                if addr_obj: symbol_in_fallback = self.find_symbol_for_address(addr_obj)
                        sanitized_symbol = self.sanitize_label_name(symbol_in_fallback) if symbol_in_fallback else None
                        # Construct operand string, preferring symbol over hex
                        op_str = sanitized_symbol if sanitized_symbol else "${}".format(addr_hex)
                        op_str_built = True

                    # If none of the regex patterns matched or built the string
                    if not op_str_built:
                        # Use Ghidra's default representation, converting hex format
                        op_str = self.convert_to_kick_hex(default_op_rep)
                        # Ensure KickAss style indexing (lowercase)
                        if op_str.endswith(",X"): op_str = op_str[:-2] + ",x"
                        if op_str.endswith(",Y"): op_str = op_str[:-2] + ",y"
                # --- End Fallback Logic ---

                # Final check if operand string is still None (shouldn't happen ideally)
                if op_str is None:
                    print("Warning: Operand {} for instruction at {} could not be processed, using Ghidra default: {}".format(i, norm_addr_str, default_op_rep))
                    op_str = self.convert_to_kick_hex(default_op_rep) # Final fallback

                operand_strings.append(op_str)
            # --- End Operand Loop ---

            # Assemble the full instruction line (mnemonic + operands)
            kick_disasm = mnemonic.ljust(3) + (" " + ", ".join(operand_strings) if operand_strings else "")
        # --- End Non-Accumulator Processing ---

        # --- Format and Write Output Line ---
        instruction_text = "  {}".format(kick_disasm) # Indent instruction

        EOL_COMMENT_COLUMN = self.EOL_COMMENT_COLUMN

        # Prepare Ghidra-generated part of the comment
        bytes_str = " ".join(bytes_list)
        MAX_BYTES_WIDTH = 8 # Fixed width for byte display in comment
        padded_bytes_str = "{:<{}}".format(bytes_str, MAX_BYTES_WIDTH)
        main_comment_content = "[{}:{} {}]".format(norm_addr_str, padded_bytes_str, original_asm_for_comment)

        # Get the user's EOL comment from Ghidra
        eol_comment = self.listing.getComment(CodeUnit.EOL_COMMENT, address)

        # Calculate padding to align the main comment part (the "// [ADDR...]")
        padding1_len = self.COMMENT_COLUMN - len(instruction_text) - 2 # -2 for "//"
        padding1 = " " * max(1, padding1_len)

        # Assemble the first part of the line (instruction + main comment)
        line_so_far = "{}{}// {}".format(instruction_text, padding1, main_comment_content)

        # Handle multi-line EOL comments correctly.
        if not eol_comment:
            # If no user comment, just write the line and return.
            f.write(line_so_far + "\n")
        else:
            # If there is a user comment, split it into lines and sanitize.
            comment_lines = eol_comment.splitlines()
            comment_lines = [line.encode('ascii', 'ignore').decode('ascii') for line in comment_lines]

            # Calculate padding for the first line of the user comment.
            current_len = len(line_so_far)
            if current_len >= (self.EOL_COMMENT_COLUMN - 1):
                padding2 = " "
            else:
                padding2_len = (self.EOL_COMMENT_COLUMN - 1) - current_len
                padding2 = " " * padding2_len

            # Append the first comment line and write the full instruction line.
            line_so_far += "{}{}".format(padding2, comment_lines[0].strip())
            f.write(line_so_far + "\n")

            # If there are more comment lines, write them on subsequent lines, indented.
            if len(comment_lines) > 1:
                # Build a prefix to align the '//' and the text to the correct columns.
                
                # Part 1: Pad to align the '//' to the main comment column.
                # (Column is 1-based, so subtract 1 for string index)
                prefix_part1 = " " * (self.COMMENT_COLUMN - 2) + "//"
                
                # Part 2: Pad from the end of part 1 to align the text to the EOL comment column.
                padding_len = (self.EOL_COMMENT_COLUMN - 1) - len(prefix_part1) + 2
                prefix_part2 = " " * max(1, padding_len)
                
                # Combine to form the full prefix for each subsequent line.
                line_prefix = prefix_part1 + prefix_part2

                for extra_line in comment_lines[1:]:
                    f.write("{}{}\n".format(line_prefix, extra_line.strip()))

        # --- Handle POST Comments (Below the instruction) ---
        post_comment = self.listing.getComment(CodeUnit.POST_COMMENT, address)
        # Write POST comment below if it exists
        write_multi_line_comment("POST:  ", post_comment, f, comment_indent)


    # --- Main Export Orchestration (NEW UNIFIED LOGIC) ---
    def export(self):
        """Main export function with unified block processing."""
        print("Starting Kick Assembler Export...")
        start_time = datetime.datetime.now()

        # --- PROMPT USER FOR PATH AND SAVE PREFERENCE ---
        options_name = "KickAssemblerExport"
        try:
            from java.io import File
    
            # Set initial directory to last used path (or default)
            initial_dir = os.path.expanduser(os.path.join("~", self.OUTPUT_PATH))
            if not os.path.exists(initial_dir):
                initial_dir = os.path.expanduser("~")
            
            # Use askDirectory to select export directory
            selected_dir = askDirectory("Select Export Directory", "Choose:")
            
            if selected_dir is None:
                print("User cancelled the export.")
                return
            
            # Convert selected directory to relative path from home dir
            selected_path = selected_dir.getAbsolutePath()
            home_dir = os.path.expanduser("~")
            
            if selected_path.startswith(home_dir):
                # Make it relative to home directory
                relative_path = os.path.relpath(selected_path, home_dir)
                self.OUTPUT_PATH = relative_path
            else:
                # Use absolute path if outside home directory
                self.OUTPUT_PATH = selected_path
            
            # Save the new path back to Ghidra's preferences for the next session
            state.getTool().getOptions(options_name).setString("LastOutputPath", self.OUTPUT_PATH)
            print("Export path set to: {}".format(self.OUTPUT_PATH))

        except CancelledException:
            print("User cancelled the export.")
            return

        main_file, symbols_file = self.build_output_paths()
        if not main_file or not symbols_file:
            print("ERROR: Could not determine output file paths. Aborting.")
            return

        # Build internal maps needed for processing
        self.build_symbol_map()
        self.build_label_map()
        # Clear label cache before export run
        self.labels_getting_colon_cache = {}

        # Write the symbols file (Now filters based on get_labels_at_address)
        try: self.write_symbols_file(symbols_file)
        except Exception as e: print("ERROR: Unexpected error writing symbols file:"); traceback.print_exc(); return

        # --- Unified Block Processing ---
        print("Writing main assembly file (unified processing)...")
        try:
            # Open main file for writing assembly code
            with open(main_file, 'w') as f:
                self.write_header(f, symbols_file)

                # Process memory blocks (sorted by address)
                try: blocks_list = sorted(self.blocks, key=lambda b: b.getStart())
                except Exception as sort_e: print("Warning: Could not sort blocks..."); blocks_list = self.blocks

                block_count, total_blocks = 0, len(blocks_list)

                # Iterate through each memory block defined by Ghidra
                for block in blocks_list:
                    block_count += 1
                    start_addr, end_addr = block.getStart(), block.getEnd()
                    print("  Processing block {}/{} : {} ({} - {}) - Size: {}".format(
                           block_count, total_blocks, block.getName(), start_addr, end_addr, block.getSize()))

                    # Skip blocks that aren't initialized or are empty
                    if not block.isInitialized() or block.getSize() <= 0:
                        print("    Skipping empty or uninitialized block.")
                        continue

                    # Write block header and origin directive
                    f.write("\n// *** BLOCK START: {} ({} - {}) ***\n".format(block.getName(), start_addr, end_addr))
                    f.write(".pc = ${} \"{}\"\n".format(start_addr.toString().split(':')[-1], block.getName())) # Use .pc for segment/origin

                    current_address = start_addr
                    raw_byte_buffer = []
                    buffer_start_address = None # Tracks the address of the first byte in the current buffer

                    # --- Loop through addresses within the current block ---
                    while current_address is not None and current_address.compareTo(end_addr) <= 0:
                        processed_length = 1 # Default advance length to 1
                        address_processed_by_instruction_or_data = False

                        # --- 1. Check for Labels at current address ---
                        # Use the definitive get_labels_at_address function
                        pending_labels = self.get_labels_at_address(current_address)
                        if pending_labels:
                            # Flush any raw bytes *before* writing the label
                            if self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                raw_byte_buffer = [] ; buffer_start_address = None
                            f.write("\n") # Add blank line before labels for readability
                            # Write flow XREFs before the label definition
                            self.process_xrefs(current_address, f)
                            # Write the labels that get a colon
                            for label in pending_labels:
                                sanitized_label = self.sanitize_label_name(label)
                                if sanitized_label:
                                    f.write("{}:\n".format(sanitized_label))
                                else:
                                    f.write("// Warning: Skipped invalid sanitized label for '{}' at {}\n".format(label, current_address))

                        # --- 1.5. Check for Plate/Pre Comments at current address (for non-instruction addresses) ---
                        # Note: Instructions handle their own plate/pre comments in process_instruction()
                        code_unit_check = self.listing.getCodeUnitAt(current_address)
                        if not isinstance(code_unit_check, Instruction):
                            # Only check for comments if this isn't an instruction (to avoid duplication)
                            plate_comment = self.listing.getComment(CodeUnit.PLATE_COMMENT, current_address)
                            pre_comment = self.listing.getComment(CodeUnit.PRE_COMMENT, current_address)
                            
                            if plate_comment or pre_comment:
                                # Flush raw bytes before writing comments
                                if self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                    raw_byte_buffer = [] ; buffer_start_address = None
                                
                                comment_indent = "  "
                                
                                # Helper function for multi-line comments (reuse from process_instruction)
                                def write_multi_line_comment_local(prefix, comment, file_handle, indent):
                                    if comment:
                                        f.write("\n")  # Blank line before plate comment
                                        lines = comment.splitlines()
                                        for i, line in enumerate(lines):
                                            p = prefix if i == 0 else " " * len(prefix)
                                            safe_line = line.encode('ascii', 'ignore').decode('ascii')
                                            file_handle.write("{}// {}{}\n".format(indent, p, safe_line))
                                
                                write_multi_line_comment_local("", plate_comment, f, comment_indent)
                                write_multi_line_comment_local("", pre_comment, f, comment_indent)

                        # --- 2. Determine what's at the current address ---
                        code_unit = self.listing.getCodeUnitAt(current_address)

                        # --- Handle Instructions ---
                        if isinstance(code_unit, Instruction):
                            # Flush raw bytes before instruction
                            if self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f):
                                 raw_byte_buffer = [] ; buffer_start_address = None
                            # Process and write the instruction
                            self.process_instruction(code_unit, f)
                            processed_length = code_unit.getLength()
                            address_processed_by_instruction_or_data = True

                        # --- Handle Defined Data ---
                        elif isinstance(code_unit, Data):
                            # Defined data is added to the raw byte buffer for unified .byte output
                            data_length = code_unit.getLength()
                            try:
                                data_bytes = code_unit.getBytes()
                                temp_addr = current_address # To track address for buffer start within this data block
                                for byte_value in data_bytes:
                                     # Ensure buffer start address is set
                                     if buffer_start_address is None: buffer_start_address = temp_addr

                                     raw_byte_buffer.append(byte_value & 0xff)

                                     # Flush if buffer hits limit *during* adding data bytes
                                     if len(raw_byte_buffer) >= self.MAX_RAW_BYTES_PER_LINE:
                                          self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                          raw_byte_buffer = []
                                          buffer_start_address = None # Reset buffer start address after flush

                                     # Advance local tracker for next potential buffer start
                                     try: temp_addr = temp_addr.addNoWrap(1)
                                     except AddressOutOfBoundsException: temp_addr = None; break # Stop if address wraps
                                     except Exception: temp_addr = None; break # Stop on other errors

                            except Exception as e:
                                print("Error reading bytes from Data unit at {}: {}".format(current_address, e))
                                # Attempt to flush any bytes gathered before the error
                                self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                raw_byte_buffer = [] ; buffer_start_address = None
                                f.write(" // Error processing Data unit at {}\n".format(current_address))

                            # Set length to advance outer loop past the entire data unit
                            processed_length = data_length
                            address_processed_by_instruction_or_data = True


                        # --- Handle Undefined Byte (Only if not covered by Instruction or Data) ---
                        if not address_processed_by_instruction_or_data:
                             # Treat as raw byte if no code unit handled it
                             try:
                                  byte_value = self.memory.getByte(current_address) & 0xff
                                  # Set buffer start address if needed
                                  if buffer_start_address is None: buffer_start_address = current_address
                                  raw_byte_buffer.append(byte_value)
                                  # Flush if buffer hits limit
                                  if len(raw_byte_buffer) >= self.MAX_RAW_BYTES_PER_LINE:
                                       self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                       raw_byte_buffer = []
                                       buffer_start_address = None
                             except Exception as e:
                                  print("Error reading undefined byte at {}: {}".format(current_address, e))
                                  # Attempt to flush buffer before error
                                  self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                                  raw_byte_buffer = [] ; buffer_start_address = None
                                  f.write(" // Error reading byte at {}\n".format(current_address))
                             # Keep processed_length = 1 for undefined byte handled here

                        # --- 3. Advance Address for Next Iteration ---
                        if processed_length <= 0:
                             print("Warning: Processed length was <= 0 at {}, advancing by 1.".format(current_address))
                             processed_length = 1

                        try:
                             # Use addNoWrap to prevent address space wrapping errors within a block
                             next_address = current_address.addNoWrap(processed_length)
                             # Basic check: ensure forward progress if possible
                             if next_address.compareTo(current_address) < 0:
                                 print("Warning: Address wrap detected or no progress at {}, stopping block.".format(current_address))
                                 current_address = None # Stop processing this block
                             else:
                                 current_address = next_address
                        except AddressOutOfBoundsException:
                             # Expected exception when advancing past end of address space or block boundary
                             current_address = None # Stop processing this block
                        except Exception as addr_e:
                             print("Error advancing address from {}: {}".format(current_address, addr_e))
                             current_address = None # Stop processing this block

                    # --- End of block address loop ---
                    # Flush any remaining raw bytes at the very end of the block
                    self.flush_raw_bytes(raw_byte_buffer, buffer_start_address, f)
                    f.write("// *** BLOCK END: {} ***\n".format(block.getName()))
                    # --- End of loop for single block ---

                # --- End of loop for all blocks ---

        # Handle file closing and potential errors during file writing
        except IOError as e: print("ERROR: Cannot write main assembly file {}: {}".format(main_file, e)); return
        except Exception as e: print("ERROR: Unexpected error writing main assembly file:"); traceback.print_exc(); return

        # Calculate and print execution time
        end_time = datetime.datetime.now()
        print("\nExport Complete.")
        print("  Main disassembly saved to: {}".format(main_file))
        print("  Symbols file saved to: {}".format(symbols_file))
        print("  Total time: {}".format(end_time - start_time))


# ==============================================================================
# Main script execution (when run from Ghidra)
# ==============================================================================
if __name__ == "__main__":
    print("="*60); print(" Kick Assembler Export Script "); print("="*60)
    exporter_instance = None
    try:
        # Check if running in headless mode or GUI mode
        try:
            # state variable is available in GUI mode
            currentProgram = state.getCurrentProgram()
            print("Running in Ghidra GUI mode.")
        except NameError:
            # state variable not defined, try headless arguments
            import sys
            print("Running in potential Headless mode.")
            # Example for headless: ghidra_headless <project_location> <project_name> -process <program_name> -scriptPath <script_dir> -postScript <script_name.py>
            # You might need to retrieve currentProgram differently in headless
            # This is a placeholder, adjust based on Ghidra headless documentation if needed
            # currentProgram = getCurrentProgram() # Function usually available in headless context
            # For safety, check if currentProgram got defined
            if 'currentProgram' not in globals() or not currentProgram:
                 raise NameError("'currentProgram' not available. Ensure script is run correctly in Ghidra (GUI or Headless).")


        if currentProgram:
            exporter_instance = KickAssemblerExporter(currentProgram)
            exporter_instance.export()
        else:
            print("ERROR: Script could not access the current program.")
            try: from javax.swing import JOptionPane; JOptionPane.showMessageDialog(None, "Script could not access the current program.", "Export Error", JOptionPane.ERROR_MESSAGE)
            except ImportError: print("(Swing UI not available for popup message)")
            except Exception as ui_e: print("(Error showing Swing popup: {})".format(ui_e))

    except NameError as ne:
         # Handles cases where Ghidra environment variables (like state or currentProgram) aren't defined
         print("ERROR: Ghidra environment not detected ('{}'). Is this script running inside Ghidra?".format(ne))
         try: from javax.swing import JOptionPane; JOptionPane.showMessageDialog(None, "Ghidra environment not detected ('{}').\nIs the script running inside Ghidra?".format(ne), "Export Error", JOptionPane.ERROR_MESSAGE)
         except ImportError: print("(Swing UI not available for popup message)")
         except Exception as ui_e: print("(Error showing Swing popup: {})".format(ui_e))
    except Exception as e:
         print("\n--- EXPORT FAILED ---"); print("An unexpected error occurred:"); traceback.print_exc(); print("---------------------")
         try: from javax.swing import JOptionPane; error_summary="Export failed: {}\n\nSee console log for details.".format(e); JOptionPane.showMessageDialog(None, error_summary, "Export Error", JOptionPane.ERROR_MESSAGE)
         except ImportError: print("(Swing UI not available for popup message)")
         except Exception as ui_e: print("(Error showing Swing popup: {})".format(ui_e))
    finally:
        print("Script finished.")
