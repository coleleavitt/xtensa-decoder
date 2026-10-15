# Xtensa ISA Decoder

A complete Python implementation of the Tensilica Xtensa instruction set decoder,
built from LLVM TableGen definitions and validated against `llvm-mc`.

## Features

- **Complete ISA coverage**: All base Xtensa instructions including:
  - Core ALU operations (add, sub, and, or, xor, shifts)
  - Load/store instructions (8/16/32-bit, signed/unsigned)
  - Branch instructions (conditional/unconditional, compare-immediate)
  - Call/return with windowed register support (call0/call4/call8/call12, retw)
  - **Memory barrier instructions** (memw, isync, rsync, dsync, extw, esync)
  - MAC16 DSP operations
  - Narrow (16-bit) instruction encoding

- **Analysis-ready**: Instructions are classified by type (ALU, LOAD, STORE, BRANCH,
  SYNC, etc.) for semantic analysis

- **Firmware analysis**: Designed for reverse engineering Xtensa-based firmware
  (WiFi chips, embedded DSPs, etc.)

## Installation

```bash
pip install xtensa-decoder  # TODO: publish to PyPI
# Or just copy xtensa_decoder.py to your project
```

## Usage

```python
from xtensa_decoder import XtensaDecoder, InsnType

# Create decoder
decoder = XtensaDecoder()

# Decode firmware at a base address
firmware_bytes = open("firmware.bin", "rb").read()
base_addr = 0x409200

for insn in decoder.decode_range(firmware_bytes, base_addr, 0, len(firmware_bytes)):
    print(f"0x{insn.addr:08x}: {insn.mnemonic:10} {insn.operands}")
    
    # Find memory barriers
    if insn.itype == InsnType.SYNC:
        print(f"  ^ Memory barrier: {insn.mnemonic}")
```

## Validation

The decoder has been validated against LLVM's `llvm-mc` assembler/disassembler:

```bash
# Test memory barrier encodings
echo "0x00 0x20 0xc0" | llvm-mc -triple=xtensa -mattr=+density --disassemble
# Output: memw

echo "0x00 0x20 0x20" | llvm-mc -triple=xtensa -mattr=+density --disassemble  
# Output: isync
```

All instruction encodings match the authoritative LLVM implementation.

## Source

The instruction encodings are derived from LLVM's Xtensa target:
- `llvm/lib/Target/Xtensa/XtensaInstrInfo.td` - Core instructions
- `llvm/lib/Target/Xtensa/XtensaDSPInstrInfo.td` - DSP/MAC16 instructions
- `llvm/lib/Target/Xtensa/XtensaInstrFormats.td` - Encoding formats

## Use Case: Finding DMA Coherency Bugs

This decoder was built to analyze WiFi firmware for missing memory barriers.
On Xtensa cores used in WiFi SoCs (QCA4019, etc.), DMA descriptors require
`memw` barriers after writes to ensure coherency with DMA hardware.

```python
# Find stores to DMA descriptor fields without barriers
for insn in decoder.decode_range(data, base, 0, len(data)):
    if insn.itype == InsnType.STORE:
        # Check if a memw follows within reasonable distance
        next_insns = list(decoder.decode_range(data, base, 
            insn.addr - base + insn.size, 20))
        has_barrier = any(i.itype == InsnType.SYNC for i in next_insns[:5])
        if not has_barrier:
            print(f"WARNING: Store at 0x{insn.addr:08x} without barrier")
```

## License

MIT License - see LICENSE file.

## Contributing

Issues and pull requests welcome. Please validate against `llvm-mc` when
adding new instruction support.
