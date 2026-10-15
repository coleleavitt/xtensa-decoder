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

- **DMA Bug Detection**: Built-in analysis to find stores to DMA descriptor 
  offsets without nearby memory barriers - a common source of packet corruption

- **SGMT Format Support**: Automatically parses Qualcomm SGMT firmware headers

## Installation

```bash
pip install xtensa-decoder  # TODO: publish to PyPI
# Or just copy xtensa_decoder.py to your project
```

## Quick Start

```bash
# Analyze firmware for DMA coherency bugs
python xtensa_decoder.py firmware.bin

# Search for stores to a specific DMA offset
python xtensa_decoder.py firmware.bin 844
```

Output:
```
Firmware: firmware.bin
Base address: 0x00409200
Size: 345990 bytes

Barrier instructions:
  memw: 632
  extw: 0
  dsync: 0
  isync: 10
  TOTAL: 642

Stores to offset 844:
  Total: 3
  WITHOUT barrier (BUGS): 1 (33.3%)
  WITH barrier (safe): 2

Bug locations:
  0x004214c0: f26cd3   s32i         a15, a12, 844
```

## Python API

```python
from xtensa_decoder import XtensaDecoder, load_firmware

# Load firmware (handles SGMT header automatically)
data, base_addr = load_firmware("firmware.bin")
decoder = XtensaDecoder(data, base_addr)

# Count barrier instructions
barriers = decoder.get_barrier_count()
print(f"memw: {barriers['memw']}, isync: {barriers['isync']}")

# Find DMA bugs (stores to offset 844 without nearby barriers)
result = decoder.find_dma_bugs(dma_offset=844)
print(f"Bugs: {result['bug_count']}, Safe: {result['safe_count']}")

for insn in result['bugs']:
    print(f"BUG: {insn}")

# Decode single instruction
insn = decoder.decode(0x004214c0)
print(f"{insn.mnemonic} {insn.operands}")
print(f"Is store: {insn.is_store}, Is barrier: {insn.is_barrier}")

# Disassemble a function
insns = decoder.disassemble_function(entry_addr)
for insn in insns:
    print(insn)
```

## Instruction Encoding

Xtensa uses **little-endian** byte order. For RRI8 format (loads/stores):

```
byte0: {t[3:0], op0[3:0]}     # t=dest reg, op0=instruction class
byte1: {r[3:0], s[3:0]}       # r=opcode, s=base reg
byte2: imm8                    # scaled immediate offset
```

Example: `s32i a15, a12, 844` encodes as `[0xf2, 0x6c, 0xd3]`
- byte0=0xf2: t=15, op0=2 (LSAI)
- byte1=0x6c: r=6 (s32i), s=12
- byte2=0xd3: imm8=211 (offset=844)

Memory barriers encode as:
- `memw`:  `[0xc0, 0x20, 0x00]`
- `extw`:  `[0xd0, 0x20, 0x00]`
- `dsync`: `[0x30, 0x20, 0x00]`
- `isync`: `[0x00, 0x20, 0x00]`

## Validation

All encodings validated against LLVM's `llvm-mc`:

```bash
# Verify s32i encoding
echo "s32i a15, a12, 844" | llvm-mc -triple=xtensa --show-encoding
# Output: s32i a15, a12, 844  # encoding: [0xf2,0x6c,0xd3]

# Verify memw decoding
echo "0xc0 0x20 0x00" | llvm-mc -triple=xtensa --disassemble
# Output: memw
```

## Use Case: WiFi Firmware DMA Bugs

This decoder was built to analyze WiFi firmware for missing memory barriers.
On Xtensa cores in WiFi SoCs (QCA4019, etc.), DMA descriptors require
`memw` barriers after writes to ensure coherency with DMA hardware.

Missing barriers cause packet corruption (e.g., TLS `bad_record_mac` errors).

## Source

Instruction encodings derived from LLVM's Xtensa target:
- `llvm/lib/Target/Xtensa/XtensaInstrInfo.td`
- `llvm/lib/Target/Xtensa/XtensaDSPInstrInfo.td`
- `llvm/lib/Target/Xtensa/XtensaInstrFormats.td`

## License

MIT License - see LICENSE file.
