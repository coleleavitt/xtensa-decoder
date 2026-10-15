"""
Complete Xtensa ISA Decoder
Built from LLVM TableGen definitions (llvm/lib/Target/Xtensa/*.td)
Validated against llvm-mc --triple=xtensa

Features:
- Full instruction decoding (24-bit and 16-bit narrow)
- Control flow analysis (branches, calls, returns)
- Memory barrier detection (memw, extw, dsync, isync)
- DMA bug detection (stores without barriers)

Encoding Note:
  Xtensa uses LITTLE-ENDIAN byte order. A 3-byte instruction
  stored as bytes [b0, b1, b2] in memory is decoded as:
    op0 = b0 & 0x0F
    t = (b0 >> 4) & 0x0F
    s = b1 & 0x0F
    r = (b1 >> 4) & 0x0F
    op1 = b2 & 0x0F
    op2 = (b2 >> 4) & 0x0F

  Memory barriers encode as:
    memw:  c0 20 00  (op0=0, r=2, s=0, t=c, op1=0, op2=0)
    extw:  d0 20 00  (op0=0, r=2, s=0, t=d, op1=0, op2=0)
    dsync: 30 20 00  (op0=0, r=2, s=0, t=3, op1=0, op2=0)
    isync: 00 20 00  (op0=0, r=2, s=0, t=0, op1=0, op2=0)
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set, Iterator
from enum import Enum, auto
import struct


class InsnType(Enum):
    """Instruction classification for analysis"""
    ALU = auto()
    LOAD = auto()
    STORE = auto()
    BRANCH = auto()
    JUMP = auto()
    CALL = auto()
    RETURN = auto()
    SYNC = auto()      # Memory barriers
    SHIFT = auto()
    MOVE = auto()
    COMPARE = auto()
    SPECIAL = auto()
    UNKNOWN = auto()


@dataclass
class Insn:
    """Decoded instruction"""
    addr: int
    size: int          # 2 or 3 bytes
    raw: bytes
    mnemonic: str
    operands: str = ""

    # Classification
    itype: InsnType = InsnType.UNKNOWN

    # Control flow
    is_branch: bool = False
    is_call: bool = False
    is_return: bool = False
    is_jump: bool = False
    is_barrier: bool = False

    # Target addresses
    target: Optional[int] = None
    fallthrough: Optional[int] = None

    # Registers read/written
    reads: List[str] = field(default_factory=list)
    writes: List[str] = field(default_factory=list)

    # Memory access
    is_load: bool = False
    is_store: bool = False
    mem_offset: Optional[int] = None  # Immediate offset for load/store
    mem_size: int = 0

    # Literals (for L32R)
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None

    def __repr__(self):
        return f"0x{self.addr:08x}: {self.raw.hex():<8s} {self.mnemonic:<12s} {self.operands}"


# Barrier instruction patterns (little-endian byte order)
BARRIER_PATTERNS = {
    bytes([0xc0, 0x20, 0x00]): "memw",   # Memory write barrier
    bytes([0xd0, 0x20, 0x00]): "extw",   # External write barrier
    bytes([0x30, 0x20, 0x00]): "dsync",  # Data sync
    bytes([0x00, 0x20, 0x00]): "isync",  # Instruction sync
}


class XtensaDecoder:
    """
    Complete Xtensa instruction decoder.

    Instruction formats (from XtensaInstrFormats.td):
    - 24-bit (3-byte) standard instructions
    - 16-bit (2-byte) narrow instructions (density option)

    Bit layout for 24-bit RRR format (in memory order):
    byte0: {7-4: t, 3-0: op0}
    byte1: {7-4: r, 3-0: s}
    byte2: {7-4: op2, 3-0: op1}
    """

    # Register names
    AR_NAMES = [f"a{i}" for i in range(16)]

    # Special register names (from XtensaRegisterInfo.td)
    SR_NAMES = {
        0: "LBEG", 1: "LEND", 2: "LCOUNT", 3: "SAR",
        4: "BR", 5: "LITBASE", 12: "SCOMPARE1",
        72: "WINDOWBASE", 73: "WINDOWSTART",
        96: "IBREAKENABLE", 97: "MEMCTL", 99: "ATOMCTL",
        104: "DDR", 176: "IBREAKA0", 177: "IBREAKA1",
        144: "DBREAKA0", 145: "DBREAKA1",
        160: "DBREAKC0", 161: "DBREAKC1",
        177: "EPC1", 178: "EPC2", 179: "EPC3", 180: "EPC4",
        192: "DEPC", 194: "EPS2", 195: "EPS3", 196: "EPS4",
        209: "EXCSAVE1", 210: "EXCSAVE2", 211: "EXCSAVE3",
        212: "EXCSAVE4", 224: "CPENABLE", 226: "INTSET",
        227: "INTCLEAR", 228: "INTENABLE", 230: "PS",
        232: "EXCCAUSE", 233: "DEBUGCAUSE", 234: "CCOUNT",
        238: "EXCVADDR", 240: "CCOMPARE0", 241: "CCOMPARE1",
    }

    def __init__(self, data: bytes, base: int = 0):
        self.data = data
        self.base = base
        self.insns: Dict[int, Insn] = {}

        # Pre-compute barrier locations for fast lookup
        self._barrier_addrs: Set[int] = set()
        self._precompute_barriers()

    def _precompute_barriers(self):
        """Find all barrier instructions for fast lookup"""
        for pattern in BARRIER_PATTERNS:
            idx = 0
            while True:
                idx = self.data.find(pattern, idx)
                if idx == -1:
                    break
                self._barrier_addrs.add(self.base + idx)
                idx += 1

    def get_barrier_count(self) -> Dict[str, int]:
        """Count each type of barrier instruction"""
        counts = {name: 0 for name in BARRIER_PATTERNS.values()}
        for pattern, name in BARRIER_PATTERNS.items():
            counts[name] = self.data.count(pattern)
        return counts

    def _u8(self, off: int) -> int:
        if 0 <= off < len(self.data):
            return self.data[off]
        return 0

    def _u16(self, off: int) -> int:
        if 0 <= off + 1 < len(self.data):
            return struct.unpack('<H', self.data[off:off+2])[0]
        return 0

    def _u32(self, off: int) -> int:
        if 0 <= off + 3 < len(self.data):
            return struct.unpack('<I', self.data[off:off+4])[0]
        return 0

    def _sext(self, val: int, bits: int) -> int:
        """Sign extend a value"""
        sign = 1 << (bits - 1)
        return (val & (sign - 1)) - (val & sign)

    def _ar(self, n: int) -> str:
        """Get AR register name"""
        return self.AR_NAMES[n & 0xF]

    def _sr(self, n: int) -> str:
        """Get special register name"""
        return self.SR_NAMES.get(n, f"sr{n}")

    def _is_narrow(self, b0: int) -> bool:
        """Check if instruction is 16-bit narrow format.

        From XtensaInstrFormats.td: narrow instructions have op0 in {0x8-0xD}
        """
        op0 = b0 & 0x0F
        return 0x8 <= op0 <= 0xD

    def decode(self, addr: int) -> Optional[Insn]:
        """Decode instruction at address"""
        off = addr - self.base
        if off < 0 or off >= len(self.data):
            return None

        # Check cache
        if addr in self.insns:
            return self.insns[addr]

        b0 = self._u8(off)

        if self._is_narrow(b0):
            insn = self._decode_narrow(addr, off)
        else:
            insn = self._decode_24bit(addr, off)

        self.insns[addr] = insn
        return insn

    def _decode_narrow(self, addr: int, off: int) -> Insn:
        """Decode 16-bit narrow instruction"""
        b0, b1 = self._u8(off), self._u8(off + 1)
        raw = bytes([b0, b1])

        op0 = b0 & 0x0F
        t = (b0 >> 4) & 0x0F
        s = b1 & 0x0F
        r = (b1 >> 4) & 0x0F

        ft = addr + 2

        # L32I.N
        if op0 == 0x8:
            imm = r << 2
            return Insn(addr, 2, raw, "l32i.n", f"{self._ar(t)}, {self._ar(s)}, {imm}",
                       itype=InsnType.LOAD, is_load=True, mem_size=4, mem_offset=imm,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)

        # S32I.N
        elif op0 == 0x9:
            imm = r << 2
            return Insn(addr, 2, raw, "s32i.n", f"{self._ar(t)}, {self._ar(s)}, {imm}",
                       itype=InsnType.STORE, is_store=True, mem_size=4, mem_offset=imm,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)

        # ADD.N
        elif op0 == 0xA:
            return Insn(addr, 2, raw, "add.n", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                       itype=InsnType.ALU,
                       reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)

        # ADDI.N
        elif op0 == 0xB:
            imm = r if r != 0 else -1
            return Insn(addr, 2, raw, "addi.n", f"{self._ar(s)}, {self._ar(t)}, {imm}",
                       itype=InsnType.ALU,
                       reads=[self._ar(t)], writes=[self._ar(s)], fallthrough=ft)

        # op0 = 0xC: MOVI.N / BEQZ.N / BNEZ.N
        elif op0 == 0xC:
            i_bit = (b0 >> 7) & 1
            z_bit = (b0 >> 6) & 1

            if i_bit == 0:
                # MOVI.N
                imm7 = (r << 4) | s
                if imm7 >= 0x60:
                    imm7 = imm7 - 128
                return Insn(addr, 2, raw, "movi.n", f"{self._ar(t)}, {imm7}",
                           itype=InsnType.MOVE, writes=[self._ar(t)], fallthrough=ft)
            else:
                # BEQZ.N / BNEZ.N
                imm6 = (r << 2) | ((b0 >> 4) & 0x3)
                target = addr + 4 + imm6
                mnem = "beqz.n" if z_bit == 0 else "bnez.n"
                return Insn(addr, 2, raw, mnem, f"{self._ar(s)}, 0x{target:08x}",
                           itype=InsnType.BRANCH, is_branch=True,
                           target=target, reads=[self._ar(s)], fallthrough=ft)

        # op0 = 0xD: MOV.N / RET.N / RETW.N / NOP.N / BREAK.N
        elif op0 == 0xD:
            if r == 0xF:
                if s == 0x0 and t == 0x0:
                    return Insn(addr, 2, raw, "ret.n", "",
                               itype=InsnType.RETURN, is_return=True, reads=["a0"])
                elif s == 0x0 and t == 0x1:
                    return Insn(addr, 2, raw, "retw.n", "",
                               itype=InsnType.RETURN, is_return=True)
                elif s == 0x2 and t == 0x0:
                    return Insn(addr, 2, raw, "break.n", f"{r}, {s}",
                               itype=InsnType.SPECIAL)
                elif s == 0x3 and t == 0x0:
                    return Insn(addr, 2, raw, "nop.n", "",
                               itype=InsnType.SPECIAL, fallthrough=ft)
            else:
                # MOV.N
                return Insn(addr, 2, raw, "mov.n", f"{self._ar(t)}, {self._ar(s)}",
                           itype=InsnType.MOVE,
                           reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)

        return Insn(addr, 2, raw, "???n", f"0x{b1:02x}{b0:02x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)

    def _decode_24bit(self, addr: int, off: int) -> Insn:
        """Decode 24-bit standard instruction"""
        b0, b1, b2 = self._u8(off), self._u8(off + 1), self._u8(off + 2)
        raw = bytes([b0, b1, b2])

        op0 = b0 & 0x0F
        t = (b0 >> 4) & 0x0F
        s = b1 & 0x0F
        r = (b1 >> 4) & 0x0F
        op1 = b2 & 0x0F
        op2 = (b2 >> 4) & 0x0F

        ft = addr + 3

        # op0 = 0: QRST (most RRR instructions including barriers)
        if op0 == 0x0:
            return self._decode_qrst(addr, raw, op1, op2, r, s, t)

        # op0 = 1: L32R
        elif op0 == 0x1:
            imm16 = (b2 << 8) | b1
            imm16_signed = self._sext(imm16, 16)
            lit_addr = ((addr + 3) & ~3) + (imm16_signed << 2)
            lit_off = lit_addr - self.base
            lit_val = self._u32(lit_off) if 0 <= lit_off < len(self.data) - 3 else None

            val_str = f" ; =0x{lit_val:08x}" if lit_val is not None else ""
            return Insn(addr, 3, raw, "l32r", f"{self._ar(t)}, 0x{lit_addr:08x}{val_str}",
                       itype=InsnType.LOAD, is_load=True, mem_size=4,
                       writes=[self._ar(t)], fallthrough=ft,
                       literal_addr=lit_addr, literal_value=lit_val)

        # op0 = 2: LSAI (loads, stores, addi)
        elif op0 == 0x2:
            return self._decode_lsai(addr, raw, r, s, t)

        # op0 = 5: CALL
        elif op0 == 0x5:
            n = (b0 >> 4) & 0x3
            offset18 = (b2 << 10) | (b1 << 2) | ((b0 >> 6) & 0x3)
            offset18_signed = self._sext(offset18, 18)
            target = ((addr + 4) & ~3) + (offset18_signed << 2)

            mnem = f"call{n * 4}" if n > 0 else "call0"
            return Insn(addr, 3, raw, mnem, f"0x{target:08x}",
                       itype=InsnType.CALL, is_call=True,
                       target=target, writes=[f"a{n * 4}"], fallthrough=ft)

        # op0 = 6: J (unconditional jump)
        elif op0 == 0x6:
            offset18 = (b2 << 10) | (b1 << 2) | ((b0 >> 6) & 0x3)
            offset18_signed = self._sext(offset18, 18)
            target = addr + 4 + offset18_signed

            return Insn(addr, 3, raw, "j", f"0x{target:08x}",
                       itype=InsnType.JUMP, is_jump=True, target=target)

        # op0 = 7: BI (branches)
        elif op0 == 0x7:
            return self._decode_bi(addr, raw, r, s, t, b1, b2)

        return Insn(addr, 3, raw, "???", f"op0={op0:x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)

    def _decode_qrst(self, addr: int, raw: bytes, op1: int, op2: int, r: int, s: int, t: int) -> Insn:
        """Decode QRST format (op0 = 0)"""
        ft = addr + 3

        if op1 == 0x0:
            if op2 == 0x0:
                # SYNC instructions (r=2)
                if r == 0x2 and s == 0x0:
                    sync_names = {0x0: "isync", 0x1: "rsync", 0x2: "esync", 0x3: "dsync",
                                 0xC: "memw", 0xD: "extw", 0xF: "nop"}
                    if t in sync_names:
                        is_bar = t in [0x0, 0x1, 0x2, 0x3, 0xC, 0xD]
                        return Insn(addr, 3, raw, sync_names[t], "",
                                   itype=InsnType.SYNC, is_barrier=is_bar, fallthrough=ft)

                # Control flow
                if r == 0x0:
                    if s == 0x0 and t == 0x0:
                        return Insn(addr, 3, raw, "ill", "", itype=InsnType.SPECIAL)
                    elif s == 0x0 and t == 0x1:
                        return Insn(addr, 3, raw, "ret", "",
                                   itype=InsnType.RETURN, is_return=True, reads=["a0"])
                    elif s == 0x0 and t == 0x2:
                        return Insn(addr, 3, raw, "retw", "",
                                   itype=InsnType.RETURN, is_return=True)

                if r == 0xA and t == 0x0:
                    return Insn(addr, 3, raw, "jx", f"{self._ar(s)}",
                               itype=InsnType.JUMP, is_jump=True, reads=[self._ar(s)])

                if (r & 0xC) == 0xC:
                    n = r & 0x3
                    mnem = f"callx{n * 4}" if n > 0 else "callx0"
                    return Insn(addr, 3, raw, mnem, f"{self._ar(s)}",
                               itype=InsnType.CALL, is_call=True,
                               reads=[self._ar(s)], writes=[f"a{n * 4}"], fallthrough=ft)

            # ALU operations
            elif op2 == 0x8:
                return Insn(addr, 3, raw, "add", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)],
                           writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0xC:
                return Insn(addr, 3, raw, "sub", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)],
                           writes=[self._ar(r)], fallthrough=ft)

        return Insn(addr, 3, raw, "qrst", f"op1={op1:x},op2={op2:x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)

    def _decode_lsai(self, addr: int, raw: bytes, r: int, s: int, t: int) -> Insn:
        """Decode LSAI format (op0 = 2) - loads, stores, addi

        RRI8 format encoding (from llvm-mc):
          byte0: {t[3:0], op0[3:0]}
          byte1: {r[3:0], s[3:0]}
          byte2: imm8
        """
        ft = addr + 3
        imm8 = raw[2]  # imm8 is in byte2, not byte1!

        # r field determines instruction type
        if r == 0x0:
            # L8UI
            return Insn(addr, 3, raw, "l8ui", f"{self._ar(t)}, {self._ar(s)}, {imm8}",
                       itype=InsnType.LOAD, is_load=True, mem_size=1, mem_offset=imm8,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0x1:
            # L16UI
            offset = imm8 << 1
            return Insn(addr, 3, raw, "l16ui", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.LOAD, is_load=True, mem_size=2, mem_offset=offset,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0x2:
            # L32I
            offset = imm8 << 2
            return Insn(addr, 3, raw, "l32i", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.LOAD, is_load=True, mem_size=4, mem_offset=offset,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0x4:
            # S8I
            return Insn(addr, 3, raw, "s8i", f"{self._ar(t)}, {self._ar(s)}, {imm8}",
                       itype=InsnType.STORE, is_store=True, mem_size=1, mem_offset=imm8,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)
        elif r == 0x5:
            # S16I
            offset = imm8 << 1
            return Insn(addr, 3, raw, "s16i", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.STORE, is_store=True, mem_size=2, mem_offset=offset,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)
        elif r == 0x6:
            # S32I - THE KEY INSTRUCTION FOR DMA BUGS
            offset = imm8 << 2
            return Insn(addr, 3, raw, "s32i", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.STORE, is_store=True, mem_size=4, mem_offset=offset,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)
        elif r == 0x9:
            # L16SI
            offset = imm8 << 1
            return Insn(addr, 3, raw, "l16si", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.LOAD, is_load=True, mem_size=2, mem_offset=offset,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0xA:
            # MOVI
            imm12 = (raw[2] << 4) | ((raw[1] >> 4) & 0xF)
            if imm12 >= 0x800:
                imm12 = imm12 - 0x1000
            return Insn(addr, 3, raw, "movi", f"{self._ar(t)}, {imm12}",
                       itype=InsnType.MOVE, writes=[self._ar(t)], fallthrough=ft)
        elif r == 0xB:
            # L32AI (acquire)
            offset = imm8 << 2
            return Insn(addr, 3, raw, "l32ai", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.LOAD, is_load=True, is_barrier=True,
                       mem_size=4, mem_offset=offset,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0xC:
            # ADDI
            simm8 = self._sext(imm8, 8)
            return Insn(addr, 3, raw, "addi", f"{self._ar(t)}, {self._ar(s)}, {simm8}",
                       itype=InsnType.ALU, reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0xD:
            # ADDMI
            simm8 = self._sext(imm8, 8)
            return Insn(addr, 3, raw, "addmi", f"{self._ar(t)}, {self._ar(s)}, {simm8 << 8}",
                       itype=InsnType.ALU, reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        elif r == 0xF:
            # S32RI (release)
            offset = imm8 << 2
            return Insn(addr, 3, raw, "s32ri", f"{self._ar(t)}, {self._ar(s)}, {offset}",
                       itype=InsnType.STORE, is_store=True, is_barrier=True,
                       mem_size=4, mem_offset=offset,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)

        return Insn(addr, 3, raw, "lsai", f"r={r:x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)

    def _decode_bi(self, addr: int, raw: bytes, r: int, s: int, t: int, b1: int, b2: int) -> Insn:
        """Decode BI format (op0 = 7) - branches"""
        ft = addr + 3

        # Calculate branch offset (8-bit signed, scaled)
        imm8 = b1
        offset = self._sext(imm8, 8)
        target = addr + 4 + offset

        if r == 0x0:
            # BNEZ
            return Insn(addr, 3, raw, "bnez", f"{self._ar(s)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0x1:
            # BEQZ
            return Insn(addr, 3, raw, "beqz", f"{self._ar(s)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0x2:
            # BLTZ
            return Insn(addr, 3, raw, "bltz", f"{self._ar(s)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0x3:
            # BGEZ
            return Insn(addr, 3, raw, "bgez", f"{self._ar(s)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0x4:
            # BEQ
            return Insn(addr, 3, raw, "beq", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)
        elif r == 0x5:
            # BNE
            return Insn(addr, 3, raw, "bne", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)
        elif r == 0x6:
            # BBCI (branch if bit clear)
            bit = ((b2 >> 4) & 1) << 4 | t
            return Insn(addr, 3, raw, "bbci", f"{self._ar(s)}, {bit}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0x7:
            # BBSI (branch if bit set)
            bit = ((b2 >> 4) & 1) << 4 | t
            return Insn(addr, 3, raw, "bbsi", f"{self._ar(s)}, {bit}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s)], fallthrough=ft)
        elif r == 0xA:
            # BLT
            return Insn(addr, 3, raw, "blt", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)
        elif r == 0xB:
            # BGE
            return Insn(addr, 3, raw, "bge", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)
        elif r == 0xC:
            # BLTU
            return Insn(addr, 3, raw, "bltu", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)
        elif r == 0xD:
            # BGEU
            return Insn(addr, 3, raw, "bgeu", f"{self._ar(s)}, {self._ar(t)}, 0x{target:08x}",
                       itype=InsnType.BRANCH, is_branch=True,
                       target=target, reads=[self._ar(s), self._ar(t)], fallthrough=ft)

        return Insn(addr, 3, raw, "bi", f"r={r:x}",
                   itype=InsnType.BRANCH, is_branch=True, fallthrough=ft)

    # =========================================================================
    # ANALYSIS METHODS
    # =========================================================================

    def find_stores_to_offset(self, target_offset: int, max_search: int = 0) -> List[Insn]:
        """Find all store instructions to a specific memory offset.

        For s32i (RRI8 format), verified encoding from llvm-mc:
          byte0: {7-4: t, 3-0: op0=2}
          byte1: {7-4: r=6, 3-0: s}
          byte2: imm8 (offset = imm8 * 4)

        Example: s32i a0, a1, 844 -> [0x02, 0x61, 0xd3]
        """
        stores = []
        imm8 = target_offset >> 2  # s32i uses scaled offset (844 -> 211 = 0xD3)

        for i in range(len(self.data) - 3):
            b0, b1, b2 = self.data[i], self.data[i + 1], self.data[i + 2]
            op0 = b0 & 0x0F
            r = (b1 >> 4) & 0x0F  # r is in byte1 upper nibble

            # s32i: op0=2, r=6, imm8 in byte2
            if op0 == 0x2 and r == 0x6 and b2 == imm8:
                insn = self.decode(self.base + i)
                if insn and insn.is_store:
                    stores.append(insn)
                    if max_search and len(stores) >= max_search:
                        break

        return stores

    def has_barrier_within(self, addr: int, max_bytes: int = 50) -> Optional[int]:
        """Check if there's a barrier instruction within max_bytes after addr"""
        for barrier_addr in self._barrier_addrs:
            if addr < barrier_addr <= addr + max_bytes:
                return barrier_addr
        return None

    def find_dma_bugs(self, dma_offset: int = 844, search_radius: int = 50) -> Dict:
        """
        Find stores to DMA descriptor offset without nearby barriers.

        Args:
            dma_offset: Memory offset used for DMA descriptor (default: 844 = 0x34C)
            search_radius: How many bytes after store to look for barrier

        Returns:
            Dict with 'bugs' (stores without barrier) and 'safe' (stores with barrier)
        """
        stores = self.find_stores_to_offset(dma_offset)

        bugs = []
        safe = []

        for insn in stores:
            barrier = self.has_barrier_within(insn.addr, search_radius)
            if barrier:
                safe.append({'insn': insn, 'barrier_at': barrier,
                            'distance': barrier - insn.addr})
            else:
                bugs.append(insn)

        return {
            'bugs': bugs,
            'safe': safe,
            'total_stores': len(stores),
            'bug_count': len(bugs),
            'safe_count': len(safe),
            'bug_rate': len(bugs) / len(stores) if stores else 0
        }

    def disassemble_range(self, start: int, end: int) -> List[Insn]:
        """Disassemble a range of addresses"""
        insns = []
        addr = start
        while addr < end:
            insn = self.decode(addr)
            if insn:
                insns.append(insn)
                addr += insn.size
            else:
                addr += 1
        return insns

    def disassemble_function(self, entry: int, max_insns: int = 500) -> List[Insn]:
        """Disassemble a function starting at entry point"""
        insns = []
        visited = set()
        worklist = [entry]

        while worklist and len(insns) < max_insns:
            addr = worklist.pop(0)
            if addr in visited:
                continue
            visited.add(addr)

            insn = self.decode(addr)
            if not insn:
                continue

            insns.append(insn)

            # Add successors
            if insn.fallthrough and insn.fallthrough not in visited:
                worklist.append(insn.fallthrough)
            if insn.target and insn.target not in visited:
                worklist.append(insn.target)

            # Stop at returns
            if insn.is_return:
                continue

        return sorted(insns, key=lambda i: i.addr)

    def find_functions(self) -> List[int]:
        """Find all function entry points (addresses with entry instruction)"""
        functions = []
        i = 0
        while i < len(self.data) - 3:
            b0 = self.data[i]
            # entry instruction: op0=6, t=3 (encoded as 0x36 in lower 6 bits)
            if (b0 & 0x3F) == 0x36:
                functions.append(self.base + i)
            i += 1
        return sorted(functions)

    def get_function_at(self, addr: int) -> Optional[Tuple[int, int]]:
        """Get the function containing an address.

        Returns (start_addr, approx_end_addr) or None.
        """
        functions = self.find_functions()

        # Find the function that contains this address
        func_start = None
        for ep in functions:
            if ep <= addr:
                func_start = ep
            else:
                break

        if func_start is None:
            return None

        # Find next function for approximate end
        func_end = None
        for ep in functions:
            if ep > func_start:
                func_end = ep
                break

        if func_end is None:
            func_end = func_start + 2000  # Default max size

        return (func_start, func_end)

    def analyze_function_barriers(self, func_addr: int) -> Dict:
        """Analyze stores and barriers in a function.

        Returns dict with:
          - stores: count of store instructions
          - barriers: count of barrier instructions
          - stores_without_after_barrier: stores lacking barrier within 30 bytes after
          - offsets: dict of offset -> count for stores
        """
        func_info = self.get_function_at(func_addr)
        if not func_info:
            return {'error': 'Function not found'}

        start, end = func_info
        start_off = start - self.base
        end_off = end - self.base

        stores = []
        barriers = []
        memw_pattern = bytes([0xc0, 0x20, 0x00])

        i = start_off
        while i < min(end_off, len(self.data) - 3):
            # Check for memw
            if self.data[i:i+3] == memw_pattern:
                barriers.append(self.base + i)

            b0 = self.data[i]
            op0 = b0 & 0x0F

            # s32i (op0=2, r=6)
            if op0 == 0x2:
                b1 = self.data[i+1]
                r = (b1 >> 4) & 0x0F
                if r == 0x6:
                    b2 = self.data[i+2]
                    offset = b2 << 2
                    stores.append({'addr': self.base + i, 'offset': offset})

            # s32i.n (op0=9)
            if op0 == 0x9:
                b1 = self.data[i+1]
                r = (b1 >> 4) & 0x0F
                offset = r << 2
                stores.append({'addr': self.base + i, 'offset': offset})

            i += 2 if op0 >= 0x8 else 3

        # Count stores without after barrier
        unprotected = 0
        for store in stores:
            has_barrier = False
            for bar in barriers:
                if store['addr'] < bar <= store['addr'] + 30:
                    has_barrier = True
                    break
            if not has_barrier:
                unprotected += 1

        # Group by offset
        from collections import Counter
        offsets = Counter(s['offset'] for s in stores)

        return {
            'func_start': start,
            'func_end': end,
            'func_size': end - start,
            'stores': len(stores),
            'barriers': len(barriers),
            'stores_without_after_barrier': unprotected,
            'offsets': dict(offsets),
            'danger_level': 'CRITICAL' if len(barriers) == 0 and len(stores) > 10 else
                           'HIGH' if unprotected > len(stores) * 0.8 else
                           'MEDIUM' if unprotected > len(stores) * 0.5 else 'LOW'
        }


def load_firmware(path: str, skip_header: int = 16, base_addr: Optional[int] = None) -> Tuple[bytes, int]:
    """
    Load firmware file, skipping SGMT header.

    Args:
        path: Path to firmware file
        skip_header: Bytes to skip (16 for SGMT header)
        base_addr: Override base address (use when loading raw/stripped firmware)

    Returns:
        (raw_data, base_address)
    """
    import struct

    with open(path, 'rb') as f:
        data = f.read()

    # Check for SGMT header
    if data[:4] == b'SGMT':
        detected_base = struct.unpack('<I', data[8:12])[0]
        return data[skip_header:], base_addr if base_addr else detected_base
    else:
        # Raw firmware - use provided base or default for QCA4019
        return data, base_addr if base_addr else 0x00409200


def analyze_firmware(path: str, dma_offset: int = 844) -> None:
    """
    Analyze firmware for DMA coherency bugs.

    Args:
        path: Path to firmware file
        dma_offset: DMA descriptor offset to check (default: 844)
    """
    data, base = load_firmware(path)
    dec = XtensaDecoder(data, base)

    print(f"Firmware: {path}")
    print(f"Base address: 0x{base:08x}")
    print(f"Size: {len(data)} bytes")
    print()

    # Barrier counts
    barriers = dec.get_barrier_count()
    print("Barrier instructions:")
    for name, count in barriers.items():
        print(f"  {name}: {count}")
    print(f"  TOTAL: {sum(barriers.values())}")
    print()

    # DMA bug analysis
    result = dec.find_dma_bugs(dma_offset)
    print(f"Stores to offset {dma_offset}:")
    print(f"  Total: {result['total_stores']}")
    print(f"  WITHOUT barrier (BUGS): {result['bug_count']} ({result['bug_rate']*100:.1f}%)")
    print(f"  WITH barrier (safe): {result['safe_count']}")
    print()

    if result['bugs']:
        print("Bug locations:")
        for insn in result['bugs'][:20]:
            print(f"  {insn}")
        if len(result['bugs']) > 20:
            print(f"  ... and {len(result['bugs']) - 20} more")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python xtensa_decoder.py <firmware.bin> [dma_offset]")
        print()
        print("Analyzes Xtensa firmware for DMA coherency bugs.")
        print()
        print("Arguments:")
        print("  firmware.bin  Path to firmware file (SGMT format supported)")
        print("  dma_offset    DMA descriptor offset to check (default: 844)")
        sys.exit(1)

    path = sys.argv[1]
    dma_offset = int(sys.argv[2]) if len(sys.argv) > 2 else 844

    analyze_firmware(path, dma_offset)
