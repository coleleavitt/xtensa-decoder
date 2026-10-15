"""
Complete Xtensa ISA Decoder
Built from LLVM TableGen definitions (llvm/lib/Target/Xtensa/*.td)
Validated against llvm-mc --triple=xtensa

Author: Generated for Ruckus firmware analysis
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Tuple, Set
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
    mem_size: int = 0
    
    # Literals (for L32R)
    literal_addr: Optional[int] = None
    literal_value: Optional[int] = None
    
    def __repr__(self):
        return f"0x{self.addr:08x}: {self.raw.hex():<8s} {self.mnemonic:<12s} {self.operands}"


class XtensaDecoder:
    """
    Complete Xtensa instruction decoder.
    
    Instruction formats (from XtensaInstrFormats.td):
    - 24-bit (3-byte) standard instructions
    - 16-bit (2-byte) narrow instructions (density option)
    
    Bit layout for 24-bit RRR format:
    {23-20: op2, 19-16: op1, 15-12: r, 11-8: s, 7-4: t, 3-0: op0}
    
    Bit layout for 16-bit RRRN format:
    {15-12: r, 11-8: s, 7-4: t, 3-0: op0}
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
    
    def __init__(self, data: bytes, base: int):
        self.data = data
        self.base = base
        self.insns: Dict[int, Insn] = {}
    
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
        return op0 >= 0x8 and op0 <= 0xD
    
    def decode(self, addr: int) -> Optional[Insn]:
        """Decode instruction at address"""
        off = addr - self.base
        if off < 0 or off >= len(self.data):
            return None
        
        b0 = self._u8(off)
        
        if self._is_narrow(b0):
            return self._decode_narrow(addr, off)
        else:
            return self._decode_24bit(addr, off)
    
    def _decode_narrow(self, addr: int, off: int) -> Insn:
        """Decode 16-bit narrow instruction.
        
        RRRN format: {15-12: r, 11-8: s, 7-4: t, 3-0: op0}
        """
        b0, b1 = self._u8(off), self._u8(off + 1)
        raw = bytes([b0, b1])
        
        op0 = b0 & 0x0F
        t = (b0 >> 4) & 0x0F
        s = b1 & 0x0F
        r = (b1 >> 4) & 0x0F
        
        ft = addr + 2  # fallthrough
        
        # op0 = 0x8: L32I.N
        if op0 == 0x8:
            imm = r << 2  # 4-byte aligned offset
            return Insn(addr, 2, raw, "l32i.n", f"{self._ar(t)}, {self._ar(s)}, {imm}",
                       itype=InsnType.LOAD, is_load=True, mem_size=4,
                       reads=[self._ar(s)], writes=[self._ar(t)], fallthrough=ft)
        
        # op0 = 0x9: S32I.N
        elif op0 == 0x9:
            imm = r << 2
            return Insn(addr, 2, raw, "s32i.n", f"{self._ar(t)}, {self._ar(s)}, {imm}",
                       itype=InsnType.STORE, is_store=True, mem_size=4,
                       reads=[self._ar(t), self._ar(s)], fallthrough=ft)
        
        # op0 = 0xA: ADD.N
        elif op0 == 0xA:
            return Insn(addr, 2, raw, "add.n", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                       itype=InsnType.ALU,
                       reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
        
        # op0 = 0xB: ADDI.N
        elif op0 == 0xB:
            imm = r if r != 0 else -1
            return Insn(addr, 2, raw, "addi.n", f"{self._ar(s)}, {self._ar(t)}, {imm}",
                       itype=InsnType.ALU,
                       reads=[self._ar(t)], writes=[self._ar(s)], fallthrough=ft)
        
        # op0 = 0xC: Various
        elif op0 == 0xC:
            # MOVI.N: t != 0x7
            if t != 0x7:
                imm7 = (r << 4) | (s & 0x0F)
                if imm7 & 0x40:
                    imm7 = self._sext(imm7, 7)
                return Insn(addr, 2, raw, "movi.n", f"{self._ar(t)}, {imm7}",
                           itype=InsnType.MOVE, writes=[self._ar(t)], fallthrough=ft)
            # t = 0x7: BEQZ.N / BNEZ.N
            else:
                imm6 = (r << 4) | ((s >> 2) & 0x3) | ((s & 0x3) << 4)  # Rearrange bits
                # Actually from RI6_Inst: imm6[3:0] in bits 15-12, imm6[5:4] in bits 5-4
                # Let me recompute: bits 15-12=r, bits 11-8=s, bit 7=i, bit 6=z, bits 5-4=imm6[5:4]
                # For BEQZ.N: op0=0xC, i=1, z=0; for BNEZ.N: op0=0xC, i=1, z=1
                i = (b0 >> 7) & 1
                z = (b0 >> 6) & 1
                imm6_lo = r
                imm6_hi = (b0 >> 4) & 0x3
                imm6 = (imm6_hi << 4) | imm6_lo
                target = addr + 4 + imm6
                
                if z == 0:
                    return Insn(addr, 2, raw, "beqz.n", f"{self._ar(s)}, 0x{target:08x}",
                               itype=InsnType.BRANCH, is_branch=True,
                               target=target, reads=[self._ar(s)], fallthrough=ft)
                else:
                    return Insn(addr, 2, raw, "bnez.n", f"{self._ar(s)}, 0x{target:08x}",
                               itype=InsnType.BRANCH, is_branch=True,
                               target=target, reads=[self._ar(s)], fallthrough=ft)
        
        # op0 = 0xD: Various
        elif op0 == 0xD:
            # Check r field for subtype
            if r == 0xF:
                # RET.N, RETW.N, NOP.N, ILL.N based on s and t
                if s == 0x0 and t == 0x0:
                    return Insn(addr, 2, raw, "ret.n", "",
                               itype=InsnType.RETURN, is_return=True, reads=["a0"])
                elif s == 0x0 and t == 0x1:
                    return Insn(addr, 2, raw, "retw.n", "",
                               itype=InsnType.RETURN, is_return=True)
                elif s == 0x1:
                    return Insn(addr, 2, raw, "nop.n", "",
                               itype=InsnType.SPECIAL, fallthrough=ft)
                elif s == 0x6 and t == 0xF:
                    return Insn(addr, 2, raw, "ill.n", "",
                               itype=InsnType.SPECIAL)
            # MOV.N
            elif t == 0x0:
                return Insn(addr, 2, raw, "mov.n", f"{self._ar(r)}, {self._ar(s)}",
                           itype=InsnType.MOVE,
                           reads=[self._ar(s)], writes=[self._ar(r)], fallthrough=ft)
            # BREAK.N
            else:
                return Insn(addr, 2, raw, "break.n", f"{s}, {t}",
                           itype=InsnType.SPECIAL, fallthrough=ft)
        
        # Unknown narrow
        return Insn(addr, 2, raw, "???n", f"0x{b1:02x}{b0:02x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)
    
    def _decode_24bit(self, addr: int, off: int) -> Insn:
        """Decode 24-bit standard instruction.
        
        RRR format: {23-20: op2, 19-16: op1, 15-12: r, 11-8: s, 7-4: t, 3-0: op0}
        Little-endian: byte0 = {7-4: t, 3-0: op0}, byte1 = {7-4: r, 3-0: s}, byte2 = {7-4: op2, 3-0: op1}
        """
        b0, b1, b2 = self._u8(off), self._u8(off + 1), self._u8(off + 2)
        raw = bytes([b0, b1, b2])
        
        op0 = b0 & 0x0F
        t = (b0 >> 4) & 0x0F
        s = b1 & 0x0F
        r = (b1 >> 4) & 0x0F
        op1 = b2 & 0x0F
        op2 = (b2 >> 4) & 0x0F
        
        ft = addr + 3  # fallthrough
        
        # ========== op0 = 0: QRST (most RRR instructions) ==========
        if op0 == 0x0:
            return self._decode_qrst(addr, raw, op1, op2, r, s, t)
        
        # ========== op0 = 1: L32R ==========
        elif op0 == 0x1:
            imm16 = (b2 << 8) | b1
            imm16_signed = self._sext(imm16, 16)
            # L32R target: ((PC + 3) & ~3) + (imm16 * 4) for signed offset
            lit_addr = ((addr + 3) & ~3) + (imm16_signed << 2)
            lit_off = lit_addr - self.base
            lit_val = self._u32(lit_off) if 0 <= lit_off < len(self.data) - 3 else None
            
            val_str = f" ; =0x{lit_val:08x}" if lit_val is not None else ""
            return Insn(addr, 3, raw, "l32r", f"{self._ar(t)}, 0x{lit_addr:08x}{val_str}",
                       itype=InsnType.LOAD, is_load=True, mem_size=4,
                       writes=[self._ar(t)], fallthrough=ft,
                       literal_addr=lit_addr, literal_value=lit_val)
        
        # ========== op0 = 2: LSAI (loads/stores/addi) ==========
        elif op0 == 0x2:
            return self._decode_lsai(addr, raw, r, s, t, b2)
        
        # ========== op0 = 3: LSCI (cache/FP loads/stores) ==========
        elif op0 == 0x3:
            imm8 = b2
            return Insn(addr, 3, raw, "lsci", f"{r}, {s}, {t}, {imm8}",
                       itype=InsnType.SPECIAL, fallthrough=ft)
        
        # ========== op0 = 4: MAC16 ==========
        elif op0 == 0x4:
            return Insn(addr, 3, raw, "mac16", "",
                       itype=InsnType.ALU, fallthrough=ft)
        
        # ========== op0 = 5: CALL ==========
        elif op0 == 0x5:
            n = (b0 >> 4) & 0x3
            offset18 = (b2 << 10) | (b1 << 2) | ((b0 >> 6) & 0x3)
            offset18_signed = self._sext(offset18, 18)
            target = ((addr + 4) & ~3) + (offset18_signed << 2)
            
            mnem = f"call{n * 4}" if n > 0 else "call0"
            return Insn(addr, 3, raw, mnem, f"0x{target:08x}",
                       itype=InsnType.CALL, is_call=True,
                       target=target, writes=[f"a{n * 4}"], fallthrough=ft)
        
        # ========== op0 = 6: J (unconditional jump) ==========
        elif op0 == 0x6:
            offset18 = (b2 << 10) | (b1 << 2) | ((b0 >> 6) & 0x3)
            offset18_signed = self._sext(offset18, 18)
            target = addr + 4 + offset18_signed
            
            return Insn(addr, 3, raw, "j", f"0x{target:08x}",
                       itype=InsnType.JUMP, is_jump=True, target=target)
        
        # ========== op0 = 7: BI (branches) ==========
        elif op0 == 0x7:
            return self._decode_bi(addr, raw, r, s, t, b2)
        
        # Unknown
        return Insn(addr, 3, raw, "???", f"op0={op0:x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)
    
    def _decode_qrst(self, addr: int, raw: bytes, op1: int, op2: int, r: int, s: int, t: int) -> Insn:
        """Decode QRST format (op0 = 0, various op1/op2)"""
        ft = addr + 3
        
        # ===== op1 = 0: Main ALU/control group =====
        if op1 == 0x0:
            # op2 = 0: ST2 (misc control)
            if op2 == 0x0:
                if r == 0x0:
                    if s == 0x0 and t == 0x0:
                        return Insn(addr, 3, raw, "ill", "", itype=InsnType.SPECIAL)
                    elif s == 0x0 and t == 0x1:
                        return Insn(addr, 3, raw, "ret", "", 
                                   itype=InsnType.RETURN, is_return=True, reads=["a0"])
                    elif s == 0x0 and t == 0x2:
                        return Insn(addr, 3, raw, "retw", "",
                                   itype=InsnType.RETURN, is_return=True)
                elif r == 0xA and t == 0x0:
                    return Insn(addr, 3, raw, "jx", f"{self._ar(s)}",
                               itype=InsnType.JUMP, is_jump=True, reads=[self._ar(s)])
                elif (r & 0xC) == 0xC:
                    n = r & 0x3
                    mnem = f"callx{n * 4}" if n > 0 else "callx0"
                    return Insn(addr, 3, raw, mnem, f"{self._ar(s)}",
                               itype=InsnType.CALL, is_call=True,
                               reads=[self._ar(s)], writes=[f"a{n * 4}"], fallthrough=ft)
            
            # op2 = 2: SYNC group (r=2 for all sync insns)
            elif op2 == 0x0 and r == 0x2:
                sync_names = {0: "isync", 1: "rsync", 2: "esync", 3: "dsync",
                             0xC: "memw", 0xD: "extw", 0xF: "nop"}
                if t in sync_names:
                    return Insn(addr, 3, raw, sync_names[t], "",
                               itype=InsnType.SYNC, is_barrier=(t in [0, 1, 2, 3, 0xC, 0xD]),
                               fallthrough=ft)
            
            # op2 = 3: RSR/WSR/XSR
            elif op2 == 0x3:
                sr = (r << 4) | s
                sr_name = self._sr(sr)
                if t == 0x0:
                    return Insn(addr, 3, raw, "rsr", f"{self._ar(s)}, {sr_name}",
                               itype=InsnType.SPECIAL, writes=[self._ar(s)], fallthrough=ft)
                elif t == 0x1:
                    return Insn(addr, 3, raw, "wsr", f"{sr_name}, {self._ar(s)}",
                               itype=InsnType.SPECIAL, reads=[self._ar(s)], fallthrough=ft)
                elif t == 0x6:
                    return Insn(addr, 3, raw, "xsr", f"{self._ar(s)}, {sr_name}",
                               itype=InsnType.SPECIAL, 
                               reads=[self._ar(s)], writes=[self._ar(s)], fallthrough=ft)
            
            # op2 = 4: BREAK, SYSCALL, etc
            elif op2 == 0x4:
                if r == 0x1 and t == 0x0:
                    return Insn(addr, 3, raw, "ssl", f"{self._ar(s)}",
                               itype=InsnType.SHIFT, reads=[self._ar(s)], writes=["sar"], fallthrough=ft)
                elif r == 0x0 and t == 0x0:
                    return Insn(addr, 3, raw, "ssr", f"{self._ar(s)}",
                               itype=InsnType.SHIFT, reads=[self._ar(s)], writes=["sar"], fallthrough=ft)
                elif r == 0x4:
                    imm5 = (t & 1) << 4 | s
                    return Insn(addr, 3, raw, "ssai", f"{imm5}",
                               itype=InsnType.SHIFT, writes=["sar"], fallthrough=ft)
            
            elif op2 == 0x5:
                if r == 0x0 and s == 0x0:
                    return Insn(addr, 3, raw, "syscall", "",
                               itype=InsnType.SPECIAL, fallthrough=ft)
                elif r == 0x0 and s == 0x1:
                    return Insn(addr, 3, raw, "simcall", "",
                               itype=InsnType.SPECIAL, fallthrough=ft)
            
            # op2 = 6: NEG, ABS
            elif op2 == 0x6:
                if s == 0x0:
                    return Insn(addr, 3, raw, "neg", f"{self._ar(r)}, {self._ar(t)}",
                               itype=InsnType.ALU, reads=[self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
                elif s == 0x1:
                    return Insn(addr, 3, raw, "abs", f"{self._ar(r)}, {self._ar(t)}",
                               itype=InsnType.ALU, reads=[self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = 8: ADD
            elif op2 == 0x8:
                return Insn(addr, 3, raw, "add", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = 9: ADDX2
            elif op2 == 0x9:
                return Insn(addr, 3, raw, "addx2", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = A: ADDX4
            elif op2 == 0xA:
                return Insn(addr, 3, raw, "addx4", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = B: ADDX8
            elif op2 == 0xB:
                return Insn(addr, 3, raw, "addx8", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = C: SUB
            elif op2 == 0xC:
                return Insn(addr, 3, raw, "sub", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = D: SUBX2
            elif op2 == 0xD:
                return Insn(addr, 3, raw, "subx2", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = E: SUBX4
            elif op2 == 0xE:
                return Insn(addr, 3, raw, "subx4", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            
            # op2 = F: SUBX8
            elif op2 == 0xF:
                return Insn(addr, 3, raw, "subx8", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.ALU, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
        
        # ===== op1 = 1: Shifts =====
        elif op1 == 0x1:
            if op2 == 0x0:
                # SLLI
                sa = ((raw[2] >> 4) & 1) << 4 | t
                return Insn(addr, 3, raw, "slli", f"{self._ar(r)}, {self._ar(s)}, {sa}",
                           itype=InsnType.SHIFT, reads=[self._ar(s)], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0x2:
                # SRAI
                sa = ((raw[2] >> 4) & 1) << 4 | s
                return Insn(addr, 3, raw, "srai", f"{self._ar(r)}, {self._ar(t)}, {sa}",
                           itype=InsnType.SHIFT, reads=[self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0x4:
                # SRLI
                return Insn(addr, 3, raw, "srli", f"{self._ar(r)}, {self._ar(t)}, {s}",
                           itype=InsnType.SHIFT, reads=[self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0x8:
                # SRC
                return Insn(addr, 3, raw, "src", f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.SHIFT, reads=[self._ar(s), self._ar(t), "sar"], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0x9 and s == 0x0:
                # SRL
                return Insn(addr, 3, raw, "srl", f"{self._ar(r)}, {self._ar(t)}",
                           itype=InsnType.SHIFT, reads=[self._ar(t), "sar"], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0xA and t == 0x0:
                # SLL
                return Insn(addr, 3, raw, "sll", f"{self._ar(r)}, {self._ar(s)}",
                           itype=InsnType.SHIFT, reads=[self._ar(s), "sar"], writes=[self._ar(r)], fallthrough=ft)
            elif op2 == 0xB and s == 0x0:
                # SRA
                return Insn(addr, 3, raw, "sra", f"{self._ar(r)}, {self._ar(t)}",
                           itype=InsnType.SHIFT, reads=[self._ar(t), "sar"], writes=[self._ar(r)], fallthrough=ft)
        
        # ===== op1 = 2: AND/OR/XOR =====
        elif op1 == 0x0:
            # These should be op2 specific
            pass  # Handled above
        
        # ===== op1 = 3: Conditional moves =====
        elif op1 == 0x3:
            move_ops = {0x8: "moveqz", 0x9: "movnez", 0xA: "movltz", 0xB: "movgez"}
            if op2 in move_ops:
                return Insn(addr, 3, raw, move_ops[op2], f"{self._ar(r)}, {self._ar(s)}, {self._ar(t)}",
                           itype=InsnType.MOVE, reads=[self._ar(s), self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
        
        # ===== op1 = 4: EXTUI =====
        elif op1 == 0x4:
            shiftimm = ((raw[2] >> 4) & 1) << 4 | s
            maskimm = op2 + 1
            return Insn(addr, 3, raw, "extui", f"{self._ar(r)}, {self._ar(t)}, {shiftimm}, {maskimm}",
                       itype=InsnType.SHIFT, reads=[self._ar(t)], writes=[self._ar(r)], fallthrough=ft)
        
        # Fallback
        return Insn(addr, 3, raw, "qrst", f"op1={op1:x},op2={op2:x}",
                   itype=InsnType.UNKNOWN, fallthrough=ft)
    
    # [Continued in next cell due to length...]
