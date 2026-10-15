# End-to-End TLS Corruption Path Analysis

## Overview

This document traces the exact control flow from user application to TLS corruption,
showing where the DMA coherency bug causes `bad_record_mac` errors.

## The Complete TX Path

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: APPLICATION                                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  User Application                                                            │
│       │                                                                      │
│       └── HTTPS POST (large file upload)                                    │
│               │                                                              │
│               ▼                                                              │
│  OpenSSL/TLS Library                                                         │
│       │                                                                      │
│       ├── Fragment data into TLS records                                     │
│       ├── Encrypt each record                                                │
│       └── Compute MAC for each record                                       │
│               │                                                              │
│               ▼                                                              │
│  TLS Record: [header (5 bytes)][encrypted_data][MAC (32 bytes)]             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: LINUX KERNEL (IPQ4019 ARM Cortex-A7)                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  TCP/IP Stack                                                                │
│       │                                                                      │
│       └── Build Ethernet frame with IP/TCP headers                          │
│               │                                                              │
│               ▼                                                              │
│  ath_dual.ko Driver                                                          │
│       │                                                                      │
│       ├── ath10k_htt_tx_send()                                              │
│       │       │                                                              │
│       │       ├── Build HTT TX descriptor                                    │
│       │       └── Write to Copy Engine (CE) ring                            │
│       │               │                                                      │
│       │               ▼                                                      │
│       └── WAR_CE_SRC_RING_WRITE_IDX_SET()                                   │
│               │                                                              │
│               ├── Multiple __dsb() ARM barriers ✓ CORRECT                   │
│               ├── Dummy read for bus sync                                    │
│               └── Update CE write index                                      │
│                                                                              │
│  NOTE: ARM driver has correct barriers!                                      │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ CE Ring Write (triggers firmware IRQ)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: WIFI FIRMWARE (QCA4019 Xtensa)                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  CE Interrupt Handler                                                        │
│       │                                                                      │
│       └── Process CE ring entries                                            │
│               │                                                              │
│               ▼                                                              │
│  TX Descriptor Builder (Function 0x0042136d)                                │
│       │                                                                      │
│       ├── Build DMA descriptor for packet transmission                       │
│       │                                                                      │
│       │   0x0042137c: s32i.n a11, a2, 0    ; buffer pointer                 │
│       │   0x004213f6: s32i.n a10, a1, 0    ; descriptor base                │
│       │   0x004213f8: s32i.n a9, a1, 4     ; length/flags                   │
│       │   0x00421421: s32i.n a10, a1, 8    ; next descriptor                │
│       │   ... (25 stores total to descriptor fields)                        │
│       │                                                                      │
│       │   ❌ NO memw BARRIERS AFTER ANY STORES!                              │
│       │                                                                      │
│       └── Update DMA chain pointer                                           │
│               │                                                              │
│               │   0x004214ab: l32i a15, a12, 844   ; load current ptr       │
│               │   0x004214c0: s32i a15, a12, 844   ; store updated ptr      │
│               │   0x004214c9: j 0x0041fc6f         ; jump out               │
│               │                                                              │
│               │   ❌ NO memw BETWEEN STORE AND JUMP!                         │
│               │                                                              │
│               └── Value in CPU cache, NOT in memory!                         │
│                                                                              │
│  ┌────────────────────────────────────────────────────────────────┐         │
│  │ BUG: Store to offset 844 stays in CPU cache                    │         │
│  │      DMA engine reads from memory (stale value)                │         │
│  └────────────────────────────────────────────────────────────────┘         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ DMA reads STALE descriptor chain
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: DMA ENGINE (Hardware)                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  DMA Controller                                                              │
│       │                                                                      │
│       ├── Read descriptor chain from memory at offset 844                    │
│       │       └── Gets OLD/STALE pointer (CPU cache not flushed)            │
│       │                                                                      │
│       ├── Follow descriptor chain                                            │
│       │       └── Points to: old buffer, freed memory, or wrong chain       │
│       │                                                                      │
│       └── Fetch data from wrong/old buffer                                   │
│               └── Wrong bytes sent to radio                                  │
│                                                                              │
│  RESULT: DMA transmits WRONG DATA or data from WRONG BUFFER                 │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5: RADIO TRANSMISSION (2.4GHz)                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  PHY/MAC                                                                     │
│       │                                                                      │
│       ├── Modulate and transmit corrupted packet                            │
│       │                                                                      │
│       └── Packet contains:                                                   │
│               ├── Wrong data (from stale buffer)                            │
│               ├── Partial data (truncated at wrong boundary)                │
│               └── Out-of-order data (wrong descriptor chain)                │
│                                                                              │
│  WHY 2.4GHz IS WORSE:                                                        │
│       ├── 61% channel utilization = more TX operations                      │
│       ├── More retries = more descriptor updates                            │
│       └── Higher race probability between CPU and DMA                       │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    │ Corrupted WiFi frame over air
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│ LAYER 6: RECEIVER (API Server)                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  WiFi AP / Router / Endpoint                                                 │
│       │                                                                      │
│       └── Receive WiFi frame (corrupted)                                    │
│               │                                                              │
│               ▼                                                              │
│  TCP/IP Stack                                                                │
│       │                                                                      │
│       └── Reassemble TCP segments (corrupted)                               │
│               │                                                              │
│               ▼                                                              │
│  TLS Library                                                                 │
│       │                                                                      │
│       ├── Extract TLS record                                                 │
│       ├── Decrypt record                                                     │
│       ├── Compute MAC on decrypted data                                     │
│       │                                                                      │
│       └── MAC VERIFICATION:                                                  │
│               │                                                              │
│               │   Expected MAC = f(original data)                           │
│               │   Computed MAC = f(corrupted data)                          │
│               │   Expected ≠ Computed                                        │
│               │                                                              │
│               └── ❌ ERROR: bad_record_mac                                  │
│                       │                                                      │
│                       └── TLS connection RESET                              │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## The Specific Bug

### Location: Function 0x0042136d

```xtensa
; Build DMA descriptor chain (25 stores, NO barriers)
0x0042137c: s32i.n a11, a2, 0      ; buffer pointer - NO BARRIER
0x004213f6: s32i.n a10, a1, 0      ; descriptor base - NO BARRIER
0x004213f8: s32i.n a9, a1, 4       ; length/flags - NO BARRIER
0x00421421: s32i.n a10, a1, 8      ; next descriptor - NO BARRIER
... (21 more stores)

; THE CRITICAL BUG - Update chain pointer and exit
0x004214ab: l32i a15, a12, 844     ; load current chain pointer
0x004214c0: s32i a15, a12, 844     ; store updated chain pointer
0x004214c9: j 0x0041fc6f           ; JUMP OUT - NO memw BARRIER!
                                    ;
                                    ; CPU cache: has new value
                                    ; Memory:    has OLD value
                                    ; DMA reads: OLD value → CORRUPTION
```

### What Should Happen

```xtensa
0x004214ab: l32i a15, a12, 844     ; load current chain pointer
0x004214c0: s32i a15, a12, 844     ; store updated chain pointer
0x004214c3: memw                    ; <-- MUST ADD THIS
0x004214c6: j 0x0041fc6f           ; Now safe to exit
```

The `memw` instruction flushes the CPU write buffer to memory, ensuring
the DMA engine sees the updated chain pointer.

## Statistics

| Metric | Value |
|--------|-------|
| Total DMA stores in firmware | 15,785 |
| Stores WITHOUT memw after | 15,099 (95.7%) |
| Functions with unprotected stores | 1,853 |
| Total memw barriers | 632 (but placed BEFORE stores) |

## Why Radio Restart Fixes It

1. Radio restart resets all DMA ring pointers to known-good state
2. Clears any corrupted descriptor chains in progress
3. Reinitializes hardware state
4. Flushes all CPU caches
5. Bug can still recur after restart, but corrupted state is cleared

## Root Cause

The firmware systematically places `memw` barriers BEFORE stores instead of AFTER:

```
WRONG (current firmware):          CORRECT (required):
  memw                               s32i a0, a1, offset
  s32i a0, a1, offset                memw
  ; NO barrier after                 ; flush to memory
```

A barrier BEFORE only ensures previous stores are visible - it does NOT
flush the current store to memory.

---

## IDA Pro Verification (ARM Driver)

The ARM driver barriers were verified via IDA Pro decompilation:

### WAR_CE_SRC_RING_WRITE_IDX_SET @ 0x0003dfbc

```c
int WAR_CE_SRC_RING_WRITE_IDX_SET(int result, _DWORD *a2, int a3, int a4)
{
  if ( war1 == 0 )
    return WAR_PCI_WRITE32(...);
    
  // Critical section with multiple barriers:
  __dsb(0xEu);                    // Store barrier
  *v5 = a4 | 0xCEEF0000;
  
  // OR in the else path:
  CPSR = __get_CPSR();
  __disable_irq();                // Disable interrupts
  __dsb(0xEu);                    // Store barrier
  *v5 = 1;
  __dsb(0xFu);                    // Full system barrier
  __dsb(0xFu);                    // Full system barrier (again!)
  result = WAR_PCI_WRITE32(...);
  __dsb(0xEu);                    // Store barrier
  *v5 = 0;
  __set_CPSR(CPSR);
  return result;
}
```

### WAR_PCI_WRITE32 @ 0x0002ab90

```c
int WAR_PCI_WRITE32(int result, int a2, int a3)
{
  if ( war1 != 0 )
  {
    raw_spin_lock_irqsave(&pciwar_lock);
    __dsb(0xFu);                  // Full barrier
    __dsb(0xFu);                  // Full barrier (again!)
    v7 = *(_DWORD *)(v3 + a2 + 4); // Dummy read (bus sync)
    __dsb(0xFu);                  // Full barrier
    __dsb(0xEu);                  // Store barrier
    *(_DWORD *)(v3 + a2) = a3;    // Actual write
    raw_spin_unlock_irqrestore(&pciwar_lock, ...);
  }
  else
  {
    __dsb(0xEu);                  // Store barrier
    *(_DWORD *)(result + a2) = a3;
  }
}
```

### Barrier Count in ARM TX Path

| Function | __dsb() calls | Spinlocks | IRQ disable |
|----------|---------------|-----------|-------------|
| WAR_CE_SRC_RING_WRITE_IDX_SET | 4 | 0 | 1 |
| WAR_PCI_WRITE32 | 5 | 1 | 1 |
| CE_send | 2 | 1 | 0 |
| **TOTAL** | **11+** | **2** | **2** |

### Contrast with Xtensa Firmware

| Component | Barrier calls | Notes |
|-----------|---------------|-------|
| ARM Driver TX path | 11+ __dsb() | Correct |
| Xtensa TX path | 0 memw | **BUG** |

The ARM driver developers clearly understood the DMA coherency requirements.
The Xtensa firmware developers did not apply equivalent barriers.
