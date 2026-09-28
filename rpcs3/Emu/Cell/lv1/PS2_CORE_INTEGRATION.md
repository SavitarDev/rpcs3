# Integrating a PS2 emulator core with ps2_emu on RPCS3

This is for developers of PlayStation 2 emulators (PCSX2, Play!, Iris, DobieStation, ...) who want to try their
core as the "silicon" of the first PlayStation 3 model. It explains what the console does, which part of the PS2
the core has to provide, where it connects to RPCS3, and what is still unknown. See `STATUS.md` for how far the
boot gets today and `lv1.md` for the hypervisor model.

## The idea

The CECHA01 (and the other launch models) run PS2 software on real PS2 silicon: an EE+GS chip sits on a PCI bus
behind the PS3's south bridge. Everything else a PS2 had is provided by `ps2_emu.self`, a program the firmware
boots as the operating system of its own lv1 partition:

| PS2 part | On the CECHA01 | On RPCS3 |
|---|---|---|
| Emotion Engine (R5900, VU0/VU1, DMAC, IPU, timers, INTC), GS, 32 MB main RAM | the EE+GS chip | **your core** |
| IOP (R3000A side: SIF, CDVD, SPU2, pads, memory cards, USB, network, ...) | software in ps2_emu (on the PPE) | ps2_emu, unchanged |
| SPU2 sound | ps2_emu code on an SPE | ps2_emu on an RPCS3 SPU |
| CDVD drive | the PS3 BD drive, through lv1 storage | lv1 model + the host's drive or an ISO |
| Memory cards, HDD | files on the PS3 disk | lv1 storage model |
| Video out | GS output through the RSX | RSX emulation |
| Pads | USB/Bluetooth through lv1 | lv1 USB model |

So a core does **not** need an IOP, a CDVD, an SPU2 or pads: ps2_emu does those. It needs the EE side and
the GS, and it has to talk to ps2_emu the way the chip talks to it: through registers, DMA and an interrupt.
That also makes this a way to test an EE/GS core against Sony's own IOP-side implementation.

## Where the chip appears to ps2_emu

All of this is in `lv1.cpp` and `lv1.md` ("PCI", "The PS2 chip's registers", "The PS2 chip's DMA addresses"):

- **PCI device.** Bus 2 (the south bridge's PCI bus), vendor/device `0x820e104d`, found by ps2_emu through the
  repository (`bus2.dev0`) and `lv1_pci_config_read`. Its BAR0 is a memory window at bus address
  `0x60000000` (1 MB), which ps2_emu maps with `lv1_map_device_mmio_region` and uses through its page table.
- **Registers.** Every load and store ps2_emu makes to BAR0 reaches `lv1_device_access()` (bus 2, device 0,
  offset from `ps2_chip_bar0`). Today stores are recorded in `ps2_chip_registers` and loads stop the
  emulation. **This is the function a core plugs into.**
- **DMA.** The chip masters partition memory through DMA regions ps2_emu allocates and maps
  (`lv1_allocate_device_dma_region` / `lv1_map_device_dma_region` on bus 2, through the PCI bridge's I/O
  space). `sb_dma_ptr()` turns a bus address the device uses into a host pointer. The first stores ps2_emu
  makes to BAR0 program the chip's DMA windows: `+0x10`/`+0x14` and `+0x20`/`+0x24` are the base and mask of
  two regions, `+0x80` an SPE's `SPU_In_Mbox` reached through a third, `+0x84..+0xbc` a table.
- **Interrupt.** The chip's PCI interrupt goes to an lv1 interrupt outlet ps2_emu connects. The model has
  `raise_sb_interrupt()`/outlets; the PS2 chip's line is not wired yet (its PCI slot, and so its interrupt
  number, is an approximation documented in `lv1.md`).
- **SPEs.** ps2_emu runs helpers on SPEs that talk to the chip directly (an SPE's mailbox is programmed
  into the chip's DMA table). An SPE reaches the chip's registers by DMA to their bus/partition addresses;
  the MFC translation path in `spu_thread::lv1_translate` is where such accesses arrive.

What each BAR0 register means is **not public**: it has to be read out of ps2_emu (which, being the only
driver, is the specification) and confirmed against the core's behaviour. Notes from an earlier prototype
(not re-verified on this branch; use them as hints): an "ICFG"-like register whose bit 31 must read set before
the IOP-side initialization proceeds; SIF traffic (EE<->IOP DMA channels 5, 6, 7 and the SIF flag/mailbox
registers) is what ps2_emu's IOP exchanges with the EE; the BIOS image comes from ps2_emu's own "ps2 rom"
segment.

## The interface a core should implement

Keep the core behind a small C interface so it can be built and licensed on its own (see "Licensing"). A
suggested shape (names are illustrative; nothing in RPCS3 depends on them yet):

```c
/* ps2_chip.h - the boundary between RPCS3's lv1 model and an EE+GS core. */
typedef struct ps2_chip_host
{
    void* opaque;
    /* The chip masters partition memory: bus address -> host pointer (NULL if unmapped). */
    uint8_t* (*dma)(void* opaque, uint64_t bus_addr, uint32_t size, int write);
    /* The chip's interrupt line changed level. */
    void (*interrupt)(void* opaque, int level);
    /* A finished GS frame: the displayed buffer as the PCRTC shows it. */
    void (*frame)(void* opaque, const uint32_t* rgba, uint32_t width, uint32_t height, uint32_t pitch);
} ps2_chip_host;

typedef struct ps2_chip ps2_chip;

ps2_chip* ps2_chip_create(const ps2_chip_host* host);
void      ps2_chip_destroy(ps2_chip* chip);
void      ps2_chip_reset(ps2_chip* chip);
/* BAR0 accesses, big-endian data as the PPE sees it. */
uint32_t  ps2_chip_read32(ps2_chip* chip, uint32_t offset);
void      ps2_chip_write32(ps2_chip* chip, uint32_t offset, uint32_t value);
/* Run the EE (and GS) for at least `cycles` EE cycles; returns the cycles run. */
uint64_t  ps2_chip_run(ps2_chip* chip, uint64_t cycles);
```

On the RPCS3 side the glue would:

1. load the core as a shared library at boot (only when `ps2_emu.self` is the guest);
2. route bus 2 / device 0 accesses in `lv1_device_access()` to `read32`/`write32`;
3. back `dma` with `sb_dma_ptr()` for bus 2;
4. drive `interrupt` into the chip's lv1 outlet (end of interrupt re-arms it while the level is high, like
   the USB controllers do in `outlet_still_asked()`);
5. run the core on a thread of its own, throttled to the EE's 294.912 MHz, and wake it whenever ps2_emu
   starts a transfer (the IOP side waits for EE DMA completion in tight loops, so latency matters more than
   throughput);
6. present `frame` through the RSX path ps2_emu programs, or in a window of its own while that path is not
   followed.

## Practical advice from the earlier prototype

- Treat ps2_emu as the specification: instrument `lv1_device_access()` and log every BAR0 access with the
  guest's PC; the protocol is visible in ps2_emu's code around each access.
- Make register waits observable. ps2_emu polls status bits in closed loops with no timeout; a register
  that never changes looks like a hang, not an error.
- DMA completion latency decides speed: an EE core that only services DMA at the end of long time slices
  starves ps2_emu's IOP.
- Runs are not deterministic (two PPE threads race in ps2_emu's startup): compare two runs of the same build
  before trusting a change.

## Licensing

RPCS3 is GPL-2.0-only. Several PS2 emulator cores are GPL-3.0-or-later (PCSX2), which cannot be distributed
combined with GPL-2.0-only code. Others use permissive or GPL-2.0-compatible licenses (for example Play! is
BSD-2-Clause). Check your core's license before distributing a build that links it. Keeping the core in a
separately built shared library behind a permissively licensed interface header keeps local experiments
simple; it does not by itself make distributing an incompatible combination acceptable.

## Getting started

1. Read `STATUS.md`: the boot has to reach the point where ps2_emu programs the chip beyond its first stores.
2. Build this branch, place `ps2_emu.self` in `dev_flash/ps2emu/`, run it, and watch the `lv1` log channel.
3. Add the bus 2 branch in `lv1_device_access()` that forwards to your core, and follow the first load that
   stops.
