# lv1 guest operating system model

`ps2_emu.self`, the PlayStation 2 emulator of the CECHA01, is not a GameOS process. lv1 boots it as the
operating system of its own logical partition, in place of the GameOS kernel. `lv1_guest_os.cpp` loads it
the way lv1 does and `lv1.cpp` answers the hypervisor calls (`sc 1`) its two PPE threads make.

## Evidence

Every answer is taken from one of these sources, cited in the code comments:

- **lv1 4.93** (`lv1 4.93 0x...`): `lv1.self` from the `CORE_OS_PACKAGE.pkg` of the official 4.93 update,
  decrypted locally with the keys RPCS3 already carries (`SCEPKG_ERK`/`SCEPKG_RIV` for the package, the
  LV1 SELF keys for `lv1.self`). The hypercall dispatcher at 0xc00 indexes a 256-entry table at 0x372d08.
  Most handlers are registered from a static list at 0x3c2340 (`{number, descriptor}`, the descriptor
  pointers being stored by static initializers); the rest are registered at boot through 0x2c8b90 (arrays
  at 0x361db8, 0x362060, 0x3621a0, 0x362258, 0x3623d0, 0x363890 and 0x363980).
- **lv1's processes** (`lparmgr 0x...`, `SLL 0x...`): lv1 carries seven process images in its data segment
  from 0x5f00e8 (file offset 0x1f00e8). Processes 1 to 6 are each preceded by a 0x3f0-byte block that starts
  with a copy of their ELF header and program headers; the image itself is the ELF that follows the block,
  and its addresses are the ones cited. Process 1 is the System Manager with lparmgr, process 6 the Secure
  LPAR Loader (SLL), which loads a partition's operating system image.
- **ps2_emu.elf** (`ps2_emu.elf 0x...`): how the guest calls and what it does with the results.
- The Linux PS3 platform code written by Sony (`arch/powerpc/platforms/ps3`, `asm/lv1call.h`), PowerPC
  Operating Environment Architecture Book III v2.02, Cell Broadband Engine Registers v1.5, and psdevwiki.

There are no tolerated divergences. A call, or a value, that has not been determined from these sources
stops the emulation with "not implemented" or "not determined" instead of being answered: a made-up value
would be read by the guest as the hypervisor's word. The list of what is still undetermined is at the end.

The partition's timebase counts at the console's 79.8 MHz (`lv1_timebase()`): the repository gives that
frequency as `be.0.tb_clk` (0x4c1a6c0, a fortieth of the 3.192 GHz of `be.0.nclk`) and Linux sets its
timebase from that node. GameOS processes keep RPCS3's own 80 MHz timebase, which this work does not touch.

## Status codes and registers

lv1 returns a 32-bit status in the low word of r3, zero-extended; when it refuses an argument, bit n - 1 of
the high word names the nth argument (`0x1ffffffef` is `LV1_ILLEGAL_PARAMETER_VALUE` for the first one).
Further results go in r4 onwards. `lv1_status()` builds that encoding.

The hypercall vector clears, with `dcbz` at 0xc08, the 128-byte block of its per-thread data from which it
reloads r3 to r10 on the way out (0x1040..0x1068), so every result register a call does not set is 0. It
returns with `hrfid` to the SRR0 and MSR the `sc` saved, which it leaves in r11 and r12, and with LR at
0x1028 from its own call to 0x1240. If a raised plug of the calling thread is unmasked and the caller had
MSR[EE] set, lv1 does not return but enters the External interrupt vector (0x18e0), with r11 and r12 holding
that vector and MSR.

Every call runs its handler with MSR[EE] set (0x27a0 and an `mtmsrd` around it, or the trampoline of the
calls registered at boot). A Decrementer exception of the thread that exists meanwhile is therefore taken by
lv1, which notes it and parks DEC at 0x7fffffff (0x2c632c..0x2c637c); on the way out it writes 0 to DEC, so the
guest takes the interrupt right after, from a call at 0x1050 that leaves LR at 0x1054 (0x1094).

Where the model does not reproduce lv1, and why the guest cannot tell:

- r0 (the TSRL lv1 saved), CTR, XER and CR fields 0, 1 and 5 to 7 keep what lv1's own code left there, which
  depends on the handler's path. The model leaves them as they were.
- The calls registered at boot (0, 6, 13, 15, 90 to 93, 105 to 112, 116 to 119, 122 to 126, 135, 136, 182,
  183, 231) go through a trampoline (0x2c89cc) that copies r4 to r10 into the return block from its own stack
  frame (0x2c8b14) without initialising them, so a result its handler does not set is whatever that stack
  held. The model gives 0.

Checked over ps2_emu.elf's 259 `sc 1` sites with a liveness walk that follows both sides of each branch and
the direct calls: after the calls registered at boot it reads r4 (and r5 after 0 and 91), only on success,
which are results the handlers set; lv1's r0, r11, r12, LR, CTR and XER are never read before being set. The
volatile CR fields reach only `mfcr` instructions in the prologues of 0x40b8, 0x1de84 and 0x1df14 and of the
functions the external interrupt handler calls through its table (0x3520..0x3728). Those save the whole CR
and put back fields 2 to 4 only (`mtcrf` masks 0x20, 0x10, 0x08), so the saved bits of fields 0, 1 and 5 to 7
are never used again.

## Virtual interrupt delivery

lv1 delivers a partition's External interrupts itself, on its way back to the partition after an interrupt
of its own (0x1870) or at the end of a hypervisor call (0x18e0): SRR0 and SRR1 as the hardware would set
them, and an MSR that keeps bits 0:47 of SRR1 with SF set, which keeps VEC and clears ME where the
architected interrupt does the opposite. The vector is 0x500 for every partition thread (0x2c3dc8). With
MSR[EE] clear it sets LPCR[MER] and the interrupt comes when the guest enables it.

## The partition

How lparmgr builds the `PS2_LPAR` partition (its `SCE_CELLOS_SYSTEM_MGR_PS2` class, 0x8001e364, chosen at
0x8001d0f8 when the hardware configuration word says the console has the PlayStation 2 chips) and how the
SLL loads `ps2_emu.self` into it, as far as lv1 is concerned:

1. `construct_logical_partition` (PMI 0x10009, 0x8001cd58).
2. `allocate_memory(lpar, 1 << 0x1a, 0x1a, 0, 8)` (PMI 0x10000, 0x8001cd94): the partition's memory, see
   below.
3. The SLL reads the image into a buffer it allocates in the partition (`allocate_memory(lpar, size rounded up
   to 1 MB, 20, 0, 2)`, 0x80001600), maps the partition's memory through `/proc/partitions/N/mem`, has an
   isolated SPU decrypt the image into it (`auth_lv2`, with an SPE constructed in its own partition), and
   releases the buffer (PMI 0x1000e, 0x80001508).
4. PMI 0x10034 for each of the bits 2, 3, 5, 6 and 7 of the class's mask 0x37 << 56 (0x8001ca40), then
   `construct_logical_pu` (PMI 0x10005, 0x8001ca78), repository nodes, PMI 0x1002e and
   `activate_logical_pu` (PMI 0x10007, 0x8001cc78).

- Memory: 64 MB at logical partition address 0. `default.spp` (decrypted with the key the firmware's own
  `spp_verifier.self` holds) gives the `PS2_LPAR` partition the log2 memory size 0x1a at entry +0x148, where
  `PS3_LPAR` has 0x18, the 16 MB of a retail console's `bi.pu.1.rm_size`; lparmgr's partition record keeps it
  at +0x128 (0x8001e16c, the record's name being at +8 where the entry's is at +0x18). Flag 8 makes lv1's
  allocator place the region at address 0 without drawing on its counter (0x2dea14 -> 0x2cec78, 0x2cee3c).
  ps2_emu.elf lays its regions out downwards from 0x4000000 (0x47f8). The loader commits all of it.
- Object ids: lv1 hands out the lowest free id of the partition (0x2ca258), shared by its event receive
  ports, I/O interrupt outlets, address spaces, logical PUs, logical SPEs and performance monitors, the only
  classes built on the partition object constructor 0x2cc64c. The logical PU of step 4 takes id 0 (0x2e7754
  -> 0x2e0df8 with the target partition). No other step creates an object there: the other constructors are
  reached only from hypercalls, and from process calls that build the object in the caller's own partition
  (the event port core 0x2e24e8 and the SPE path through 0x300a28 take the current one). So the guest's first
  object gets id 1.
- Logical addresses: the allocator (0x2cec78) is built with its counter at 1 (0x2cef10) and hands out
  `(class << 42) | (n << class)`, class the rounded-up log2 of the size (12 up to 4 KB) and n the low
  42 - class bits of the counter, which it increments on every attempt; an address still in use makes it try
  the next one (0x2ce7c4 answers 4). Step 3's buffer is the only allocation that draws on the counter before
  the guest starts (lparmgr and the SLL are the only processes that call PMI 0x10000, once each), so the
  guest starts with the counter at 2.
- Both PPE hardware threads start at the system reset vector with the reset MSR (SF only), and run in the
  PPU interpreter.

## Virtual interrupts: 9, 18, 24, 26, 27, 28, 73

An outlet is a partition object shared by event receive ports and I/O interrupt outlets (0x2df60c,
0x2df6b8). It is a latch: raising it sets it, and raising it again before its end of interrupt changes
nothing (0x2df808). Each PPE thread has 256 plugs, plug n being bit 63 - n % 64 of word n / 64, with a status
bitmap (set while the plug's outlet is raised) and a mask. The external interrupt exists while a plug's
status and mask bits are both set.

- `construct_event_receive_port` (18, 0x2e24e8): a new outlet, its id from the partition's allocator.
- `connect_irq_plug(plug, outlet)` (28, 0x2e7018, 0x2df968): a plug of the calling thread (CTRL gives the
  thread). Plug above 255 `ILLEGAL` (argument 1), no such outlet `NO_ENTRY` (2), outlet connected already
  `DUPLICATE_ENTRY` (2), plug in use `DUPLICATE_ENTRY` (1). The plug takes the outlet's state, so an outlet
  raised before being connected makes its plug pending at once.
- `send_event_locally(outlet)` (24, 0x2e269c): raises an event receive port; anything else is `NO_ENTRY` (1).
- `detect_pending_interrupts(0)` (26, 0x2c3cc8): the thread's status bitmap, unmasked, changing nothing.
- `end_of_interrupt(plug)` (27, 0x2dfea8, 0x2dfc5c): lowers the plug's outlet and clears its status. Plug
  above 255 `ILLEGAL`, no outlet `NO_ENTRY`, outlet not raised `WRONG_STATE`, all for argument 1. For an I/O
  interrupt outlet lv1 also re-arms the source, which nothing in the model raises yet.
- `set_interrupt_mask(0, m0..m3)` (73, 0x2c356c): the thread's mask; a first argument other than 0 is
  `ILLEGAL` (1).
- `pause(mode)` (9, 0x2c68c4): returns at once or when a plug is raised and unmasked; with mode 0 an expired
  Decrementer ends it too. Other modes are `ILLEGAL` (1).

## Virtual address spaces: 1, 2, 7, 95

- `construct_virtual_address_space` (0x2ec554): the log2 table size is refused above 20 and raised to 18
  below it, so ps2_emu's 0 gives a 256 KB table; at most two page sizes, each 16, 20 or 24; the size comes
  back in bytes.
- `select_virtual_address_space` (0x2eafe4): 0 is the partition's initial address space. SDR1 is shared by
  both PPE threads (Cell BE Registers Table 12-1), so the selection is per partition.
- `write_htab_entry` (0x2ed1c0, 0x2d368c) and `read_htab_entries` (0x2ecaf8, 0x2d1720): argument checks,
  the large-page encoding (the number of ones from bit 12 of the second doubleword indexes the address
  space's page sizes) and the packed low halfwords follow the handlers.

Address translation itself (MSR[IR]/[DR], the SLB, lookups in the selected table) is not modelled yet.

## Repository: 91

`read_repository_node` (0x2e52c4, 0x2e3d20) reads the repository of the partition it is given; the guest
reads the platform management partition's (lpar 1). Keys are built as lv1 builds them (0x2384a0): the first
is the name in the low 32 bits plus an index, the others the name padded to 64 bits plus an index. A missing
node is `LV1_NO_ENTRY` with the four keys marked (`0x1efffffffa`).

lv1 creates the buses at boot in 0x23906c: bus0 (type 3, one device of type 0), bus1 the south bridge (type
4, 0x238e20), bus2 (type 1) and bus3 (type 2) from objects that list what the hardware has (0x238964), and
bus4 the storage bus (0x2523b4). Modelled so far: the nodes of bus0 and bus1 whose values are constants of
those functions. The USB register windows (`bus1.dev1/dev2.reg.data`) are regions 1 and 2 of the south
bridge's devices 3 and 4, which its driver defines with constants for every chip revision (0x3a9a60..
0x3a9af0; the chip types 3 and 4 only add a region elsewhere, 0x3a9c4c). Reading a node the model does not
know stops with "not modelled"; nodes lv1 is known not to create (bus5 onwards, anything else under bus0 and
bus1) answer `LV1_NO_ENTRY`.

The second value of `bus1.id` is the south bridge's revision word, which lv1 reads from the chip
(0x22b760). The model answers an approximation (see "Approximations"). ps2_emu.elf cannot see it: its bus
scan stores that value where the next read overwrites it (0x1da70, then 0x1daa4) and its id readers return
the first value only (0x1dd14, 0x1dd90).

## South bridge devices: 120, 170, 172, 174, 176

- `open_device` (0x305a38, 0x2375b0) and the checks the device calls share (0x2363e0): bus id above 4 is an
  illegal first argument, buses 1 to 4 only, and the device has to exist on the bus.
- `map_device_mmio_region` (0x306d64, 0x237254, 0x228bec): `bus_addr` has to be the base of one of the
  device's register windows (the repository's `reg.data`), the size has to fit and the page be 12, 16, 20
  or 24. The logical partition address comes from the partition's allocator (0x2cec78), which hands out
  `(class << 42) | (n << class)` with class the rounded-up log2 of the size and n a counter; psdevwiki's
  `allocate_memory` example (a 4 KB region at 0x30000001f000) has exactly this form.
- The debug card calls (105 to 112, 124 to 126, 135, 136, 231; 0x312714 for 105) return 0 and do nothing
  on a retail console, which has no `sys.dbgcard.dgbe` repository node.
- `construct_io_irq_outlet` (0x2c0604): interrupt ids up to 0x3f, one outlet per interrupt.
- `allocate_device_dma_region` (0x306a6c, 0x236f88, 0x23d4c4) and `map_device_dma_region` (0x306770): the
  argument checks and the six DMA windows of a USB controller follow lv1.

### The USB controllers' DMA addresses

The address comes from the device's I/O space (0x2267fc -> method 0x226bc8 -> 0x22d990 -> 0x22d3a4):

- The USB controllers are south bridge devices 3 and 4 of types 8 and 9 (created at 0x3a9a5c and 0x3a9ab0,
  constructor 0x22dd88: index at +0x80, type at +0xa0, the south bridge at +0x88).
- The size is rounded up to a power of two (0x22d404), more than 4 GB is refused.
- `[lpar+0x50]` is the partition id (lv1 prints it after "LPAR#", 0x2e6074). The id table reserves 0 when it
  is created (0x3af6a4) and the system partition takes 1 (0x3b0158), so the PS2 partition's id is at least
  2 and lv1 takes the partition path (0x22cf74): a per-type allocator at `[south bridge+0x148+type*8]`,
  created on first use (0x22d280) with the window `(type 8: 4, type 9: 5) << 32 | 0x40000000`, 1 GB
  (0x22d32c, 0x22d344, 0x22a1f0; id 1 would take the window 0x20000000 below it).
- The allocator (0x22ac9c) keeps regions in creation order (the ordering method 0x22a124 always answers
  false) keyed by partition id and page size. It gives the first block of a region at its start; after
  that it only looks after the region's first block, first fit, aligned to the larger of the block and the
  page. With no room it creates a region (0x22a6ac): the size is `max(page, block) * 0x80`, at most 256 MB,
  or whole 256 MB segments above that (0x22a424), and each segment is the lowest free one of the window in
  I/O space 0's segment table (0x2da2c8 -> 0x2d9d20 -> 0x2d9868 -> 0x2d9510 with a range, 0x2ca01c).
  The segments claimed at boot (0x213b34, 0x80000000..0xdfffffff) and the other types' windows do not
  overlap the USB windows.
- The device sees an I/O address as `0x80000000 + (address - io base)` (0x22d6a0); the south bridge set
  the io base to `(4 or 5) << 32` when it created the device (0x3a9878, 0x3a986c, 0x22db70). A non-zero
  IOIFC `trxba` would move that base; the model takes zero (see "Approximations").
- The first USB0 region is therefore 64 MB at 0x4_40000000 and ps2_emu's first request (512 KB) gets
  0xc0000000, confirmed by the run.

What happens when all six windows are in use is not modelled: lv1 allocates first and releases the block
again (0x23d58c), and that release has not been followed, so the model stops.

### The PS2 chip's registers

ps2_emu's first accesses to BAR0 are stores (0x1d6d8..0x1d7cc): +0x10/+0x14 and +0x20/+0x24 the base and
mask of its first two DMA regions (0xc0000000 / 0x1fffff, 0xc0400000 / 0x3fffff), +0x80 and a table at
+0x84..+0xbc whose addresses (0xc020400c) reach a logical SPE's SPU_In_Mbox through its third DMA region,
which maps the SPE's problem state. The model keeps the stores; loads stop until their meaning is known.

### The PS2 chip's DMA addresses (bus 2)

A PCI device (class vtable 0x35ce08, created by the bus scan at 0x232930) gets its DMA address from the
PCI host (0x3682d0, vtable 0x35cc28) through method 0x58 (0x2347dc): the host forwards to the south bridge
bridge object (0x3682c8, vtable 0x35ca28), whose method 0x60 (0x23066c) takes one of sixteen slots
(RESOURCE_SHORTAGE when all are used) and creates the block in south bridge device 6's I/O space
(0x226990 -> 0x22d3a4). Device 6 is of type 0 (0x3a9d58), so its window is `0x40000000`, 1 GB, with io
base 0 (the default of the type table at 0x22d244). The device's ioid is device 6's, which lv1 sets to 0
when it creates device 6 (0x22ddf8..0x22de70, the only device that does not draw one from the pool). Flags
other than 0 are UNSUPPORTED for a device outside bus 1 (0x237010).

## I/O address spaces: 116, 118

- `allocate_ioid(ioas_id)` (0x2d7de8): lv1 creates one I/O address space, 0 (0x2d945c); any other id has no
  entry. The ioid is the lowest free one (0x2d7a14). The space reserves 0 and 1 (0x2d91e4..0x2d92b0) and
  each south bridge device lv1 creates takes the next (0x22de08), except device 6 and the type 0x10 one.
  Which devices lv1 creates depends on the chip type of the south bridge revision (0x3a9af4, 0x3a9b6c,
  0x3a9c20; types 3 and 4: devices 0 to 4, 7, 0xc, 9, plus 6 for type 3, eight ioids; type 1 creates
  more). With the approximated revision (chip type 3) the guest's first ioid is 10.
  ps2_emu only gives the ioid back to `release_ioid` (119) when it shuts the RSX down (0x45ae4).
- `allocate_io_segment(ioas_id, size, page)` (0x2da1f0 -> 0x2d9d20): space 0 only; the size below 1 << 35
  and at most 256 MB, the page 12, 16, 20 or 24 (0x2b9db0). lv1 takes the lowest free segment of the space
  (0x2ca258) and gives it back as BUSY if it is above 7 (0x2d960c, 0x2d9bd4); the address is segment << 28.
  The same segment table holds the device windows' segments (the USB regions above).

Segments in use when the guest starts:

- 8 to 0xd: a boot initializer (0x213adc, in lv1's static initializer list at 0x3c2180) reserves
  0x80000000..0xdfffffff.
- 0 and 1: the UX kernel creates "cp0" (0x375ee8 -> 0x377b30). Its constructor asks whether a
  Communication Processor exists (0x301e60 -> 0x20afc0), probing for the Sony chip 0x104d:0x81ff on the
  south bridge's ebus (0x20ae04, only tried for chip types 3 and 4). A retail console has no such chip (it
  belongs to the reference tools), so for every chip type cp0 then allocates two 4 KB segments at the
  lowest free position (0x2aa6bc -> 0x300608 -> 0x2da55c) and maps memory into them (0x300570). The other
  constructor copy (0x37798c) is not referenced. The hypervisor console's segment (0x209460) is only taken
  with a debug card (`sys.dbgcard.dgbe` 2 or 4, 0x313600), which a retail console does not have.
- 3: only if lv1's RSX initialisation (static initializer 0x20c6ac -> 0x3a1d24) finds an RSX revision above
  2 in the RSX register at 0x28000000000 (bits 16..19, or 8..11 once 0x28000000004 reads 0x01000001;
  0x3a1dd4, 0x3a281c). It then runs 0x3a5a14, which reserves 0x30000000 (0x3a76d4 -> 0x2da250). That
  branch is the post of the 28 nm RSX with GDDR5 memory (its strings: "post/post_rsx28.cc",
  "gddr5WaitIdle_RSX28()"); every other revision runs post_rsx.cc's initialisation script, which reserves
  nothing. The CECHA01 has the 90 nm RSX (CXD2971 family) with GDDR3 (psdevwiki), so segment 3 is free.

So ps2_emu's two `allocate_io_segment` calls (128 MB, 4 KB pages) get 0x20000000 and 0x30000000.

## PCI: the south bridge's bus (bus2) and 178, 179

- lv1 builds `bus2` (id 2, type 1) and `bus3` (id 3, type 2) from two PCI host objects (0x2390ac..
  0x2390f8, 0x238964). bus2's host is the south bridge's PCI bus (0x23d024, the global 0x3682d0), with the
  memory window of south bridge device 6's region 2: 0x60000000, 512 MB (0x3a9db0), and an I/O window of
  64 KB at 0x1000 (0x231a50). lv1's own default configuration text (lv1 file offset 0x1d0d30, which also
  sets `sys.lv1.rsxenable = 3`) has no `sys.lv1.large_pciex`, which would move the window (0x22c8cc).
- The scan (0x2331ec, devices 0..15, functions 0..3 of the host's bus 0) hides the ids of lv1's known table
  (0x35cc08) and hands the others to 0x232b98: the device's id is its index (0x23296c), memory BARs are
  sized the usual way and recorded at least 1 MB (0x232d18), and placed from the window's cursor aligned to
  the largest (0x233064). Interrupt: on the root bus the host's routing table (0x22f478: devices 5..8);
  the `intr` node is {1, that number} (0x238bdc), or three nodes for devices the Communication Processor
  driver marks (0x2888c0, only with that driver's hardware).
- On a CECHA01 the scan finds the PS2 chip, 104D:820E (ps2_emu's comparison at 0x1d404), so bus2 has one
  device: id 0, type 1, pci_bus 0, `reg` type 1 with (0x60000000, 0x100000). See "Approximations" for its
  position and BAR size.
- `pci_config_read/write` (0x3063cc/0x306190 -> 0x2361c0/0x235fa0): argument checks (bus > 4, bus/dev/fun >
  0xff, offset > 0xff, or 0xfff on bus 3, size not 1/2/4: ILLEGAL of that argument); buses 1 and 4 are an
  ACCESS_VIOLATION, others but 2 and 3 NO_ENTRY; misaligned: ILLEGAL of the size; writes to 0x10..0x3f:
  ACCESS_VIOLATION of the offset; an unlisted function: NO_ENTRY (read value -1). The chip's configuration
  space is only known at offset 0 (its id); ps2_emu writes 0x146 to the command register and 0 at 0xc.
- `open_device` on bus2 finds the device by id (0x236568 -> 0x232b5c; NO_ENTRY of the second argument
  otherwise) and `map_device_mmio_region` uses the same generic path as the south bridge's devices
  (0x228bec), refusing device 0 only on bus 1.

## RSX: 210, 212, 214, 217

lv1's RSX driver (NVIDIA's "cellos" driver inside lv1) is followed as far as the partition can see it.

- `gpu_open` (0x20e908 -> 0x20c548): NO_ENTRY if `sys.lv1.rsxenable` is at most 1 (a retail console, whose
  games use the RSX, has it above 1); BUSY while a partition owns the device (0x35b4c4, 0xff when free).
  The device object (0x20be10) creates lv1's RSX memory manager, which is global (0x363f10) and made by the
  first open since lv1 started; the PS2 mode is booted from lv0, so the PS2 partition is the first. The
  manager maps into the partition, in this order: the local memory but its last 2 MB (1 MB pages,
  0x211b98), resource 0xb (0xc000 bytes of host memory, 0x211be4) and resource 0xa (0x40000 bytes in the
  last 2 MB, 0x211c08) of its static resource table (0x35ba60, twelve entries of {id, type, offset, size});
  then the FIFO maps 0x20000 bytes of the RSX registers at 0xc00000 (0x21cc34). Each takes an address from
  the partition's allocator (0x2dd46c -> 0x2dce84 -> 0x2cec78, the page size plays no part). The local
  memory is 256 MB on every PS3; any size between 130 and 258 MB gives the same allocator class.
- `gpu_device_map(id)` (0x20db58 -> 0x20b4b0): windows of the RSX registers, 4 KB pages, addresses from the
  partition's allocator: 2 = 0x80100 (0x8000 bytes), 5 = 0x8a000 (0x1000), 6 = 0x200000 (0x1000),
  7 = 0x600000 (0x10000); a mapped device is a DUPLICATE. The ids are only restricted (1, 2, 5, and 9, 11
  with another flag; others succeed without mapping) when lv1's flag 0x363f08 is set, which `gpu_open` does
  for `sys.boot.gos` == 3. lv0 passes that value (lv0 0x80072d0 -> 0x8002810) from a syscon read (block
  0xff, byte 0, & 3; command 0x20 of service 0x14, 0x800c128). It is not public, but it cannot be 3 on a
  console that runs ps2_emu: ps2_emu maps devices 6 and 7 at 0x50100000 and 0x50200000 (0x45890..0x458b4)
  and reads the video input registers of device 6 there, which would fault with nothing mapped.
- `gpu_memory_allocate(size, a2, a3, a4, a5)` (0x20ec9c -> 0x212178): the first free of 16 memory objects,
  handle = slot ^ 0x5a5a5a5a; five resources from first-fit bitmaps (0x217538): the local memory in 1 MB
  units (bitmap based at the local memory's partition address, 0x211c78) and the four others. The address
  is the local memory's partition address plus the block's offset. Nothing in `gpu_open` allocates local
  memory (the only bitmap call it reaches is the bitmap constructor's), so the first block is at 0.
- `gpu_context_allocate(memory_handle, flags)` (0x20f5bc -> 0x21519c -> 0x214eb8): handle = global slot ^
  0x55555555; dma_control = FIFO window + channel << 12 (0x21b5e4; four channels, bitmap 0x20be7c);
  driver_info = resource 0xb + one of three 0x4000 blocks (0x2146f4, bitmap 0x211ea4); reports = resource
  0xa + one of four 0x10000 blocks, reports_size = 0x10000 (0x2143e0, bitmap 0x211cac). The context uses
  the I/O segment 0x80000000 + channel << 28 among those the boot initializer reserved (flag 1 at 0x214dac
  = an already reserved segment, 0x2d9ba8), so the segment table does not change. Only a first context
  with flags 0 is followed.
- ps2_emu maps 64 KB of each of those three regions (0x457c8..0x45814); the driver info has only 0xc000,
  and `write_htab_entry` answers the four pages beyond with ACCESS_VIOLATION, as lv1 does for any page past
  its region (0x2d2510: slot by the address's class, offset below the region size; error 0x997997d2b58e3c01
  -> 0xfffffffb at 0x2ed5fc).

## Logical SPEs: 57, 207, 78, 61

- `construct_logical_spe(pshift1..5, vas_id, type)` (0x31ab6c -> 0x31a34c): each page shift from 12 to 61
  (ILLEGAL naming it), then any above 48 is RESOURCE_SHORTAGE without naming one; the address space has to be
  an object of the partition (NO_ENTRY for the sixth argument; the initial address space is not one); the
  type 0, 1 or 2 (ILLEGAL for the seventh). ps2_emu asks for type 0 (0x2fb734), the only one followed. The
  SPE object takes its id first (0x2fa614 -> 0x2cc64c), then the partition's allocator gives the SPE's
  512 KB window (0x2fecdc) and the shadow registers, 1 << pshift5 bytes (0x2ff4ec); pshift1 to 4 are only
  checked. The three interrupt classes get an outlet each, new objects of the partition after the SPE
  (0x2ff934 -> 0x2df60c). Results: priv2 = window + 0x60000, problem state = window + 0x40000, local
  store = window, 0, shadow, spe id. Both windows count as the partition's pages for `write_htab_entry`.
- `enable_logical_spe(spe_id, resource_id)` (0x2fd394 -> 0x2fbda8): NO_ENTRY for an unknown SPE,
  WRONG_STATE for one already enabled. The resource is an index into lv1's SPE manager (0x373ef0), which
  lv1 fills at boot with the usable SPEs in the ring order 0, 2, 4, 6, 7, 5, 3, 1 starting after the first
  system SPE, so the system SPE (type 2) is the last (0x3b057c, 0x3b02f0); a resource past the list is
  NO_ENTRY for the second argument, one another logical SPE holds BUSY (0x3174e8). Which SPEs are usable
  or system comes from `be.0.spu.faultbm` and `sys.cellos.spu.configure`. **Derived with public facts**:
  every PS3 has 7 of its 8 SPEs enabled and one kept by the system (psdevwiki), and lv1 has a system SPE
  (the isolated modules ps2_emu uses run on it, and a type 1 SPE needs it, 0x31a6c0), so there are 7
  resources and the last is the system one. Resources 0 to 5, the ones ps2_emu uses being 0 to 2, do not
  depend on which physical SPE is off. The system SPE's own path (a partition privilege, 0x3176e0) stops.
- `get_spe_irq_outlet(spe_id, class)` (0x2fc738): the class's outlet; class above 2 ILLEGAL (second),
  unknown SPE NO_ENTRY (first).
- `set_spe_interrupt_mask(spe_id, class, mask)` (0x2fe340): same checks; the mask keeps the class's bits
  (table 0x329a98: class 0 all but bits 3 and 32) and never fails (0x2ffba4). The masks lv1 starts with are
  not determined.

### The SPE running (SPUThread.cpp, RawSPUThread.cpp)

- The physical SPE `enable_logical_spe` binds is an SPU of the emulator run as a raw SPU: the raw SPU of the
  resource's number (ps2_emu uses 0 to 2), its local store in the emulator's SPU area. The class masks set
  so far go to it (0x2ffba4), and an enabled interrupt that becomes pending raises the class's outlet
  (`spu_int_ctrl_t::lv1_raise`).
- The window: the local store is memory (a translation of the partition's to it is cached like the memory
  from address 0); the problem state registers (window + 0x40000) are the raw SPU's (`read_reg`,
  `write_reg`), 32 bits wide. ps2_emu's loader (0x1cc00) stops the SPU, sets SPU_LSLR and SPU_Cfg, runs
  128 two-instruction programs that clear one register each, clears the local store, copies the program and
  starts it at its entry.
- The privilege 2 registers (window + 0x60000) followed: SPU_LSLR (0x4058; only the full 256 KB, the only
  size the emulator's SPU has), SPU_Cfg (0x4078; the signal notification OR modes), and the MFC's SLB:
  SLB_Index_W (0x1108), SLB_ESID_RW (0x1110) and SLB_VSID_RW (0x1118), 8 entries (Cell BE Handbook v1.1
  4.3.3). ps2_emu loads one entry per segment of its table with Ks = Kp = 1 (0x1ce5c..0x1cec4). What lv1
  leaves in the SLB is not determined; the model starts it invalid.
- The shadow registers are lv1's memory (zeroed at construction, 0x2fc250). +0xf00 is the execution state,
  from the SPE object's state word by 0x2f9738 (high word 1 gives 3, 2 gives 2, 0 or 0x10 give 0);
  `enable_logical_spe` sets 1 << 32 | 2 (0x2fbe58), so it reads 3 once the SPE is enabled, which ps2_emu
  waits for before loading (0x1cde8). Other shadow fields stop.
- The MFC translates the partition's 64-bit effective addresses through the SPE's SLB and the hash table of
  the address space the SPE was constructed with (`spu_thread::lv1_translate`): every DMA
  (`do_dma_transfer`, list elements with the command's EAH, proxy commands) and the atomic commands. What
  would make the MFC raise a class 1 interrupt (no segment, no page, protection) stops, and so does a
  segment whose Ks and Kp differ (which one the MFC uses is lv1's MFC_SR1). With an lv1 guest the SPU LLVM
  recompiler keeps EAH and does not inline MFC commands or the PUTLLC16 pattern, which address memory by
  EAL directly.

## Virtual UART: 164, 165, 166

- `configure_virtual_uart_irq(bitmap)` (0x2f2810): the 32-byte bitmap of interrupting ports has to be in the
  partition's memory (NO_ENTRY), in an ordinary memory region with its 32 bytes inside (TYPE_MISMATCH) and
  within one page (ILLEGAL). The page size of the memory from address 0 is not determined; a bitmap inside
  a 4 KB page is inside a page of any size, and one across a 4 KB boundary stops. A second call is
  WRONG_STATE (0x2f1474). The outlet is a new object of the partition (0x2f14b0 -> 0x2df6b8).
- The ports: lparmgr builds port 2, the system manager's, for the partition with a receive buffer of 0x800
  bytes (PMI 0x10084 from lparmgr 0x8001b1c4, lv1 0x29a238 -> 0x2f2540) and is its peer ("lpar_event").
  After loading any guest the Secure LPAR Loader sets up its dispatcher (0x80000af4 -> 0x80000e34), whose
  `vuart_pme::connect` builds port 10 with 0x1000 bytes (0x800081e8). Which other ports the partition has is
  not determined. lv1 builds a port with both triggers and the interrupt mask at 0 (0x2f18d4..0x2f18dc).
- Interrupt state (0x2f0cc4): 8 while the peer is connected, 1 while the peer's buffer holds at most the
  transmit trigger (the peers read what arrives, so always), 2 while the port's free space is at most the
  receive trigger. When a port's state changes lv1 sets or clears its bit in the partition's bitmap as the
  state meets the mask (port n = bit 63 - n % 64 of doubleword n / 64, lv1 stores the doubleword from its
  own copy), counts the ports set and raises the outlet when the count goes from 0 to 1 (0x2f21f0..0x2f2394).
- `read_virtual_uart(port, lpar_addr, bytes)` (0x2f429c): the checks of `write_virtual_uart`; copies what the
  port holds, up to the size asked.
- `get_virtual_uart_param(port, param)` (0x2f34e0) and `set_virtual_uart_param(port, param, value)`
  (0x2f3c0c): port above 255 or absent NO_ENTRY (first), parameter above 7 NO_ENTRY (second). The
  parameters (Linux's names): 0 transmit trigger, 1 receive trigger, 2 interrupt mask (3 bits, ILLEGAL for
  the third argument when setting), 3 receive buffer size, 4 bytes received, 5 and 6 the peer's buffer size
  and bytes, 7 interrupt status; only 0 to 2 can be set (NO_ENTRY for the second otherwise). The values a
  port is built with are not determined, so reading 0 to 2 stops until the partition set them.
- `write_virtual_uart(port, lpar_addr, bytes)` (0x2f2af4): port checks as above; the buffer has to be in
  the partition's memory (NO_ENTRY, second) and in one ordinary region (TYPE_MISMATCH, second); lv1 copies
  what fits into the peer's receive buffer and returns the count. lparmgr reads port 2 as messages arrive
  (16-byte header, then at most 0x800 bytes of payload, 0x8001b014), so the model takes every byte, one of
  the outcomes the console can give; ps2_emu writes again whatever is not taken.

### The system manager (lparmgr's side of port 2)

The messages carry Linux's `ps3_sys_manager_header`; lparmgr dispatches on the low byte of the service id
through its table at 0x8003e020 (services above 0x3d go to service 6's handler).

- Service 8, set attributes (0x8001a6b4): the attribute word unmasks the partition's events of four kinds
  (0x80021848); events queued while masked would be sent then, and none of lparmgr's event sources (the
  system controller's buttons and thermal alerts) fires during the boot. No answer. ps2_emu sends 7.
- Service 9 (0x8001c144), op 1: the **inter-lpar parameter**, the data the GameOS left with lparmgr when it
  booted the PS2 mode (service 10 from the GameOS, at most 0x600 bytes, 0x8001b6c0); the answer is service
  10 with {1, 0, size (16 bits), 0} and the parameter's bytes, and lparmgr's size counts down as it writes
  them, so it is given once. The parameter is the first 0x4f0 bytes of vsh's PS2 boot parameters
  (`/dev_hdd0/tmp/game/ps2bootparam.dat`, psdevwiki PS2bootparam.dat: clock, product code, title id,
  language, time zone, network, video modes, the XMB's "PS/PS2 Upscaler" at 0x4cc and "Smoothing" at 0x4cd,
  ...), which vsh passes to `sys_sm_shutdown(0x8202, buffer, 0x4f0)` (vsh 0xd4e24). RPCS3's lv2 now keeps
  it for lparmgr and reboots into `/dev_flash/ps2emu/ps2_emu.self` (the PS2_LPAR entry of default.spp names
  `/local_sys0/ps2emu/ps2_emu.self`). ps2_emu only parses a parameter of exactly 0x4f0 bytes
  (0x1f750); booted directly, without vsh, lparmgr has none and answers with size 0.
- Service 9, op 2: service 11 with {2, A, B, 0, C (32 bits), D (64 bits)} (0x8001c188). D is +0x60 of
  lparmgr's object for the partition, set only for the GameOS class (0x8001e464) and computed as a boot
  parameter only for "PS3_LPAR" (0x80019754), so 0 for the PS2 partition. ps2_emu keeps only byte 15, as a
  product code if it is 0x83 to 0x8e (0x1f7a0).
- Other operations of service 9 stop.

## Address translation of the guest (PPUThread.cpp, PPUInterpreter.cpp)

ps2_emu runs with translation on: thirteen 256 MB segments of its own table at 0x4ea930 ("work" at 0,
"user stack" 0x10000000, "sb mmio" 0x20000000, "sb work" 0x30000000, "spc area" 0x40000000, "rsx mmio"
0x50000000, "rsx gcmbar1" 0x60000000, "spu2 ram" 0x70000000, "pcm work" 0x80000000, "menu work"
0x90000000, and above 4 GB "iop ram" 0x100000000, "ps2 rom" 0x200000000, "memcard" 0x300000000), entered
into the SLB by its segment interrupt handlers (0x380, 0x480 -> 0x2ac0 -> 0x4a24, slbmte), and pages it
writes with `write_htab_entry`. The model is the architecture's (Book III v2.02 chapter 4):

- A supervisor thread runs one instruction at a time. Its data accesses, and its fetches with IR set, go
  through `ppu_supervisor_translate`: real mode addresses the memory from address 0 (the real mode limit
  lv1 sets is not determined); with relocation the SLB entry whose ESID matches (none: Data or Instruction
  Segment interrupt), then the selected address space's hash table (`lv1_htab_lookup`: primary and secondary
  hash, L and LP as `write_htab_entry` encodes them; no match: Data Storage interrupt with DSISR bit 1, or
  Instruction Storage with SRR1 bit 33), then the PP/key and N/G checks (protection: DSISR bit 4 / SRR1 bit
  36). A failed translation restarts the instruction at the interrupt vector with SRR0 at it.
- The translations are cached per effective page until the SLB changes (`slbmte`, `slbie`, `tlbie`,
  `tlbiel`, which the interpreter now executes) or lv1's hash table does.
- A page in the memory from address 0 is addressed where it lies. A page of a device window goes through a
  scratch page: a load asks lv1 for the registers before the instruction, a store hands them to lv1 after
  it (`lv1_device_access`). Code has to run where it was fetched from (EA equal to the address).
- Not modelled: the reference and change bits of the hash table entries.

## Gigabit Ethernet: 191, 193, 194, 197

The south bridge's dev0 (type 3), opened by ps2_emu. Every call checks the bus (above 4 ILLEGAL, other
than 1 NO_ENTRY, first argument) and device (other than 0 NO_ENTRY, second), then that the device is open.

- `net_set_interrupt_status_indicator(bus, dev, lpar_addr, 0)` (0x308204): WRONG_STATE unopened, a non-zero
  fourth argument ILLEGAL, the address 8-byte aligned in an ordinary memory region of the partition (ILLEGAL
  third), a second indicator DUPLICATE.
- `net_set_interrupt_mask(bus, dev, mask, 0)` (0x307fe0): WRONG_STATE unopened (state 2, 0x3080cc), a
  non-zero fourth argument ILLEGAL (0x308198); the mask goes to the device object (+0x20).
- `connect_interrupt_event_receive_port(bus, dev, port, irq)` (0x305cf0 -> 0x236924): irq 0 only (NO_ENTRY
  fourth), the device opened (NO_ENTRY), the port an event receive port of the partition (NO_ENTRY third),
  connected once (BUSY fourth).
- `net_control(bus, dev, code, v1, v2, v3)` (0x307d2c -> 0x244a84): codes 1 to 11. Code 1 is the MAC
  address, RPCS3's (`np_handler::get_ether_addr`). Code 2 is the port status (bit 0 link, bit 1 full duplex,
  bits 4 to 6 the speed); the model's cable is RPCS3's network setting, and only "disconnected" is followed
  (see "Approximations"). Code 4 is a traffic class's VLAN id (table in the code). Its DMA region uses the
  south bridge's I/O space as the USB controllers' do (type 2, 0xc0000000 for ps2_emu's first).

## Storage devices (bus 4): 170, 174, 197

lv1's storage subsystem (0x2527d0) creates its devices as it finds them; ps2_emu looks them up by type (its
scan 0x1d954 reads `bus{n}.type`, `num_dev` and `dev{n}.type`, then the bus and device `id`): the BD drive
(type 5, its CDVD, 0x224b0), the disk (type 0, "pata", 0x42ecc) and the flash (type 14, 0xfbc60).

- Repository (0x2524a4, 0x252670): `bus4` id 4, type 5, `num_dev` the devices registered. A device takes the
  next slot of a counter that starts at -1 (0x252808) when it is created; the slot is its `id`, the one the
  hypercalls take (0x236594: slots 0 to 6, -1 the storage system itself). Its node index is its registration
  order (0x252c50). Creation order (0x2528dc): slot 0 the type 0xff device (0x287a54), slot 1 the flash
  (0x288214: type 0xe, 0xfe with a vflash), then the ATA ports 0 and 1 (0x252924; the ATAPI device type 5,
  0x27187c, the disk type 0, 0x26d9d0), and a vflash device only with one (0x25deb0). Every device has
  `intr` 0 = {2, 0} (0x25254c). The public 3.41 repository dump (a NOR console: 0xff, 0xfe, BD, disk,
  vflash) matches this order. The model's console: 0xff, flash (0xe), BD (5), disk (0), in slot order (see
  "Approximations"). Other nodes (`blk_size`, `n_blocks`, `port`, `meddling`, `hosttype`, regions) stop.
- `open_device(4, dev, flags)` (0x2545a4): the partition's LAID decides. A device not yet registered
  opens only for 0x1070000001000001; with no access list (`[[dev + 0x90] + 0x930]`) a disk opens only for
  0x1070000002000001 and 0x1070000001000001 (DENIED_BY_POLICY), other types for anyone. Two partitions can
  hold a device, a third is RESOURCE_SHORTAGE, the same one twice BUSY. The disk's access list is not
  followed (opening it stops).
- `connect_interrupt_event_receive_port(4, dev, port, irq)` (0x23698c -> 0x255254): irq 0 (NO_ENTRY fourth),
  the port an event receive port of the partition and the partition an opener (NO_ENTRY third), once (BUSY
  fourth).
- `allocate_device_dma_region(4, dev, ...)`: through the south bridge's ATA controller of the device's port
  (0x258698; `[[dev + 0x1638] + 0x578] + 0x10` for the ATAPI device). The south bridge devices (0x3a9718, index:
  type): 0: 2 (Ethernet), 1: 0xa, 2: 0xb, 3: 8, 4: 9 (USB), 5: 4, 6: 0 (PCI), 7: 0xc, 9: 0xe, 0xa: 0xe,
  0xb: 7, 0xc: 0xe, 0xd: 0x10; the ATA controllers are 1 and 2, io base 2 << 32 and 3 << 32 (0x22d35c,
  0x22d374, the type table at 0x22d244: 2: 1, 4: 6, 7: 6, 8: 4, 9: 5, 10: 2, 11: 3, 12 and 14: 7, others 0).

### Storage commands: 248, 254 (lv1_bdvd.cpp)

- `storage_send_device_command(dev, cmd, cmdbuf, cmdbuf_size, databuf, databuf_size) -> tag` (0x3094e4 ->
  0x251be0): the device by slot (NO_ENTRY without an argument), held open by the partition (WRONG_STATE), then
  its method: a tag (16 per device, the lowest free, BUSY when none, 0x25397c); a data buffer with an address
  and a size has to be partition memory to the end of its region (an I/O address of the device's DMA regions
  is taken as such, not followed). The ATAPI device (0x272be4) takes commands 1, 2, 0x10, 0x11, 0x13, 0x14,
  0x19 to 0x1c, 0x21, 0x24, 0x26, 0x27, 0x29, 0x30 (ILLEGAL otherwise), checks lv1's access list for storage
  commands (0x31d34c) and queues the command for a timer (16 entries at +0x1880).
- The access list is the `SCE_CELLOS_SS_INIT_LV1_ACL` entry of default.spp: 32-byte entries {LAID, LAID mask,
  key (command << 32 | ATAPI operation code, 0 = every command), permissions}; its storage table allows every
  command to the LAIDs 0x101..., 0x102... (the PS2 partition's) and 0x104..., and single commands to
  Linux's (0x108...).
- Command 1 sends a packet: Linux's `lv1_atapi_cmnd_block` (packet, length 12, blocks, block size, protocol
  0/1/2/3, direction). The BD drive model (`lv1_bdvd.cpp`) answers from the MMC command set; the status is 0
  or CHECK CONDITION with the sense key, ASC and ASCQ in its low 24 bits (Linux `decode_lv1_status`).
  Implemented: MODE SENSE(10) and MODE SELECT(10) of page 0x1a (Power Condition).
- `storage_check_async_status(dev, tag) -> status` (0x30926c -> 0x255ad8): the same device checks, a tag above
  15 ILLEGAL; a request of the partition that is done gives its status and frees the tag, anything else is
  NO_ENTRY. ps2_emu's CDVD calls it from its interrupt handler (0x222cc) and waits for bit 0x4000 of its event
  flags (0x22254).
- The disc: `/dev_ps2disc/` of vfs.yml. The user's test disc is in the host's optical drive (`D:/`).

## Memory: 0

- `allocate_memory(size, page_shift, arg3, flags) -> lpar_addr, 1` (0x2df470 -> 0x2dee58): size above 1 << 62
  or not a multiple of the page ILLEGAL (first), page shift outside 12 to 61 ILLEGAL (second), arg3 above 1
  NO_ENTRY (third), flags above 0xf ILLEGAL (fourth). lv1 takes the pages from its physical pool (0x2c14bc) and
  the address from the partition's allocator (0x2dea14); the second result is 1. Only arg3 = 0 and flags = 0
  are followed. The model backs the region with the emulator's main memory (`memory_regions`), reachable
  through the page table and the SPEs' DMA.

## The AV settings manager (vUART port 0)

lparmgr's "avset" (constructed with port 0 at 0x80007654, the port built for PS3_LPAR and the PS2 partitions
at 0x800073b8 -> 0x80007210 with a receive buffer of 0x800) serves Linux's PS3AV protocol: packets {u16
version 0x205, u16 size, u32 cid, ...} (receive loop 0x8000883c, command table 0x8000d460, answer 0x80007cf4).
The command executor (0x80007bb4) asks the command's class for the packet size (+0x18, 0 = any; status 0xa
when it differs), whether it is allowed (+0x28, status 0xc), then runs it (+0x10): code 0 answers at once,
code 1 queues the command (0x80007b04) and the answer comes when the AV manager runs it again internally
(its r7 = 0) after the System Controller (`/dev/sc0`) answers. A version other than 0x205 is status 3; an
unknown cid is dropped. `scratchpad/avcmd.py` resolves a cid's class. Modelled: 0x01000001 and 0x02000001
(status 0, they notify lparmgr objects), 0x02000003 (audio outputs, status 0).

The AV settings depend on state lparmgr keeps from the system's boot and the partitions it ran before
(the mute state object 0x800067c4, the AV version byte +0x210 from System Controller command 0x30 that sets
+0x212/+0x213 at 0x80006c7c), and the audio and video commands go to the System Controller. Next stop:
0x00020002 (`0205 0008 00020002 00000001`), queued: mute state (0x80016ce0, 0x80005f08), System Controller
packet 0x13 (0x80016ddc), status from its answer code (0x80016c98: 0x85 or 0x93 = 0, else 2).

## USB host controllers (lv1_usb.cpp)

ps2_emu drives the OHCI of controller 0 (interrupt 0x10) and the EHCI of controller 1 (interrupt 0xb)
itself; lv1 only maps their windows. The model follows OHCI 1.0a and EHCI 1.0 with big-endian registers
and descriptors (the Linux PS3 glue):

- OHCI: every operational register, frames every millisecond on the "lv1 USB" thread (frame number to the
  HCCA, periodic, control and bulk lists, the done queue and its write-back, interrupts through the
  controller's outlet). The root hub has 2 ports (ps2_emu handles HcRhPortStatus[0] and [1] only).
- EHCI: the capability and operational registers ps2_emu uses, micro-frames every 125 us, both schedules
  walked (QH, iTD, siTD, FSTN), the doorbell, frame list rollover, interrupts.
- Device DMA reaches the partition's memory through the DMA regions and mappings lv1 keeps
  (`lv1_map_device_dma_region`), from the thread's own view of the memory.
- **No device is attached yet** (all ports empty; a transfer with work to do stops). On the console the EHCI
  root ports carry the internal Bluetooth module and the card reader, and the front ports hang off an
  internal hub (the Linux PS3 kernel overview), so the pads are not there yet.

## Not determined yet (the emulation stops there)

- **DMA addresses of the other south bridge devices** (only the USB controllers' I/O space is followed).
- **The GPIO interrupt** (`bus1.dev3.intr`), which depends on the hardware configuration.
- **The threads' state when lv1 starts them** (`activate_logical_pu`, PMI 0x10007): the MSR, the registers
  and the Decrementer, which the model still starts at 0x7fffffff, the value the guest itself writes to mean
  no deadline (ps2_emu.elf 0x39d0).
- What PMI 0x10034 (0x3018fc -> 0x30aae8, an index up to 7 per partition) and 0x1002e give the partition.
- The end of interrupt of an I/O interrupt outlet, which re-arms its interrupt source.
- **The SPEs' other registers**: the privilege 2 registers but SPU_LSLR, SPU_Cfg and the SLB loads, the
  shadow registers but the execution state, class 1 interrupts (MFC translation faults) and
  `get/clear_spe_interrupt_status`.
- **The devices on the USB ports** (Bluetooth module, card reader, internal hub and what is plugged in).
- **The Gigabit Ethernet device's traffic**: descriptors, DMA and interrupts, and a link up.
- **The storage commands** other than ATAPI packets to the BD drive, the other BD drive commands, the disk
  and the flash.
- **lparmgr's AV settings manager** (vUART port 0): next stop.
- The EHCI and OHCI interrupts, the virtual UART and the SPE outlets are re-armed on end of interrupt
  (listeners, 0x2dfd88); other I/O interrupt outlets stop there.
- The rest of the system manager services, and writes to port 10.
- `read_htab_entries` with the largest indices, for which lv1's bound check wraps and it reads past its
  table: it stops.

## Approximations

Values the model uses although lv1, ps2_emu and public sources do not determine them for a CECHA01. The
standing rule is that an undetermined value stops the emulation; each entry here is an exception, and
only the user approves one.

### What happened (2026-09-27)

The south bridge revision was put into `bus1.id` with the value of a public dump without the user's
approval; the user was only told afterwards, and the report presented it as already settled. When the same
revision turned out to decide `allocate_ioid`'s result, the model first stopped there, the user confirmed
the stop, noticed the earlier `bus1.id` value had never been approved, and then approved the approximation
for both. From now on a value is only approximated after the user approves it, before it is written.

### Approved by the user

- **South bridge revision** (`sb_revision_approximation`, approved 2026-09-27). lv1 reads it from the chip
  (0x24000087000, 0x22c66c). The model uses 0x3000103, the `bus1.id` revision word of the public 3.41
  GameOS repository dump on psdevwiki (Repository_Nodes). That console's model is not known: its platform
  id `CokF10` carries the chassis letter F, which psdevwiki only defines from the COK-002 on, while the
  CECHA01 has a COK-001. Used for:
  - the second value of `bus1.id` (ps2_emu never uses it);
  - the ioids lv1's south bridge devices hold, so the ioid `allocate_ioid` returns (10). ps2_emu only
    hands it back to `release_ioid`.

### Under the criteria of 2026-09-27 (used values that lv1, ps2_emu and public sources do not fix)

The user's criteria: a value that does not affect the boot may stay stopped; a value that is used and
cannot be determined is approximated, as little as possible, documented here and commented in the code.

- **The PS2 chip's position on the south bridge's PCI bus** (`ps2_chip_pci_dev`, device 5, function 0).
  lv1 scans devices 0 to 15, functions 0 to 3 (0x2331ec) and routes interrupts to devices 5 to 8 of bus 0
  (0x22f904..0x22f968), so the chip is in one of those four slots; which one is board wiring. The
  position only goes back to lv1 in `pci_config_read/write` and decides the interrupt number (0x22f478:
  5 -> 0x36, 6 -> 0x33, 7 -> 0x34, 8 -> 0x35), and ps2_emu does not read this device's `intr` node, which
  therefore stays unmodelled.
- **The chip's first BAR is a memory one of at most 1 MB** (`ps2_chip_bar0_size`). lv1 records a smaller
  memory BAR as 1 MB (0x232d18) and places the bus's first device at the start of the PCI window, so the
  window is 0x60000000 with 1 MB for any BAR up to 1 MB; ps2_emu maps the first memory window it finds
  and uses 4 KB of it (0x1d4ec..0x1d528).

- **System manager service 11's A, B and C are sent as 0** (2026-09-28). A and B are lparmgr bytes at
  0xc000d35d/e and C the system controller's wake source (0xc000d2d8); ps2_emu reads only byte 15 of the
  answer (0x1f770..0x1f7b0), so they cannot change the boot.

- **The Sony registers of the USB OHCI window** (0x800 to 0xfff): the model keeps what was written.
  ps2_emu's reset handshake at 0xff0 (bits 16 and 17 to read back set) and its writes to 0x804 and 0x80c
  are all it does with them.
- **USB controller constants that are not public**: OHCI HcRhDescriptorA's reset values but NDP (0; ps2_emu
  sets NPS and clears PSM), EHCI CAPLENGTH (0x10; ps2_emu finds the operational registers through it),
  HCSPARAMS but N_PORTS (no port power control, one companion owning both ports), HCCPARAMS (0: 32-bit,
  1024-entry frame list, no park). The port counts (2) are derived from ps2_emu's driver.

- **Gigabit Ethernet port status with the link down** (`net_control` code 2, 2026-09-28): what the PHY's
  speed method answers with no link has not been followed; the call succeeds with no bit set. ps2_emu only
  tests bit 0, and a failure takes it down the same path (0x26e98..0x26eb4). RPCS3 with its network
  enabled (a link up) stops.
- **An SPE outlet asks again while an enabled interrupt of its class is pending** (INT_Stat & INT_Mask) at
  its end of interrupt (2026-09-28); lv1's path from the SPE interrupt to the outlet has not been followed.
- **ps2_emu's word store to the first half of SPU_Cfg is ignored** (0x3f400, 2026-09-28). The register is
  64 bits wide, the modes are bits 62:63 and the first half is reserved; the handbook does not define an
  access of another size. The value (3) is the one the loader already stored as a doubleword (0x1cc54).

- **The model's storage devices** (2026-09-28): the CECHA01 has NAND flash, so no vflash (the loader
  parameter `sys.flash.ext` that makes one, 0x252870, is the NOR models'; psdevwiki: the vflash is on the
  disk of NOR consoles); its BD drive is on ATA port 0 and its disk on port 1, as on the console of the public
  3.41 dump (BD port 0, disk port 2 = port 1 master); the devices register in slot order, as there. So bus 4
  holds 0xff, flash, BD and disk with ids 0 to 3. ps2_emu finds them by type; the ids only come back in
  hypercalls.

- **Storage commands complete when they are sent** (2026-09-28): lv1 queues a command and a timer runs it on
  the device; the model runs it within `storage_send_device_command` and the request is done when the call
  returns (the event port is raised then). ps2_emu sends with EE off and stores the tag before enabling it
  (0x221c4..0x22254), so its interrupt handler still sees the tag.
- **The BD drive's Power Condition page starts with no timer** (2026-09-28): the drive firmware's values have
  not been determined; ps2_emu only keeps them and then selects both timers off.
- **`ss.param.product.mode` is 0xff** (2026-09-28): the console's EEPROM flag, "not in product mode" on a retail
  console as the public 3.41 dump shows; ps2_emu only compares it with 0xff (a failed read counts the same).
- **The disk's region table is not empty** (2026-09-28): the count lv1 reads from the disk
  (`[[dev + 0x90] + 0x930]`) decides whether the disk opens for the PS2 partition; a disk the GameOS formatted
  has regions (the public dump lists three), so it opens.
- **`allocate_memory` succeeds** (2026-09-28): the physical memory lv1 has left and any limit for the partition
  have not been followed; in the PS2 mode the GameOS partition does not exist. ps2_emu's memory card cache (17
  MB) is the first such allocation.

### Not yet approved (decided while modelling, awaiting the user)

- **IOIFC `trxba` is zero.** A hardware register of the south bridge that nothing in lv1 writes; lv1 prints
  a warning when it is not zero (0x22dc7c). It would move every USB DMA address.
- **The Decrementer starts at 0x7fffffff** when lv1 starts the thread (`activate_logical_pu` not followed).
- **Registers lv1 leaves undefined after a hypercall** (see "Status codes and registers"): the model gives
  0 for the unset results of runtime-registered calls (lv1 leaves stack residue) and does not reproduce
  r0, CTR, XER and the volatile CR fields. ps2_emu provably never reads them.
