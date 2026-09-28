# Running ps2_emu.self on RPCS3: status and what is missing

This branch runs the PlayStation 2 emulator of the first PlayStation 3 model, `ps2_emu.self` from the CECHA01's
firmware (4.93), the way the console does: not as a GameOS process but as the operating system of its own
logical partition, on top of a model of the hypervisor (lv1) written from the decrypted `lv1.elf` 4.93.
`lv1.md` documents every hypercall and device the model follows, with the lv1 addresses it was read from, and
lists every value that had to be approximated.

On the real console `ps2_emu.self` does not emulate the Emotion Engine or the Graphics Synthesizer: the CECHA01
carries the PS2's EE+GS chip on a PCI bus behind the south bridge, and ps2_emu drives it. ps2_emu itself
provides everything around the chip (the IOP side, SPU2 on an SPE, the CDVD drive through the BD drive, the
memory cards on the hard disk, USB pads, the network, video output through the RSX and audio). On RPCS3 the
chip has to be provided by an emulator core; `PS2_CORE_INTEGRATION.md` describes that interface.

## How to try it

1. Put the firmware's `ps2_emu.self` in `dev_flash/ps2emu/` (it is part of every firmware's `dev_flash`).
2. Optionally point `/dev_ps2disc/` in `vfs.yml` at a PS2 disc: a drive root (`D:/`, read raw through
   `\\.\D:` on Windows) or an ISO image.
3. Boot `dev_flash/ps2emu/ps2_emu.self` directly, or launch a PS2 disc from the XMB (vsh's `sys_sm_shutdown(0x8202)`
   now stores the PS2 boot parameters for lparmgr and reboots into ps2_emu).

The guest runs on the PPU interpreter, one instruction at a time (see "Performance" below).

## What works

Boot order, each step documented in `lv1.md`:

- Loading the image as a guest OS: two PPE threads from the system reset vector, real mode, the guest's own
  interrupt vectors (0x500 external, 0x900 decrementer, 0xc00 hypercalls), `lv1_pause`.
- Guest MMU: virtual address spaces and the hashed page table (`construct_virtual_address_space`,
  `write_htab_entry`, `select_virtual_address_space`), SLB instructions, storage interrupts, device windows
  through a scratch page (`PPUThread.cpp`, `PPUInterpreter.cpp`).
- Interrupts: outlets, plugs, event receive ports, end of interrupt.
- Repository (lpar 1): the buses and devices ps2_emu looks for, including the storage bus.
- Memory: the 64 MB from address 0, `allocate_memory`.
- South bridge: USB OHCI/EHCI controllers (`lv1_usb.cpp`, no devices attached), Gigabit Ethernet setup,
  I/O address spaces and DMA regions, IOPTE mapping.
- PCI: the PS2 chip on bus 2 (config space, BAR0 window, DMA through the PCI bridge). Its register stores are
  recorded; loads stop.
- RSX: `gpu_open`, device maps, memory and context allocation.
- Logical SPEs: they run on RPCS3 raw SPUs (local store, problem state, privilege 2 SLB, shadow registers,
  MFC address translation through the SPE's SLB and the page table). SPU2's SPE is loaded and started.
- Virtual UART: port 2 (lparmgr's system manager: attributes, inter-lpar parameter) and port 0 (lparmgr's AV
  settings, the PS3AV protocol, first three commands).
- Storage: the BD drive (ATAPI packets, `lv1_bdvd.cpp`: MODE SENSE/SELECT), the disk opened for the memory
  card cache, asynchronous request status.

## Where it stops today

`lv1_write_virtual_uart(0, ...)`: the AV settings command `0x00020002` (audio). lparmgr's AV settings manager
keeps state from the system's boot (mute state, the AV version read from the System Controller) and queues
audio and video commands until the System Controller answers.

## What is missing, in the order ps2_emu will need it

1. **lparmgr's AV settings and system manager.** Decided direction: run the real lparmgr (lv1 process 1,
   `proc1` inside `lv1.elf`) instead of rewriting its services. That needs:
   - a loader for lv1 processes (text at 0x80000000, data at 0xc0000000, in an address space of their own);
   - the lv1 UX kernel system calls lparmgr uses (about 22: `sc` with the number in r11, 7 = open, ...) and
     the process management calls (0x10000+, listed in `lv1.md`), taken from lv1's own implementation
     (`src/UX/...` in `lv1.elf`);
   - the files it opens: `/proc/partitions/<n>/vuart/<m>` (the peer side of the partition's ports),
     `/dev/sc0` (the System Controller, whose answers must be approximated, documented one by one),
     `/dev/rflash`, `/rmt/av_setting.conf`;
   - booting the PS2 partition as lparmgr's initial guest (its boot parameter from the System Controller's
     EEPROM chooses it, 0x80018e60), so that the GameOS's history does not have to be replayed.
   The hand-written port 0 and port 2 services in `lv1.cpp` are then replaced.
2. **The BD drive with media.** Reading sectors (READ(10)/(12), the vendor raw read the PS3 drive offers,
   GET CONFIGURATION with the PlayStation disc profiles, READ TOC, REQUEST SENSE, TEST UNIT READY, ...), from
   the medium `/dev_ps2disc/` names. Each drive-specific answer is an approximation to document.
3. **The disk and the flash.** ps2_emu keeps its memory card images (`/savedata/vmc/*.VM2`) and a virtual
   HDD on the PS3 disk, and reads the flash (fonts for its menu). The disk's regions, their encryption and
   the file systems on them (lv1 handles the disk encryption; the files are the GameOS's) need a model or a
   bridge to RPCS3's `dev_hdd0`/`dev_flash`.
4. **The PS2 chip.** Register loads (BAR0 at 0x60000000), its DMA into partition memory, its interrupt, and an
   EE+GS core behind it. See `PS2_CORE_INTEGRATION.md`.
5. **Video.** The GS output reaches the screen through the RSX (the FIFO and display buffers ps2_emu
   programs through lv1's GPU calls).
6. **Audio.** SPU2 runs on an SPE; its output goes to the RSX audio block (lv1 audio DMA and notifications).
7. **Controllers.** Devices on the USB root ports (the internal hub, a DualShock 3, the Bluetooth module)
   behind the OHCI/EHCI models already in `lv1_usb.cpp`.
8. **Network** (optional): Gigabit Ethernet descriptors, DMA and interrupts, link up.
9. **Other lv1 services** as they are reached (see "Not determined yet" in `lv1.md`).

## Performance

The guest PPU code runs on the interpreter, one instruction at a time, because address translation and
storage interrupts are checked per instruction. That is far too slow for games. Options, none started:
a fast path for pages whose translation is cached, and compiling ps2_emu's hot code (its IOP core is the
hottest part) with the PPU recompiler once translation is stable.

## Known issues

- Once, ps2_emu's SPE loader (128 run/stop pairs microseconds apart) left a raw SPU reported running; the
  stop request in `lv1_device_access` now waits with a limit and reports the SPU state instead of hanging.
- Runs are not fully deterministic: the two PPE threads race in ps2_emu's own startup.
