#pragma once

#include <optional>
#include <span>

#include "util/types.hpp"
#include "Loader/ELF.h"

class ppu_thread;

// Status codes returned by lv1 hypervisor calls, named as the Linux PS3 platform code names them
// (arch/powerpc/include/asm/ps3.h, enum lv1_result).
enum lv1_result : s64
{
	LV1_SUCCESS = 0,
	LV1_RESOURCE_SHORTAGE = -2,
	LV1_NO_PRIVILEGE = -3,
	LV1_DENIED_BY_POLICY = -4,
	LV1_ACCESS_VIOLATION = -5,
	LV1_NO_ENTRY = -6,
	LV1_DUPLICATE_ENTRY = -7,
	LV1_TYPE_MISMATCH = -8,
	LV1_BUSY = -9,
	LV1_EMPTY = -10,
	LV1_WRONG_STATE = -11,
	LV1_NO_MATCH = -13,
	LV1_ALREADY_CONNECTED = -14,
	LV1_UNSUPPORTED_PARAMETER_VALUE = -15,
	LV1_CONDITION_NOT_SATISFIED = -16,
	LV1_ILLEGAL_PARAMETER_VALUE = -17,
	LV1_BAD_OPTION = -18,
	LV1_IMPLEMENTATION_LIMITATION = -19,
	LV1_NOT_IMPLEMENTED = -20,
	LV1_INVALID_CLASS_ID = -21,
	LV1_CONSTRAINT_NOT_SATISFIED = -22,
	LV1_ALIGNMENT_ERROR = -23,
	LV1_HARDWARE_ERROR = -24,
	LV1_INVALID_DATA_FORMAT = -25,
	LV1_INVALID_OPERATION = -26,
	LV1_INTERNAL_ERROR = -32768,
};

// The memory a PlayStation 2 emulator partition has from logical partition address 0: 1 << 0x1a bytes. The
// PS2_LPAR entry of default.spp gives that log2 size at +0x148 (0x18 for GameOS, the 16 MB of its
// bi.pu.1.rm_size), and the System Manager allocates it with flag 8 right after constructing the partition,
// which lv1 places at address 0 (lv1 4.93 0x2dea14 -> 0x2cec78). ps2_emu.elf lays its regions out downwards
// from 0x4000000 (0x47f8..0x490c).
constexpr u32 lv1_guest_region0_size = 0x4000000;

// The PlayStation 2 emulators in /dev_flash/ps2emu are not GameOS processes. lv1 loads them in place
// of the GameOS kernel and each runs as the operating system of its own logical partition. They are
// told apart from everything else by their SELF program authority ID and program type.
bool lv1_is_guest_os(u64 program_authority_id, u32 program_type);

// Load a guest operating system image into a fresh partition and start both PPE hardware threads at
// the system reset vector, the way the hardware leaves a reset.
bool lv1_load_guest_os(const ppu_exec_object& elf, const std::string& path);

// The hypervisor call instruction (sc with LEV=1) executed by a guest operating system thread
void lv1_hypercall(ppu_thread& ppu);

// The timebase the partition's threads read. The console's counts at 79.8 MHz: the repository gives that
// frequency as be.0.tb_clk (0x4c1a6c0, psdevwiki Repository_Nodes; a fortieth of the 3.192 GHz of be.0.nclk),
// and Linux sets its own timebase frequency from that node (arch/powerpc/platforms/ps3/time.c). RPCS3 runs
// GameOS processes on an 80 MHz timebase, so the partition's is kept apart.
constexpr u64 lv1_timebase_freq = 79'800'000;
u64 lv1_timebase();

// The translation of a virtual address through the hash table of the partition's selected address space
struct lv1_translation
{
	u64 lpar_addr; // the logical partition address the virtual address falls on
	u32 page_shift;
	u64 hpte_r; // the second doubleword of the entry (protection and storage control bits)
};

// Look a virtual address, given as a VSID and an offset in its 256 MB segment, up in the hash table the
// partition's threads translate through (SDR1). large and lp are the SLB entry's L and LP fields.
std::optional<lv1_translation> lv1_htab_lookup(u64 vsid, u64 offset, bool large, u32 lp);

// Changes whenever that table may translate differently
u64 lv1_htab_generation();

// A load (store = false) or store of size bytes at a logical partition address outside the partition's
// memory from address 0: a device's registers the partition mapped. data holds the bytes in storage order.
void lv1_device_access(u64 lpar_addr, u8* data, u32 size, bool store);

// The emulator address of memory at a logical partition address outside the partition's memory from
// address 0 (a logical SPE's local store), if there is memory there
std::optional<u32> lv1_memory_address(u64 lpar_addr);

// Whether the emulated system is a partition lv1 runs a guest operating system in (lv1_load_guest_os)
bool lv1_guest_running();

// What the GameOS hands to the next partition through lparmgr, the "inter-lpar parameter" (sys_sm_shutdown's
// parameter): lparmgr keeps it and gives it to the partition that asks for it on its system manager port
void lv1_set_inter_lpar_parameter(std::span<const u8> parameter);

// The PPU thread IDs of the partition's two PPE hardware threads, for interrupt delivery
void lv1_register_guest_threads(u32 thread0_id, u32 thread1_id);
