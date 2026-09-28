#include "stdafx.h"
#include "lv1.h"
#include "lv1_usb.h"
#include "lv1_bdvd.h"

#include "Emu/IdManager.h"
#include "Emu/System.h"
#include "Emu/Memory/vm.h"
#include "Emu/Cell/PPUThread.h"
#include "Emu/Cell/SPUThread.h"
#include "Emu/Cell/lv2/sys_process.h"
#include "Emu/NP/np_handler.h"
#include "Emu/system_config.h"
#include "Emu/Cell/timers.hpp"
#include "Emu/Cell/lv2/sys_time.h"
#include "Crypto/key_vault.h"
#include "Utilities/mutex.h"
#include "Utilities/StrUtil.h"
#include "util/asm.hpp"

#include <deque>
#include <map>
#include <optional>
#include <span>
#include <set>
#include <tuple>

LOG_CHANNEL(lv1);

namespace
{
	// The inter-lpar parameter lparmgr (lv1 process 1) holds: what the GameOS left with it (service 10 from
	// the GameOS, 0x8001b6c0, at most 0x600 bytes) for the next partition. lparmgr outlives the partitions, so
	// the parameter outlives the emulated GameOS that set it.
	shared_mutex g_inter_lpar_parameter_mutex;
	std::vector<u8> g_inter_lpar_parameter;

	// Bumped whenever the hash table SDR1 points to may translate differently (an entry written, another
	// table selected), so that the PPE threads drop the translations they cached
	atomic_t<u64> g_htab_generation{0};

	// APPROXIMATION, approved by the user on 2026-09-27 (lv1.md, "Approximations"): the south bridge revision
	// register lv1 reads at boot (0x24000087000, 0x22c66c) has not been determined for a CECHA01. The model
	// uses the revision word of the public 3.41 GameOS repository dump (psdevwiki Repository_Nodes, bus1.id,
	// platform "CokF10", console model unknown), whose chip type (bits 24..29) is 3.
	constexpr u64 sb_revision_approximation = 0x3000103;

	// The ioids of I/O address space 0 in use when the guest starts: lv1 reserves 0 and 1 when it creates the
	// space (0x2d91e4..0x2d92b0), and every south bridge device it creates takes the lowest free one (0x22de08)
	// except device 6 and the type 0x10 device (0x22ddf4, 0x22ddf8). With chip type 3 or 4 lv1 creates devices
	// 0 to 4, 7, 0xc and 9, and device 6 as well for type 3 (0x3a9914..0x3a9cec): eight ioids.
	// The PS2 chip (EE+GS) on the south bridge's PCI bus, the one device lv1's scan finds there on a CECHA01
	// (0x2331ec scans devices 0 to 15, functions 0 to 3; a console without the chip, the public 3.41 dump, has
	// no device on bus2). Its PCI id is what ps2_emu looks for (ps2_emu.elf 0x1d404: 0x820e104d). lv1 hides only
	// the ids of its known table (0x35cc08: 104d:81ff, 104d:8183, 8086:1076), so the chip is bus2's device 0
	// (the id is the index, 0x23296c).
	// APPROXIMATION (lv1.md "Approximations"): its position on the bus. lv1 wires interrupts to devices 5 to 8
	// of bus 0 (0x22f904..0x22f968), so the chip is one of those; which one is not public. The position only
	// goes back to lv1, in lv1_pci_config_read/write, and decides the interrupt number, which ps2_emu does not
	// read for this device.
	constexpr u64 ps2_chip_pci_bus = 0; // the scanned bus (0x2329c0: the host's bus number, 0 at 0x231ac0)
	constexpr u64 ps2_chip_pci_dev = 5;
	constexpr u64 ps2_chip_pci_fun = 0;
	constexpr u64 ps2_chip_pci_id = 0x820e104d;

	// APPROXIMATION (lv1.md "Approximations"): the chip's first base address register is a memory one of at
	// most 1 MB. lv1 records any memory BAR below 1 MB as 1 MB (0x232d18) and gives the first device of the bus
	// the start of the PCI memory window (0x233064 from the cursor 0x60000000, the south bridge device 6 region
	// 2 at 0x3a9db0, since lv1's default configuration has no sys.lv1.large_pciex, lv1 0x1d0d30). ps2_emu maps
	// the first memory window it finds and uses 4 KB of it (0x1d4ec..0x1d528).
	constexpr u64 ps2_chip_bar0 = 0x60000000;
	constexpr u64 ps2_chip_bar0_size = 0x100000;

	std::set<u64> initial_ioids()
	{
		const u64 chip_type = (sb_revision_approximation >> 24) & 0x3f;
		ensure(chip_type == 3 || chip_type == 4);

		std::set<u64> ioids;

		for (u64 id = 0; id < 2 + 8; id++)
		{
			ioids.emplace(id);
		}

		return ioids;
	}

	// lv1 virtual interrupts (lv1 4.93): an interrupt source is an outlet, a partition object shared by event
	// receive ports and I/O interrupt outlets (0x2df60c, 0x2df6b8). An outlet is a latch: raising it sets it
	// and raising it again before its end of interrupt changes nothing (0x2df808). Each PPE thread has 256 plugs
	// with a status and a mask bitmap indexed by plug (plug n is bit 63 - n % 64 of dword n / 64, 0x2c65b8); the
	// status bit of a plug is set while its connected outlet is raised.
	struct lv1_outlet
	{
		u32 hw_thread = umax; // PPE thread whose plug the outlet is connected to (umax: none)
		u32 plug = 0;
		bool raised = false;
		bool event_port = false; // made by construct_event_receive_port rather than construct_io_irq_outlet
	};

	struct lv1_thread_interrupts
	{
		std::array<u64, 4> status{}; // plugs whose connected outlet is raised
		std::array<u64, 4> mask{}; // plugs enabled by lv1_set_interrupt_mask
		std::map<u32, u64> plug_outlets; // the outlet connected to each plug
	};

	// A virtual address space: a hashed page table of 128-byte PTE groups, eight 16-byte entries each (Book
	// III v2.02 4.4.2), and the large page sizes it was constructed with. lv1 4.93 keeps the same things in
	// its VAS object (0x2d1fdc: log2 of the table size at +0x74, page sizes at +0x60, their number at +0x70).
	struct lv1_vas
	{
		u32 htab_log2 = 0;
		u32 page_size_count = 0;
		u64 page_sizes = 0;
		std::vector<u64> htab; // two doublewords per entry
	};

	struct lv1_state
	{
		shared_mutex mutex;

		std::map<u64, lv1_outlet> outlets;

		// The outlet each I/O interrupt of the south bridge is connected to, by interrupt id
		std::map<u64, u64> io_irq_outlets;

		lv1_thread_interrupts irq[2]{};
		u32 ppu_ids[2]{};

		std::map<u64, lv1_vas> vases;

		// The address space whose hash table SDR1 holds. SDR1 is not duplicated for multithreading (Cell BE
		// Registers v1.5 Table 12-1), so both PPE threads translate through the same one.
		u64 selected_vas = 0;

		// Devices the partition has opened, by bus id and device id
		std::set<std::pair<u64, u64>> open_devices;

		// Device register windows mapped with lv1_map_device_mmio_region, by logical partition address
		struct io_region
		{
			u64 size;
			u32 page_shift;
			u64 bus_id;
			u64 dev_id;
			u64 bus_addr;
		};

		std::map<u64, io_region> io_regions;

		// What lv1's RSX driver put into the partition (lv1_gpu_open, lv1_gpu_device_map), by logical partition
		// address
		enum class gpu_region_kind
		{
			registers, // a window of the RSX registers, at rsx_offset from their base
			local_memory, // the RSX local memory but its last 2 MB
			driver_host, // resource 0xb of the driver's table, host memory
			driver_local_top, // resource 0xa, in the last 2 MB of local memory
		};

		struct gpu_region
		{
			u64 size;
			gpu_region_kind kind;
			u64 gpu_dev_id; // lv1_gpu_device_map id, umax for the regions of lv1_gpu_open
			u64 rsx_offset;
		};

		std::map<u64, gpu_region> gpu_regions;

		// The logical SPEs of the partition (lv1_construct_logical_spe), by id: the 512 KB window of the SPE's
		// local store and registers, the shadow registers, and the outlets of the SPE's three interrupt classes
		struct logical_spe
		{
			u64 vas_id;
			u64 lpar_addr;
			u64 shadow_lpar_addr;
			std::array<u64, 3> outlets;
			u64 resource_id = umax; // the SPE resource lv1_enable_logical_spe bound, umax while none is

			// The interrupt masks lv1_set_spe_interrupt_mask set, by class. What lv1 starts them at (+0x70 of the
			// class objects 0x2ff9e4 builds) has not been determined; nothing reads them yet.
			std::array<u64, 3> interrupt_masks{};

			// The physical SPE lv1_enable_logical_spe bound: an SPU of the emulator run as a raw SPU, whose local
			// store the emulator keeps in its SPU area (vm::spu)
			shared_ptr<named_thread<spu_thread>> spu;

			// SPU_LSLR as the partition wrote it (privilege 2 area, 0x4058)
			std::optional<u64> lslr;

			// The MFC's segment lookaside buffer, 8 entries (Cell BE Handbook v1.1 4.3.3), loaded through the
			// privilege 2 area: SLB_Index_W, SLB_ESID_RW and SLB_VSID_RW. The ESID holds the V bit (0x8000000)
			// as slbmte's RB does and the VSID the fields of the PPE's SLB entries. What lv1 leaves in it has not
			// been determined; the model starts it invalid, and ps2_emu loads every entry it uses (0x1ce5c).
			struct slb_entry
			{
				u64 esid = 0;
				u64 vsid = 0;
			};

			std::array<slb_entry, 8> slb{};
			u64 slb_index = 0;
		};

		std::map<u64, logical_spe> logical_spes;

		// The same windows by logical partition address, for the page checks
		struct spe_region
		{
			u64 size;
			u64 spe_id;
		};

		std::map<u64, spe_region> spe_regions;

		// Memory lv1_allocate_memory gave the partition after its memory from address 0, by logical partition
		// address: its size and where the emulator keeps it
		struct memory_region
		{
			u64 size;
			u32 addr;
		};

		std::map<u64, memory_region> memory_regions;

		// lv1_configure_virtual_uart_irq: the outlet of the partition's virtual UART interrupt (umax until it
		// is configured) and the logical partition address of the 256-bit bitmap of the ports that interrupt
		u64 vuart_irq_outlet = umax;
		u64 vuart_irq_bitmap = 0;

		// The partition's virtual UART ports, by port number (lv1 keeps them at +0x98 of the partition's
		// virtual UART object, 0x2f3574). Port 2 is the system manager's: lparmgr (lv1 process 1) builds it
		// for the partition with a receive buffer of 0x800 bytes (PMI 0x10084 construct_virtual_uart from
		// 0x8001b1c4, lv1 0x29a238 -> 0x2f2540) and serves it itself ("lpar_event", 0x8001b218..0x8001b25c).
		// Port 10 is the service port: after loading any guest the Secure LPAR Loader (lv1 process 6) sets up its
		// dispatcher (0x80000af4 -> 0x80000e34), whose vuart_pme::connect builds the partition's port with a
		// receive buffer of 0x1000 bytes (0x800081e8) and reads it. Which other ports the partition has has not
		// been determined.
		struct vuart_port
		{
			u64 rx_buffer_size;

			// The triggers and the interrupt mask, 0 when lv1 builds the port (0x2f1844, +0x88..+0x98 at
			// 0x2f18d4..0x2f18dc)
			u64 tx_trigger = 0;
			u64 rx_trigger = 0;
			u64 interrupt_mask = 0;

			// The bytes the peer wrote and the partition has not read yet (+0x78 of the port counts them)
			std::deque<u8> rx;
		};

		// Port 0 is lparmgr's AV settings manager ("avset", constructed with port 0 at 0x80007654 and built with a
		// receive buffer of 0x800 for PS3_LPAR and the PS2 partitions at 0x800073b8 -> 0x80007210), port 2 its
		// system manager, port 10 the Secure LPAR Loader's dispatcher
		std::map<u64, vuart_port> vuart_ports{{0, {0x800}}, {2, {0x800}}, {10, {0x1000}}};

		// lparmgr's side of port 0: the bytes of an AV settings packet not complete yet
		std::vector<u8> avset_pending;

		// lparmgr's side of port 2: the bytes of a system manager message not complete yet, and the event
		// attributes the partition asked for (service 8)
		std::vector<u8> sysmgr_pending;
		std::optional<u32> sysmgr_attributes;

		// lv1's copy of the virtual UART interrupt bitmap (+0x38 of its interrupt object) and how many ports
		// have their bit set (+0x898)
		std::array<u64, 4> vuart_irq_bits{};
		u32 vuart_irq_count = 0;

		// The USB host controllers of the south bridge (bus 1, devices 1 and 2), by device id
		std::map<u64, lv1_usb_controller> usb_controllers;
		u64 gpu_local_memory_lpar = 0;
		u64 gpu_driver_host_lpar = 0;
		u64 gpu_driver_local_top_lpar = 0;
		u64 gpu_fifo_lpar = 0;

		// lv1_gpu_context_allocate: whether the partition has a context (only a first one is followed)
		bool gpu_context_allocated = false;

		// lv1_gpu_memory_allocate: the 16 memory objects (handle = slot ^ 0x5a5a5a5a) and the local memory
		// bitmap in units of 1 MB
		std::array<bool, 16> gpu_memory_slots{};
		std::vector<bool> gpu_local_units;

		// Device DMA regions from lv1_allocate_device_dma_region, by bus id, device id and I/O address, and the
		// partition memory lv1_map_device_dma_region put behind them
		struct dma_mapping
		{
			u64 lpar_addr;
			u64 size;
			u64 flags;
		};

		struct dma_region
		{
			u64 size;
			u32 page_shift;
			u64 flags;
			std::map<u64, dma_mapping> mappings; // by I/O address
		};

		std::map<std::tuple<u64, u64, u64>, dma_region> dma_regions;

		// The ids of the partition's objects: lv1 4.93 hands out the lowest free one (0x2ca258), shared by the
		// event receive ports, I/O interrupt outlets, address spaces, logical PUs, logical SPEs and performance
		// monitors of the partition (the only constructors that call 0x2cc64c). Before the guest starts, lparmgr
		// (lv1 process 1) constructs the partition's logical PU (PMI 0x10005 at 0x8001ca78), which takes id 0
		// (0x2e7754 -> 0x2e0df8). Nothing else lparmgr or the Secure LPAR Loader asks of lv1 creates an object
		// there: the other object constructors are reached only from hypercalls and from process calls that
		// build the object in the caller's own partition (0x2e24e8 and 0x300a28 take the current one).
		std::set<u64> object_ids{0};

		// The partition's logical address allocator (0x2cec78), built with its counter at 1 (0x2cef10). lparmgr
		// allocates the memory at address 0 with flag 8, which does not draw on the counter (0x2cee3c); the
		// Secure LPAR Loader (lv1 process 6) then reads the guest image into a buffer it allocates in the
		// partition with flags 2 (0x80001600) and releases once the image is loaded (0x80001508), so the counter
		// is at 2 when the guest starts. The addresses the allocator holds, the memory at 0 included, are kept
		// to reproduce its retry on an address still in use (0x2ce7c4 answers 4, 0x2cede4).
		u64 lpar_counter = 2;
		std::set<u64> lpar_addresses{0};

		// The I/O spaces lv1_allocate_device_dma_region draws on, by the I/O base of the south bridge device type
		// they belong to. lv1 keeps, per device type, a list of regions (0x22ac9c), each one or more 256 MB I/O
		// segments it claims for the partition (0x22a6ac), and hands out blocks from them.
		struct io_space_region
		{
			u32 page_shift;
			u64 base;
			u64 size;
			std::map<u64, u64> blocks; // size by offset
		};

		struct io_space
		{
			std::vector<io_space_region> regions; // in creation order
		};

		std::map<u64, io_space> sb_io_spaces;

		// The claimed segments (256 MB each, numbered by I/O address >> 28) of I/O address space 0, the only
		// one lv1 creates (0x2d945c). When the guest starts: 8 to 0xd, which a boot initializer reserves
		// (0x213adc, listed at 0x3c21a8), and 0 and 1, the two lowest free ones, which the UX kernel's "cp0"
		// takes for itself (0x375ee8 -> 0x377b30 -> 0x2aa6bc -> 0x300608 -> 0x2da55c, 4 KB each) on a console
		// without a Communication Processor: the retail consoles, where the probe for the Sony 0x104d:0x81ff
		// chip on the south bridge's ebus fails (0x20ae04, 0x20afc0, 0x301e60). lv1's own RSX initialisation
		// reserves segment 3 only for an RSX revision above 2 (0x3a1dd4..0x3a27f0 -> 0x3a5a14 -> 0x3a76d4),
		// which is the post of the 28 nm RSX with GDDR5 memory ("post/post_rsx28.cc", gddr5*_RSX28); the
		// other revisions run post_rsx.cc's script, which reserves nothing. The CECHA01 has the 90 nm RSX
		// (CXD2971 family, GDDR3; psdevwiki), so segment 3 is free.
		std::set<u64> io_segments{0, 1, 8, 9, 10, 11, 12, 13};

		// The segments lv1_allocate_io_segment gave the partition, by I/O address
		struct io_segment
		{
			u64 size;
			u32 page_shift;
		};

		std::map<u64, io_segment> guest_io_segments;

		// Values the partition wrote to the PS2 chip's configuration space, by offset
		std::map<u64, u64> ps2_chip_config_writes;

		// The words the partition stored to the PS2 chip's registers (BAR0), by offset
		std::map<u64, u32> ps2_chip_registers;

		// Where the Gigabit Ethernet device writes its interrupt status (lv1_net_set_interrupt_status_indicator)
		std::optional<u64> net_status_indicator;

		// The event receive port the Gigabit Ethernet device's interrupt sends to
		// (lv1_connect_interrupt_event_receive_port)
		std::optional<u64> net_event_port;

		// The Gigabit Ethernet device's interrupt mask (lv1_net_set_interrupt_mask), 0 until the partition sets it
		u64 net_interrupt_mask = 0;

		// The event receive port each storage device's interrupt sends to, by device id
		std::map<u64, u64> storage_event_ports;

		// A storage device's requests by tag: lv1 keeps 16 per device (the bitmap at +0xa78, 0x25397c) with the
		// status the command ended with (+0xa98) once it is done (+0xaa8)
		struct storage_request
		{
			bool done = false;
			u64 status = 0;
		};

		std::map<u64, std::array<std::optional<storage_request>, 16>> storage_requests;

		// The BD drive behind storage device 2
		lv1_bdvd bdvd;

		// Whether the partition has opened the RSX (lv1_gpu_open): lv1 keeps the id of the partition that owns
		// the device at 0x35b4c4, 0xff while nobody does
		bool gpu_opened = false;

		// The ioids of I/O address space 0 in use (lv1_allocate_ioid)
		std::set<u64> ioids = initial_ioids();
	};

	// lv1 returns its status as a 32-bit value in the low word of r3, zero-extended (lv1 4.93 0xc44..0xc50,
	// 0x1088..0x108c). When it refuses an argument, bit n - 1 of the high word names the nth one (for
	// example 0x1ffffffef from construct_virtual_address_space, 0x2ec7a4..0x2ec7b0).
	u64 lv1_status(lv1_result result, u32 refused_arguments = 0)
	{
		return u64{refused_arguments} << 32 | static_cast<u32>(result);
	}

	// Repository node keys, built as lv1 builds them (lv1 4.93 0x2384a0) and Linux reads them (arch/powerpc/
	// platforms/ps3/repository.c): the first key is the name in the low 32 bits plus an index, the others the
	// name padded to 64 bits plus an index
	using repo_keys = std::array<u64, 4>;

	u64 repo_name(std::string_view name)
	{
		u64 value = 0;

		for (usz i = 0; i < 8; i++)
		{
			value = value << 8 | (i < name.size() ? static_cast<u8>(name[i]) : 0);
		}

		return value;
	}

	u64 repo_first(std::string_view name, u64 index)
	{
		return (repo_name(name) >> 32) + index;
	}

	u64 repo_key(std::string_view name, u64 index = 0)
	{
		return repo_name(name) + index;
	}

	// The keys as text for the log, "bus1.dev2.type"
	std::string repo_path(const repo_keys& keys)
	{
		std::string path;

		for (u32 k = 0; k < 4 && keys[k]; k++)
		{
			const u32 bytes = k ? 8 : 4;
			std::string name;
			u32 i = 0;

			for (; i < bytes; i++)
			{
				const u8 c = static_cast<u8>(keys[k] >> ((bytes - 1 - i) * 8));

				if (!(c >= 'a' && c <= 'z') && !(c >= 'A' && c <= 'Z') && !(c >= '0' && c <= '9') && c != '_')
				{
					break;
				}

				name += static_cast<char>(c);
			}

			const u64 index = i < bytes ? keys[k] & (~0ull >> (64 - (bytes - i) * 8)) : 0;
			fmt::append(path, "%s%s", k ? "." : "", name);

			if (index)
			{
				fmt::append(path, "%u", index);
			}
		}

		return path;
	}

	enum class repo_lookup
	{
		found,
		absent, // lv1 is known not to create the node
		unknown, // the node is not modelled
	};

	// The nodes of the repository of the platform management partition (lpar 1) that this model knows, each
	// from the constants of the lv1 4.93 code that creates it at boot (0x23906c)
	repo_lookup pme_repository_read(const repo_keys& keys, u64& v1, u64& v2)
	{
		static const std::map<repo_keys, std::array<u64, 2>> s_nodes = []
		{
			std::map<repo_keys, std::array<u64, 2>> n;

			const u64 id = repo_key("id");
			const u64 type = repo_key("type");
			const u64 num_dev = repo_key("num_dev");
			const auto bus = [](u64 i) { return repo_first("bus", i); };
			const auto dev = [](u64 i) { return repo_key("dev", i); };
			const auto intr = [](u64 i) { return repo_key("intr", i); };
			const auto reg = [](u64 i) { return repo_key("reg", i); };

			// bus0: 0x237e8c(0, 0, 0, 3, 1) makes id, type and num_dev, 0x23830c(0, 0, 0, 0) its one device
			n[{bus(0), id, 0, 0}] = {0, 0};
			n[{bus(0), type, 0, 0}] = {3, 0};
			n[{bus(0), num_dev, 0, 0}] = {1, 0};
			n[{bus(0), dev(0), id, 0}] = {0, 0};
			n[{bus(0), dev(0), type, 0}] = {0, 0};

			// bus1, the south bridge (0x238e20), with the chip's two USB controllers (0x23d0f8), both of which the
			// guest uses
			n[{bus(1), type, 0, 0}] = {4, 0};
			n[{bus(1), num_dev, 0, 0}] = {4, 0};

			// dev0, type 3 (Gigabit Ethernet, PS3_DEV_TYPE_SB_GELIC in Linux ps3.h)
			n[{bus(1), dev(0), id, 0}] = {0, 0};
			n[{bus(1), dev(0), type, 0}] = {3, 0};
			n[{bus(1), dev(0), intr(0), 0}] = {2, 0};

			// bus1.id: the bus id, and the south bridge's revision word (0x22b760, [sb + 0x18]). This is an
			// approximation (see sb_revision_approximation). ps2_emu.elf never uses it: its bus scan stores it where
			// the next read's second value overwrites it (0x1da70, 0x1daa4), and its id readers return the first
			// value only (0x1dd14, 0x1dd90).
			n[{bus(1), id, 0, 0}] = {1, sb_revision_approximation};

			// dev1 and dev2, type 4 (USB, PS3_DEV_TYPE_SB_USB), each with two interrupts and two register windows:
			// regions 1 and 2 of the south bridge's devices 3 and 4 (0x22b838 at 0x238ed4 and 0x238fac), which its
			// driver defines with these constants for every chip revision (0x3a9a60..0x3a9af0)
			n[{bus(1), dev(1), id, 0}] = {1, 0};
			n[{bus(1), dev(1), type, 0}] = {4, 0};
			n[{bus(1), dev(1), intr(0), 0}] = {3, 0x10};
			n[{bus(1), dev(1), intr(1), 0}] = {4, 0xa};
			n[{bus(1), dev(1), reg(0), type}] = {3, 0};
			n[{bus(1), dev(1), reg(0), repo_key("data")}] = {0x3010000, 0x10000};
			n[{bus(1), dev(1), reg(1), type}] = {4, 0};
			n[{bus(1), dev(1), reg(1), repo_key("data")}] = {0x3810000, 0x10000};

			n[{bus(1), dev(2), id, 0}] = {2, 0};
			n[{bus(1), dev(2), type, 0}] = {4, 0};
			n[{bus(1), dev(2), intr(0), 0}] = {3, 0x11};
			n[{bus(1), dev(2), intr(1), 0}] = {4, 0xb};
			n[{bus(1), dev(2), reg(0), type}] = {3, 0};
			n[{bus(1), dev(2), reg(0), repo_key("data")}] = {0x3020000, 0x10000};
			n[{bus(1), dev(2), reg(1), type}] = {4, 0};
			n[{bus(1), dev(2), reg(1), repo_key("data")}] = {0x3820000, 0x10000};

			// dev3, type 6 (GPIO, 0x238cc0)
			n[{bus(1), dev(3), id, 0}] = {3, 0};
			n[{bus(1), dev(3), type, 0}] = {6, 0};

			// bus2 and bus3, the devices two PCI host objects enumerated (0x232aa4 and 0x235074, 0x2390ac..0x2390f8):
			// 0x238964 makes the bus with its index as id and types 1 and 2 (0x238b7c -> 0x237e8c)
			n[{bus(2), id, 0, 0}] = {2, 0};
			n[{bus(2), type, 0, 0}] = {1, 0};
			n[{bus(3), id, 0, 0}] = {3, 0};
			n[{bus(3), type, 0, 0}] = {2, 0};

			// bus2's one device, the PS2 chip (see ps2_chip_pci_dev): id and type (the bus type, 0x238a38),
			// pci_bus/dev/fun (0x238a50) and a node per BAR, type 1 for memory (0x238b0c..0x238b5c)
			n[{bus(2), num_dev, 0, 0}] = {1, 0};
			n[{bus(2), dev(0), id, 0}] = {0, 0};
			n[{bus(2), dev(0), type, 0}] = {1, 0};
			n[{bus(2), dev(0), repo_key("pci_bus"), 0}] = {ps2_chip_pci_bus, 0};
			n[{bus(2), dev(0), repo_key("pci_dev"), 0}] = {ps2_chip_pci_dev, 0};
			n[{bus(2), dev(0), repo_key("pci_fun"), 0}] = {ps2_chip_pci_fun, 0};
			n[{bus(2), dev(0), reg(0), type}] = {1, 0};
			n[{bus(2), dev(0), reg(0), repo_key("data")}] = {ps2_chip_bar0, ps2_chip_bar0_size};

			// bus4, the storage devices (0x2524a4, 0x252670: id 4, type 5 and num_dev the devices registered). Each
			// device takes the next slot of a counter that starts at -1 (0x252808) when it is created, and its
			// slot is its id; it gets its node index when it registers (0x252c50), which the model takes in slot
			// order, as the public 3.41 dump shows. Creation order (0x2528dc): slot 0 the type 0xff device
			// (0x287a54), slot 1 the flash (0x288214: type 0xe, or 0xfe with a vflash), then the ATA devices as
			// the two ports are probed (0x252924: port 0, then port 1; the ATAPI one type 5, the disk type 0), and
			// the vflash device last only with one (0x25deb0). Each has interrupt 0 = {2, 0} (0x25254c).
			// APPROXIMATION (lv1.md, "Approximations"): the CECHA01 has NAND flash, so no vflash (the loader
			// parameter sys.flash.ext that makes one, 0x252870, is the NOR models'), and its BD drive and disk are
			// on ATA ports 0 and 1 as on the console of the public dump (BD port 0, disk port 2 = port 1 master).
			// ss.param.product.mode: the console's product (factory) mode flag, which lparmgr also reads
			// (0x8001ead8). The value is the console's own (the system controller's EEPROM); lv1's code does not
			// name the node, so its creator has not been followed. DERIVED WITH PUBLIC FACTS: 0xff, "not in product
			// mode", which the public 3.41 dump of a retail console shows; the user's CECHA01 is a retail console.
			// ps2_emu only tests it against 0xff (0x1e0bc; a failed read counts as 0xff), for its "pata" factory
			// mode (0x43030).
			n[{repo_first("ss", 0), repo_key("param"), repo_key("product"), repo_key("mode")}] = {0xff, 0};

			n[{bus(4), id, 0, 0}] = {4, 0};
			n[{bus(4), type, 0, 0}] = {5, 0};
			n[{bus(4), num_dev, 0, 0}] = {4, 0};

			for (u64 slot = 0; slot < 4; slot++)
			{
				static constexpr u64 storage_types[4]{0xff, 0xe, 5, 0};
				n[{bus(4), dev(slot), id, 0}] = {slot, 0};
				n[{bus(4), dev(slot), type, 0}] = {storage_types[slot], 0};
				n[{bus(4), dev(slot), intr(0), 0}] = {2, 0};
			}

			return n;
		}();

		// Nodes lv1 creates with values that depend on the hardware, whose CECHA01 values have not been
		// determined: the GPIO interrupt depends on the hardware configuration (sys.hw.config and a south bridge
		// sub-object, 0x238cc0)
		static const std::set<repo_keys> s_undetermined = []
		{
			return std::set<repo_keys>
			{
				{repo_first("bus", 1), repo_key("dev", 3), repo_key("intr", 0), 0},
			};
		}();

		if (const auto found = s_nodes.find(keys); found != s_nodes.end())
		{
			v1 = found->second[0];
			v2 = found->second[1];
			return repo_lookup::found;
		}

		if (s_undetermined.contains(keys))
		{
			return repo_lookup::unknown;
		}

		const u64 bus0 = repo_first("bus", 0);

		// lv1 makes bus0 to bus4 only (0x23906c), and every other node of bus0 and bus1 is above
		if (keys[0] >= bus0 + 5 && keys[0] <= bus0 + 0xff)
		{
			return repo_lookup::absent;
		}

		if (keys[0] == bus0 || keys[0] == bus0 + 1)
		{
			return repo_lookup::absent;
		}

		return repo_lookup::unknown;
	}

	// The id of a new object of the partition: the event port, outlet or address space id lv1 returns is the
	// object's id (lv1 4.93 0x2e2628), the lowest free one (0x2ca258 takes the first group with a free id and
	// the lowest set bit of its bitmap).
	u64 allocate_object_id(lv1_state& lv1s)
	{
		u64 id = 0;

		while (lv1s.object_ids.contains(id))
		{
			id++;
		}

		lv1s.object_ids.emplace(id);
		return id;
	}

	// A logical partition address range from the partition's allocator (lv1 4.93 0x2cec78). It hands out
	// (class << 42) | (n << class), class being the log2 of the size rounded up (12 for up to 4 KB) and n the
	// low 42 - class bits of a counter it increments on every attempt; an address still in use makes it try the
	// next one, at most 1 << (42 - class) times (0x2ced84..0x2cedec). psdevwiki's allocate_memory example, a
	// 4 KB region at 0x30000001f000, has this form.
	u64 lpar_allocate(lv1_state& lv1s, std::string_view call, u64 size)
	{
		// Above 1 << 42 bytes lv1 fails with an internal code (0x2cecd0) whose status for the caller has not
		// been determined
		if (size > 1ull << 42)
		{
			fmt::throw_exception("%s: 0x%x bytes is more than the allocator hands out", call, size);
		}

		const u32 size_class = size <= 0xfff ? 12 : 64 - std::countl_zero(size - 1);
		const u64 slots = 1ull << (42 - size_class);

		for (u64 attempt = 0; attempt < slots; attempt++)
		{
			const u64 n = lv1s.lpar_counter++;
			const u64 address = u64{size_class} << 42 | (n & (slots - 1)) << size_class;

			if (lv1s.lpar_addresses.emplace(address).second)
			{
				return address;
			}
		}

		// Every address of the class in use: another internal code (0x2cee08)
		fmt::throw_exception("%s: no free logical partition address for 0x%x bytes", call, size);
	}

	// The DMA address of a new block of a south bridge device type's I/O space (lv1 4.93 0x22d3a4). The USB
	// controllers are the south bridge devices 3 and 4 of types 8 and 9 (0x3a9a4c, 0x3a9aa0); the PCI bus
	// behind device 6, of type 0 (0x3a9d58), draws on device 6's space (0x2347dc -> 0x232148 -> 0x23066c ->
	// 0x226990). The partition's id is neither 0, which lv1 reserves when it creates the id table (0x3af6a4),
	// nor 1, the system partition's (0x3b0158), so lv1 takes the partition path (0x22cf74, [lpar+0x50] being
	// the id lv1 prints after "LPAR#" at 0x2e6074) with the type's window of 1 GB at io_base | 0x40000000,
	// io_base being type << 32 by the table at 0x22d244 (type 8: 4, type 9: 5, type 0: 0; 0x22d280, 0x22d32c,
	// 0x22d344, 0x22a1f0). The south bridge set the device's I/O base to io_base when it created it (0x3a9878,
	// 0x3a986c, 0x22db70), and the device sees an I/O address as 0x80000000 plus its offset from that base
	// (0x22d6a0).
	u64 sb_dma_allocate(lv1_state& lv1s, u64 io_base, u64 multiplier, u64 size, u32 page_shift)
	{
		const u64 first_segment = (io_base | 0x40000000) >> 28;
		const u64 end_segment = first_segment + 4;
		const u64 page_size = 1ull << page_shift;

		auto& space = lv1s.sb_io_spaces[io_base];

		// A block takes the size rounded up to a power of two (0x22d404..0x22d42c, more than 4 GB was refused
		// by the caller) and is aligned to it or to the page if larger
		const u64 block_size = std::bit_ceil(size);
		const u64 align = std::max(block_size, page_size);
		const auto align_up = [&](u64 address) { return (address + align - 1) & ~(align - 1); };

		u64 address = umax;

		// First fit in the regions of the page size, in creation order (0x22ad3c..0x22ae44). lv1 starts after
		// the region's first block, so the space before it stays unused, and only an empty region is given
		// from its start (0x22afdc).
		for (auto& region : space.regions)
		{
			if (region.page_shift != page_shift)
			{
				continue;
			}

			if (region.blocks.empty())
			{
				if (region.size >= block_size)
				{
					address = region.base;
					region.blocks.emplace(0, block_size);
					break;
				}

				continue;
			}

			auto block = region.blocks.begin();
			u64 candidate = align_up(region.base + block->first + block->second);
			bool found = false;

			for (++block; candidate - region.base <= region.size && block != region.blocks.end(); ++block)
			{
				const u64 start = region.base + block->first;

				if (start >= candidate && start - candidate >= block_size)
				{
					found = true;
					break;
				}

				candidate = align_up(start + block->second);
			}

			if (candidate - region.base > region.size)
			{
				continue;
			}

			if (found || region.size - (candidate - region.base) >= block_size)
			{
				address = candidate;
				region.blocks.emplace(candidate - region.base, block_size);
				break;
			}
		}

		if (address == umax)
		{
			// A new region (0x22b0b8): lv1 sizes it (0x22a424) and claims its segments one by one, each the
			// lowest free one of the window (0x2d9680..0x2d9648), requiring them to be consecutive (0x22a7c8)
			u64 count = 1;
			u64 segment_size = 1ull << 28;

			if (block_size > (1ull << 28) - 1)
			{
				count = (block_size + (1ull << 28) - 1) >> 28;
			}
			else
			{
				// The window's multiplier: 0x80 for most types, 0 for type 2, whose region is the block alone
				// (0x22a490..0x22a4c4)
				segment_size = multiplier ? std::min(std::max(page_size, block_size) * multiplier, 1ull << 28) : std::max(page_size, block_size);
			}

			u64 segment = first_segment;

			while (lv1s.io_segments.contains(segment))
			{
				segment++;
			}

			// Running out of segments, or finding them apart, makes lv1 release what it claimed and fail with
			// codes whose status for the caller has not been determined (0x2d9bd4, 0x22a814)
			for (u64 i = 0; i < count; i++)
			{
				if (segment + i >= end_segment || lv1s.io_segments.contains(segment + i))
				{
					fmt::throw_exception("lv1_allocate_device_dma_region(): no free I/O segment for 0x%x bytes", size);
				}
			}

			for (u64 i = 0; i < count; i++)
			{
				lv1s.io_segments.emplace(segment + i);
			}

			address = segment << 28;
			space.regions.push_back({page_shift, address, count * segment_size, {{0, block_size}}});
		}

		// The address has to be within 2 GB above the device's I/O base (0x22d6d8..0x22d710), which every
		// segment of the window is
		ensure(address - io_base < 0x80000000);
		return 0x80000000 + (address - io_base);
	}

	// Whether a page lies in memory the partition owns: its memory from address 0, or a device register window
	// it mapped
	bool lpar_page_owned(const lv1_state& lv1s, u64 address, u64 size)
	{
		if (address + size <= lv1_guest_region0_size)
		{
			return true;
		}

		const auto within = [&](const auto& regions)
		{
			const auto next = regions.upper_bound(address);

			if (next == regions.begin())
			{
				return false;
			}

			const auto& [base, region] = *std::prev(next);
			return address >= base && address + size <= base + region.size;
		};

		return within(lv1s.io_regions) || within(lv1s.gpu_regions) || within(lv1s.spe_regions) || within(lv1s.memory_regions);
	}

	// The interrupt state of a virtual UART port (lv1 4.93 0x2f0cc4, and inline at 0x2f21b0..0x2f2210): 8 while
	// the peer is connected, 1 (transmit) while the bytes waiting in the peer's buffer are at most the
	// transmit trigger, 2 (receive) while the free space of the port's own buffer is at most the receive
	// trigger. The peers of the partition's ports (lparmgr for port 2, the Secure LPAR Loader's dispatcher for
	// port 10) read what arrives, so their buffer is empty and the transmit bit is set whatever the trigger.
	u64 vuart_status(const lv1_state::vuart_port& vp)
	{
		u64 status = 8 | 1;

		if (vp.rx_buffer_size - vp.rx.size() <= vp.rx_trigger)
		{
			status |= 2;
		}

		return status;
	}

	void raise_outlet(lv1_state& lv1s, lv1_outlet& outlet);

	// What lv1 does when a port's state changes (0x2f21f0..0x2f2394): the port's bit in the bitmap follows
	// whether its status meets its interrupt mask. Port n is bit 63 - n % 64 of doubleword n / 64; lv1 keeps
	// its own copy and stores the doubleword into the partition's bitmap, counts the ports whose bit is set,
	// and raises the outlet when the count goes from 0 to 1.
	void vuart_update_interrupt(lv1_state& lv1s, u64 port)
	{
		if (lv1s.vuart_irq_outlet == umax)
		{
			return;
		}

		const auto& vp = lv1s.vuart_ports.at(port);

		const bool on = (vuart_status(vp) & vp.interrupt_mask) != 0;
		u64& word = lv1s.vuart_irq_bits[port / 64];
		const u64 bit = 1ull << (63 - port % 64);

		if (on == ((word & bit) != 0))
		{
			return;
		}

		word = on ? word | bit : word & ~bit;
		vm::write64(static_cast<u32>(lv1s.vuart_irq_bitmap + port / 64 * 8), word);

		if (!on)
		{
			lv1s.vuart_irq_count--;
			return;
		}

		if (++lv1s.vuart_irq_count == 1)
		{
			raise_outlet(lv1s, lv1s.outlets.at(lv1s.vuart_irq_outlet));
		}
	}

	// A message from lparmgr to the partition on port 2 (0x8001a784): the header lparmgr builds (0x80019d38:
	// version 1, header size 0x10, payload size, service, request tag), the payload and, for some services,
	// more bytes counted in the payload size and written after it. lparmgr waits while the port's buffer is
	// full; the model's messages fit.
	void sysmgr_send(lv1_state& lv1s, u16 service, u32 tag, std::span<const u8> payload, std::span<const u8> extra = {})
	{
		auto& vp = lv1s.vuart_ports.at(2);

		if (16 + payload.size() + extra.size() > vp.rx_buffer_size - vp.rx.size())
		{
			fmt::throw_exception("System manager: a message of 0x%x bytes does not fit port 2's buffer", 16 + payload.size() + extra.size());
		}

		u8 header[16]{1, 0x10};
		write_to_ptr<be_t<u32>>(header, 4, static_cast<u32>(payload.size() + extra.size()));
		write_to_ptr<be_t<u16>>(header, 8, service);
		write_to_ptr<be_t<u32>>(header, 12, tag);

		vp.rx.insert(vp.rx.end(), std::begin(header), std::end(header));
		vp.rx.insert(vp.rx.end(), payload.begin(), payload.end());
		vp.rx.insert(vp.rx.end(), extra.begin(), extra.end());

		lv1.notice("System manager: to the partition, service %u, 0x%x bytes", service, payload.size() + extra.size());
		vuart_update_interrupt(lv1s, 2);
	}

	// A system manager message the partition sent on virtual UART port 2, as lparmgr handles it (lv1 process
	// 1, 0x8001b014): the header is Linux's struct ps3_sys_manager_header (drivers/ps3/ps3-sys-manager.c),
	// and the service is the low byte of its service id (header byte 9), which indexes lparmgr's table of
	// handlers at 0x8003e020 (above 0x3d the handler of service 6).
	void sysmgr_receive(lv1_state& lv1s, std::span<const u8> header, std::span<const u8> payload)
	{
		const u8 service = header[9];
		lv1.notice("System manager: from the partition, service %u, 0x%x bytes", service, payload.size());

		switch (service)
		{
		case 8:
		{
			// Set attributes (0x8001a6b4): the attribute word at offset 4 of the payload unmasks, for the four
			// event kinds of the table at 0x8003a4ac, their events for the partition (0x80021848). Events queued
			// while they were masked would be sent then; none of lparmgr's event sources (the system
			// controller's buttons and thermal alerts) fires during the boot. No answer.
			// (a shorter payload leaves lparmgr reading what its buffer held before, not modelled)
			if (payload.size() < 8)
			{
				break;
			}

			lv1s.sysmgr_attributes = read_from_ptr<be_t<u32>>(payload, 4);
			return;
		}
		case 9:
		{
			// 0x8001c144: the operation is payload byte 1
			if (payload.size() < 2)
			{
				break;
			}

			const u32 tag = read_from_ptr<be_t<u32>>(header, 12);
			const u8 op = payload[1];

			if (op == 2)
			{
				// Operation 2 answers with service 11 and 16 bytes (0x8001c188..0x8001c1e4, built at 0x80019db4):
				// {2, A, B, 0, C (32 bits), D (64 bits)}. D is +0x60 of lparmgr's object for the partition (0x8001da40),
				// which only the GameOS class sets (0x8001e464, its privileges); the other classes leave it at 0
				// (0x8001e02c) and lparmgr computes a boot parameter into it only for "PS3_LPAR" (0x80019754), so D
				// is 0 for the PS2 partition. A and B (0xc000d35d, 0xc000d35e) and C (the system controller's
				// wake source, 0xc000d2d8, 0x800220b8) have not been determined, and ps2_emu does not read them:
				// it keeps only byte 15, as a product code if it is 0x83 to 0x8e (0x1f7a0..0x1f7b0). They are
				// sent as 0 (lv1.md, "Approximations").
				u8 reply[16]{op};
				sysmgr_send(lv1s, 11, tag, reply);
				return;
			}

			if (op != 1)
			{
				break;
			}

			// Operation 1 sends the inter-lpar parameter back as service 10: {1, 0, size (16 bits), 0} and then
			// the parameter's bytes, the size counting down as lparmgr writes them, so the parameter is given
			// once (0x8001c1ec..0x8001c288)
			std::vector<u8> parameter;
			{
				std::lock_guard lock(g_inter_lpar_parameter_mutex);
				parameter = std::exchange(g_inter_lpar_parameter, {});
			}

			u8 reply[8]{op, 0};
			write_to_ptr<be_t<u16>>(reply, 2, static_cast<u16>(parameter.size()));
			sysmgr_send(lv1s, 10, tag, reply, parameter);
			return;
		}
		default: break;
		}

		std::string hex;

		for (u8 byte : payload)
		{
			fmt::append(hex, "%02x", byte);
		}

		fmt::throw_exception("System manager: service %u from the partition is not implemented (payload %s)", service, hex);
	}

	// The bus and device checks lv1's device calls share: a bus id above 4 is an illegal first argument (each
	// call checks it first, e.g. lv1 4.93 0x305ac8), one of the buses 1 to 4 has to be named and the device has
	// to be on it (NO_ENTRY for the first and second arguments, 0x2363e0). Only the south bridge's four devices
	// are modelled. Returns 0 when the device may be used, or the status to answer.
	u64 check_sb_device(const lv1_state& lv1s, std::string_view call, u64 bus_id, u64 dev_id, bool must_be_open)
	{
		if (bus_id > 4)
		{
			return lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
		}

		if (bus_id == 0)
		{
			return lv1_status(LV1_NO_ENTRY, 1);
		}

		// bus2 finds the device by id in the PCI host's list (0x236568 -> 0x232b5c), which has the PS2 chip only
		if (bus_id == 2)
		{
			if (dev_id != 0)
			{
				return lv1_status(LV1_NO_ENTRY, 2);
			}
		}
		else if (bus_id == 4)
		{
			// The storage devices by slot (0x236594 -> 0x2365e0): slots 0 to 6, of which the model's console
			// fills 0 to 3 (see the repository); -1 names the storage system itself, which is not followed
			if (dev_id == umax)
			{
				fmt::throw_exception("%s(4, -1): the storage system object is not modelled", call);
			}

			if (dev_id > 3)
			{
				return lv1_status(LV1_NO_ENTRY, 2);
			}
		}
		else if (bus_id != 1)
		{
			fmt::throw_exception("%s(%u, %u): the devices of this bus are not modelled", call, bus_id, dev_id);
		}
		else if (dev_id > 3)
		{
			return lv1_status(LV1_NO_ENTRY, 2);
		}

		// The device's own check (0x2364b8) has not been followed; using a device the partition has not opened
		// stops here
		if (must_be_open && !lv1s.open_devices.contains({bus_id, dev_id}))
		{
			fmt::throw_exception("%s(%u, %u): device not open", call, bus_id, dev_id);
		}

		return 0;
	}

	// An answer of lparmgr's AV settings manager on port 0 (0x80008c4c, 0x80007cf4): Linux's ps3av_reply_hdr, the
	// version 0x205, the size of what follows it, the command id with bit 31 set, the status, then the data
	void avset_send(lv1_state& lv1s, u32 cid, u32 status, std::span<const u8> data = {})
	{
		auto& vp = lv1s.vuart_ports.at(0);

		if (12 + data.size() > vp.rx_buffer_size - vp.rx.size())
		{
			fmt::throw_exception("AV settings: an answer of 0x%x bytes does not fit port 0's buffer", 12 + data.size());
		}

		u8 header[12]{};
		write_to_ptr<be_t<u16>>(header, 0, 0x205);
		write_to_ptr<be_t<u16>>(header, 2, static_cast<u16>(8 + data.size()));
		write_to_ptr<be_t<u32>>(header, 4, cid | 0x80000000);
		write_to_ptr<be_t<u32>>(header, 8, status);

		vp.rx.insert(vp.rx.end(), std::begin(header), std::end(header));
		vp.rx.insert(vp.rx.end(), data.begin(), data.end());

		lv1.notice("AV settings: to the partition, cid 0x%x, status 0x%x, 0x%x bytes", cid, status, data.size());
		vuart_update_interrupt(lv1s, 0);
	}

	// A packet the partition sent to lparmgr's AV settings manager (lv1 process 1, receive loop 0x8000883c):
	// Linux's PS3AV protocol, {u16 version, u16 size of what follows, u32 cid, ...}. A version other than
	// 0x205 is answered with status 3 (0x800088c8), for the low 16 bits of the cid as the other errors are. The
	// cid names a command object (0x8000d460; a cid it does not know is dropped, 0x80008b18), whose methods
	// the executor calls (0x80007bb4): the packet size it takes (+0x18, status 0xa when it differs), whether it
	// is allowed (+0x28, status 0xc when not), then the command (+0x10), which queues its own answer.
	void avset_receive(lv1_state& lv1s, std::span<const u8> packet)
	{
		const u16 version = read_from_ptr<be_t<u16>>(packet, 0);
		const u32 cid = read_from_ptr<be_t<u32>>(packet, 4);
		lv1.notice("AV settings: from the partition, cid 0x%x, 0x%x bytes", cid, packet.size());

		if (version != 0x205)
		{
			avset_send(lv1s, cid & 0xffff, 3);
			return;
		}

		// The commands followed: the packet size (+0x18) and whether it is allowed (+0x28)
		struct command
		{
			u32 size;
			bool allowed;
		};

		command cmd{};

		switch (cid)
		{
		case 0x01000001: cmd = {8, true}; break; // vtable 0x8003d028: 0x80008dbc, 0x80005ef8
		case 0x02000001: cmd = {8, true}; break; // vtable 0x8003d2b0: 0x80008e08, 0x80005ef8
		case 0x02000003: cmd = {0, true}; break; // vtable 0x8003d340: 0x80005eec (any size), 0x80005ef8
		default: fmt::throw_exception("AV settings: command 0x%x (%s) is not implemented", cid, fmt::buf_to_hexstring(packet.data(), packet.size()));
		}

		// A size of 0 takes any (0x80007c24)
		if (cmd.size && packet.size() != cmd.size)
		{
			avset_send(lv1s, cid & 0xffff, 0xa);
			return;
		}

		if (!cmd.allowed)
		{
			avset_send(lv1s, cid & 0xffff, 0xc);
			return;
		}

		switch (cid)
		{
		case 0x01000001:
		case 0x02000001:
		{
			// 0x8000b508 and 0x8000bce4: tell an lparmgr object (0x01000001: its AV manager, 0x8002642c with 0xd on
			// [0xc000d4c8]; 0x02000001: 0x80005a38 on [0xc000d518]) and answer status 0 without data, 0xd when the
			// answer buffer has 11 bytes or less left, which the model's never has. What those objects do with it
			// has not been followed.
			avset_send(lv1s, cid, 0);
			return;
		}
		case 0x02000003:
		{
			// 0x8000c8d0: hands the parameters (from +8) to 0x80004f60 on [0xc000d518], which sets the audio
			// outputs from the first byte (0, 1, 0x10, 0x11, 0x20, 0x21) and byte 4 and always succeeds (status
			// 0x11 would be its failure); status 0 without data
			avset_send(lv1s, cid, 0);
			return;
		}
		default: break;
		}
	}

	// The device checks of the storage request calls (0x251be0, 0x251d70): a storage device by slot (0x251bf0,
	// NO_ENTRY without an argument when the slot is empty; -1, the storage system itself, is not followed) that
	// the partition holds open (the device's method +0x30, WRONG_STATE otherwise)
	u64 check_storage_request(const lv1_state& lv1s, std::string_view call, u64 dev_id)
	{
		if (dev_id == umax)
		{
			fmt::throw_exception("%s(-1): the storage system object is not modelled", call);
		}

		if (dev_id > 3)
		{
			return lv1_status(LV1_NO_ENTRY);
		}

		if (!lv1s.open_devices.contains({4, dev_id}))
		{
			return lv1_status(LV1_WRONG_STATE);
		}

		return 0;
	}

	// Bits of the first doubleword of a hashed page table entry (Book III v2.02 4.4.2.1)
	constexpr u64 hpte_v_valid = 1ull << 0;
	constexpr u64 hpte_v_large = 1ull << 2;

	// The address space an lv1 call names: 0 is the one selected for the PPE (lv1 4.93 0x2d1c90), which is how
	// Linux uses it (PS3_LPAR_VAS_ID_CURRENT, arch/powerpc/platforms/ps3/htab.c). nullptr if the id names none.
	lv1_vas* find_vas(lv1_state& lv1s, u64 vas_id)
	{
		if (!vas_id)
		{
			if (!lv1s.selected_vas)
			{
				fmt::throw_exception("lv1: the hash table of the partition's initial address space has not been investigated");
			}

			vas_id = lv1s.selected_vas;
		}

		const auto found = lv1s.vases.find(vas_id);
		return found == lv1s.vases.end() ? nullptr : &found->second;
	}

	u32 plug_word(u64 plug)
	{
		return static_cast<u32>(plug / 64);
	}

	u64 plug_bit(u64 plug)
	{
		return 1ull << (63 - plug % 64);
	}

	named_thread<ppu_thread>* get_hw_thread(lv1_state& lv1s, u32 hw_thread)
	{
		return idm::check_unlocked<named_thread<ppu_thread>>(lv1s.ppu_ids[hw_thread]);
	}

	// The external interrupt condition of a thread exists while one of its plugs is raised and enabled
	void update_external_line(lv1_state& lv1s, u32 hw_thread)
	{
		const auto& irq = lv1s.irq[hw_thread];

		bool pending = false;

		for (u32 i = 0; i < 4; i++)
		{
			pending |= (irq.status[i] & irq.mask[i]) != 0;
		}

		if (auto ppu = get_hw_thread(lv1s, hw_thread))
		{
			if (ppu->supervisor->external_pending.exchange(pending) != static_cast<u32>(pending) && pending)
			{
				ppu->supervisor->external_pending.notify_one();
			}
		}
	}

	// Set or clear the status bit of a plug (lv1 4.93 0x2c65b8, 0x2c3794)
	void set_plug_status(lv1_state& lv1s, u32 hw_thread, u32 plug, bool raised)
	{
		auto& status = lv1s.irq[hw_thread].status[plug_word(plug)];
		status = raised ? status | plug_bit(plug) : status & ~plug_bit(plug);
		update_external_line(lv1s, hw_thread);
	}

	// Raise an outlet (lv1 4.93 0x2df808): an outlet raised already stays as it is, and one that is not
	// connected yet makes its plug pending when it gets connected (0x2dfa94)
	void raise_outlet(lv1_state& lv1s, lv1_outlet& outlet)
	{
		if (outlet.raised)
		{
			return;
		}

		outlet.raised = true;

		if (outlet.hw_thread != umax)
		{
			set_plug_status(lv1s, outlet.hw_thread, outlet.plug, true);
		}
	}
}

namespace
{
	// The memory behind a bus address a south bridge device masters: its DMA regions and the partition
	// memory lv1_map_device_dma_region put behind them. Only the memory from address 0 is followed.
	u8* sb_dma_ptr(lv1_state& lv1s, u64 bus_id, u64 dev_id, u32 bus_addr, u32 size)
	{
		auto region = lv1s.dma_regions.upper_bound({bus_id, dev_id, bus_addr});

		if (region == lv1s.dma_regions.begin())
		{
			return nullptr;
		}

		region--;
		const auto& [key, dr] = *region;

		if (std::get<0>(key) != bus_id || std::get<1>(key) != dev_id || bus_addr - std::get<2>(key) >= dr.size)
		{
			return nullptr;
		}

		auto mapping = dr.mappings.upper_bound(bus_addr);

		if (mapping == dr.mappings.begin())
		{
			return nullptr;
		}

		mapping--;

		if (bus_addr + u64{size} > mapping->first + mapping->second.size)
		{
			return nullptr;
		}

		const u64 lpar = mapping->second.lpar_addr + (bus_addr - mapping->first);

		if (lpar + size > lv1_guest_region0_size)
		{
			fmt::throw_exception("Device DMA to logical partition address 0x%llx outside the memory from address 0 is not implemented", lpar);
		}

		// A device writes the memory whatever protection the emulator put on its pages
		return vm::get_super_ptr<u8>(static_cast<u32>(lpar));
	}

	// Raise the south bridge interrupt with the given id through the outlet the partition constructed for it
	void raise_sb_interrupt(lv1_state& lv1s, u64 interrupt_id)
	{
		if (const auto outlet = lv1s.io_irq_outlets.find(interrupt_id); outlet != lv1s.io_irq_outlets.end())
		{
			raise_outlet(lv1s, lv1s.outlets.at(outlet->second));
			return;
		}

		fmt::throw_exception("South bridge interrupt 0x%x without an outlet is not implemented", interrupt_id);
	}

	// The south bridge's USB controllers, set up when the partition first touches one: the OHCI interrupt of
	// device n is bus1.devn.intr0's (0x10, 0x11) and the EHCI one bus1.devn.intr1's (0xa, 0xb)
	lv1_usb_controller& usb_controller(lv1_state& lv1s, u64 dev_id)
	{
		auto [it, fresh] = lv1s.usb_controllers.try_emplace(dev_id);

		if (fresh)
		{
			auto& usb = it->second;
			const u64 ohci_interrupt = dev_id == 1 ? 0x10 : 0x11;
			const u64 ehci_interrupt = dev_id == 1 ? 0xa : 0xb;

			usb.dma = [&lv1s, dev_id](u32 bus_addr, u32 size) { return sb_dma_ptr(lv1s, 1, dev_id, bus_addr, size); };
			usb.interrupt = [&lv1s, ohci_interrupt]() { raise_sb_interrupt(lv1s, ohci_interrupt); };
			usb.ehci_interrupt = [&lv1s, ehci_interrupt]() { raise_sb_interrupt(lv1s, ehci_interrupt); };
		}

		return it->second;
	}

	// Whether the source of an outlet still asks for it after an end of interrupt (see lv1_end_of_interrupt)
	bool outlet_still_asked(lv1_state& lv1s, u64 outlet)
	{
		if (outlet == lv1s.vuart_irq_outlet)
		{
			return lv1s.vuart_irq_count > 0;
		}

		// APPROXIMATION (lv1.md, "Approximations"): an SPE's class outlet asks again while an enabled interrupt
		// of that class is pending in the SPE (INT_Stat & INT_Mask); lv1's path from the SPE interrupt to the
		// outlet has not been followed.
		for (const auto& [id, spe] : lv1s.logical_spes)
		{
			for (u32 cls = 0; cls < 3; cls++)
			{
				if (spe.outlets[cls] == outlet)
				{
					return spe.spu && (spe.spu->int_ctrl[cls].stat & spe.spu->int_ctrl[cls].mask) != 0;
				}
			}
		}

		for (const auto& [interrupt_id, io_outlet] : lv1s.io_irq_outlets)
		{
			if (io_outlet != outlet)
			{
				continue;
			}

			// The USB controllers' OHCI (0x10, 0x11) and EHCI (0xa, 0xb) interrupts
			const u64 dev_id = interrupt_id == 0x10 || interrupt_id == 0xa ? 1 : interrupt_id == 0x11 || interrupt_id == 0xb ? 2 : 0;

			if (!dev_id)
			{
				break;
			}

			const auto usb = lv1s.usb_controllers.find(dev_id);

			if (usb == lv1s.usb_controllers.end())
			{
				return false;
			}

			return interrupt_id >= 0x10 ? lv1_usb_ohci_interrupt_level(usb->second) : lv1_usb_ehci_interrupt_level(usb->second);
		}

		fmt::throw_exception("lv1_end_of_interrupt(): what the source of outlet 0x%x does has not been modelled", outlet);
	}

	// The controllers' frames run on a thread of their own, every millisecond while one is operational
	struct lv1_usb_thread
	{
		atomic_t<u32> active = 0;

		void operator()()
		{
			while (thread_ctrl::state() != thread_state::aborting)
			{
				thread_ctrl::wait_for(active ? 1000 : 100000);

				if (!active || Emu.IsPausedOrReady())
				{
					continue;
				}

				auto& lv1s = g_fxo->get<lv1_state>();
				std::lock_guard lock(lv1s.mutex);

				// The partition's memory, as the controllers master it
				const auto vm_globals = lv2_process::acquire_globals(id_manager::g_process);

				for (auto& [dev_id, usb] : lv1s.usb_controllers)
				{
					lv1_usb_ohci_run(usb, lv1_timebase());
					lv1_usb_ehci_run(usb, lv1_timebase());
				}
			}
		}

		static constexpr auto thread_name = "lv1 USB"sv;
	};
}

u64 lv1_htab_generation()
{
	return g_htab_generation;
}

static std::optional<lv1_translation> htab_lookup(const lv1_state& lv1s, u64 vas_id, u64 vsid, u64 offset, bool large, u32 lp);

std::optional<lv1_translation> lv1_htab_lookup(u64 vsid, u64 offset, bool large, u32 lp)
{
	auto& lv1s = g_fxo->get<lv1_state>();
	reader_lock lock(lv1s.mutex);

	// The table SDR1 holds: the selected address space's
	return htab_lookup(lv1s, lv1s.selected_vas, vsid, offset, large, lp);
}

// The translation of a virtual address through the hash table of an address space of the partition
static std::optional<lv1_translation> htab_lookup(const lv1_state& lv1s, u64 vas_id, u64 vsid, u64 offset, bool large, u32 lp)
{
	// The partition's initial address space is not followed
	const auto found = lv1s.vases.find(vas_id);

	if (found == lv1s.vases.end())
	{
		fmt::throw_exception("lv1_htab_lookup(): the partition's initial address space has not been investigated");
	}

	const lv1_vas& vas = found->second;

	// A large page segment names the page size by its SLB LP field, which indexes the sizes the address space
	// was constructed with as the number of ones in an entry's page number does (0x2d38d8)
	u32 page_shift = 12;

	if (large)
	{
		if (lp >= vas.page_size_count)
		{
			fmt::throw_exception("lv1_htab_lookup(): SLB LP %u names no page size of the address space", lp);
		}

		page_shift = static_cast<u32>((vas.page_sizes >> (56 - lp * 8)) & 0xff);
	}

	// Book III v2.02 4.5.2: the primary hash is the low 39 bits of the VSID XOR the page index within the
	// 256 MB segment, the secondary hash its complement; each selects a group of eight entries. An entry
	// matches when it is valid, its H bit names the hash used, its L bit the segment's, and its abbreviated
	// virtual page number (bits 0:56 of the virtual address, VSID || offset) agrees above the page size.
	const u64 groups = vas.htab.size() / 16;
	const u64 page_index = offset >> page_shift;
	const u64 hash = (vsid & 0x7fffffffff) ^ page_index;
	const u64 avpn_mask = page_shift > 23 ? ~((1ull << (page_shift - 23)) - 1) : ~0ull;
	const u64 avpn = ((vsid << 5) | (offset >> 23)) & avpn_mask;

	for (u64 h = 0; h < 2; h++)
	{
		const u64 group = (h ? ~hash : hash) & (groups - 1);

		for (u64 i = 0; i < 8; i++)
		{
			const u64 v = vas.htab[(group * 8 + i) * 2];
			const u64 r = vas.htab[(group * 8 + i) * 2 + 1];

			if (!(v & hpte_v_valid) || ((v >> 1) & 1) != h || ((v & hpte_v_large) != 0) != large || ((v >> 7) & avpn_mask) != avpn)
			{
				continue;
			}

			u64 base = r & 0x3ffffffffffff000;

			if (large)
			{
				// The ones from bit 12 on name the page size and are not part of the address (0x2d38d8..0x2d3938)
				if (std::countr_one(r >> 12) != lp)
				{
					continue;
				}

				base &= ~((1ull << page_shift) - 1);
			}

			return lv1_translation{base | (offset & ((1ull << page_shift) - 1)), page_shift, r};
		}
	}

	return std::nullopt;
}

void lv1_device_access(u64 lpar_addr, u8* data, u32 size, bool store)
{
	auto& lv1s = g_fxo->get<lv1_state>();
	std::unique_lock lock(lv1s.mutex);

	// A logical SPE's window: the problem state registers at 0x40000 and the privilege 2 ones at 0x60000
	// (lv1_construct_logical_spe). The local store is memory (lv1_memory_address) and the shadow registers
	// have not been followed.
	if (const auto spe_region = lv1s.spe_regions.upper_bound(lpar_addr); spe_region != lv1s.spe_regions.begin() && lpar_addr - std::prev(spe_region)->first < std::prev(spe_region)->second.size)
	{
		const auto& [base, region] = *std::prev(spe_region);
		auto& spe = lv1s.logical_spes.at(region.spe_id);
		const u64 spe_id = region.spe_id;
		const u64 offset = lpar_addr - base;

		if (base != spe.lpar_addr && offset == 0xf00 && size == 8 && !store)
		{
			// The shadow registers are lv1's memory, which it zeroes when it constructs the SPE (0x2fc250) and
			// updates as the SPE's state changes; the partition reads them. +0xf00 is the execution state, from
			// the state word of the SPE object (+0xb8) by 0x2f9738: its high word 1 (enabled) gives 3, 2 gives
			// 2 and 0 or 0x10 give 0. lv1_enable_logical_spe sets it to 1 << 32 | 2 (0x2fbe58..0x2fbe6c).
			write_to_ptr_unsafe<be_t<u64>>(data, spe.resource_id != umax ? 3 : 0);
			return;
		}

		if (base != spe.lpar_addr || offset < 0x40000 || !spe.spu)
		{
			fmt::throw_exception("Access to 0x%x of the %s of logical SPE %u (0x%x bytes, %s) is not implemented", offset, base != spe.lpar_addr ? "shadow registers" : "window", spe_id, size, store ? "store" : "load");
		}

		const auto spu = spe.spu;

		if (offset < 0x60000)
		{
			// The problem state registers, all 32 bits wide (Cell BE Handbook v1.1 Table 3-1), are the raw
			// SPU's. A store to a full SPU_In_Mbox makes the emulator retry the instruction, which the
			// supervisor path does not do.
			lock.unlock();
			const u32 reg = static_cast<u32>(offset - 0x40000);
			const u32 addr = spu->vm_offset() + RAW_SPU_PROB_OFFSET + reg;

			if (size != 4)
			{
				fmt::throw_exception("Access to problem state register 0x%x of logical SPE %u with %u bytes is not implemented", reg, spe_id, size);
			}

			if (store)
			{
				const u32 value = read_from_ptr_unsafe<be_t<u32>>(data, 0);
				lv1.trace("SPE %u problem state 0x%x <- 0x%x", spe_id, reg, value);

				if (reg == SPU_RunCntl_offs && value == SPU_RUNCNTL_STOP_REQUEST)
				{
					// A stop request, as RawSPUThread.cpp makes it, but with a bounded wait: once, ps2_emu's loader
					// (0x1cc74..0x1cd08, 128 run/stop pairs microseconds apart) left the raw SPU reported running
					// for good, a race in the emulator's SPU thread that has not been found. The wait reports the
					// SPU's state instead of hanging.
					std::lock_guard run_lock(spu->run_ctrl_mtx);
					spu->run_ctrl = value;

					if (spu->status_npc.load().status & SPU_STATUS_RUNNING)
					{
						spu->state += cpu_flag::stop + cpu_flag::ret;
						const u64 start = get_system_time();

						while (spu->status_npc.load().status & SPU_STATUS_RUNNING)
						{
							if (get_system_time() - start > 5'000'000)
							{
								fmt::throw_exception("SPE %u did not stop: pc=0x%x state=%s status=0x%x npc=0x%x", spe_id, spu->pc, spu->state.load(), spu->status_npc.load().status, spu->status_npc.load().npc);
							}

							std::this_thread::yield();
						}
					}

					return;
				}

				if (!spu->write_reg(addr, value) || (cpu_thread::get_current() && cpu_thread::get_current()->state & cpu_flag::again))
				{
					fmt::throw_exception("Store of 0x%x to problem state register 0x%x of logical SPE %u is not implemented", value, reg, spe_id);
				}
			}
			else
			{
				u32 value;

				if (!spu->read_reg(addr, value))
				{
					fmt::throw_exception("Load of problem state register 0x%x of logical SPE %u is not implemented", reg, spe_id);
				}

				write_to_ptr_unsafe<be_t<u32>>(data, value);
			}

			return;
		}

		// The privilege 2 registers, 64 bits wide (Cell BE Handbook v1.1 Table 3-1)
		const u64 reg = offset - 0x60000;

		if (reg == 0x4078 && size == 4 && store)
		{
			// APPROXIMATION (lv1.md, "Approximations"): ps2_emu stores a word to the first half of SPU_Cfg
			// (0x3f400, 3 again after the loader's doubleword store of 3 at 0x1cc54). That half is bits 0:31,
			// reserved (the modes are bits 62:63), and an access of another size than the register's is not
			// defined by the handbook; the model ignores it.
			lv1.trace("SPE %u privilege 2 0x%x <- word 0x%x (ignored)", spe_id, reg, read_from_ptr_unsafe<be_t<u32>>(data, 0));
			return;
		}

		if (size != 8)
		{
			fmt::throw_exception("Access to privilege 2 register 0x%x of logical SPE %u with %u bytes is not implemented", reg, spe_id, size);
		}

		const u64 value = store ? static_cast<u64>(read_from_ptr_unsafe<be_t<u64>>(data, 0)) : 0;
		lv1.trace("SPE %u privilege 2 0x%x %s 0x%x", spe_id, reg, store ? "<-" : "load", value);

		switch (reg)
		{
		case 0x1108:
		case 0x1110:
		case 0x1118:
		{
			// SLB_Index_W selects the entry SLB_ESID_RW and SLB_VSID_RW write (Linux loads an entry by writing the
			// index, then the VSID, then the ESID with V set)
			if (!store)
			{
				fmt::throw_exception("Load of privilege 2 register 0x%x of logical SPE %u is not implemented", reg, spe_id);
			}

			if (reg == 0x1108)
			{
				if (value >= spe.slb.size())
				{
					fmt::throw_exception("SLB index %u of logical SPE %u is past its 8 entries", value, spe_id);
				}

				spe.slb_index = value;
			}
			else
			{
				(reg == 0x1110 ? spe.slb[spe.slb_index].esid : spe.slb[spe.slb_index].vsid) = value;
			}

			return;
		}
		case 0x4058:
		{
			// SPU_LSLR, the local store limit. The emulator's SPU always addresses the full 256 KB, so another
			// limit is not followed.
			if (store)
			{
				if (value != SPU_LS_SIZE - 1)
				{
					fmt::throw_exception("A local store limit of 0x%x for logical SPE %u is not implemented", value, spe_id);
				}

				spe.lslr = value;
				return;
			}

			if (!spe.lslr)
			{
				fmt::throw_exception("SPU_LSLR of logical SPE %u before the partition writes it has not been determined", spe_id);
			}

			write_to_ptr_unsafe<be_t<u64>>(data, *spe.lslr);
			return;
		}
		case 0x4078:
		{
			// SPU_Cfg: bits 0 and 1 (from the right) select the logical OR mode of signal notification 1 and 2
			if (store)
			{
				if (value & ~3ull)
				{
					fmt::throw_exception("SPU_Cfg 0x%x for logical SPE %u is not implemented", value, spe_id);
				}

				spu->snr_config = value;
				return;
			}

			write_to_ptr_unsafe<be_t<u64>>(data, spu->snr_config);
			return;
		}
		default: break;
		}

		fmt::throw_exception("Privilege 2 register 0x%x of logical SPE %u (%s 0x%x) is not implemented", reg, spe_id, store ? "store" : "load", value);
	}

	const auto region = lv1s.io_regions.upper_bound(lpar_addr);

	if (region == lv1s.io_regions.begin() || lpar_addr - std::prev(region)->first >= std::prev(region)->second.size)
	{
		fmt::throw_exception("Device access at logical partition address 0x%llx (0x%x bytes, %s) outside the device windows the partition mapped is not implemented",
			lpar_addr, size, store ? "store" : "load");
	}

	const auto& [base, io] = *std::prev(region);
	const u64 bus_addr = io.bus_addr + (lpar_addr - base);

	const auto describe = [&]()
	{
		std::string value;

		if (store)
		{
			for (u32 i = 0; i < size; i++)
			{
				fmt::append(value, "%02x", data[i]);
			}
		}

		return fmt::format("bus %u device %u, bus address 0x%x, 0x%x bytes, %s%s", io.bus_id, io.dev_id, bus_addr, size, store ? "store " : "load", value);
	};

	// The USB host controllers: the OHCI registers at 0x3010000 + (device - 1) * 0x10000 and the EHCI ones
	// at 0x3810000 + (device - 1) * 0x10000 (the repository's reg nodes, lv1_map_device_mmio_region)
	if (io.bus_id == 1 && (io.dev_id == 1 || io.dev_id == 2))
	{
		auto& usb = usb_controller(lv1s, io.dev_id);
		const u64 ohci = 0x3010000 + (io.dev_id - 1) * 0x10000;

		if (bus_addr >= ohci && bus_addr < ohci + 0x1000)
		{
			lv1_usb_ohci_access(usb, static_cast<u32>(bus_addr - ohci), data, size, store);
			g_fxo->get<named_thread<lv1_usb_thread>>().active = 1;
			return;
		}

		const u64 ehci = 0x3810000 + (io.dev_id - 1) * 0x10000;

		if (bus_addr >= ehci && bus_addr < ehci + 0x1000)
		{
			lv1_usb_ehci_access(usb, static_cast<u32>(bus_addr - ehci), data, size, store);
			g_fxo->get<named_thread<lv1_usb_thread>>().active = 1;
			return;
		}
	}

	// The PS2 chip (bus 2, device 0, BAR0 at 0x60000000). Its registers are Sony's and not public; ps2_emu's
	// driver is the only description. Its first accesses are stores of its DMA windows and descriptors
	// (0x1d6d8..0x1d7cc: +0x10/+0x14 and +0x20/+0x24 the base and mask of two DMA regions, +0x80 a
	// logical SPE's SPU_In_Mbox through the third one, +0x84..+0xbc a table), which the model keeps. What
	// a load returns is followed register by register.
	if (io.bus_id == 2 && io.dev_id == 0 && size == 4 && !(bus_addr & 3))
	{
		const u64 offset = bus_addr - ps2_chip_bar0;

		if (store)
		{
			lv1s.ps2_chip_registers[offset] = read_from_ptr_unsafe<be_t<u32>>(data, 0);
			lv1.trace("PS2 chip: %s", describe());
			return;
		}
	}

	fmt::throw_exception("Device register not implemented: %s", describe());
}

static std::optional<u32> memory_address(const lv1_state& lv1s, u64 lpar_addr);

namespace
{
	// The emulator address the MFC of a logical SPE reaches at an effective address: the SPE's SLB and the hash
	// table of the address space the SPE was constructed with (the SPE's MFC translates for the partition like
	// its threads do, Cell BE Handbook v1.1 4.3). Whatever would make the MFC raise a class 1 interrupt (no
	// segment, no page, a protection violation) is not followed.
	u32 spe_translate(u64 spe_id, u64 ea, u32 size, bool store)
	{
		auto& lv1s = g_fxo->get<lv1_state>();
		reader_lock lock(lv1s.mutex);

		const auto& spe = lv1s.logical_spes.at(spe_id);
		u32 result = 0;

		for (u64 page = ea & ~0xfffull; page < ea + std::max<u32>(size, 1); page += 0x1000)
		{
			const auto entry = std::find_if(spe.slb.begin(), spe.slb.end(), [&](const auto& e)
			{
				return (e.esid & 0x8000000) && (e.esid >> 28) == (page >> 28);
			});

			if (entry == spe.slb.end())
			{
				fmt::throw_exception("SPE %u: an MFC access to 0x%llx outside the segments of its SLB is not implemented", spe_id, page);
			}

			const u64 vsid_data = entry->vsid;
			const auto translation = htab_lookup(lv1s, spe.vas_id, vsid_data >> 12, page & 0xfffffff, (vsid_data >> 8) & 1, (vsid_data >> 4) & 3);

			if (!translation)
			{
				fmt::throw_exception("SPE %u: an MFC access to 0x%llx the page table does not map is not implemented", spe_id, page);
			}

			// The key is Ks or Kp as the SPE's privilege state (MFC_SR1, lv1's) selects; only segments whose keys
			// agree are followed. The PP bits then allow as they do for the PPE (Book III 4.6).
			const bool ks = (vsid_data >> 11) & 1;
			const bool kp = (vsid_data >> 10) & 1;

			if (ks != kp)
			{
				fmt::throw_exception("SPE %u: an MFC access to 0x%llx in a segment with different Ks and Kp is not implemented", spe_id, page);
			}

			const u64 pp = translation->hpte_r & 3;

			if ((ks && pp == 0) || (store && (ks ? pp != 2 : pp == 3)))
			{
				fmt::throw_exception("SPE %u: an MFC %s of 0x%llx the page protection refuses is not implemented", spe_id, store ? "store" : "load", page);
			}

			const u64 lpar = translation->lpar_addr;
			u32 addr;

			if (lpar + 0x1000 <= lv1_guest_region0_size)
			{
				addr = static_cast<u32>(lpar);
			}
			else if (const auto memory = memory_address(lv1s, lpar))
			{
				addr = *memory;
			}
			else
			{
				fmt::throw_exception("SPE %u: an MFC access to 0x%llx (logical partition address 0x%llx) outside memory is not implemented", spe_id, page, lpar);
			}

			if (page == (ea & ~0xfffull))
			{
				result = addr | static_cast<u32>(ea & 0xfff);
			}
			else if (addr != (result & ~0xfffu) + (page - (ea & ~0xfffull)))
			{
				fmt::throw_exception("SPE %u: an MFC access across pages that do not follow each other (0x%llx, 0x%x bytes) is not implemented", spe_id, ea, size);
			}
		}

		return result;
	}
}

bool lv1_guest_running()
{
	return g_fxo->get<lv1_state>().ppu_ids[0] != 0;
}

std::optional<u32> lv1_memory_address(u64 lpar_addr)
{
	auto& lv1s = g_fxo->get<lv1_state>();
	reader_lock lock(lv1s.mutex);
	return memory_address(lv1s, lpar_addr);
}

static std::optional<u32> memory_address(const lv1_state& lv1s, u64 lpar_addr)
{
	// Memory lv1_allocate_memory gave
	if (const auto region = lv1s.memory_regions.upper_bound(lpar_addr); region != lv1s.memory_regions.begin() && lpar_addr - std::prev(region)->first < std::prev(region)->second.size)
	{
		return std::prev(region)->second.addr + static_cast<u32>(lpar_addr - std::prev(region)->first);
	}

	// The local store of a logical SPE bound to a physical one, at the start of its window
	const auto spe_region = lv1s.spe_regions.upper_bound(lpar_addr);

	if (spe_region == lv1s.spe_regions.begin())
	{
		return std::nullopt;
	}

	const auto& [base, region] = *std::prev(spe_region);
	const auto& spe = lv1s.logical_spes.at(region.spe_id);

	if (base != spe.lpar_addr || lpar_addr - base >= SPU_LS_SIZE)
	{
		return std::nullopt;
	}

	if (!spe.spu)
	{
		fmt::throw_exception("Access to the local store of logical SPE %u before a physical SPE is bound to it is not implemented", region.spe_id);
	}

	return spe.spu->vm_offset() + static_cast<u32>(lpar_addr - base);
}

u64 lv1_timebase()
{
	// The emulator's timebase, counted again at the console's frequency
	const u64 timebase = get_timebased_time();
	const u64 freq = sys_time_get_timebase_frequency();
	return timebase / freq * lv1_timebase_freq + timebase % freq * lv1_timebase_freq / freq;
}

void lv1_set_inter_lpar_parameter(std::span<const u8> parameter)
{
	std::lock_guard lock(g_inter_lpar_parameter_mutex);
	g_inter_lpar_parameter.assign(parameter.begin(), parameter.end());
}

void lv1_register_guest_threads(u32 thread0_id, u32 thread1_id)
{
	auto& lv1s = g_fxo->get<lv1_state>();
	lv1s.ppu_ids[0] = thread0_id;
	lv1s.ppu_ids[1] = thread1_id;
}

bool lv1_is_guest_os(u64 program_authority_id, u32 program_type)
{
	// PAID_05 is the authority ID of every image in /dev_flash/ps2emu (Crypto/key_vault.h), and the SELF
	// header of ps2_emu.self from firmware 4.93 carries it together with program type 3, the LV2 key
	// class that the GameOS kernel itself belongs to. A GameOS process is program type 4 (APP) or 8
	// (NPDRM), so the pair names exactly the images lv1 boots as a partition's operating system.
	return static_cast<s64>(program_authority_id) == PAID_05 && program_type == KEY_LV2;
}

// One hypervisor call: the arguments are in[3] to in[10] (r3 to r10 at the sc), the status goes to r3 and
// further results to r4 onwards, which are 0 when the call does not set them
static void lv1_call(ppu_thread& ppu, u64 code, const std::array<u64, 11>& in)
{
	const u32 hw_thread = ppu.supervisor->hw_thread;
	auto& lv1s = g_fxo->get<lv1_state>();

	switch (code)
	{
	case 1:
	{
		// lv1_write_htab_entry(vas_id, index, hpte_v, hpte_r) (lv1 4.93 0x2ed1c0, writer 0x2d368c): stores one entry
		// of an address space's hash table. The real page number in hpte_r is a logical partition address.
		const u64 vas_id = in[3];
		const u64 index = in[4];
		const u64 hpte_v = in[5];
		const u64 hpte_r = in[6];
		lv1.trace("lv1_write_htab_entry(vas_id=%u, index=0x%x, hpte_v=0x%016x, hpte_r=0x%016x)", vas_id, index, hpte_v, hpte_r);

		std::lock_guard lock(lv1s.mutex);
		const auto vas = find_vas(lv1s, vas_id);

		if (!vas)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (index >= vas->htab.size() / 2)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		// Bits 0:1 and 52:53 of the second doubleword are reserved (0x2ed488..0x2ed494), and a large page may not
		// have bits 45:51 all set (0x2ed498..0x2ed4a4, 0x2ed634)
		if ((hpte_r & 0xc000000000000c00) || ((hpte_r & 0x7f000) == 0x7f000 && (hpte_v & hpte_v_large)))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		// The abbreviated virtual page number has to lie in the 65 bits of virtual address that the PPE
		// implements (0x2ed4a8..0x2ed4bc, with 65 from 0x2b9ce8)
		if (hpte_v >> 49)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		u32 page_shift = 12;
		u64 address = hpte_r & 0x3ffffffffffff000;

		if (hpte_v & hpte_v_large)
		{
			// A large page names its size by the number of ones from bit 12 of the second doubleword on, which
			// indexes the page sizes the address space was constructed with; those bits are not part of the
			// address, which has to be aligned to the page (0x2d38d8..0x2d3938)
			const u32 ones = std::countr_one(hpte_r >> 12);

			if (ones >= vas->page_size_count)
			{
				ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 8);
				return;
			}

			page_shift = static_cast<u32>((vas->page_sizes >> (56 - ones * 8)) & 0xff);
			address -= (1ull << (12 + ones)) - 0x1000;

			if (address & ((1ull << page_shift) - 1))
			{
				ppu.gpr[3] = lv1_status(LV1_ALIGNMENT_ERROR, 8);
				return;
			}
		}

		// lv1 looks the page of a valid entry up in the partition's memory (0x2d368c -> 0x2d2510): by the
		// allocator slot of the address (its class, bits 42 to 47), then the offset has to be below the size of
		// the region there (0x2d25b0..0x2d25c4). A page outside, or an address the partition's allocator does
		// not hold (0x2ce74c), gives the error 0x997997d2b58e3c01, which write_htab_entry answers with
		// ACCESS_VIOLATION (0x2ed55c..0x2ed5fc). ps2_emu maps 64 KB of the driver info although lv1 gives
		// 0xc000 (0x457e4), so its last four pages are refused this way.
		if ((hpte_v & hpte_v_valid) && !lpar_page_owned(lv1s, address, 1ull << page_shift))
		{
			ppu.gpr[3] = lv1_status(LV1_ACCESS_VIOLATION);
			return;
		}

		vas->htab[index * 2] = hpte_v;
		vas->htab[index * 2 + 1] = hpte_r;
		g_htab_generation++;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 2:
	{
		// lv1_construct_virtual_address_space(htab_size, number_of_sizes, page_sizes) -> vas_id, act_htab_size
		// (lv1 4.93 0x2ec554). htab_size is the log2 of the hash table size: above 20 it is refused and below
		// 18 it is raised to 18 (0x2ec644..0x2ec654), so the 0 that ps2_emu.elf passes (0x47a4) makes a 256 KB
		// table. There may be two page sizes at most (0x2b9ce0), each the log2 16, 20 or 24 in one byte,
		// starting from the most significant one (0x2b9cf8). The size is returned in bytes (0x2ec6b0..0x2ec6c8).
		const u64 htab_size = in[3];
		const u64 number_of_sizes = in[4];
		const u64 page_sizes = in[5];
		lv1.notice("lv1_construct_virtual_address_space(htab_size=%u, number_of_sizes=%u, page_sizes=0x%016x)", htab_size, number_of_sizes, page_sizes);

		if (htab_size > 20)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (number_of_sizes > 2)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		for (u64 i = 0; i < number_of_sizes; i++)
		{
			const u64 shift = (page_sizes >> (56 - i * 8)) & 0xff;

			if (shift != 16 && shift != 20 && shift != 24)
			{
				ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
				return;
			}
		}

		// A new table holds no valid entry: Linux, which inserts its own entries the same way, never clears
		// the table it is given (arch/powerpc/platforms/ps3/htab.c clears it only in ps3_hpte_clear, for kexec)
		lv1_vas vas;
		vas.htab_log2 = std::max<u32>(static_cast<u32>(htab_size), 18);
		vas.page_size_count = static_cast<u32>(number_of_sizes);
		vas.page_sizes = page_sizes;
		vas.htab.resize((1ull << vas.htab_log2) / sizeof(u64));

		const u64 act_htab_size = 1ull << vas.htab_log2;

		std::lock_guard lock(lv1s.mutex);
		const u64 vas_id = allocate_object_id(lv1s);
		lv1s.vases.emplace(vas_id, std::move(vas));

		lv1.notice("lv1_construct_virtual_address_space() -> vas_id %u, htab_size 0x%x", vas_id, act_htab_size);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = vas_id;
		ppu.gpr[5] = act_htab_size;
		return;
	}
	case 7:
	{
		// lv1_select_virtual_address_space(vas_id) (lv1 4.93 0x2eafe4): the address space's hash table becomes
		// the one SDR1 holds. 0 selects the partition's initial address space (0x2eb258); an id that names no
		// address space of the partition is LV1_NO_ENTRY for the first argument (0x2eb198).
		const u64 vas_id = in[3];
		lv1.notice("lv1_select_virtual_address_space(vas_id=%u)", vas_id);

		std::lock_guard lock(lv1s.mutex);

		if (vas_id && !lv1s.vases.contains(vas_id))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		lv1s.selected_vas = vas_id;
		g_htab_generation++;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 9:
	{
		// lv1_pause(mode) (lv1 4.93 0x2eb618, 0x2c68c4): the thread stays inactive until one of its plugs is
		// raised and unmasked; with mode 0 an expired Decrementer also ends the pause (0x2c6380), with mode 1 it
		// does not. Modes other than 0 and 1 are ILLEGAL for the first argument (0x2eb6b4). What becomes of the
		// Decrementer is lv1_hypercall's.
		const u64 mode = in[3];
		lv1.trace("lv1_pause(mode=0x%x)", mode);

		if (mode > 1)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		auto& sv = *ppu.supervisor;

		while (!ppu.is_stopped())
		{
			if (sv.external_pending)
			{
				break;
			}

			u64 timeout = umax;

			if (mode == 0)
			{
				const u64 timebase = lv1_timebase();

				if (sv.dec_exception(timebase))
				{
					break;
				}

				// Microseconds until DEC turns negative
				timeout = (u64{sv.read_dec(timebase)} + 1) * 1'000'000 / lv1_timebase_freq + 1;
			}

			thread_ctrl::wait_on(sv.external_pending, 0u, timeout);
		}

		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 18:
	{
		// lv1_construct_event_receive_port() -> outlet (lv1 4.93 0x2ef424, 0x2e24e8): an outlet of the partition
		// that lv1_send_event_locally() raises
		std::lock_guard lock(lv1s.mutex);

		const u64 outlet = allocate_object_id(lv1s);
		lv1s.outlets.emplace(outlet, lv1_outlet{.event_port = true});

		lv1.notice("lv1_construct_event_receive_port() -> outlet 0x%x", outlet);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = outlet;
		return;
	}
	case 24:
	{
		// lv1_send_event_locally(outlet) (lv1 4.93 0x2ef530, 0x2e269c): raises an event receive port of the
		// partition; an id that names none, an I/O interrupt outlet included, is NO_ENTRY for the first argument
		const u64 outlet = in[3];
		lv1.trace("lv1_send_event_locally(outlet=0x%x)", outlet);

		std::lock_guard lock(lv1s.mutex);
		const auto found = lv1s.outlets.find(outlet);

		if (found == lv1s.outlets.end() || !found->second.event_port)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		raise_outlet(lv1s, found->second);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 26:
	{
		// lv1_detect_pending_interrupts(0) -> the calling thread's plug status (lv1 4.93 0x2eac98, 0x2c3cc8): the
		// plugs whose connected outlet is raised, masked or not, changing nothing. Anything but 0 is ILLEGAL for
		// the first argument (0x2ead18).
		if (in[3] != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);
		const auto& irq = lv1s.irq[hw_thread];

		for (u32 i = 0; i < 4; i++)
		{
			ppu.gpr[4 + i] = irq.status[i];
		}

		lv1.trace("lv1_detect_pending_interrupts() -> 0x%016x 0x%016x 0x%016x 0x%016x", ppu.gpr[4], ppu.gpr[5], ppu.gpr[6], ppu.gpr[7]);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 27:
	{
		// lv1_end_of_interrupt(plug) (lv1 4.93 0x2eab90, 0x2e59cc -> 0x2dfea8 -> 0x2dfc5c): lowers the outlet
		// connected to the plug of the calling thread and clears the plug's status. A plug above 255 is ILLEGAL,
		// a plug with no outlet NO_ENTRY and one whose outlet is not raised WRONG_STATE, all for the first
		// argument. lv1 then tells the outlet's listeners (0x2dfd88..0x2dfdc4), which raise it again while their
		// source still asks: the virtual UART's while a port's bit is set in its bitmap (0x2f118c, the count at
		// +0x898), a south bridge interrupt's while its device keeps the line up (the interrupt is level).
		const u64 plug = in[3];
		lv1.trace("lv1_end_of_interrupt(plug=%u)", plug);

		if (plug > 255)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);
		const auto& plug_outlets = lv1s.irq[hw_thread].plug_outlets;
		const auto connected = plug_outlets.find(static_cast<u32>(plug));

		if (connected == plug_outlets.end())
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		auto& outlet = lv1s.outlets.at(connected->second);

		if (!outlet.raised)
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE, 1);
			return;
		}

		outlet.raised = false;
		set_plug_status(lv1s, hw_thread, static_cast<u32>(plug), false);

		if (!outlet.event_port && outlet_still_asked(lv1s, connected->second))
		{
			raise_outlet(lv1s, outlet);
		}

		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 28:
	{
		// lv1_connect_irq_plug(plug, outlet) (lv1 4.93 0x2eaecc, 0x2e7018 -> 0x2df968): connects an outlet of the
		// partition to a plug of the calling PPE thread (its index from CTRL, 0x2e7268). A plug above 255 is
		// ILLEGAL for the first argument, an id that names no outlet NO_ENTRY for the second, an outlet connected
		// already DUPLICATE for the second and a plug in use DUPLICATE for the first. The plug takes the outlet's
		// state: pending if it is raised, clear otherwise (0x2dfa94).
		const u64 plug = in[3];
		const u64 outlet = in[4];
		lv1.notice("lv1_connect_irq_plug(plug=%u, outlet=0x%x) on PPE thread %u", plug, outlet, hw_thread);

		if (plug > 255)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);
		const auto found = lv1s.outlets.find(outlet);

		if (found == lv1s.outlets.end())
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		if (found->second.hw_thread != umax)
		{
			ppu.gpr[3] = lv1_status(LV1_DUPLICATE_ENTRY, 2);
			return;
		}

		auto& plug_outlets = lv1s.irq[hw_thread].plug_outlets;

		if (!plug_outlets.emplace(static_cast<u32>(plug), outlet).second)
		{
			ppu.gpr[3] = lv1_status(LV1_DUPLICATE_ENTRY, 1);
			return;
		}

		found->second.hw_thread = hw_thread;
		found->second.plug = static_cast<u32>(plug);
		set_plug_status(lv1s, hw_thread, static_cast<u32>(plug), found->second.raised);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 0:
	{
		// lv1_allocate_memory(size, page_shift, arg3, flags) -> lpar_addr, 1 (lv1 4.93 0x2df470 -> 0x2dee58): memory
		// for the partition. A size above 1 << 62 is ILLEGAL for the first argument, a page shift outside 12 to 61
		// for the second, a size that is not a multiple of the page ILLEGAL for the first; a third argument above 1
		// is NO_ENTRY for it and flags above 0xf ILLEGAL for the fourth. lv1 then takes the pages one by one from
		// the physical memory pool (0x2c14bc) and gives the region a logical partition address from the
		// partition's allocator (0x2dea14); the second result is always 1 (0x2df280).
		const u64 size = in[3];
		const u64 page_shift = in[4];
		const u64 arg3 = in[5];
		const u64 flags = in[6];
		lv1.notice("lv1_allocate_memory(size=0x%x, page_shift=%u, 0x%x, flags=0x%x)", size, page_shift, arg3, flags);

		if (size > 0x3fffffffffffffff)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (page_shift - 12 > 0x31)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		if (size & ((1ull << page_shift) - 1))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (arg3 > 1)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 4);
			return;
		}

		if (flags > 0xf)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		// What the third argument and the flags select (flag 8 places the region at address 0 for lparmgr's
		// first allocation) has not been followed for other values than 0
		if (arg3 != 0 || flags != 0 || !size)
		{
			fmt::throw_exception("lv1_allocate_memory(0x%x, %u, 0x%x, 0x%x) is not implemented", size, page_shift, arg3, flags);
		}

		// APPROXIMATION (lv1.md, "Approximations"): the physical memory lv1 has left and any limit it keeps for
		// the partition have not been followed; the allocation succeeds. In the PS2 mode the GameOS partition does
		// not exist, and ps2_emu's memory card cache (0x10fcc, 17 MB) is this memory.
		ppu.state += cpu_flag::wait;
		std::unique_lock lock(lv1s.mutex);

		const u32 addr = vm::alloc(static_cast<u32>(size), vm::main, 0x10000);

		if (!addr || size > u32{umax})
		{
			fmt::throw_exception("lv1_allocate_memory(): the emulator has no room for 0x%x bytes", size);
		}

		const u64 lpar_addr = lpar_allocate(lv1s, "lv1_allocate_memory()", size);
		lv1s.memory_regions.emplace(lpar_addr, lv1_state::memory_region{size, addr});
		lock.unlock();
		ppu.check_state();

		lv1.notice("lv1_allocate_memory() -> lpar_addr 0x%x", lpar_addr);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = lpar_addr;
		ppu.gpr[5] = 1;
		return;
	}
	case 57:
	{
		// lv1_construct_logical_spe(pshift1, pshift2, pshift3, pshift4, pshift5, vas_id, spe_type) -> priv2_addr,
		// problem_addr, local_store_addr, unused, shadow_addr, spe_id (lv1 4.93 0x31ab6c -> 0x31a34c)
		const u64 vas_id = in[8];
		const u64 spe_type = in[9];
		lv1.notice("lv1_construct_logical_spe(pshift=0x%x, 0x%x, 0x%x, 0x%x, 0x%x, vas_id=%u, spe_type=%u)", in[3], in[4], in[5], in[6], in[7], vas_id, spe_type);

		// Each page shift has to be from 12 to 61 (0x31a35c..0x31a3e0) and, past that, one above 48 is
		// RESOURCE_SHORTAGE without naming it (0x31a3e4..0x31a458)
		for (u32 i = 0; i < 5; i++)
		{
			if (in[3 + i] - 12 > 0x31)
			{
				ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1u << i);
				return;
			}
		}

		for (u32 i = 0; i < 5; i++)
		{
			if (in[3 + i] > 0x30)
			{
				ppu.gpr[3] = lv1_status(LV1_RESOURCE_SHORTAGE);
				return;
			}
		}

		std::lock_guard lock(lv1s.mutex);

		// The address space has to be an object of the partition of that type (0x31a46c..0x31a584), whose state
		// word at +0x90 0x2d29e8 then reads under the object's lock; the address spaces lv1_construct_virtual_
		// address_space makes pass it. The partition's initial address space is not such an object (id 0 is the
		// logical PU's).
		if (!lv1s.vases.contains(vas_id))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 0x20);
			return;
		}

		// Type 0 is built by 0x2fb734, type 1 by 0x31588c and type 2 by 0x3186cc; any other is an illegal
		// seventh argument (0x31a684..0x31a6b4). Only type 0, which ps2_emu.elf asks for, is followed.
		if (spe_type > 2)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x40);
			return;
		}

		if (spe_type != 0)
		{
			fmt::throw_exception("lv1_construct_logical_spe(): SPE type %u is not implemented", spe_type);
		}

		// 0x2fb734: the SPE object takes its id first (0x2fb7d8 -> 0x2fa614 -> 0x2cc64c), then lv1 allocates
		// the SPE's window, 512 KB with 4 KB pages (0x2fecdc, the physical SPE is not bound yet), and the shadow
		// registers, 1 << pshift5 bytes with pages of that size (0x2ff4ec). pshift1 to pshift4 are only checked.
		// The three outlets of the SPE's interrupt classes follow (0x2fb8b8..0x2fb948: 0x2ff934 -> 0x2df60c ->
		// 0x2cc64c), and both windows are entered in the partition's memory (0x2fba58, 0x2fba8c).
		const u64 spe_id = allocate_object_id(lv1s);
		const u64 lpar_addr = lpar_allocate(lv1s, "lv1_construct_logical_spe()", 0x80000);
		const u64 shadow_size = 1ull << in[7];
		const u64 shadow_lpar_addr = lpar_allocate(lv1s, "lv1_construct_logical_spe()", shadow_size);

		lv1_state::logical_spe spe{vas_id, lpar_addr, shadow_lpar_addr, {}};

		for (u64& outlet : spe.outlets)
		{
			outlet = allocate_object_id(lv1s);
			lv1s.outlets.emplace(outlet, lv1_outlet{});
		}

		lv1s.logical_spes.emplace(spe_id, spe);
		lv1s.spe_regions.emplace(lpar_addr, lv1_state::spe_region{0x80000, spe_id});
		lv1s.spe_regions.emplace(shadow_lpar_addr, lv1_state::spe_region{shadow_size, spe_id});

		// The local store is at the start of the window, the problem state registers at 0x40000 and the
		// privilege 2 ones at 0x60000 (0x2fbab0..0x2fbadc), as in the SPE's own register space (Cell BE
		// Handbook v1.1 Table 3-1). The fourth output is cleared (0x31a68c).
		lv1.notice("lv1_construct_logical_spe() -> spe_id %u, local store 0x%x, shadow 0x%x, outlets 0x%x, 0x%x, 0x%x", spe_id, lpar_addr, shadow_lpar_addr, spe.outlets[0], spe.outlets[1], spe.outlets[2]);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = lpar_addr + 0x60000;
		ppu.gpr[5] = lpar_addr + 0x40000;
		ppu.gpr[6] = lpar_addr;
		ppu.gpr[7] = 0;
		ppu.gpr[8] = shadow_lpar_addr;
		ppu.gpr[9] = spe_id;
		return;
	}
	case 207:
	{
		// lv1_enable_logical_spe(spe_id, resource_id) (lv1 4.93 0x2fd394): binds a physical SPE to the logical
		// SPE and starts it. The id has to name a logical SPE of the partition (0x2fd420..0x2fd544), NO_ENTRY
		// for the first argument otherwise.
		const u64 spe_id = in[3];
		const u64 resource_id = in[4];
		lv1.notice("lv1_enable_logical_spe(spe_id=%u, resource_id=%u)", spe_id, resource_id);

		ppu.state += cpu_flag::wait;
		std::unique_lock lock(lv1s.mutex);

		const auto found = lv1s.logical_spes.find(spe_id);

		if (found == lv1s.logical_spes.end())
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		// 0x2fbda8: an SPE already enabled (state 1 << 32 | 2 or | 3 at +0xb8) is WRONG_STATE for the first
		// argument
		if (found->second.resource_id != umax)
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE, 1);
			return;
		}

		// The resources are the SPE manager's list (0x3174e8, the manager at 0x373ef0): lv1 fills it at boot
		// with the usable SPEs (0x3b057c) in the ring order 0, 2, 4, 6, 7, 5, 3, 1 (0x329af8) starting after
		// the first system SPE, so the system SPE comes last, with type 2 and the others with type 1
		// (0x3b02f0..0x3b03e8). Usable and system SPEs come from the loader parameter be.0.spu.faultbm and
		// sys.cellos.spu.configure (0x3b05d0..0x3b0730). DERIVED WITH PUBLIC FACTS: the Cell of every PS3
		// has 7 of its 8 SPEs enabled, one of which is kept by the system (psdevwiki "SPE"), and lv1 does have
		// a system SPE, which the isolated SPU modules ps2_emu uses (sv_iso_for_ps2emu) run on, so there are
		// 7 resources and the last one is the system SPE. Resources 0 to 5 do not depend on which physical SPE
		// is disabled.
		constexpr u64 spe_resources = 7;

		if (resource_id >= spe_resources)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		if (resource_id == spe_resources - 1)
		{
			// The system SPE needs a privilege of the partition (0x3176e0 -> 0x31d7d8) and is claimed from lv1's
			// own use (0x3173d4); not followed
			fmt::throw_exception("lv1_enable_logical_spe(): the system SPE is not implemented");
		}

		// A resource another logical SPE holds is BUSY for the second argument (0x3175f4..0x3175fc)
		for (const auto& [id, spe] : lv1s.logical_spes)
		{
			if (spe.resource_id == resource_id)
			{
				ppu.gpr[3] = lv1_status(LV1_BUSY, 2);
				return;
			}
		}

		// The physical SPE is an SPU of the emulator run as a raw SPU, the raw SPU of the resource's number
		if (resource_id >= std::size(spu_thread::g_raw_spu_id))
		{
			fmt::throw_exception("lv1_enable_logical_spe(): resource %u is past the emulator's raw SPUs", resource_id);
		}

		const u32 index = static_cast<u32>(resource_id);
		const auto spu = idm::make_ptr<named_thread<spu_thread>>(nullptr, index, fmt::format("SPE %u", spe_id), index);
		ensure(vm::get(vm::spu)->falloc(spu->vm_offset(), SPU_LS_SIZE, &spu->shm, vm::page_size_64k));
		spu->map_ls(*spu->shm, spu->ls);
		spu_thread::g_raw_spu_ctr++;
		spu_thread::g_raw_spu_id[index] = idm::last_id();

		// The interrupt masks set so far go to the SPE (0x2ffba4), and its pending interrupts raise the class
		// outlets
		for (u32 cls = 0; cls < 3; cls++)
		{
			spu->int_ctrl[cls].mask = found->second.interrupt_masks[cls];
			spu->int_ctrl[cls].lv1_raise = [spe_id, cls]()
			{
				auto& lv1s = g_fxo->get<lv1_state>();
				std::lock_guard lock(lv1s.mutex);
				raise_outlet(lv1s, lv1s.outlets.at(lv1s.logical_spes.at(spe_id).outlets[cls]));
			};
		}

		spu->lv1_translate = [spe_id](u64 ea, u32 size, bool store)
		{
			return spe_translate(spe_id, ea, size, store);
		};

		found->second.resource_id = resource_id;
		found->second.spu = spu;
		lock.unlock();

		ppu.check_state();
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 61:
	{
		// lv1_set_spe_interrupt_mask(spe_id, class, mask) (lv1 4.93 0x2fe570 -> 0x2fe340): a class above 2 is an
		// illegal second argument (0x2fe36c) and an id that names no logical SPE of the partition NO_ENTRY for
		// the first (0x2fe498). The mask keeps the bits the class has (0x2fa23c, the table at 0x329a98: class
		// 0 all but bits 3 and 32, the others all) and goes to the class object, which writes it to the SPE's
		// INT_Mask register if a physical SPE is bound and never fails (0x2ffba4).
		const u64 spe_id = in[3];
		const u64 int_class = in[4];
		const u64 mask = in[5];
		lv1.notice("lv1_set_spe_interrupt_mask(spe_id=%u, class=%u, mask=0x%x)", spe_id, int_class, mask);

		if (int_class > 2)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		const auto found = lv1s.logical_spes.find(spe_id);

		if (found == lv1s.logical_spes.end())
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		found->second.interrupt_masks[int_class] = mask & (int_class == 0 ? 0xfffffffefffffff7 : umax);

		if (found->second.spu)
		{
			found->second.spu->int_ctrl[int_class].mask = found->second.interrupt_masks[int_class];
		}

		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 73:
	{
		// lv1_set_interrupt_mask(0, mask0, mask1, mask2, mask3) (lv1 4.93 0x2eaa28, 0x2c356c): the 256-bit mask of
		// the calling thread's plugs, a set bit enabling the plug (the exit test at 0xfc4 ands it with the
		// status); ps2_emu.elf passes one bank per thread (0x3a74, 0x4fd938 + 0x930). A first argument other than
		// 0 is ILLEGAL (0x2eaac8).
		if (in[3] != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		lv1.notice("lv1_set_interrupt_mask(0, 0x%016x, 0x%016x, 0x%016x, 0x%016x) on PPE thread %u", in[4], in[5], in[6], in[7], hw_thread);

		std::lock_guard lock(lv1s.mutex);
		auto& irq = lv1s.irq[hw_thread];

		for (u32 i = 0; i < 4; i++)
		{
			irq.mask[i] = in[4 + i];
		}

		update_external_line(lv1s, hw_thread);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 78:
	{
		// lv1_get_spe_irq_outlet(spe_id, class) -> outlet (lv1 4.93 0x2fc968 -> 0x2fc738): the outlet lv1 made for
		// the class when it constructed the SPE (0x2fa588). A class above 2 is an illegal second argument
		// (0x2fc738) and an id that names no logical SPE of the partition NO_ENTRY for the first (0x2fc890).
		const u64 spe_id = in[3];
		const u64 int_class = in[4];

		if (int_class > 2)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		const auto found = lv1s.logical_spes.find(spe_id);

		if (found == lv1s.logical_spes.end())
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		lv1.notice("lv1_get_spe_irq_outlet(spe_id=%u, class=%u) -> outlet 0x%x", spe_id, int_class, found->second.outlets[int_class]);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = found->second.outlets[int_class];
		return;
	}
	case 91:
	{
		// lv1_read_repository_node(lpar_id, n1, n2, n3, n4) -> v1, v2 (lv1 4.93 0x2e52c4, lookup 0x2e3d20): reads a
		// node of the given partition's repository. lpar 0 names none (0x2e5364), and a node that does not exist
		// is LV1_NO_ENTRY for the four keys (0x2e3e9c).
		const u64 lpar_id = in[3];
		const repo_keys keys{in[4], in[5], in[6], in[7]};

		if (!lpar_id)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (lpar_id != 1)
		{
			fmt::throw_exception("lv1_read_repository_node(): the repository of partition %u has not been investigated (%s)", lpar_id, repo_path(keys));
		}

		u64 v1 = 0, v2 = 0;

		switch (pme_repository_read(keys, v1, v2))
		{
		case repo_lookup::found:
		{
			lv1.notice("lv1_read_repository_node(1, %s) -> 0x%x, 0x%x", repo_path(keys), v1, v2);
			ppu.gpr[3] = LV1_SUCCESS;
			ppu.gpr[4] = v1;
			ppu.gpr[5] = v2;
			return;
		}
		case repo_lookup::absent:
		{
			lv1.notice("lv1_read_repository_node(1, %s) -> no entry", repo_path(keys));
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 0x1e);
			return;
		}
		case repo_lookup::unknown: break;
		}

		fmt::throw_exception("lv1_read_repository_node(1, %s): node not modelled (keys 0x%x 0x%x 0x%x 0x%x)", repo_path(keys), keys[0], keys[1], keys[2], keys[3]);
	}
	case 95:
	{
		// lv1_read_htab_entries(vas_id, index) (lv1 4.93 0x2ecaf8, reader 0x2d1720): the first doublewords of the
		// four entries from index on, and the low 16 bits of their second doublewords packed into a fifth result,
		// the first entry's in the most significant halfword (so, as Linux notes in htab.c, never the real page
		// number). The four entries have to lie in the table (0x2ecd88..0x2ecda4); index needs no alignment.
		const u64 vas_id = in[3];
		const u64 index = in[4];
		lv1.trace("lv1_read_htab_entries(vas_id=%u, index=0x%x)", vas_id, index);

		std::lock_guard lock(lv1s.mutex);
		const auto vas = find_vas(lv1s, vas_id);

		if (!vas)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		const u64 entries = vas->htab.size() / 2;

		if (entries < index + 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		// For the largest indices index + 4 wraps, the comparison passes and lv1 reads past its table, which
		// cannot be reproduced
		if (index > entries - 4)
		{
			fmt::throw_exception("lv1_read_htab_entries(): index 0x%x makes lv1 read past its table", index);
		}

		u64 low_halfwords = 0;

		for (u32 i = 0; i < 4; i++)
		{
			ppu.gpr[4 + i] = vas->htab[(index + i) * 2];
			low_halfwords = low_halfwords << 16 | (vas->htab[(index + i) * 2 + 1] & 0xffff);
		}

		ppu.gpr[8] = low_halfwords;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 105:
	{
		// Undocumented; 105 to 112, 124 to 126, 135, 136 and 231 are the debug card's calls (lv1 4.93 0x312714
		// for 105). The first of them to run reads the repository node sys.dbgcard.dgbe: when it does not
		// change the default of 6, as on a retail console, which has no such node (psdevwiki's 3.41 retail
		// repository), all of them return status 0 from then on and do nothing (0x312784..0x312808).
		// ps2_emu.elf calls 105 first of all at 0x3c24 with (1, 0, 0, 0x1000, 0x1000, 0, 0).
		lv1.notice("lv1_undocumented_function_105(0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x, 0x%x)", in[3], in[4], in[5], in[6], in[7], in[8], in[9]);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 107:
	{
		// Undocumented; a debug card call like 105 (lv1 4.93 0x312ee4), so on a retail console it returns 0
		// and does nothing. ps2_emu.elf 0x3c64..0x3c80 passes 1, a length and up to 32 bytes of text in r5-r8
		// (its build tag "ps2ver:..."), which is kept in the log here.
		const be_t<u64> words[4]{in[5], in[6], in[7], in[8]};
		const std::string_view text(reinterpret_cast<const char*>(words), std::min<u64>(in[4], sizeof(words)));
		lv1.notice("lv1_undocumented_function_107(0x%x, 0x%x): \"%s\"", in[3], in[4], text);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 109:
	{
		// Undocumented; a debug card call like 105 (lv1 4.93 0x31327c), so on a retail console it returns 0
		// and does nothing. ps2_emu.elf calls it after 107, at 0x3c88, with the argument 1.
		lv1.notice("lv1_undocumented_function_109(0x%x)", in[3]);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 120:
	{
		// lv1_construct_io_irq_outlet(interrupt_id) -> outlet (lv1 4.93 0x2c0604): an outlet the south bridge
		// interrupt raises, connected to it in the interrupt controller (0x2c0394). Interrupt ids above 0x3f are
		// NO_ENTRY and an interrupt that already has an outlet is BUSY, both for the first argument
		// (0x2c092c, 0x2c0940). The ids come from the repository (bus1.devN.intrM, second value).
		const u64 interrupt_id = in[3];
		lv1.notice("lv1_construct_io_irq_outlet(interrupt_id=0x%x)", interrupt_id);

		if (interrupt_id > 0x3f)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (lv1s.io_irq_outlets.contains(interrupt_id))
		{
			ppu.gpr[3] = lv1_status(LV1_BUSY, 1);
			return;
		}

		const u64 outlet = allocate_object_id(lv1s);
		lv1s.outlets.emplace(outlet, lv1_outlet{});
		lv1s.io_irq_outlets.emplace(interrupt_id, outlet);

		lv1.notice("lv1_construct_io_irq_outlet() -> outlet 0x%x", outlet);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = outlet;
		return;
	}
	case 162:
	{
		// lv1_read_virtual_uart(port, lpar_addr, bytes) -> bytes_read (lv1 4.93 0x2f429c): the checks of
		// lv1_write_virtual_uart (NO_ENTRY for the port, NO_ENTRY and TYPE_MISMATCH for the buffer); lv1 copies
		// what the port's buffer holds, up to the size asked (0x2f44f4 -> 0x2f06c0), and the port's state
		// changes.
		const u64 port = in[3];
		const u64 addr = in[4];
		const u64 bytes = in[5];

		if (port > 0xff)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		const auto found = lv1s.vuart_ports.find(port);

		if (found == lv1s.vuart_ports.end())
		{
			fmt::throw_exception("lv1_read_virtual_uart(): whether the partition has port %u has not been determined", port);
		}

		if (addr >= 1ull << 62 || !lpar_page_owned(lv1s, addr, 1))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		if (addr >= lv1_guest_region0_size)
		{
			fmt::throw_exception("lv1_read_virtual_uart(): a buffer at 0x%x, outside the memory from address 0, is not implemented", addr);
		}

		if (bytes > lv1_guest_region0_size - addr)
		{
			ppu.gpr[3] = lv1_status(LV1_TYPE_MISMATCH, 2);
			return;
		}

		auto& rx = found->second.rx;
		const u64 count = std::min<u64>(bytes, rx.size());
		std::copy_n(rx.begin(), count, vm::_ptr<u8>(static_cast<u32>(addr)));
		rx.erase(rx.begin(), rx.begin() + count);

		vuart_update_interrupt(lv1s, port);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = count;
		return;
	}
	case 163:
	{
		// lv1_write_virtual_uart(port, lpar_addr, bytes) -> bytes_written (lv1 4.93 0x2f2af4)
		const u64 port = in[3];
		const u64 addr = in[4];
		const u64 bytes = in[5];

		if (port > 0xff)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.vuart_ports.contains(port))
		{
			fmt::throw_exception("lv1_write_virtual_uart(): whether the partition has port %u has not been determined", port);
		}

		// The buffer has to be in the partition's memory (NO_ENTRY for the second argument, 0x2f2c90) and in
		// one region of ordinary memory (TYPE_MISMATCH for the second, 0x2f2c9c..0x2f2cc0)
		if (addr >= 1ull << 62 || !lpar_page_owned(lv1s, addr, 1))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		if (addr >= lv1_guest_region0_size)
		{
			fmt::throw_exception("lv1_write_virtual_uart(): a buffer at 0x%x, outside the memory from address 0, is not implemented", addr);
		}

		if (bytes > lv1_guest_region0_size - addr)
		{
			ppu.gpr[3] = lv1_status(LV1_TYPE_MISMATCH, 2);
			return;
		}

		// lv1 copies the bytes into the peer's receive buffer as far as they fit (0x2f2d40..0x2f2df0) and
		// returns how many it took. The peer of port 2 is lparmgr, whose loop reads the port as messages
		// arrive: first the 16-byte header, then the payload, at most 0x800 bytes of it (0x8001b014), so the
		// write takes all the bytes, one of the outcomes the real console can give (ps2_emu writes again what
		// was not taken, 0x1e3c8..0x1e3dc).
		if (port == 0)
		{
			// lparmgr reads the packets one after the other: the 4-byte header, then its size field's bytes
			// (0x8000887c..0x80008890)
			auto& pending = lv1s.avset_pending;
			const u8* data = vm::_ptr<const u8>(static_cast<u32>(addr));
			pending.insert(pending.end(), data, data + bytes);

			while (pending.size() >= 4)
			{
				const u32 total = 4 + read_from_ptr<be_t<u16>>(pending, 2);

				if (pending.size() < total)
				{
					break;
				}

				avset_receive(lv1s, std::span<const u8>(pending.data(), total));
				pending.erase(pending.begin(), pending.begin() + total);
			}

			ppu.gpr[3] = LV1_SUCCESS;
			ppu.gpr[4] = bytes;
			return;
		}

		if (port != 2)
		{
			std::string text;

			for (u64 i = 0; i < std::min<u64>(bytes, 0x40); i++)
			{
				fmt::append(text, "%02x", vm::read8(static_cast<u32>(addr + i)));
			}

			fmt::throw_exception("lv1_write_virtual_uart(): the peer of port %u is not implemented (0x%x bytes: %s)", port, bytes, text);
		}

		auto& pending = lv1s.sysmgr_pending;
		const u8* data = vm::_ptr<const u8>(static_cast<u32>(addr));
		pending.insert(pending.end(), data, data + bytes);

		while (pending.size() >= 16)
		{
			const u32 payload_size = std::min<u32>(read_from_ptr<be_t<u32>>(pending, 4), 0x800);

			if (pending.size() < 16 + payload_size)
			{
				break;
			}

			sysmgr_receive(lv1s, std::span<const u8>(pending.data(), 16), std::span<const u8>(pending.data() + 16, payload_size));
			pending.erase(pending.begin(), pending.begin() + 16 + payload_size);
		}

		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = bytes;
		return;
	}
	case 164:
	{
		// lv1_set_virtual_uart_param(port, param, value) (lv1 4.93 0x2f4100 -> 0x2f3c0c): the port checks of
		// lv1_get_virtual_uart_param; only the transmit trigger (0, +0x88 of the port), the receive trigger (1,
		// +0x90) and the interrupt mask (2, +0x98) can be set, any other parameter is NO_ENTRY for the second
		// argument (0x2f3df8), and the mask has 3 bits, ILLEGAL for the third argument otherwise (0x2f3f40).
		// The port's listeners are told afterwards (0x2f3d70..0x2f3dc4), which is where its interrupt would be
		// raised; the partition has not made the port interrupt yet.
		const u64 port = in[3];
		const u64 param = in[4];
		const u64 value = in[5];
		lv1.notice("lv1_set_virtual_uart_param(port=%u, param=%u, value=0x%x)", port, param, value);

		if (port > 0xff)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		const auto found = lv1s.vuart_ports.find(port);

		if (found == lv1s.vuart_ports.end())
		{
			fmt::throw_exception("lv1_set_virtual_uart_param(): whether the partition has port %u has not been determined", port);
		}

		switch (param)
		{
		case 0: found->second.tx_trigger = value; break;
		case 1: found->second.rx_trigger = value; break;
		case 2:
		{
			if (value > 7)
			{
				ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
				return;
			}

			found->second.interrupt_mask = value;
			break;
		}
		default:
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}
		}

		vuart_update_interrupt(lv1s, port);
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 165:
	{
		// lv1_get_virtual_uart_param(port, param) -> value (lv1 4.93 0x2f3a68 -> 0x2f34e0): a port above 255 or
		// one the partition does not have is NO_ENTRY for the first argument (0x2f34e0, 0x2f35bc) and a
		// parameter above 7 NO_ENTRY for the second (0x2f35c4). The parameters are, as Linux names them
		// (drivers/ps3/ps3-vuart.c): 0 transmit trigger (+0x88 of the port), 1 receive trigger (+0x90), 2
		// interrupt mask (+0x98), 3 receive buffer size (+0x70), 4 bytes received (+0x78), 5 and 6 the peer's
		// receive buffer size and bytes (+0x48 -> +0x70, +0x78), 7 interrupt status (0x2f0cc4).
		const u64 port = in[3];
		const u64 param = in[4];

		std::lock_guard lock(lv1s.mutex);

		if (port > 0xff)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		const auto found = lv1s.vuart_ports.find(port);

		if (found == lv1s.vuart_ports.end())
		{
			fmt::throw_exception("lv1_get_virtual_uart_param(): whether the partition has port %u has not been determined", port);
		}

		if (param > 7)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		const auto& vp = found->second;
		const std::optional<u64> value =
			param == 0 ? std::optional<u64>{vp.tx_trigger} :
			param == 1 ? std::optional<u64>{vp.rx_trigger} :
			param == 2 ? std::optional<u64>{vp.interrupt_mask} :
			param == 3 ? std::optional<u64>{vp.rx_buffer_size} :
			param == 4 ? std::optional<u64>{vp.rx.size()} :
			param == 7 ? std::optional<u64>{vuart_status(vp)} : std::nullopt;

		if (!value)
		{
			fmt::throw_exception("lv1_get_virtual_uart_param(port=%u, param=%u) is not implemented", port, param);
		}

		lv1.notice("lv1_get_virtual_uart_param(port=%u, param=%u) -> 0x%x", port, param, *value);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = *value;
		return;
	}
	case 166:
	{
		// lv1_configure_virtual_uart_irq(bitmap_lpar_addr) -> outlet (lv1 4.93 0x2f2810)
		const u64 bitmap = in[3];
		lv1.notice("lv1_configure_virtual_uart_irq(bitmap=0x%x)", bitmap);

		std::lock_guard lock(lv1s.mutex);

		// The bitmap has to be in the partition's memory (0x2f28a4, 0x2ce74c), NO_ENTRY for the first argument
		// otherwise, and in a region of ordinary memory (type 0x3292a4 at +0x48) with its 32 bytes inside
		// the region, TYPE_MISMATCH otherwise (0x2f2900..0x2f2924); the memory from address 0 is such a
		// region. What the type of the other regions of the partition is has not been determined.
		if (bitmap >= 1ull << 62 || !lpar_page_owned(lv1s, bitmap, 1))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (bitmap >= lv1_guest_region0_size)
		{
			fmt::throw_exception("lv1_configure_virtual_uart_irq(): a bitmap at 0x%x, outside the memory from address 0, is not implemented", bitmap);
		}

		if (bitmap + 0x20 > lv1_guest_region0_size)
		{
			ppu.gpr[3] = lv1_status(LV1_TYPE_MISMATCH, 1);
			return;
		}

		// The 32 bytes may not cross a page of the region (0x2f2928..0x2f2944, ILLEGAL for the first argument).
		// The page size of the memory from address 0 (+0xa0 of the region) has not been determined, but a
		// bitmap that stays inside a 4 KB page stays inside a page of any size.
		if ((bitmap ^ (bitmap + 0x20)) >> 12)
		{
			fmt::throw_exception("lv1_configure_virtual_uart_irq(): a bitmap across a 4 KB boundary (0x%x) is not implemented", bitmap);
		}

		// Configuring it again is WRONG_STATE without naming an argument (0x2f1474, 0x2f2a90). The outlet is a
		// new object of the partition (0x2f14b0 -> 0x2df6b8).
		if (lv1s.vuart_irq_outlet != umax)
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE);
			return;
		}

		const u64 outlet = allocate_object_id(lv1s);
		lv1s.outlets.emplace(outlet, lv1_outlet{});
		lv1s.vuart_irq_outlet = outlet;
		lv1s.vuart_irq_bitmap = bitmap;

		lv1.notice("lv1_configure_virtual_uart_irq() -> outlet 0x%x", outlet);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = outlet;
		return;
	}
	case 170:
	{
		// lv1_open_device(bus_id, dev_id, flags) (lv1 4.93 0x305a38, 0x2375b0): a bus id above 4 is an illegal
		// first argument, and one of the buses 1 to 4 has to be named (NO_ENTRY otherwise); a device the bus does
		// not have is NO_ENTRY for the second argument. With flags 0 the device's own open method runs (0x23760c,
		// under a lock for the south bridge); flags 1 and 2 are special paths for the two USB controllers
		// (0x237758..0x2377f0).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 flags = in[5];
		lv1.notice("lv1_open_device(bus_id=%u, dev_id=%u, flags=0x%x)", bus_id, dev_id, flags);

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_sb_device(lv1s, "lv1_open_device", bus_id, dev_id, false))
		{
			ppu.gpr[3] = status;
			return;
		}

		if (bus_id == 4)
		{
			// A storage device's open method (0x2545a4): the partition's LAID (0x31ce8c) decides. Every device is
			// registered on the model's console ([dev + 0xda8] set), so only the type check applies: with no access
			// list for the device ([[dev + 0x90] + 0x930] = 0) a disk (type 0) opens only for the LAIDs
			// 0x1070000002000001 and 0x1070000001000001 (DENIED_BY_POLICY otherwise), other types for anyone.
			// Two partitions can hold a device (+0x9f0 and +0xa30, RESOURCE_SHORTAGE for a third), the same one
			// twice is BUSY; the flags are kept with the opener.
			// That count ([[dev + 0x90] + 0x930]) is the number of regions of the region table lv1 reads from the
			// device (0x25bd50, from the table's header). The console's disk is formatted by the GameOS, whose
			// regions the public 3.41 dump lists (bus4.dev3.region1..3), so it is not 0 and the disk opens for any
			// partition. DERIVED WITH PUBLIC FACTS (lv1.md, "Approximations").

			if (!lv1s.open_devices.emplace(bus_id, dev_id).second)
			{
				ppu.gpr[3] = lv1_status(LV1_BUSY);
				return;
			}

			ppu.gpr[3] = LV1_SUCCESS;
			return;
		}

		// What a device's open method answers when the device is open already, or for other flags, has not
		// been determined
		if (flags != 0 || !lv1s.open_devices.emplace(bus_id, dev_id).second)
		{
			fmt::throw_exception("lv1_open_device(%u, %u, 0x%x): device already open or flags not investigated", bus_id, dev_id, flags);
		}

		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 172:
	{
		// lv1_map_device_mmio_region(bus_id, dev_id, bus_addr, size, page_size) -> lpar_addr (lv1 4.93 0x306d64,
		// 0x237254, 0x228bec): gives a register window of an open device a logical partition address
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 bus_addr = in[5];
		const u64 size = in[6];
		const u64 page_size = in[7];
		lv1.notice("lv1_map_device_mmio_region(bus_id=%u, dev_id=%u, bus_addr=0x%x, size=0x%x, page_size=%u)", bus_id, dev_id, bus_addr, size, page_size);

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_sb_device(lv1s, "lv1_map_device_mmio_region", bus_id, dev_id, true))
		{
			ppu.gpr[3] = status;
			return;
		}

		// The south bridge's Ethernet device is refused (0x2372b8 -> 0x237394, bus 1 only)
		if (bus_id == 1 && dev_id == 0)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		// bus_addr has to be the base of one of the device's register windows (0x228c70..0x228ca8), the ones the
		// repository lists, and size has to fit in it (0x228d04..0x228d14)
		u64 window_size = 0;

		for (u64 r = 0; r < 8 && !window_size; r++)
		{
			u64 base = 0, length = 0;

			if (pme_repository_read({repo_first("bus", bus_id), repo_key("dev", dev_id), repo_key("reg", r), repo_key("data")}, base, length) == repo_lookup::found && base == bus_addr)
			{
				window_size = length;
			}
		}

		if (!window_size)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		if (!size || size > window_size)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		// 4 KB, 64 KB, 1 MB or 16 MB pages (0x228d18..0x228d34)
		if (page_size != 12 && page_size != 16 && page_size != 20 && page_size != 24)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x10);
			return;
		}

		const u64 lpar_addr = lpar_allocate(lv1s, "lv1_map_device_mmio_region()", size);
		lv1s.io_regions.emplace(lpar_addr, lv1_state::io_region{size, static_cast<u32>(page_size), bus_id, dev_id, bus_addr});

		lv1.notice("lv1_map_device_mmio_region() -> lpar_addr 0x%x", lpar_addr);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = lpar_addr;
		return;
	}
	case 174:
	{
		// lv1_allocate_device_dma_region(bus_id, dev_id, io_size, io_pagesize, flags) -> dma_addr (lv1 4.93 0x306a6c,
		// 0x236f88): reserves I/O addresses for a device's DMA. flags above 3 are an illegal fifth argument
		// (0x306b14); the USB controllers take all four, which select the window mode (0x23d3a8), the other
		// devices only 0 (UNSUPPORTED_PARAMETER_VALUE, 0x237010). The page size has to be 12, 16, 20 or 24 and the
		// size a non-zero multiple of the page (0x2267fc), and a USB controller has six DMA windows (0x23d54c).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 io_size = in[5];
		const u64 io_pagesize = in[6];
		const u64 flags = in[7];
		lv1.notice("lv1_allocate_device_dma_region(bus_id=%u, dev_id=%u, io_size=0x%x, io_pagesize=%u, flags=0x%x)", bus_id, dev_id, io_size, io_pagesize, flags);

		if (bus_id <= 4 && flags > 3)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x10);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_sb_device(lv1s, "lv1_allocate_device_dma_region", bus_id, dev_id, true))
		{
			ppu.gpr[3] = status;
			return;
		}

		const bool usb = bus_id == 1 && (dev_id == 1 || dev_id == 2);
		const bool pci = bus_id == 2;

		if (!usb && flags != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_UNSUPPORTED_PARAMETER_VALUE, 0x10);
			return;
		}

		if (io_pagesize != 12 && io_pagesize != 16 && io_pagesize != 20 && io_pagesize != 24)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		if (!io_size || io_size % (1ull << io_pagesize))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		// The device's regions, in I/O address order
		const auto first = lv1s.dma_regions.lower_bound({bus_id, dev_id, 0});
		const auto last = lv1s.dma_regions.lower_bound({bus_id, dev_id + 1, 0});

		// lv1 looks for a free window only after allocating, and releases the block again when all six are in
		// use (0x23d58c, RESOURCE_SHORTAGE); what the release leaves of the region has not been followed
		if (usb && std::distance(first, last) >= 6)
		{
			fmt::throw_exception("lv1_allocate_device_dma_region(): a seventh region of USB controller %u", dev_id);
		}

		// The PCI devices' regions take the sixteen slots of the bridge's I/O space object (0x2306c0..0x2306e8),
		// RESOURCE_SHORTAGE without an argument bit when all are in use
		if (pci && std::distance(lv1s.dma_regions.lower_bound({2, 0, 0}), lv1s.dma_regions.lower_bound({3, 0, 0})) >= 16)
		{
			ppu.gpr[3] = lv1_status(LV1_RESOURCE_SHORTAGE);
			return;
		}

		// Above 4 GB lv1 refuses the size (0x22d4d0) without an argument bit
		if (io_size > 1ull << 32)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		// lv1 takes the I/O address from the device's own I/O space, a virtual method of the device (0x2268a0,
		// 0x22d990); for a USB controller it then programs the address into one of its windows (0x23d3a8). A PCI
		// device's comes from the bridge (south bridge device 6, type 0), whose ioid it uses: lv1 gives device 6
		// ioid 0 when it creates it (0x22ddf8..0x22de70), so no ioid is drawn from the pool. The Gigabit Ethernet
		// device is south bridge device 0 (bus 1 device 0 maps to it, 0x235d98), of type 2 (0x3a992c): io base
		// 1 << 32 and regions the size of their block (0x22d2e0, 0x22d214).
		const bool net = bus_id == 1 && dev_id == 0;

		// A storage device's DMA goes through the south bridge's ATA controller of its port (0x258698: the
		// controller behind the port object, [[dev + 0x1638] + 0x578] + 0x10 for the ATAPI device): south bridge
		// devices 1 and 2, of types 0xa and 0xb (0x3a9974, 0x3a99e0), io base 2 << 32 and 3 << 32 (0x22d35c,
		// 0x22d374). The model's BD drive is on port 0 and its disk on port 1 (see the repository).
		const bool storage = bus_id == 4 && (dev_id == 2 || dev_id == 3);

		if (!usb && !pci && !net && !storage)
		{
			fmt::throw_exception("lv1_allocate_device_dma_region(): the I/O space of device %u has not been followed (0x%x bytes)", dev_id, io_size);
		}

		const u64 io_base = usb ? (dev_id == 1 ? 4ull : 5ull) << 32 : net ? 1ull << 32 : storage ? (dev_id == 2 ? 2ull : 3ull) << 32 : 0;
		const u64 dma_addr = sb_dma_allocate(lv1s, io_base, net ? 0 : 0x80, io_size, static_cast<u32>(io_pagesize));

		lv1s.dma_regions.emplace(std::tuple{bus_id, dev_id, dma_addr}, lv1_state::dma_region{io_size, static_cast<u32>(io_pagesize), flags, {}});

		lv1.notice("lv1_allocate_device_dma_region() -> dma_addr 0x%x", dma_addr);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = dma_addr;
		return;
	}
	case 176:
	{
		// lv1_map_device_dma_region(bus_id, dev_id, lpar_addr, dma_addr, size, flags) (lv1 4.93 0x306770, 0x236d1c):
		// puts partition memory behind I/O addresses of a DMA region. flags may only have bits 0 to 4 and 52
		// set (0x306820..0x306840), the I/O page table entry bits (Linux cbe IOPTE_PP_W, PP_R, M, SO).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 lpar_addr = in[5];
		const u64 dma_addr = in[6];
		const u64 size = in[7];
		const u64 flags = in[8];
		lv1.notice("lv1_map_device_dma_region(bus_id=%u, dev_id=%u, lpar_addr=0x%x, dma_addr=0x%x, size=0x%x, flags=0x%x)", bus_id, dev_id, lpar_addr, dma_addr, size, flags);

		if (bus_id <= 4 && (flags & ~0xf800000000000800))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x20);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_sb_device(lv1s, "lv1_map_device_dma_region", bus_id, dev_id, true))
		{
			ppu.gpr[3] = status;
			return;
		}

		// The checks of 0x236d1c have not been followed; a mapping outside one of the device's regions, not
		// aligned to its page, or of memory the partition does not own stops here
		auto region = lv1s.dma_regions.upper_bound({bus_id, dev_id, dma_addr});
		bool fits = region != lv1s.dma_regions.begin();

		if (fits)
		{
			--region;
			const auto& [key, r] = *region;
			const u64 base = std::get<2>(key);
			const u64 page_mask = (1ull << r.page_shift) - 1;
			fits = std::get<0>(key) == bus_id && std::get<1>(key) == dev_id && dma_addr >= base && size && dma_addr + size <= base + r.size &&
				!((dma_addr | lpar_addr | size) & page_mask) && lpar_page_owned(lv1s, lpar_addr, size);
		}

		if (!fits)
		{
			fmt::throw_exception("lv1_map_device_dma_region(): mapping outside the modelled checks");
		}

		region->second.mappings.emplace(dma_addr, lv1_state::dma_mapping{lpar_addr, size, flags});
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 191:
	{
		// lv1_net_set_interrupt_status_indicator(bus_id, dev_id, irq_status_lpar_addr, 0) (lv1 4.93 0x308204):
		// where the Gigabit Ethernet device writes its interrupt status. A bus above 4 is ILLEGAL and any bus but
		// 1 NO_ENTRY for the first argument, a device but 0 NO_ENTRY for the second (0x30829c..0x3082b0). The
		// device has to be in state 2 (0x3082f8), the state its per-partition object is created in when the
		// partition opens it (0x23e174 -> 0x23e1d0); WRONG_STATE without an argument otherwise. A non-zero
		// fourth argument is ILLEGAL for it (0x3083cc); the address has to be 8-byte aligned and in an ordinary
		// memory region of the partition with pages, ILLEGAL for the third otherwise (0x3083fc..0x308478).
		// Only one indicator may be set: DUPLICATE without an argument (0x308494).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 addr = in[5];
		lv1.notice("lv1_net_set_interrupt_status_indicator(bus_id=%u, dev_id=%u, addr=0x%x, 0x%x)", bus_id, dev_id, addr, in[6]);

		if (bus_id > 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (bus_id != 1)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (dev_id != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.open_devices.contains({1, 0}))
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE);
			return;
		}

		if (in[6] != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		if (addr & 7 || !lpar_page_owned(lv1s, addr, 8))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		if (addr + 8 > lv1_guest_region0_size)
		{
			fmt::throw_exception("lv1_net_set_interrupt_status_indicator(): an indicator at 0x%x, outside the memory from address 0, is not implemented", addr);
		}

		if (lv1s.net_status_indicator)
		{
			ppu.gpr[3] = lv1_status(LV1_DUPLICATE_ENTRY);
			return;
		}

		lv1s.net_status_indicator = addr;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 248:
	{
		// lv1_storage_send_device_command(dev_id, cmd, cmdbuf, cmdbuf_size, databuf, databuf_size) -> tag
		// (lv1 4.93 0x3094e4 -> 0x251be0)
		const u64 dev_id = in[3];
		const u64 cmd = in[4];
		const u64 cmdbuf = in[5];
		const u64 cmdbuf_size = in[6];
		const u64 databuf = in[7];
		const u64 databuf_size = in[8];
		lv1.notice("lv1_storage_send_device_command(dev_id=%u, cmd=%u, cmdbuf=0x%x, cmdbuf_size=0x%x, databuf=0x%x, databuf_size=0x%x)", dev_id, cmd, cmdbuf, cmdbuf_size, databuf, databuf_size);

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_storage_request(lv1s, "lv1_storage_send_device_command", dev_id))
		{
			ppu.gpr[3] = status;
			return;
		}

		// The device's command method (+0x110, 0x256cd4) takes a tag first (0x25397c): the lowest of the 16 that
		// is free, BUSY when none is
		auto& requests = lv1s.storage_requests[dev_id];
		const auto free_tag = std::find_if(requests.begin(), requests.end(), [](const auto& r) { return !r.has_value(); });

		if (free_tag == requests.end())
		{
			ppu.gpr[3] = lv1_status(LV1_BUSY);
			return;
		}

		const u64 tag = free_tag - requests.begin();

		// The data buffer, when there are both an address and a size (0x2539d0, 0x253aa4): an I/O address the
		// device's DMA regions map is taken as such (0x2284c8, not followed); otherwise it has to lie in a memory
		// region of the partition, from the address to the region's end (NO_ENTRY otherwise, 0x253b14..0x253b48)
		if (databuf && databuf_size)
		{
			const auto region = lv1s.dma_regions.upper_bound({4, dev_id, databuf});

			if (region != lv1s.dma_regions.begin() && std::get<0>(std::prev(region)->first) == 4 && std::get<1>(std::prev(region)->first) == dev_id &&
				databuf - std::get<2>(std::prev(region)->first) < std::prev(region)->second.size)
			{
				fmt::throw_exception("lv1_storage_send_device_command(): a data buffer at an I/O address (0x%x) is not implemented", databuf);
			}

			if (databuf + databuf_size > lv1_guest_region0_size)
			{
				fmt::throw_exception("lv1_storage_send_device_command(): a data buffer outside the memory from address 0 (0x%x, 0x%x bytes) is not implemented", databuf, databuf_size);
			}
		}

		if (dev_id != 2)
		{
			fmt::throw_exception("lv1_storage_send_device_command(): the commands of storage device %u have not been followed", dev_id);
		}

		// The ATAPI device (+0x180, 0x27302c -> 0x272be4): commands 1, 2, 0x10, 0x11, 0x13, 0x14, 0x19 to 0x1c,
		// 0x21, 0x24, 0x26, 0x27, 0x29 and 0x30 (the mask at 0x272c84), ILLEGAL without an argument otherwise; a
		// command block with a size has to be in the partition's memory (0x254484, ILLEGAL otherwise)
		if (cmd > 0x30 || !((0x102d21e1b0006ull >> cmd) & 1))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		if (cmdbuf_size && cmdbuf + cmdbuf_size > lv1_guest_region0_size)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		// Then lv1's access list (0x272f84 -> 0x31d7b0 -> 0x31d34c) for storage commands, keyed by command << 32
		// and, for command 1, the packet's operation code: the list is the SCE_CELLOS_SS_INIT_LV1_ACL entry of
		// default.spp, whose storage table allows every command (a key of 0) to the LAIDs 0x101..., 0x102...
		// and 0x104... (mask 0xf0...), the PS2 partition's (0x1020000003000001) among them, and lists single
		// commands for the Linux partition's. So the command is allowed.
		if (cmd != 1)
		{
			fmt::throw_exception("lv1_storage_send_device_command(): command %u of the ATAPI device has not been followed", cmd);
		}

		// Command 1 sends a packet: the block is Linux's lv1_atapi_cmnd_block (drivers/scsi/ps3rom.c): the
		// packet (32 bytes), its length, the number of blocks and their size, the protocol (0 no data, 1 PIO in,
		// 2 PIO out, 3 DMA) and the direction (1 to the host). How lv1 reads it (0x27212c, the queue) has not
		// been followed past these fields.
		if (cmdbuf_size < 0x34)
		{
			fmt::throw_exception("lv1_storage_send_device_command(): an ATAPI command block of 0x%x bytes is not implemented", cmdbuf_size);
		}

		const u8* block = vm::_ptr<const u8>(static_cast<u32>(cmdbuf));
		const u32 packet_length = read_from_ptr_unsafe<be_t<u32>>(block, 0x20);
		const u32 blocks = read_from_ptr_unsafe<be_t<u32>>(block, 0x24);
		const u32 block_size = read_from_ptr_unsafe<be_t<u32>>(block, 0x28);
		const u32 proto = read_from_ptr_unsafe<be_t<u32>>(block, 0x2c);
		const u32 in_out = read_from_ptr_unsafe<be_t<u32>>(block, 0x30);
		const u64 transfer = u64{blocks} * block_size;

		if (packet_length != 12 || proto > 2 || (proto == 0) != (transfer == 0) || (proto != 0 && (proto == 1) != (in_out == 1)) || transfer != (proto ? databuf_size : 0))
		{
			fmt::throw_exception("lv1_storage_send_device_command(): ATAPI block (packet length %u, %u blocks of 0x%x, protocol %u, direction %u) with 0x%x data bytes is not implemented",
				packet_length, blocks, block_size, proto, in_out, databuf_size);
		}

		// APPROXIMATION (lv1.md, "Approximations"): lv1 queues the command (16 entries at +0x1880) and a timer
		// runs it on the drive; the model runs it now and the request is done when the call returns. The device's
		// interrupt then raises the event receive port connected to it.
		const u64 status = lv1_bdvd_packet(lv1s.bdvd, {block, 12}, transfer ? vm::_ptr<u8>(static_cast<u32>(databuf)) : nullptr, static_cast<u32>(transfer), proto == 1);

		*free_tag = lv1_state::storage_request{true, status};

		if (const auto port = lv1s.storage_event_ports.find(dev_id); port != lv1s.storage_event_ports.end())
		{
			raise_outlet(lv1s, lv1s.outlets.at(port->second));
		}

		lv1.notice("lv1_storage_send_device_command() -> tag %u, status 0x%x", tag, status);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = tag;
		return;
	}
	case 254:
	{
		// lv1_storage_check_async_status(dev_id, tag) -> status (lv1 4.93 0x30926c -> 0x251d70 -> 0x255ad8): the
		// device checks of lv1_storage_send_device_command, a tag above 15 ILLEGAL; a request of the partition
		// that is done gives its status and frees the tag, anything else is NO_ENTRY (0x255b90). The wait an
		// opener with flag bit 63 has for an event word (0x255d24, NO_MATCH) is not followed: ps2_emu opens
		// with flags 0.
		const u64 dev_id = in[3];
		const u64 tag = in[4];
		lv1.notice("lv1_storage_check_async_status(dev_id=%u, tag=%u)", dev_id, tag);

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_storage_request(lv1s, "lv1_storage_check_async_status", dev_id))
		{
			ppu.gpr[3] = status;
			return;
		}

		if (tag > 15)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		auto& request = lv1s.storage_requests[dev_id][tag];

		if (!request || !request->done)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY);
			return;
		}

		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = request->status;
		request.reset();
		return;
	}
	case 193:
	{
		// lv1_net_set_interrupt_mask(bus_id, dev_id, mask, 0) (lv1 4.93 0x307fe0): the interrupt status bits of
		// the Gigabit Ethernet device that raise its interrupt. The bus and device checks of
		// lv1_net_set_interrupt_status_indicator (0x308070..0x308084, 0x308108, 0x3081b4), then the device has to
		// be in state 2 (opened, WRONG_STATE without an argument, 0x3080cc), and a non-zero fourth argument is
		// ILLEGAL for it (0x308198). The mask is stored in the device object (+0x20, 0x3081cc).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 mask = in[5];
		lv1.notice("lv1_net_set_interrupt_mask(bus_id=%u, dev_id=%u, mask=0x%x, 0x%x)", bus_id, dev_id, mask, in[6]);

		if (bus_id > 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (bus_id != 1)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (dev_id != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.open_devices.contains({1, 0}))
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE);
			return;
		}

		if (in[6] != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8);
			return;
		}

		lv1s.net_interrupt_mask = mask;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 197:
	{
		// lv1_connect_interrupt_event_receive_port(bus_id, dev_id, port, irq) (lv1 4.93 0x305cf0 -> 0x236924): a
		// device's interrupt sends events to an event receive port. Followed for the Gigabit Ethernet device
		// (bus 1, device 0, 0x236a0c): the fourth argument has to be 0 (NO_ENTRY for it, 0x236ab4), the device
		// in state 2 (opened, NO_ENTRY without an argument, 0x236a5c), the port an event receive port of the
		// partition (NO_ENTRY for the third, 0x245ffc..0x246128), and not connected already (BUSY for the
		// fourth, 0x245fa0 -> 0x236bcc).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 port = in[5];
		const u64 irq = in[6];
		lv1.notice("lv1_connect_interrupt_event_receive_port(bus_id=%u, dev_id=%u, port=0x%x, irq=%u)", bus_id, dev_id, port, irq);

		if (bus_id > 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (const u64 status = check_sb_device(lv1s, "lv1_connect_interrupt_event_receive_port", bus_id, dev_id, false))
		{
			ppu.gpr[3] = status;
			return;
		}

		if (bus_id == 4)
		{
			// A storage device (0x23698c -> 0x255254): irq 0 only (NO_ENTRY for the fourth argument); the port
			// has to be an event receive port of the partition and the partition one of the device's openers
			// (+0x9f0, +0xa30), NO_ENTRY for the third otherwise; a port connected already is BUSY for the fourth
			if (irq != 0)
			{
				ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 8);
				return;
			}

			const auto found = lv1s.outlets.find(port);

			if (found == lv1s.outlets.end() || !found->second.event_port || !lv1s.open_devices.contains({bus_id, dev_id}))
			{
				ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 4);
				return;
			}

			if (!lv1s.storage_event_ports.emplace(dev_id, port).second)
			{
				ppu.gpr[3] = lv1_status(LV1_BUSY, 8);
				return;
			}

			ppu.gpr[3] = LV1_SUCCESS;
			return;
		}

		if (bus_id != 1 || dev_id != 0)
		{
			fmt::throw_exception("lv1_connect_interrupt_event_receive_port(): device %u of bus %u is not implemented", dev_id, bus_id);
		}

		if (irq != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 8);
			return;
		}

		if (!lv1s.open_devices.contains({1, 0}))
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY);
			return;
		}

		if (lv1s.net_event_port)
		{
			ppu.gpr[3] = lv1_status(LV1_BUSY, 8);
			return;
		}

		if (const auto found = lv1s.outlets.find(port); found == lv1s.outlets.end() || !found->second.event_port)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 4);
			return;
		}

		lv1s.net_event_port = port;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 194:
	{
		// lv1_net_control(bus_id, dev_id, code, v1, v2, v3) -> v1, v2 (lv1 4.93 0x307d2c -> 0x245108 -> 0x244a84):
		// the bus and device checks of lv1_net_set_interrupt_status_indicator (0x307dd4..0x307e30), then codes 1
		// to 11 for a partition without the privilege at 0x309830 (ILLEGAL for the third argument otherwise,
		// 0x307f40), each handled by the device (0x244a84; an unknown one is ILLEGAL, 0x244b24).
		const u64 bus_id = in[3];
		const u64 dev_id = in[4];
		const u64 code = in[5];
		lv1.notice("lv1_net_control(bus_id=%u, dev_id=%u, code=%u, 0x%x, 0x%x, 0x%x)", bus_id, dev_id, code, in[6], in[7], in[8]);

		if (bus_id > 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1);
			return;
		}

		if (bus_id != 1)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (dev_id != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 2);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.open_devices.contains({1, 0}))
		{
			ppu.gpr[3] = lv1_status(LV1_WRONG_STATE);
			return;
		}

		if (code - 1 > 10)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		switch (code)
		{
		case 1:
		{
			// The device's MAC address (+0x10 of its state, 0x244f9c), which lv1 has from the console. The
			// model's console is RPCS3's, whose MAC is the network handler's (derived from the configured PSID
			// or taken from the host's adapter, np_handler::discover_ether_address), in the low 48 bits.
			const auto nph = g_fxo->try_get<named_thread<np::np_handler>>();

			if (!nph)
			{
				fmt::throw_exception("lv1_net_control(1): the network handler that holds the console's MAC address is not running");
			}

			u64 mac = 0;

			for (u8 byte : nph->get_ether_addr())
			{
				mac = mac << 8 | byte;
			}

			ppu.gpr[3] = LV1_SUCCESS;
			ppu.gpr[4] = mac;
			ppu.gpr[5] = 0;
			return;
		}
		case 2:
		{
			// The Ethernet port status (0x244cac): v1 above 2 is ILLEGAL; bit 0 link up and bit 1 full duplex from
			// the PHY (its methods 0x38, 0x40), then the speed from its method 0x30 as bit 4, 5 or 6 for 10, 100
			// and 1000 Mb/s, an error of that method being the call's status. The model's cable is RPCS3's network
			// setting. With it disconnected the link is down. APPROXIMATION (lv1.md, "Approximations"): what the
			// PHY's speed method answers with the link down has not been followed; the call succeeds with no bit
			// set. ps2_emu only tests bit 0, and a failure takes it down the same path (0x26e98..0x26eb4).
			if (in[6] > 2)
			{
				ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
				return;
			}

			if (g_cfg.net.net_active != np_internet_status::disabled)
			{
				fmt::throw_exception("lv1_net_control(2): a link up (RPCS3's network enabled) is not implemented");
			}

			ppu.gpr[3] = LV1_SUCCESS;
			ppu.gpr[4] = 0;
			ppu.gpr[5] = 0;
			return;
		}
		case 4:
		{
			// The VLAN id of a traffic class (0x244dd8): NO_ENTRY without an argument when bit 0 of +0x20 of the
			// device is set, which it is not (the device is created and opened with 0 there, 0x23df80, 0x23e058);
			// then a table by v1 (0x244e14), ILLEGAL for the others. Index 5 depends on the byte at +0x1c, not
			// followed.
			const u64 index = in[6];
			const u64 vlan =
				index == 1 ? 0x124 : index == 2 ? 0x126 : index == 3 ? 0x127 : index == 4 ? 0x123 :
				index == 0x10 ? 0x120 : index == 0x11 ? 0x121 : index == 0x12 ? 0x122 : index == 0x13 ? 0x105 : index == 0x14 ? 0x100 : 0;

			if (index == 5)
			{
				fmt::throw_exception("lv1_net_control(4, 5): the device byte at +0x1c has not been followed");
			}

			if (!vlan)
			{
				ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
				return;
			}

			ppu.gpr[3] = LV1_SUCCESS;
			ppu.gpr[4] = vlan;
			ppu.gpr[5] = 0;
			return;
		}
		default: break;
		}

		fmt::throw_exception("lv1_net_control(): code %u is not implemented", code);
	}
	case 210:
	{
		// lv1_gpu_open(arg) (lv1 4.93 0x20e908 -> 0x20c548). With sys.lv1.rsxenable at most 1 lv1 answers
		// NO_ENTRY (0x20c590); a retail console, whose games use the RSX, has it above 1. lv1 then refuses
		// with BUSY while a partition owns the device (0x20c5b8) and otherwise creates the device object for
		// the partition (0x20be10) and succeeds. sys.boot.gos above 3 would make it ILLEGAL (0x20e964); ==3
		// only sets a flag (0x20ec90) that later calls check.
		lv1.notice("lv1_gpu_open(arg=0x%x)", in[3]);

		std::lock_guard lock(lv1s.mutex);

		if (lv1s.gpu_opened)
		{
			ppu.gpr[3] = lv1_status(LV1_BUSY);
			return;
		}

		// The device object (0x20be10) creates lv1's RSX memory manager, which is global (0x363f10) and made
		// by the first lv1_gpu_open since lv1 started: the PS2 mode is booted from lv0 (the syscon byte behind
		// sys.boot.gos), so this partition is the first. The manager (0x2124a8 -> 0x211a90) maps into the
		// partition, in this order, the local memory but its last 2 MB with 1 MB pages (0x211b98), resource
		// 0xb (0xc000 bytes of host memory, 0x211be4) and resource 0xa (0x40000 bytes in the last 2 MB,
		// 0x211c08) of its static table (0x35ba60); then the FIFO (0x21ca70) maps 0x20000 bytes of the RSX
		// registers at 0xc00000 (0x21cc34). Each mapping takes an address from the partition's allocator
		// (0x2dd46c). The local memory is 256 MB on every PS3 (psdevwiki, RSX); lv1 reads it from the bus
		// object (vtable +0x60, 0x21252c).
		constexpr u64 local_memory_size = 256ull << 20;
		constexpr u64 local_reserved = 0x200000;

		const auto map = [&](u64 size, lv1_state::gpu_region_kind kind, u64 rsx_offset)
		{
			const u64 lpar_addr = lpar_allocate(lv1s, "lv1_gpu_open()", size);
			lv1s.gpu_regions.emplace(lpar_addr, lv1_state::gpu_region{size, kind, umax, rsx_offset});
			return lpar_addr;
		};

		lv1s.gpu_local_memory_lpar = map(local_memory_size - local_reserved, lv1_state::gpu_region_kind::local_memory, 0);
		lv1s.gpu_driver_host_lpar = map(0xc000, lv1_state::gpu_region_kind::driver_host, 0);
		lv1s.gpu_driver_local_top_lpar = map(0x40000, lv1_state::gpu_region_kind::driver_local_top, 0);
		lv1s.gpu_fifo_lpar = map(0x20000, lv1_state::gpu_region_kind::registers, 0xc00000);

		// The manager's local memory bitmap: base the partition address, units of 1 MB (0x211c1c..0x211c78)
		lv1s.gpu_local_units.assign((local_memory_size - local_reserved) >> 20, false);

		lv1s.gpu_opened = true;
		ppu.gpr[3] = LV1_SUCCESS;
		return;
	}
	case 217:
	{
		// lv1_gpu_context_allocate(memory_handle, flags) -> context_handle, lpar_dma_control, lpar_driver_info,
		// lpar_reports, reports_size (lv1 4.93 0x20f5bc -> 0x21519c -> 0x214eb8). The memory object has to
		// exist (0x211608, else ILLEGAL at 0x20f860); a device has three context slots (0x20f9e0, then
		// RESOURCE_SHORTAGE) and lv1 sixteen (0x2151e0). The outputs, for the first context of a fresh
		// driver, where every bitmap involved is empty:
		// - the handle is the global slot ^ 0x55555555 (0x214ec8);
		// - lpar_dma_control is the FIFO window of lv1_gpu_open plus the channel << 12 (0x213b7c -> 0x221210
		//   -> 0x21b5e4), the channel the first free of four (0x220ed4 on the bitmap made at 0x20be7c);
		// - lpar_driver_info is resource 0xb (host memory) plus the first free of its three 0x4000 blocks
		//   (0x2146f4, bitmap made at 0x211ea4, host to partition address at 0x2147a8..0x2147cc);
		// - lpar_reports is resource 0xa plus the first free of its four 0x10000 blocks, reports_size the
		//   block (0x2143e0, bitmap made at 0x211cac, 0x214478).
		// The context also takes the I/O segment 0x80000000 + channel << 28 among those a boot initializer
		// reserved for it (0x214dac with flag 1 = an already reserved segment, 0x2d9ba8), which leaves the
		// segment table as it is. The context's other resources (0x214040, 0x212f78, ...) are not visible to
		// the partition; a second context has not been followed.
		const u64 memory_handle = in[3];
		const u64 flags = in[4];
		lv1.notice("lv1_gpu_context_allocate(memory_handle=0x%x, flags=0x%x)", memory_handle, flags);

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.gpu_opened)
		{
			fmt::throw_exception("lv1_gpu_context_allocate(): the RSX has not been opened");
		}

		if (memory_handle != (0 ^ 0x5a5a5a5a) || !lv1s.gpu_memory_slots[0])
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		if (lv1s.gpu_context_allocated)
		{
			fmt::throw_exception("lv1_gpu_context_allocate(): a second context has not been followed");
		}

		// The flags select other paths of the context set-up (0x214ec0..0x214f6c)
		if (flags)
		{
			fmt::throw_exception("lv1_gpu_context_allocate(): flags 0x%x have not been followed", flags);
		}

		lv1s.gpu_context_allocated = true;

		const u64 channel = 0;
		const u64 context_handle = 0 ^ 0x55555555;
		const u64 dma_control = lv1s.gpu_fifo_lpar + (channel << 12);
		const u64 driver_info = lv1s.gpu_driver_host_lpar;
		const u64 reports = lv1s.gpu_driver_local_top_lpar;
		const u64 reports_size = 0x10000;

		lv1.notice("lv1_gpu_context_allocate() -> handle 0x%x, dma_control 0x%x, driver_info 0x%x, reports 0x%x (0x%x)", context_handle, dma_control, driver_info, reports, reports_size);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = context_handle;
		ppu.gpr[5] = dma_control;
		ppu.gpr[6] = driver_info;
		ppu.gpr[7] = reports;
		ppu.gpr[8] = reports_size;
		return;
	}
	case 214:
	{
		// lv1_gpu_memory_allocate(size, arg2, arg3, arg4, arg5) -> memory_handle, lpar_addr (lv1 4.93 0x20ec9c
		// -> 0x212178). A size of 0 means the local memory but 2 MB (0x20ef00). lv1 takes the first free of
		// its 16 memory objects (0x2121bc) and five resources from bitmaps, first fit (0x217538): the local
		// memory in units of 1 MB (the size has to be a whole number of them, 0x212250), and arg2 to arg5 in
		// their own units. The handle is the object's slot ^ 0x5a5a5a5a (0x21238c) and the address the local
		// memory's partition address plus the offset of the block (0x21237c, 0x20efac). Anything that fails
		// answers ILLEGAL (0x20f010). The four other bitmaps are only followed for a first allocation.
		const u64 size = in[3];
		lv1.notice("lv1_gpu_memory_allocate(size=0x%x, 0x%x, 0x%x, 0x%x, 0x%x)", size, in[4], in[5], in[6], in[7]);

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.gpu_opened)
		{
			fmt::throw_exception("lv1_gpu_memory_allocate(): the RSX has not been opened");
		}

		if (!size || size % (1ull << 20))
		{
			fmt::throw_exception("lv1_gpu_memory_allocate(): a size of 0x%x has not been followed", size);
		}

		if (std::find(lv1s.gpu_memory_slots.begin(), lv1s.gpu_memory_slots.end(), true) != lv1s.gpu_memory_slots.end())
		{
			fmt::throw_exception("lv1_gpu_memory_allocate(): a second allocation has not been followed");
		}

		const u64 units = size >> 20;
		auto& bitmap = lv1s.gpu_local_units;
		u64 first = umax;

		for (u64 i = 0; i + units <= bitmap.size(); i++)
		{
			if (std::all_of(bitmap.begin() + i, bitmap.begin() + i + units, [](bool used) { return !used; }))
			{
				first = i;
				break;
			}
		}

		if (first == umax)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE);
			return;
		}

		std::fill(bitmap.begin() + first, bitmap.begin() + first + units, true);
		lv1s.gpu_memory_slots[0] = true;

		const u64 handle = 0 ^ 0x5a5a5a5a;
		const u64 lpar_addr = lv1s.gpu_local_memory_lpar + (first << 20);

		lv1.notice("lv1_gpu_memory_allocate() -> handle 0x%x, lpar_addr 0x%x", handle, lpar_addr);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = handle;
		ppu.gpr[5] = lpar_addr;
		return;
	}
	case 212:
	{
		// lv1_gpu_device_map(dev_id) -> lpar_addr, lpar_size (lv1 4.93 0x20db58 -> 0x20b4b0). Only when lv1's
		// flag 0x363f08 is set (lv1_gpu_open sets it for sys.boot.gos == 3, 0x20ec90) does lv1 restrict the
		// ids (0x20db98: 1, 2, 5, and 9 and 11 with another flag; others answer success without mapping).
		// sys.boot.gos is a syscon value lv0 passes (lv0 0x80072d0 -> 0x8002810: block 0xff byte 0 & 3); it
		// cannot be 3 on a console that runs ps2_emu, which maps devices 6 and 7 into its address space
		// (0x45890..0x458b4) and reads the video input registers of device 6 there (0x50100200). A device
		// already mapped is a DUPLICATE (0x20b4f8). Each device is a window of the RSX registers (the bus
		// object's base, vtable +0x48) put into the partition with 4 KB pages (0x2dd46c -> 0x2dce84, whose
		// address comes from the partition's allocator, 0x2dbfb4 -> 0x2cec78).
		const u64 gpu_dev_id = in[3];
		lv1.notice("lv1_gpu_device_map(dev_id=%u)", gpu_dev_id);

		// Offset and size of the window of each device (0x20b590 table)
		static constexpr std::array<std::pair<u64, u64>, 8> windows
		{{
			{0, 0}, {0, 0}, {0x80100, 0x8000}, {0, 0}, {0, 0}, {0x8a000, 0x1000}, {0x200000, 0x1000}, {0x600000, 0x10000},
		}};

		if (gpu_dev_id >= windows.size() || !windows[gpu_dev_id].second)
		{
			fmt::throw_exception("lv1_gpu_device_map(): device %u has not been followed", gpu_dev_id);
		}

		std::lock_guard lock(lv1s.mutex);

		if (!lv1s.gpu_opened)
		{
			fmt::throw_exception("lv1_gpu_device_map(): the RSX has not been opened");
		}

		for (const auto& [addr, region] : lv1s.gpu_regions)
		{
			if (region.gpu_dev_id == gpu_dev_id)
			{
				ppu.gpr[3] = lv1_status(LV1_DUPLICATE_ENTRY);
				return;
			}
		}

		const auto [rsx_offset, size] = windows[gpu_dev_id];
		const u64 lpar_addr = lpar_allocate(lv1s, "lv1_gpu_device_map()", size);
		lv1s.gpu_regions.emplace(lpar_addr, lv1_state::gpu_region{size, lv1_state::gpu_region_kind::registers, gpu_dev_id, rsx_offset});

		lv1.notice("lv1_gpu_device_map() -> lpar_addr 0x%x, size 0x%x", lpar_addr, size);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = lpar_addr;
		ppu.gpr[5] = size;
		return;
	}
	case 178:
	case 179:
	{
		// lv1_pci_config_read(bus_id, pci_bus, pci_dev, pci_fun, offset, size) -> value (lv1 4.93 0x3063cc ->
		// 0x2361c0) and lv1_pci_config_write(..., size, value) (0x306190 -> 0x235fa0). Bus above 4, pci_bus,
		// pci_dev or pci_fun above 0xff, an offset above 0xff (0xfff on bus 3) and a size other than 1, 2 or 4
		// are illegal arguments 1 to 6. Only buses 2 and 3 have configuration space: 1 and 4 are an
		// ACCESS_VIOLATION of the first argument, others no entry. A size 2 or 4 access has to be aligned
		// (argument 6). A write to 0x10..0x3f, the BARs, is an ACCESS_VIOLATION of the offset (0x23605c). A
		// function the PCI host does not list is NO_ENTRY (and -1 for a read). The access then goes to the chip.
		const bool write = code == 179;
		const u64 bus_id = in[3], pci_bus = in[4], pci_dev = in[5], pci_fun = in[6], offset = in[7], size = in[8];
		const u64 value = in[9];
		lv1.notice("lv1_pci_config_%s(bus_id=%u, %u:%u.%u, offset=0x%x, size=%u, value=0x%x)", write ? "write" : "read", bus_id, pci_bus, pci_dev, pci_fun, offset, size, value);

		if (bus_id > 4) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 1); return; }
		if (pci_bus > 0xff) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2); return; }
		if (pci_dev > 0xff) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4); return; }
		if (pci_fun > 0xff) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 8); return; }
		if (offset > (bus_id == 3 ? 0xfffu : 0xffu)) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x10); return; }
		if (size != 1 && size != 2 && size != 4) { ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x20); return; }

		if (bus_id == 1 || bus_id == 4)
		{
			ppu.gpr[3] = lv1_status(LV1_ACCESS_VIOLATION, 1);
			return;
		}

		if (bus_id != 2 && bus_id != 3)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (bus_id == 3)
		{
			fmt::throw_exception("lv1_pci_config: bus3 has not been followed");
		}

		if (offset & (size - 1))
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 0x20);
			return;
		}

		if (write && offset >= 0x10 && offset <= 0x3f)
		{
			ppu.gpr[3] = lv1_status(LV1_ACCESS_VIOLATION, 0x10);
			return;
		}

		if (pci_bus != ps2_chip_pci_bus || pci_dev != ps2_chip_pci_dev || pci_fun != ps2_chip_pci_fun)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY);
			ppu.gpr[4] = write ? 0 : u64{umax};
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		if (write)
		{
			// The chip's side of a write (the command register at 4, latency at 0xc) is not modelled beyond
			// keeping the value
			lv1s.ps2_chip_config_writes[offset] = value;
			ppu.gpr[3] = LV1_SUCCESS;
			return;
		}

		// The chip's configuration space: only the vendor and device id are known (ps2_emu's comparison)
		if (offset != 0 || size != 4)
		{
			fmt::throw_exception("lv1_pci_config_read(): offset 0x%x (%u bytes) of the PS2 chip is not known", offset, size);
		}

		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = ps2_chip_pci_id;
		return;
	}
	case 116:
	{
		// lv1_allocate_io_segment(ioas_id, seg_size, io_pagesize) -> ioif_addr (lv1 4.93 0x2da1f0 -> 0x2d9d20,
		// runtime-registered). Space 0 is the only one (0x2d9d38). The size has to be below 1 << 35 (the
		// space's log2 size, 0x2d945c) and at most 256 MB (0x2d9e68), the page 12, 16, 20 or 24 (0x2d9e74,
		// 0x2b9db0). lv1 takes the lowest free segment of the space and gives it back if it is above 7
		// (0x2d9548..0x2d960c), which it reports as BUSY (0x2d9bd4, 0x2d9f08). The address is the segment
		// number << 28 (0x2da0fc).
		const u64 ioas_id = in[3];
		const u64 seg_size = in[4];
		const u64 io_pagesize = in[5];
		lv1.notice("lv1_allocate_io_segment(ioas_id=%u, seg_size=0x%x, io_pagesize=%u)", ioas_id, seg_size, io_pagesize);

		if (ioas_id != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		if (seg_size >= 1ull << 35 || seg_size > 1ull << 28)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 2);
			return;
		}

		if (io_pagesize != 12 && io_pagesize != 16 && io_pagesize != 20 && io_pagesize != 24)
		{
			ppu.gpr[3] = lv1_status(LV1_ILLEGAL_PARAMETER_VALUE, 4);
			return;
		}

		// The segment object then sizes its I/O page table from the size and the page (0x2d9868), which has
		// only been followed for a whole number of pages
		if (!seg_size || seg_size % (1ull << io_pagesize))
		{
			fmt::throw_exception("lv1_allocate_io_segment(): a size of 0x%x with pages of 1 << %u has not been followed", seg_size, io_pagesize);
		}

		std::lock_guard lock(lv1s.mutex);

		u64 segment = 0;

		while (lv1s.io_segments.contains(segment))
		{
			segment++;
		}

		if (segment > 7)
		{
			ppu.gpr[3] = lv1_status(LV1_BUSY);
			return;
		}

		lv1s.io_segments.emplace(segment);
		lv1s.guest_io_segments.emplace(segment << 28, lv1_state::io_segment{seg_size, static_cast<u32>(io_pagesize)});

		lv1.notice("lv1_allocate_io_segment() -> ioif_addr 0x%x", segment << 28);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = segment << 28;
		return;
	}
	case 118:
	{
		// lv1_allocate_ioid(ioas_id) -> ioid (lv1 4.93 0x2d7de8, runtime-registered): lv1 creates a single I/O
		// address space, 0 (0x2d945c), so any other id has no entry (0x2d7e18). The ioid is the lowest free one
		// of the space (0x2d7a14). The ioids already in use depend on the south bridge revision, an
		// approximation (initial_ioids). ps2_emu only hands the ioid back to lv1_release_ioid when it shuts the
		// RSX down (0x45ae4).
		const u64 ioas_id = in[3];
		lv1.notice("lv1_allocate_ioid(ioas_id=%u)", ioas_id);

		if (ioas_id != 0)
		{
			ppu.gpr[3] = lv1_status(LV1_NO_ENTRY, 1);
			return;
		}

		std::lock_guard lock(lv1s.mutex);

		u64 ioid = 0;

		while (lv1s.ioids.contains(ioid))
		{
			ioid++;
		}

		lv1s.ioids.emplace(ioid);

		lv1.notice("lv1_allocate_ioid() -> ioid %u", ioid);
		ppu.gpr[3] = LV1_SUCCESS;
		ppu.gpr[4] = ioid;
		return;
	}
	default: break;
	}

	// A call that has not been investigated is not answered: any value made up here would be read by
	// the guest as the hypervisor's word.
	fmt::throw_exception("lv1 hypercall %u is not implemented (r3=0x%x, r4=0x%x, r5=0x%x, r6=0x%x, r7=0x%x, r8=0x%x, r9=0x%x, r10=0x%x, lr=0x%x)",
		code, in[3], in[4], in[5], in[6], in[7], in[8], in[9], in[10], ppu.lr);
}

void lv1_hypercall(ppu_thread& ppu)
{
	// The hypervisor call ABI: the call number in r11, arguments from r3, status returned in r3 and further
	// results in r4 onwards (Linux arch/powerpc/include/asm/lv1call.h). lv1 4.93's vector clears the 128-byte
	// block of its per-thread data that holds r3 to r10 for the return (dcbz at 0xc08) and reloads them all
	// from it on the way out (0x1040..0x1068), so a result register a call does not set comes back 0. The calls
	// registered at boot are the exception: their trampoline copies r4 to r10 into that block from its own
	// stack frame (0x2c8b14), leaving there whatever the stack held in the ones the handler does not set. The
	// model gives 0 for those too; ps2_emu.elf only reads the results those calls set (lv1.md).
	const u64 code = ppu.gpr[11];
	const std::array<u64, 11> in{0, 0, 0, ppu.gpr[3], ppu.gpr[4], ppu.gpr[5], ppu.gpr[6], ppu.gpr[7], ppu.gpr[8], ppu.gpr[9], ppu.gpr[10]};

	for (u32 i = 4; i <= 10; i++)
	{
		ppu.gpr[i] = 0;
	}

	lv1_call(ppu, code, in);

	// The way out (0xfc0..0x107c): lv1 returns with hrfid to the SRR0 and MSR the sc saved, which it leaves in
	// r11 and r12, and with LR at 0x1028 from its own call to 0x1240. If a raised plug of the thread is
	// unmasked and the caller had MSR[EE] set, it enters the partition's External interrupt vector instead
	// (0x18e0), the way it delivers every virtual interrupt (ppu_supervisor_interrupt), and r11 and r12 hold
	// that vector and MSR; with MSR[EE] clear it leaves the interrupt for when the guest enables it (LPCR[MER]).
	// r0 (the TSRL lv1 saved), CTR, XER and CR fields 0, 1 and 5 to 7 are left as they were: lv1's own code
	// leaves values there that the guest does not use (lv1.md).
	auto& lv1s = g_fxo->get<lv1_state>();
	auto& sv = *ppu.supervisor;
	bool pending = false;

	// Every call runs its handler with MSR[EE] set (0x27a0 and mtmsrd around it, or the trampoline 0x2c89cc for
	// the calls registered at boot), so a Decrementer exception of the thread that exists meanwhile is taken
	// by lv1, which notes it and parks DEC at 0x7fffffff (0x2c632c..0x2c637c). On the way out it then writes 0 to
	// DEC for the guest to take it right after, from a call at 0x1050 that leaves LR at 0x1054 (0x1094).
	const u64 timebase = lv1_timebase();
	ppu.lr = 0x1028;

	if (sv.dec_exception(timebase))
	{
		sv.write_dec(0, timebase);
		ppu.lr = 0x1054;
	}

	{
		std::lock_guard lock(lv1s.mutex);
		const auto& irq = lv1s.irq[sv.hw_thread];

		for (u32 i = 0; i < 4; i++)
		{
			pending |= (irq.status[i] & irq.mask[i]) != 0;
		}
	}

	const u64 return_addr = ppu.cia + 4;

	if (pending && (sv.msr & ppu_msr::ee))
	{
		ppu_supervisor_interrupt(ppu, 0x500, return_addr);
		ppu.gpr[11] = 0x500;
		ppu.gpr[12] = sv.msr;
		return;
	}

	ppu.gpr[11] = return_addr;
	ppu.gpr[12] = sv.msr & ~ppu_msr::srr1_cause_bits;
	ppu.cia = static_cast<u32>(return_addr);
}
