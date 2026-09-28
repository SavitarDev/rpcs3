#include "stdafx.h"
#include "lv1.h"

#include "Emu/System.h"
#include "Emu/system_config.h"
#include "Emu/IdManager.h"
#include "Emu/Memory/vm.h"
#include "Emu/Cell/PPUThread.h"
#include "Emu/Cell/timers.hpp"
#include "Emu/Cell/lv2/sys_process.h"
#include "Emu/Cell/lv2/sys_memory.h"

LOG_CHANNEL(lv1);

extern void ppu_register_range(u32 addr, u32 size);

// Book III v2.02 Figure 35: a System Reset leaves IR, DR, FE0, FE1, EE, RI, BE, FP, PMM, PR and SE clear
// and sets SF. HV is left clear because the thread is started by lv1 for a guest, never in hypervisor
// state. The guest replaces the whole MSR at once with its own rfid at 0x110.
constexpr u64 guest_reset_msr = 1ull << 63;

bool lv1_load_guest_os(const ppu_exec_object& elf, const std::string& path)
{
	if (elf != elf_error::ok)
	{
		return false;
	}

	// An image lv1 loads is laid out by its program headers alone: there is no process parameter
	// block, no TLS and no module to link (ps2_emu.elf has a single PT_LOAD at address 0).
	for (const auto& prog : elf.progs)
	{
		if (prog.p_type == 0x1u /* LOAD */ && prog.p_memsz && ((prog.p_vaddr | prog.p_memsz) > u32{umax} || prog.p_vaddr + prog.p_memsz > lv1_guest_region0_size))
		{
			lv1.error("lv1_load_guest_os(): segment out of the modelled range (vaddr=0x%llx, memsz=0x%llx)", prog.p_vaddr, prog.p_memsz);
			return false;
		}
	}

	// The address space of the partition is modelled with the same object that holds a GameOS
	// process's memory: nothing of lv2 runs, the object only carries the 4 GB view and the threads.
	if (!Emu.init_mem_containers)
	{
		g_fxo->init<id_manager::id_map<lv2_memory_container>>();
	}

	g_fxo->init<id_manager::id_map<named_thread<ppu_thread>>>();
	g_fxo->init<id_manager::id_map<lv2_obj>>();

	const auto process_ptr = idm::make_ptr<lv2_obj, lv2_process>();
	id_manager::g_process = idm::last_id<lv2_process>();
	process_ptr->ELF_file_path = path;

	const auto vm_globals = process_ptr->acquire_globals(id_manager::g_process);

	// The image is entered in real mode and its interrupt vectors live in the first 64 KB, which a
	// GameOS process never has mapped.
	if (!vm::map(0, 0x10000, vm::page_size_4k))
	{
		lv1.error("lv1_load_guest_os(): failed to map the page at address 0");
		return false;
	}

	// The partition's memory from logical partition address 0 is committed whole, the first 64 KB in the block
	// mapped above and the rest in the main area: the image uses all of it, placing its own regions below the
	// top of it before it enables translation
	if (!vm::falloc(0, 0x10000) || !vm::falloc(0x10000, lv1_guest_region0_size - 0x10000))
	{
		lv1.error("lv1_load_guest_os(): failed to commit the partition memory");
		return false;
	}

	// Privileged instructions and the reset vector at address 0 are handled by the interpreter only
	// (the recompiler's analysis refuses an image based at 0), so the guest runs interpreted.
	g_cfg.core.ppu_decoder.set(ppu_decoder_type::_static);

	for (const auto& prog : elf.progs)
	{
		lv1.notice("** Segment: p_type=0x%x, p_vaddr=0x%llx, p_filesz=0x%llx, p_memsz=0x%llx, flags=0x%x", prog.p_type, prog.p_vaddr, prog.p_filesz, prog.p_memsz, prog.p_flags);

		if (prog.p_type != 0x1u /* LOAD */ || !prog.p_memsz)
		{
			continue;
		}

		const u32 addr = static_cast<u32>(prog.p_vaddr);
		const u32 size = static_cast<u32>(prog.p_memsz);

		if (prog.bin.size() > size || prog.bin.size() != prog.p_filesz)
		{
			lv1.error("lv1_load_guest_os(): invalid binary size (0x%llx, memsz=0x%x)", prog.bin.size(), size);
			return false;
		}

		std::memcpy(vm::base(addr), prog.bin.data(), prog.bin.size());

		if (prog.p_flags & 0x1 /* X */)
		{
			ppu_register_range(addr, size);
		}
	}

	// The emulator's own global objects (profiler, renderer, input handlers) come up as for any executable;
	// no HLE function table is created for the partition
	void init_fxo_for_exec(shared_ptr<lv2_process> process, utils::serial* ar, bool full);
	init_fxo_for_exec(process_ptr, nullptr, false);

	// The entry point names a 64-bit function descriptor: the address of the system reset vector and a
	// TOC (0x100 and 0 for ps2_emu.elf, whose reset vector sets its own r2 at 0x128).
	const u32 opd = static_cast<u32>(elf.header.e_entry);

	if (!vm::check_addr(opd, vm::page_readable, 16))
	{
		lv1.error("lv1_load_guest_os(): entry descriptor 0x%x is not in the image", opd);
		return false;
	}

	ppu_thread_params p{};
	p.entry.addr = static_cast<u32>(vm::read64(opd));
	p.entry.rtoc = static_cast<u32>(vm::read64(opd + 8));

	lv1.success("Guest operating system %s: reset vector 0x%x", path, p.entry.addr);

	// A PPE core has two hardware threads and both come out of reset at the same vector: the image
	// tells them apart by CTRL[CT] (0x130) and each waits for the other through low memory (0x2d24 and
	// 0x2d3c), so neither can start without the other.
	u32 thread_ids[2]{};

	for (u32 hw_thread = 0; hw_thread < 2; hw_thread++)
	{
		auto ppu = idm::make_ptr<named_thread<ppu_thread>>(stx::launch_retainer{}, p, hw_thread ? "PPE thread 1" : "PPE thread 0", 0, 1);
		thread_ids[hw_thread] = ppu->id;

		ppu->vm_owner = process_ptr->memory_4GB_model;
		ppu->supervisor = std::make_unique<ppu_supervisor_state>();
		ppu->supervisor->hw_thread = hw_thread;
		ppu->supervisor->msr = guest_reset_msr;
		ppu->supervisor->dec_timebase = lv1_timebase();

		// The page the thread's accesses to device registers go through (see ppu_supervisor_state)
		ppu->supervisor->mmio_scratch = vm::alloc(0x10000, vm::main);

		if (!ppu->supervisor->mmio_scratch)
		{
			lv1.error("lv1_load_guest_os(): failed to allocate the device access page");
			return false;
		}

		// GPR contents after a reset are undefined; the image sets r1 and r2 before using them
		ppu->gpr[1] = 0;

		if (hw_thread == 0 && Emu.IsReady())
		{
			ppu->cmd_push({ppu_cmd::initialize, 0});
		}

		ppu->cmd_push({ppu_cmd::entry_call, 0});

		if (!Emu.IsReady())
		{
			ppu->state -= cpu_flag::stop;
		}

		*ppu = thread_state::created;

		if (!Emu.IsReady())
		{
			ppu->state.notify_one();
		}
	}

	lv1_register_guest_threads(thread_ids[0], thread_ids[1]);
	return true;
}
