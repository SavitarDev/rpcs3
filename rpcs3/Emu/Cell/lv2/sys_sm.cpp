#include "stdafx.h"
#include "Emu/System.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"
#include "Emu/Cell/lv2/sys_process.h"

#include "sys_sm.h"


LOG_CHANNEL(sys_sm);

error_code sys_sm_get_params(vm::ptr<u8> a, vm::ptr<u8> b, vm::ptr<u32> c, vm::ptr<u64> d)
{
	sys_sm.todo("sys_sm_get_params(a=*0x%x, b=*0x%x, c=*0x%x, d=*0x%x)", a, b, c, d);

	if (a) *a = 0; else return CELL_EFAULT;
	if (b) *b = 0; else return CELL_EFAULT;
	if (c) *c = 0x200; else return CELL_EFAULT;
	if (d) *d = 7; else return CELL_EFAULT;

	return CELL_OK;
}

error_code sys_sm_get_hw_config(vm::ptr<u8> unk, vm::ptr<u64> model)
{
	sys_sm.warning("sys_sm_get_hw_config(unk=*0x%x, model=*0x%x)", unk, model);

	if (!unk || !model)
	{
		return CELL_EFAULT;
	}

	// The second output is the console's hardware configuration word: the VSH asks for it at
	// vsh.elf 0x251810 and sends it to Sony's netstart service verbatim, formatted as
	// "&model=%016llx" at 0x25182c. The bits below are the ones the firmware is known to test:
	//
	//   0x0000000000000010  optical drive present                 vsh.elf 0x44e808
	//   0x0000000000000100  PlayStation 2 hardware compatibility  explore_plugin 0xdddb0
	//   0x2000000000000000  PlayStation 2 software emulation      explore_plugin 0xdddc0
	//
	// vsh.elf 0x44e808 reads bit 0x10 and skips querying the optical drive entirely when it is
	// clear. explore_plugin tests the two PS2 bits in turn and, with neither of them set, writes
	// reason 9 into the item at +0x2c4 (0xdddd0), which is what the XMB draws as unsupported data
	// and what puts up "This model of the PS3 system is not compatible with PlayStation 2 format
	// software"; game_ext_plugin reads the same pair at 0x16fe4 to pick the hardware emulator over
	// the software one. Leaving the word at zero, which is what this syscall being unimplemented
	// amounted to, says the console has neither a drive nor PS2 support.
	//
	// This describes the machine, not the medium, so it does not follow what is in the tray: it
	// answers for the same console sys_ss_appliance_info_manager reports, a launch COK-001 with
	// the PlayStation 2 hardware on board and an optical drive attached.
	constexpr u64 hw_optical_drive = 0x0000000000000010;
	constexpr u64 hw_ps2_hardware  = 0x0000000000000100;

	*unk = 0;
	*model = hw_optical_drive | hw_ps2_hardware;

	return CELL_OK;
}

error_code sys_sm_get_ext_event2(vm::ptr<u64> a1, vm::ptr<u64> a2, vm::ptr<u64> a3, u64 a4)
{
	sys_sm.trace("sys_sm_get_ext_event2(a1=*0x%x, a2=*0x%x, a3=*0x%x, a4=*0x%x, a4=0x%xll", a1, a2, a3, a4);

	if (a4 != 0 && a4 != 1)
	{
		return CELL_EINVAL;
	}

	// a1 == 7 - 'console too hot, restart'
	// a2 looks to be used if a1 is either 5 or 3?
	// a3 looks to be ignored in vsh

	if (a1) *a1 = 0; else return CELL_EFAULT;
	if (a2) *a2 = 0; else return CELL_EFAULT;
	if (a3) *a3 = 0; else return CELL_EFAULT;

	// eagain for no event
	return not_an_error(CELL_EAGAIN);
}

error_code sys_sm_shutdown(ppu_thread& ppu, u16 op, vm::ptr<void> param, u64 size)
{
	ppu.state += cpu_flag::wait;

	sys_sm.success("sys_sm_shutdown(op=0x%x, param=*0x%x, size=0x%x)", op, param, size);

	if (!ppu.has_root_perm)
	{
		return CELL_ENOSYS;
	}

	switch (op)
	{
	case 0x100:
	case 0x1100:
	{
		sys_sm.success("Received shutdown request from application");
		_sys_process_exit(ppu, 0, 0, 0);
		break;
	}
	case 0x200:
	case 0x1200:
	{
		sys_sm.success("Received reboot request from application");
		lv2_exitspawn(ppu, true, null_ptr, Emu.argv, Emu.envp, Emu.data, *std::make_unique<std::vector<u8>>());
		break;
	}
	case 0x8201:
	case 0x8202:
	case 0x8204:
	{
		sys_sm.warning("Unsupported LPAR operation: 0x%x", op);
		return CELL_ENOTSUP;
	}
	default: return CELL_EINVAL;
	}

	return CELL_OK;
}

error_code sys_sm_set_shop_mode(s32 mode)
{
	sys_sm.todo("sys_sm_set_shop_mode(mode=0x%x)", mode);

	return CELL_OK;
}

error_code sys_sm_control_led(u8 led, u8 action)
{
	sys_sm.todo("sys_sm_control_led(led=0x%x, action=0x%x)", led, action);

	return CELL_OK;
}

error_code sys_sm_ring_buzzer(u64 packet, u64 a1, u64 a2)
{
	sys_sm.todo("sys_sm_ring_buzzer(packet=0x%x, a1=0x%x, a2=0x%x)", packet, a1, a2);

	return CELL_OK;
}
