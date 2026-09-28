#include "stdafx.h"
#include "lv1_usb.h"
#include "lv1.h"

LOG_CHANNEL(lv1_usb);

namespace
{
	// HcControl (7.1.2)
	constexpr u32 control_ple = 1u << 2; // PeriodicListEnable
	constexpr u32 control_cle = 1u << 4; // ControlListEnable
	constexpr u32 control_ble = 1u << 5; // BulkListEnable
	constexpr u32 hcfs_operational = 2;
	constexpr u32 hcfs_suspend = 3;

	// HcCommandStatus (7.1.3)
	constexpr u32 command_hcr = 1u << 0; // HostControllerReset
	constexpr u32 command_clf = 1u << 1; // ControlListFilled
	constexpr u32 command_blf = 1u << 2; // BulkListFilled

	// HcInterruptStatus and HcInterruptEnable (7.1.4, 7.1.5)
	constexpr u32 interrupt_wdh = 1u << 1; // WritebackDoneHead
	constexpr u32 interrupt_sf = 1u << 2; // StartofFrame
	constexpr u32 interrupt_fno = 1u << 5; // FrameNumberOverflow
	constexpr u32 interrupt_mie = 1u << 31; // MasterInterruptEnable

	// A frame is 1 ms (7.3.1: FrameInterval 11999 bit times of 12 MHz)
	constexpr u64 frame_ticks = lv1_timebase_freq / 1000;

	u32 hcfs(const lv1_usb_controller& usb)
	{
		return (usb.ohci.control >> 6) & 3;
	}

	// The descriptors in the partition's memory are big-endian (the PS3 glue's OHCI_QUIRK_BE_DESC)
	u8* dma(lv1_usb_controller& usb, u32 bus_addr, u32 size)
	{
		u8* ptr = usb.dma(bus_addr, size);

		if (!ptr)
		{
			fmt::throw_exception("OHCI: no memory behind bus address 0x%x", bus_addr);
		}

		return ptr;
	}

	u32 read_dma32(lv1_usb_controller& usb, u32 bus_addr)
	{
		return read_from_ptr_unsafe<be_t<u32>>(dma(usb, bus_addr, 4), 0);
	}

	void write_dma32(lv1_usb_controller& usb, u32 bus_addr, u32 value)
	{
		write_to_ptr_unsafe<be_t<u32>>(dma(usb, bus_addr, 4), 0, value);
	}

	void write_dma16(lv1_usb_controller& usb, u32 bus_addr, u16 value)
	{
		write_to_ptr_unsafe<be_t<u16>>(dma(usb, bus_addr, 2), 0, value);
	}

	// Set interrupt status bits; an enabled one raises the controller's interrupt while MIE is set (5.3)
	void set_status(lv1_usb_controller& usb, u32 bits)
	{
		const u32 fresh = bits & ~usb.ohci.interrupt_status;
		usb.ohci.interrupt_status |= bits;

		if ((fresh & usb.ohci.interrupt_enable) && (usb.ohci.interrupt_enable & interrupt_mie))
		{
			usb.interrupt();
		}
	}

	// A software reset (7.1.3 HCR): the operational registers go back to their reset values, the root hub's
	// are kept (7.4), and the controller is left in UsbSuspend
	void reset(lv1_usb_controller& usb)
	{
		const u32 rh_descriptor_a = usb.ohci.rh_descriptor_a;
		usb.ohci = {};
		usb.ohci.control = hcfs_suspend << 6;
		usb.ohci.rh_descriptor_a = rh_descriptor_a;
	}

	// Retire a general TD (4.3.1.3.5): its condition code, then onto the done queue
	void retire_td(lv1_usb_controller& usb, u32 td, u32 condition)
	{
		const u32 dword0 = read_dma32(usb, td);
		write_dma32(usb, td, (dword0 & 0x0fffffff) | (condition << 28));
		write_dma32(usb, td + 8, usb.ohci.done_head);
		usb.ohci.done_head = td;

		// The delay the TD asks for its interrupt, if shorter than the one pending (bits 21:23, 7 = none)
		usb.ohci.done_interrupt_delay = std::min<u32>(usb.ohci.done_interrupt_delay, (dword0 >> 21) & 7);
	}

	// Service one endpoint descriptor (4.2, 6.4.3): the model has no device on its bus yet, so a transaction
	// gets no answer and the TD ends with DeviceNotResponding after its three tries, halting the endpoint
	void service_ed(lv1_usb_controller& usb, u32 ed)
	{
		const u32 dword0 = read_dma32(usb, ed);
		const u32 tail = read_dma32(usb, ed + 4) & ~0xfu;
		const u32 head = read_dma32(usb, ed + 8);

		// Skip, halted, or an empty queue
		if ((dword0 >> 14) & 1 || head & 1 || (head & ~0xfu) == tail)
		{
			return;
		}

		if ((dword0 >> 15) & 1)
		{
			fmt::throw_exception("OHCI: isochronous endpoint descriptor at 0x%x is not implemented", ed);
		}

		const u32 td = head & ~0xfu;
		const u32 next_td = read_dma32(usb, td + 8) & ~0xfu;

		lv1_usb.notice("OHCI: transfer to address %u endpoint %u (ED 0x%x, TD 0x%x): no device answers", dword0 & 0x7f, (dword0 >> 7) & 0xf, ed, td);

		constexpr u32 device_not_responding = 5;
		retire_td(usb, td, device_not_responding);
		write_dma32(usb, ed + 8, next_td | (head & 2) | 1);
	}

	// Walk a list of endpoint descriptors
	void service_list(lv1_usb_controller& usb, u32 ed)
	{
		for (u32 count = 0; ed; count++)
		{
			if (count >= 0x10000)
			{
				fmt::throw_exception("OHCI: endpoint descriptor list without an end");
			}

			service_ed(usb, ed);
			ed = read_dma32(usb, ed + 12) & ~0xfu;
		}
	}

	// One frame (6.3, 6.4): the frame number goes to the HCCA, then the periodic list the interrupt table
	// names for it, then the control and bulk lists, and at its end the done queue is written back when its
	// delay has run out
	void frame(lv1_usb_controller& usb)
	{
		auto& o = usb.ohci;

		o.fm_number = (o.fm_number + 1) & 0xffff;
		o.frame_remaining_toggle = o.fm_interval >> 31;
		write_dma16(usb, o.hcca + 0x80, static_cast<u16>(o.fm_number));
		write_dma16(usb, o.hcca + 0x82, 0);

		u32 status = interrupt_sf;

		if ((o.fm_number & 0x7fff) == 0)
		{
			status |= interrupt_fno;
		}

		// An isochronous endpoint in the periodic list stops in service_ed, whether IsochronousEnable is set or not
		if (o.control & control_ple)
		{
			service_list(usb, read_dma32(usb, o.hcca + (o.fm_number & 31) * 4) & ~0xfu);
		}

		if ((o.control & control_cle) && (o.command_status & command_clf))
		{
			o.command_status &= ~command_clf;
			service_list(usb, o.control_head_ed);
		}

		if ((o.control & control_ble) && (o.command_status & command_blf))
		{
			o.command_status &= ~command_blf;
			service_list(usb, o.bulk_head_ed);
		}

		if (o.done_head && o.done_interrupt_delay != 7)
		{
			if (o.done_interrupt_delay)
			{
				o.done_interrupt_delay--;
			}
			else if (!(o.interrupt_status & interrupt_wdh))
			{
				// HccaDoneHead, with bit 0 set when other interrupts are pending too (4.4.2.2)
				const bool others = (o.interrupt_status | status) & o.interrupt_enable & ~interrupt_wdh & 0x7fffffff;
				write_dma32(usb, o.hcca + 0x84, o.done_head | (others ? 1 : 0));
				o.done_head = 0;
				o.done_interrupt_delay = 7;
				status |= interrupt_wdh;
			}
		}

		set_status(usb, status);
	}
}

bool lv1_usb_ohci_interrupt_level(const lv1_usb_controller& usb)
{
	return (usb.ohci.interrupt_enable & interrupt_mie) && (usb.ohci.interrupt_status & usb.ohci.interrupt_enable & 0x7fffffff);
}

bool lv1_usb_ehci_interrupt_level(const lv1_usb_controller& usb)
{
	return (usb.ehci.usbsts & usb.ehci.usbintr & 0x3f) != 0;
}

void lv1_usb_ohci_run(lv1_usb_controller& usb, u64 timebase)
{
	if (hcfs(usb) != hcfs_operational)
	{
		usb.last_frame = timebase;
		return;
	}

	// The frames missed while nothing ran are not made up beyond a few
	u64 due = (timebase - usb.last_frame) / frame_ticks;

	if (due > 8)
	{
		usb.last_frame = timebase - frame_ticks * 8;
		due = 8;
	}

	for (; due; due--)
	{
		usb.last_frame += frame_ticks;
		frame(usb);
	}
}

void lv1_usb_ohci_access(lv1_usb_controller& usb, u32 offset, u8* data, u32 size, bool store)
{
	if (offset >= 0x800 && offset < 0x1000 && size == 4 && offset % 4 == 0)
	{
		if (store)
		{
			usb.sony[offset] = read_from_ptr_unsafe<be_t<u32>>(data, 0);
		}
		else
		{
			write_to_ptr_unsafe<be_t<u32>>(data, 0, usb.sony[offset]);
		}

		lv1_usb.trace("Sony 0x%x: %s 0x%x", offset, store ? "store" : "load", usb.sony[offset]);
		return;
	}

	// The operational registers are 32 bits wide and accessed whole
	if (size != 4 || offset % 4)
	{
		fmt::throw_exception("OHCI: 0x%x-byte %s at 0x%x is not implemented", size, store ? "store" : "load", offset);
	}

	auto& o = usb.ohci;
	const u64 now = lv1_timebase();
	lv1_usb_ohci_run(usb, now);

	const u32 value = store ? u32{read_from_ptr_unsafe<be_t<u32>>(data, 0)} : 0;
	u32 result = 0;

	switch (offset)
	{
	case 0x00:
	{
		// HcRevision (7.1.1): OHCI 1.0, no legacy support. Read only.
		result = 0x10;
		break;
	}
	case 0x04:
	{
		// HcControl (7.1.2). Entering UsbOperational starts the frames from now.
		if (store)
		{
			if (((value >> 6) & 3) == hcfs_operational && hcfs(usb) != hcfs_operational)
			{
				usb.last_frame = now;
			}

			o.control = value & 0x7ff;
		}

		result = o.control;
		break;
	}
	case 0x08:
	{
		// HcCommandStatus (7.1.3): writing 1 sets HCR, CLF, BLF and OCR; a reset is done at once
		if (store)
		{
			if (value & command_hcr)
			{
				reset(usb);
			}

			o.command_status |= value & 0xe;
		}

		result = o.command_status;
		break;
	}
	case 0x0c:
	{
		// HcInterruptStatus (7.1.4): writing 1 clears a bit
		if (store)
		{
			o.interrupt_status &= ~value;
		}

		result = o.interrupt_status;
		break;
	}
	case 0x10:
	case 0x14:
	{
		// HcInterruptEnable (7.1.5) sets and HcInterruptDisable (7.1.6) clears the bits written as 1; both
		// read as the enabled interrupts. An interrupt pending when it gets enabled is signalled.
		if (store)
		{
			const u32 before = o.interrupt_enable;
			o.interrupt_enable = offset == 0x10 ? before | value : before & ~value;

			if (offset == 0x10 && (o.interrupt_enable & interrupt_mie) && (o.interrupt_status & o.interrupt_enable & ~before & 0x7fffffff))
			{
				usb.interrupt();
			}
		}

		result = o.interrupt_enable;
		break;
	}
	case 0x18:
	{
		// HcHCCA (7.2.1): 256-byte aligned, the low 8 bits read as 0
		if (store)
		{
			o.hcca = value & ~0xffu;
		}

		result = o.hcca;
		break;
	}
	case 0x1c:
	{
		result = o.period_current_ed;
		break;
	}
	case 0x20:
	case 0x24:
	case 0x28:
	case 0x2c:
	{
		// HcControlHeadED, HcControlCurrentED, HcBulkHeadED, HcBulkCurrentED (7.2.3 to 7.2.6): 16-byte aligned
		u32& reg = offset == 0x20 ? o.control_head_ed : offset == 0x24 ? o.control_current_ed : offset == 0x28 ? o.bulk_head_ed : o.bulk_current_ed;

		if (store)
		{
			reg = value & ~0xfu;
		}

		result = reg;
		break;
	}
	case 0x30:
	{
		// HcDoneHead (7.2.7), read only
		result = o.done_head;
		break;
	}
	case 0x34:
	{
		// HcFmInterval (7.3.1): FrameInterval 0:13, FSLargestDataPacket 16:30, FrameIntervalToggle 31
		if (store)
		{
			o.fm_interval = value & 0xffff3fff;
		}

		result = o.fm_interval;
		break;
	}
	case 0x38:
	{
		// HcFmRemaining (7.3.2): the bit times left in the frame, counting down from FrameInterval
		const u64 elapsed = hcfs(usb) == hcfs_operational ? std::min<u64>(now - usb.last_frame, frame_ticks) : 0;
		const u32 interval = o.fm_interval & 0x3fff;
		result = static_cast<u32>(interval - elapsed * interval / frame_ticks) | (o.frame_remaining_toggle << 31);
		break;
	}
	case 0x3c:
	{
		// HcFmNumber (7.3.3), read only
		result = o.fm_number;
		break;
	}
	case 0x40:
	{
		// HcPeriodicStart (7.3.4)
		if (store)
		{
			o.periodic_start = value & 0x3fff;
		}

		result = o.periodic_start;
		break;
	}
	case 0x44:
	{
		// HcLSThreshold (7.3.5)
		if (store)
		{
			o.ls_threshold = value & 0xfff;
		}

		result = o.ls_threshold;
		break;
	}
	case 0x48:
	{
		// HcRhDescriptorA (7.4.1): PSM, NPS, OCPM, NOCP and POTPGT can be written, NDP and DT cannot
		constexpr u32 writable = 0xff001b00;

		if (store)
		{
			o.rh_descriptor_a = (o.rh_descriptor_a & ~writable) | (value & writable);
		}

		result = o.rh_descriptor_a;
		break;
	}
	default:
	{
		fmt::throw_exception("OHCI: register 0x%x (%s 0x%x) is not implemented", offset, store ? "store" : "load", value);
	}
	}

	lv1_usb.trace("OHCI 0x%x: %s 0x%x", offset, store ? "store" : "load", store ? value : result);

	if (!store)
	{
		write_to_ptr_unsafe<be_t<u32>>(data, 0, result);
	}
}

namespace
{
	// EHCI: the capability registers are CAPLENGTH bytes long and the operational ones follow (2.2).
	// APPROXIMATION (lv1.md, "Approximations"): the PS3's CAPLENGTH is not public. ps2_emu locates the
	// operational registers through it (0x3c448..0x3c474), so the value only sets the model's own layout;
	// 0x10, the length of the architected capability registers.
	constexpr u32 ehci_caplength = 0x10;

	// HCSPARAMS (2.2.3): N_PORTS 2 (see rh_descriptor_a). APPROXIMATION (lv1.md): the other fields are not
	// public; port power always on (PPC 0, as the OHCI side runs without power switching once ps2_emu sets
	// it), one companion controller owning both ports (N_CC 1, N_PCC 2), no port indicators, no debug port.
	constexpr u32 ehci_hcsparams = 2 | (2 << 8) | (1 << 12);

	constexpr u32 usbcmd_rs = 1u << 0; // Run/Stop
	constexpr u32 usbcmd_hcreset = 1u << 1; // Host Controller Reset
	constexpr u32 usbcmd_pse = 1u << 4; // Periodic Schedule Enable
	constexpr u32 usbcmd_ase = 1u << 5; // Asynchronous Schedule Enable
	constexpr u32 usbsts_hchalted = 1u << 12;
	constexpr u32 usbsts_pss = 1u << 14; // Periodic Schedule Status
	constexpr u32 usbsts_ass = 1u << 15; // Asynchronous Schedule Status

	// A micro-frame is 125 us (4.5)
	constexpr u64 microframe_ticks = lv1_timebase_freq / 8000;

	constexpr u32 usbcmd_iaad = 1u << 6; // Interrupt on Async Advance Doorbell
	constexpr u32 usbsts_flr = 1u << 3; // Frame List Rollover
	constexpr u32 usbsts_iaa = 1u << 5; // Interrupt on Async Advance

	// Set USBSTS interrupt bits; an enabled one raises the controller's interrupt (2.3.3)
	void ehci_set_status(lv1_usb_controller& usb, u32 bits)
	{
		const u32 fresh = bits & ~usb.ehci.usbsts;
		usb.ehci.usbsts |= bits;

		if (fresh & usb.ehci.usbintr)
		{
			usb.ehci_interrupt();
		}
	}

	// A queue head (3.6): the model has no device on its bus yet, so a queue with a transfer to do, active in
	// its overlay or waiting as the next qTD, stops here
	void ehci_queue_head(lv1_usb_controller& usb, u32 qh)
	{
		const u32 characteristics = read_dma32(usb, qh + 4);
		const u32 next_qtd = read_dma32(usb, qh + 16);
		const u32 token = read_dma32(usb, qh + 24);

		// Token bit 7 is Active and bit 6 Halted (3.5.3). An active overlay is a transfer in progress; an
		// inactive one that is not halted advances to the next qTD when that pointer's Terminate bit is clear
		// (4.10.2), and the qTD is a transfer if it is active.
		const bool pending = (token & 0x80) || (!(token & 0x40) && !(next_qtd & 1) && (read_dma32(usb, (next_qtd & ~0x1fu) + 8) & 0x80));

		lv1_usb.trace("EHCI: queue head 0x%x: characteristics 0x%x, next qTD 0x%x, token 0x%x", qh, characteristics, next_qtd, token);

		if (pending)
		{
			fmt::throw_exception("EHCI: transfer to device address %u endpoint %u (queue head 0x%x) is not implemented", characteristics & 0x7f, (characteristics >> 8) & 0xf, qh);
		}
	}

	// Follow a chain of schedule elements by their link pointers (3.1): bit 0 is Terminate, bits 1:2 the type
	// (0 iTD, 1 QH, 2 siTD, 3 FSTN). The asynchronous list is circular and ends back at its start.
	void ehci_walk(lv1_usb_controller& usb, u32 link, bool asynchronous)
	{
		const u32 start = link & ~0x1fu;

		for (u32 count = 0; !(link & 1); count++)
		{
			if (count >= 0x1000)
			{
				fmt::throw_exception("EHCI: schedule without an end");
			}

			const u32 type = (link >> 1) & 3;
			const u32 element = link & ~0x1fu;

			switch (type)
			{
			case 0:
			{
				// iTD (3.3): eight transaction words, bit 31 Active
				for (u32 i = 1; i <= 8; i++)
				{
					if (read_dma32(usb, element + i * 4) >> 31)
					{
						fmt::throw_exception("EHCI: isochronous transfer (iTD 0x%x) is not implemented", element);
					}
				}

				break;
			}
			case 1:
			{
				ehci_queue_head(usb, element);
				break;
			}
			case 2:
			{
				// siTD (3.4): the transfer state's bit 7 is Active
				if (read_dma32(usb, element + 12) & 0x80)
				{
					fmt::throw_exception("EHCI: split isochronous transfer (siTD 0x%x) is not implemented", element);
				}

				break;
			}
			default:
			{
				// FSTN (3.7): only its normal path link matters outside split transactions
				break;
			}
			}

			link = read_dma32(usb, element);

			if (asynchronous && (link & ~0x1fu) == start)
			{
				break;
			}
		}
	}

	// A micro-frame: FRINDEX counts on, the periodic schedule runs the frame list entry of the frame, the
	// asynchronous one its list, and a rung doorbell is answered (4.8.2)
	void ehci_microframe(lv1_usb_controller& usb)
	{
		auto& e = usb.ehci;
		const u32 before = e.frindex;
		e.frindex = (e.frindex + 1) & 0x3fff;

		u32 status = 0;

		// With the 1024-entry frame list the list rolls over when FRINDEX bit 13 toggles (2.3.2)
		if ((before ^ e.frindex) & 0x2000)
		{
			status |= usbsts_flr;
		}

		if (e.usbcmd & usbcmd_pse)
		{
			ehci_walk(usb, read_dma32(usb, e.periodiclistbase + ((e.frindex >> 3) & 0x3ff) * 4), false);
		}

		if (e.usbcmd & usbcmd_ase)
		{
			ehci_walk(usb, e.asynclistaddr | 2, true);
		}

		if (e.usbcmd & usbcmd_iaad)
		{
			e.usbcmd &= ~usbcmd_iaad;
			status |= usbsts_iaa;
		}

		if (status)
		{
			ehci_set_status(usb, status);
		}
	}
}

void lv1_usb_ehci_run(lv1_usb_controller& usb, u64 timebase)
{
	if (!(usb.ehci.usbcmd & usbcmd_rs))
	{
		usb.last_microframe = timebase;
		return;
	}

	// The micro-frames missed while nothing ran are not made up beyond a few
	u64 due = (timebase - usb.last_microframe) / microframe_ticks;

	if (due > 64)
	{
		usb.last_microframe = timebase - microframe_ticks * 64;
		due = 64;
	}

	for (; due; due--)
	{
		usb.last_microframe += microframe_ticks;
		ehci_microframe(usb);
	}
}

void lv1_usb_ehci_access(lv1_usb_controller& usb, u32 offset, u8* data, u32 size, bool store)
{
	if (size != 4 || offset % 4)
	{
		fmt::throw_exception("EHCI: 0x%x-byte %s at 0x%x is not implemented", size, store ? "store" : "load", offset);
	}

	auto& e = usb.ehci;
	const u64 now = lv1_timebase();
	lv1_usb_ehci_run(usb, now);

	const u32 value = store ? u32{read_from_ptr_unsafe<be_t<u32>>(data, 0)} : 0;
	u32 result = 0;

	if (offset < ehci_caplength)
	{
		if (store)
		{
			fmt::throw_exception("EHCI: store 0x%x to capability register 0x%x", value, offset);
		}

		switch (offset)
		{
		case 0x00: result = ehci_caplength | (0x100 << 16); break; // CAPLENGTH, HCIVERSION 1.0 (2.2.1, 2.2.2)
		case 0x04: result = ehci_hcsparams; break;

		// HCCPARAMS (2.2.4). APPROXIMATION (lv1.md): not public; the architected minimum, 32-bit addressing,
		// a frame list of 1024 entries, no asynchronous schedule park, no extended capabilities.
		case 0x08: result = 0; break;

		// HCSP-PORTROUTE (2.2.5) is only valid with Port Routing Rules set in HCSPARAMS, which is 0
		case 0x0c: result = 0; break;
		default: fmt::throw_exception("EHCI: capability register 0x%x is not implemented", offset);
		}
	}
	else
	{
		switch (offset - ehci_caplength)
		{
		case 0x00:
		{
			// USBCMD (2.3.1): a reset is done at once and clears itself (4.1); Run/Stop moves HCHalted, and the
			// schedule enables their status bits
			if (store)
			{
				if (value & usbcmd_hcreset)
				{
					e = {};
				}
				else
				{
					if ((value & usbcmd_rs) && !(e.usbcmd & usbcmd_rs))
					{
						usb.last_microframe = now;
					}

					e.usbcmd = value & 0x00ff0b7d;
					e.usbsts &= ~(usbsts_hchalted | usbsts_pss | usbsts_ass);
					e.usbsts |= (e.usbcmd & usbcmd_rs) ? 0 : usbsts_hchalted;
					e.usbsts |= (e.usbcmd & usbcmd_pse) ? usbsts_pss : 0;
					e.usbsts |= (e.usbcmd & usbcmd_ase) ? usbsts_ass : 0;
				}
			}

			result = e.usbcmd;
			break;
		}
		case 0x04:
		{
			// USBSTS (2.3.2): the interrupt bits 0:5 are cleared by writing 1
			if (store)
			{
				e.usbsts &= ~(value & 0x3f);
			}

			result = e.usbsts;
			break;
		}
		case 0x08:
		{
			// USBINTR (2.3.3)
			if (store)
			{
				e.usbintr = value & 0x3f;
			}

			result = e.usbintr;
			break;
		}
		case 0x0c:
		{
			// FRINDEX (2.3.4)
			if (store)
			{
				e.frindex = value & 0x3fff;
			}

			result = e.frindex;
			break;
		}
		case 0x10:
		{
			// CTRLDSSEGMENT (2.3.5)
			if (store)
			{
				e.ctrldssegment = value;
			}

			result = e.ctrldssegment;
			break;
		}
		case 0x14:
		{
			// PERIODICLISTBASE (2.3.6), 4 KB aligned
			if (store)
			{
				e.periodiclistbase = value & ~0xfffu;
			}

			result = e.periodiclistbase;
			break;
		}
		case 0x18:
		{
			// ASYNCLISTADDR (2.3.7), 32-byte aligned
			if (store)
			{
				e.asynclistaddr = value & ~0x1fu;
			}

			result = e.asynclistaddr;
			break;
		}
		case 0x44:
		case 0x48:
		{
			// PORTSC (2.3.9). No device is attached to the model's ports yet: Current Connect Status stays 0.
			// Port Power is 1 and read only with PPC 0. Writing 1 clears the change bits (CSC 1, PEC 3, OCC 5);
			// a port without a device cannot be enabled, and a reset of an empty port ends at once.
			u32& port = e.portsc[(offset - ehci_caplength - 0x44) / 4];

			if (store)
			{
				port &= ~(value & 0x2a);

				// Port Owner (13), the wake bits (20:22), the indicator and test control (14:19) and Suspend (7)
				// follow the write; Port Enabled can only be cleared
				constexpr u32 follows = 0x2000 | 0x700000 | 0xfc000 | 0x80;
				port = (port & ~follows) | (value & follows);

				if (!(value & 4))
				{
					port &= ~4u;
				}
			}

			result = port | 0x1000;
			break;
		}
		case 0x40:
		{
			// CONFIGFLAG (2.3.8): 1 routes the ports to this controller, clearing their Port Owner bit
			if (store)
			{
				e.configflag = value & 1;

				for (u32& port : e.portsc)
				{
					port = e.configflag ? port & ~0x2000u : port | 0x2000u;
				}
			}

			result = e.configflag;
			break;
		}
		default:
		{
			fmt::throw_exception("EHCI: register 0x%x (%s 0x%x) is not implemented", offset - ehci_caplength, store ? "store" : "load", value);
		}
		}
	}

	lv1_usb.trace("EHCI 0x%x: %s 0x%x", offset, store ? "store" : "load", store ? value : result);

	if (!store)
	{
		write_to_ptr_unsafe<be_t<u32>>(data, 0, result);
	}
}
