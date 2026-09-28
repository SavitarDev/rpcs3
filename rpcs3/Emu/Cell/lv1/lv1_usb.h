#pragma once

#include "util/types.hpp"

#include <functional>
#include <map>

// The USB host controllers of the PlayStation 3 south bridge, as the partition sees them through the
// register windows it maps with lv1_map_device_mmio_region: for each of the two controllers (bus 1,
// devices 1 and 2) an OHCI one and its EHCI companion (the Linux PS3 glue, drivers/usb/host/ohci-ps3.c and
// ehci-ps3.c, drives both as standard controllers with big-endian registers and descriptors).
struct lv1_usb_controller
{
	// APPROXIMATION (lv1.md, "Approximations"): the Sony registers at 0x800 to 0xfff of the OHCI window,
	// outside the OHCI ones. ps2_emu uses 0xff0 for a reset handshake (0x28a94: writes 1, 5, 0x40005, then
	// sets bits 16 to 18 and waits for bits 16 and 17 to read back set) and writes 3 to 0x80c and 0xb0000000
	// to 0x804 (0x28bb0..0x28bcc). What the hardware does with them is not public; the model keeps what was
	// written, by offset.
	std::map<u32, u32> sony;

	// OHCI 1.0a (Open Host Controller Interface Specification for USB, release 1.0a, chapter 7) operational
	// registers, with their values after a reset (7.1 to 7.3)
	struct ohci_registers
	{
		u32 control = 0; // HcControl, UsbReset
		u32 command_status = 0; // HcCommandStatus
		u32 interrupt_status = 0; // HcInterruptStatus
		u32 interrupt_enable = 0; // HcInterruptEnable / HcInterruptDisable
		u32 hcca = 0; // HcHCCA
		u32 period_current_ed = 0; // HcPeriodCurrentED
		u32 control_head_ed = 0; // HcControlHeadED
		u32 control_current_ed = 0; // HcControlCurrentED
		u32 bulk_head_ed = 0; // HcBulkHeadED
		u32 bulk_current_ed = 0; // HcBulkCurrentED
		u32 done_head = 0; // HcDoneHead
		u32 fm_interval = 0x2edf; // HcFmInterval, FrameInterval 11999
		u32 fm_number = 0; // HcFmNumber
		u32 frame_remaining_toggle = 0; // HcFmRemaining's FrameRemainingToggle
		u32 periodic_start = 0; // HcPeriodicStart
		u32 ls_threshold = 0x628; // HcLSThreshold
		u32 done_interrupt_delay = 7; // the frames left before the done queue is written back (7: none due)

		// HcRhDescriptorA (7.4.1). The number of downstream ports is 2: ps2_emu's driver handles
		// HcRhPortStatus[0] and [1] only (0x312c0, 0x31564..0x315dc) and prints PortSC0 and PortSC1 alone for
		// the EHCI companion (0x38564). APPROXIMATION (lv1.md, "Approximations"): the reset values of the other
		// fields (PSM, NPS, OCPM, NOCP, POTPGT) are not public; they start at 0, and ps2_emu sets NPS and
		// clears PSM (0x3823c..0x38264), so power switching and its delay play no part.
		u32 rh_descriptor_a = 2;
	} ohci;

	// The timebase at which the controller ran its last frame
	u64 last_frame = 0;

	// EHCI 1.0 (Enhanced Host Controller Interface Specification for USB, revision 1.0, chapter 2) registers
	struct ehci_registers
	{
		u32 usbcmd = 0x80000; // USBCMD, Interrupt Threshold 8 micro-frames (2.3.1)
		u32 usbsts = 0x1000; // USBSTS, HCHalted (2.3.2)
		u32 usbintr = 0; // USBINTR
		u32 frindex = 0; // FRINDEX
		u32 ctrldssegment = 0; // CTRLDSSEGMENT
		u32 periodiclistbase = 0; // PERIODICLISTBASE
		u32 asynclistaddr = 0; // ASYNCLISTADDR
		u32 configflag = 0; // CONFIGFLAG
		u32 portsc[2]{0x2000, 0x2000}; // PORTSC, Port Owner (companion) set while CONFIGFLAG is 0 (2.3.9)
	} ehci;

	// The timebase at which the EHCI controller ran its last micro-frame
	u64 last_microframe = 0;

	// Reach the partition's memory behind a bus address the controller masters (null if nothing is mapped
	// there), and raise the OHCI and the EHCI interrupts
	std::function<u8*(u32 bus_addr, u32 size)> dma;
	std::function<void()> interrupt;
	std::function<void()> ehci_interrupt;
};

// A load or store of size bytes at offset offset of a controller's OHCI register window (the OHCI registers
// and the Sony ones after them). data holds the bytes in storage order.
void lv1_usb_ohci_access(lv1_usb_controller& usb, u32 offset, u8* data, u32 size, bool store);

// Run the frames an operational controller has due by the given timebase (at lv1_timebase_freq)
void lv1_usb_ohci_run(lv1_usb_controller& usb, u64 timebase);

// Whether the controller holds its OHCI interrupt line up: an enabled interrupt status bit while
// MasterInterruptEnable is set (OHCI 5.3)
bool lv1_usb_ohci_interrupt_level(const lv1_usb_controller& usb);

// Whether the controller holds its EHCI interrupt line up: an enabled USBSTS interrupt bit (EHCI 2.3.3)
bool lv1_usb_ehci_interrupt_level(const lv1_usb_controller& usb);

// A load or store at offset offset of a controller's EHCI register window
void lv1_usb_ehci_access(lv1_usb_controller& usb, u32 offset, u8* data, u32 size, bool store);

// Run the micro-frames a running EHCI controller has due by the given timebase
void lv1_usb_ehci_run(lv1_usb_controller& usb, u64 timebase);
