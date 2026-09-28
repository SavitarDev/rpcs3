#include "stdafx.h"
#include "lv1_bdvd.h"

#include <cstring>

LOG_CHANNEL(bdvd_log, "lv1_bdvd");

namespace
{
	std::string describe(std::span<const u8> packet)
	{
		std::string text;

		for (u8 byte : packet)
		{
			fmt::append(text, "%02x", byte);
		}

		return text;
	}

	// MODE SENSE(10) and MODE SELECT(10) (MMC-5 7.3.2 and 7.4.2 via SPC-3): an 8-byte header without block
	// descriptors (MMC devices have none) followed by the pages
	u64 mode_sense_10(lv1_bdvd& drive, std::span<const u8> packet, u8* data, u32 size)
	{
		const u8 page_control = packet[2] >> 6;
		const u8 page_code = packet[2] & 0x3f;
		const u32 allocation = packet[7] << 8 | packet[8];

		if (page_code != 0x1a || page_control != 0)
		{
			fmt::throw_exception("BD drive: MODE SENSE(10) of page 0x%x (page control %u) is not implemented", page_code, page_control);
		}

		// Power Condition (MMC-5 7.8.8): page code, page length 10, then the saved Idle/Standby bits and timers.
		// APPROXIMATION (lv1.md, "Approximations"): the values the drive starts with are its firmware's and have
		// not been determined; the model starts with no timer (all 0). ps2_emu reads the two timers, keeps
		// them (0x22688..0x226e8) and then selects the page with both timers off (0x22700..0x22780).
		std::array<u8, 20> reply{};
		reply[1] = 18; // mode data length, the bytes after this field
		reply[8] = 0x1a;
		reply[9] = 10;
		std::memcpy(reply.data() + 10, drive.power_condition.data(), drive.power_condition.size());

		std::memcpy(data, reply.data(), std::min<u32>({size, allocation, static_cast<u32>(reply.size())}));
		return 0;
	}

	u64 mode_select_10(lv1_bdvd& drive, std::span<const u8> packet, const u8* data, u32 size)
	{
		const u32 length = packet[7] << 8 | packet[8];

		// PF set (pages as the standard lays them out), one page after the header
		if (!(packet[1] & 0x10) || length < 20 || size < 20 || data[6] || data[7] || (data[8] & 0x3f) != 0x1a || data[9] != 10)
		{
			fmt::throw_exception("BD drive: MODE SELECT(10) %s is not implemented", describe(packet));
		}

		std::memcpy(drive.power_condition.data(), data + 10, drive.power_condition.size());
		return 0;
	}
}

u64 lv1_bdvd_packet(lv1_bdvd& drive, std::span<const u8> packet, u8* data, u32 size, bool to_host)
{
	bdvd_log.trace("packet %s, %u bytes %s", describe(packet), size, to_host ? "in" : "out");

	if (packet[0] == 0x5a && to_host)
	{
		return mode_sense_10(drive, packet, data, size);
	}

	if (packet[0] == 0x55 && !to_host)
	{
		return mode_select_10(drive, packet, data, size);
	}

	fmt::throw_exception("BD drive: packet command %s (%u bytes %s) is not implemented", describe(packet), size, to_host ? "in" : "out");
}
