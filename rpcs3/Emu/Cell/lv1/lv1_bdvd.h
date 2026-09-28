#pragma once

#include "util/types.hpp"

#include <array>
#include <span>

// The BD drive of the PlayStation 3, the ATAPI device on the south bridge's ATA port 0 that lv1 presents as
// storage device 2 (type 5) and passes packet commands to (lv1_storage_send_device_command, command 1). The
// drive is modelled from the MMC command set (SCSI Multimedia Commands); what a command answers that MMC leaves
// to the drive is documented where it is used.
struct lv1_bdvd
{
	// Mode page 0x1a (Power Condition) as MODE SELECT last set it, from byte 2 on: the Idle and Standby bits
	// and the two condition timers
	std::array<u8, 10> power_condition{};
};

// The result of a packet command: 0 when it succeeds, otherwise CHECK CONDITION with its sense data as lv1
// reports a command's status (Linux ps3rom.c, decode_lv1_status: status >> 24 the SCSI status, then the sense
// key, the additional sense code and its qualifier)
constexpr u64 lv1_atapi_check_condition(u8 key, u8 asc, u8 ascq)
{
	return u64{0x02} << 24 | u64{key} << 16 | u64{asc} << 8 | ascq;
}

// Run a packet command. packet holds the command bytes; data is the transfer buffer of size bytes (the
// partition's memory), filled for a transfer to the host (to_host) and read otherwise. Returns the status.
u64 lv1_bdvd_packet(lv1_bdvd& drive, std::span<const u8> packet, u8* data, u32 size, bool to_host);
