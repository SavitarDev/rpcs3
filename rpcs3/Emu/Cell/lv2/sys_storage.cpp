#include "stdafx.h"
#include "Emu/IdManager.h"

#include "Emu/Cell/ErrorCodes.h"
#include "Emu/Cell/PPUThread.h"
#include "Emu/System.h"
#include "sys_event.h"
#include "sys_fs.h"
#include "util/shared_ptr.hpp"

#include "sys_storage.h"
#include "sys_event.h"

#ifdef _WIN32
#include <Windows.h>
#include <ntddscsi.h>
#endif

LOG_CHANNEL(sys_storage);

namespace
{
	auto log_callback(ppu_thread& ppu)
	{	
		sys_storage.todo("Callstack:\n%s", ppu.dump_callstack());
	}

	// Layout of the buffer passed to sys_storage_(async_)send_device_command, reverse engineered
	// from the BD drive documentation (lv2_atapi_cmnd_block, see the PS3 devwiki "BD Drive Reverse
	// Engineering" page): a 32-byte ATAPI packet followed by 6 big-endian u32 fields.
	enum : u32
	{
		atapi_cdb_offset  = 0x00, // pkt[0x20]: the ATAPI/MMC command descriptor block
		atapi_pktlen      = 0x20, // 12 for ATAPI 8020
		atapi_blocks      = 0x24,
		atapi_block_size  = 0x28,
		atapi_proto       = 0x2C, // 0 = non-data, 1 = PIO in, 2 = PIO out, 3 = DMA
		atapi_in_out      = 0x30, // 0 = write, 1 = read
		atapi_cmnd_size   = 0x38,
	};

	// MMC opcodes the VSH issues while probing the optical medium.
	enum : u8
	{
		mmc_test_unit_ready         = 0x00,
		mmc_read_toc                = 0x43,
		mmc_get_configuration       = 0x46,
		mmc_get_event_status_notify = 0x4A,
		mmc_read_disc_information   = 0x51,
		mmc_report_key              = 0xA4,
		mmc_read_disc_structure     = 0xAD,
		mmc_set_cd_speed            = 0xBB,
	};

	// GET CONFIGURATION feature numbers. 0xFF40 is in the vendor specific range and is how the
	// firmware asks a Sony drive whether the medium it holds is a PlayStation one.
	constexpr u16 mmc_feature_playstation_medium = 0xFF40;

	// Sony reserved the 0xFF50-0xFF71 profile range for the PlayStation formats, and the VSH's
	// media classifier (vsh.elf 0x5209b4) maps profiles to its internal media type with exactly
	// this table - everything it does not know becomes 0xFFF0 ("Unknown media, code: 0x%x").
	// The media type names come from the firmware's own code -> name table (vsh.elf 0x6de8c8,
	// read by the formatter at 0x49bdcc): 1 PS3_BD, 2 PS3_DVD, 3 PS2_DVD, 4 PS2_CD, 5 PS1_CD,
	// 6 BDROM, 7 BDMR, 8 BDMRE, 9 DVDROM, 0xC DVDPR, 0xE CDDA, 0xF SACD, 0x11 CDMR...
	// The five reserved profiles map one to one, in order, onto those five media types.
	//
	// What the profile actually selects is the branch the medium is handled by, not the icon the
	// XMB ends up drawing. Types 2 and 3 go through the PlayStation disc authentication at
	// vsh.elf 0x518e2c - sys_ss_disc_access_control, cellSsDrvPs2DiscInsert, the PS2 flag, the
	// /dev_ps2disc mount and the SYSTEM.CNF read - while types 1, 4 and 5 skip all of that and are
	// mounted on /dev_bdvd (vsh.elf 0x51eb78 for type 1, mount mode 2 at 0x51eb18 and 0x51eb54 for
	// the other two). Type 1 is the route a PS1 disc takes, because the promoter that builds the
	// XMB item does not see these media types directly - see get_staged_profile below for the
	// translation that sits in between and for why each format is announced the way it is.
	//
	// The /dev_ps2disc branch cannot be used for a PS1 disc whatever else it is told: the parser it
	// runs on SYSTEM.CNF (0x516ff8) walks the file with 0x516dd0, which answers 0 once past the
	// end, and hands that straight to 0x516e20 without a check, so any file without a BOOT2 line
	// dereferences NULL at 0x516e34. Every PS1 disc has BOOT, not BOOT2.
	//
	// The CD/DVD distinction is not carried by the profile either: a PS2 disc announced as 0xFF60
	// is drawn with item_tex_disc_cd_ps2 (the blue CD) when the geometry reported for it is CD
	// sized and with item_tex_disc_dvd when it is DVD sized, so the firmware composes that from the
	// medium's capacity, exactly like a real drive.
	enum : u32
	{
		ps_profile_ps3_bd  = 0xFF50, // -> 1 PS3_BD,  the route a PS1 disc is announced through
		ps_profile_ps_cd   = 0xFF60, // -> 2 PS3_DVD, the route a PS2 CD  is announced through
		ps_profile_ps_dvd  = 0xFF61, // -> 3 PS2_DVD, the route a PS2 DVD is announced through
		ps_profile_ps2_cd  = 0xFF70, // -> 4 PS2_CD,  unused, see get_staged_profile
		ps_profile_ps1_cd  = 0xFF71, // -> 5 PS1_CD,  unused, see get_staged_profile
	};

	// REPORT KEY (0xA4) with key class 0xE0 and key format 3 answers 8 bytes whose last byte says
	// which PlayStation generation pressed the medium (vsh.elf 0x51f244 asks for it). Three
	// constraints in the firmware pin every value down between them:
	//
	//   - a plain CD/DVD/BD that answers 1, 2 or 3 is refused as contradictory (0x518bbc), so
	//     those three values are the three PlayStation generations and nothing else;
	//   - a PS3_BD medium that answers 2 or 3 is refused the same way (0x518c44), so 2 and 3 both
	//     mean "not a PlayStation 3 disc" and 1 is the PlayStation 3 one;
	//   - the PlayStation disc branch is entered only for 2 or 3 (0x518e2c) and the PS2 flag is
	//     kept afterwards only when the value is exactly 2 (0x519748), so 2 is PlayStation 2.
	//
	// What 3 means is still open, but it is NOT PlayStation 1: that branch sets the PS2 flag and
	// parses /dev_ps2disc/SYSTEM.CNF for a BOOT2 line unconditionally (0x518e78, 0x518eb4), long
	// before 0x519748 ever re-reads this byte, so a PS1 disc taken down it makes the firmware's
	// tokenizer dereference NULL at 0x516e34. Tried and crashed - do not report 3 for a PS1 disc.
	//
	// Only the two profiles a PS2 disc is announced with report a generation, which leaves the PS1
	// disc answering 0: it is announced 0xFF50, and 0x518c44 refuses a medium of that type that
	// claims generation 2 or 3.
	enum : u8
	{
		ps_disc_generation_none = 0,
		ps_disc_generation_ps2  = 2,
	};

	// Storage command 0x11 (not an ATAPI packet): the drive answers with the same profile as
	// above, as a big endian u32. The VSH reads it through vsh.elf 0x51f180 and rejects the
	// medium when it comes back 0 or -1 (vsh.elf 0x521338).
	constexpr u64 storage_cmd_get_profile = 0x11;

	// READ DISC STRUCTURE (0xAD) CDB byte 1, bits 3-0: the medium the structure is requested for.
	enum : u8
	{
		mmc_disc_structure_media_dvd = 0x00,
		mmc_disc_structure_media_bd  = 0x01,
	};

	// The completion event's data2 field carries the command result. Eladash's captured response
	// for READ DISC INFORMATION is 0x8000000002050000, which decodes exactly as
	// (0x80000000 << 32) | status << 24 | sense_key << 16 | ASC << 8 | ASCQ with
	// status 0x02 = CHECK CONDITION and sense key 0x05 = ILLEGAL REQUEST, so build failures the
	// same way. ASC 0x30 / ASCQ 0x00 is "INCOMPATIBLE MEDIUM INSTALLED" (SPC-4 ASC table).
	constexpr u64 make_atapi_sense(u8 status, u8 sense_key, u8 asc, u8 ascq)
	{
		return 0x8000000000000000ull | (u64{status} << 24) | (u64{sense_key} << 16) | (u64{asc} << 8) | u64{ascq};
	}

	constexpr u64 atapi_incompatible_medium = make_atapi_sense(0x02, 0x05, 0x30, 0x00);

	// The medium staged for the optical drive on the dev_ps2disc mount point.
	enum class staged_disc
	{
		none,
		ps1, // SYSTEM.CNF with a BOOT= line: always a CD
		ps2, // SYSTEM.CNF with a BOOT2= line: DVD for the vast majority of titles
	};

	// SYSTEM.CNF at the root of the disc is the definitive marker for both formats, and its
	// BOOT/BOOT2 key tells PS1 from PS2 apart. Read through the same helper the dev_bdvd fallback
	// in sys_fs uses, so the mount point and the drive never disagree about what is staged.
	staged_disc get_staged_disc()
	{
		const std::string key = get_dev_ps2disc_boot_key();

		if (key == "BOOT2")
		{
			return staged_disc::ps2;
		}

		return (key == "BOOT") ? staged_disc::ps1 : staged_disc::none;
	}

	// How much data the staged medium holds, in 2048-byte user sectors, or zero when that cannot be
	// measured. Measured from the disc contents, not from fs::statfs: when dev_ps2disc points at a
	// host folder statfs answers with the size of the drive that folder lives on, which has nothing
	// to do with the disc.
	//
	// fs::get_dir_size answers umax when it cannot walk the folder, which happens when the medium
	// goes away between being recognized and being measured. Passing that on would describe a disc
	// of 0x1FFFFFFFFFFFFF sectors, so report nothing instead - a folder holding a SYSTEM.CNF never
	// measures zero on its own, which leaves zero to mean "unknown" for the callers.
	u64 get_staged_disc_sectors()
	{
		constexpr u64 sector_size = 2048;

		const u64 size = fs::get_dir_size(get_dev_ps2disc_path(), sector_size);

		return (size == umax) ? 0 : size / sector_size;
	}

	// The profile to announce for the staged medium. A drive reports what the medium physically
	// is, and PS2 titles shipped on both CD and DVD, so the two capacities have to be told apart:
	// a CD-ROM cannot hold more than 99 minutes of data, which is 360000 sectors, so anything
	// past that is a DVD.
	//
	// A plain CD-ROM profile describes a PS1 disc just as truthfully, but the firmware has no
	// content based detection for a PlayStation 1 game: the CD branch of the classifier (vsh.elf
	// 0x520ab8) can only ever answer CDDA or a data CD type, and the promoter that then scans a
	// data CD is an AVCHD scanner (x3_mdimp1 0x15e0, which walks "" and "/PRIVATE" looking for
	// BDMV/INDEX.BDM). The only thing that makes a medium a PlayStation disc is the profile.
	//
	// Which profile, though, is not the one the classifier names after the format. The metadata
	// layer does not work in the classifier's media types: it translates them through a table of
	// its own before anything else sees them (mms.prx 0xaf0e8, searched by 0x7635c on the key at
	// each 0x18 byte entry's +0 and answering with its +0xc), and across the PlayStation formats
	// that translation is a reversal:
	//
	//     classifier 1 PS3_BD  -> 5      classifier 4 PS2_CD -> 2
	//     classifier 2 PS3_DVD -> 4      classifier 5 PS1_CD -> 1
	//     classifier 3 PS2_DVD -> 3
	//
	// The promoter switches on the translated value (x3_mdimp1 0x48a4, and identically the mini
	// importer at mms_minimdimp_media_gamedisc 0x1b94), and its case names belong to that second
	// enumeration: case 3 MMS_MEDIA_TYPE_PS2_DVD, case 4 MMS_MEDIA_TYPE_PS2_CD, case 5
	// MMS_MEDIA_TYPE_PS1_CD. Cases 1 and 2 are the PlayStation 3 ones, and they only stat
	// /dev_bdvd/PS3_GAME before giving up.
	//
	// So a medium arrives at the promoter one step removed from the profile it was announced with,
	// and the PS2 disc has always relied on that: announced 0xFF60 the classifier calls it PS3_DVD,
	// the translation turns that into 4 and the promoter builds a PS2 CD out of it. Announcing the
	// same disc as 0xFF70, the classifier's own PS2_CD, translates to 2 and loses it - which is
	// exactly what happened the one time that was tried. By the same route the promoter's PS1_CD
	// case is reached by a medium the classifier calls PS3_BD, so a PS1 disc is announced 0xFF50.
	u32 get_staged_profile(staged_disc staged, u64 sectors)
	{
		constexpr u64 max_cd_sectors = 99 * 60 * 75;

		if (staged == staged_disc::ps1)
		{
			return ps_profile_ps3_bd;
		}

		return (sectors > max_cd_sectors) ? ps_profile_ps_dvd : ps_profile_ps_cd;
	}

	// Enough of the medium to tell one disc from another without reading it. Presence alone would
	// miss a disc swapped between two polls, so the root directory's timestamp comes along:
	// optical media take it from the volume, so it differs from disc to disc, and asking for it
	// costs one stat instead of the directory walk a content check would need.
	struct medium_signature
	{
		bool present = false;
		s64 timestamp = 0;

		bool operator==(const medium_signature&) const = default;
	};

	// Watches the same folder the medium itself is read from, so what it reports and what
	// get_staged_disc concludes always describe one disc.
	medium_signature get_medium_signature()
	{
		const std::string path = get_dev_ps2disc_path();
		fs::stat_t info{};

		if (path.empty() || !fs::get_stat(path, info) || !info.is_directory)
		{
			return {};
		}

		return {true, info.mtime};
	}

#ifdef _WIN32
	// The sense buffer has to live in the same allocation as the request: the driver is handed one
	// block and told at which offset inside it the sense data begins.
	struct atapi_pass_through
	{
		SCSI_PASS_THROUGH_DIRECT request;
		u8 sense[32];
	};
#endif

	// Putting an ATAPI packet to the drive the medium is really in. lv1 answers a storage device
	// command by handing the packet to the BD drive, so where the tray holds a real disc in a real
	// drive, the truthful answer to a command is the one that drive gives.
	//
	// Nothing else can answer the command a PlayStation 1 disc is read with. Its emulator asks for
	// raw CD sectors - READ CD, with the sync pattern, both headers, the user data and the error
	// correction alongside the formatted Q subchannel - and a filesystem mounted over a disc only
	// ever exposes the user data sitting inside those sectors.
	//
	// Only what the answers below do not cover is ever put to it. What they cover is what a drive
	// that is not Sony's gets wrong, and asking one was how that was established: holding this very
	// disc it answers GET CONFIGURATION with profile 0x0008, a plain CD-ROM, where the firmware is
	// looking for one of the reserved PlayStation profiles; it answers the 0xFF40 PlayStation medium
	// feature with a header and no feature at all; and it turns down READ DISC STRUCTURE and REPORT
	// KEY outright, sense key 5 with ASC 0x30/0x02, incompatible medium. Two of the three answer,
	// which is worse than a refusal, because an answer is believed.
	class optical_drive
	{
	public:
		optical_drive() = default;
		optical_drive(const optical_drive&) = delete;
		int operator=(const optical_drive&) = delete;

		~optical_drive()
		{
			close();
		}

		// True when a drive answered. False means the packet never reached one, which is not the
		// same as a drive turning it down: a refusal is an answer, and comes back as sense data.
		//
		// How many bytes the drive put in the buffer is reported through transferred, which is not
		// the same as how many were asked for: a command answers with what it has. A drive writes
		// the bytes it transfers and no others, so the rest of the buffer is not the drive's to
		// speak for.
		bool send_atapi_command([[maybe_unused]] const u8* cdb, [[maybe_unused]] u32 cdb_size, [[maybe_unused]] u8* buffer, [[maybe_unused]] u32 buffer_size, u32& transferred)
		{
			transferred = 0;

			std::lock_guard lock(mutex);

#ifdef _WIN32
			if (!open())
			{
				return false;
			}

			atapi_pass_through packet{};

			packet.request.Length             = static_cast<u16>(sizeof(SCSI_PASS_THROUGH_DIRECT));
			packet.request.CdbLength          = static_cast<u8>(std::min<u32>(cdb_size, static_cast<u32>(sizeof(packet.request.Cdb))));
			packet.request.SenseInfoLength    = static_cast<u8>(sizeof(packet.sense));
			packet.request.SenseInfoOffset    = static_cast<u32>(offsetof(atapi_pass_through, sense));
			packet.request.DataIn             = buffer_size ? SCSI_IOCTL_DATA_IN : SCSI_IOCTL_DATA_UNSPECIFIED;
			packet.request.DataTransferLength = buffer_size;
			packet.request.DataBuffer         = buffer_size ? buffer : nullptr;

			// Seconds, and a bound rather than a figure from the console: it is here so that a drive
			// that stops answering does not hold the guest thread forever. One sector read off this
			// disc takes 3.3 ms, and 71 ms when the head has to move, both measured over a boot, so
			// ten seconds is far past anything a working drive does and still short of a hang.
			packet.request.TimeOutValue       = 10;

			std::memcpy(packet.request.Cdb, cdb, packet.request.CdbLength);

			DWORD returned = 0;

			if (!DeviceIoControl(handle, IOCTL_SCSI_PASS_THROUGH_DIRECT, &packet, static_cast<DWORD>(sizeof(packet)), &packet, static_cast<DWORD>(sizeof(packet)), &returned, nullptr))
			{
				// Losing the drive is how an ejected or swapped medium reaches this far. Let go of
				// the handle so the next command opens whatever the tray holds by then.
				sys_storage.warning("optical_drive: ATAPI opcode 0x%02x could not be sent (error 0x%x)", cdb[0], +GetLastError());
				close();
				return false;
			}

			// Updated by the driver to what the drive actually put across.
			transferred = std::min<u32>(packet.request.DataTransferLength, buffer_size);

			if (packet.request.ScsiStatus)
			{
				// The drive answered and its answer is a refusal, which is a truthful answer about
				// the disc. The caller passes on the empty buffer that comes with it.
				sys_storage.notice("optical_drive: ATAPI opcode 0x%02x refused (status 0x%02x, sense key 0x%x, asc 0x%02x/0x%02x)",
					cdb[0], packet.request.ScsiStatus, packet.sense[2] & 0xF, packet.sense[12], packet.sense[13]);
			}

			return true;
#else
			// Windows only for the time being. Elsewhere the medium is reached through the mount
			// point rather than the device behind it, and finding that device is its own work.
			return false;
#endif
		}

		// Let go of the drive. Called when the tray is read again, so a swapped medium is never
		// answered for through a handle opened against the one before it.
		void reset()
		{
			std::lock_guard lock(mutex);

			close();
			unavailable = false;
		}

	private:
#ifdef _WIN32
		// Opens the volume the medium is mounted as. Called with the mutex held.
		bool open()
		{
			if (handle != INVALID_HANDLE_VALUE)
			{
				return true;
			}

			if (unavailable)
			{
				return false;
			}

			// "D:/" mounted over the disc is reached as "\\.\D:", which is how the filesystem is
			// talked past to the drive holding it.
			//
			// Only an optical one. A folder standing in for a disc has no ATAPI bus to ask, and one
			// sitting on a fixed disk would otherwise be read as its letter and aim these packets at
			// somebody's hard drive, which is not where a command meant for a CD belongs.
			const std::string path = get_dev_ps2disc_path();

			if (path.size() < 2 || path[1] != ':')
			{
				unavailable = true;
				return false;
			}

			const std::string root = path.substr(0, 2) + "\\";

			if (GetDriveTypeA(root.c_str()) != DRIVE_CDROM)
			{
				sys_storage.notice("optical_drive: '%s' is not an optical drive, answering from the medium alone", root);
				unavailable = true;
				return false;
			}

			const std::string device = "\\\\.\\" + path.substr(0, 2);

			handle = CreateFileA(device.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

			if (handle == INVALID_HANDLE_VALUE)
			{
				// Read and write rights are what the pass through interface asks for even to read.
				// Said once rather than once for every sector the guest goes on to ask for.
				sys_storage.warning("optical_drive: cannot open '%s' (error 0x%x)", device, +GetLastError());
				unavailable = true;
				return false;
			}

			sys_storage.notice("optical_drive: sending ATAPI packets to '%s'", device);
			return true;
		}

		void close()
		{
			if (handle != INVALID_HANDLE_VALUE)
			{
				CloseHandle(handle);
				handle = INVALID_HANDLE_VALUE;
			}
		}

		HANDLE handle = INVALID_HANDLE_VALUE;
#else
		// There is no handle to let go of where no drive is ever opened, but the destructor and
		// reset still ask, so the question stays answerable on every platform.
		void close()
		{
		}
#endif

		// Set once opening has failed, so a mount point with no drive behind it is reported once
		// instead of once per command. Cleared along with the handle when the tray is read again.
		bool unavailable = false;

		shared_mutex mutex;
	};

	struct storage_manager_impl
	{
		storage_manager_impl(const storage_manager_impl&) = delete;
		int operator=(const storage_manager_impl&) = delete;

		// What the tray holds, with the geometry and profile that follow from it. Resolved together
		// whenever the medium changes rather than on demand: both readings measure the disc, which
		// on a physical drive means walking its directories, and the VSH asks for them on nearly
		// every device command. Device commands are served on guest threads, so these are read
		// from threads other than the one that maintains them.
		atomic_t<staged_disc> staged{staged_disc::none};
		atomic_t<u64> sectors = 0;
		atomic_t<u32> profile = 0;

		storage_manager_impl() = default;

		// The drive the medium is read through. Owned here because this is what follows the tray: a
		// handle opened against one disc has no business answering about the next.
		optical_drive drive;

		// Reads the tray. Called only by the thread that owns this object; everything else reads
		// what it leaves behind - never from the constructor, which runs on whichever guest thread
		// first asks for this object from inside a syscall, and measuring a disc means walking
		// every directory on it. What it publishes last is staged, because that is what every
		// reader tests before it trusts the other two.
		void resolve_medium()
		{
			const staged_disc medium = get_staged_disc();
			const u64 size = (medium == staged_disc::none) ? 0 : get_staged_disc_sectors();

			drive.reset();

			sectors = size;
			profile = (medium == staged_disc::none) ? 0 : get_staged_profile(medium, size);
			staged = medium;
		}

		// Set once the guest has re-registered its medium event port against an opened drive
		// handle, which is the point at which it can actually service a medium event.
		atomic_t<bool> drive_ready = false;

		void send_event(u64 device_id, u64 data1, u64 data2, u64 data3)
		{
			id_manager::g_process = 0;
			std::vector<shared_ptr<lv2_storage_medium_event_port>> ports;

			idm::select<lv2_storage_medium_event_port>([&](u32 id, u32 proc, lv2_storage_medium_event_port& port)
			{
				// Check port status
				if (port.savable() && (!port.device_id || port.device_id == device_id))
				{
					// Detached ports can be removed
					ports.emplace_back(ensure(idm::get_unlocked<lv2_storage_medium_event_port>(idm::id_index(id, proc))));
				}
			});

			u64 dummy_kernel_port_address = 0x800000000062d4c0;

			for (auto& port : ports)
			{
				dummy_kernel_port_address += 0x100;

				port->medium_port->send(dummy_kernel_port_address, data1, data2, data3);
			}
		}

		void announce_medium()
		{
			const staged_disc medium = staged.load();

			if (medium == staged_disc::none)
			{
				// Nothing on dev_ps2disc, so this is a PlayStation 3 medium or an empty tray:
				// Eladash's original sequence, minus the 0x101 wake-up that is sent at startup.
				// Its 0xFF71 lands on the right branch for the same reason the values chosen in
				// get_staged_profile do - the classifier reads it as PS1_CD, and the metadata
				// layer's table turns that into its own 1, which is the promoter's PlayStation 3
				// case.
				// The pauses are what space the sequence out for the firmware, and an aborting
				// thread returns from them at once, so the abort has to be tested between the
				// events as well: without that the whole sequence fires back to back into a guest
				// that is being torn down.
				constexpr u64 events[][2] =
				{
					{0x000000000000ff71, 0x0101000000000006},
					{0, 0x0101000000000004},
					{0, 0x0101000000000008},
					{0x000000000000ff71, 0x0101000000000003},
				};

				for (const auto& event : events)
				{
					if (thread_ctrl::state() == thread_state::aborting)
					{
						return;
					}

					send_event(0x0101000000000006, 0x0000000000000003, event[0], event[1]);
					thread_ctrl::wait_for(2500000);
				}

				return;
			}

			// data2 of a medium event is the drive's current profile, handed straight to the VSH's
			// media classifier (vsh.elf 0x518af8 -> 0x5209b4). Announcing the PlayStation profile of
			// the staged disc is what takes _MediaDetect down the PS1/PS2 branch, where it reads
			// /dev_ps2disc/SYSTEM.CNF for the title id (vsh.elf 0x518eb4 -> 0x517260) instead of
			// treating the medium as a Blu-ray.
			const u32 announced = profile.load();

			sys_storage.notice("storage_manager(): announcing profile 0x%x for the staged %s disc", announced, (medium == staged_disc::ps1) ? "PS1" : "PS2");
			send_event(0x0101000000000006, 0x0000000000000003, announced, 0x0101000000000006);
		}

		void operator()() noexcept
		{
			// Read the tray here rather than in the constructor: this thread has all the time it
			// needs before the first event goes out, and nothing can observe the result until it
			// does.
			resolve_medium();

			while (Emu.IsPausedOrReady())
			{
				thread_ctrl::wait_for(2500);
			}

			// Give the VSH a moment to reach the point where x3::_BDInitialize has registered its
			// bootstrap medium event port, otherwise the wake-up below reaches nobody.
			for (u32 i = 0; i < 5 && thread_ctrl::state() != thread_state::aborting; i++)
			{
				thread_ctrl::wait_for(1000 * 1000);
			}

			// The first event of the sequence is the wake-up: it is what makes x3::_PollingService
			// open the drive and re-register its medium event port against a real storage handle.
			// Only after that does x3::_MediaDetect have a usable drive object, so wait for the
			// re-registration before announcing anything about the medium itself.
			send_event(0x0101000000000006, 0x0000000000000101, 0x0000000000000000, 0x0101000000000006);

			for (u32 i = 0; i < 30 * 1000 / 25 && !drive_ready && thread_ctrl::state() != thread_state::aborting; i++)
			{
				thread_ctrl::wait_for(25000);
			}

			if (drive_ready)
			{
				sys_storage.notice("storage_manager(): the guest opened the optical drive, announcing the medium");
			}
			else
			{
				sys_storage.warning("storage_manager(): the guest never opened the optical drive, announcing the medium anyway");
			}

			// Let the drive setup that follows that registration settle.
			thread_ctrl::wait_for(2500000);

			// A medium that is already there when the VSH boots is the tray having been loaded
			// before the console was turned on, so announce it once without waiting for a change.
			// This one goes out whatever the signature says, because a PS3 disc can also be a
			// folder configured for dev_bdvd alone, which the signature below cannot see.
			medium_signature current = get_medium_signature();

			announce_medium();

			// From here on follow the drive. The two halves the firmware understands are separate:
			// event 3 carries a medium's profile and event 4 says the tray is empty, while 0x101
			// and 0x102 are the drive itself arriving and going away (vsh.elf 0x519dd0). Only the
			// medium ones belong here - tearing the device down on every disc change would take
			// the drive with it (0x519fc8 -> 0x518834).
			while (thread_ctrl::state() != thread_state::aborting)
			{
				thread_ctrl::wait_for(1000000);

				const medium_signature sampled = get_medium_signature();

				if (sampled == current)
				{
					continue;
				}

				// Read the tray before reporting anything about it. This also matters when the
				// medium only went away: everything answered for the drive, its profile and its
				// geometry, has to stop describing a disc that is no longer in it.
				resolve_medium();

				// A disc swapped for another is both halves in turn, so neither is an else.
				//
				// The event is all that is reported for a tray that went empty: the firmware takes
				// medium state 5 from it alone (vsh.elf 0x519f30), while the drive itself carries
				// on answering device commands out of the captured PS3 BD-ROM table, which
				// describes a disc that is present. Answering those commands as an empty drive
				// would mean inventing a response set that nothing here has ever captured.
				if (current.present)
				{
					sys_storage.notice("storage_manager(): the medium was removed, reporting an empty tray");
					send_event(0x0101000000000006, 0x0000000000000004, 0x0000000000000000, 0x0101000000000006);
					thread_ctrl::wait_for(2500000);
				}

				if (sampled.present)
				{
					sys_storage.notice("storage_manager(): a medium was inserted, announcing it");
					announce_medium();
				}

				current = sampled;
			}
		}

		static constexpr auto thread_name = "VSH Storage Events"sv;
	};

	using storage_manager = named_thread<storage_manager_impl>;
}

lv2_storage::lv2_storage(utils::serial& ar) noexcept
	: lv2_obj{1}
	, device_id(ar)
	, mode(ar)
	, flags(ar)
{
	lv2_event_queue::load_ptr(ar, async_port, "lv2_storage");}

void lv2_storage::save(utils::serial& ar)
{
	ar(device_id, mode, flags);
	lv2_event_queue::save_ptr(ar, async_port.load().get());
}

lv2_storage_medium_event_port::lv2_storage_medium_event_port(utils::serial& ar) noexcept
	: device_id(ar)
{
	lv2_event_queue::load_ptr(ar, medium_port, "lv2_storage_medium_event_port");
}

void lv2_storage_medium_event_port::save(utils::serial& ar)
{
	ar(device_id);
	lv2_event_queue::save_ptr(ar, medium_port.get());
}

bool lv2_storage_medium_event_port::savable() const
{
	return lv2_obj::check(medium_port);
}

void sys_storage_stage_boot_medium()
{
	// Asking for the manager is what creates it, and creating it starts the thread that follows the
	// tray. That thread reads the medium as its first act, but the boot carries on without waiting
	// for it, so read the tray here as well: this runs before there is a guest to observe either
	// result, and both readings describe the same disc.
	auto& manager = g_fxo->get<storage_manager>();

	manager.resolve_medium();
}

error_code sys_storage_open(ppu_thread& ppu, u64 device, u64 mode, vm::ptr<u32> fd, u64 flags)
{
	sys_storage.todo("sys_storage_open(device=0x%x, mode=0x%x, fd=*0x%x, flags=0x%x)", device, mode, fd, flags);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	if (device == 0)
	{
		return CELL_ENOENT;
	}

	if (!fd)
	{
		return CELL_EFAULT;
	}

	[[maybe_unused]] u64 storage_id = device & 0xFFFFF00FFFFFFFF;
	fs::file file;

	thread_local u32 weird = 0;

	// if (device == 0x0101000000000006)
	// {
	// 	if (weird < 1)
	// 	{
	// 		weird++;
	// 		return CELL_ENOEXEC;
	// 	}
	// }

	if (const u32 id = idm::make<lv2_obj, lv2_storage>(device, std::move(file), mode, flags))
	{
		*fd = id;
		sys_storage.notice("sys_storage_open(): Handle=0x%x", id);
		return CELL_OK;
	}

	return CELL_EAGAIN;
}

error_code sys_storage_close(u32 fd)
{
	sys_storage.todo("sys_storage_close(fd=0x%x)", fd);

	ensure(idm::remove<lv2_obj, lv2_storage>(fd));

	return CELL_OK;
}

error_code sys_storage_read(u32 fd, u32 mode, u32 start_sector, u32 num_sectors, vm::ptr<void> bounce_buf, vm::ptr<u32> sectors_read, u64 flags)
{
	log_callback(*cpu_thread::get_current<ppu_thread>());
	sys_storage.todo("sys_storage_read(fd=0x%x, mode=0x%x, start_sector=0x%x, num_sectors=0x%x, bounce_buf=*0x%x, sectors_read=*0x%x, flags=0x%x)", fd, mode, start_sector, num_sectors, bounce_buf, sectors_read, flags);

	if (!bounce_buf || !sectors_read)
	{
		return CELL_EFAULT;
	}

	std::memset(bounce_buf.get_ptr(), 0, num_sectors * 0x200ull);
	const auto handle = idm::get_unlocked<lv2_obj, lv2_storage>(fd);

	if (!handle)
	{
		return CELL_ESRCH;
	}

	if (handle->file)
	{
		handle->file.seek(start_sector * 0x200ull);
		const u64 size = num_sectors * 0x200ull;
		const u64 result = lv2_file::op_read(handle->file, bounce_buf, size);
		num_sectors = ::narrow<u32>(result / 0x200ull);
	}

	*sectors_read = num_sectors;

	return CELL_OK;
}

error_code sys_storage_write(u32 fd, u32 mode, u32 start_sector, u32 num_sectors, vm::ptr<void> data, vm::ptr<u32> sectors_wrote, u64 flags)
{
	sys_storage.todo("sys_storage_write(fd=0x%x, mode=0x%x, start_sector=0x%x, num_sectors=0x%x, data=*=0x%x, sectors_wrote=*0x%x, flags=0x%llx)", fd, mode, start_sector, num_sectors, data, sectors_wrote, flags);

	if (!sectors_wrote)
	{
		return CELL_EFAULT;
	}

	const auto handle = idm::get_unlocked<lv2_obj, lv2_storage>(fd);

	if (!handle)
	{
		return CELL_ESRCH;
	}

	*sectors_wrote = num_sectors;

	return CELL_OK;
}

error_code sys_storage_async_configure(u32 fd, u32 io_buf, u32 equeue_id, u32 unk)
{
	sys_storage.todo("sys_storage_async_configure(fd=0x%x, io_buf=0x%x, equeue_id=0x%x, unk=*0x%x)", fd, io_buf, equeue_id, unk);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	const auto handle = idm::get_unlocked<lv2_obj, lv2_storage>(fd);

	if (!handle)
	{
		return CELL_ESRCH;
	}

	if (auto queue = idm::get_unlocked<lv2_obj, lv2_event_queue>(equeue_id))
	{
		handle->async_port.store(queue);
	}
	else
	{
		return CELL_ESRCH;
	}

	return CELL_OK;
}

// What a device command is answered with does not depend on which syscall carried it. lv1 puts the
// same packet to the same drive either way, and the only thing the asynchronous entry point adds is
// the completion event it posts afterwards, so both of them come through here.
//
// Which is what a PlayStation 1 disc depends on. ps1_emu reaches the drive from xcdrom.cc, through
// its _xcd_reader_thread and _xcdrom_thread, and every one of those calls takes the synchronous
// syscall: one boot of a disc put 109 commands through it and none through the asynchronous one,
// which is the path the VSH uses. They ask the same ATAPI questions about the same disc.
//
// The event data a command produces belongs to the command rather than to the transport, so it is
// returned here and posted by the caller that has somewhere to post it.
//
// What is logged here says this function rather than either syscall, because either one of them
// may be the caller and a line that names the wrong one is worse than one that names neither.
struct storage_command_response
{
	u64 event_data2 = 0;
	u64 event_data3 = 0;
};

static storage_command_response storage_device_command(u64 cmd, vm::ptr<void> in, u64 inlen, vm::ptr<void> out, u64 outlen)
{
	sys_storage.todo("storage_device_command(): BUF: %s", std::span<u8>(vm::get_super_ptr(in.addr()), inlen));

	// try_get rather than get: the manager is a named_thread, and starting the medium event thread
	// is the asynchronous entry point's business, not something a command should do by arriving
	// first. Nothing staged reads the same as an empty tray, which is the truth until it has run.
	const auto manager = g_fxo->try_get<storage_manager>();

	std::vector<u8> data_in(inlen);

	if (inlen && !vm::try_access(in.addr(), data_in.data(), inlen, false))
	{
		fmt::throw_exception("Failed to read input data!");
	}

	std::memset(out.get_ptr(), 0, outlen);

	struct input_output
	{
		u32 ID; // So we can identify the command later and fill response_base accordingly
		std::vector<u8> data_in; // Data input (masked)
		std::vector<u8> data_mask; // Input mask
		std::vector<u8> response_base; // Dat to be memcpy'ed to output, prior to possibly doing more modifications
		u64 response_event_data2; // Event data sent
		u64 response_event_data3; // Event data sent
	};

	static const std::vector<input_output> inputs_outputs
	{
		input_output
		{
			1, 
			std::vector<u8> // input
			{
				0x51, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x22, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x0C,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x23,
				0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // input mask
			{
				0xFF, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0xFF, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // output base
			{
				0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00
			},
			0x8000000002050000, 0,
		},

		input_output
		{
			2, 
			std::vector<u8> // input
			{
				0xA4, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0xE0,
		 		0x00, 0x08, 0x03, 0x00,
		 		0x00, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0x00,
		 		0x00, 0x00, 0x00, 0x0C,
		 		0x00, 0x00, 0x00, 0x01,
		 		0x00, 0x00, 0x00, 0x08,
		 		0x00, 0x00, 0x00, 0x03,
		 		0x00, 0x00, 0x00, 0x01,
		 		0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // input mask
			{
				0xFF, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0xFF, 0xFF, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // output base
			{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			0, 0,
		},

		input_output
		{
			3,
			std::vector<u8> // input
			{
				0xAD, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x73, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x0C,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x73,
				0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // input mask
			{
				0xFF, 0xFF, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0xFF, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,//
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0xFF,
				0x00, 0x00, 0x00, 0x00
			},
			std::vector<u8> // outout base
			{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			    0x00, 0x00, 0x00,
			},
			0, 0
		}
	};

	std::vector<u8> data_for_comparison;

	u32 found_ID = umax;
	u64 response_event_data2 = 0;
	u64 response_event_data3 = 0;

	for (const input_output& info : inputs_outputs)
	{
		if (data_in.size() != info.data_in.size())
		{
			continue;
		}

		data_for_comparison.resize(data_in.size());
		std::memcpy(data_for_comparison.data(), data_in.data(), data_in.size());

		for (u32 index = 0; index < data_for_comparison.size(); index++)
		{
			data_for_comparison[index] &= info.data_mask[index];
		}

		if (data_for_comparison == data_in)
		{
			if (info.response_base.size() != outlen)
			{
				// A known opcode issued with an unexpected allocation length. Answer with an empty
				// buffer instead of aborting the emulator: non-PS3 media make the VSH use command
				// variants that the reverse engineered PS3 BD-ROM table does not cover.
				sys_storage.warning("storage_device_command(): command ID=%d expects a 0x%x byte response, guest asked for 0x%x", info.ID, info.response_base.size(), outlen);
				continue;
			}

			found_ID = info.ID;
			response_event_data2 = info.response_event_data2;
			response_event_data3 = info.response_event_data3;
			ensure(vm::try_access(out.addr(), const_cast<u8*>(info.response_base.data()), outlen, true));
		}
	}

	// The captured response table above describes a PS3 BD-ROM, so on its own the VSH's
	// _MediaDetect always concludes "Blu-ray" and never probes the PS1/PS2 path. When a PS1/PS2
	// disc is staged on dev_ps2disc instead, answer the standard MMC probe commands the way a
	// real drive holding a CD/DVD would, so the VSH classifies the medium correctly.
	// One reading of the tray for the whole command. The thread that follows the drive can resolve
	// a different medium at any point, and a drive answers a command about the disc it began it
	// with rather than half about one disc and half about the next.
	const staged_disc staged = manager ? manager->staged.load() : staged_disc::none;
	const u32 staged_profile = manager ? manager->profile.load() : 0;
	const u64 staged_sectors = manager ? manager->sectors.load() : 0;

	const u8 opcode = (cmd == 1 && data_in.size() >= atapi_cmnd_size) ? data_in[atapi_cdb_offset] : 0xFF;
	bool answered_as_cd_dvd = false;

	// Handing the packet the guest wrote to the drive the medium is really in, and passing back what
	// comes out. False means no drive answered it, and the caller falls back to the answers worked
	// out below.
	//
	// Reads, and commands that carry no data at all: telling a drive it is about to be read from is
	// part of reading it. A write stays out - nothing a disc is read through needs one, and letting
	// one reach somebody's drive is not a thing to do by accident. Read off the packets ps1_emu
	// sends: READ CD, GET EVENT STATUS, READ DISC INFORMATION and READ TOC all arrive as protocol 3
	// with direction 1, DMA and read, while SET CD SPEED arrives as protocol 0, no data at all.
	const auto ask_the_drive = [&]() -> bool
	{
		if (cmd != 1 || !manager || staged == staged_disc::none || data_in.size() < atapi_cmnd_size)
		{
			return false;
		}

		// The protocol and direction fields are big-endian u32, so the value sits in the last byte.
		if (data_in[atapi_proto + 3] != 0 && data_in[atapi_in_out + 3] != 1)
		{
			return false;
		}

		const u32 cdb_size = data_in[atapi_pktlen + 3];

		if (!cdb_size)
		{
			return false;
		}

		std::vector<u8> answer(outlen);
		u32 transferred = 0;

		if (!manager->drive.send_atapi_command(data_in.data() + atapi_cdb_offset, cdb_size, answer.data(), static_cast<u32>(outlen), transferred))
		{
			return false;
		}

		// Only as far as the drive answered. What it did not write is not its to write, and the
		// buffer was zeroed above, so what the guest reads past that point is what lv2 left rather
		// than something this made up.
		if (transferred)
		{
			ensure(vm::try_access(out.addr(), answer.data(), transferred, true));
		}

		return true;
	};

	// What the medium's own layout is, as opposed to what kind of medium the firmware should believe
	// it is. A drive holding the disc knows where its tracks and its lead out actually sit, and the
	// emulator reading the disc needs that: the table of contents answered below is built out of the
	// size of the files on the medium, which is not its geometry.
	//
	// Measured, not assumed. Answering READ TOC from the files puts the lead out at LBA 327165 and
	// the emulator never finds what it is looking for: it rereads LBA 0x04 to 0x1C without end, 1031
	// READ CD commands over 42 passes of the same 25 sectors, while the drive answers every one of
	// them. Asking the drive instead, the same disc reads its descriptors once, LBA 0x10 to 0x1D in
	// 23 commands, and goes on to what it found there.
	//
	// Everything else stays as it is answered below, because a drive that is not Sony's answers the
	// rest wrongly rather than not at all: profile 0x0008 for a medium the firmware needs a reserved
	// PlayStation profile for, and no 0xFF40 feature where it looks for one. See optical_drive.
	if ((opcode == mmc_read_toc || opcode == mmc_read_disc_information) && ask_the_drive())
	{
		// The drive answered, so the event reports the plain success every other answered command
		// reports rather than the sense the captured table would have paired with it.
		return storage_command_response{};
	}

	// Not an ATAPI packet: the drive's own "which profile is loaded" query. The VSH runs it twice
	// before it accepts a PS1/PS2 medium and rejects the disc when it answers 0 or -1.
	if (cmd == storage_cmd_get_profile && outlen >= sizeof(u32) && staged != staged_disc::none)
	{
		be_t<u32> profile{staged_profile};

		ensure(vm::try_access(out.addr(), &profile, sizeof(profile), true));
		found_ID = umax;
		answered_as_cd_dvd = true;
		response_event_data2 = 0;
		response_event_data3 = 0;

		sys_storage.notice("storage_device_command(): reporting profile 0x%x for the staged disc", profile);
	}

	if (cmd == 1 && staged != staged_disc::none)
	{
		std::vector<u8> response;

		switch (opcode)
		{
		case mmc_read_disc_structure:
		{
			// READ DISC STRUCTURE for BD media on a CD/DVD fails on real hardware with
			// CHECK CONDITION / ILLEGAL REQUEST / INCOMPATIBLE MEDIUM INSTALLED - the medium
			// simply has no Blu-ray structure to read - and refusing it is what makes the VSH
			// stop treating the medium as a Blu-ray.
			//
			// This holds for a PS1 CD too. The routine that probes a PS1_CD (vsh.elf 0x51fefc,
			// reached from the media type 5 branch at 0x518df4) issues exactly this command and
			// reads the high nibble of byte 0x10 of the answer; on a CD it gets the failure above
			// and returns 1, so the drive flag its caller would otherwise set stays clear and the
			// mount request goes out without the extra "-HDDCACHE" attribute (vsh.elf 0x54441c).
			// Letting Eladash's captured Blu-ray structure through instead would set that flag,
			// but only by telling the firmware a CD is a Blu-ray disc.
			if ((data_in[atapi_cdb_offset + 1] & 0xF) == mmc_disc_structure_media_bd)
			{
				// A failed command transfers nothing, so leave the guest buffer cleared. Written
				// through the same guarded path as every other answer here: the address comes from
				// the guest and may name no memory at all.
				if (outlen)
				{
					std::vector<u8> nothing(outlen);

					ensure(vm::try_access(out.addr(), nothing.data(), static_cast<u32>(outlen), true));
				}

				found_ID = umax;
				answered_as_cd_dvd = true;
				response_event_data2 = atapi_incompatible_medium;
				response_event_data3 = 0;
				sys_storage.notice("storage_device_command(): PS1/PS2 disc staged, refusing READ DISC STRUCTURE for BD media");
			}

			break;
		}
		case mmc_read_toc:
		{
			// READ TOC/PMA/ATIP, format 0 (MMC-5). The VSH asks for it while classifying a CD
			// (vsh.elf 0x52030c, CDB "43 00 00 00 00 00 00 <alloc>") and parses the answer at
			// 0x520628: bytes 0-1 are the TOC data length, byte 2 the first track and byte 3 the
			// last track, followed by eight byte descriptors. 0x5208a0 then hands the answer to
			// 0x520578, which walks those descriptors looking for the data bit in the ADR/Control
			// field, and that is how it tells a data disc from an audio one. A game disc is one
			// data track plus the lead out, and the first request only asks for the four byte
			// header.
			// A table of contents cannot be built without knowing where the lead out sits, and a
			// drive that cannot read one fails the command rather than answering a disc of no
			// length, so leave it to the captured table when the medium could not be measured.
			//
			// The addresses below are logical block addresses, which is what byte 1 bit 1 clear
			// asks for. The VSH only ever asks that way, and answering minutes, seconds and frames
			// as an LBA would misplace the lead out, so the MSF form is left to the captured table
			// rather than answered in the wrong units.
			if (staged_sectors && outlen >= 4 && !(data_in[atapi_cdb_offset + 1] & 0x02) && (data_in[atapi_cdb_offset + 2] & 0xF) == 0)
			{
				const be_t<u32> lead_out{static_cast<u32>(staged_sectors)};

				// The four byte header followed by the track 1 and lead out descriptors. The
				// length field counts everything after itself, so it is 18 while the structure
				// is 20 bytes long, and the VSH asks for exactly that 18 on its second pass -
				// answer whatever fits, the way a drive truncates to the allocation length.
				u8 toc[20]{};

				toc[1]  = 18;   // TOC data length: the two track numbers plus two descriptors
				toc[2]  = 1;    // first track
				toc[3]  = 1;    // last track
				toc[5]  = 0x14; // ADR 1, control 4: a data track
				toc[6]  = 1;    // track number, starting at LBA 0
				toc[13] = 0x14;
				toc[14] = 0xAA; // the lead out
				std::memcpy(&toc[16], &lead_out, sizeof(lead_out));

				response.resize(outlen);
				std::memcpy(response.data(), toc, std::min<usz>(outlen, sizeof(toc)));

				sys_storage.notice("storage_device_command(): reporting a single data track, lead out at LBA %d, %d of %d bytes", lead_out, std::min<usz>(outlen, sizeof(toc)), outlen);
			}

			break;
		}
		case mmc_read_disc_information:
		{
			// Standard Disc Information (MMC-5). Eladash's captured PS3 BD-ROM answer reports the
			// command as failed (CHECK CONDITION) and leaves byte 2 at 0xFF, which describes an
			// erasable, random-access medium - a BD-RE, not a pressed disc. A PS1/PS2 game disc is
			// a finalized read-only CD/DVD, so describe it as such and let the command succeed.
			if (outlen >= 34)
			{
				response.resize(outlen);
				response[1] = 0x20; // disc information length: 32
				response[2] = 0x0E; // erasable 0, last session complete (11b), disc status complete (10b)
				response[3] = 1;    // number of first track
				response[4] = 1;    // number of sessions (LSB)
				response[5] = 1;    // first track in last session (LSB)
				response[6] = 1;    // last track in last session (LSB)
				response[7] = 0x20; // URU: the medium may be read by any application
				response[8] = 0;    // disc type: CD-DA or CD-ROM

				// The disc type above is defined for CD media only, and the addresses that follow
				// it - last session lead in, last possible lead out - are left at zero rather than
				// made up. What a real drive answers here for a DVD is not captured anywhere, and
				// nothing observed so far reads either of them.

				sys_storage.notice("storage_device_command(): reporting a finalized read-only medium for the staged PS1/PS2 disc");
			}

			break;
		}
		case mmc_get_configuration:
		{
			// MMC-5 feature header: u32 data length, u16 reserved, u16 current profile. Report the
			// PlayStation profile of the medium, the same value the medium event and the profile
			// query carry - 0xFF50-0xFF71 sit in the vendor specific part of the MMC profile
			// space, which is what Sony allocated them from, and the VSH cross-checks the three
			// against each other.
			//
			// With RT=01b the request names one feature in CDB bytes 2-3 and the drive answers with
			// the header plus that feature's descriptor, or with the header alone when the feature
			// is not current. vsh.elf 0x51f8f4 asks for two of them in a row and its answer is what
			// the MMS metadata generator is told about the medium (0x521c58 -> 0x52f7a0, and it
			// refuses to go on to the profile query at 0x5201b0 unless this comes back 1):
			//
			//   0xFF40, a Sony vendor feature: accepted only as {code 0xFF40, additional length 4}
			//           whose data bytes 1 and 3 both read 1 (0x51f9ec - 0x51fa28). Present makes
			//           the query answer 1, absent makes it answer 2, which is the refusal.
			//   0x0080, MMC-5 Hybrid Disc: matched at 0x51fae0 and only decides the hybrid flag
			//           that 0x51fb4c stores at ctx+0x4c, so a plain PlayStation disc leaves the
			//           feature out and is reported as non hybrid.
			if (outlen >= 8)
			{
				const u16 feature = static_cast<u16>((data_in[atapi_cdb_offset + 2] << 8) | data_in[atapi_cdb_offset + 3]);
				const u8 request_type = data_in[atapi_cdb_offset + 1] & 3;
				const bool wants_playstation_feature = request_type == 1 && feature == mmc_feature_playstation_medium;

				response.resize(outlen);
				response[3] = 4; // data length, big endian: the header alone
				response[6] = static_cast<u8>(staged_profile >> 8);
				response[7] = static_cast<u8>(staged_profile & 0xFF);

				if (wants_playstation_feature && outlen >= 16)
				{
					response[3]  = 12;   // header plus one 8 byte descriptor
					response[8]  = static_cast<u8>(mmc_feature_playstation_medium >> 8);
					response[9]  = static_cast<u8>(mmc_feature_playstation_medium & 0xFF);
					response[10] = 1;    // version 0, not persistent, current
					response[11] = 4;    // additional length
					response[13] = 1;
					response[15] = 1;

					sys_storage.notice("storage_device_command(): reporting the PlayStation medium feature 0x%04x for the staged %s disc", feature, (staged == staged_disc::ps1) ? "PS1" : "PS2");
					break;
				}

				sys_storage.notice("storage_device_command(): reporting current profile 0x%04x for the staged %s disc (RT %d, feature 0x%04x)", staged_profile, (staged == staged_disc::ps1) ? "PS1" : "PS2", request_type, feature);
			}

			break;
		}
		case mmc_report_key:
		{
			// Vendor key class 0xE0 / key format 3: what kind of medium the drive holds, in the
			// last byte of the 8 byte answer - the routine at vsh.elf 0x51f244 issues the command
			// and takes that byte at 0x51f334. Eladash's captured table answers this one with
			// zeros, which reads as "not a PlayStation disc" and makes the VSH refuse every
			// PlayStation disc path outright.
			//
			// The answer has to agree with the profile: the VSH refuses as contradictory any
			// medium whose profile says plain CD/DVD/BD while this byte claims a PlayStation
			// generation (vsh.elf 0x518bbc), and it does so by publishing medium state 4,
			// unsupported media. Only a medium announced with one of the reserved PlayStation
			// profiles reports a generation here.
			//
			// Only the two profiles a PS2 disc is announced with report a generation. A PS1 disc
			// goes out as 0xFF50, which the classifier calls PS3_BD, and 0x518c44 refuses a medium
			// of that type that claims generation 2 or 3, so it has to answer 0.
			if (outlen == 8 && data_in[atapi_cdb_offset + 7] == 0xE0 && (data_in[atapi_cdb_offset + 10] & 0x3F) == 3)
			{
				const bool playstation_2_medium = staged_profile == ps_profile_ps_cd || staged_profile == ps_profile_ps_dvd;

				response.resize(outlen);
				response[7] = playstation_2_medium ? ps_disc_generation_ps2 : ps_disc_generation_none;

				sys_storage.notice("storage_device_command(): reporting PlayStation generation %d to REPORT KEY", response[7]);
			}

			break;
		}
		case mmc_get_event_status_notify:
		{
			// Media event class (requested through the notification class bitmask in CDB byte 4,
			// bit 4). Report a present, unchanged medium so the VSH keeps the drive as loaded.
			if (outlen >= 8 && (data_in[atapi_cdb_offset + 4] & 0x10))
			{
				response.resize(outlen);
				response[1] = 6;    // event descriptor length
				response[2] = 4;    // notification class: media
				response[3] = 0x10; // supported event classes: media
				response[4] = 0;    // event code: no change
				response[5] = 0x02; // media status: media present, tray closed

				sys_storage.notice("storage_device_command(): reporting media present for the staged PS1/PS2 disc");
			}

			break;
		}
		default: break;
		}

		if (!response.empty())
		{
			found_ID = umax;
			answered_as_cd_dvd = true;
			response_event_data2 = 0;
			response_event_data3 = 0;
			ensure(vm::try_access(out.addr(), response.data(), static_cast<u32>(outlen), true));
		}
	}

	if (found_ID == umax && !answered_as_cd_dvd)
	{
		// Nothing above knows this command. If the medium is a real disc in a real drive then the
		// drive does, so let it answer. This is the path READ CD takes, and with it every sector a
		// PlayStation 1 disc is read through.
		if (ask_the_drive())
		{
			return storage_command_response{};
		}

		// Log the opcode of everything the response table does not cover. This is what tells us
		// which command variants the VSH falls back to once the Blu-ray path is refused.
		if (cmd == 1)
		{
			sys_storage.notice("storage_device_command(): unhandled ATAPI opcode 0x%02x (inlen=0x%x, outlen=0x%x)", opcode, inlen, outlen);
		}
		else
		{
			sys_storage.notice("storage_device_command(): unhandled command 0x%llx (inlen=0x%x, outlen=0x%x)", cmd, inlen, outlen);
		}
	}

	return storage_command_response{response_event_data2, response_event_data3};
}

error_code sys_storage_send_device_command(u32 dev_handle, u64 cmd, vm::ptr<void> in, u64 inlen, vm::ptr<void> out, u64 outlen)
{
	sys_storage.todo("sys_storage_send_device_command(dev_handle=0x%x, cmd=0x%llx, in=*0x%x, inlen=0x%x, out=*0x%x, outlen=0x%x)", dev_handle, cmd, in, inlen, out, outlen);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	// The same packet, put to the same drive, and answered the same way: lv1 does not keep two
	// sets of answers, one per syscall. What this one does not have is a queue to report a
	// completion to, so the event data the command produced is dropped here. The handle is not
	// looked up either, because this syscall never looked it up: what lv2 answers here to one it
	// does not know is not written down anywhere, and the asynchronous path is not evidence of it.
	storage_device_command(cmd, in, inlen, out, outlen);

	return CELL_OK;
}

error_code sys_storage_async_send_device_command(u32 dev_handle, u64 cmd, vm::ptr<void> in, u64 inlen, vm::ptr<void> out, u64 outlen, u64 operation_name)
{
	sys_storage.todo("sys_storage_async_send_device_command(dev_handle=0x%x, cmd=0x%llx, in=*0x%x, inlen=0x%x, out=*0x%x, outlen=0x%x, operation_name=0x%x)", dev_handle, cmd, in, inlen, out, outlen, operation_name);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	// Bring the medium event thread up. This is the path the VSH probes the drive through, so it is
	// the one that decides the manager exists before anything asks what is in the tray.
	g_fxo->get<storage_manager>();

	const auto handle = idm::get_unlocked<lv2_obj, lv2_storage>(dev_handle);

	if (!handle)
	{
		return CELL_ESRCH;
	}

	const storage_command_response response = storage_device_command(cmd, in, inlen, out, outlen);

	if (auto q = handle->async_port.load())
	{
		q->send(0, operation_name, response.event_data2, response.event_data3);
	}

	return CELL_OK;
}

error_code sys_storage_async_read()
{
	sys_storage.todo("sys_storage_async_read()");

	return CELL_OK;
}

error_code sys_storage_async_write()
{
	sys_storage.todo("sys_storage_async_write()");

	return CELL_OK;
}

error_code sys_storage_async_cancel()
{
	sys_storage.todo("sys_storage_async_cancel()");

	return CELL_OK;
}

error_code sys_storage_get_device_info(u64 device, vm::ptr<StorageDeviceInfo> buffer)
{
	sys_storage.todo("sys_storage_get_device_info(device=0x%x, buffer=*0x%x)", device, buffer);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	if (!buffer)
	{
		return CELL_EFAULT;
	}

	memset(buffer.get_ptr(), 0, sizeof(StorageDeviceInfo));

	u64 storage = device & 0xFFFFF00FFFFFFFF;
	u32 dev_num = (device >> 32) & 0xFF;

	if (storage == ATA_HDD) // dev_hdd?
	{
		if (dev_num > 2)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());
		buffer->sector_size = 0x200;
		buffer->one = 1;
		buffer->one1 = 1;
		buffer->one2 = 1;
		buffer->flag5 = 1;

		// set partition size based on dev_num
		// stole these sizes from kernel dump, unknown if they are 100% correct
		// vsh reports only 2 partitions even though there is 3 sizes
		switch (dev_num)
		{
		case 0:
			buffer->sector_count = 0x2542EAB0; // possibly total size
			break;
		case 1:
			buffer->sector_count = 0x24FAEA98; // which makes this hdd0
			break;
		case 2:
			buffer->sector_count = 0x3FFFF8; // and this one hdd1
			break;
		}
	}
	else if (storage == BDVD_DRIVE) //	dev_bdvd?
	{
		if (dev_num > 0)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());

		const bool connected = true;
		if (!connected)
		{
			buffer->sector_count = 0;
			buffer->sector_size = 0x7FFFFFFF;
		}
		else
		{
			buffer->sector_count = 0x1EC4B00;
			buffer->sector_size = 0x800;
		}
// [000] | 75 6E 6E 61 | 6D 65 64 00 |
// [008] | 00 00 00 00 | 00 00 00 00 |
// [010] | 00 00 00 00 | 00 00 00 00 |
// [018] | 00 00 00 00 | 00 00 00 00 |
// [020] | 00 00 00 00 | 00 00 00 00 |
// [028] | 00 00 00 00 | 01 EC 4B 00 |
// [030] | 00 00 02 00 | 00 00 00 01 |
// [038] | 01 01 01 00 | 01 01 00 01 |



// [000] | 75 6E 6E 61 | 6D 65 64 00 |
// [008] | 00 00 00 00 | 00 00 00 00 |
// [010] | 00 00 00 00 | 00 00 00 00 |
// [018] | 00 00 00 00 | 00 00 00 00 |
// [020] | 00 00 00 00 | 00 00 00 00 |
// [028] | 00 00 00 00 | 00 62 83 E0 |
// [030] | 00 00 08 00 | 00 00 00 01 |
// [038] | 00 01 01 00 | 00 00 00 01 |

		buffer->one = 1;
		buffer->connected = connected;
		buffer->one1 = 1;
		buffer->one2 = 1;
		buffer->flag3 = 0;
		//buffer->flags4 = 0;
		buffer->flag5 = 1;

		static const unsigned char dump2[0x40] =
		{
			0x75, 0x6E, 0x6E, 0x61, 0x6D, 0x65, 0x64, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x83, 0xE0,
			0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01
		};

		static const unsigned char data_mode_8[0x40] =
		{
		    0x75, 0x6E, 0x6E, 0x61, 0x6D, 0x65, 0x64, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		    0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x83, 0xE0,
		    0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01,
		    0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01
		};


		std::memcpy(&*buffer, data_mode_8, sizeof(data_mode_8));
	//	buffer->sector_size = 0x200;

		// The blob above describes a PS3 BD-ROM. When a PS1/PS2 disc is staged instead, report the
		// geometry of that medium: 2048-byte user sectors, the same for CD, DVD and BD, and the
		// capacity of the disc itself, so it does not contradict the profile reported for it.
		//
		// Only read what the storage manager already worked out, never bring it into being from
		// here: it is a named_thread, so asking for it with g_fxo->get would start the medium
		// event thread off a query that has nothing to do with medium events.
		const auto manager = g_fxo->try_get<storage_manager>();

		if (const u64 sector_count = manager ? manager->sectors.load() : 0)
		{
			buffer->sector_size = 2048;
			buffer->sector_count = sector_count;
			sys_storage.notice("sys_storage_get_device_info(): reporting %d sectors of 2048 bytes for the staged PS1/PS2 disc", sector_count);
		}
	}
	else if (storage == USB_MASS_STORAGE_1(0))
	{
		if (dev_num > 0)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());
		/*buffer->sector_count = 0x4D955;*/
		buffer->sector_size = 0x200;
		buffer->one = 1;
		buffer->one1 = 1;
		buffer->one2 = 1;
		buffer->flag5 = 1;
	}
	else if (storage == NAND_FLASH)
	{
		if (dev_num > 6)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());
		buffer->sector_size = 0x200;
		buffer->one = 1;
		buffer->one1 = 1;
		buffer->one2 = 1;
		buffer->flag5 = 1;

		// see ata_hdd for explanation
		switch (dev_num)
		{
		case 0: buffer->sector_count = 0x80000;
			break;
		case 1: buffer->sector_count = 0x75F8;
			break;
		case 2: buffer->sector_count = 0x63E00;
			break;
		case 3: buffer->sector_count = 0x8000;
			break;
		case 4: buffer->sector_count = 0x400;
			break;
		case 5: buffer->sector_count = 0x2000;
			break;
		case 6: buffer->sector_count = 0x200;
			break;
		}
	}
	else if (storage == NOR_FLASH)
	{
		if (dev_num > 3)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());
		buffer->sector_size = 0x200;
		buffer->one = 1;
		buffer->one1 = 0;
		buffer->one2 = 1;
		buffer->flag5 = 1;

		// see ata_hdd for explanation
		switch (dev_num)
		{
		case 0: buffer->sector_count = 0x8000;
			break;
		case 1: buffer->sector_count = 0x77F8;
			break;
		case 2: buffer->sector_count = 0x100; // offset, 0x20000
			break;
		case 3: buffer->sector_count = 0x400;
			break;
		}
	}
	else if (storage == NAND_UNK)
	{
		if (dev_num > 1)
		{
			return not_an_error(-5);
		}

		std::string u = "unnamed";
		memcpy(buffer->name, u.c_str(), u.size());
		buffer->sector_size = 0x800;
		buffer->one = 1;
		buffer->one1 = 0;
		buffer->one2 = 1;
		buffer->flag5 = 1;

		// see ata_hdd for explanation
		switch (dev_num)
		{
		case 0: buffer->sector_count = 0x7FFFFFFF;
			break;
		}
	}
	else
	{
		sys_storage.error("sys_storage_get_device_info(device=0x%x, buffer=*0x%x)", device, buffer);
	}

	return CELL_OK;
}

error_code sys_storage_get_device_config(vm::ptr<u32> storages, vm::ptr<u32> devices)
{
	sys_storage.todo("sys_storage_get_device_config(storages=*0x%x, devices=*0x%x)", storages, devices);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	if (storages) *storages = 6; else return CELL_EFAULT;
	if (devices)  *devices = 17; else return CELL_EFAULT;

	return CELL_OK;
}

error_code sys_storage_report_devices(u32 storages, u32 start, u32 devices, vm::ptr<u64> device_ids)
{
	sys_storage.todo("sys_storage_report_devices(storages=0x%x, start=0x%x, devices=0x%x, device_ids=0x%x)", storages, start, devices, device_ids);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	if (!device_ids)
	{
		return CELL_EFAULT;
	}

	if (storages != 6)
	{
		return -5;
	}

	static constexpr std::array<u64, 0x11> all_devs = []
	{
		std::array<u64, 0x11> all_devs{};
		all_devs[0] = 0x10300000000000A;

		for (int i = 0; i < 7; ++i)
		{
			all_devs[i + 1] = 0x100000000000001 | (static_cast<u64>(i) << 32);
		}

		for (int i = 0; i < 3; ++i)
		{
			all_devs[i + 8] = 0x101000000000007 | (static_cast<u64>(i) << 32);
		}

		all_devs[11] = 0x101000000000006;

		for (int i = 0; i < 4; ++i)
		{
			all_devs[i + 12] = 0x100000000000004 | (static_cast<u64>(i) << 32);
		}

		all_devs[16] = 0x100000000000003;
		return all_devs;
	}();

	if (!devices || start >= all_devs.size() || devices > all_devs.size() - start)
	{
		return CELL_EINVAL;
	}

	std::copy_n(all_devs.begin() + start, devices, device_ids.get_ptr());

	return CELL_OK;
}

error_code sys_storage_configure_medium_event(ppu_thread& ppu, u32 fd, u32 equeue_id, vm::ptr<u32> handle)
{
	sys_storage.todo("sys_storage_configure_medium_event(fd=0x%x, equeue_id=0x%x, c=0x%x)", fd, equeue_id, handle);
	log_callback(*cpu_thread::get_current<ppu_thread>());

	if (!ppu.has_root_perm)
	{
		return CELL_EPERM;
	}

	u64 device_id = 0; // 0 means global

	if (fd)
	{
		const auto storage = idm::get_unlocked<lv2_obj, lv2_storage>(fd);

		if (!storage)
		{
			return {CELL_ESRCH, "storage"};
		}

		// Oddly that is all it needs from the storage descriptor
		// It closes the handle right after device ID extraction
		// Perhaps because not calling sys_storage_open's routines saves on expensive "error checking" the device ID?
		device_id = storage->device_id;
	}

	auto& manager = *ensure(g_fxo->try_get<storage_manager>());

	if (device_id)
	{
		// The VSH registers twice: once from x3::_BDInitialize with fd 0, before it has opened the
		// drive, and again from x3::_PollingService with a real storage handle once the drive is
		// up. Only after the second one does x3::_MediaDetect have a usable drive object - firing
		// a medium event before that makes it run a method on a null object and crash.
		manager.drive_ready = true;
	}

	if (auto queue = idm::get_unlocked<lv2_obj, lv2_event_queue>(equeue_id))
	{
		// A configured event queue carries a single registration. The VSH configures the medium
		// event twice on the same queue - once from x3::_BDInitialize with fd 0, before the drive
		// is open, and again from x3::_PollingService with a real storage handle (vsh.elf 0x516ca4,
		// reached from 0x51850c and 0x518570) - and hands the same output address to both calls, so
		// it only ever remembers one handle. Keeping the earlier registration alive would deliver
		// every medium event to that queue twice, and the VSH answers a medium event by spawning an
		// x3::_MediaDetect thread: the second thread then races the first over the same drive, its
		// sys_fs_mount of /dev_bdvd fails with EBUSY, and the VSH takes the mount failure path that
		// publishes an unsupported medium (vsh.elf 0x518ef0).
		std::vector<u32> superseded;

		idm::select<lv2_storage_medium_event_port>([&](u32 id, lv2_storage_medium_event_port& port)
		{
			if (port.medium_port.get() == queue.get())
			{
				superseded.emplace_back(id);
			}
		});

		for (u32 id : superseded)
		{
			idm::remove<lv2_storage_medium_event_port>(id);
		}

		while (!idm::make_ptr<lv2_storage_medium_event_port>(device_id, queue))
		{
			std::vector<std::pair<u32, u32>> cleanup_list;

			// Try cleanup
			id_manager::g_process = 0;
			idm::select<lv2_storage_medium_event_port>([&](u32 id, u32 proc, lv2_storage_medium_event_port& port)
			{
				// Check port status
				if (!port.savable())
				{
					// Detached ports can be removed
					cleanup_list.emplace_back(id, proc);
				}
			});

			bool success = false;

			for (auto [id, proc] : cleanup_list)
			{
				success = idm::remove<lv2_storage_medium_event_port>(idm::id_index(id, proc));
			}

			id_manager::g_process = ppu.proc_id;

			if (!success)
			{
				fmt::throw_exception("lv2_storage_medium_event_port() entries depletion, consider increases lv2_storage_medium_event_port::id_count!");
			}
		}
	}
	else
	{
		return CELL_ESRCH;
	}

	// No idea what this means, seems like it returns uninitialized memory
	*handle = 0x5D7280;
	return CELL_OK;
}

error_code sys_storage_set_medium_polling_interval(ppu_thread& ppu, u32 fd, u64 interval)
{
	sys_storage.todo("sys_storage_set_medium_polling_interval()");

	return CELL_OK;
}

error_code sys_storage_create_region()
{
	sys_storage.todo("sys_storage_create_region()");

	return CELL_OK;
}

error_code sys_storage_delete_region()
{
	sys_storage.todo("sys_storage_delete_region()");

	return CELL_OK;
}

error_code sys_storage_execute_device_command(u32 fd, u64 cmd, vm::ptr<char> cmdbuf, u64 cmdbuf_size, vm::ptr<char> databuf, u64 databuf_size, vm::ptr<u32> driver_status)
{
	sys_storage.todo("sys_storage_execute_device_command(fd=0x%x, cmd=0x%llx, cmdbuf=*0x%x, cmdbuf_size=0x%llx, databuf=*0x%x, databuf_size=0x%llx, driver_status=*0x%x)", fd, cmd, cmdbuf, cmdbuf_size, databuf, databuf_size, driver_status);

	// cmd == 2 is get device info,
	// databuf, first byte 0 == status ok?
	// byte 1, if < 0 , not ata device
	return CELL_OK;
}

error_code sys_storage_check_region_acl()
{
	sys_storage.todo("sys_storage_check_region_acl()");

	return CELL_OK;
}

error_code sys_storage_set_region_acl()
{
	sys_storage.todo("sys_storage_set_region_acl()");

	return CELL_OK;
}

error_code sys_storage_get_region_offset()
{
	sys_storage.todo("sys_storage_get_region_offset()");

	return CELL_OK;
}

error_code sys_storage_set_emulated_speed()
{
	sys_storage.todo("sys_storage_set_emulated_speed()");

	// todo: only debug kernel has this
	return CELL_ENOSYS;
}
