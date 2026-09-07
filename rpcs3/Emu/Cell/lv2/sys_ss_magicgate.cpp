#include "stdafx.h"
#include "sys_ss_magicgate.h"

#include "Utilities/File.h"

#include <cstring>
#include <mutex>
#include <vector>

// MechaCon cipher + memory-card auth flow, ported from ps3mca-tool (GPLv3):
//   src/cipher.c and src/mecha_emu.c  -  Copyright (C) 2011 "someone who wants to stay anonymous"
// The cipher is FIPS 46-3 DES with a reordered key schedule (PC-2x); each 8-byte block is read as a
// big-endian u64 (ps3mca-tool's read_le_uint64 helper is misnamed - it is big-endian).

LOG_CHANNEL(sys_ss_mg);

namespace magicgate
{
	// ---------------------------------------------------------------------------------------------
	// 8-byte block <-> u64. NOTE: ps3mca-tool's helpers are named read_le_uint64 / append_le_uint64
	// but are actually BIG-endian (byte 0 = MSB). We must match them exactly or the cipher diverges.
	// ---------------------------------------------------------------------------------------------
	static u64 read_block64(const u8* p)
	{
		u64 v = 0;
		for (int i = 0; i < 8; i++)
			v = (v << 8) | p[i];
		return v;
	}

	static void write_block64(u8* p, u64 v)
	{
		for (int i = 7; i >= 0; i--, v >>= 8)
			p[i] = static_cast<u8>(v);
	}

	static void mem_xor(const u8* a, const u8* b, u8* out, usz len)
	{
		for (usz i = 0; i < len; i++)
			out[i] = a[i] ^ b[i];
	}

	// ---------------------------------------------------------------------------------------------
	// MechaCon DES cipher (verbatim from ps3mca-tool src/cipher.c)
	// ---------------------------------------------------------------------------------------------
	static const u8 PC1_table[56] = {
		57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4};

	static const u8 LS_table[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

	static const u8 PC2x_table[48] = {
		14, 17, 11, 24, 1, 5, 23, 19, 12, 4, 26, 8,
		41, 52, 31, 37, 47, 55, 44, 49, 39, 56, 34, 53,
		3, 28, 15, 6, 21, 10, 16, 7, 27, 20, 13, 2,
		30, 40, 51, 45, 33, 48, 46, 42, 50, 36, 29, 32};

	static void cipherKeyScheduleInner(u64 RoundKeys[16], u64 Key)
	{
		u64 Input = 0;
		for (int i = 0; i < 56; i++)
		{
			if (Key & (u64{1} << (64 - PC1_table[i])))
				Input |= u64{1} << (55 - i);
		}

		u32 C = static_cast<u32>(Input >> 28) & 0x0FFFFFFF;
		u32 D = static_cast<u32>(Input) & 0x0FFFFFFF;

		for (int i = 0; i < 16; i++)
		{
			if (LS_table[i] == 1)
			{
				C = (C << 1) | (C >> 27);
				D = (D << 1) | (D >> 27);
			}
			else
			{
				C = (C << 2) | (C >> 26);
				D = (D << 2) | (D >> 26);
			}

			const u64 CD = (u64{C & 0x0FFFFFFF} << 28) | (D & 0x0FFFFFFF);
			u64 Ki = 0;
			for (int j = 0; j < 48; j++)
			{
				if (CD & (u64{1} << (56 - PC2x_table[j])))
					Ki |= u64{1} << (63 - 2 - ((j / 6) * 8 + (j % 6)));
			}
			RoundKeys[i] = Ki;
		}
	}

	static const u8 IP_table[64] = {
		58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
		57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7};

	static u64 cipherIP(u64 Value)
	{
		u64 Output = 0;
		for (int i = 0; i < 64; i++)
		{
			if (Value & (u64{1} << (64 - IP_table[i])))
				Output |= u64{1} << (63 - i);
		}
		return Output;
	}

	static const u8 IPinv_table[64] = {
		40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25};

	static u64 cipherIPInverse(u64 Value)
	{
		u64 Output = 0;
		for (int i = 0; i < 64; i++)
		{
			if (Value & (u64{1} << (64 - IPinv_table[i])))
				Output |= u64{1} << (63 - i);
		}
		return Output;
	}

	static const u32 SP_box_1[64] = {
		0x00808200, 0x00000000, 0x00008000, 0x00808202, 0x00808002, 0x00008202, 0x00000002, 0x00008000,
		0x00000200, 0x00808200, 0x00808202, 0x00000200, 0x00800202, 0x00808002, 0x00800000, 0x00000002,
		0x00000202, 0x00800200, 0x00800200, 0x00008200, 0x00008200, 0x00808000, 0x00808000, 0x00800202,
		0x00008002, 0x00800002, 0x00800002, 0x00008002, 0x00000000, 0x00000202, 0x00008202, 0x00800000,
		0x00008000, 0x00808202, 0x00000002, 0x00808000, 0x00808200, 0x00800000, 0x00800000, 0x00000200,
		0x00808002, 0x00008000, 0x00008200, 0x00800002, 0x00000200, 0x00000002, 0x00800202, 0x00008202,
		0x00808202, 0x00008002, 0x00808000, 0x00800202, 0x00800002, 0x00000202, 0x00008202, 0x00808200,
		0x00000202, 0x00800200, 0x00800200, 0x00000000, 0x00008002, 0x00008200, 0x00000000, 0x00808002};

	static const u32 SP_box_2[64] = {
		0x40084010, 0x40004000, 0x00004000, 0x00084010, 0x00080000, 0x00000010, 0x40080010, 0x40004010,
		0x40000010, 0x40084010, 0x40084000, 0x40000000, 0x40004000, 0x00080000, 0x00000010, 0x40080010,
		0x00084000, 0x00080010, 0x40004010, 0x00000000, 0x40000000, 0x00004000, 0x00084010, 0x40080000,
		0x00080010, 0x40000010, 0x00000000, 0x00084000, 0x00004010, 0x40084000, 0x40080000, 0x00004010,
		0x00000000, 0x00084010, 0x40080010, 0x00080000, 0x40004010, 0x40080000, 0x40084000, 0x00004000,
		0x40080000, 0x40004000, 0x00000010, 0x40084010, 0x00084010, 0x00000010, 0x00004000, 0x40000000,
		0x00004010, 0x40084000, 0x00080000, 0x40000010, 0x00080010, 0x40004010, 0x40000010, 0x00080010,
		0x00084000, 0x00000000, 0x40004000, 0x00004010, 0x40000000, 0x40080010, 0x40084010, 0x00084000};

	static const u32 SP_box_3[64] = {
		0x00000104, 0x04010100, 0x00000000, 0x04010004, 0x04000100, 0x00000000, 0x00010104, 0x04000100,
		0x00010004, 0x04000004, 0x04000004, 0x00010000, 0x04010104, 0x00010004, 0x04010000, 0x00000104,
		0x04000000, 0x00000004, 0x04010100, 0x00000100, 0x00010100, 0x04010000, 0x04010004, 0x00010104,
		0x04000104, 0x00010100, 0x00010000, 0x04000104, 0x00000004, 0x04010104, 0x00000100, 0x04000000,
		0x04010100, 0x04000000, 0x00010004, 0x00000104, 0x00010000, 0x04010100, 0x04000100, 0x00000000,
		0x00000100, 0x00010004, 0x04010104, 0x04000100, 0x04000004, 0x00000100, 0x00000000, 0x04010004,
		0x04000104, 0x00010000, 0x04000000, 0x04010104, 0x00000004, 0x00010104, 0x00010100, 0x04000004,
		0x04010000, 0x04000104, 0x00000104, 0x04010000, 0x00010104, 0x00000004, 0x04010004, 0x00010100};

	static const u32 SP_box_4[64] = {
		0x80401000, 0x80001040, 0x80001040, 0x00000040, 0x00401040, 0x80400040, 0x80400000, 0x80001000,
		0x00000000, 0x00401000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00400040, 0x80400000,
		0x80000000, 0x00001000, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x80001000, 0x00001040,
		0x80400040, 0x80000000, 0x00001040, 0x00400040, 0x00001000, 0x00401040, 0x80401040, 0x80000040,
		0x00400040, 0x80400000, 0x00401000, 0x80401040, 0x80000040, 0x00000000, 0x00000000, 0x00401000,
		0x00001040, 0x00400040, 0x80400040, 0x80000000, 0x80401000, 0x80001040, 0x80001040, 0x00000040,
		0x80401040, 0x80000040, 0x80000000, 0x00001000, 0x80400000, 0x80001000, 0x00401040, 0x80400040,
		0x80001000, 0x00001040, 0x00400000, 0x80401000, 0x00000040, 0x00400000, 0x00001000, 0x00401040};

	static const u32 SP_box_5[64] = {
		0x00000080, 0x01040080, 0x01040000, 0x21000080, 0x00040000, 0x00000080, 0x20000000, 0x01040000,
		0x20040080, 0x00040000, 0x01000080, 0x20040080, 0x21000080, 0x21040000, 0x00040080, 0x20000000,
		0x01000000, 0x20040000, 0x20040000, 0x00000000, 0x20000080, 0x21040080, 0x21040080, 0x01000080,
		0x21040000, 0x20000080, 0x00000000, 0x21000000, 0x01040080, 0x01000000, 0x21000000, 0x00040080,
		0x00040000, 0x21000080, 0x00000080, 0x01000000, 0x20000000, 0x01040000, 0x21000080, 0x20040080,
		0x01000080, 0x20000000, 0x21040000, 0x01040080, 0x20040080, 0x00000080, 0x01000000, 0x21040000,
		0x21040080, 0x00040080, 0x21000000, 0x21040080, 0x01040000, 0x00000000, 0x20040000, 0x21000000,
		0x00040080, 0x01000080, 0x20000080, 0x00040000, 0x00000000, 0x20040000, 0x01040080, 0x20000080};

	static const u32 SP_box_6[64] = {
		0x10000008, 0x10200000, 0x00002000, 0x10202008, 0x10200000, 0x00000008, 0x10202008, 0x00200000,
		0x10002000, 0x00202008, 0x00200000, 0x10000008, 0x00200008, 0x10002000, 0x10000000, 0x00002008,
		0x00000000, 0x00200008, 0x10002008, 0x00002000, 0x00202000, 0x10002008, 0x00000008, 0x10200008,
		0x10200008, 0x00000000, 0x00202008, 0x10202000, 0x00002008, 0x00202000, 0x10202000, 0x10000000,
		0x10002000, 0x00000008, 0x10200008, 0x00202000, 0x10202008, 0x00200000, 0x00002008, 0x10000008,
		0x00200000, 0x10002000, 0x10000000, 0x00002008, 0x10000008, 0x10202008, 0x00202000, 0x10200000,
		0x00202008, 0x10202000, 0x00000000, 0x10200008, 0x00000008, 0x00002000, 0x10200000, 0x00202008,
		0x00002000, 0x00200008, 0x10002008, 0x00000000, 0x10202000, 0x10000000, 0x00200008, 0x10002008};

	static const u32 SP_box_7[64] = {
		0x00100000, 0x02100001, 0x02000401, 0x00000000, 0x00000400, 0x02000401, 0x00100401, 0x02100400,
		0x02100401, 0x00100000, 0x00000000, 0x02000001, 0x00000001, 0x02000000, 0x02100001, 0x00000401,
		0x02000400, 0x00100401, 0x00100001, 0x02000400, 0x02000001, 0x02100000, 0x02100400, 0x00100001,
		0x02100000, 0x00000400, 0x00000401, 0x02100401, 0x00100400, 0x00000001, 0x02000000, 0x00100400,
		0x02000000, 0x00100400, 0x00100000, 0x02000401, 0x02000401, 0x02100001, 0x02100001, 0x00000001,
		0x00100001, 0x02000000, 0x02000400, 0x00100000, 0x02100400, 0x00000401, 0x00100401, 0x02100400,
		0x00000401, 0x02000001, 0x02100401, 0x02100000, 0x00100400, 0x00000000, 0x00000001, 0x02100401,
		0x00000000, 0x00100401, 0x02100000, 0x00000400, 0x02000001, 0x02000400, 0x00000400, 0x00100001};

	static const u32 SP_box_8[64] = {
		0x08000820, 0x00000800, 0x00020000, 0x08020820, 0x08000000, 0x08000820, 0x00000020, 0x08000000,
		0x00020020, 0x08020000, 0x08020820, 0x00020800, 0x08020800, 0x00020820, 0x00000800, 0x00000020,
		0x08020000, 0x08000020, 0x08000800, 0x00000820, 0x00020800, 0x00020020, 0x08020020, 0x08020800,
		0x00000820, 0x00000000, 0x00000000, 0x08020020, 0x08000020, 0x08000800, 0x00020820, 0x00020000,
		0x00020820, 0x00020000, 0x08020800, 0x00000800, 0x00000020, 0x08020020, 0x00000800, 0x00020820,
		0x08000800, 0x00000020, 0x08000020, 0x08020000, 0x08020020, 0x08000000, 0x00020000, 0x08000820,
		0x00000000, 0x08020820, 0x00020020, 0x08000020, 0x08020000, 0x08000800, 0x08000820, 0x00000000,
		0x08020820, 0x00020800, 0x00020800, 0x00000820, 0x00000820, 0x00020020, 0x08000000, 0x08020800};

	static void cipherForward(u64 Value, u64* Result, const u64 RoundKeys[16])
	{
		const u64 Current = cipherIP(Value);
		u32 Low = static_cast<u32>(Current);
		u32 High = static_cast<u32>(Current >> 32);

		for (int i = 0; i <= 15; i++)
		{
			u32 X = (Low << 29) | (Low >> 3);
			u32 Y = (Low << 1) | (Low >> 31);

			X ^= static_cast<u32>(RoundKeys[i] >> 32);
			Y ^= static_cast<u32>(RoundKeys[i]);

			const u32 Tab =
				SP_box_1[(X >> 24) & 0x3F] | SP_box_2[(Y >> 24) & 0x3F] |
				SP_box_3[(X >> 16) & 0x3F] | SP_box_4[(Y >> 16) & 0x3F] |
				SP_box_5[(X >> 8) & 0x3F] | SP_box_6[(Y >> 8) & 0x3F] |
				SP_box_7[(X >> 0) & 0x3F] | SP_box_8[(Y >> 0) & 0x3F];

			const u32 NewLow = High ^ Tab;
			High = Low;
			Low = NewLow;
		}

		*Result = cipherIPInverse((u64{Low} << 32) | u64{High});
	}

	static void _cipherKeySchedule(const u8 Key[8], u64 RoundKeys[16])
	{
		cipherKeyScheduleInner(RoundKeys, read_block64(Key));
	}

	static void _cipherKeyScheduleReverse(const u8 Key[8], u64 RoundKeys[16])
	{
		u64 Forward[16];
		cipherKeyScheduleInner(Forward, read_block64(Key));
		for (int i = 0; i < 16; i++)
			RoundKeys[i] = Forward[15 - i];
	}

	static int cipherKeySchedule(u64* RoundKeys, const u8* Keys, int KeyCount)
	{
		if (KeyCount != 1 && KeyCount != 2 && KeyCount != 3)
			return -1;

		_cipherKeySchedule(Keys + 0, RoundKeys + 0);
		if (KeyCount == 1)
			return 1;

		_cipherKeyScheduleReverse(Keys + 8, RoundKeys + 16);
		if (KeyCount == 2)
			return 2;

		_cipherKeySchedule(Keys + 16, RoundKeys + 32);
		return 3;
	}

	static int cipherKeyScheduleReverse(u64* RoundKeys, const u8* Keys, int KeyCount)
	{
		if (KeyCount != 1 && KeyCount != 2 && KeyCount != 3)
			return -1;

		_cipherKeyScheduleReverse(Keys + 0, RoundKeys + 0);
		if (KeyCount == 1)
			return 1;

		_cipherKeySchedule(Keys + 8, RoundKeys + 16);
		if (KeyCount == 2)
			return 2;

		std::memcpy(RoundKeys + 32, RoundKeys, sizeof(RoundKeys[0]) * 16);
		_cipherKeyScheduleReverse(Keys + 16, RoundKeys);
		return 3;
	}

	static void cipherSingleBlock(u8 Result[8], const u8 Data[8], const u64* RoundKeys, int KeyCount)
	{
		u64 Output;
		cipherForward(read_block64(Data), &Output, RoundKeys);

		if (KeyCount != 1)
		{
			cipherForward(Output, &Output, RoundKeys + 16);
			if (KeyCount == 2)
				cipherForward(Output, &Output, RoundKeys);
			else
				cipherForward(Output, &Output, RoundKeys + 32);
		}

		write_block64(Result, Output);
	}

	static int cipherCbcEncrypt(u8* Result, const u8* Data, usz Length, const u8* Keys, int KeyCount, const u8 IV[8])
	{
		u64 RoundKeys[16 * 3];
		u8 LastBlock[8];

		if (Length == 0)
			return -2;

		KeyCount = cipherKeySchedule(RoundKeys, Keys, KeyCount);
		if (KeyCount < 1)
			return -1;

		std::memcpy(LastBlock, IV, 8);

		usz i = 0;
		for (; Length - i * 8 >= 8; i++)
		{
			u8 InputBlock[8];
			mem_xor(LastBlock, Data + i * 8, InputBlock, 8);
			cipherSingleBlock(LastBlock, InputBlock, RoundKeys, KeyCount);
			std::memcpy(Result + i * 8, LastBlock, 8);
		}

		if (Length - i * 8 > 0)
		{
			u8 BaseBlock[8];
			cipherSingleBlock(BaseBlock, LastBlock, RoundKeys, KeyCount);
			for (usz k = 0; k < Length - i * 8; k++)
				Result[i * 8 + k] = BaseBlock[k] ^ Data[i * 8 + k];
		}

		return 0;
	}

	static int cipherCbcDecrypt(u8* Result, const u8* Data, usz Length, const u8* Keys, int KeyCount, const u8 IV[8])
	{
		u64 RoundKeys[16 * 3];
		u8 LastBlock[8], TailBlock[8]{};

		if (Length == 0)
			return -2;

		KeyCount = cipherKeyScheduleReverse(RoundKeys, Keys, KeyCount);
		if (KeyCount < 1)
			return -1;

		std::memcpy(LastBlock, IV, 8);

		usz i = 0;
		for (; Length - i * 8 >= 8; i++)
		{
			u8 OutputBlock[8];
			std::memcpy(TailBlock, Data + i * 8, 8);
			cipherSingleBlock(OutputBlock, TailBlock, RoundKeys, KeyCount);
			mem_xor(LastBlock, OutputBlock, OutputBlock, 8);
			std::memcpy(LastBlock, TailBlock, 8);
			std::memcpy(Result + i * 8, OutputBlock, 8);
		}

		if (Length - i * 8 > 0)
		{
			u8 BaseBlock[8];
			cipherKeySchedule(RoundKeys, Keys, KeyCount);
			cipherSingleBlock(BaseBlock, TailBlock, RoundKeys, KeyCount);
			for (usz k = 0; k < Length - i * 8; k++)
				Result[i * 8 + k] = BaseBlock[k] ^ Data[i * 8 + k];
		}

		return 0;
	}

	// ---------------------------------------------------------------------------------------------
	// Key store + auth context
	// ---------------------------------------------------------------------------------------------
	struct mg_keys
	{
		bool loaded = false;
		u8 cardkey_material_1[8]{};
		u8 cardkey_hashkey_1[16]{};
		u8 cardkey_material_2[8]{};
		u8 cardkey_hashkey_2[16]{};
		u8 challenge_material[8]{};
	};

	struct mg_context
	{
		std::mutex mtx;
		mg_keys keys;
		bool keys_load_attempted = false;

		u8 unique_key[16]{};
		u8 card_iv[8]{};
		u8 card_nonce[8]{};
		u8 mecha_nonce[8]{};
		u8 session_key[8]{};
		bool have_challenge = false;
		bool have_session = false;
	};

	static mg_context& ctx()
	{
		static mg_context c;
		return c;
	}

	static void ensure_keys_loaded(mg_context& c)
	{
		if (c.keys_load_attempted)
			return;

		c.keys_load_attempted = true;

		// Look for MagicGate.bin next to config.yml (get_config_dir(true), e.g. bin/config/ on a
		// portable Windows build) and also in the base config dir.
		const std::string candidates[] = {
			fs::get_config_dir(true) + "MagicGate.bin",
			fs::get_config_dir() + "MagicGate.bin",
		};

		std::string path;
		fs::file f;
		for (const std::string& cand : candidates)
		{
			if ((f = fs::file(cand)))
			{
				path = cand;
				break;
			}
		}

		if (!f)
		{
			sys_ss_mg.error("MagicGate.bin not found (looked in '%s' and '%s'). PS2 memory card "
				"authentication is disabled. Provide the retail MagicGate keys to use the XMB memory "
				"card utility with the adaptor.", candidates[0], candidates[1]);
			return;
		}

		const std::vector<u8> data = f.to_vector<u8>();
		if (data.size() < mg_key_file_min_size)
		{
			sys_ss_mg.error("MagicGate.bin is too small (%d bytes, need at least %d).", data.size(), mg_key_file_min_size);
			return;
		}

		std::memcpy(c.keys.cardkey_material_1, &data[0x00], 8);
		std::memcpy(c.keys.cardkey_hashkey_1, &data[0x08], 16);
		std::memcpy(c.keys.cardkey_material_2, &data[0x18], 8);
		std::memcpy(c.keys.cardkey_hashkey_2, &data[0x20], 16);
		std::memcpy(c.keys.challenge_material, &data[0x30], 8);
		c.keys.loaded = true;

		sys_ss_mg.success("MagicGate keys loaded from '%s' (%d bytes).", path, data.size());
	}

	bool keys_available()
	{
		auto& c = ctx();
		std::lock_guard lock(c.mtx);
		ensure_keys_loaded(c);
		return c.keys.loaded;
	}

	// meCardCalcUniqueKey + meCardGenerateChallenge (mecha_emu.c)
	mc_auth_result mc_auth_generate_challenge(
		const u8 card_iv[8], const u8 card_material[8], const u8 card_nonce[8],
		u8 out_challenge1[8], u8 out_challenge2[8], u8 out_challenge3[8])
	{
		auto& c = ctx();
		std::lock_guard lock(c.mtx);
		ensure_keys_loaded(c);

		if (!c.keys.loaded)
			return mc_auth_result::no_keys;

		if (!card_iv || !card_material || !card_nonce || !out_challenge1 || !out_challenge2 || !out_challenge3)
			return mc_auth_result::bad_params;

		// UniqueKey = E(cardkey_hashkey_1, card_iv ^ card_material) || E(cardkey_hashkey_2, ...)
		u8 input[8];
		mem_xor(card_iv, card_material, input, 8);
		cipherCbcEncrypt(&c.unique_key[0], input, 8, c.keys.cardkey_hashkey_1, 2, c.keys.cardkey_material_1);
		cipherCbcEncrypt(&c.unique_key[8], input, 8, c.keys.cardkey_hashkey_2, 2, c.keys.cardkey_material_2);

		std::memcpy(c.card_iv, card_iv, 8);
		std::memcpy(c.card_nonce, card_nonce, 8);

		// A fixed MechaNonce is fine: the card only ever sees it encrypted inside challenge1 and
		// echoes it back; we keep the same value for the verify step.
		static constexpr u8 kMechaNonce[8] = {0xde, 0xad, 0xc0, 0xde, 0xde, 0xad, 0xc0, 0xde};
		std::memcpy(c.mecha_nonce, kMechaNonce, 8);

		cipherCbcEncrypt(out_challenge1, c.mecha_nonce, 8, c.unique_key, 2, c.keys.challenge_material);
		cipherCbcEncrypt(out_challenge2, card_nonce, 8, c.unique_key, 2, out_challenge1);
		cipherCbcEncrypt(out_challenge3, card_iv, 8, c.unique_key, 2, out_challenge2);

		c.have_challenge = true;
		c.have_session = false;
		return mc_auth_result::ok;
	}

	// meCardVerifyResponse (mecha_emu.c)
	mc_auth_result mc_auth_verify_response(
		const u8 card_response1[8], const u8 card_response2[8], const u8 card_response3[8])
	{
		auto& c = ctx();
		std::lock_guard lock(c.mtx);

		if (!c.keys.loaded)
			return mc_auth_result::no_keys;
		if (!c.have_challenge)
			return mc_auth_result::bad_params;
		if (!card_response1 || !card_response2 || !card_response3)
			return mc_auth_result::bad_params;

		u8 dr1[8], dr2[8], dr3[8];
		cipherCbcDecrypt(dr1, card_response1, 8, c.unique_key, 2, c.keys.challenge_material);
		cipherCbcDecrypt(dr2, card_response2, 8, c.unique_key, 2, card_response1);
		cipherCbcDecrypt(dr3, card_response3, 8, c.unique_key, 2, card_response2);

		if (std::memcmp(dr1, c.card_nonce, 8) != 0 || std::memcmp(dr2, c.mecha_nonce, 8) != 0)
		{
			sys_ss_mg.error("MagicGate: card response verification failed (wrong keys, or the card is not a "
				"genuine MagicGate memory card).");
			return mc_auth_result::verify_fail;
		}

		std::memcpy(c.session_key, dr3, 8);
		c.have_session = true;
		sys_ss_mg.success("MagicGate: memory card authenticated, session key established.");
		return mc_auth_result::ok;
	}

	std::array<u8, 8> session_key()
	{
		auto& c = ctx();
		std::lock_guard lock(c.mtx);
		std::array<u8, 8> k{};
		std::memcpy(k.data(), c.session_key, 8);
		return k;
	}
}
