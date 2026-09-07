#pragma once

#include "util/types.hpp"

#include <array>

// MagicGate / MechaCon memory-card authentication.
//
// This is the crypto that lv1's Storage Manager normally delegates to the isolated SPU module
// sb_iso_spu_module.self when the "Memory Card Utility (PS/PS2)" (libmcadpt.sprx) talks to the
// PS3 Memory Card Adaptor (CECHZM1). RPCS3 has no isolated-SPU/lv1 support, so sys_ss_sec_hw_framework
// packet 0x5008 ("HW mc") is served here instead.
//
// The retail MagicGate keys are NOT shipped. The user must place them in <config>/MagicGate.bin
// (see mg_key_file_layout below). Without the file, authentication returns an error and PS2 memory
// cards will not mount.
//
// Cipher + auth flow ported from ps3mca-tool (GPLv3) - src/cipher.c and src/mecha_emu.c.

namespace magicgate
{
	// <config>/MagicGate.bin layout (raw bytes, no header):
	//   0x00  8   MC_CARDKEY_MATERIAL_1  (IV for UniqueKey lo)
	//   0x08  16  MC_CARDKEY_HASHKEY_1   (2-key 3DES key for UniqueKey lo)
	//   0x18  8   MC_CARDKEY_MATERIAL_2  (IV for UniqueKey hi)
	//   0x20  16  MC_CARDKEY_HASHKEY_2   (2-key 3DES key for UniqueKey hi)
	//   0x30  8   MC_CHALLENGE_MATERIAL  (IV for the challenge/response chain)
	//   -- optional, only needed for KELF (de)signing, not for basic save access --
	//   0x38  8   MG_KBIT_MATERIAL
	//   0x40  8   MG_KC_MATERIAL
	//   0x48  16  MG_KBIT_MASTER_KEY
	//   0x58  16  MG_KC_MASTER_KEY
	// Minimum file size: 0x38 (56) bytes. Full: 0x68 (104) bytes.
	constexpr usz mg_key_file_min_size = 0x38;
	constexpr usz mg_key_file_full_size = 0x68;

	// True once a valid key file has been loaded.
	bool keys_available();

	// Result of a memory-card auth step.
	enum class mc_auth_result
	{
		ok,
		no_keys,     // MagicGate.bin missing/too small
		bad_params,  // bad packet / null buffers
		verify_fail, // card response did not verify (wrong keys, or not a MagicGate card)
	};

	// packet 0x5008 sub-command 1 ("mc_auth_1"): given the card's IV/material/nonce, derive the
	// UniqueKey and produce the three MechaChallenge values to send to the card.
	mc_auth_result mc_auth_generate_challenge(
		const u8 card_iv[8], const u8 card_material[8], const u8 card_nonce[8],
		u8 out_challenge1[8], u8 out_challenge2[8], u8 out_challenge3[8]);

	// packet 0x5008 sub-command 2 ("mc_auth_2"): verify the card's three responses and, on success,
	// latch the session key. Must be called after mc_auth_generate_challenge.
	mc_auth_result mc_auth_verify_response(
		const u8 card_response1[8], const u8 card_response2[8], const u8 card_response3[8]);

	// The session key latched by the last successful mc_auth_verify_response (8 bytes).
	std::array<u8, 8> session_key();
}
