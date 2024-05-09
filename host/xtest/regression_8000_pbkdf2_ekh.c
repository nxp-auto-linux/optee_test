// SPDX-License-Identifier: GPL-2.0
/*
 * Helper code for PBKDF2 (regression 8000) in the HSE compile-time config
 * with embedded key handles support (CFG_HSE_EMBED_KEYHANDLES).
 * Moved to separate file to keep the original regression_8000.c manageable.
 *
 * Copyright 2024 NXP
 * Copyright (c) 2014, Linaro Limited
 */
#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <tee_api_compat.h>
#include <utee_defines.h>
#include <string.h>
#include <enc_fs_key_manager_test.h>


#if defined(CFG_HSE_EMBED_KEYHANDLES)

#define TEST_PBKDF2_DATA(level, section, algo, id, oeb /* omit empty bufs */, run_test) \
	{ \
		level, section, algo, \
		pbkdf2_##id##_password, sizeof(pbkdf2_##id##_password), \
		(oeb && !sizeof(pbkdf2_##id##_salt)) ? NULL : pbkdf2_##id##_salt, sizeof(pbkdf2_##id##_salt), \
		pbkdf2_##id##_iteration_count, \
		pbkdf2_##id##_dkm, sizeof(pbkdf2_##id##_dkm), \
		run_test \
	}
#if defined _TO_STR
#undef _TO_STR
#endif
#define _TO_STR(n) #n
#if defined TO_STR
#undef TO_STR
#endif
#define TO_STR(n) _TO_STR(n)

struct pbkdf2_case {
	unsigned int level;
	const char *subcase_name;
	uint32_t algo;
	const uint8_t *password;
	size_t password_len;
	const uint8_t *salt;
	size_t salt_len;
	uint32_t iteration_count;
	const uint8_t *dkm;
	size_t dkm_len;
	bool run_test;
};

/* 15 - based off test #13 */
static const uint8_t __maybe_unused pbkdf2_15_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_15_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_15_iteration_count 4096
/* Derived with SHA512-224 */
static const uint8_t __maybe_unused pbkdf2_15_dkm[] = {
	0x57, 0x3D, 0xF9, 0x67, 0x62, 0xEA, 0x7D, 0xA4,
	0xF7, 0x12, 0x31, 0x85, 0x9C, 0xA2, 0x82, 0xEF,
	0x48, 0x27, 0x64, 0xAD, 0x96, 0x71, 0xC5, 0x27,
	0x5C
};

static const uint8_t __maybe_unused pbkdf2_15_dkm_aes_dummy[] = {
	0x8b, 0xa8, 0x39, 0x1f, 0xc0, 0xaa, 0xf4, 0x2d,
	0x5a, 0x5a, 0x93, 0x91, 0x0e, 0x26, 0xa2, 0x68,
	0x1b, 0x28, 0xee, 0x56, 0x51, 0x34, 0xf3, 0x9e,
	0xf5,
};

void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session);

/* The key handles implementation changes both the logic (further split for the
 * RAM key slots and NVM key slots) and the test vectors.
 */
static void xtest_pbkdf2_main_loop(ADBG_Case_t *c, TEEC_Session *session,
				   const struct pbkdf2_case *pc)
{
	return;
} /* xtest_pbkdf2_main_loop() */

/* Modified tests, using opaque key handles and involving an extra
 * verification step. Cases when the derived key's slot is stored in NVM
 * and in RAM are differentiated; in the former case, the application (here,
 * xtest) is required to preprovision the key; in the latter case, the OP-TEE
 * HSE driver allocates the key slot and returns it to the TA/xtest.
 *
 * xtest then takes an additional step of performing some crypto operation with
 * the indicated key handle and compare the result with its actual test vectors.
 */
static void do_pbkdf2_embed_keyhandles_nvm(ADBG_Case_t *c, TEEC_Session *session)
{
	// TODO
}

static void do_pbkdf2_embed_keyhandles_ram(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;

/* PBKDF2 Embedded Key Handles test, RAM key storage */
#define PBKDF2_EKH_RAM_TEST(l, n, algo, run) \
	TEST_PBKDF2_DATA(l, "RFC 6070 extension with RAM key handles " TO_STR(n) " (HMAC-SHAxxx)", \
			 algo, n, false, run)
	static struct pbkdf2_case pbkdf2_cases[] = {
		/* NOTE: HSE requires salt to be at least 16 bytes long, which
		 * is in violation of RFC6070.
		 */
		PBKDF2_EKH_RAM_TEST(0, 15, SHA1, true),
	};

	for (n = 0; n < sizeof(pbkdf2_cases) / sizeof(struct pbkdf2_case); n++) {
		const struct pbkdf2_case *pc = &pbkdf2_cases[n];

		if (!(pc->run_test))
			continue;
		if (pc->level > level)
			continue;

		xtest_pbkdf2_main_loop(c, session, pc);

		Do_ADBG_EndSubCase(c, "PBKDF2 %s", pc->subcase_name);
	}
}

void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session)
{
	do_pbkdf2_embed_keyhandles_nvm(c, session);
	do_pbkdf2_embed_keyhandles_ram(c, session);
}

#undef _TO_STR
#undef TO_STR
#undef TEST_PBKDF2_DATA
#endif /* CFG_HSE_EMBED_KEYHANDLES */
