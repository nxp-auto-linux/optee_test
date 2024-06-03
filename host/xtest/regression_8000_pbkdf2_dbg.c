// SPDX-License-Identifier: GPL-2.0
/*
 * Helper code for PBKDF2 (regression 8000) in the HSE debug/test compile-time
 * configuration (CFG_HSE_PBKDF2_EXPORT_DERIVED_KEY_DBG).
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


#define TEST_PBKDF2_DATA(level, section, algo, id, oeb /* omit empty bufs */, run_test) \
	{ \
		level, section, TEE_ALG_PBKDF2_HMAC_##algo##_DERIVE_KEY, \
		pbkdf2_##id##_password, sizeof(pbkdf2_##id##_password), \
		(oeb && !sizeof(pbkdf2_##id##_salt)) ? NULL : pbkdf2_##id##_salt, sizeof(pbkdf2_##id##_salt), \
		pbkdf2_##id##_iteration_count, \
		pbkdf2_##id##_dkm_aes_dummy, sizeof(pbkdf2_##id##_dkm_aes_dummy), \
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

/*
 * NXP S32G note: unfortunately, with HSE most of the default test vectors
 * are not supported, because they don't meet HSE's minimum length conditions.
 * From the standard set of 6 vectors, only vector #5 as-is meets the
 * length criteria, so we'll just come up with a different set of vectors,
 * double-checked against open-source precomputed test vectors.
 */

/* 5 */
static const uint8_t __maybe_unused pbkdf2_5_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_5_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_5_iteration_count 4096
static const uint8_t __maybe_unused pbkdf2_5_dkm[] = {
	0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
	0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
	0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
	0x38
};
/* HSE will not export any key material (including ones resulted from key derivation)
 * unencrypted. So strictly for the purposes of unit-testing, we are encrypting
 * the PBKDF2 derived key with a dummy, 256-bit, all-zero, AES-CTR key.
 *
 * This here is `pbkdf2_5_dkm` encrypted with that dummy key.
 *
 * NOTE: because of this hack, the unit test should allocate a buffer large enough
 * to accommodate the *encrypted* version of the expected derived key.
 */
/* Derived with SHA1 */
static const uint8_t __maybe_unused pbkdf2_5_dkm_aes_dummy[] = {
	0xe1, 0xbb, 0x2c, 0x37, 0x46, 0x5c, 0x0d, 0x12,
	0x2d, 0x80, 0x7a, 0x22, 0xf0, 0x44, 0xc4, 0xcd,
	0xd8, 0x26, 0x90, 0x6d, 0x8b, 0xb7, 0xc6, 0xc9,
	0x91,
};

/* 7 */
/* This is basically test #5, only with different SHA */
static const uint8_t __maybe_unused pbkdf2_7_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_7_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_7_iteration_count 4096
/* Derived with SHA256 */
static const uint8_t __maybe_unused pbkdf2_7_dkm[] = {
	0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
	0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
	0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
	0x1C
};

static const uint8_t __maybe_unused pbkdf2_7_dkm_aes_dummy[] = {
	0xe8, 0x19, 0x49, 0xa3, 0x69, 0x93, 0xa2, 0xa6,
	0x9f, 0x90, 0xb6, 0xac, 0x83, 0xea, 0xa4, 0x48,
	0x78, 0x18, 0xbe, 0x85, 0x7b, 0x5d, 0x36, 0xa1,
	0xb5,
};

/* 8 */
static const uint8_t __maybe_unused pbkdf2_8_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_8_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_8_iteration_count 10000
/* Derived with SHA256 */
static const uint8_t __maybe_unused pbkdf2_8_dkm[] = {
	0x96, 0xE1, 0x7B, 0x0C, 0x4E, 0x3C, 0x0C, 0x08,
	0xDB, 0x3B, 0xE7, 0x09, 0xDF, 0x3D, 0xB5, 0xC1,
	0xEF, 0xB0, 0xC8, 0xA7, 0xEA, 0xA4, 0xFC, 0x65,
	0x17
};

static const uint8_t __maybe_unused pbkdf2_8_dkm_aes_dummy[] = {
	0x4a, 0x74, 0xbb, 0x74, 0xec, 0x7c, 0x85, 0x81,
	0x76, 0x73, 0x45, 0x1d, 0x4d, 0xb9, 0x95, 0x46,
	0xbc, 0xbf, 0x42, 0x5c, 0x2d, 0xe1, 0xca, 0xdc,
	0xbe,
};

/* 9 */
static const uint8_t __maybe_unused pbkdf2_9_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_9_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_9_iteration_count 4096
/* Cannot put an empty string here. The actual size of this array is taken
 * by the OP-TEE HSE driver as the requested output key length.
 */
/* Derived with SHA512 */
static const uint8_t __maybe_unused pbkdf2_9_dkm[] = {
	0x8C, 0x05, 0x11, 0xF4, 0xC6, 0xE5, 0x97, 0xC6,
	0xAC, 0x63, 0x15, 0xD8, 0xF0, 0x36, 0x2E, 0x22,
	0x5F, 0x3C, 0x50, 0x14, 0x95, 0xBA, 0x23, 0xB8,
	0x68
};

static const uint8_t __maybe_unused pbkdf2_9_dkm_aes_dummy[] = {
	0x50, 0x90, 0xd1, 0x8c, 0x64, 0xa5, 0x1e, 0x4f,
	0x01, 0x2b, 0xb7, 0xcc, 0x62, 0xb2, 0x0e, 0xa5,
	0x0c, 0x33, 0xda, 0xef, 0x52, 0xff, 0x15, 0x01,
	0xc1,
};

/* 10 */
static const uint8_t __maybe_unused pbkdf2_10_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_10_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_10_iteration_count 4096
/* Cannot put an empty string here. The actual size of this array is taken
 * by the OP-TEE HSE driver as the requested output key length.
 */
/* Derived with SHA224 */
static const uint8_t __maybe_unused pbkdf2_10_dkm[] = {
	0x05, 0x6C, 0x4B, 0xA4, 0x38, 0xDE, 0xD9, 0x1F,
	0xC1, 0x4E, 0x05, 0x94, 0xE6, 0xF5, 0x2B, 0x87,
	0xE1, 0xF3, 0x69, 0x0C, 0x0D, 0xC0, 0xFB, 0xC0,
	0x57
};

static const uint8_t __maybe_unused pbkdf2_10_dkm_aes_dummy[] = {
	0xd9, 0xf9, 0x8b, 0xdc, 0x9a, 0x9e, 0x50, 0x96,
	0x6c, 0x06, 0xa7, 0x80, 0x74, 0x71, 0x0b, 0x00,
	0xb2, 0xfc, 0xe3, 0xf7, 0xca, 0x85, 0xcd, 0x79,
	0xfe,
};

/* 11 */
static const uint8_t __maybe_unused pbkdf2_11_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_11_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_11_iteration_count 4096
/* Cannot put an empty string here. The actual size of this array is taken
 * by the OP-TEE HSE driver as the requested output key length.
 */
/* Derived with SHA384 */
static const uint8_t __maybe_unused pbkdf2_11_dkm[] = {
	0x81, 0x91, 0x43, 0xAD, 0x66, 0xDF, 0x9A, 0x55,
	0x25, 0x59, 0xB9, 0xE1, 0x31, 0xC5, 0x2A, 0xE6,
	0xC5, 0xC1, 0xB0, 0xEE, 0xD1, 0x8F, 0x4D, 0x28,
	0x3
};

static const uint8_t __maybe_unused pbkdf2_11_dkm_aes_dummy[] = {
	0x5d, 0x04, 0x83, 0xd5, 0xc4, 0x9f, 0x13, 0xdc,
	0x88, 0x11, 0x1b, 0xf5, 0xa3, 0x41, 0x0a, 0x61,
	0x96, 0xce, 0x3a, 0x15, 0x16, 0xca, 0x7b, 0x91,
	0x92,
};

/* 12 */
static const uint8_t __maybe_unused pbkdf2_12_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_12_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_12_iteration_count 4096
/* Cannot put an empty string here. The actual size of this array is taken
 * by the OP-TEE HSE driver as the requested output key length.
 */
/* Derived with SHA512-256 */
static const uint8_t __maybe_unused pbkdf2_12_dkm[] = {
	0x31, 0xCF, 0x94, 0xE3, 0xD8, 0xE3, 0x6A, 0xA1,
	0x8D, 0x40, 0xAD, 0x92, 0x65, 0x4A, 0xB8, 0x0F,
	0x50, 0x0E, 0xD7, 0xFB, 0x57, 0x5A, 0x22, 0x15,
	0x54
};

static const uint8_t __maybe_unused pbkdf2_12_dkm_aes_dummy[] = {
	0xed, 0x5a, 0x54, 0x9b, 0x7a, 0xa3, 0xe3, 0x28,
	0x20, 0x08, 0x0f, 0x86, 0xf7, 0xce, 0x98, 0x88,
	0x03, 0x01, 0x5d, 0x00, 0x90, 0x1f, 0x14, 0xac,
	0xfd,
};

/* 13 */
static const uint8_t __maybe_unused pbkdf2_13_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_13_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_13_iteration_count 4096
/* Cannot put an empty string here. The actual size of this array is taken
 * by the OP-TEE HSE driver as the requested output key length.
 */
/* Derived with SHA512-224 */
static const uint8_t __maybe_unused pbkdf2_13_dkm[] = {
	0x57, 0x3D, 0xF9, 0x67, 0x62, 0xEA, 0x7D, 0xA4,
	0xF7, 0x12, 0x31, 0x85, 0x9C, 0xA2, 0x82, 0xEF,
	0x48, 0x27, 0x64, 0xAD, 0x96, 0x71, 0xC5, 0x27,
	0x5C
};

static const uint8_t __maybe_unused pbkdf2_13_dkm_aes_dummy[] = {
	0x8b, 0xa8, 0x39, 0x1f, 0xc0, 0xaa, 0xf4, 0x2d,
	0x5a, 0x5a, 0x93, 0x91, 0x0e, 0x26, 0xa2, 0x68,
	0x1b, 0x28, 0xee, 0x56, 0x51, 0x34, 0xf3, 0x9e,
	0xf5,
};

/* 14 */
static const uint8_t __maybe_unused pbkdf2_14_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __maybe_unused pbkdf2_14_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_14_iteration_count 8192
/* Derived with SHA1 */
static const uint8_t __maybe_unused pbkdf2_14_dkm[] = {
	0xBF, 0x23, 0x01, 0x2D, 0xB2, 0x0B, 0xC1, 0xB1,
	0x47, 0x6D, 0xE4, 0x3B, 0x3D, 0xD8, 0x53, 0x7A,
	0x34, 0x89, 0x0E, 0xC6, 0xDD, 0x22, 0x22, 0x14,
	0xB8, 0x1B, 0x47, 0x4D, 0xA7, 0x88, 0x84, 0xAB,
	0xF8, 0x19, 0xA5, 0x05, 0x47, 0x44, 0xA3, 0x69,
	0x77, 0xFF, 0x57, 0xC0, 0x6D, 0x64, 0xAF, 0x3D,
	0x9A, 0x16, 0x0D, 0x3A, 0x2B, 0x35, 0xD1, 0x74,
	0x38, 0x1C, 0x56, 0x09, 0x9B, 0x84, 0x4E, 0x6A
};

static const uint8_t __maybe_unused pbkdf2_14_dkm_aes_dummy[] = {
	0x63, 0xb6, 0xc1, 0x55, 0x10, 0x4b, 0x48, 0x38,
	0xea, 0x25, 0x46, 0x2f, 0xaf, 0x5c, 0x73, 0xfd,
	0x67, 0x86, 0x84, 0x3d, 0x1a, 0x67, 0x14, 0xad,
	0x11, 0x78, 0xf3, 0xbc, 0x63, 0x43, 0xf7, 0x20,
	0x36, 0xbe, 0xe5, 0x38, 0x0a, 0x24, 0xc8, 0x07,
	0x70, 0xb1, 0x92, 0x13, 0xd7, 0x97, 0x32, 0x25,
	0xe8, 0x76, 0x0e, 0xf0, 0x1c, 0x93, 0xfb, 0x00,
	0xe9, 0xbe, 0xa3, 0x87, 0xee, 0x82, 0x7b, 0xe4,
};

void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session);

/* This is the same implementation as in the default/software fallback
 * configuration (the one without HSE support). Duplicated for simplicity.
 */
static void xtest_pbkdf2_main_loop(ADBG_Case_t *c, TEEC_Session *session,
				   const struct pbkdf2_case *pc)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[4] = { };
	size_t param_count = 0;
	uint8_t out[2048] = { };
	size_t out_size = 0;
	size_t max_size = 2048;

	Do_ADBG_BeginSubCase(c, "PBKDF2 %s", pc->subcase_name);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, session, &op,
			pc->algo, TEE_MODE_DERIVE, max_size)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, session,
			TEE_TYPE_PBKDF2_PASSWORD, max_size,
			&key_handle)))
		return;

	xtest_add_attr(&param_count, params, TEE_ATTR_PBKDF2_PASSWORD,
		       pc->password, pc->password_len);

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_populate_transient_object(c, session,
			key_handle, params, param_count)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_set_operation_key(c, session, op,
					       key_handle)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, session,
						   key_handle)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_transient_object(c, session,
			TEE_TYPE_GENERIC_SECRET, pc->dkm_len * 8,
			&sv_handle)))
		return;

	param_count = 0;

	if (pc->salt)
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_PBKDF2_SALT, pc->salt,
			       pc->salt_len);

	params[param_count].attributeID = TEE_ATTR_PBKDF2_DKM_LENGTH;
	params[param_count].content.value.a = pc->dkm_len;
	params[param_count].content.value.b = 0;
	param_count++;

	params[param_count].attributeID =
		TEE_ATTR_PBKDF2_ITERATION_COUNT;
	params[param_count].content.value.a = pc->iteration_count;
	params[param_count].content.value.b = 0;
	param_count++;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_derive_key(c, session, op, sv_handle,
					params, param_count)))
		return;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_get_object_buffer_attribute(c, session,
					sv_handle, TEE_ATTR_SECRET_VALUE,
					out, &out_size)))
		return;

	if (!ADBG_EXPECT_BUFFER(c, pc->dkm, pc->dkm_len, out, out_size))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_operation(c, session, op)))
		return;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, session,
						   sv_handle)))
		return;
} /* xtest_pbkdf2_main_loop() */

/* The OP-TEE HSE driver may be configured in debug mode, so we use a modified
 * variant of the xtest test case.
 */
void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
#define RFC6070_TEST(l, n, algo, run) \
	TEST_PBKDF2_DATA(l, "RFC 6070 extension " TO_STR(n) " (HMAC-SHAxxx)", \
			 algo, n, false, run)
	static struct pbkdf2_case pbkdf2_cases[] = {
		/* NOTE: HSE requires salt to be at least 16 bytes long, which
		 * is in violation of RFC6070.
		 */
		/* 25-byte output key */
		RFC6070_TEST(0, 5, SHA1, true),
		RFC6070_TEST(0, 7, SHA256, true),
		RFC6070_TEST(0, 8, SHA256, true),
		RFC6070_TEST(0, 9, SHA512, true),
		RFC6070_TEST(0, 10, SHA224, true),
		RFC6070_TEST(0, 11, SHA384, true),
		RFC6070_TEST(0, 12, SHA512_256, true),
		RFC6070_TEST(0, 13, SHA512_224, true),
		/* 64-byte output key */
		/* FIXME test currently disabled */
		RFC6070_TEST(0, 14, SHA1, false),
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
} /* xtest_test_derivation_pbkdf2() */

#undef _TO_STR
#undef TO_STR
#undef TEST_PBKDF2_DATA
