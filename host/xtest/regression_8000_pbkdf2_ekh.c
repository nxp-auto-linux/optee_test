// SPDX-License-Identifier: GPL-2.0
/*
 * Helper code for PBKDF2 (regression 8000) in the HSE compile-time config
 * with embedded key handles support (CFG_HSE_EMBED_KEYHANDLES).
 * Moved to separate file to keep the original regression_8000.c manageable.
 *
 * Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright 2024 NXP
 */
#include "xtest_test.h"
#include "xtest_helpers.h"

#include <tee_api_defines.h>
#include <tee_api_defines_extensions.h>
#include <tee_api_types.h>
#include <tee_api_compat.h>
#include <utee_defines.h>
#include <string.h>
#include <malloc.h>
#include <util.h>
#include <assert.h>
#include <enc_fs_key_manager_test.h>
#include <ta_crypt.h>
/* Opportunistically include header for the definitions already used by
 * other tests (e.g. regressions 4019, 4020), to avoid duplication of
 * HSE definitions.
 *
 * TODO: To avoid duplication across tests, eventually the HSE data types used
 * by xtests should stay in a common header.
 * This also applies to the hse_magic definition below.
 */
#include <pta_hse_kp.h>


static const uint8_t hse_magic[] = {
	0xCA, 0xBF, 0x00, 0x1C, 0xCA, 0xBF, 0x54, 0x1C,
	0x39, 0x78, 0x04, 0xA3, 0x5A, 0x11, 0x24, 0x9F,
	0x64, 0xEE, 0x89, 0x23, 0x90, 0x8C, 0xF5, 0x64,
	0x9A, 0x8C, 0x7E, 0x35
};
#if defined HSE_MAGIC_SIZE
#undef HSE_MAGIC_SIZE
#endif
#define HSE_MAGIC_SIZE		ARRAY_SIZE(hse_magic)

/* These HSE types we redefine in-here for now. We don't want to modify
 * pta_hse_kp.h, which is not "our" header and is not even in this repository.
 */
typedef uint32_t hseKeyHandle_t;
typedef uint8_t hseKeyType_t;

/* Metadata shared between the host TA and the OP-TEE HSE driver. This is
 * transparent to both the Client API and the Internal Core API. Also, because
 * it is used by the HSE driver, it cannot be included from a common header, so
 * it must be duplicated instead.
 */
struct pbkdf2_in_metadata {
	hseKeyHandle_t key_handle;
	hseKeyType_t key_type;
};

struct pbkdf2_password_buf {
	struct pbkdf2_in_metadata metadata;
	/* allocated of size:
	 *   password_len - sizeof(struct pbkd2_in_metadata)
	 */
	uint8_t password[];
} __packed;

/* Despite it wrapping only the key handle (which is expectedly shorter than
 * a derived password), the entire buffer must be allocated (at least)
 * derived_key_len bytes, since that is the size OP-TEE will copy back
 * to the TA.
 */
struct pbkdf2_derived_key_buf {
	hseKeyHandle_t key_handle;
	/* allocated of size:
	 *   derived_key_len - sizeof(hseKeyHandle_t)
	 */
	uint8_t reserved[];
} __packed;

#define TEST_PBKDF2_DATA(level, section, algo, id, dk_type, run_test) \
	{ \
		level, \
		section, \
		run_test, \
		TEE_ALG_PBKDF2_HMAC_##algo##_DERIVE_KEY, \
		pbkdf2_##id##_password, \
		sizeof(pbkdf2_##id##_password), \
		pbkdf2_##id##_salt, \
		sizeof(pbkdf2_##id##_salt), \
		pbkdf2_##id##_iteration_count, \
		pbkdf2_##id##_dkm, \
		sizeof(pbkdf2_##id##_dkm), \
		HSE_KEY_TYPE_##dk_type, \
		!sizeof(pbkdf2_##id##_iv) ? NULL : pbkdf2_##id##_iv, \
		sizeof(pbkdf2_##id##_iv), \
		pbkdf2_##id##_plaintext, \
		sizeof(pbkdf2_##id##_plaintext), \
		pbkdf2_##id##_ciphertext, \
		sizeof(pbkdf2_##id##_ciphertext), \
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
	/*
	 * Test configuration & control
	 */
	unsigned int level;
	const char *subcase_name;
	bool run_test; /* a local flag to compound the global 'level' flag */
	/*
	 * PBKDF2 parameters
	 */
	uint32_t algo;		/* pbkdf2 algo */
	const uint8_t *password;
	size_t password_len;
	const uint8_t *salt;
	size_t salt_len;
	uint32_t iteration_count;
	const uint8_t *dkm;
	size_t dkm_len;		/* even though the return buffer contains a
				 * key handle instead of the actual bytes array,
				 * its allocated length reflects the requested
				 * key length
				 */
	/*
	 * Validation test vectors in the opaque key handles setup
	 */
	hseKeyType_t dkm_type; /* instruct the HSE driver to convert the
				* returned key to this type
				*/
	const uint8_t *iv;
	size_t iv_len;
	const uint8_t *plaintext;
	size_t plaintext_len;
	const uint8_t *ciphertext;
	size_t ciphertext_len;
};

/* Pick a key slot from the RAM catalog that is not managed by
 * the HSE driver. These configurations are static and must be kept
 * in sync:
 *  - The HSE catalog format, which is user-defined. Ours is in
 *    pkcs11-hse/examples/hse-secboot/keys-config.h
 *  - The OP-TEE HSE driver's key groups list - see hse-keygroup-define
 *    macros in core/drivers/crypto/hse/crypto.mk
 */
#define DUMMY_RAM_AES_KEY_HANDLE    GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_RAM, 0, 0)
#define DUMMY_RAM_HMAC_KEY_HANDLE   GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_RAM, 1, 0)
#define DUMMY_NVM_AES_KEY_HANDLE    GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 1, 0)
#define DUMMY_NVM_HMAC_KEY_HANDLE   GET_KEY_HANDLE(HSE_KEY_CATALOG_ID_NVM, 2, 0)

/* Test vectors for derived keys exported as AES key handles.
 * Inspired from RFC-6070 and the original regression_8000.c,
 * but here manually generated using openssl.
 *
 * NOTES:
 *  - HSE requires salt to be at least 16 bytes long, which is
 *    in violation of RFC6070.
 */
/* ***********************************************************/

/* 1005 */
#ifdef HSE_KDF_SHA_1 /* In newer firmware variants, this is obsolete */
static const uint8_t pbkdf2_1005_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1005_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1005_iteration_count 4096
/* Expected SHA1 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length
 */
static const uint8_t pbkdf2_1005_dkm[] = {
	0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b,
	0x80, 0xc8, 0xd8, 0x36, 0x62, 0xc0, 0xe4, 0x4a,
	0x8B, 0x29, 0x1A, 0x96, 0x4C, 0xF2, 0xF0, 0x70,
	0x38, 0xB6, 0xB8, 0x9A, 0x48, 0x61, 0x2C, 0x5A,
};
/* Will use AES-ECB, no need for iv */
static const uint8_t pbkdf2_1005_iv[] = {
};
/* The AES unit-test currently supports only blocksized text */
static const uint8_t pbkdf2_1005_plaintext[] = {
	'a', 'n', 't', 'h',
	'r', 'o', 'p', 'o',
	'm', 'o', 'r', 'p',
	'h', 'i', 's', 'm',
};
static const uint8_t pbkdf2_1005_ciphertext[] = {
	0xa5, 0xb1, 0x52, 0x19, 0xb5, 0xb2, 0x47, 0x27,
	0xaf, 0x61, 0xd4, 0xec, 0x0b, 0x2c, 0x47, 0x9d,
};
#endif /* HSE_KDF_SHA_1 */

/* 1006 */
static const uint8_t pbkdf2_1006_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1006_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1006_iteration_count 4096
/* Expected SHA256 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length
 */
static const uint8_t pbkdf2_1006_dkm[] = {
	0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
	0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
	0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
	0x1C, 0x4E, 0x2A, 0x1F, 0xB8, 0xDD, 0x53, 0xE1,
};
/* Will use AES-ECB, no need for iv */
static const uint8_t pbkdf2_1006_iv[] = {
};
/* The AES unit-test currently supports only blocksized text */
static const uint8_t pbkdf2_1006_plaintext[] = {
	'e', 'x', 't', 'r',
	'a', 't', 'e', 'r',
	'r', 'e', 's', 't',
	'r', 'i', 'a', 'l',
};
static const uint8_t pbkdf2_1006_ciphertext[] = {
	0x56, 0xc5, 0xd0, 0xd1, 0x82, 0xa4, 0x06, 0xf5,
	0xec, 0x12, 0x40, 0xef, 0xca, 0xa5, 0x19, 0xd8
};

/* 1007 */
static const uint8_t pbkdf2_1007_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1007_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1007_iteration_count 4096
/* Expected SHA512 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length
 */
static const uint8_t pbkdf2_1007_dkm[] = {
	0x8C, 0x05, 0x11, 0xF4, 0xC6, 0xE5, 0x97, 0xC6,
	0xAC, 0x63, 0x15, 0xD8, 0xF0, 0x36, 0x2E, 0x22,
	0x5F, 0x3C, 0x50, 0x14, 0x95, 0xBA, 0x23, 0xB8,
	0x68, 0xC0, 0x05, 0x17, 0x4D, 0xC4, 0xEE, 0x71,
};
/* Will use AES-ECB, no need for iv */
static const uint8_t pbkdf2_1007_iv[] = {
};
/* The AES unit-test currently supports only blocksized text */
static const uint8_t pbkdf2_1007_plaintext[] = {
	'c', 'h', 'e', 'm',
	'i', 'l', 'u', 'm',
	'i', 'n', 'e', 's',
	'c', 'e', 'n', 't'
};
static const uint8_t pbkdf2_1007_ciphertext[] = {
	0xe6, 0x23, 0x29, 0xbd, 0x8e, 0xc3, 0x01, 0xd8,
	0x8b, 0xee, 0xe8, 0x6b, 0x30, 0xbe, 0x65, 0x98,
};

/* 1008 */
static const uint8_t pbkdf2_1008_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1008_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1008_iteration_count 4096
/* Expected SHA512-256 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length
 */
static const uint8_t pbkdf2_1008_dkm[] = {
	0x31, 0xCF, 0x94, 0xE3, 0xD8, 0xE3, 0x6A, 0xA1,
	0x8D, 0x40, 0xAD, 0x92, 0x65, 0x4A, 0xB8, 0x0F,
	0x50, 0x0E, 0xD7, 0xFB, 0x57, 0x5A, 0x22, 0x15,
	0x54, 0x7D, 0xB6, 0xF8, 0x2D, 0xD2, 0x27, 0xED,
};
/* Will use AES-ECB, no need for iv */
static const uint8_t pbkdf2_1008_iv[] = {
};
/* The AES unit-test currently supports only blocksized text */
static const uint8_t pbkdf2_1008_plaintext[] = {
	'a', 'b', 's', 'e',
	'n', 't', 'm', 'i',
	'n', 'd', 'e', 'd',
	'n', 'e', 's', 's',
};
static const uint8_t pbkdf2_1008_ciphertext[] = {
	0xe4, 0x1e, 0x11, 0x8f, 0x7f, 0x22, 0x28, 0xa1,
	0x36, 0xd8, 0xbe, 0x58, 0x77, 0x8a, 0x30, 0x3d,
};
/* ***********************************************************/

/* Test vectors for derived keys exported as HMAC key handles.
 * Currently all of them are for HMAC-256. Note this (HMAC-256)
 * is independent of the actual PBKDF2 hash algorithm used for
 * generating the key in the first place.
 */
/* ***********************************************************/

/* 1106 */
static const uint8_t pbkdf2_1106_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1106_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1106_iteration_count 4096
/* Expected PBKDF2/SHA256 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length.
 *
 * Note: max supported by test is 32-byte, because of the particular
 * keygroup allocation (256-bit key slots) we are using.
 */
static const uint8_t pbkdf2_1106_dkm[] = {
	0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
	0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
	0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
	0x1C, 0x4E, 0x2A, 0x1F, 0xB8, 0xDD, 0x53, 0xE1,
};
static const uint8_t pbkdf2_1106_iv[] = {
};
static const uint8_t pbkdf2_1106_plaintext[] = {
	'p', 'h', 'y', 'l', 'o', 'g', 'e', 'n',
	'e', 't', 'i', 'c', 'a', 'l', 'l', 'y',

	'i', 'n', 'c', 'o', 'n', 't', 'r', 'o',
	'v', 'e', 'r', 't', 'i', 'b', 'l', 'e',

	'u', 'n', 'c', 'h', 'a', 'r', 'a', 'c',
	't', 'e', 'r', 'i', 's', 't', 'i', 'c',

	'p', 'h', 'o', 't', 'o', 'l', 'i', 't',
	'h', 'o', 'g', 'r', 'a', 'p', 'h', 'y'
};
/* Hashed with SHA256 (independently of the HMAC used for PBKDF2) */
static const uint8_t pbkdf2_1106_ciphertext[] = {
	0x3b, 0xc0, 0xe9, 0xde, 0x31, 0xe4, 0xad, 0x12,
	0xc2, 0xd3, 0xad, 0xa3, 0xa5, 0x1b, 0xb4, 0x1e,
	0x6d, 0x64, 0xf2, 0x7f, 0xb2, 0x75, 0x47, 0x53,
	0xb9, 0x8e, 0x45, 0xf3, 0xf3, 0x2c, 0x4d, 0x68
};

/* ***********************************************************/

/* 1107 */
static const uint8_t pbkdf2_1107_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};
static const uint8_t pbkdf2_1107_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};
#define pbkdf2_1107_iteration_count 4096
/* Expected PBKDF2/SHA512 derived key (but it cannot be directly verified).
 * Size of this array will indicate the required derived key length.
 *
 * Note: max supported by test is 32-byte, because of the particular
 * keygroup allocation (256-bit key slots) we are using.
 */
static const uint8_t pbkdf2_1107_dkm[] = {
	0x8C, 0x05, 0x11, 0xF4, 0xC6, 0xE5, 0x97, 0xC6,
	0xAC, 0x63, 0x15, 0xD8, 0xF0, 0x36, 0x2E, 0x22,
	0x5F, 0x3C, 0x50, 0x14, 0x95, 0xBA, 0x23, 0xB8,
	0x68, 0xC0, 0x05, 0x17, 0x4D, 0xC4, 0xEE, 0x71,
};
static const uint8_t pbkdf2_1107_iv[] = {
};
static const uint8_t pbkdf2_1107_plaintext[] = {
	'c', 'i', 'r', 'c', 'u', 'm', 's', 't',
	'a', 'n', 't', 'i', 'a', 'l', 'l', 'y',

	'd' ,'i', 's', 'p', 'r', 'o', 'p', 'o',
	'r', 't', 'i', 'o', 'n', 'a', 't', 'e',

	'f', 'i', 'c', 't', 'i', 'o' ,'n', 'a',
	'l', 'i', 's', 'a', 't', 'i', 'o', 'n'
};
/* Hashed with SHA256 (independently of the HMAC used for PBKDF2) */
static const uint8_t pbkdf2_1107_ciphertext[] = {
	0xba, 0x33, 0x4f, 0xd5, 0x8e, 0x1d, 0x81, 0x9d,
	0xcd, 0x6d, 0xc8, 0x8c, 0x73, 0xda, 0x31, 0x90,
	0xe7, 0x6d, 0xc5, 0xab, 0x00, 0xff, 0x3c, 0xbc,
	0x21, 0x0b, 0xd6, 0xd5, 0xd6, 0x76, 0xa0, 0xba
};

/* ***********************************************************/
/* Put the magic (metadata) and the key handle into the buffer, in preparation
 * for an HSE operation with opaque key handles support.
 *
 * The destination buffer keybuf must be of sufficient length to
 * accommodate the key handle and the magic.
 */
static void fill_hse_key_handle(uint8_t *keybuf, const hseKeyHandle_t *kh)
{
	memcpy(keybuf, hse_magic, HSE_MAGIC_SIZE);
	memcpy(keybuf + HSE_MAGIC_SIZE, kh, sizeof(*kh));
}

/*
 * Functions borrowed from regression_4000.c
 */

static TEEC_Result ta_crypt_cmd_cipher_init(ADBG_Case_t *c, TEEC_Session *s,
					    TEE_OperationHandle oph,
					    const void *iv, size_t iv_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_update(ADBG_Case_t *c, TEEC_Session *s,
					      TEE_OperationHandle oph,
					      const void *src, size_t src_len,
					      void *dst, size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result ta_crypt_cmd_cipher_do_final(ADBG_Case_t *c,
						TEEC_Session *s,
						TEE_OperationHandle oph,
						const void *src,
						size_t src_len,
						void *dst,
						size_t *dst_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)src;
	op.params[1].tmpref.size = src_len;

	op.params[2].tmpref.buffer = (void *)dst;
	op.params[2].tmpref.size = *dst_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_CIPHER_DO_FINAL, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
			    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*dst_len = op.params[2].tmpref.size;

	return res;
}

static TEEC_Result pta_hse_kp_cmd_key_erase(ADBG_Case_t *c, TEEC_Session *sess,
					    uint32_t hse_key_handle)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res;
	uint32_t ret_orig = 0;

	if (!sess)
		return TEEC_ERROR_BAD_PARAMETERS;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].value.a = hse_key_handle;

	res = TEEC_InvokeCommand(sess, PTA_CMD_KEY_ERASE,
				 &op, &ret_orig);
	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_init(ADBG_Case_t *c, TEEC_Session *s,
					 TEE_OperationHandle oph,
					 const void *iv, size_t iv_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	if (iv != NULL) {
		op.params[1].tmpref.buffer = (void *)iv;
		op.params[1].tmpref.size = iv_len;
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_MEMREF_TEMP_INPUT,
						 TEEC_NONE, TEEC_NONE);
	} else {
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
	}

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_INIT, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_update(ADBG_Case_t *c, TEEC_Session *s,
					   TEE_OperationHandle oph,
					   const void *chunk, size_t chunk_size)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_size;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_UPDATE, &op, &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	return res;
}

static TEEC_Result ta_crypt_cmd_mac_final_compute(ADBG_Case_t *c,
						  TEEC_Session *s,
						  TEE_OperationHandle oph,
						  const void *chunk,
						  size_t chunk_len,
						  void *hash,
						  size_t *hash_len)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	uint32_t ret_orig = 0;

	assert((uintptr_t)oph <= UINT32_MAX);
	op.params[0].value.a = (uint32_t)(uintptr_t)oph;

	op.params[1].tmpref.buffer = (void *)chunk;
	op.params[1].tmpref.size = chunk_len;

	op.params[2].tmpref.buffer = (void *)hash;
	op.params[2].tmpref.size = *hash_len;

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);

	res = TEEC_InvokeCommand(s, TA_CRYPT_CMD_MAC_FINAL_COMPUTE, &op,
				 &ret_orig);

	if (res != TEEC_SUCCESS) {
		(void)ADBG_EXPECT_TEEC_ERROR_ORIGIN(c, TEEC_ORIGIN_TRUSTED_APP,
						    ret_orig);
	}

	if (res == TEEC_SUCCESS)
		*hash_len = op.params[2].tmpref.size;

	return res;
}
/* ***********************************************************/

void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session);

/* Perform an indirect validation of the key pointed to (via its handle) by
 * hse_kh, by using it to encrypt a known buffer and comparing with the
 * expected result stored in *pc.
 * Heavily borrowed from xtest_4000.c's xtest_ciph_operation().
 */
static TEEC_Result pbkdf2_validate_aes_key_handle(ADBG_Case_t *c,
						  TEEC_Session *session,
						  const hseKeyHandle_t *hse_kh,
						  const struct pbkdf2_case *pc)
{
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle tee_kh = TEE_HANDLE_NULL;
	/* taken from test vectors data */
	const uint8_t *iv = pc->iv;
	size_t iv_len = pc->iv_len;
	const uint32_t mode = TEE_MODE_ENCRYPT;
	const uint32_t algo = TEE_ALG_AES_ECB_NOPAD;
	const uint32_t key_type = TEE_TYPE_AES;
	size_t ekh_key_size, ekh_key_size_bits;
	const uint8_t *plaintext = pc->plaintext;
	size_t plaintext_len = pc->plaintext_len;
	TEE_Attribute key_attr = {0};
	/* this is large enough to accommodate the "opaque key handle"
	 * buffer format
	 */
	const size_t max_aes_key_size = 32;
	/* to store the crypto op result */
	uint8_t out[2048] = {0};
	size_t out_len = sizeof(out);
	/* modified key handle buf for HSE operation */
	uint8_t *ekh;

	Do_ADBG_Log("Validating AES key handle 0x%x\n", *hse_kh);
	/* ekh will masquerade as the key buffer from here on, so far as the
	 * Internal Core API is concerned
	 */
	ekh_key_size = max_aes_key_size;
	assert(ekh_key_size >= HSE_MAGIC_SIZE + sizeof(hseKeyHandle_t));
	ekh = malloc(ekh_key_size);
	if (!ekh) {
		ret = TEEC_ERROR_OUT_OF_MEMORY;
		goto err_malloc;
	}
	fill_hse_key_handle(ekh, hse_kh);

	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = (void *)ekh;
	key_attr.content.ref.length = ekh_key_size;
	ekh_key_size_bits = key_attr.content.ref.length * 8;

	ret = ta_crypt_cmd_allocate_operation(c, session, &op, algo, mode,
					      ekh_key_size_bits);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_operation;

	ret = ta_crypt_cmd_allocate_transient_object(c, session, key_type,
						     ekh_key_size_bits, &tee_kh);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_transient_object;

	ret = ta_crypt_cmd_populate_transient_object(c, session, tee_kh,
						     &key_attr, 1);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_populate_transient_object;

	ret = ta_crypt_cmd_set_operation_key(c, session, op, tee_kh);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_set_operation_key;

	ret = ta_crypt_cmd_cipher_init(c, session, op, iv, iv_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_cipher_init;

	/* we'll test-encrypt exactly one block */
	ret = ta_crypt_cmd_cipher_update(c, session, op,
					 plaintext, plaintext_len,
					 out, &out_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_cipher_update;
	ADBG_EXPECT_COMPARE_UNSIGNED(c, out_len, ==, plaintext_len);

	/* because we have been encrypting exactly one AES block, 'do_final'
	 * isn't in fact performing any encryption
	 */
	ret = ta_crypt_cmd_cipher_do_final(c, session, op, plaintext + plaintext_len,
					   0, out + out_len, &out_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_cipher_do_final;

	ADBG_EXPECT_BUFFER(c, pc->ciphertext, pc->ciphertext_len, out, pc->ciphertext_len);

err_cipher_do_final:
err_cipher_update:
err_cipher_init:
err_set_operation_key:
err_populate_transient_object:
	ta_crypt_cmd_free_transient_object(c, session, tee_kh);
err_allocate_transient_object:
	ta_crypt_cmd_free_operation(c, session, op);
err_allocate_operation:
	free(ekh);
err_malloc:
	return ret;
} /* pbkdf2_validate_aes_key_handle() */

/* Perform an indirect validation of the key in the indicated key slot, by
 * using it to hash over a known buffer and comparing it with the expected
 * result from the *pc vector.
 */
static TEEC_Result pbkdf2_validate_hmac_key_handle(ADBG_Case_t *c,
						   TEEC_Session *session,
						   hseKeyHandle_t *kh,
						   const struct pbkdf2_case *pc)
{
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	TEE_Attribute key_attr = { } ;
	TEE_OperationHandle op;
	TEE_ObjectHandle tee_kh;
	const uint32_t algo = TEE_ALG_HMAC_SHA256;
	const uint32_t mode = TEE_MODE_MAC;
	const uint32_t key_type = TEE_TYPE_HMAC_SHA256;
	uint8_t out[32] = {0};
	size_t out_len = sizeof(out);
	/* Modified buffer for embedded key operation */
	uint8_t *ekh = NULL;
	size_t ekh_size = pc->dkm_len, ekh_size_bits;

	Do_ADBG_Log("Validating HMAC key handle 0x%x\n", *kh); usleep(100000);
	assert(ekh_size >= HSE_MAGIC_SIZE + sizeof(hseKeyHandle_t));
	ekh = malloc(ekh_size);
	if (!ekh) {
		return TEEC_ERROR_OUT_OF_MEMORY;
	}
	fill_hse_key_handle(ekh, kh);

	key_attr.attributeID = TEE_ATTR_SECRET_VALUE;
	key_attr.content.ref.buffer = ekh;
	key_attr.content.ref.length = ekh_size;
	ekh_size_bits = key_attr.content.ref.length * 8;

	ret = ta_crypt_cmd_allocate_operation(c, session, &op, algo, mode,
					      ekh_size_bits);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_operation;

	ret = ta_crypt_cmd_allocate_transient_object(c, session, key_type,
						     ekh_size_bits, &tee_kh);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_transient_object;

	ret = ta_crypt_cmd_populate_transient_object(c, session, tee_kh,
						     &key_attr, 1);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_populate_transient_object;

	ret = ta_crypt_cmd_set_operation_key(c, session, op, tee_kh);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_set_operation_key;

	ret = ta_crypt_cmd_mac_init(c, session, op, NULL, 0);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_mac_init;

	/* Will process exactly one block. With our hard-coded SHA256 (see algo
	 * and key_type), that would be 64-byte. */
	ret = ta_crypt_cmd_mac_update(c, session, op, pc->plaintext,
				      pc->plaintext_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_mac_update;

	ret = ta_crypt_cmd_mac_final_compute(c, session, op,
					     pc->plaintext + pc->plaintext_len,
					     0,
					     out, &out_len);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_mac_final_compute;

	ADBG_EXPECT_BUFFER(c, pc->ciphertext, pc->ciphertext_len, out, out_len);

err_mac_final_compute:
err_mac_update:
err_mac_init:
err_set_operation_key:
err_populate_transient_object:
	ta_crypt_cmd_free_transient_object(c, session, tee_kh);
err_allocate_transient_object:
	ta_crypt_cmd_free_operation(c, session, op);
err_allocate_operation:
	free(ekh);

	return ret;
} /* pbkdf2_validate_hmac_key_handle() */

static void xtest_pbkdf2_main_ram_loop(ADBG_Case_t *c, TEEC_Session *session,
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
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	/* embedded key handle password buf */
	struct pbkdf2_password_buf *ekh_pwd = NULL;
	size_t ekh_pwd_len;
	/* expected return buffer */
	struct pbkdf2_derived_key_buf *ekh_dkm = NULL;
	hseKeyHandle_t derived_kh;
	hseKeyHandle_t dummy_ram_key_handle;


	switch(pc->dkm_type) {
	case HSE_KEY_TYPE_AES:
		dummy_ram_key_handle = DUMMY_RAM_AES_KEY_HANDLE;
		break;
	case HSE_KEY_TYPE_HMAC:
		dummy_ram_key_handle = DUMMY_RAM_HMAC_KEY_HANDLE;
		break;
	default:
		ret = TEEC_ERROR_NOT_IMPLEMENTED;
		goto out;
	}

	Do_ADBG_BeginSubCase(c, "PBKDF2 %s", pc->subcase_name);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, session, &op,
			pc->algo, TEE_MODE_DERIVE, max_size)))
		return;

	ret = ta_crypt_cmd_allocate_transient_object(c, session,
						     TEE_TYPE_PBKDF2_PASSWORD,
						     max_size,
						     &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_transient_object;

	/* Allocate metadata and the actual password */
	ekh_pwd_len = pc->password_len + sizeof(ekh_pwd->metadata);
	ekh_pwd = malloc(ekh_pwd_len);
	if (!ekh_pwd) {
		ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_ERROR_OUT_OF_MEMORY);
		goto err_malloc;
	}
	/* Fill in the password */
	memcpy(ekh_pwd->password, pc->password, pc->password_len);
	/* Fill in the metadata */
	ekh_pwd->metadata.key_handle = dummy_ram_key_handle;
	ekh_pwd->metadata.key_type = pc->dkm_type;

	xtest_add_attr(&param_count, params, TEE_ATTR_PBKDF2_PASSWORD,
	       ekh_pwd, ekh_pwd_len);

	ret = ta_crypt_cmd_populate_transient_object(c, session, key_handle,
						     params, param_count);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_set_operation_key(c, session, op, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_free_transient_object(c, session, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_allocate_transient_object(c, session,
						    TEE_TYPE_GENERIC_SECRET,
						    pc->dkm_len * 8,
						    &sv_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	param_count = 0;
	if (pc->salt)
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_PBKDF2_SALT, pc->salt,
			       pc->salt_len);
	xtest_add_attr_value(&param_count, params, TEE_ATTR_PBKDF2_DKM_LENGTH,
			     pc->dkm_len, 0);
	xtest_add_attr_value(&param_count, params,
			    TEE_ATTR_PBKDF2_ITERATION_COUNT,
			    pc->iteration_count, 0);

	ret = ta_crypt_cmd_derive_key(c, session, op, sv_handle, params,
				      param_count);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	ret = ta_crypt_cmd_get_object_buffer_attribute(c, session, sv_handle,
						       TEE_ATTR_SECRET_VALUE,
						       out, &out_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ekh_dkm = (struct pbkdf2_derived_key_buf *)out;
	derived_kh = ekh_dkm->key_handle;
	/* Validate what we got */
	switch (pc->dkm_type) {
	case HSE_KEY_TYPE_AES:
		ret = pbkdf2_validate_aes_key_handle(c, session, &derived_kh, pc);
		break;
	case HSE_KEY_TYPE_HMAC:
		ret = pbkdf2_validate_hmac_key_handle(c, session, &derived_kh, pc);
		break;
	default:
		ret = TEEC_ERROR_NOT_IMPLEMENTED;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, ret);

out:
	free(ekh_pwd);
err_malloc:
	ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, session, sv_handle));
err_allocate_transient_object:
	ADBG_EXPECT_TEEC_SUCCESS(c,
		 ta_crypt_cmd_free_operation(c, session, op));
} /* xtest_pbkdf2_main_ram_loop() */

static void xtest_pbkdf2_main_nvm_loop(ADBG_Case_t *c, TEEC_Session *session,
				       const struct pbkdf2_case *pc,
				       TEEC_Session *dummy_key_session)
{
	TEE_OperationHandle op = TEE_HANDLE_NULL;
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
	TEE_Attribute params[4] = { };
	size_t param_count = 0;
	uint8_t out[2048] = { };
	size_t out_size = 0;
	size_t max_size = 2048;
	TEEC_Result ret = TEEC_ERROR_GENERIC;
	/* embedded key handle password buf */
	struct pbkdf2_password_buf *ekh_pwd = NULL;
	size_t ekh_pwd_len;
	/* expected return buffer */
	struct pbkdf2_derived_key_buf *ekh_dkm = NULL;
	hseKeyHandle_t derived_kh;
	hseKeyHandle_t dummy_nvm_key_handle = DUMMY_NVM_AES_KEY_HANDLE;

	Do_ADBG_BeginSubCase(c, "PBKDF2 %s", pc->subcase_name);

	/* Make sure the NVM key slot is erased */
	ADBG_EXPECT_TEEC_SUCCESS(c, pta_hse_kp_cmd_key_erase(c,
						dummy_key_session,
						dummy_nvm_key_handle));

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_allocate_operation(c, session, &op,
			pc->algo, TEE_MODE_DERIVE, max_size)))
		return;

	ret = ta_crypt_cmd_allocate_transient_object(c, session,
						     TEE_TYPE_PBKDF2_PASSWORD,
						     max_size,
						     &key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto err_allocate_transient_object;

	/* Allocate metadata and the actual password */
	ekh_pwd_len = pc->password_len + sizeof(ekh_pwd->metadata);
	ekh_pwd = malloc(ekh_pwd_len);
	if (!ekh_pwd) {
		ADBG_EXPECT_TEEC_SUCCESS(c, TEEC_ERROR_OUT_OF_MEMORY);
		goto err_malloc;
	}
	/* Fill in the password */
	memcpy(ekh_pwd->password, pc->password, pc->password_len);
	/* Fill in the metadata */
	ekh_pwd->metadata.key_handle = dummy_nvm_key_handle;
	ekh_pwd->metadata.key_type = pc->dkm_type;

	xtest_add_attr(&param_count, params, TEE_ATTR_PBKDF2_PASSWORD,
	       ekh_pwd, ekh_pwd_len);

	ret = ta_crypt_cmd_populate_transient_object(c, session, key_handle,
						     params, param_count);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_set_operation_key(c, session, op, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_free_transient_object(c, session, key_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ret = ta_crypt_cmd_allocate_transient_object(c, session,
						    TEE_TYPE_GENERIC_SECRET,
						    pc->dkm_len * 8,
						    &sv_handle);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	param_count = 0;
	if (pc->salt)
		xtest_add_attr(&param_count, params,
			       TEE_ATTR_PBKDF2_SALT, pc->salt,
			       pc->salt_len);
	xtest_add_attr_value(&param_count, params, TEE_ATTR_PBKDF2_DKM_LENGTH,
			     pc->dkm_len, 0);
	xtest_add_attr_value(&param_count, params,
			    TEE_ATTR_PBKDF2_ITERATION_COUNT,
			    pc->iteration_count, 0);

	ret = ta_crypt_cmd_derive_key(c, session, op, sv_handle, params,
				      param_count);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	out_size = sizeof(out);
	memset(out, 0, sizeof(out));
	ret = ta_crypt_cmd_get_object_buffer_attribute(c, session, sv_handle,
						       TEE_ATTR_SECRET_VALUE,
						       out, &out_size);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	ekh_dkm = (struct pbkdf2_derived_key_buf *)out;
	derived_kh = ekh_dkm->key_handle;
	/* Validate what we got */
	switch (pc->dkm_type) {
	case HSE_KEY_TYPE_AES:
		ret = pbkdf2_validate_aes_key_handle(c, session, &derived_kh, pc);
		break;
	case HSE_KEY_TYPE_HMAC:
		ret = pbkdf2_validate_hmac_key_handle(c, session, &derived_kh, pc);
		break;
	default:
		ret = TEEC_ERROR_NOT_IMPLEMENTED;
	}
	ADBG_EXPECT_TEEC_SUCCESS(c, ret);

out:
	free(ekh_pwd);
err_malloc:
	ADBG_EXPECT_TEEC_SUCCESS(c,
		ta_crypt_cmd_free_transient_object(c, session, sv_handle));
err_allocate_transient_object:
	ADBG_EXPECT_TEEC_SUCCESS(c,
		 ta_crypt_cmd_free_operation(c, session, op));
} /* xtest_pbkdf2_main_nvm_loop() */

/* Modified tests, using opaque key handles and involving an extra
 * verification step of performing some crypto operation with
 * the indicated key handle and compare the result with its actual
 * test vectors.
 */
static void do_pbkdf2_embed_keyhandles_nvm(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
	TEEC_Session dummy_key_session = { };
	uint32_t origin = 0;
	TEEC_Result ret = TEEC_ERROR_GENERIC;
#define PBKDF2_EKH_NVM_TEST(l, n, algo, dk_type, run) \
	TEST_PBKDF2_DATA(l, "RFC 6070 extension with NVM key handles " TO_STR(n) " (HMAC-SHAxxx)", \
			 algo, n, dk_type, run)
	static struct pbkdf2_case pbkdf2_cases[] = {
#ifdef HSE_KDF_SHA_1 /* In newer firmware variants, this is obsolete */
		PBKDF2_EKH_NVM_TEST(0, 1005, SHA1, AES, true),
#endif
		PBKDF2_EKH_NVM_TEST(0, 1006, SHA256,     AES, true),
		PBKDF2_EKH_NVM_TEST(0, 1007, SHA512,     AES, true),
		PBKDF2_EKH_NVM_TEST(0, 1008, SHA512_256, AES, true),
	};

	ret = xtest_teec_open_session(&dummy_key_session, &pta_hse_kp_uuid,
				      NULL, &origin);
	if (!ADBG_EXPECT_TEEC_SUCCESS(c, ret))
		goto out;

	for (n = 0; n < sizeof(pbkdf2_cases) / sizeof(struct pbkdf2_case); n++) {
		const struct pbkdf2_case *pc = &pbkdf2_cases[n];

		if (!(pc->run_test))
			continue;
		if (pc->level > level)
			continue;

		xtest_pbkdf2_main_nvm_loop(c, session, pc, &dummy_key_session);

		Do_ADBG_EndSubCase(c, "PBKDF2 %s", pc->subcase_name);
	}
out:
	TEEC_CloseSession(&dummy_key_session);
	return;
}

static void do_pbkdf2_embed_keyhandles_ram(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n;
/* PBKDF2 Embedded Key Handles test, RAM key storage */
#define PBKDF2_EKH_RAM_TEST(l, n, algo, dk_type, run) \
	TEST_PBKDF2_DATA(l, "RFC 6070 extension with RAM key handles " TO_STR(n) " (HMAC-SHAxxx)", \
			 algo, n, dk_type, run)
	static struct pbkdf2_case pbkdf2_cases[] = {
#ifdef HSE_KDF_SHA_1 /* In newer firmware variants, this is obsolete */
		PBKDF2_EKH_RAM_TEST(0, 1005, SHA1,       AES, true),
#endif
		PBKDF2_EKH_RAM_TEST(0, 1006, SHA256,     AES, true),
		PBKDF2_EKH_RAM_TEST(0, 1007, SHA512,     AES, true),
		PBKDF2_EKH_RAM_TEST(0, 1008, SHA512_256, AES, true),
		PBKDF2_EKH_RAM_TEST(0, 1106, SHA256,    HMAC, true),
		PBKDF2_EKH_RAM_TEST(0, 1107, SHA512,    HMAC, true),
	};

	for (n = 0; n < sizeof(pbkdf2_cases) / sizeof(struct pbkdf2_case); n++) {
		const struct pbkdf2_case *pc = &pbkdf2_cases[n];

		if (!(pc->run_test))
			continue;
		if (pc->level > level)
			continue;

		xtest_pbkdf2_main_ram_loop(c, session, pc);

		Do_ADBG_EndSubCase(c, "PBKDF2 %s", pc->subcase_name);
	}
}

void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session)
{
	do_pbkdf2_embed_keyhandles_nvm(c, session);
	do_pbkdf2_embed_keyhandles_ram(c, session);
}
