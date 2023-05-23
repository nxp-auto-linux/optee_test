// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014, Linaro Limited
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
#include <enc_fs_key_manager_test.h>

#define WITH_HKDF 1
#define WITH_CONCAT_KDF 1
#define WITH_PBKDF2 1

/*
 * HKDF test data from RFC 5869
 */

/* A.1 SHA-256 */

#if (WITH_HKDF == 1)
static const uint8_t hkdf_a1_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
};

static const uint8_t hkdf_a1_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t hkdf_a1_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9
};

static const uint8_t hkdf_a1_okm[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
	0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
	0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
	0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65
};

#if !defined(CFG_NXP_HSE) || CFG_HSE_PREMIUM_FW
/* A.2 SHA-256 */
static const uint8_t hkdf_a2_ikm[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const uint8_t hkdf_a2_salt[] = {
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf
};

static const uint8_t hkdf_a2_info[] = {
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

static const uint8_t hkdf_a2_okm[] = {
	0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
	0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
	0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
	0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
	0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
	0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
	0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
	0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
	0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
	0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
	0x1d, 0x87
};
#endif
/* A.3 SHA-256 */
#define hkdf_a3_ikm hkdf_a1_ikm
static const uint8_t hkdf_a3_salt[] = {};

static const uint8_t hkdf_a3_info[] = {};

static const uint8_t hkdf_a3_okm[] = {
	0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
	0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
	0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
	0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
	0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
	0x96, 0xc8
};

/* A.4 SHA-1 */
static const uint8_t hkdf_a4_ikm[] = {
	0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
	0x0b, 0x0b, 0x0b
};

static const uint8_t hkdf_a4_salt[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c
};

static const uint8_t hkdf_a4_info[] = {
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9
};

static const uint8_t hkdf_a4_okm[] = {
	0x08, 0x5a, 0x01, 0xea, 0x1b, 0x10, 0xf3, 0x69,
	0x33, 0x06, 0x8b, 0x56, 0xef, 0xa5, 0xad, 0x81,
	0xa4, 0xf1, 0x4b, 0x82, 0x2f, 0x5b, 0x09, 0x15,
	0x68, 0xa9, 0xcd, 0xd4, 0xf1, 0x55, 0xfd, 0xa2,
	0xc2, 0x2e, 0x42, 0x24, 0x78, 0xd3, 0x05, 0xf3,
	0xf8, 0x96
};

#if !defined(CFG_NXP_HSE) || CFG_HSE_PREMIUM_FW
/* A.5 SHA-1 */
#define hkdf_a5_ikm hkdf_a2_ikm
#define hkdf_a5_salt hkdf_a2_salt
#define hkdf_a5_info hkdf_a2_info
static const uint8_t hkdf_a5_okm[] = {
	0x0b, 0xd7, 0x70, 0xa7, 0x4d, 0x11, 0x60, 0xf7,
	0xc9, 0xf1, 0x2c, 0xd5, 0x91, 0x2a, 0x06, 0xeb,
	0xff, 0x6a, 0xdc, 0xae, 0x89, 0x9d, 0x92, 0x19,
	0x1f, 0xe4, 0x30, 0x56, 0x73, 0xba, 0x2f, 0xfe,
	0x8f, 0xa3, 0xf1, 0xa4, 0xe5, 0xad, 0x79, 0xf3,
	0xf3, 0x34, 0xb3, 0xb2, 0x02, 0xb2, 0x17, 0x3c,
	0x48, 0x6e, 0xa3, 0x7c, 0xe3, 0xd3, 0x97, 0xed,
	0x03, 0x4c, 0x7f, 0x9d, 0xfe, 0xb1, 0x5c, 0x5e,
	0x92, 0x73, 0x36, 0xd0, 0x44, 0x1f, 0x4c, 0x43,
	0x00, 0xe2, 0xcf, 0xf0, 0xd0, 0x90, 0x0b, 0x52,
	0xd3, 0xb4
};
#endif

/* A.6 SHA-1 */
#define hkdf_a6_ikm hkdf_a1_ikm
static const uint8_t hkdf_a6_salt[] = {};

static const uint8_t hkdf_a6_info[] = {};

static const uint8_t hkdf_a6_okm[] = {
	0x0a, 0xc1, 0xaf, 0x70, 0x02, 0xb3, 0xd7, 0x61,
	0xd1, 0xe5, 0x52, 0x98, 0xda, 0x9d, 0x05, 0x06,
	0xb9, 0xae, 0x52, 0x05, 0x72, 0x20, 0xa3, 0x06,
	0xe0, 0x7b, 0x6b, 0x87, 0xe8, 0xdf, 0x21, 0xd0,
	0xea, 0x00, 0x03, 0x3d, 0xe0, 0x39, 0x84, 0xd3,
	0x49, 0x18
};

/* A.7 SHA-1 */
static const uint8_t hkdf_a7_ikm[] = {
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c,
	0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c
};

static const uint8_t hkdf_a7_salt[] = {};

static const uint8_t hkdf_a7_info[] = {};

static const uint8_t hkdf_a7_okm[] = {
	0x2c, 0x91, 0x11, 0x72, 0x04, 0xd7, 0x45, 0xf3,
	0x50, 0x0d, 0x63, 0x6a, 0x62, 0xf6, 0x4f, 0x0a,
	0xb3, 0xba, 0xe5, 0x48, 0xaa, 0x53, 0xd4, 0x23,
	0xb0, 0xd1, 0xf2, 0x7e, 0xbb, 0xa6, 0xf5, 0xe5,
	0x67, 0x3a, 0x08, 0x1d, 0x70, 0xcc, 0xe7, 0xac,
	0xfc, 0x48
};
#endif /* WITH HKDF */

/*
 * Concat KDF (NIST SP 800-56A R1)
 *
 * Test vector from:
 * https://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms-37
 * appendix C
 */
#if (WITH_CONCAT_KDF == 1)
static const uint8_t concat_kdf_1_z[] = {
	158, 86, 217, 29, 129, 113, 53, 211,
	114, 131, 66, 131, 191, 132, 38, 156,
	251, 49, 110, 163, 218, 128, 106, 72,
	246, 218, 167, 121, 140, 254, 144, 196
};

static const uint8_t concat_kdf_1_other_info[] = {
	0, 0, 0, 7, 65, 49, 50, 56,
	71, 67, 77, 0, 0, 0, 5, 65,
	108, 105, 99, 101, 0, 0, 0, 3,
	66, 111, 98, 0, 0, 0, 128
};

static const uint8_t concat_kdf_1_derived_key[] = {
	86, 170, 141, 234, 248, 35, 109, 32,
	92, 34, 40, 205, 113, 167, 16, 26
};
#endif /* WITH_CONCAT_KDF */

/*
 * PKCS #5 2.0 / RFC 2898 Key Derivation Function 2 (PBKDF2)
 * Test vectors from RFC 6070 https://www.ietf.org/rfc/rfc6070.txt
 */

/*
 * NXP S32G note: unfortunately, with HSE most of these test vectors are not
 * supported, because they don't meet HSE's minimum length conditions. From the
 * standard set of 6 vectors, only vector #5 as-is meets the length criteria,
 * so for the others we'll just come up with a different set,
 * double-checked against open-source precomputed test vectors.
 */
#if (WITH_PBKDF2 == 1)
/* 1 */
static const uint8_t __unused pbkdf2_1_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t __unused pbkdf2_1_salt[] = {
	's', 'a', 'l', 't'
};

#define pbkdf2_1_iteration_count 1
static const uint8_t __unused pbkdf2_1_dkm[] = {
	0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
	0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
	0x2f, 0xe0, 0x37, 0xa6
};

/* 2 */
#define pbkdf2_2_password pbkdf2_1_password
#define pbkdf2_2_salt pbkdf2_1_salt
#define pbkdf2_2_iteration_count 2
static const uint8_t __unused pbkdf2_2_dkm[] = {
	0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c,
	0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d, 0x41, 0xf0,
	0xd8, 0xde, 0x89, 0x57
};

/* 3 */
#define pbkdf2_3_password pbkdf2_1_password
#define pbkdf2_3_salt pbkdf2_1_salt
#define pbkdf2_3_iteration_count 4096
static const uint8_t __unused pbkdf2_3_dkm[] = {
	0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a,
	0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7, 0x21, 0xd0,
	0x65, 0xa4, 0x29, 0xc1
};

/* 4 */
#define pbkdf2_4_password pbkdf2_1_password
#define pbkdf2_4_salt pbkdf2_1_salt
#define pbkdf2_4_iteration_count 16777216
static const uint8_t __unused pbkdf2_4_dkm[] = {
	0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4,
	0xe9, 0x94, 0x5b, 0x3d, 0x6b, 0xa2, 0x15, 0x8c,
	0x26, 0x34, 0xe9, 0x84
};

/* 5 */
static const uint8_t pbkdf2_5_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_5_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_5_iteration_count 4096
static const uint8_t __unused pbkdf2_5_dkm[] = {
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
static const uint8_t pbkdf2_5_dkm_aes_dummy[] = {
	0xe1, 0xbb, 0x2c, 0x37, 0x46, 0x5c, 0x0d, 0x12,
	0x2d, 0x80, 0x7a, 0x22, 0xf0, 0x44, 0xc4, 0xcd,
	0xd8, 0x26, 0x90, 0x6d, 0x8b, 0xb7, 0xc6, 0xc9,
	0x91,
};

/* 6 */
static const uint8_t __unused pbkdf2_6_password[] = {
	'p', 'a', 's', 's', '\0', 'w', 'o', 'r',
	'd',
};

static const uint8_t __unused pbkdf2_6_salt[] = {
	's', 'a', '\0', 'l', 't'
};

#define pbkdf2_6_iteration_count 4096
static const uint8_t __unused pbkdf2_6_dkm[] = {
	0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d,
	0xcc, 0x37, 0xd7, 0xf0, 0x34, 0x25, 0xe0, 0xc3
};

/*
 * NXP hand-made test vectors, validated against openssl.
 */

/* 7 */
/* This is basically test #5, only with different SHA */
static const uint8_t pbkdf2_7_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_7_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_7_iteration_count 4096
/* Derived with SHA256 */
static const uint8_t __unused pbkdf2_7_dkm[] = {
	0x34, 0x8C, 0x89, 0xDB, 0xCB, 0xD3, 0x2B, 0x2F,
	0x32, 0xD8, 0x14, 0xB8, 0x11, 0x6E, 0x84, 0xCF,
	0x2B, 0x17, 0x34, 0x7E, 0xBC, 0x18, 0x00, 0x18,
	0x1C
};

static const uint8_t pbkdf2_7_dkm_aes_dummy[] = {
	0xe8, 0x19, 0x49, 0xa3, 0x69, 0x93, 0xa2, 0xa6,
	0x9f, 0x90, 0xb6, 0xac, 0x83, 0xea, 0xa4, 0x48,
	0x78, 0x18, 0xbe, 0x85, 0x7b, 0x5d, 0x36, 0xa1,
	0xb5,
};

/* 8 */
static const uint8_t pbkdf2_8_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_8_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_8_iteration_count 10000
/* Derived with SHA256 */
static const uint8_t __unused pbkdf2_8_dkm[] = {
	0x96, 0xE1, 0x7B, 0x0C, 0x4E, 0x3C, 0x0C, 0x08,
	0xDB, 0x3B, 0xE7, 0x09, 0xDF, 0x3D, 0xB5, 0xC1,
	0xEF, 0xB0, 0xC8, 0xA7, 0xEA, 0xA4, 0xFC, 0x65,
	0x17
};

static const uint8_t pbkdf2_8_dkm_aes_dummy[] = {
	0x4a, 0x74, 0xbb, 0x74, 0xec, 0x7c, 0x85, 0x81,
	0x76, 0x73, 0x45, 0x1d, 0x4d, 0xb9, 0x95, 0x46,
	0xbc, 0xbf, 0x42, 0x5c, 0x2d, 0xe1, 0xca, 0xdc,
	0xbe,
};

/* 9 */
static const uint8_t pbkdf2_9_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_9_salt[] = {
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
static const uint8_t __unused pbkdf2_9_dkm[] = {
	0x8C, 0x05, 0x11, 0xF4, 0xC6, 0xE5, 0x97, 0xC6,
	0xAC, 0x63, 0x15, 0xD8, 0xF0, 0x36, 0x2E, 0x22,
	0x5F, 0x3C, 0x50, 0x14, 0x95, 0xBA, 0x23, 0xB8,
	0x68
};

static const uint8_t pbkdf2_9_dkm_aes_dummy[] = {
	0x50, 0x90, 0xd1, 0x8c, 0x64, 0xa5, 0x1e, 0x4f,
	0x01, 0x2b, 0xb7, 0xcc, 0x62, 0xb2, 0x0e, 0xa5,
	0x0c, 0x33, 0xda, 0xef, 0x52, 0xff, 0x15, 0x01,
	0xc1,
};

/* 10 */
static const uint8_t pbkdf2_10_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_10_salt[] = {
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
static const uint8_t __unused pbkdf2_10_dkm[] = {
	0x05, 0x6C, 0x4B, 0xA4, 0x38, 0xDE, 0xD9, 0x1F,
	0xC1, 0x4E, 0x05, 0x94, 0xE6, 0xF5, 0x2B, 0x87,
	0xE1, 0xF3, 0x69, 0x0C, 0x0D, 0xC0, 0xFB, 0xC0,
	0x57
};

static const uint8_t pbkdf2_10_dkm_aes_dummy[] = {
	0xd9, 0xf9, 0x8b, 0xdc, 0x9a, 0x9e, 0x50, 0x96,
	0x6c, 0x06, 0xa7, 0x80, 0x74, 0x71, 0x0b, 0x00,
	0xb2, 0xfc, 0xe3, 0xf7, 0xca, 0x85, 0xcd, 0x79,
	0xfe,
};

/* 11 */
static const uint8_t pbkdf2_11_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_11_salt[] = {
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
static const uint8_t __unused pbkdf2_11_dkm[] = {
	0x81, 0x91, 0x43, 0xAD, 0x66, 0xDF, 0x9A, 0x55,
	0x25, 0x59, 0xB9, 0xE1, 0x31, 0xC5, 0x2A, 0xE6,
	0xC5, 0xC1, 0xB0, 0xEE, 0xD1, 0x8F, 0x4D, 0x28,
	0x3
};

static const uint8_t pbkdf2_11_dkm_aes_dummy[] = {
	0x5d, 0x04, 0x83, 0xd5, 0xc4, 0x9f, 0x13, 0xdc,
	0x88, 0x11, 0x1b, 0xf5, 0xa3, 0x41, 0x0a, 0x61,
	0x96, 0xce, 0x3a, 0x15, 0x16, 0xca, 0x7b, 0x91,
	0x92,
};

/* 12 */
static const uint8_t pbkdf2_12_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_12_salt[] = {
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
static const uint8_t __unused pbkdf2_12_dkm[] = {
	0x31, 0xCF, 0x94, 0xE3, 0xD8, 0xE3, 0x6A, 0xA1,
	0x8D, 0x40, 0xAD, 0x92, 0x65, 0x4A, 0xB8, 0x0F,
	0x50, 0x0E, 0xD7, 0xFB, 0x57, 0x5A, 0x22, 0x15,
	0x54
};

static const uint8_t pbkdf2_12_dkm_aes_dummy[] = {
	0xed, 0x5a, 0x54, 0x9b, 0x7a, 0xa3, 0xe3, 0x28,
	0x20, 0x08, 0x0f, 0x86, 0xf7, 0xce, 0x98, 0x88,
	0x03, 0x01, 0x5d, 0x00, 0x90, 0x1f, 0x14, 0xac,
	0xfd,
};

/* 13 */
static const uint8_t pbkdf2_13_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_13_salt[] = {
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
static const uint8_t __unused pbkdf2_13_dkm[] = {
	0x57, 0x3D, 0xF9, 0x67, 0x62, 0xEA, 0x7D, 0xA4,
	0xF7, 0x12, 0x31, 0x85, 0x9C, 0xA2, 0x82, 0xEF,
	0x48, 0x27, 0x64, 0xAD, 0x96, 0x71, 0xC5, 0x27,
	0x5C
};

static const uint8_t pbkdf2_13_dkm_aes_dummy[] = {
	0x8b, 0xa8, 0x39, 0x1f, 0xc0, 0xaa, 0xf4, 0x2d,
	0x5a, 0x5a, 0x93, 0x91, 0x0e, 0x26, 0xa2, 0x68,
	0x1b, 0x28, 0xee, 0x56, 0x51, 0x34, 0xf3, 0x9e,
	0xf5,
};

/* The following subset contains 64-byte generated keys. This is useful with
 * 256-bit key handle + magic constructs, where the output buffer must be
 * at least the 256-bit size thereof.
 * FIXME currently disabled.
 */

/* 14 */
static const uint8_t pbkdf2_14_password[] = {
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd',
	'P', 'A', 'S', 'S', 'W', 'O', 'R', 'D',
	'p', 'a', 's', 's', 'w', 'o', 'r', 'd'
};

static const uint8_t pbkdf2_14_salt[] = {
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't', 'S', 'A', 'L', 'T',
	's', 'a', 'l', 't'
};

#define pbkdf2_14_iteration_count 8192
/* Derived with SHA1 */
static const uint8_t __unused pbkdf2_14_dkm[] = {
	0xBF, 0x23, 0x01, 0x2D, 0xB2, 0x0B, 0xC1, 0xB1,
	0x47, 0x6D, 0xE4, 0x3B, 0x3D, 0xD8, 0x53, 0x7A,
	0x34, 0x89, 0x0E, 0xC6, 0xDD, 0x22, 0x22, 0x14,
	0xB8, 0x1B, 0x47, 0x4D, 0xA7, 0x88, 0x84, 0xAB,
	0xF8, 0x19, 0xA5, 0x05, 0x47, 0x44, 0xA3, 0x69,
	0x77, 0xFF, 0x57, 0xC0, 0x6D, 0x64, 0xAF, 0x3D,
	0x9A, 0x16, 0x0D, 0x3A, 0x2B, 0x35, 0xD1, 0x74,
	0x38, 0x1C, 0x56, 0x09, 0x9B, 0x84, 0x4E, 0x6A
};

static const uint8_t pbkdf2_14_dkm_aes_dummy[] = {
	0x63, 0xb6, 0xc1, 0x55, 0x10, 0x4b, 0x48, 0x38,
	0xea, 0x25, 0x46, 0x2f, 0xaf, 0x5c, 0x73, 0xfd,
	0x67, 0x86, 0x84, 0x3d, 0x1a, 0x67, 0x14, 0xad,
	0x11, 0x78, 0xf3, 0xbc, 0x63, 0x43, 0xf7, 0x20,
	0x36, 0xbe, 0xe5, 0x38, 0x0a, 0x24, 0xc8, 0x07,
	0x70, 0xb1, 0x92, 0x13, 0xd7, 0x97, 0x32, 0x25,
	0xe8, 0x76, 0x0e, 0xf0, 0x1c, 0x93, 0xfb, 0x00,
	0xe9, 0xbe, 0xa3, 0x87, 0xee, 0x82, 0x7b, 0xe4,
};
#endif /* WITH_PBKDF2 */


#if (WITH_HKDF == 1)
static void xtest_test_derivation_hkdf(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n = 0;
#define TEST_HKDF_DATA(section, algo, id, oeb /* omit empty bufs */) \
	{ \
		section, algo, \
		hkdf_##id##_ikm, sizeof(hkdf_##id##_ikm), \
		(oeb && !sizeof(hkdf_##id##_salt)) ? NULL : hkdf_##id##_salt, sizeof(hkdf_##id##_salt), \
		(oeb && !sizeof(hkdf_##id##_info)) ? NULL : hkdf_##id##_info, sizeof(hkdf_##id##_info), \
		hkdf_##id##_okm, sizeof(hkdf_##id##_okm), \
	}
	static struct hkdf_case {
		const char *subcase_name;
		uint32_t algo;
		const uint8_t *ikm;
		size_t ikm_len;
		const uint8_t *salt;
		size_t salt_len;
		const uint8_t *info;
		size_t info_len;
		const uint8_t *okm;
		size_t okm_len;
	} hkdf_cases[] = {
		TEST_HKDF_DATA("A.1 (SHA-256)",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a1, false),

#if !defined(CFG_NXP_HSE) || CFG_HSE_PREMIUM_FW
		TEST_HKDF_DATA("A.2 (SHA-256)",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a2, false),
#endif
		TEST_HKDF_DATA("A.3 (SHA-256) [1]",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a3, false),
		TEST_HKDF_DATA("A.3 (SHA-256) [2]",
			       TEE_ALG_HKDF_SHA256_DERIVE_KEY, a3, true),
		TEST_HKDF_DATA("A.4 (SHA-1)",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a4, false),
#if !defined(CFG_NXP_HSE) || CFG_HSE_PREMIUM_FW
		TEST_HKDF_DATA("A.5 (SHA-1)",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a5, false),
#endif
		TEST_HKDF_DATA("A.6 (SHA-1) [1]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a6, false),
		TEST_HKDF_DATA("A.6 (SHA-1) [2]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a6, true),
		TEST_HKDF_DATA("A.7 (SHA-1) [1]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a7, false),
		TEST_HKDF_DATA("A.7 (SHA-1) [2]",
			       TEE_ALG_HKDF_SHA1_DERIVE_KEY, a7, true),
	};
	size_t max_size = 2048;

	for (n = 0; n < sizeof(hkdf_cases) / sizeof(struct hkdf_case); n++) {
		TEE_OperationHandle op = TEE_HANDLE_NULL;
		TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
		TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
		TEE_Attribute params[4] = { };
		size_t param_count = 0;
		uint8_t out[2048] = { };
		size_t out_size = 0;
		const struct hkdf_case *hc = &hkdf_cases[n];

		Do_ADBG_BeginSubCase(c, "HKDF RFC 5869 %s", hc->subcase_name);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				hc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_HKDF_IKM, max_size, &key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_IKM, hc->ikm,
			       hc->ikm_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, hc->okm_len * 8,
				&sv_handle)))
			goto out;

		param_count = 0;

		if (hc->salt)
			xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_SALT,
				hc->salt, hc->salt_len);
		if (hc->info)
			xtest_add_attr(&param_count, params, TEE_ATTR_HKDF_INFO,
				hc->info, hc->info_len);

		params[param_count].attributeID = TEE_ATTR_HKDF_OKM_LENGTH;
		params[param_count].content.value.a = hc->okm_len;
		params[param_count].content.value.b = 0;
		param_count++;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, hc->okm, hc->okm_len, out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
	out:
		Do_ADBG_EndSubCase(c, "HKDF RFC 5869 %s", hc->subcase_name);
	}
}
#endif /* WITH_HKDF */

#if (WITH_CONCAT_KDF == 1)
static void xtest_test_derivation_concat_kdf(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n = 0;
#define TEST_CONCAT_KDF_DATA(name, algo, id, oeb /* omit empty bufs */) \
	{ \
		name, algo, \
		concat_kdf_##id##_z, sizeof(concat_kdf_##id##_z), \
		(oeb && !sizeof(concat_kdf_##id##_other_info)) ? NULL \
							       : concat_kdf_##id##_other_info, \
		sizeof(concat_kdf_##id##_other_info), \
		concat_kdf_##id##_derived_key, sizeof(concat_kdf_##id##_derived_key), \
	}
	static struct concat_kdf_case {
		const char *subcase_name;
		uint32_t algo;
		const uint8_t *shared_secret;
		size_t shared_secret_len;
		const uint8_t *other_info;
		size_t other_info_len;
		const uint8_t *derived_key;
		size_t derived_key_len;
	} concat_kdf_cases[] = {
		TEST_CONCAT_KDF_DATA("JWA-37 C (SHA-256)",
			TEE_ALG_CONCAT_KDF_SHA256_DERIVE_KEY, 1, false),
	};
	size_t max_size = 2048;

	for (n = 0;
	     n < sizeof(concat_kdf_cases) / sizeof(struct concat_kdf_case);
	     n++) {
		TEE_OperationHandle op = TEE_HANDLE_NULL;
		TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
		TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
		TEE_Attribute params[4] = { };
		size_t param_count = 0;
		uint8_t out[2048] = { };
		size_t out_size = 0;
		const struct concat_kdf_case *cc = &concat_kdf_cases[n];

		Do_ADBG_BeginSubCase(c, "Concat KDF %s", cc->subcase_name);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				cc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_CONCAT_KDF_Z, max_size, &key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_CONCAT_KDF_Z,
			       cc->shared_secret, cc->shared_secret_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, cc->derived_key_len *
				8, &sv_handle)))
			goto out;

		param_count = 0;

		if (cc->other_info)
			xtest_add_attr(&param_count, params,
				       TEE_ATTR_CONCAT_KDF_OTHER_INFO,
				       cc->other_info, cc->other_info_len);

		params[param_count].attributeID = TEE_ATTR_CONCAT_KDF_DKM_LENGTH;
		params[param_count].content.value.a = cc->derived_key_len;
		params[param_count].content.value.b = 0;
		param_count++;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_derive_key(c, session, op, sv_handle,
						params, param_count)))
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
				sv_handle, TEE_ATTR_SECRET_VALUE, out,
				&out_size)))
			goto out;

		if (!ADBG_EXPECT_BUFFER(c, cc->derived_key, cc->derived_key_len,
					out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
out:
		Do_ADBG_EndSubCase(c, "Concat KDF %s", cc->subcase_name);
	}
}
#endif /* WITH_CONCAT_KDF */

#if (WITH_PBKDF2 == 1)
static void xtest_test_derivation_pbkdf2(ADBG_Case_t *c, TEEC_Session *session)
{
	size_t n = 0;
#define TEST_PBKDF2_DATA(level, section, algo, id, oeb /* omit empty bufs */, run_test) \
	{ \
		level, section, TEE_ALG_PBKDF2_HMAC_##algo##_DERIVE_KEY, \
		pbkdf2_##id##_password, sizeof(pbkdf2_##id##_password), \
		(oeb && !sizeof(pbkdf2_##id##_salt)) ? NULL : pbkdf2_##id##_salt, sizeof(pbkdf2_##id##_salt), \
		pbkdf2_##id##_iteration_count, \
		pbkdf2_##id##_dkm_aes_dummy, sizeof(pbkdf2_##id##_dkm_aes_dummy), \
		run_test \
	}
#define _TO_STR(n) #n
#define TO_STR(n) _TO_STR(n)
#define RFC6070_TEST(l, n, algo, run) \
	TEST_PBKDF2_DATA(l, "RFC 6070 extension " TO_STR(n) " (HMAC-SHAxxx)", \
			 algo, n, false, run)
	static struct pbkdf2_case {
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
	} pbkdf2_cases[] = {
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
	size_t max_size = 2048;

	for (n = 0; n < sizeof(pbkdf2_cases) / sizeof(struct pbkdf2_case); n++) {
		TEE_OperationHandle op = TEE_HANDLE_NULL;
		TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
		TEE_ObjectHandle sv_handle = TEE_HANDLE_NULL;
		TEE_Attribute params[4] = { };
		size_t param_count = 0;
		uint8_t out[2048] = { };
		size_t out_size = 0;
		const struct pbkdf2_case *pc = &pbkdf2_cases[n];

		if (!(pc->run_test))
			continue;

		if (pc->level > level)
			continue;

		Do_ADBG_BeginSubCase(c, "PBKDF2 %s", pc->subcase_name);
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_operation(c, session, &op,
				pc->algo, TEE_MODE_DERIVE, max_size)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_PBKDF2_PASSWORD, max_size,
				&key_handle)))
			goto out;

		xtest_add_attr(&param_count, params, TEE_ATTR_PBKDF2_PASSWORD,
			       pc->password, pc->password_len);

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_populate_transient_object(c, session,
				key_handle, params, param_count)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_set_operation_key(c, session, op,
						       key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   key_handle)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_allocate_transient_object(c, session,
				TEE_TYPE_GENERIC_SECRET, pc->dkm_len * 8,
				&sv_handle)))
			goto out;

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
			goto out;

		out_size = sizeof(out);
		memset(out, 0, sizeof(out));
		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_get_object_buffer_attribute(c, session,
						sv_handle, TEE_ATTR_SECRET_VALUE,
						out, &out_size)))
			goto out;

		/* With HSE, we are *not* exporting the plaintext derived key,
		 * but rather that key further encrypted with a dummy AES-CTR-256
		 * all-zero dummy key.
		 */
		if (!ADBG_EXPECT_BUFFER(c, pc->dkm, pc->dkm_len, out, out_size))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_operation(c, session, op)))
			goto out;

		if (!ADBG_EXPECT_TEEC_SUCCESS(c,
			ta_crypt_cmd_free_transient_object(c, session,
							   sv_handle)))
			goto out;
out:
		Do_ADBG_EndSubCase(c, "PBKDF2 %s", pc->subcase_name);
	}
}
#endif /* WITH_PBKDF2 */

static TEEC_Result enc_fs_km_self_test(TEEC_Session *sess)
{
	TEEC_Operation op = TEEC_OPERATION_INITIALIZER;
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t org = 0;

	res = TEEC_InvokeCommand(sess, CMD_SELF_TESTS, &op, &org);
	return res;
}

static void xtest_tee_test_8001(ADBG_Case_t *c)
{
	TEEC_Session session = { };
	uint32_t ret_orig = 0;

	if (!ADBG_EXPECT_TEEC_SUCCESS(c,
		xtest_teec_open_session(&session, &crypt_user_ta_uuid, NULL,
					&ret_orig))) {
		return;
	}

#if (WITH_HKDF == 1)
	xtest_test_derivation_hkdf(c, &session);
#endif
#if (WITH_CONCAT_KDF == 1)
	xtest_test_derivation_concat_kdf(c, &session);
#endif
#if (WITH_PBKDF2 == 1)
	xtest_test_derivation_pbkdf2(c, &session);
#endif

	TEEC_CloseSession(&session);
}
ADBG_CASE_DEFINE(regression, 8001, xtest_tee_test_8001,
		 "Test TEE Internal API key derivation extensions");

/* secure storage key manager self test */
static void xtest_tee_test_8002(ADBG_Case_t *c)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Session sess = { };
	uint32_t orig = 0;

	res = xtest_teec_open_session(&sess,
			&enc_fs_key_manager_test_ta_uuid,
			NULL, &orig);
	if (res != TEEC_SUCCESS) {
		Do_ADBG_Log("Ignore test due to TA does not exist");
		return;
	}

	if (!ADBG_EXPECT_TEEC_SUCCESS(
		    c, enc_fs_km_self_test(&sess)))
		goto exit;

exit:
	TEEC_CloseSession(&sess);
}
ADBG_CASE_DEFINE(regression, 8002, xtest_tee_test_8002,
	"Secure Storage Key Manager API Self Test");
