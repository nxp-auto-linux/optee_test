// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */

#include "xtest_test.h"
#include <enc_fs_key_manager_test.h>
#include <pta_invoke_tests.h>
#include <pta_hse_kp.h>
#include <ta_concurrent.h>
#include <ta_concurrent_large.h>
#include <ta_create_fail_test.h>
#include <ta_crypt.h>
#include <ta_large.h>
#include <ta_miss_test.h>
#include <ta_os_test.h>
#include <ta_rpc_test.h>
#include <ta_sdp_basic.h>
#include <ta_sims_keepalive_test.h>
#include <ta_sims_test.h>
#include <ta_socket.h>
#include <ta_storage_benchmark.h>
#include <ta_storage.h>
#include <ta_supp_plugin.h>
#include <ta_tpm_log_test.h>
#include <ta_arm_bti.h>
#include <ta_subkey1.h>
#include <ta_subkey2.h>
#include <tee_api_defines.h>
#include <tee_client_api.h>
#include <__tee_isocket_defines.h>
#include <__tee_tcpsocket_defines.h>
#include <__tee_udpsocket_defines.h>

ADBG_ENUM_TABLE_DEFINE_BEGIN(TEEC_Result)
ADBG_ENUM_TABLE_ENTRY(TEEC_SUCCESS),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_CORRUPT_OBJECT),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_CORRUPT_OBJECT_2),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_STORAGE_NOT_AVAILABLE),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_STORAGE_NOT_AVAILABLE_2),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_GENERIC),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_ACCESS_DENIED),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_CANCEL),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_ACCESS_CONFLICT),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_EXCESS_DATA),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_BAD_FORMAT),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_BAD_PARAMETERS),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_BAD_STATE),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_ITEM_NOT_FOUND),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_NOT_IMPLEMENTED),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_NOT_SUPPORTED),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_NO_DATA),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_OUT_OF_MEMORY),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_BUSY),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_COMMUNICATION),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_SECURITY),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_SHORT_BUFFER),
ADBG_ENUM_TABLE_ENTRY(TEEC_ERROR_EXTERNAL_CANCEL),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_OVERFLOW),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_TARGET_DEAD),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_STORAGE_NO_SPACE),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_MAC_INVALID),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_SIGNATURE_INVALID),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_TIME_NOT_SET),
ADBG_ENUM_TABLE_ENTRY(TEE_ERROR_TIME_NEEDS_RESET),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_PROTOCOL),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_REMOTE_CLOSED),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_TIMEOUT),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_OUT_OF_RESOURCES),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_LARGE_BUFFER),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_WARNING_PROTOCOL),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_ERROR_HOSTNAME),
ADBG_ENUM_TABLE_ENTRY(TEE_ISOCKET_UDP_WARNING_UNKNOWN_OUT_OF_BAND)
ADBG_ENUM_TABLE_DEFINE_END(TEEC_Result);

ADBG_ENUM_TABLE_DEFINE_BEGIN(TEEC_ErrorOrigin)
ADBG_ENUM_TABLE_ENTRY(TEEC_ORIGIN_API),
ADBG_ENUM_TABLE_ENTRY(TEEC_ORIGIN_COMMS),
ADBG_ENUM_TABLE_ENTRY(TEEC_ORIGIN_TEE),
ADBG_ENUM_TABLE_ENTRY(TEEC_ORIGIN_TRUSTED_APP)
ADBG_ENUM_TABLE_DEFINE_END(TEEC_ErrorOrigin);

#ifdef CFG_PKCS11_TA
ADBG_ENUM_TABLE_DEFINE_BEGIN(CK_RV)
ADBG_ENUM_TABLE_ENTRY(CKR_OK),
ADBG_ENUM_TABLE_ENTRY(CKR_CANCEL),
ADBG_ENUM_TABLE_ENTRY(CKR_HOST_MEMORY),
ADBG_ENUM_TABLE_ENTRY(CKR_SLOT_ID_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_GENERAL_ERROR),
ADBG_ENUM_TABLE_ENTRY(CKR_FUNCTION_FAILED),
ADBG_ENUM_TABLE_ENTRY(CKR_ARGUMENTS_BAD),
ADBG_ENUM_TABLE_ENTRY(CKR_NO_EVENT),
ADBG_ENUM_TABLE_ENTRY(CKR_NEED_TO_CREATE_THREADS),
ADBG_ENUM_TABLE_ENTRY(CKR_CANT_LOCK),
ADBG_ENUM_TABLE_ENTRY(CKR_ATTRIBUTE_READ_ONLY),
ADBG_ENUM_TABLE_ENTRY(CKR_ATTRIBUTE_SENSITIVE),
ADBG_ENUM_TABLE_ENTRY(CKR_ATTRIBUTE_TYPE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_ATTRIBUTE_VALUE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_ACTION_PROHIBITED),
ADBG_ENUM_TABLE_ENTRY(CKR_DATA_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_DATA_LEN_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_DEVICE_ERROR),
ADBG_ENUM_TABLE_ENTRY(CKR_DEVICE_MEMORY),
ADBG_ENUM_TABLE_ENTRY(CKR_DEVICE_REMOVED),
ADBG_ENUM_TABLE_ENTRY(CKR_ENCRYPTED_DATA_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_ENCRYPTED_DATA_LEN_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_FUNCTION_CANCELED),
ADBG_ENUM_TABLE_ENTRY(CKR_FUNCTION_NOT_PARALLEL),
ADBG_ENUM_TABLE_ENTRY(CKR_FUNCTION_NOT_SUPPORTED),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_HANDLE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_SIZE_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_TYPE_INCONSISTENT),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_NOT_NEEDED),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_CHANGED),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_NEEDED),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_INDIGESTIBLE),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_FUNCTION_NOT_PERMITTED),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_NOT_WRAPPABLE),
ADBG_ENUM_TABLE_ENTRY(CKR_KEY_UNEXTRACTABLE),
ADBG_ENUM_TABLE_ENTRY(CKR_MECHANISM_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_MECHANISM_PARAM_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_OBJECT_HANDLE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_OPERATION_ACTIVE),
ADBG_ENUM_TABLE_ENTRY(CKR_OPERATION_NOT_INITIALIZED),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_INCORRECT),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_LEN_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_EXPIRED),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_LOCKED),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_CLOSED),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_COUNT),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_HANDLE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_PARALLEL_NOT_SUPPORTED),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_READ_ONLY),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_EXISTS),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_READ_ONLY_EXISTS),
ADBG_ENUM_TABLE_ENTRY(CKR_SESSION_READ_WRITE_SO_EXISTS),
ADBG_ENUM_TABLE_ENTRY(CKR_SIGNATURE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_SIGNATURE_LEN_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_TEMPLATE_INCOMPLETE),
ADBG_ENUM_TABLE_ENTRY(CKR_TEMPLATE_INCONSISTENT),
ADBG_ENUM_TABLE_ENTRY(CKR_TOKEN_NOT_PRESENT),
ADBG_ENUM_TABLE_ENTRY(CKR_TOKEN_NOT_RECOGNIZED),
ADBG_ENUM_TABLE_ENTRY(CKR_TOKEN_WRITE_PROTECTED),
ADBG_ENUM_TABLE_ENTRY(CKR_UNWRAPPING_KEY_HANDLE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_UNWRAPPING_KEY_SIZE_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_ALREADY_LOGGED_IN),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_NOT_LOGGED_IN),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_PIN_NOT_INITIALIZED),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_TYPE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_ANOTHER_ALREADY_LOGGED_IN),
ADBG_ENUM_TABLE_ENTRY(CKR_USER_TOO_MANY_TYPES),
ADBG_ENUM_TABLE_ENTRY(CKR_WRAPPED_KEY_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_WRAPPED_KEY_LEN_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_WRAPPING_KEY_HANDLE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_WRAPPING_KEY_SIZE_RANGE),
ADBG_ENUM_TABLE_ENTRY(CKR_WRAPPING_KEY_TYPE_INCONSISTENT),
ADBG_ENUM_TABLE_ENTRY(CKR_RANDOM_SEED_NOT_SUPPORTED),
ADBG_ENUM_TABLE_ENTRY(CKR_RANDOM_NO_RNG),
ADBG_ENUM_TABLE_ENTRY(CKR_DOMAIN_PARAMS_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_CURVE_NOT_SUPPORTED),
ADBG_ENUM_TABLE_ENTRY(CKR_BUFFER_TOO_SMALL),
ADBG_ENUM_TABLE_ENTRY(CKR_SAVED_STATE_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_INFORMATION_SENSITIVE),
ADBG_ENUM_TABLE_ENTRY(CKR_STATE_UNSAVEABLE),
ADBG_ENUM_TABLE_ENTRY(CKR_CRYPTOKI_NOT_INITIALIZED),
ADBG_ENUM_TABLE_ENTRY(CKR_CRYPTOKI_ALREADY_INITIALIZED),
ADBG_ENUM_TABLE_ENTRY(CKR_MUTEX_BAD),
ADBG_ENUM_TABLE_ENTRY(CKR_MUTEX_NOT_LOCKED),
ADBG_ENUM_TABLE_ENTRY(CKR_NEW_PIN_MODE),
ADBG_ENUM_TABLE_ENTRY(CKR_NEXT_OTP),
ADBG_ENUM_TABLE_ENTRY(CKR_EXCEEDED_MAX_ITERATIONS),
ADBG_ENUM_TABLE_ENTRY(CKR_FIPS_SELF_TEST_FAILED),
ADBG_ENUM_TABLE_ENTRY(CKR_LIBRARY_LOAD_FAILED),
ADBG_ENUM_TABLE_ENTRY(CKR_PIN_TOO_WEAK),
ADBG_ENUM_TABLE_ENTRY(CKR_PUBLIC_KEY_INVALID),
ADBG_ENUM_TABLE_ENTRY(CKR_FUNCTION_REJECTED),
ADBG_ENUM_TABLE_ENTRY(CKR_VENDOR_DEFINED)
ADBG_ENUM_TABLE_DEFINE_END(CK_RV);
#endif /*CFG_PKCS11_TA*/

#define ECC_SELF_TEST_UUID \
		{ 0xf34f4f3c, 0xab30, 0x4573,  \
		{ 0x91, 0xBF, 0x3C, 0x57, 0x02, 0x4D, 0x51, 0x99 } }

const TEEC_UUID crypt_user_ta_uuid = TA_CRYPT_UUID;
const TEEC_UUID os_test_ta_uuid = TA_OS_TEST_UUID;
const TEEC_UUID create_fail_test_ta_uuid = TA_CREATE_FAIL_TEST_UUID;
const TEEC_UUID ecc_test_ta_uuid = ECC_SELF_TEST_UUID;
const TEEC_UUID pta_invoke_tests_ta_uuid = PTA_INVOKE_TESTS_UUID;
const TEEC_UUID pta_hse_kp_uuid = PTA_HSE_KP_UUID;
const TEEC_UUID rpc_test_ta_uuid = TA_RPC_TEST_UUID;
const TEEC_UUID sims_test_ta_uuid = TA_SIMS_TEST_UUID;
const TEEC_UUID miss_test_ta_uuid = TA_MISS_TEST_UUID;
const TEEC_UUID sims_keepalive_test_ta_uuid = TA_SIMS_KEEP_ALIVE_TEST_UUID;
const TEEC_UUID storage_ta_uuid = TA_STORAGE_UUID;
const TEEC_UUID storage2_ta_uuid = TA_STORAGE2_UUID;
const TEEC_UUID enc_fs_key_manager_test_ta_uuid = ENC_FS_KEY_MANAGER_TEST_UUID;
const TEEC_UUID concurrent_ta_uuid = TA_CONCURRENT_UUID;
const TEEC_UUID concurrent_large_ta_uuid = TA_CONCURRENT_LARGE_UUID;
const TEEC_UUID storage_benchmark_ta_uuid = TA_STORAGE_BENCHMARK_UUID;
const TEEC_UUID socket_ta_uuid = TA_SOCKET_UUID;
const TEEC_UUID sdp_basic_ta_uuid = TA_SDP_BASIC_UUID;
const TEEC_UUID tpm_log_test_ta_uuid = TA_TPM_LOG_TEST_UUID;
const TEEC_UUID supp_plugin_test_ta_uuid = TA_SUPP_PLUGIN_UUID;
const TEEC_UUID large_ta_uuid = TA_LARGE_UUID;
const TEEC_UUID bti_test_ta_uuid = TA_BTI_UUID;
const TEEC_UUID subkey1_ta_uuid = TA_SUBKEY1_UUID;
const TEEC_UUID subkey2_ta_uuid = TA_SUBKEY2_UUID;
