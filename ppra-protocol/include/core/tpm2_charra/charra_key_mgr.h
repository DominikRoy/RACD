/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_key_mgr.h
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de), Dominik Roy George (dominik.roy.george@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#ifndef CHARRA_KEY_MGR_H
#define CHARRA_KEY_MGR_H

#include <inttypes.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

TSS2_RC charra_load_tpm2_key(ESYS_CONTEXT* ctx, const uint32_t key_len,
	const uint8_t* key, ESYS_TR* key_handle, TPM2B_PUBLIC** out_public);

TSS2_RC charra_load_external_public_key(ESYS_CONTEXT* ctx,
	TPM2B_PUBLIC* external_public_key, ESYS_TR* key_handle);

/**
 * @brief The function checks if the primarykey/ attestation key exists in the NVRAM, otherwise it genreates a new key 
 * and stores it in the NVRAM.
 * 
 * @param ctx [in,out] ctx The TSS ESAPI context.
 * @param key_handle [in] The TPM key handle.
 * @param out_public [out] public data of the key.
 * @return TSS2_RC The TSS return code.
 */
TSS2_RC ppra_create_store_tpm2_key(ESYS_CONTEXT* ctx, ESYS_TR* key_handle, TPM2B_PUBLIC** out_public);
#endif /* CHARRA_KEY_MGR_H */
