/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_key_mgr.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
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

#include "core/tpm2_charra/charra_key_mgr.h"
#include "util/tpm2_util.h"
#include <inttypes.h>
#include <string.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

TSS2_RC charra_load_tpm2_key(ESYS_CONTEXT *ctx, const uint32_t key_len,
							 const uint8_t *key, ESYS_TR *key_handle, TPM2B_PUBLIC **out_public)
{
	TSS2_RC r = TSS2_RC_SUCCESS;
	if (memcmp(key, "PK.RSA.default", key_len) == 0)
	{
		printf("Loading key \"PK.RSA.default\".");
		r = tpm2_create_primary_key_rsa2048(ctx, key_handle, out_public);
		if (r != TSS2_RC_SUCCESS)
		{
			fprintf(stderr, "Loading of key \"PK.RSA.default\" failed.");
			return TSS2_BASE_RC_GENERAL_FAILURE;
		}
	}
	else
	{
		fprintf(stderr, "TPM key not found.");
		return TSS2_BASE_RC_KEY_NOT_FOUND;
	}

	return TSS2_RC_SUCCESS;
}

TSS2_RC charra_load_external_public_key(ESYS_CONTEXT *ctx,
										TPM2B_PUBLIC *external_public_key, ESYS_TR *key_handle)
{
	TSS2_RC r = TSS2_RC_SUCCESS;
	if (external_public_key == NULL)
	{
		fprintf(stderr, "External public key does not exist.");
		return TSS2_BASE_RC_KEY_NOT_FOUND;
	}

	r = Esys_LoadExternal(ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
						  NULL, external_public_key, TPM2_RH_OWNER, key_handle);
	if (r != TSS2_RC_SUCCESS)
	{
		fprintf(stderr, "Loading external public key failed.");
		return TSS2_BASE_RC_GENERAL_FAILURE;
	}

	return TSS2_RC_SUCCESS;
}

TSS2_RC ppra_create_store_tpm2_key(ESYS_CONTEXT *ctx, ESYS_TR *key_handle, TPM2B_PUBLIC **out_public)
{
	TSS2_RC r = TSS2_RC_SUCCESS;
	if ((r = tpm2_load_key_from_nvram(ctx, key_handle)) == TSS2_RC_SUCCESS)
	{
		if((r = tpm2_read_public(ctx,key_handle,out_public))!=TSS2_RC_SUCCESS){
			printf("failed to load pub key structure!");
			return TSS2_BASE_RC_GENERAL_FAILURE;
		}
		return TSS2_RC_SUCCESS;
	}
	else
	{
		printf("Loading key \"PK.RSA.default\".");
		r = tpm2_create_primary_key_rsa2048(ctx, key_handle, out_public);
		if (r != TSS2_RC_SUCCESS)
		{
			fprintf(stderr, "Loading of key \"PK.RSA.default\" failed.");
			return TSS2_BASE_RC_GENERAL_FAILURE;
		}
		r = tpm2_store_key_in_nvram(ctx, key_handle);
		if (r != TSS2_RC_SUCCESS)
		{
			fprintf(stderr, "Storing key failed in NVRAM.");
			return TSS2_BASE_RC_GENERAL_FAILURE;
		}

		return TSS2_RC_SUCCESS;
	}
	return r;
}