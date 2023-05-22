/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019-2020, Fraunhofer Institute for Secure Information Technology
 * SIT. All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.c
 * @author Michael Eckel (michael.eckel@sit.fraunhofer.de)
 * @brief
 * @version 0.1
 * @date 2019-09-19
 *
 * @copyright Copyright 2019-2020, Fraunhofer Institute for Secure Information
 * Technology SIT. All rights reserved.
 *
 * @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 * BSD-3-Clause).
 */

#include "charra_util.h"

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

#include "util/tpm2_util.h"
#include "core/hash/hash_sig_verify.h"

#define UNUSED __attribute__((unused))



TSS2_RC charra_unmarshal_tpm2_quote(size_t attest_buf_len,
	const uint8_t* attest_buf, TPMS_ATTEST* attest_struct) {
	TSS2_RC charra_rc = TSS2_RC_SUCCESS;
	TSS2_RC tss2_rc = TSS2_RC_SUCCESS;
	char* error_msg = NULL;

	/* verify input parameters */
	if (attest_buf == NULL) {
		error_msg = "Bad argument. attest_buf is NULL.";
		charra_rc = TSS2_BASE_RC_BAD_VALUE;
		goto error;
	} else if (attest_struct == NULL) {
		error_msg = "Bad argument. attest_struct is NULL.";
		charra_rc = TSS2_BASE_RC_BAD_VALUE;
		goto error;
	}

	/* unmarshal TPMS_ATTEST structure */
	size_t offset = 0;
	if ((tss2_rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest_buf, attest_buf_len,
			 &offset, attest_struct)) != TSS2_RC_SUCCESS) {
		error_msg = "Unmarshal TPMS_ATTEST structure.";
		charra_rc = TSS2_BASE_RC_GENERAL_FAILURE;//unmarshal issue with  TPMS ATTEST
		goto error;
	}

error:
	/* print error message */
	if (error_msg != NULL) {
		fprintf(stderr,"%s (CHARRA RC: 0x%04x, TSS2 RC: 0x%04x)", error_msg,
			charra_rc, tss2_rc);
	}

	/* transform TSS2_RC to CHARRA_RC */
	if ((charra_rc == TSS2_RC_SUCCESS) && (tss2_rc != TSS2_RC_SUCCESS)) {
		charra_rc = TSS2_BASE_RC_NO_TPM;//issue with tpm
	}

	return charra_rc;
}

bool charra_verify_tpm2_quote_qualifying_data(uint16_t qualifying_data_len,
	const uint8_t* const qualifying_data,
	const TPMS_ATTEST* const attest_struct) {

	/* verify input parameters */
	if (qualifying_data == NULL) {
		return false;
	} else if (attest_struct == NULL) {
		return false;
	}

	/* compare sizes and content */
	if (attest_struct->extraData.size != qualifying_data_len) {
		return false;
	} else if (memcmp(qualifying_data, attest_struct->extraData.buffer,
				   qualifying_data_len) != 0) {
		return false;
	}

	return true;
}



bool charra_verify_tpm2_quote_pcr_composite_digest(
	const TPMS_ATTEST* const attest_struct,
	const uint8_t* const pcr_composite_digest,
	const uint16_t pcr_composite_digest_len) {

	/* extract PCR digest from attestation structure */
	TPMS_QUOTE_INFO quote_info = attest_struct->attested.quote;
	const uint8_t* const pcr_digest = quote_info.pcrDigest.buffer;
	uint16_t pcr_digest_size = quote_info.pcrDigest.size;

	/* compare digests */
	if (pcr_digest_size != pcr_composite_digest_len) {
		printf("size does not match!\n");
		return false;
	} else if (memcmp(pcr_digest, pcr_composite_digest, pcr_digest_size) != 0) {
		printf("bytesequence does not match!\n");
		return false;
	}

	return true;
}

void folding_digest_init_sha256(uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE]){
	uint8_t init_digest [TPM2_SHA256_DIGEST_SIZE] = {0};

	for (size_t i = 0; i < TPM2_MAX_PCRS; i++)
	{
		memcpy(pcr_folding_digest[i],init_digest,TPM2_SHA256_DIGEST_SIZE);
	}
	
}

void extend_folding_digest_sha256(uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE],uint8_t pcr, uint8_t * event_hash){
	uint8_t extended_digest [TPM2_SHA256_DIGEST_SIZE] = {0};
	mbedtls_sha256_context ctx = {0};
	mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
	mbedtls_sha256_update_ret(&ctx,pcr_folding_digest[pcr], TPM2_SHA256_DIGEST_SIZE);
    mbedtls_sha256_update_ret(&ctx,event_hash, TPM2_SHA256_DIGEST_SIZE);
	mbedtls_sha256_finish_ret(&ctx, extended_digest);
    mbedtls_sha256_free(&ctx);
	
	memcpy(pcr_folding_digest[pcr],extended_digest,TPM2_SHA256_DIGEST_SIZE);
}


void compute_composite_digest_sha256(uint8_t pcr_composite_digest [TPM2_SHA256_DIGEST_SIZE],uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE],uint8_t pcr){
	mbedtls_sha256_context ctx = {0};
	mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
	mbedtls_sha256_update_ret(&ctx,pcr_folding_digest[pcr], TPM2_SHA256_DIGEST_SIZE);
	mbedtls_sha256_finish_ret(&ctx, pcr_composite_digest);
    mbedtls_sha256_free(&ctx);
}