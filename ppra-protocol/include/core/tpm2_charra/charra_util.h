/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_util.h
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

#include <inttypes.h>
#include <stdbool.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>


#ifndef CHARRA_UTIL_H
#define CHARRA_UTIL_H



TSS2_RC charra_unmarshal_tpm2_quote(size_t attest_buf_len,
	const uint8_t* attest_buf, TPMS_ATTEST* attest_struct);

bool charra_verify_tpm2_quote_qualifying_data(uint16_t qualifying_data_len,
	const uint8_t* const qualifying_data,
	const TPMS_ATTEST* const attest_struct);

bool charra_verify_tpm2_quote_pcr_composite_digest(
	const TPMS_ATTEST* const attest_struct, const uint8_t* const pcr_composite,
	const uint16_t pcr_composite_len);

/**
 * @brief Init function which fill all PCR banks with zeros
 * 
 * @param pcr_folding_digest [in,out]
 */
void folding_digest_init_sha256(uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE]);



/**
 * @brief The function simulates the extended folding hash procedure same as the TPM_PCR_extend
 * 
 * @param pcr_folding_digest [out] folded hash for sha256
 * @param pcr [in]  PCR value
 * @param event_hash [in] event hash as input
 */
void extend_folding_digest_sha256(uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE],uint8_t pcr, uint8_t * event_hash);
/**
 * @brief This function exists due to the pcr folding digest function, because the tpm hashes the for the selected pcr in our case 10 again the hashed
 * value. Therefore to verify the pcr values it needs this function to hash it again to compare it afterwards.
 * 
 * @param pcr_composite_digest [out] tpm quote hash
 * @param pcr_folding_digest [in] Folded / extended hahs
 * @param pcr [in] PCR value
 */
void compute_composite_digest_sha256(uint8_t pcr_composite_digest [TPM2_SHA256_DIGEST_SIZE],uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE],uint8_t pcr);

#endif /* CHARRA_UTIL_H */
