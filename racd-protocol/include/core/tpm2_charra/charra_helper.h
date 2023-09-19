/* SPDX-License-Identifier: BSD-3-Clause */
/*****************************************************************************
 * Copyright 2019, Fraunhofer Institute for Secure Information Technology SIT.
 * All rights reserved.
 ****************************************************************************/

/**
 * @file charra_helper.h
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

#include <inttypes.h>

#include <tss2/tss2_tpm2_types.h>
#include "../dto/ppra_dto.h"

#ifndef CHARRA_HELPER_H
#define CHARRA_HELPER_H

/**
 * TODO change after libcharra exists
 * 
 * @brief Converts a selection of TPM PCRs (array) to a TPM PCR selection
 * bitmap.
 *
 * @param pcr_selection[in] The PCR selection.
 * @param pcr_selection_len[in] The length of the PCR selection.
 * @param pcr_selection_bitmap[out] The PCR selection bitmap
 * as TPMS_PCR_SELECTION. Note that only the PCR selection bitmap is set,
 * nothing else, such as the algorithm, is set.
 * @return CHARRA_RC_BAD_ARGUMENT If input parameters are invalid. value changed to int 1 sucess and 0 error
 */
TSS2_RC  charra_tpm2_pcr_selection_to_bitmap(const uint32_t pcr_selection_len,
	const uint8_t pcr_selection[], TPMS_PCR_SELECTION* pcr_selection_bitmap);

TSS2_RC charra_pcr_selections_to_tpm_pcr_selections(
	const uint32_t pcr_selection_list_len, pcr_selection_dto* pcr_selection_list,
	TPML_PCR_SELECTION* tpm_pcr_selections);

#endif /* CHARRA_HELPER_H */
