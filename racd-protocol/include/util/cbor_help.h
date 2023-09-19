/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2020, Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file cbor_help.h
 *  @author Tim Riemann <tim.riemann@sit.fraunhofer.de>
 *  @date 10. April 2020
 *  
 *  @copyright Copyright 2020, Fraunhofer Institute for Secure Information
 *  Technology SIT. All rights reserved.
 * 
 *  @license BSD 3-Clause "New" or "Revised" License (SPDX-License-Identifier:
 *  BSD-3-Clause)
 * 
 */

#ifndef CBOR_HELP_H
#define CBOR_HELP_H
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

size_t get_size_for_cbor_uint(uint64_t num);

size_t get_size_for_cbor_string(char *str);

size_t get_size_for_cbor_bstring(size_t size_bstring);
size_t get_size_for_cbor_hash(void);

#ifdef __cplusplus
}
#endif

#endif /* CBOR_HELP_H */

