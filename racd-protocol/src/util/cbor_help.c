/* SPDX-License-Identifier: BSD-3-Clause  */
/*  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  * 
 *  Copyright 2020, Fraunhofer Institute for Secure Information Technology SIT.
 *  All rights reserved.
 *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  *  */

/*
 * 
 *  @file cbor_help.c
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
#include "util/cbor_help.h"

size_t get_size_for_cbor_uint(uint64_t num) {
    size_t size = 0;
    if (num <= 23) {
        size = 1; // base for typ idenifier(3bit) and unsigend values until 23, see rfc7049 section 2.1
    } else if (num <= UCHAR_MAX) {
        size = 2; // base and uint8_t
    } else if (num <= USHRT_MAX) {
        size = 3; // base and uint16_t
    } else if (num <= UINT_MAX) {
        size = 5; // base and uint32_t
    } else if (num <= ULONG_MAX) {
        size = 9; // base and uint64_t
    }
    return size;
}

size_t get_size_for_cbor_string(char *str) {
    return get_size_for_cbor_uint(strlen(str)) + strlen(str);
}

size_t get_size_for_cbor_bstring(size_t size_bstring) {
    return get_size_for_cbor_uint(size_bstring) + size_bstring;
}
size_t get_size_for_cbor_hash(){
    return (size_t)32;
}