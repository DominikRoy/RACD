#ifndef PPRA_SETUP_H
#define PPRA_SETUP_H

#include <stdlib.h>
#include <qcbor/qcbor.h>
#include <qcbor/UsefulBuf.h>
#include <mbedtls/x509.h>
#include "core/hash/hash_sig_verify.h"
#include "core/dto/ppra_dto.h"

/**
 * @file events.h
 * @author Dominik Roy George (dominik.roy.george@sit.fraunhofer.de)
 * @brief This header file provides the encoding and decoding operation for  mapping the event C struct to byte strings.
 * @version 0.1
 * @date 2021-04-12
 * 
 * @copyright Copyright (c) 2021
 * 
 */


/* Encode function */
/**
 * @brief The function encodes the events struct to byte string with the QCBOR library.
 * 
 * @param eventlist [in] to be encoded struct with data
 * @param buf_len [out] length of the byte string
 * @return uint8_t*  returns the byte string
 */
uint8_t* events_encode(events *eventlist, uint32_t * buf_len);

/* Decode function */
/**
 * @brief The function decodes the events byte string back to a struct with data with the QCBOR library.
 * 
 * @param eventlist [out] the struct filled with decoded data
 * @param buf [in] Bytestring which needs to be decoded
 * @param buf_len [in] length of the bytestring
 * @return int 
 */
int events_decode(events *eventlist, uint8_t *buf, uint64_t buf_len);

/**
 * @brief Get the size of event object
 * 
 * @param event 
 * @return size_t 
 */
size_t get_size_of_event(event event);

/**
 * @brief Get the size of events object
 * 
 * @param eventlist 
 * @return size_t 
 */
size_t get_size_of_events(events* eventlist);

/**
 * @brief Free events struct
 * 
 * @param eventlist 
 */
void free_events(events * eventlist);
#endif /* PPRA_SETUP_H */

