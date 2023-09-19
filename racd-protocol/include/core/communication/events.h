#ifndef PPRA_SETUP_H
#define PPRA_SETUP_H

#include <stdlib.h>
#include <qcbor/qcbor.h>
#include <qcbor/UsefulBuf.h>
#include <mbedtls/x509.h>
#include "core/hash/hash_sig_verify.h"
#include "core/dto/ppra_dto.h"


/* Encode function */
uint8_t* events_encode(events *eventlist, uint32_t * buf_len);

/* Decode function */
int events_decode(events *eventlist, uint8_t *buf, uint64_t buf_len);

size_t get_size_of_event(event event);
size_t get_size_of_events(events* eventlist);
void free_events(events * eventlist);
#endif /* PPRA_SETUP_H */

