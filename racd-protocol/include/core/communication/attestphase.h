




#ifndef PPRA_ATTEST_H
#define PPRA_ATTEST_H

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/x509.h>
#include <unistd.h>
#include <sodium.h>
#include <stdio.h> 
#include <stdbool.h>
#include <string.h> 
#include <qcbor/qcbor.h>
#include <qcbor/UsefulBuf.h>
#include <tss2/tss2_tpm2_types.h>
#include <tss2/tss2_esys.h>


#include "core/nizk/nizk.h"
#include "util/fileIO.h"
#include "util/cbor_help.h"
#include "util/tpm2_util.h"




/* Encode function */
uint8_t* eventrecords_encode(eventrecords *records, uint32_t * buf_len);

/* Decode function */
int eventrecords_decode(events* evlist, bool selection,eventrecords *records, uint8_t *buf, uint64_t buf_len);


size_t get_size_of_eventrecords(eventrecords * records);

uint8_t * create_attestrequest(msg_attestation_request_dto * request, uint32_t * buf_len);
uint8_t * send_attestresponse(mbedtls_x509_name subject,TPM2B_PUBLIC * out_public,uint8_t *p_buf,uint64_t len,uint32_t *buf_len);
void verify_attestresponse(uint8_t nonce[crypto_box_NONCEBYTES],char * rim_path, uint8_t *buf, uint64_t len);
void free_eventrecords(eventrecords *records);
void simulate_measured_boot(char * filepath);
void create_store_pk(TPM2B_PUBLIC ** out_public);
bool is_authenticated(char * policy_path, events * swSelection);

#endif /* PPRA_ATTEST_H */