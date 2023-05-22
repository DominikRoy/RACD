




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

/**
 * @file attestphase.h
 * @author Dominik Roy George (dominik.roy.george@sit.fraunhofer.de)
 * @brief The attestphase implements all the function for simulating the measurement process as well as the implementations for 
 * remote attestation.
 * @version 0.1
 * @date 2021-01-12
 * 
 * @copyright Copyright (c) 2021
 * 
 */





/* Encode function */
/**
 * @brief The function encodes the eventrecords C struct into binary format
 * 
 * @param records  [in] records contains the information to be encoded.
 * @param buf_len  [out] returns the length of the bytestring
 * @return uint8_t* returns byte string
 */
uint8_t* eventrecords_encode(eventrecords *records, uint32_t * buf_len);

/* Decode function */
/**
 * @brief The decode function decodes the byte string back to eventrecords struct containing information.
 * Further, the function provides two options, either decodes the whole list or only selected areas
 * 
 * @param evlist [in] selection which events should be decoded
 * @param selection [in] selection enbaled or not
 * @param records [out] returns eventrecord with filled values
 * @param buf [in] bytestring which will be decoded
 * @param buf_len [in] bytestring length for decoding
 * @return int should return 1 if success if 1 and error is printed means that CBOR error appeared
 */
int eventrecords_decode(events* evlist, bool selection,eventrecords *records, uint8_t *buf, uint64_t buf_len);

/**
 * @brief Get the size of eventrecords object for CBOR encoding and decoding process
 * 
 * @param records 
 * @return size_t 
 */
size_t get_size_of_eventrecords(eventrecords * records);

/**
 * @brief Create a attestrequest object
 * 
 * @param request [in] request with dto filled information for the attester
 * @param buf_len [out] returns the length of the bytestring
 * @return uint8_t*  returns the byte string
 */
uint8_t * create_attestrequest(msg_attestation_request_dto * request, uint32_t * buf_len);

/**
 * @brief This function will be invoked on the attester side 
 * 
 * @param subject [in] The name of the policy file is extracted from verified certificate from the verifier
 * @param out_public [in] The publik key from TPM, extraced  from the NVRAM for signing the TPM_QUOTE
 * @param p_buf [in] the message request dto struct byte string will be used to decode the information and select the pcrs as well as 
 * the software selection.
 * @param len [in] length of the message request dto byte string
 * @param buf_len [out] outputs the length of message response dto byte string
 * @return uint8_t* returns the byte string of message response dto
 */
uint8_t * send_attestresponse(mbedtls_x509_name subject,TPM2B_PUBLIC * out_public,uint8_t *p_buf,uint64_t len,uint32_t *buf_len);

/**
 * @brief This function verifies the attestation response from the attestor, while checking the proof of knowledge, the nonce, the TPM_Quote
 * and signature and cross referencing the software selection with rim.
 * 
 * @param nonce [in] generated nonce for attestation request will be given as input to check the nonce with the response 
 * @param rim_path [in] file path to the cross reference file RIM
 * @param buf [in] bytestring of the attestion response
 * @param len [in] length of the byte string for the decoding process
 */
void verify_attestresponse(uint8_t nonce[crypto_box_NONCEBYTES],char * rim_path, uint8_t *buf, uint64_t len);

/**
 * @brief Frees the eventrecords struct
 * 
 * @param records 
 */
void free_eventrecords(eventrecords *records);

/**
 * @brief The function simulates the IMA process of the measured boot, where it measures the binary and generates the hash und templatehash
 * Further, it generates the Schnorr Signature/ event hash for each entry of the measured binary.
 * Next, it extends the PCR of each generated event hash.
 * 
 * @param filepath 
 */
void simulate_measured_boot(char * filepath);

/**
 * @brief The function creates the primary key / attestation key if the no key exists in the NVRAM of the TPM and stores them in the NVRAM.
 * However, if a key exists then it will be loaded from NVRAM and in out_public stored.
 * 
 * @param out_public [out] returns the public paramters of the key
 */
void create_store_pk(TPM2B_PUBLIC ** out_public);

/**
 * @brief This function simulates the IMA checking policy, if the selected software list is valid.
 * 
 * @param policy_path  [in] path to the policy file
 * @param swSelection  [in] software selection list from the verifier side
 * @return true 
 * @return false 
 */
bool is_authenticated(char * policy_path, events * swSelection);

#endif /* PPRA_ATTEST_H */