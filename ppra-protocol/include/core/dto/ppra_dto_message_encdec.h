#ifndef PPRA_DTO_FUNC_H
#define PPRA_DTO_FUNC_H
/**
 * @file ppra_dto_message_encdec.h
 * @author Dominik Roy George (dominik.roy.george@sit.fraunhofer.de)
 * @brief The header file is used to implement the encoding and decoding function for the dtos to be transfered between
 * verifier and attester.
 * @version 0.1
 * @date 2021-04-12
 * 
 * @copyright Copyright (c) 2021
 * 
 */
#include "core/dto/ppra_dto.h"

/* Encode function */
/**
 * @brief This function encodes the dto into a bytestring so it can be transfered over the channel
 * 
 * @param response [in] The dto with information to be encoded
 * @param buf_len [out] length of the bytestring
 * @return uint8_t* returns the bytestring
 */
uint8_t* msg_attestation_request_encode(msg_attestation_request_dto * request, uint32_t * buf_len);

/* Decode function */
/**
 * @brief  This function decodes the bytestring and maps the information into the dto.
 * 
 * @param response [out] the dto will filled with decoded information
 * @param buf [in] Bytestring
 * @param buf_len [in] length of the bytestring
 * @return int 
 */
int msg_attestation_request_decode(msg_attestation_request_dto * request, uint8_t *buf, uint64_t buf_len);

/**
 * @brief Get the size of msg attestation request object
 * 
 * @param request 
 * @return size_t 
 */
size_t get_size_of_msg_attestation_request(msg_attestation_request_dto * request);

/**
 * @brief Frees the msg_attestation_request dto 
 * 
 * @param request 
 */
void free_msg_attestation_request(msg_attestation_request_dto * request);



/* Encode function */
/**
 * @brief This function encodes the dto into a bytestring so it can be transfered over the channel
 * 
 * @param response [in] The dto with information to be encoded
 * @param buf_len [out] length of the bytestring
 * @return uint8_t* returns the bytestring
 */
uint8_t* msg_attestation_response_encode(msg_attestation_response_dto * response, uint32_t * buf_len);

/* Decode function */
/**
 * @brief  This function decodes the bytestring and maps the information into the dto.
 * 
 * @param response [out] the dto will filled with decoded information
 * @param buf [in] Bytestring
 * @param buf_len [in] length of the bytestring
 * @return int 
 */
int msg_attestation_response_decode(msg_attestation_response_dto * response, uint8_t *buf, uint64_t buf_len);

/**
 * @brief Get the size of msg attestation response object
 * 
 * @param response 
 * @return size_t 
 */
size_t get_size_of_msg_attestation_response(msg_attestation_response_dto * response);

/**
 * @brief Frees the msg_attestation_response dto
 * 
 * @param response 
 */
void free_msg_attestation_response(msg_attestation_response_dto * response);

#endif /* PPRA_DTO_FUNC_H */