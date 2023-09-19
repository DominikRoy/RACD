#ifndef PPRA_DTO_FUNC_H
#define PPRA_DTO_FUNC_H
#include "core/dto/ppra_dto.h"

/* Encode function */
uint8_t* msg_attestation_request_encode(msg_attestation_request_dto * request, uint32_t * buf_len);

/* Decode function */
int msg_attestation_request_decode(msg_attestation_request_dto * request, uint8_t *buf, uint64_t buf_len);


size_t get_size_of_msg_attestation_request(msg_attestation_request_dto * request);

void free_msg_attestation_request(msg_attestation_request_dto * request);



/* Encode function */
uint8_t* msg_attestation_response_encode(msg_attestation_response_dto * response, uint32_t * buf_len);

/* Decode function */
int msg_attestation_response_decode(msg_attestation_response_dto * response, uint8_t *buf, uint64_t buf_len);


size_t get_size_of_msg_attestation_response(msg_attestation_response_dto * response);

void free_msg_attestation_response(msg_attestation_response_dto * response);

#endif /* PPRA_DTO_FUNC_H */