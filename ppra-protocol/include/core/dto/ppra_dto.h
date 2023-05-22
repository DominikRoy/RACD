#include <stdlib.h>
#include <stdint.h>
#include <tss2/tss2_tpm2_types.h>

#ifndef PPRA_DTO_H
#define PPRA_DTO_H

#define SIG_KEY_ID_MAXLEN 256

/* Struct for setup data */
typedef struct event
{
    char * file_name;
    uint64_t file_name_len;

    char * file_path; 
    uint64_t file_path_len;   
    uint8_t * file_hash;

} event;

typedef struct events
{
    event* e;//reference to event pointer
    size_t count;
}events;


typedef struct eventrecord{
    uint8_t pcr;
    uint8_t * event_hash;
    events event;
    uint8_t * c;
    uint8_t * s;
}eventrecord;

typedef struct eventrecords{
    eventrecord* record;//reference to event pointer
    size_t count;
    //uint8_t * nonce;

}eventrecords;


/*MESSAGE  https://github.com/Fraunhofer-SIT/charra/blob/master/src/core/charra_dto.h*/
typedef struct {
	uint16_t tcg_hash_alg_id; // TPM2_ALG_ID
	uint32_t pcrs_len;
	uint8_t pcrs[TPM2_MAX_PCRS];
} pcr_selection_dto;


typedef struct {
	size_t sig_key_id_len;
	uint8_t sig_key_id[SIG_KEY_ID_MAXLEN];
	size_t nonce_len;
	uint8_t nonce[sizeof(TPMU_HA)];
	size_t pcr_selections_len;
	pcr_selection_dto pcr_selections[TPM2_NUM_PCR_BANKS];
    uint8_t * swSelection;
    size_t swSelection_len;

} msg_attestation_request_dto;

typedef struct {
	// TODO Use tpms_attest_dto attestation_data;
	uint32_t attestation_data_len;
	uint8_t attestation_data[sizeof(TPMS_ATTEST)];
	uint32_t tpm2_signature_len;
	uint8_t tpm2_signature[sizeof(TPMT_SIGNATURE)];
    uint32_t tpm2_public_key_len;
	uint8_t tpm2_public_key[sizeof(TPM2B_PUBLIC)];
    uint8_t * eventrecords_bytestr;
    size_t eventrecords_bytestr_len;
} msg_attestation_response_dto;






#endif /* PPRADTO_H */