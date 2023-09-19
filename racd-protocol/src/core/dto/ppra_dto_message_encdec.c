#include <qcbor/qcbor.h>
#include <stdio.h>
#include "core/dto/ppra_dto_message_encdec.h"
#include "util/cbor_help.h"

/* Encode function 

* code is from https://github.com/Fraunhofer-SIT/charra/blob/master/src/core/charra_marshaling.c

*/
uint8_t *msg_attestation_request_encode(msg_attestation_request_dto *request, uint32_t *buf_len)
{

    UsefulBuf buf;
    buf.len = get_size_of_msg_attestation_request(request);
    buf.ptr = malloc(buf.len);
    //printf("request enc size :%zu",buf.len);
    QCBOREncodeContext ec;

    QCBOREncode_Init(&ec, buf);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "key_id" */
    UsefulBufC key_id = {
        request->sig_key_id, request->sig_key_id_len};
    QCBOREncode_AddBytes(&ec, key_id);

    /* encode "nonce" */
    UsefulBufC nonce = {
        request->nonce, request->nonce_len};
    QCBOREncode_AddBytes(&ec, nonce);

    {
        QCBOREncode_OpenArray(&ec);

        for (uint32_t i = 0; i < request->pcr_selections_len; ++i)
        {
            {
                QCBOREncode_OpenArray(&ec);

                QCBOREncode_AddInt64(&ec,
                                     request->pcr_selections[i].tcg_hash_alg_id);

                {
                    QCBOREncode_OpenArray(&ec);

                    for (uint32_t j = 0;
                         j < request->pcr_selections[i].pcrs_len;
                         ++j)
                    {

                        QCBOREncode_AddUInt64(&ec,
                                              request->pcr_selections[i].pcrs[j]);
                    }

                    /* close array: pcrs_array_encoder */
                    QCBOREncode_CloseArray(&ec);
                }

                /* close array: pcr_selection_array_encoder */
                QCBOREncode_CloseArray(&ec);
            }
        }

        /* close array: pcr_selections_array_encoder */
        QCBOREncode_CloseArray(&ec);
    }

    /* Adding encoded swSelection (events encoded)*/
    UsefulBufC swSelection = {
        request->swSelection, request->swSelection_len};
    QCBOREncode_AddBytes(&ec, swSelection);

    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    UsefulBufC Encoded;

    QCBORError uErr;
    uErr = QCBOREncode_Finish(&ec, &Encoded);
    // //printf("\n%d\n", Encoded.len);
    // //printf("\n%u\n", uErr);
    if (uErr != QCBOR_SUCCESS)
    {
        printf("\nattest : %u\n", uErr);
    }
    //printf("\req_enc : %u\n", uErr);

    uint8_t *reBuf = memcpy(malloc(Encoded.len), Encoded.ptr, Encoded.len);
    *buf_len = Encoded.len;
    free(buf.ptr);
    return reBuf;
}

/* Decode function */
int msg_attestation_request_decode(msg_attestation_request_dto *request, uint8_t *buf, uint64_t buf_len)
{

    QCBORDecodeContext dc;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    QCBORDecode_Init(&dc, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&dc, &item);

    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4)
    {
        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            request->sig_key_id_len = item.val.string.len;
            memcpy(request->sig_key_id, item.val.string.ptr, request->sig_key_id_len);
        }

        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            request->nonce_len = item.val.string.len;
            memcpy(request->nonce, item.val.string.ptr, request->nonce_len);
        }

        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_ARRAY)
        {
            request->pcr_selections_len = (uint32_t)item.val.uCount;
        }

        for (uint32_t i = 0; i < request->pcr_selections_len; ++i)
        {
            /* parse array "pcr-selection" */
            QCBORDecode_GetNext(&dc, &item);
            if (item.uDataType == QCBOR_TYPE_ARRAY)
            {
                QCBORDecode_GetNext(&dc, &item);
                if (item.uDataType == QCBOR_TYPE_INT64)
                {
                    request->pcr_selections[i].tcg_hash_alg_id = (uint16_t)item.val.uint64;

                    QCBORDecode_GetNext(&dc, &item);
                    if (item.uDataType == QCBOR_TYPE_ARRAY)
                    {

                        request->pcr_selections[i].pcrs_len = (uint32_t)item.val.uCount;
                        for (uint32_t j = 0; j < request->pcr_selections[i].pcrs_len; ++j)
                        {
                            QCBORDecode_GetNext(&dc, &item);
                            if (item.uDataType == QCBOR_TYPE_INT64)
                            {

                                request->pcr_selections[i].pcrs[j] = (uint8_t)item.val.uint64;
                            }
                        }
                    }
                }
            }
        }
        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            request->swSelection_len = item.val.string.len;
            request->swSelection = memcpy(malloc(request->swSelection_len), item.val.string.ptr, request->swSelection_len);
        }
    }
    QCBORError uErr;
    uErr = QCBORDecode_Finish(&dc);
    if (uErr != QCBOR_SUCCESS)
    {
           printf("request: %u\n", uErr);
    }

    return 1; //TODO CHANGE
}

size_t get_size_of_msg_attestation_request(msg_attestation_request_dto *request)
{

    size_t size = 1;
    size += get_size_for_cbor_bstring(request->sig_key_id_len);
    //size += request->sig_key_id_len;
    size += get_size_for_cbor_bstring(request->nonce_len);
    //size += request->nonce_len;
    size += get_size_for_cbor_uint(request->pcr_selections_len);
    size += request->pcr_selections_len;
    size += get_size_for_cbor_bstring(request->swSelection_len);
    //size += request->swSelection_len;
    size += get_size_for_cbor_uint(request->pcr_selections->pcrs_len);
    size += request->pcr_selections->pcrs_len;
    size += get_size_for_cbor_uint(request->pcr_selections->tcg_hash_alg_id);
 


    return size;
}



void free_msg_attestation_request(msg_attestation_request_dto * request){
    free(request->swSelection);
}
/* Encode function */
uint8_t *msg_attestation_response_encode(msg_attestation_response_dto *response, uint32_t *buf_len)
{
    UsefulBuf buf;
    buf.len = get_size_of_msg_attestation_response(response);
    buf.ptr = malloc(buf.len);

    //printf("response enc size :%d\n",buf.len);
    QCBOREncodeContext ec;

    QCBOREncode_Init(&ec, buf);

    /* root array */
    QCBOREncode_OpenArray(&ec);

    /* encode "attestation-data" */
    UsefulBufC attestation_data = {response->attestation_data,
                                   response->attestation_data_len};
    QCBOREncode_AddBytes(&ec, attestation_data);

    /* encode "tpm2-signature" */
    UsefulBufC tpm2_signature = {response->tpm2_signature,
                                 response->tpm2_signature_len};
    QCBOREncode_AddBytes(&ec, tpm2_signature);

    	/* encode "tpm2-key-signature" */
	UsefulBufC Tpm2KeyPublic = {response->tpm2_public_key,
		response->tpm2_public_key_len};
	QCBOREncode_AddBytes(&ec, Tpm2KeyPublic);

    /* encode "eventrecordbystestring" */
    UsefulBufC eventrecordsbytestring = {response->eventrecords_bytestr, response->eventrecords_bytestr_len};

    QCBOREncode_AddBytes(&ec, eventrecordsbytestring);
    /* close array: root_array_encoder */
    QCBOREncode_CloseArray(&ec);

    UsefulBufC Encoded;

    QCBORError uErr;
    uErr = QCBOREncode_Finish(&ec, &Encoded);
    // //printf("\n%d\n", Encoded.len);
    // //printf("\n%u\n", uErr);
    if (uErr != QCBOR_SUCCESS)
    {
        printf("\nattest : %u\n", uErr);
    }

    uint8_t *reBuf = memcpy(malloc(Encoded.len), Encoded.ptr, Encoded.len);
    *buf_len = Encoded.len;
    free(buf.ptr);
    return reBuf;
}

/* Decode function */
int msg_attestation_response_decode(msg_attestation_response_dto *response, uint8_t *buf, uint64_t buf_len)
{

    QCBORDecodeContext dc;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    QCBORDecode_Init(&dc, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&dc, &item);

    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 4)
    {
        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            response->attestation_data_len = item.val.string.len;
            memcpy(response->attestation_data, item.val.string.ptr, response->attestation_data_len);
        }

        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            response->tpm2_signature_len = item.val.string.len;
            memcpy(response->tpm2_signature, item.val.string.ptr, response->tpm2_signature_len);
        }

        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            response->tpm2_public_key_len = item.val.string.len;
            memcpy(response->tpm2_public_key, item.val.string.ptr, response->tpm2_public_key_len);
        }

        QCBORDecode_GetNext(&dc, &item);
        if (item.uDataType == QCBOR_TYPE_BYTE_STRING)
        {
            response->eventrecords_bytestr_len = item.val.string.len;
            response->eventrecords_bytestr = memcpy(malloc(response->eventrecords_bytestr_len), item.val.string.ptr, response->eventrecords_bytestr_len);
        }
    }

    

    QCBORError uErr;
    uErr = QCBORDecode_Finish(&dc);
    if (uErr != QCBOR_SUCCESS)
    {
        printf("response: %u\n", uErr);
    }
    //
    return 1; //TODO CHANGE
}

size_t get_size_of_msg_attestation_response(msg_attestation_response_dto * response)
{
    size_t size = 1;
    size += get_size_for_cbor_bstring(response->attestation_data_len);
    //printf("1 %lu\n",size);
    //size += response->attestation_data_len;
    //printf("2 %lu\n",size);
    size += get_size_for_cbor_bstring(response->tpm2_signature_len);
    //printf("3 %lu\n",size);
    //size += response->tpm2_signature_len;
    //printf("4 %lu\n",size);
    size += get_size_for_cbor_bstring(response->tpm2_public_key_len);
    //printf("5 %lu\n",size);
    //size += response->tpm2_public_key_len;
    //printf("6 %lu\n",size);
    size += get_size_for_cbor_bstring(response->eventrecords_bytestr_len);
    //printf("7 %lu\n",size);
    //size += response->eventrecords_bytestr_len;
    //printf("8 %lu\n",size);

    return size;
}

void free_msg_attestation_response(msg_attestation_response_dto * response){
    free(response->eventrecords_bytestr);
}
