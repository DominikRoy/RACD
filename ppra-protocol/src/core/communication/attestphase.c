
#include <tss2/tss2_tpm2_types.h>
#include "core/communication/attestphase.h"
#include "core/communication/events.h"
#include "core/dto/ppra_dto_message_encdec.h"
#include "util/nonce.h"
#include "util/tpm2_util.h"
#include "core/tpm2_charra/charra_helper.h"
#include "core/tpm2_charra/charra_key_mgr.h"
#include "core/tpm2_charra/charra_util.h"
#include "core/hash/hash_sig_verify.h"
#include "util/buftohex.h"
#include <mbedtls/sha256.h>

#define PCR 10
#define LOG_FILE_NAME "pcr0.log"

uint8_t *eventrecords_encode(eventrecords *records, uint32_t *buf_len)
{
    UsefulBuf buf;
    buf.len = get_size_of_eventrecords(records);
    buf.ptr = malloc(buf.len);
    QCBOREncodeContext eCtx;
    QCBOREncode_Init(&eCtx, buf);
    QCBOREncode_OpenArray(&eCtx);
    QCBOREncode_OpenArray(&eCtx);
    for (uint64_t i = 0; i < records->count; i++)
    {

        QCBOREncode_OpenArray(&eCtx);
        QCBOREncode_AddUInt64(&eCtx, records->record[i].pcr);
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){records->record[i].event_hash, TPM2_SHA256_DIGEST_SIZE});

        if (records->record[i].c != NULL)
        {
            uint32_t eventencoded_len;
            uint8_t *eventencoded = events_encode(&records->record[i].event, &eventencoded_len);
            QCBOREncode_AddEncoded(&eCtx, (UsefulBufC){eventencoded, eventencoded_len});
            free(eventencoded);
        }

        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){records->record[i].c, records->record[i].c == NULL ? 0 : crypto_generichash_BYTES_MAX});
        QCBOREncode_AddBytes(&eCtx, (UsefulBufC){records->record[i].s, records->record[i].s == NULL ? 0 : TPM2_SHA256_DIGEST_SIZE});
        QCBOREncode_CloseArray(&eCtx);
    }
    QCBOREncode_CloseArray(&eCtx);
    QCBOREncode_CloseArray(&eCtx);
    UsefulBufC Encoded;

    QCBORError uErr;
    uErr = QCBOREncode_Finish(&eCtx, &Encoded);

    if (uErr != QCBOR_SUCCESS)
    {
        printf("\nattest : %u\n", uErr);
    }

    uint8_t *reBuf = memcpy(malloc(Encoded.len), Encoded.ptr, Encoded.len);
    *buf_len = Encoded.len;
    free(buf.ptr);
    return reBuf;

}

int eventrecords_decode(events *evlist, bool selection, eventrecords *records, uint8_t *buf, uint64_t buf_len)
{
    QCBORDecodeContext DCtx;
    UsefulBufC bufC;
    QCBORItem item;
    bufC.len = buf_len;
    bufC.ptr = buf;
    bool selected = false;
    QCBORDecode_Init(&DCtx, bufC, QCBOR_DECODE_MODE_NORMAL);
    QCBORDecode_GetNext(&DCtx, &item);
    if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 1)
    {

        QCBORDecode_GetNext(&DCtx, &item);
        if (item.uDataType == QCBOR_TYPE_ARRAY)
        {
            records->count = item.val.uCount;
            records->record = calloc(records->count, sizeof(eventrecord));
    
        }

        for (uint8_t i = 0; i < records->count; i++)
        {

            selected = false;
            QCBORDecode_GetNext(&DCtx, &item);
            uint16_t count = item.val.uCount;
            if (item.uDataType == QCBOR_TYPE_ARRAY && (count == 5 || count == 4))
            {
                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_INT64)
                {
                    records->record[i].pcr = item.val.int64;
                }
                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && TPM2_SHA256_DIGEST_SIZE == item.val.string.len)
                {
                    records->record[i].event_hash = memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len);
                }

                if (count == 5)
                {
                    QCBORDecode_GetNext(&DCtx, &item);
                    if (item.uDataType == QCBOR_TYPE_ARRAY)
                    {

                        records->record[i].event.count = item.val.uCount;
                        records->record[i].event.e = calloc(records->record[i].event.count, sizeof(event));
                        for (uint8_t j = 0; j < records->record[i].event.count; j++)
                        {
                            QCBORDecode_GetNext(&DCtx, &item);

                            if (item.uDataType == QCBOR_TYPE_ARRAY && item.val.uCount == 3)
                            {

                                QCBORDecode_GetNext(&DCtx, &item);

                                if (item.uDataType == QCBOR_TYPE_TEXT_STRING)
                                {

                                    if (!selection)
                                    {
                                        records->record[i].event.e[j].file_name = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                                        records->record[i].event.e[j].file_name[item.val.string.len] = '\0';
                                        records->record[i].event.e[j].file_name_len = item.val.string.len;

                                    }
                                    else
                                    {
                                        for (size_t k = 0; k < evlist->count; k++)
                                        {

                                            if ((evlist->e[k].file_name_len== item.val.string.len)&&(memcmp(evlist->e[k].file_name, item.val.string.ptr, evlist->e[k].file_name_len) == 0))
                                            {
                                                records->record[i].event.e[j].file_name = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                                                records->record[i].event.e[j].file_name[item.val.string.len] = '\0';
                                                records->record[i].event.e[j].file_name_len = item.val.string.len;

                                                selected = true;
                                                break;
                                            }
                                        }
                                        if (!selected)
                                        {
                                            records->record[i].event.e[j].file_name = "";
                                            records->record[i].event.e[j].file_name_len = 0;
                                        }
                                    }
                                }

                                QCBORDecode_GetNext(&DCtx, &item);

                                if (item.uDataType == QCBOR_TYPE_TEXT_STRING)
                                {
                                    if (((selection && selected) || !selection))
                                    {
                                        records->record[i].event.e[j].file_path = memcpy(malloc(item.val.string.len + 1), item.val.string.ptr, item.val.string.len);
                                        records->record[i].event.e[j].file_path[item.val.string.len] = '\0';
                                        records->record[i].event.e[j].file_path_len = item.val.string.len;
                                    
                                    }
                                    else
                                    {
                                        records->record[i].event.e[j].file_path = "";
                                        records->record[i].event.e[j].file_path_len = 0;
                                    }
                                }

                                QCBORDecode_GetNext(&DCtx, &item);

                                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && TPM2_SHA256_DIGEST_SIZE == item.val.string.len)
                                {
                                    records->record[i].event.e[j].file_hash = ((selection && selected) || !selection) ? memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len) : NULL;
                                }
                            }
                        }

                        if (selection && !selected)
                        {
                            free(records->record[i].event.e);
                        }
                    }
                }
                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && crypto_generichash_BYTES_MAX == item.val.string.len)
                {
                    records->record[i].c = ((selection && selected) || !selection) ? memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len) : NULL;
                }

                QCBORDecode_GetNext(&DCtx, &item);
                if (item.uDataType == QCBOR_TYPE_BYTE_STRING && TPM2_SHA256_DIGEST_SIZE == item.val.string.len)
                {
                    records->record[i].s = ((selection && selected) || !selection) ? memcpy(malloc(item.val.string.len), item.val.string.ptr, item.val.string.len) : NULL;
                }
            }
        }
    }

    QCBORError uErr;
    uErr = QCBORDecode_Finish(&DCtx);
    if (uErr != QCBOR_SUCCESS)
    {
        printf("eventrec_dec: %u\n", uErr);
    }
    

    return 1;
}

uint8_t *create_attestrequest(msg_attestation_request_dto *request, uint32_t *buflen)
{

    return msg_attestation_request_encode(request, buflen);
}

uint8_t *send_attestresponse(mbedtls_x509_name subject,TPM2B_PUBLIC * public_key, uint8_t *p_buf, uint64_t len, uint32_t *buf_len)
{

    char subjectname[60];
    //char * subjectname = "CN=localhost, O=Verifier, C=DE";
    mbedtls_x509_dn_gets(subjectname, 60, &subject);

    if (access(subjectname, F_OK) == -1)
    {
        char *nreg = "not auth";
        *buf_len = strlen(nreg);
        return (uint8_t *)nreg;
    }

    msg_attestation_request_dto req;
    msg_attestation_request_decode(&req, p_buf, len);

    events evlist;
    uint32_t buf_len_int;

    events_decode(&evlist, req.swSelection, req.swSelection_len);

    if (is_authenticated(subjectname, &evlist))
    {

     

        char *buffer;
        size_t f_size;
        loadFile(LOG_FILE_NAME, &buffer, &f_size);

        //Selection
        eventrecords records_selected;
        eventrecords_decode(&evlist, true, &records_selected, (uint8_t *)buffer, f_size);

        uint8_t *ret = eventrecords_encode(&records_selected, &buf_len_int);
       
        /* --- TPM quote --- */
        ESYS_TR sig_key_handle = ESYS_TR_NONE;
        //TPM2B_PUBLIC *public_key2 = NULL;
        TSS2_RC charra_r = TSS2_RC_SUCCESS;
        TSS2_RC tss_r = 0;

  

        /* nonce */
        if (req.nonce_len > sizeof(TPMU_HA))
        {
            printf("Nonce too long.");
        }
        TPM2B_DATA qualifying_data = {.size = 0, .buffer = {0}};
        qualifying_data.size = req.nonce_len;
        memcpy(qualifying_data.buffer, req.nonce, req.nonce_len);



        /* PCR selection */
        TPML_PCR_SELECTION pcr_selection = {0};
        if ((charra_r = charra_pcr_selections_to_tpm_pcr_selections(
                 req.pcr_selections_len, req.pcr_selections, &pcr_selection)) !=
            TSS2_RC_SUCCESS)
        {
            printf(" PCR selection conversion error.");
        }

        /* initialize ESAPI */
        ESYS_CONTEXT *esys_ctx = NULL;
        if ((tss_r = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS)
        {
            printf(" Esys_Initialize.");
        }

        /* load TPM key */


        if((charra_r = tpm2_load_key_from_nvram(esys_ctx,&sig_key_handle)) !=TSS2_RC_SUCCESS){
            printf("Could not load TPM key from NVRAM.");
        }


        /* do the TPM quote */
        TPM2B_ATTEST *attest_buf = NULL;
        TPMT_SIGNATURE *signature = NULL;
        if ((tss_r = tpm2_quote(esys_ctx, sig_key_handle, &pcr_selection,
                                &qualifying_data, &attest_buf, &signature)) != TSS2_RC_SUCCESS)
        {
            printf("TPM2 quote.");
        }
        else
        {
            printf(" TPM Quote successful.\n");
        }

        msg_attestation_response_dto res = {
            .attestation_data_len = attest_buf->size,
            .attestation_data = {0}, // must be memcpy'd, see below
            .tpm2_signature_len = sizeof(*signature),
            .tpm2_signature = {0}, // must be memcpy'd, see below
            .tpm2_public_key_len = sizeof(*public_key),
            .tpm2_public_key = {0}}; // must be memcpy'd, see below
        memcpy(res.attestation_data, attest_buf->attestationData,res.attestation_data_len);
        memcpy(res.tpm2_signature, signature, res.tpm2_signature_len);
        memcpy(res.tpm2_public_key, public_key, res.tpm2_public_key_len);


        res.eventrecords_bytestr_len = buf_len_int;
        res.eventrecords_bytestr = malloc(buf_len_int);
        memcpy(res.eventrecords_bytestr, ret, buf_len_int);

        uint8_t *res_enc = msg_attestation_response_encode(&res, buf_len);


    
        //free(public_key);
        free(attest_buf);
        free(signature);
        free_events(&evlist);
        free(buffer);
        free(ret);
        free_msg_attestation_response(&res);
        free_eventrecords(&records_selected);
        /* finalize ESAPI */
        Esys_Finalize(&esys_ctx);

        return res_enc;
    }
    else
    {
        free_events(&evlist);
        free_msg_attestation_request(&req);
        char *nreg = "selection invalid";
        *buf_len = strlen(nreg);
        return (uint8_t *)nreg;
    }
}

void verify_attestresponse(uint8_t nonce[crypto_box_NONCEBYTES], char *rim_path, uint8_t *buf, uint64_t len)
{

    TSS2_RC charra_r = 0;

    CHARRA_RC charra_value = CHARRA_RC_SUCCESS;



    TPM2B_ATTEST attest = {0};
    TPMT_SIGNATURE signature = {0};
    bool attestation_result_partial_integrity = false;
    bool attestation_result_rim_match = false;
    bool attestation_result_signature = false;

    TPMS_ATTEST attest_struct = {0};

    bool attestation_result_nonce = false;

    bool attestation_result_pcrs = false;

    bool attestation_result = false;

    events rim;
    char *buffer;
    size_t f_size;

    loadFile(rim_path, &buffer, &f_size);
    events_decode(&rim, (uint8_t *)buffer, f_size);

    msg_attestation_response_dto res;
    msg_attestation_response_decode(&res, buf, len);

    eventrecords records;
    eventrecords_decode(NULL, false, &records, res.eventrecords_bytestr, res.eventrecords_bytestr_len);


    /* compute PCR composite digest from reference PCRs */
    uint8_t pcr_composite_digest[TPM2_SHA256_DIGEST_SIZE] = {0};

    uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE];

    folding_digest_init_sha256(pcr_folding_digest);

    bool *verify = calloc(rim.count, sizeof(bool));
    uint64_t j;
    size_t index = 0;
    size_t rim_match = 0;
    for (j = 0; j < records.count; j++)
    {

        if (records.record[j].c != NULL)
        {
            verify[index] = nizkverify_eventrecord(&records.record[j]);
            if (!verify[index])
            {
                break;
            }
            for (uint64_t k = 0; k < rim.count; k++)
            {

                if (memcmp(rim.e[k].file_name, records.record[j].event.e[0].file_name, rim.e[k].file_name_len <= records.record[j].event.e[0].file_name_len ? rim.e[k].file_name_len : records.record[j].event.e[0].file_name_len) == 0)
                {
                    rim_match++;
                    break;
                }
            }

            index++;
        }

        extend_folding_digest_sha256(pcr_folding_digest, records.record[j].pcr, records.record[j].event_hash);
   
    }

    if ((index == rim.count) && (rim_match == rim.count))
    {
        attestation_result_partial_integrity = true;
        attestation_result_rim_match = true;
        printf("\n partial true and rim match true!\n");
    }

    /*START OF VERIFYING TPM QUOTE*/

    if (res.attestation_data_len > sizeof(TPM2B_ATTEST))
    {
        printf(
            "Length of attestation data exceeds maximum allowed size.");
    }
    if (res.tpm2_signature_len > sizeof(TPMT_SIGNATURE))
    {
        printf(
            "Length of signature exceeds maximum allowed size.");
    }


    // /* load TPM key */
    TPM2B_PUBLIC *tpm2_public_key = (TPM2B_PUBLIC *)res.tpm2_public_key;

    attest.size = res.attestation_data_len;
    memcpy(attest.attestationData, res.attestation_data, res.attestation_data_len);

    memcpy(&signature, res.tpm2_signature, res.tpm2_signature_len);

    /* --- verify attestation signature --- */
   
    /* convert TPM public key to mbedTLS public key */
    mbedtls_rsa_context mbedtls_rsa_pub_key = {0};
    if ((charra_value = charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
             tpm2_public_key, &mbedtls_rsa_pub_key)) != CHARRA_RC_SUCCESS)
    {
        printf(" mbedTLS RSA error");
    }

    if ((charra_value = charra_crypto_rsa_verify_signature(&mbedtls_rsa_pub_key,
                                                           MBEDTLS_MD_SHA256, res.attestation_data,
                                                           (size_t)res.attestation_data_len,
                                                           signature.signature.rsapss.sig.buffer)) == CHARRA_RC_SUCCESS)
    {
        printf(
            "   => TPM Quote signature is valid!\n");
        attestation_result_signature = true;
    }
    else
    {
        printf(
            "   => TPM Quote signature is NOT valid!");
    }
    // /* unmarshal attestation data */

    charra_r = charra_unmarshal_tpm2_quote(
        res.attestation_data_len, res.attestation_data, &attest_struct);

    /* --- verify nonce --- */
    attestation_result_nonce = charra_verify_tpm2_quote_qualifying_data(
        crypto_box_NONCEBYTES, nonce, &attest_struct);
    if (attestation_result_nonce == true)
    {
        printf(" => Nonce in TPM Quote is valid! (matches the one sent)\n");
    }
    else
    {
        printf(
            "    => Nonce in TPM Quote is NOT valid! (does "
            "not match the one sent)");
    }

    // /* compare reference PCR composite with actual PCR composite */
    compute_composite_digest_sha256(pcr_composite_digest, pcr_folding_digest, PCR); // dynamic pcr currently hardcoded for 10

    attestation_result_pcrs = charra_verify_tpm2_quote_pcr_composite_digest(
        &attest_struct, pcr_composite_digest, TPM2_SHA256_DIGEST_SIZE);
    if (attestation_result_pcrs == true)
    {
        printf(
            "    => PCR composite digest is valid! (matches the "
            "one from reference PCRs)\n");
    }
    else
    {
        printf(
            "   => PCR composite digest is NOT valid! (does "
            "not match the one from reference PCRs)");
    }

    /* --- output result --- */

    attestation_result = attestation_result_partial_integrity &&
                         attestation_result_rim_match &&
                         attestation_result_signature &&
                         attestation_result_nonce &&
                         attestation_result_pcrs;

    /* print attestation result */

    if (attestation_result)
    {
        printf(" \n\r  ATTESTATION SUCCESSFUL \n\r  ");
    }
    else
    {
        printf("ATTESTATION FAILED     ");
    }

  

    mbedtls_rsa_free(&mbedtls_rsa_pub_key);


    free_eventrecords(&records);
    free(buffer);
    free_events(&rim);
    free_msg_attestation_response(&res);
    free(verify);
}

size_t get_size_of_eventrecords(eventrecords *records)
{
    size_t size = 1; //array 2;
    size += get_size_for_cbor_uint(records->count);

    for (uint8_t i = 0; i < records->count; i++)
    {
        size += 1;
        size += get_size_for_cbor_uint(records->record[i].pcr);

        size += get_size_for_cbor_bstring(TPM2_SHA256_DIGEST_SIZE); //event hash
       
        if (records->record[i].c != NULL)
        {
            size += get_size_of_events(&records->record[i].event);
            size += get_size_for_cbor_bstring(crypto_generichash_BYTES_MAX); // c --> H(g_i||t_i||eventhash)
  
            size += get_size_for_cbor_bstring(TPM2_SHA256_DIGEST_SIZE); // s --> s= v_i -c*r
     
        }
        else
        {
            size += get_size_for_cbor_uint(0); // null c
            size += get_size_for_cbor_uint(0); // null s
        }
    }
    return size;
}

void free_eventrecords(eventrecords *records)
{
   
    for (uint64_t i = 0; i < records->count; i++)
    {
        if (records->record[i].c != NULL)
        {
            free(records->record[i].c);
            free(records->record[i].s);
            free_events(&records->record[i].event);
        }

        free(records->record[i].event_hash);
    }
    free(records->record);
}

void simulate_measured_boot(char *filepath) //simulate_measured_boot
{

    if (access(LOG_FILE_NAME, F_OK) == -1)
    {
        TSS2_RC tss_rc = 0;
        TPML_DIGEST_VALUES dig;

        dig.digests[0].hashAlg = TPM2_ALG_SHA256;
        dig.count = 1;

        ESYS_CONTEXT *esys_ctx = NULL;
        if ((tss_rc = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS)
        {
            printf("%s", "Error init");
        }

        char *buffer;
        size_t f_size;

        events evlist;
        loadFile(filepath, &buffer, &f_size);

        events_decode(&evlist, (uint8_t *)buffer, f_size);

        free(buffer);
        eventrecords records;
        records.count = evlist.count;
        records.record = calloc(evlist.count, sizeof(eventrecord));

        for (uint64_t index = 0; index < records.count; index++)

        {
            records.record[index].event.e = (event *)calloc(1, sizeof(struct event));
            records.record[index].event.count = 1;

            uint64_t fname_len = evlist.e[index].file_name_len;
            records.record[index].event.e[0].file_name = malloc(sizeof(char) * fname_len + 1);
            memcpy(records.record[index].event.e[0].file_name, evlist.e[index].file_name, fname_len);
            records.record[index].event.e[0].file_name[fname_len] = '\0';
            records.record[index].event.e[0].file_name_len = fname_len;

            uint64_t fpath_len = evlist.e[index].file_path_len;
            records.record[index].event.e[0].file_path = malloc(sizeof(char) * fpath_len + 1);
            memcpy(records.record[index].event.e[0].file_path, evlist.e[index].file_path, fpath_len);
            records.record[index].event.e[0].file_path[fpath_len] = '\0';
            records.record[index].event.e[0].file_path_len = fpath_len;

            records.record[index].event.e[0].file_hash = malloc(TPM2_SHA256_DIGEST_SIZE);
            memcpy(records.record[index].event.e[0].file_hash, evlist.e[index].file_hash, TPM2_SHA256_DIGEST_SIZE);


            nizksign_eventrecord(&records.record[index]);


            records.record[index].pcr = PCR;

            memcpy(dig.digests[0].digest.sha256, records.record[index].event_hash, TPM2_SHA256_DIGEST_SIZE);
            if ((tss_rc = tpm2_pcr_extend(esys_ctx, records.record[index].pcr, &dig)) != TSS2_RC_SUCCESS)
            {
                printf("%s", "Error ext");
                Esys_Finalize(&esys_ctx);
            }

        }

        uint32_t buf_len;
        uint8_t *ret = eventrecords_encode(&records, &buf_len);
        FILE *f = fopen(LOG_FILE_NAME, "wb");
        if (f == NULL)
            printf("file not found");
        fwrite(ret, buf_len, 1, f);

        fclose(f);
        free_eventrecords(&records);
        free_events(&evlist);
        free(ret);
        Esys_Finalize(&esys_ctx);
    }
}

bool is_authenticated(char *policy_path, events *swSelection)
{
    events policy;
    char *buffer;
    size_t f_size;
    loadFile(policy_path, &buffer, &f_size);
    events_decode(&policy, (uint8_t *)buffer, f_size);
    free(buffer);
    if (swSelection->count <= policy.count)
    {
        size_t counter = 0;
        for (uint64_t i = 0; i < policy.count; i++)
        {
            for (uint64_t j = 0; j < swSelection->count; j++)
            {
                if (memcmp(policy.e[i].file_name, swSelection->e[j].file_name, policy.e[i].file_name_len <= swSelection->e[j].file_name_len ? policy.e[i].file_name_len : swSelection->e[j].file_name_len) == 0)
                {
                    counter++;
                    break;
                }
            }
        }
        if (counter == swSelection->count)
        {
            free_events(&policy);
            return true;
        }
    }
    else
    {
        free_events(&policy);
        return false;
    }
}


void create_store_pk(TPM2B_PUBLIC ** out_public){
        TSS2_RC tss_rc = 0;
        ESYS_CONTEXT *esys_ctx = NULL;
        if ((tss_rc = Esys_Initialize(&esys_ctx, NULL, NULL)) != TSS2_RC_SUCCESS)
        {
            printf("%s", "Error init");
            
        }
        ESYS_TR sig_key_handle = ESYS_TR_NONE;
        if((tss_rc= ppra_create_store_tpm2_key(esys_ctx,&sig_key_handle,out_public))!= TSS2_RC_SUCCESS){
              printf("%s", "Error creating and storing key!");
              Esys_Finalize(&esys_ctx);
        }
        Esys_Finalize(&esys_ctx);

}