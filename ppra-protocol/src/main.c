#include <stdio.h>
#include <string.h>
#include <util/fileIO.h>
#include <core/hash/templatehash.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <libgen.h>
#include <util/clock-profiling.h>
#include <tss2/tss2_tpm2_types.h>
#include <util/nonce.h>
#include <sodium.h>
#include <mbedtls/sha256.h>
#include "core/hash/hash_sig_verify.h"
#include "core/hash/templatehash.h"
#include "core/communication/attestphase.h"

#include "core/communication/events.h"
#include "util/cbor_help.h"
#include "core/dto/ppra_dto_message_encdec.h"
#include "core/tpm2_charra/charra_util.h"

typedef struct
{
    char *path;
    char *name;
    long variant1;
    long variant2;
    long variant3;
    long variantristretto1;
    long variantristretto2;
    long variantristretto3;
} data;

typedef struct
{
    char *path;
    char *name;
} programs;

int main()
{

    uint8_t *output = calloc(32, sizeof(uint8_t)); /* SHA-256 outputs 32 bytes */
    uint8_t *output2 = calloc(32, sizeof(uint8_t));
    mbedtls_sha256_context ctx2;
    mbedtls_sha256_context ctx1;

    mbedtls_sha256_init(&ctx1);

    mbedtls_sha256_starts_ret(&ctx1, 0);

    mbedtls_sha256_init(&ctx2);
    mbedtls_sha256_starts_ret(&ctx2,
                              0); /* 0 here means use the full SHA-256, not the SHA-224 variant */
    const char *path0 = "/opt/visual-studio-code-insiders/bin/code-insiders";
    const char *path1 = "/bin/bash";
    const char *file0 = "code-insiders";
    const char *file1 = "bash";
    mbedtls_sha256_update_ret(&ctx1, (unsigned char *)path0, strlen(path0));
    mbedtls_sha256_update_ret(&ctx2, (unsigned char *)path1, strlen(path1));
    mbedtls_sha256_finish_ret(&ctx2, output);
    mbedtls_sha256_finish_ret(&ctx1, output2);
    mbedtls_sha256_free(&ctx1);
    mbedtls_sha256_free(&ctx2);

    for (int i = 0; i < 32; i++)
    {
        printf("%02x", output[i]);
    }
    printf("\r\n");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", output2[i]);
    }
    printf("\r\n");

    //     events evlist;
    // 	evlist.e=(event*) calloc(2, sizeof (struct event));
    // 	evlist.count=2;
    // 	evlist.e[0].file_name= malloc(1 + strlen(file0));
    //     evlist.e[0].file_path=malloc(1 + strlen(path0));
    // 	strcpy(evlist.e[0].file_name, file0);
    // 	strcpy(evlist.e[0].file_path, path0);
    // 	evlist.e[0].file_name_len = strlen(file0);
    // 	evlist.e[0].file_path_len = strlen(path0);
    // 	evlist.e[0].file_hash=output;

    // 	evlist.e[1].file_name= malloc(1 + strlen(file1));
    //     evlist.e[1].file_path=malloc(1 + strlen(path1));
    // 	strcpy(evlist.e[1].file_name, file1);
    // 	strcpy(evlist.e[1].file_path, path1);
    // 	evlist.e[1].file_name_len = strlen(file1);
    // 	evlist.e[1].file_path_len = strlen(path1);
    // 	evlist.e[1].file_hash=output2;
    // 	uint32_t buf_len;

    // 	uint8_t *testD = events_encode(&evlist,&buf_len);
    // 	printf("%d\n",buf_len);
    //     for (size_t i = 0; i < get_size_of_events(&evlist); i++) {
    //         printf("%02x", testD[i]);
    //     }
    //     printf("\r\n");

    // 	events eventlistdecoded;
    // 	events_decode(&eventlistdecoded,testD,buf_len);
    // 	printf("%d\n",eventlistdecoded.count);
    // 	printf("%d",memcmp(evlist.e[0].file_hash,eventlistdecoded.e[0].file_hash,TPM2_SHA256_DIGEST_SIZE));
    // 	printf("%d\n",memcmp(evlist.e[1].file_hash,eventlistdecoded.e[1].file_hash,TPM2_SHA256_DIGEST_SIZE));

    //     uint8_t nonce [crypto_box_NONCEBYTES];
    //     generateNonce(nonce);

    //     eventrecords records;
    //     records.record=(eventrecord*) calloc(2, sizeof (struct eventrecord));
    //     records.count=2;
    //     records.nonce=nonce;
    //     // for (size_t i = 0; i < crypto_box_NONCEBYTES; i++) {
    //     //     printf("%02x", records.nonce[i]);
    //     // }
    //     // printf("\r\n");
    //     // printf("%d\n",memcmp(records.nonce,nonce,crypto_box_NONCEBYTES));
    //     records.record[0].event=&evlist;
    //     records.record[1].event=&evlist;
    //     records.record[0].event_hash=output;
    //     records.record[0].c=output;
    //     records.record[0].s=output;
    //     records.record[0].pcr=12;
    //     records.record[1].event_hash=output2;
    //     records.record[1].c=output2;
    //     records.record[1].s=output2;
    //     records.record[1].pcr=12;
    //     uint32_t buf_len_attest;

    //     for (size_t i = 0; i < 32; i++) {
    //          printf("%02x", records.record[0].event.e[0].file_hash[i]);
    //     }
    //     printf("\r\n");

    //     uint8_t *testA = eventrecords_encode(&records,&buf_len_attest);
    // 	printf("%d\n",buf_len_attest);
    //     for (size_t i = 0; i < get_size_of_eventrecords(&records); i++) {
    //         printf("%02x", testA[i]);
    //     }
    //     printf("\r\n");

    //     eventrecords eventrecordsdecoded;
    // 	eventrecords_decode(&eventrecordsdecoded,testA,buf_len_attest);
    // 	printf("%d\n",eventrecordsdecoded.count);
    // 	printf("%d",memcmp(eventrecordsdecoded.record[0].event_hash,records.record[0].event_hash,TPM2_SHA256_DIGEST_SIZE));
    // 	printf("%d",memcmp(eventrecordsdecoded.record[0].c,records.record[0].c,TPM2_SHA256_DIGEST_SIZE));

    // 	printf("%d",memcmp(eventrecordsdecoded.record[0].event.e[0].file_hash,records.record[0].event.e[0].file_hash,TPM2_SHA256_DIGEST_SIZE));

    // 	printf("%d",memcmp(eventrecordsdecoded.record[1].event_hash,records.record[1].event_hash,TPM2_SHA256_DIGEST_SIZE));
    // 	printf("%d",memcmp(eventrecordsdecoded.record[1].c,records.record[1].c,TPM2_SHA256_DIGEST_SIZE));

    // 	printf("%d",memcmp(eventrecordsdecoded.record[1].event.e[0].file_hash,records.record[1].event.e[0].file_hash,TPM2_SHA256_DIGEST_SIZE));
    //     free (testA);

    //     loadFile("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/output","43:30:FD:94:E4:D2:02:A7:CD:9C:3");
    //     char * buffer = malloc(getFilesize());
    //     buffer = getBuffer();
    //     char * name ;
    //     char * path ;
    //     uint8_t * hash;

    //     char *next = NULL;
    //     char *first = strtok_r(buffer, "\n", &next);
    //     long count;
    //     count = strtol(first, (char **)NULL, 10);
    //     printf( " %lu\n", count );

    // while ((first = strtok_r(NULL, "\n", &next)) != NULL){
    //     char *part;
    //     char *posn;
    //     int c =0;
    //     printf("%s\n", first);
    //     part = strtok_r(first, ",", &posn);
    //     name = part;
    //     part = strtok_r(NULL, ",", &posn);
    //     path = part;
    //     part = strtok_r(NULL, ",", &posn);
    //     hash = part;
    //     printf("%s\n",name);
    //     printf("%s\n",path);
    //     printf("%s\n",hash);

    // }

    unsigned char digest[32];
    unsigned char NDdigest[32];
    char path[] = "/opt/visual-studio-code-insiders/bin/code-insiders";
    char name[] = "code-insiders";
    //char path [] ="/bin";
    //char name [] = "bash";

    //templatehash(path, name, digest);
    //NDhash(path,name,digest);
    //NDhashOpenSSL(path,name,digest);
    unsigned char r_i[128];
    // NDhashVariant1(path,name,digest,NDdigest,r_i);
    int indx = 0;
    unsigned char nonce[crypto_box_NONCEBYTES];
    // nizkdto dto[1];
    // dto[indx].fname = name;
    // dto[indx].fpath = path;
    //memcpy(dto[indx].temphash, digest , TPM2_SHA256_DIGEST_SIZE);
    //memcpy(dto[indx].nd, NDdigest , TPM2_SHA256_DIGEST_SIZE);
    //memcpy(dto[indx].ri, r_i , 128);
    generateNonce(nonce);
    //memcpy(dto[indx].nonce, nonce , crypto_box_NONCEBYTES);
    // //printf("%d",memcmp(dto[indx].temphash, digest , TPM2_SHA256_DIGEST_SIZE));
    // //printf("%d",memcmp(dto[indx].nd, NDdigest , TPM2_SHA256_DIGEST_SIZE));
    // printf("%d",memcmp(dto[indx].nonce, nonce , crypto_box_NONCEBYTES));
    // //printf("%d",memcmp(dto[indx].ri, r_i , 128));
    // printf("\n");
    // printf("\n\n---TEST WITH SIGNER AND VERIFIER FUNC---\n\n");
    // //nizksign(dto,indx);
    // //nizkverifier(dto,indx);
    // printf("\n\n---END TEST WITH SIGNER AND VERIFIER FUNC END---\n\n");

    eventrecord record;
    record.pcr = 12;
    record.event.count = 1;
    record.event.e = (event *)calloc(1, sizeof(struct event));

    record.event.e[0].file_name = malloc(1 + strlen(file0));
    record.event.e[0].file_path = malloc(1 + strlen(path0));
    strcpy(record.event.e[0].file_name, file0);
    strcpy(record.event.e[0].file_path, path0);
    record.event.e[0].file_name_len = strlen(file0);
    record.event.e[0].file_path_len = strlen(path0);
    record.event.e[0].file_hash = output;
    nizksign_eventrecord(&record);

    eventrecord record1;
    record1.pcr = 12;
    record1.event.count = 1;
    record1.event.e = (event *)calloc(1, sizeof(struct event));
    record1.event_hash = calloc(TPM2_SHA256_DIGEST_SIZE, sizeof(uint8_t));
    record1.c = calloc(2 * TPM2_SHA256_DIGEST_SIZE, sizeof(uint8_t));
    record1.s = calloc(TPM2_SHA256_DIGEST_SIZE, sizeof(uint8_t));
    memcpy(record1.event_hash, record.event_hash, TPM2_SHA256_DIGEST_SIZE);

    memcpy(record1.c, record.c, 2 * TPM2_SHA256_DIGEST_SIZE);

    memcpy(record1.s, record.s, TPM2_SHA256_DIGEST_SIZE);

    record1.event.e[0].file_name = malloc(1 + strlen(file0));
    record1.event.e[0].file_path = malloc(1 + strlen(path0));
    strcpy(record1.event.e[0].file_name, file0);
    strcpy(record1.event.e[0].file_path, path0);
    record1.event.e[0].file_name_len = strlen(file0);
    record1.event.e[0].file_path_len = strlen(path0);
    record1.event.e[0].file_hash = output;
    printf("\n");
    printf("\n\n---TEST WITH SIGNER AND VERIFIER FUNC---\n\n");
    uint8_t t[32];
    //templatehash(record1.event.e[0].file_path,record1.event.e[0].file_name,t);
    nizkverify_eventrecord(&record1);
    printf("\n\n---END TEST WITH SIGNER AND VERIFIER FUNC END---\n\n");
    free(record.event_hash);
    free(record.c);
    free(record.s);
    free(record.event.e[0].file_name);
    free(record.event.e[0].file_path);
    free(record.event.e);

    free(record1.event_hash);
    free(record1.c);
    free(record1.s);
    free(record1.event.e[0].file_name);
    free(record1.event.e[0].file_path);
    free(record1.event.e);

    free(output);
    free(output2);

    // templatehash(path,name,digest);
    // char * buffer;
    // int result;
    // size_t size;
    // result = loadFile("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/programs",&buffer,&size);
    // //printf("%s\n",buffer);
    // printf("%lu\n",size);
    // free(buffer);
    uint32_t buf_len;
    //uint8_t* test = create_setuprequest("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/test0.cbor",&buf_len);
    //free(test);

    //  eventrecords records;
    // records.nonce = nonce;

    // for (size_t i = 0; i < crypto_box_NONCEBYTES; i++)
    // {
    //     printf("%02x", records.nonce[i]);
    // }
    // printf("\n\r");
    // char * buffer;
    // size_t f_size;
    // loadFile("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/output/CN=localhost, O=Verifier, C=DE",&buffer,&f_size);
    // events evlist;
    // events_decode(&evlist,buffer,f_size);
    // //freeBuffer();
    // free(buffer);
    // records.count = evlist.count;
    // records.record = calloc(evlist.count, sizeof(eventrecord));
    // printf("count :%lu\n",records.count);

    // for (size_t index = 0; index < records.count; index++)

    // {
    //     records.record[index].event.e = (event *)calloc(1, sizeof(struct event));
    //     records.record[index].event.count = 1;

    //     size_t fname_len = evlist.e[index].file_name_len;
    //     records.record[index].event.e[0].file_name = malloc(sizeof(char )* fname_len+1);
    //     memcpy(records.record[index].event.e[0].file_name, evlist.e[index].file_name,fname_len);
    // 	records.record[index].event.e[0].file_name[fname_len] = '\0';
    //     records.record[index].event.e[0].file_name_len = fname_len;
    // 	printf("fname_len :%s\n",records.record[index].event.e[0].file_name);

    //     size_t fpath_len = evlist.e[index].file_path_len;
    //     records.record[index].event.e[0].file_path = malloc(sizeof(char ) * fpath_len+1);
    //     memcpy(records.record[index].event.e[0].file_path, evlist.e[index].file_path,fpath_len);
    // 	records.record[index].event.e[0].file_path[fpath_len] = '\0';
    //     records.record[index].event.e[0].file_path_len = fpath_len;

    // 	printf("path :%s\n",records.record[index].event.e[0].file_path);

    //     records.record[index].event.e[0].file_hash = malloc(TPM2_SHA256_DIGEST_SIZE);
    //     memcpy(records.record[index].event.e[0].file_hash, evlist.e[index].file_hash,TPM2_SHA256_DIGEST_SIZE);

    //     printf("%lu\n",records.record[index].event.e[0].file_path_len);
    //nizksign_eventrecord(&records.record[index], records.nonce);
    //nizkverify_eventrecord(&records.record[index], records.nonce);

    //     records.record[index].pcr = 12;

    // for (size_t i = 0; i < 32; i++)
    // {
    //     printf("%02x", records.record[index].event.e[0].file_hash[i]);
    // }
    //     printf("\n\r");
    //     for (size_t i = 0; i < 64; i++)
    //     {
    //         printf("%02x", records.record[index].c[i]);
    //     }
    //     printf("\n\r");
    //     for (size_t i = 0; i < 32; i++)
    //     {
    //         printf("%02x", records.record[index].s[i]);
    //     }
    //     printf("\n\r");

    // }

    // uint8_t *ret = eventrecords_encode(&records, buf_len);
    // free_eventrecords(&records);
    // free_events(&evlist);

    //Generator

    /* FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/output/programslocal5", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    events newevents;
    newevents.count = 10;
    newevents.e = calloc(newevents.count, sizeof(event));
    int indi = 0;
    uint8_t *output3 = calloc(32, sizeof(uint8_t));
    mbedtls_sha256_context ctx12;
    mbedtls_sha256_init(&ctx12);
     
    while ((read = getline(&line, &len, fp))!=-1)
    {
        //

        size_t ln = strlen(line) - 1;
        if (*line && line[ln] == '\n') 
        line[ln] = '\0';
        char * text = line;
        size_t fname_len = strlen(basename(line));
        newevents.e[indi].file_name = malloc(sizeof(char) * fname_len + 1);
        memcpy(newevents.e[indi].file_name, basename(line), fname_len);
        newevents.e[indi].file_name[fname_len] = '\0';
        newevents.e[indi].file_name_len = fname_len;
        size_t fpath_len = strlen(text);
        newevents.e[indi].file_path = malloc(sizeof(char) * fpath_len+1);

         printf("%s\n",text); 
        memcpy(newevents.e[indi].file_path, text, fpath_len);
        newevents.e[indi].file_path[fpath_len] = '\0';
        newevents.e[indi].file_path_len = fpath_len;
        printf("%s\n",newevents.e[indi].file_path);   
        
        printf("%d\n",strlen(newevents.e[indi].file_path));    
        char *buffer;
        size_t f_size = 0;

        printf("%d\n",strlen(line));
        loadFile(line,&buffer,&f_size);

       
        // size_t size = 0;


        printf("index: %d\n",indi);

        mbedtls_sha256_starts_ret(&ctx12, 0);
        mbedtls_sha256_update_ret(&ctx12, buffer, f_size);
        mbedtls_sha256_finish_ret(&ctx12, output3);
        newevents.e[indi].file_hash = calloc(32, sizeof(uint8_t));
        memcpy(newevents.e[indi].file_hash, output3, TPM2_SHA256_DIGEST_SIZE);
    free(buffer);
    indi++;
        
    }
    free(output3);
    mbedtls_sha256_free(&ctx12);

    fclose(fp);
    if (line)
        free(line);

    uint32_t buf_len_internal;

    uint8_t *encoded = events_encode(&newevents, &buf_len_internal);

    

    FILE *f = fopen("programs.cbor", "wb");
    if (f == NULL)
         return "file nof found! Prover side issue!";
    fwrite(encoded, buf_len_internal, 1, f);

    fclose(f);*/

    ////// END of GENERATOR
    char * buffer;
    size_t f_size;

    events l;
    loadFile("swSelection.cbor",&buffer,&f_size);
    	msg_attestation_request_dto req = {
    	.sig_key_id_len = 14,
    	.sig_key_id = {0}, // must be memcpy'd, see below
    	.nonce_len = crypto_box_NONCEBYTES,
    	.nonce = {0}, // must be memcpy'd, see below
    	.pcr_selections_len = 1,
    	.pcr_selections = {{
    		.tcg_hash_alg_id = TPM2_ALG_SHA256,
    		.pcrs_len = 1,
    		.pcrs = {0} // must be memcpy'd, see below
    	}}, .swSelection_len = f_size};
    memcpy(req.sig_key_id, "PK.RSA.default", 14);
    memcpy(req.nonce, nonce, crypto_box_NONCEBYTES);
    uint8_t TPM_PCR_SELECTION[TPM2_MAX_PCRS] = {10};
    uint32_t TPM_PCR_SELECTION_LEN = 1;
    memcpy(req.pcr_selections->pcrs, TPM_PCR_SELECTION, TPM_PCR_SELECTION_LEN);
    req.swSelection = malloc(f_size);
    memcpy(req.swSelection,buffer,f_size);
    printf("%d\n",get_size_of_msg_attestation_request(&req));
    uint32_t size_req;
    uint8_t * req_enc = msg_attestation_request_encode(&req,&size_req);
    FILE *f = fopen("request.cbor", "wb");
    if (f == NULL)
         return "file nof found! Prover side issue!";
    fwrite(req_enc, size_req, 1, f);

    fclose(f);

    //free(req.swSelection);
    // free(buffer);

    // loadFile("request.cbor",&buffer,&f_size);
    // printf("fsze: %d\n",size_req);
    // msg_attestation_request_dto req_dec;
    // msg_attestation_request_decode(&req_dec,buffer, f_size);
    // free(req_enc);

    // events_decode(&l, req_dec.swSelection, req_dec.swSelection_len);
    // free_msg_attestation_request(&req_dec);
    // //free(req_dec.swSelection);
    // printf("fsze: %d\n",l.count);

    // //printf("%d",size_req);

    // simulate_measured_boot("programs.cbor");
    // printf("before encoding!");
    // msg_attestation_request_encode(&req,&f_size);
    // printf("after encoding");
    f_size = 0;
    uint32_t buf_len_internal;
    uint8_t * reqq = create_attestrequest(&req,&f_size);
    free_msg_attestation_request(&req);
     mbedtls_x509_name subject;

    uint8_t *encoded = send_attestresponse(subject,reqq,f_size,&buf_len_internal);
    verify_attestresponse(nonce,"swSelection.cbor",encoded,buf_len_internal);

    // msg_attestation_response_dto res = {
    //     .attestation_data_len = 5,
    //     .attestation_data = {0},
    //     .tpm2_signature_len = 5,
    //     .tpm2_signature = {0}
    // };
    // memcpy(res.attestation_data,"test",res.attestation_data_len);
    // memcpy(res.tpm2_signature,"test",res.tpm2_signature_len);
    // res.eventrecords_bytestr_len = buf_len_internal;
    // res.eventrecords_bytestr = malloc (buf_len_internal);
    // memcpy(res.eventrecords_bytestr,encoded,buf_len_internal);
    // buf_len_internal =0;
    // uint8_t * res_enc = msg_attestation_response_encode(&res,&buf_len_internal);

    // f = fopen("response.cbor", "wb");
    // if (f == NULL)
    //      printf("file not open");
    // fwrite(res_enc, buf_len_internal, 1, f);

    // fclose(f);

    // free_msg_attestation_response(&res);
    // free(buffer);

    // loadFile("response.cbor",&buffer,&f_size);

    // msg_attestation_response_dto res_dec;
    // msg_attestation_response_decode(&res_dec,buffer, f_size);
    // free(res_enc);

    // eventrecords rs;
    // printf("fsze: %d\n",res_dec.eventrecords_bytestr_len);
    // eventrecords_decode(NULL,false,&rs, res_dec.eventrecords_bytestr, res_dec.eventrecords_bytestr_len);
    // free_msg_attestation_response(&res_dec);
    // printf("fsze: %d\n",rs.count);
    // printf("%s",rs.record[0].event.e[0].file_name);

    free(reqq);
    free(encoded);
    free(buffer);
    free_events(&l);
    //free_eventrecords(&rs);

    // uint8_t pcr_folding_digest[TPM2_MAX_PCRS][TPM2_SHA256_DIGEST_SIZE];
    // folding_digest_init_sha256(pcr_folding_digest);
    // for (size_t j = 0; j < TPM2_MAX_PCRS; j++)
    // {
    //     for (size_t i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++)
    //     {
    //         printf("%02x", pcr_folding_digest[j][i]);
    //     }
    //     printf("\n\r");
    // }

    // FILE *f = fopen("selected.cbor", "wb");
    // if (f == NULL)
    //     printf("file not open");
    // fwrite(encoded, buf_len_internal, 1, f);

    // fclose(f);
    // eventrecords records;
    // //eventrecords_decode(NULL,false,&records,encoded,buf_len_internal);

    // // f = fopen("nizk.cbor", "wb");
    // // if (f == NULL)
    // //     printf("file not open");
    // // fwrite(encoded, buf_len_internal, 1, f);
    // // fclose(f);
    // // free_eventrecords(&records);
    // char * buffern;
    // size_t len;
    // loadFile("nizk1.cbor",&buffern, &len);
    // eventrecords_decode(NULL,false,&records,buffern,buf_len_internal);
    // for (size_t i = 0; i < 5; i++)
    // {
    //     nizksign_eventrecord(&records.record[i],NULL);
    //     //nizkverify_eventrecord(&records_selected.record[1],NULL);
    // }

    // uint8_t * encoded = eventrecords_encode(&records,&buf_len_internal);

    // FILE * f = fopen("nizk.cbor", "wb");
    // if (f == NULL)
    //     printf("file not open");
    // fwrite(encoded, buf_len_internal, 1, f);
    // fclose(f);
    // free_eventrecords(&records);
    // free(encoded);
    // free(buffern);
    // loadFile("pcr0.log",&buffern, &len);
    // eventrecords_decode(NULL,false,&records,buffern,len);
    //     for (size_t i = 0; i < records.count; i++)
    // {
    //     //nizksign_eventrecord(&records.record[i],NULL);
    //     nizkverify_eventrecord(&records.record[i],NULL);
    // }

    //recieve_attestresponse(&l,encoded,buf_len_internal);

    // 	//nizktest();
    // 	//nizktestristretto(path,name,digest);
    // 	//nizktestristrettoSSLbig(path,name,digest);

    // 	data dat [100000];
    // // 	for(int i=0; i<100000;i++){
    // // 	dat[i].path =path;
    // // 	dat[i].name =name;
    // // 	dat[i].variant1= NDhashVariant1(path,name,digest,NDdigest);

    // // 	/*VARIANT 2*/

    // // 	dat[i].variant2 = NDhashVariant2(path,name,digest,NDdigest);

    // // 	/*Variant 3*/

    // // 	dat[i].variant3 =NDhashVariant3(path,name,digest,NDdigest);

    // // 	/*------------------RISTRETTO------------*/

    // // 	dat[i].variantristretto1=NDhashRistrettoVariant1(path,name,digest,NDdigest);

    // // 	/*VARIANT 2*/

    // // 	dat[i].variantristretto2=NDhashRistrettoVariant2(path,name,digest,NDdigest);

    // // 	/*Variant 3*/

    // // 	dat[i].variantristretto3=NDhashRistrettoVariant3(path,name,digest,NDdigest);
    // // 	}

    // //   FILE *f = fopen("timemeasurement.csv", "w");
    // //   if (f == NULL) return -1;
    // //   for (int i=0; i<100000; i++) {
    // //     // you might want to check for out-of-disk-space here, too
    // //     fprintf(f, "%d,%lu,%lu,%lu,%lu,%lu,%lu\n", i+1,dat[i].variant1, dat[i].variant2,dat[i].variant3,dat[i].variantristretto1,dat[i].variantristretto2,dat[i].variantristretto3);

    // //   }
    // //   fclose(f);

    // 	printf("Template Hash:\n");
    // 	for (int i = 0; i < TPM2_SHA256_DIGEST_SIZE; i++) {
    //         printf("%02x", digest[i]);
    //     }

    // 	printf("\nFile Hash:\n%s", getFileHash());
    // 	freeBuffer();
    // 	printf("\nFile Path:\n%s", path);
    // 	loadFile("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/","programs");
    // 	printf("loaded: %s",getBuffer());
    // 	char * prg = strtok(getBuffer()," \n\t");
    // 	if (prg == 0)
    //     printf("strtok() failed\n");
    // 		else
    //     printf("Part 1 -> %s\n\n", prg);
    // 	int count = 0;
    // 	int index = 0;
    // 	programs prog [10];
    // 	while( prg != NULL ) {
    //       //printf( " %s\n", prg );
    // 	  if(count%2==0){
    // 		  prog[index].path=prg;
    // 	  }else{
    // 		  prog[index].name=prg;
    // 		  index++;
    // 	  }
    //       prg = strtok(NULL, " \n\t");
    // 	  count++;
    //    	}

    // 	for (int i=0;i<10;i++){
    // 		nizktestristretto(prog[i].path,prog[i].name,digest);
    // 	}

    // 	for (int i=0; i<10; i++) {
    //     // you might want to check for out-of-disk-space here, too
    //     dat[i].path =prog[i].path;
    // 	dat[i].name =prog[i].name;
    // 	dat[i].variant1= NDhashVariant1(prog[i].path,prog[i].name,digest,NDdigest,r_i);

    // 	/*VARIANT 2*/

    // 	dat[i].variant2 = NDhashVariant2(prog[i].path,prog[i].name,digest,NDdigest);

    // 	/*Variant 3*/

    // 	dat[i].variant3 =NDhashVariant3(prog[i].path,prog[i].name,digest,NDdigest);

    // 	/*------------------RISTRETTO------------*/

    // 	dat[i].variantristretto1=NDhashRistrettoVariant1(prog[i].path,prog[i].name,digest,NDdigest);

    // 	/*VARIANT 2*/

    // 	dat[i].variantristretto2=NDhashRistrettoVariant2(prog[i].path,prog[i].name,digest,NDdigest);

    // 	/*Variant 3*/

    // 	dat[i].variantristretto3=NDhashRistrettoVariant3(prog[i].path,prog[i].name,digest,NDdigest);

    //   	}
    // 	FILE *f = fopen("timemeasurement10.csv", "w");
    //   	if (f == NULL) return -1;
    //   	for (int i=0; i<10; i++) {
    //     	// you might want to check for out-of-disk-space here, too
    //     	fprintf(f, "%s/%s,%lu,%lu,%lu,%lu,%lu,%lu\n", dat[i].path,dat[i].name,dat[i].variant1, dat[i].variant2,dat[i].variant3,dat[i].variantristretto1,dat[i].variantristretto2,dat[i].variantristretto3);

    //   	}
    //  	fclose(f);

    // 	printf("\n%d",count);

    return (0);
}
