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
#include <mbedtls/sha512.h>
#include "core/hash/hash_sig_verify.h"
#include "core/hash/templatehash.h"
#include "core/communication/attestphase.h"

#include "core/communication/events.h"
#include "util/cbor_help.h"
#include "core/dto/ppra_dto_message_encdec.h"
#include "core/tpm2_charra/charra_util.h"



int main()
{
    unsigned char nonce[crypto_box_NONCEBYTES];

    generateNonce(nonce);



    //Generator

    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    fp = fopen("/run/media/dominik/DATA/Master/Master_Dev/ppra-protocol/output/programslocalmixed", "r");
    if (fp == NULL)
        exit(EXIT_FAILURE);
    events newevents;
    newevents.count = 152;
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
        newevents.e[indi].file_hash = calloc(64, sizeof(uint8_t));
        memcpy(newevents.e[indi].file_hash, output3, TPM2_SHA512_DIGEST_SIZE);
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

    

    FILE *f = fopen("programsmixed.cbor", "wb");
    if (f == NULL)
         return "file nof found! Prover side issue!";
    fwrite(encoded, buf_len_internal, 1, f);

    fclose(f);

    ////// END of GENERATOR


    return (0);
}
