#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sodium.h>
#include <mbedtls/sha256.h>

#include "util/fileIO.h"
#include "core/hash/hash_sig_verify.h"
#include "core/hash/templatehash.h"
/**
 * @file templatehash.c
 * @brief  This file implements the function of the header @file templatehash.h. It creates the templatehash by concaniating the hashstring from the file with
 * the file path.
 * @author Dominik Roy George dominik.roy.george@sit.fraunhaufer.de
 * 
 * 
 * 
 * app-event-log-record = [
    pcr-no: uint .size 1,
    event_hash: bstr,
    event: bstr,
]

event = [
    file_hash: bstr,
    file_path: string,
]
CDDDL
 */


char filedigest[TPM2_SHA256_DIGEST_SIZE];

int templatehash(char* filepath, unsigned char digest[TPM2_SHA256_DIGEST_SIZE])
{
    char * buffer;
    size_t f_size;
    int result = loadFile(filepath,&buffer,&f_size);
    
    if (result!=1)
    {
        printf("could not load file or could not find file!");
    }
    
    CHARRA_RC ret= hash_sha256(f_size,(unsigned char *)buffer, digest);
    free(buffer);


 

    size_t filepathlength= strlen(filepath);
    memcpy(filedigest,digest,TPM2_SHA256_DIGEST_SIZE);

    unsigned char * templatehashconcat= malloc(TPM2_SHA256_DIGEST_SIZE + filepathlength );// +1  for slash and +1 for null terminator string
    
    /*Concatination of the hashstring */
    memcpy(templatehashconcat, digest,TPM2_SHA256_DIGEST_SIZE);
    memcpy(&templatehashconcat[TPM2_SHA256_DIGEST_SIZE],filepath,filepathlength);

    /*hashing the string (strlen does not include null terminator so the size 82 for the constant file)*/
    size_t datalen=TPM2_SHA256_DIGEST_SIZE + filepathlength;// + 1 + filenamelength;
    ret= hash_sha256(datalen,templatehashconcat, digest);
    free(templatehashconcat);

    return ret;
}


int templatehashevent(event * ev, unsigned char digest[TPM2_SHA256_DIGEST_SIZE])
{
   



    size_t filepathlength= ev->file_path_len;

    unsigned char * templatehashconcat= malloc(TPM2_SHA256_DIGEST_SIZE + filepathlength );// +1  for slash and +1 for null terminator string
    
    /*Concatination of the hashstring */
    memcpy(templatehashconcat, ev->file_hash,TPM2_SHA256_DIGEST_SIZE);
    memcpy(&templatehashconcat[TPM2_SHA256_DIGEST_SIZE],ev->file_path,filepathlength);

    /*hashing the string (strlen does not include null terminator so the size 82 for the constant file)*/
    size_t datalen=TPM2_SHA256_DIGEST_SIZE + filepathlength;// + 1 + filenamelength;
    int ret= hash_sha256(datalen,templatehashconcat, digest);
    free(templatehashconcat);






    return ret;
}

char * getFileHash(){
    return filedigest;
}