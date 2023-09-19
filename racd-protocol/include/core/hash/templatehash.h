
#ifndef PPRA_TEMPLATEHASH_H
#define PPRA_TEMPLATEHASH_H

#include "core/hash/hash_sig_verify.h"
#include "core/dto/ppra_dto.h"

/**
 * @file templatehash.h
 * @brief 
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @date
 */


/**
 * @brief The function creates a template hash from the give sha26 digest of  a file and concnates it with the path and returns 
 * of the concatination the sha256 hash.
 * 
 * @param filepath 
 * @param filename 
 * @param digest 
 * @return int 
 */
int templatehash(char* filepath, unsigned char digest [TPM2_SHA256_DIGEST_SIZE]);

int templatehashevent(event * ev, unsigned char digest[TPM2_SHA256_DIGEST_SIZE]);
/**
 * @brief Get the File Hash object
 * 
 * @return char* 
 */
char* getFileHash(void);

#endif /* PPRA_TEMPLATEHASH_H */