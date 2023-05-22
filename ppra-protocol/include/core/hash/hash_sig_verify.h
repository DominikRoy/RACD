#include <stdio.h>
#ifndef CHARRA_ERROR_H
#define CHARRA_ERROR_H

#include <inttypes.h>

/**
 * @file hash_sig_verify.h
 * @brief  original author Michael Eckel michael.eckel@sit.fraunhofer.de
 * @author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @date
 */
typedef uint32_t CHARRA_RC;
#define CHARRA_RC_SUCCESS ((CHARRA_RC)0x00000000)
#define CHARRA_RC_ERROR ((CHARRA_RC)0xffffffff)
#define CHARRA_RC_CRYPTO_ERROR ((CHARRA_RC)0x0001ffff)
#define CHARRA_RC_BAD_ARGUMENT ((CHARRA_RC)0x0000ffff)
#define CHARRA_RC_MARSHALING_ERROR ((CHARRA_RC)0x0000fffe)
#define TPM2_SHA256_DIGEST_SIZE 32
#endif /* CHARRA_ERROR_H */

#ifndef PPRA_HASH_SIG_VERIFY_H
#define PPRA_HASH_SIG_VERIFY_H

#include <tss2/tss2_tpm2_types.h>
#include <mbedtls/rsa.h>

/**
 * @brief The function returns, for a given char buffer or data and with it lengths, its sha256
 * @author  original author Michael Eckel michael.eckel@sit.fraunhofer.de; using author Dominik Roy George dominik.roy.george@sit.fraunhofer.de
 * @param data_len length of the data
 * @param data data itself
 * @param digest fills the buffer with sha256 digest
 * @return CHARRA_RC 
 */
CHARRA_RC hash_sha256(const size_t data_len, unsigned char* data,
    unsigned char digest[TPM2_SHA256_DIGEST_SIZE]);


/**
 * @brief The function generate the hash digest for the given hash algorithm and input data and length
 * 
 * @param hash_algo [in] hashing algorithm
 * @param data [in] Data to be hashed
 * @param data_len [in] Data length of the data buffer
 * @param digest [out] digest output
 * @return CHARRA_RC 
 */
CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
	const uint8_t* const data, const size_t data_len,
	uint8_t digest[MBEDTLS_MD_MAX_SIZE]);

/**
 * @brief Converts the tpm public key to the mbedtls public key.
 * 
 * @param tpm_rsa_pub_key [in] tpm public key
 * @param mbedtls_rsa_pub_key [out] mbedtls based public key
 * @return CHARRA_RC 
 */
CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
	const TPM2B_PUBLIC* tpm_rsa_pub_key,
	mbedtls_rsa_context* mbedtls_rsa_pub_key);

/**
 * @brief verify the the signature based on the mbedtls public key. Returns success code  if validation was a success.
 * 
 * @param mbedtls_rsa_pub_key [in] public key
 * @param hash_algo [in] hash algorithm
 * @param data_digest [in] data digest
 * @param signature [in] signature
 * @return CHARRA_RC 
 */
CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data_digest, const unsigned char* signature);

/**
 * @brief verify the the signature based on the mbedtls public key. Returns success code  if validation was a success.
 * 
 * @param mbedtls_rsa_pub_key [in] public key
 * @param hash_algo [in] hash algorithm
 * @param data_digest [in] data digest
 * @param signature [in] signature
 * @return CHARRA_RC 
 */
CHARRA_RC charra_crypto_rsa_verify_signature(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data, size_t data_len, const unsigned char* signature);

#endif /* PPRA_HASH_SIG_VERIFY_H */