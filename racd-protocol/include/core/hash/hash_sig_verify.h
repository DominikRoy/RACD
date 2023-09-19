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



CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
	const uint8_t* const data, const size_t data_len,
	uint8_t digest[MBEDTLS_MD_MAX_SIZE]);

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
	const TPM2B_PUBLIC* tpm_rsa_pub_key,
	mbedtls_rsa_context* mbedtls_rsa_pub_key);

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data_digest, const unsigned char* signature);

CHARRA_RC charra_crypto_rsa_verify_signature(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data, size_t data_len, const unsigned char* signature);

#endif /* PPRA_HASH_SIG_VERIFY_H */