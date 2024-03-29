#include <mbedtls/sha256.h>
#include <string.h>
#include "core/hash/hash_sig_verify.h"

/**
 * @file hash_sig_verify.c
 * @brief  This file implements the function of the header @file hash_sig_verify.h and using the hash functions of the mbedtls library
 * @author Dominik Roy George dominik.roy.george@sit.fraunhaufer.de
 */

CHARRA_RC hash_sha256( const size_t data_len, unsigned char* data,
    unsigned char digest[TPM2_SHA256_DIGEST_SIZE]) {
    CHARRA_RC r = CHARRA_RC_SUCCESS;

    /* init */
    mbedtls_sha256_context ctx = {0};
    mbedtls_sha256_init(&ctx);

    /* hash */
    if ((mbedtls_sha256_starts_ret(&ctx, 0)) != 0) {
        r = CHARRA_RC_ERROR;
        goto error;
    }

    if ((mbedtls_sha256_update_ret(&ctx, data, data_len)) != 0) {
        r = CHARRA_RC_ERROR;
        goto error;
    }
    /*End of hashing*/
    if ((mbedtls_sha256_finish_ret(&ctx, digest)) != 0) {
        r = CHARRA_RC_ERROR;
        goto error;
    }
	/* free */
    mbedtls_sha256_free(&ctx);

error:
    /* free */
    mbedtls_sha256_free(&ctx);

    return r;
}

CHARRA_RC charra_crypto_hash(mbedtls_md_type_t hash_algo,
	const uint8_t* const data, const size_t data_len,
	uint8_t digest[MBEDTLS_MD_MAX_SIZE]) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;

	/* init */
	const mbedtls_md_info_t* hash_info = mbedtls_md_info_from_type(hash_algo);
	mbedtls_md_context_t ctx = {0};
	if ((mbedtls_md_init_ctx(&ctx, hash_info)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	/* hash */
	if ((mbedtls_md_starts(&ctx)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_md_update(&ctx, data, data_len)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

	if ((mbedtls_md_finish(&ctx, digest)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	/* free */
	mbedtls_md_free(&ctx);

	return r;
}

CHARRA_RC charra_crypto_tpm_pub_key_to_mbedtls_pub_key(
	const TPM2B_PUBLIC* tpm_rsa_pub_key,
	mbedtls_rsa_context* mbedtls_rsa_pub_key) {
	CHARRA_RC r = CHARRA_RC_SUCCESS;
	int mbedtls_r = 0;

	/* construct a RSA public key from modulus and exponent */
	mbedtls_mpi n = {0}; /* modulus */
	mbedtls_mpi e = {0}; /* exponent */

	/* init mbedTLS structures */
	mbedtls_rsa_init(mbedtls_rsa_pub_key, MBEDTLS_RSA_PKCS_V15, 0);
	mbedtls_mpi_init(&n);
	mbedtls_mpi_init(&e);

	if ((mbedtls_r = mbedtls_mpi_read_binary(&n,
			 (const unsigned char*)
				 tpm_rsa_pub_key->publicArea.unique.rsa.buffer,
			 (size_t)tpm_rsa_pub_key->publicArea.unique.rsa.size)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_mpi_read_binary\n");
		goto error;
	}

	/* set exponent from TPM public key (if 0 set it to 65537) */
	{
		uint32_t exp = 65537; /* set default exponent */
		if (tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent != 0) {
			exp = tpm_rsa_pub_key->publicArea.parameters.rsaDetail.exponent;
		}

		if ((mbedtls_r = mbedtls_mpi_lset(&e, (mbedtls_mpi_sint)exp)) != 0) {
			r = CHARRA_RC_CRYPTO_ERROR;
			printf("Error mbedtls_mpi_lset\n");
			goto error;
		}
	}

	if ((mbedtls_r = mbedtls_rsa_import(
			 mbedtls_rsa_pub_key, &n, NULL, NULL, NULL, &e)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_import\n");
		goto error;
	}

	if ((mbedtls_r = mbedtls_rsa_complete(mbedtls_rsa_pub_key)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_complete\n");
		goto error;
	}

	if ((mbedtls_r = mbedtls_rsa_check_pubkey(mbedtls_rsa_pub_key)) != 0) {
		r = CHARRA_RC_CRYPTO_ERROR;
		printf("Error mbedtls_rsa_check_pubkey\n");
		goto error;
	}

	/* cleanup */
	mbedtls_mpi_free(&n);
	mbedtls_mpi_free(&e);

	return CHARRA_RC_SUCCESS;

error:
	/* cleanup */
	mbedtls_rsa_free(mbedtls_rsa_pub_key);
	mbedtls_mpi_free(&n);
	mbedtls_mpi_free(&e);

	return r;
}

CHARRA_RC charra_crypto_rsa_verify_signature_hashed(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data_digest, const unsigned char* signature) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;
	int mbedtls_r = 0;

	/* verify signature */
	if ((mbedtls_r = mbedtls_rsa_rsassa_pss_verify(mbedtls_rsa_pub_key, NULL,
			 NULL, MBEDTLS_RSA_PUBLIC, hash_algo, 0, data_digest, signature)) !=
		0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	return charra_r;
}

CHARRA_RC charra_crypto_rsa_verify_signature(
	mbedtls_rsa_context* mbedtls_rsa_pub_key, mbedtls_md_type_t hash_algo,
	const unsigned char* data, size_t data_len,
	const unsigned char* signature) {
	CHARRA_RC charra_r = CHARRA_RC_SUCCESS;

	/* hash data */
	uint8_t data_digest[MBEDTLS_MD_MAX_SIZE] = {0};
	if ((charra_r = charra_crypto_hash(
			 hash_algo, data, data_len, data_digest)) != CHARRA_RC_SUCCESS) {
		goto error;
	}

	/* verify signature */
	if ((charra_r = charra_crypto_rsa_verify_signature_hashed(
			 mbedtls_rsa_pub_key, hash_algo, data_digest, signature)) != 0) {
		charra_r = CHARRA_RC_CRYPTO_ERROR;
		goto error;
	}

error:
	return charra_r;
}