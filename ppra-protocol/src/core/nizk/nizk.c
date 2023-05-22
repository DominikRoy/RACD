
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <mbedtls/bignum.h>

#include "core/nizk/nizk.h"
#include "util/buftohex.h"
#include "util/nonce.h"

int nizksign_eventrecord(eventrecord *rec)
{
    if (sodium_init() == -1)
    {
        printf("init is minus one");
        return 1;
    }

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    uint8_t *random = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *reduced_digest = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *r_h = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *event_hash = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *v = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *g_i = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *t_i = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *reduced_c = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *r_c = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *s = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));

    /*Templatehash*/
    templatehashevent(&rec->event.e[0], digest);
    /*random scalar r generating*/
    crypto_core_ristretto255_scalar_random(random);

    unsigned char c1[crypto_generichash_BYTES_MAX];
    //memcpy(c1,digest,TPM2_SHA256_DIGEST_SIZE);
    //memcpy(&c1[TPM2_SHA256_DIGEST_SIZE],digest,TPM2_SHA256_DIGEST_SIZE);


    crypto_hash_sha512_state sha512state;

    crypto_hash_sha512_init(&sha512state);
    crypto_hash_sha512_update(&sha512state, digest, TPM2_SHA256_DIGEST_SIZE);
    crypto_hash_sha512_final(&sha512state, c1);

    crypto_core_ristretto255_scalar_reduce(reduced_digest, c1);

    /*r * h_t(x)*/
    crypto_core_ristretto255_scalar_mul(r_h, random, reduced_digest);

    if (crypto_scalarmult_ristretto255_base(event_hash, r_h) != 0)
    {
        printf("base mult for nd not okay");
    }

    if (crypto_core_ristretto255_is_valid_point(event_hash) != 1)
    {
        printf("ND is not valid");
    }


    rec->event_hash = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    memcpy(rec->event_hash, event_hash, crypto_core_ristretto255_BYTES);


    /*END OF ND-HASH*/

    /*Generator */
    crypto_scalarmult_ristretto255_base(g_i, reduced_digest);
    if (crypto_core_ristretto255_is_valid_point(g_i) != 1)
    {
        printf("gi is not valid");
    }


    /*t_i*/
    crypto_core_ristretto255_scalar_random(v);
    if(crypto_scalarmult_ristretto255(t_i, v, g_i) == -1) printf("not valid t_i");
    if (crypto_core_ristretto255_is_valid_point(t_i) != 1)
    {
        printf("t_i is  not valid");
    }


    /*c_i*/
    uint8_t c[crypto_generichash_BYTES_MAX];
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, 0, sizeof c);

    crypto_generichash_update(&state, g_i, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, t_i, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, event_hash, crypto_core_ristretto255_BYTES);


    crypto_generichash_final(&state, c, sizeof c);
    rec->c = calloc(crypto_generichash_BYTES_MAX, sizeof(uint8_t));
    memcpy(rec->c, c, crypto_generichash_BYTES_MAX);

    /*s = v -r*c */
    crypto_core_ristretto255_scalar_reduce(reduced_c, c);
    crypto_core_ristretto255_scalar_mul(r_c, random, reduced_c); // (a*c)mod group order

    crypto_core_ristretto255_scalar_sub(s, v, r_c); // (v-z)mod group order


    rec->s = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    memcpy(rec->s, s, crypto_core_ristretto255_SCALARBYTES);

    free(random);
    free(reduced_digest);
    free(r_h);
    free(event_hash);
    free(v);
    free(g_i);
    free(t_i);
    free(reduced_c);
    free(r_c);
    free(s);

    return 0;
}

bool nizkverify_eventrecord(eventrecord *rec)
{


    if (sodium_init() == -1)
    {
        printf("init is minus one");
        return 1;
    }
    bool verify = false;

    uint8_t digest[TPM2_SHA256_DIGEST_SIZE];
    uint8_t *reduced_digest = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));
    uint8_t *g_i = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *g_i_s = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *event_hash_c = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *t_i_prime = calloc(crypto_core_ristretto255_BYTES, sizeof(uint8_t));
    uint8_t *reduced_c = calloc(crypto_core_ristretto255_SCALARBYTES, sizeof(uint8_t));

    /*Templatehash*/
    templatehashevent(&rec->event.e[0], digest);


    unsigned char c1[crypto_generichash_BYTES_MAX];

    //memcpy(c1,digest,TPM2_SHA256_DIGEST_SIZE);
    //memcpy(&c1[TPM2_SHA256_DIGEST_SIZE],digest,TPM2_SHA256_DIGEST_SIZE);

    crypto_hash_sha512_state sha512state;
    crypto_hash_sha512_init(&sha512state);
    crypto_hash_sha512_update(&sha512state, digest, TPM2_SHA256_DIGEST_SIZE);
    crypto_hash_sha512_final(&sha512state, c1);

    crypto_core_ristretto255_scalar_reduce(reduced_digest, c1);


    /*Generator */
    crypto_scalarmult_ristretto255_base(g_i, reduced_digest);
    if (crypto_core_ristretto255_is_valid_point(g_i) != 1)
    {
        printf("gi is not valid");
    }


    if(crypto_scalarmult_ristretto255(g_i_s, rec->s, g_i) == -1) printf("not valid g_i_s!");
    if (crypto_core_ristretto255_is_valid_point(g_i_s) != 1)
    {
        printf("gis is not valid");
    }

    crypto_core_ristretto255_scalar_reduce(reduced_c, rec->c);
    if(crypto_scalarmult_ristretto255(event_hash_c, reduced_c, rec->event_hash) == -1) printf("not valid event_hash_c");
    if (crypto_core_ristretto255_is_valid_point(event_hash_c) != 1)
    {
        printf("ndc is not valid");
    }

    if (crypto_core_ristretto255_add(t_i_prime, g_i_s, event_hash_c) != 0)
    {
        printf("Point addition was not an success!!\n");
    }



    unsigned char c_prime[crypto_generichash_BYTES_MAX];
    crypto_generichash_state state;

    crypto_generichash_init(&state, NULL, 0, sizeof c_prime);
    crypto_generichash_update(&state, g_i, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, t_i_prime, crypto_core_ristretto255_BYTES);
    crypto_generichash_update(&state, rec->event_hash, crypto_core_ristretto255_BYTES);
    crypto_generichash_final(&state, c_prime, sizeof c_prime);


    if (memcmp(rec->c, c_prime, crypto_generichash_BYTES_MAX) == 0)
    {
       
        verify = true;
       
    }

    free(reduced_digest);
    free(event_hash_c);
    free(g_i_s);
    free(g_i);
    free(t_i_prime);
    free(reduced_c);

    return verify;
}
