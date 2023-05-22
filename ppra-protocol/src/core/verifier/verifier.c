/*
 *  SSL client demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_time time
#define mbedtls_time_t time_t
#define mbedtls_fprintf fprintf
#define mbedtls_printf printf
#define mbedtls_exit exit
#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_ENTROPY_C) ||  \
    !defined(MBEDTLS_SSL_TLS_C) || !defined(MBEDTLS_SSL_CLI_C) || \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_RSA_C) ||         \
    !defined(MBEDTLS_CERTS_C) || !defined(MBEDTLS_PEM_PARSE_C) || \
    !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_ENTROPY_C and/or "
                   "MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_CLI_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
                   "not defined.\n");
    mbedtls_exit(0);
}
#else

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/sha256.h"
#include "core/hash/hash_sig_verify.h"
#include "util/nonce.h"
//#include "core/hash/templatehash.h"

#include "core/communication/events.h"
#include "core/communication/attestphase.h"
#include "core/dto/ppra_dto.h"
#include "core/dto/ppra_dto_message_encdec.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <tss2/tss2_tpm2_types.h>

#define SERVER_PORT "4433"
#define SERVER_NAME "localhost"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"
#define BUF_SIZE 50096

#define DEBUG_LEVEL 1

#define TPM_SIG_KEY_ID_LEN 14
#define TPM_SIG_KEY_ID "PK.RSA.default"
static const uint8_t TPM_PCR_SELECTION[TPM2_MAX_PCRS] = {
    10};
static const uint32_t TPM_PCR_SELECTION_LEN = 1;

static void my_debug(void *ctx, int level,
                     const char *file, int line,
                     const char *str)
{
    ((void)level);

    mbedtls_fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
    fflush((FILE *)ctx);
}

int main(int argc, char *argv[])
{
    int ret = 1, len;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_net_context server_fd;
    uint32_t flags;
    uint8_t buf[BUF_SIZE];
    const char *pers = "ssl_client1";
    //char *ca_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/my_ca_localhost.crt";
    //char *crt_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/verifier_localhost.crt";
    //char *key_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/verifier_key.key";
    int key_cert_init = 0;
    char *server_name;
    char *server_port;
    char *ca_file;
    char *crt_file;
    char *key_file;
    char *swSelection_file;

    char *p, *q;
    for (int j = 1; j < argc; j++)
    {
        p = argv[j];
        if ((q = strchr(p, '=')) == NULL)
        {
            mbedtls_printf("value us NULL");
        }
        *q++ = '\0';

        if (strcmp(p, "server_name") == 0)
        {
            server_name = q;
        }
        else if (strcmp(p, "server_port") == 0)
        {
            server_port = q;
        }
        else if (strcmp(p, "ca_file") == 0)
        {
            ca_file = q;
        }
        else if (strcmp(p, "crt_file") == 0)
        {
            crt_file = q;
        }
        else if (strcmp(p, "key_file") == 0)
        {
            key_file = q;
        }
        else if (strcmp(p, "swSelection_file") == 0)
        {
            swSelection_file = q;
        }
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cert;
    mbedtls_pk_context pkey;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&pkey);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    mbedtls_printf("\n  . Seeding the random number generator...");
    fflush(stdout);

    mbedtls_entropy_init(&entropy);
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 0. Initialize certificates
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);
    if ((ret = mbedtls_x509_crt_parse_file(&cacert, ca_file)) < 0)
    {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    mbedtls_printf(" ok (%d skipped)\n", ret);

    /*
     * 1.2. Load own certificate and private key
     *
     * (can be skipped if client authentication is not required)
     */
    mbedtls_printf("  . Loading the client cert. and key...");
    fflush(stdout);

    key_cert_init++;
    if ((ret = mbedtls_x509_crt_parse_file(&cert, crt_file)) != 0)
    {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n",
                       (unsigned int)-ret);
        goto exit;
    }

    key_cert_init++;
    if ((ret = mbedtls_pk_parse_keyfile(&pkey, key_file,
                                        NULL)) != 0)
    {
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    if (key_cert_init == 1)
    {
        mbedtls_printf(" failed\n  !  crt_file without key_file or vice-versa\n\n");
        goto exit;
    }

    /*
     * 1. Start the connection
     */
    mbedtls_printf("  . Connecting to tcp/%s/%s...", server_name, server_port);
    fflush(stdout);

    if ((ret = mbedtls_net_connect(&server_fd, server_name,
                                   server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup stuff
     */
    mbedtls_printf("  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &cert, &pkey)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
                       ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, server_name)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    /*
     * 4. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int)-ret);
            goto exit;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the server certificate
     */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
        char vrfy_buf[512];

        mbedtls_printf(" failed\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
    }
    else
        mbedtls_printf(" ok\n");

    /*
     * 3. Send register command
     */
    mbedtls_printf("  > Write to server:");
    fflush(stdout);

    /**
     * 
     * ATTEST REQUEST WITH TEST DATA
     * 
     * 
     * **/
    char *buffer;
    size_t f_size;
    loadFile(swSelection_file, &buffer, &f_size);
    uint8_t nonce[crypto_box_NONCEBYTES];
    generateNonce(nonce);
    msg_attestation_request_dto req = {
        .sig_key_id_len = TPM_SIG_KEY_ID_LEN,
        .sig_key_id = {0}, // must be memcpy'd, see below
        .nonce_len = crypto_box_NONCEBYTES,
        .nonce = {0}, // must be memcpy'd, see below
        .pcr_selections_len = 1,
        .pcr_selections = {{
            .tcg_hash_alg_id = TPM2_ALG_SHA256,
            .pcrs_len = 1,
            .pcrs = {0} // must be memcpy'd, see below
        }},
        .swSelection_len = f_size};
    memcpy(req.sig_key_id, TPM_SIG_KEY_ID, TPM_SIG_KEY_ID_LEN);
    memcpy(req.nonce, nonce, crypto_box_NONCEBYTES);
    memcpy(req.pcr_selections->pcrs, TPM_PCR_SELECTION, TPM_PCR_SELECTION_LEN);
    req.swSelection = malloc(f_size);
    memcpy(req.swSelection, buffer, f_size);

    free(buffer);

    uint32_t buf_len;

    uint8_t *attestrequest = create_attestrequest(&req, &buf_len);
    len = buf_len;
    ret = mbedtls_ssl_write(&ssl, attestrequest, len);
    free(attestrequest);
    free_msg_attestation_request(&req);

    /**
     * END OF ATTEST REQUEST
     * 
     */

    while ((ret) <= 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n", len);

    /*
     * 7. Read the response
     */
    mbedtls_printf("  < Read from server:");
    fflush(stdout);
    int counter = 0;
    uint8_t response_buf[BUF_SIZE];
    int data_position = 0;
    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
        {
            verify_attestresponse(nonce,swSelection_file,response_buf, data_position);
            break;
        }

        if (ret < 0)
        {
            mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
            break;
        }

        if (ret == 0)
        {
            mbedtls_printf("\n\nEOF\n\n");
            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n", len);

      
        
        if (counter == 0)
        {
            memcpy(response_buf,buf, ret);
            data_position = ret;

        }else{
            memcpy(&response_buf[data_position],buf,ret);
            data_position += ret;
        }
        counter++;

    } while (1);

    mbedtls_ssl_close_notify(&ssl);

    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:

#ifdef MBEDTLS_ERROR_C
    if (exit_code != MBEDTLS_EXIT_SUCCESS)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&server_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&pkey);

    mbedtls_x509_crt_free(&cacert);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
    mbedtls_printf("  + Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    mbedtls_exit(exit_code);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_ENTROPY_C && MBEDTLS_SSL_TLS_C &&   \
          MBEDTLS_SSL_CLI_C && MBEDTLS_NET_C && MBEDTLS_RSA_C &&          \
          MBEDTLS_CERTS_C && MBEDTLS_PEM_PARSE_C && MBEDTLS_CTR_DRBG_C && \
          MBEDTLS_X509_CRT_PARSE_C */
