/*
 *  SSL server demonstration program
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
#endif

#if !defined(MBEDTLS_BIGNUM_C) || !defined(MBEDTLS_CERTS_C) ||       \
    !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_SSL_TLS_C) ||    \
    !defined(MBEDTLS_SSL_SRV_C) || !defined(MBEDTLS_NET_C) ||        \
    !defined(MBEDTLS_RSA_C) || !defined(MBEDTLS_CTR_DRBG_C) ||       \
    !defined(MBEDTLS_X509_CRT_PARSE_C) || !defined(MBEDTLS_FS_IO) || \
    !defined(MBEDTLS_PEM_PARSE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_BIGNUM_C and/or MBEDTLS_CERTS_C and/or MBEDTLS_ENTROPY_C "
                   "and/or MBEDTLS_SSL_TLS_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_RSA_C and/or "
                   "MBEDTLS_CTR_DRBG_C and/or MBEDTLS_X509_CRT_PARSE_C "
                   "and/or MBEDTLS_PEM_PARSE_C not defined.\n");
    mbedtls_exit(0);
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#endif

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "core/communication/events.h"
#include "core/communication/attestphase.h"
#include "evaluation/duration.h"
#include <stdbool.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define HTTP_RESPONSE                                    \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

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
    int ret, len;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[20096];
    const char *pers = "ssl_server";
    //char *ca_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/my_ca_localhost.crt";
    //char *crt_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/prover_localhost.crt";
    //char *key_file="/run/media/dominik/DATA/Master/Master_Dev/mbedtls-2.25.0/programs/x509/prover_key.key";
    int key_cert_init = 0;
    uint32_t flags;
    char * server_name;
    char * server_port;
    char * ca_file;
    char * crt_file;
    char * key_file;
    char * programs_file; //saving registerd info
    char * p,*q;
    TPM2B_PUBLIC *public_key = NULL;
    uint8_t * response = NULL;
    uint32_t attest_len;
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
        else if (strcmp(p, "programs_file") == 0)
        {
            programs_file = q;
        }
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif

    mbedtls_x509_crt_init(&cacert);
    mbedtls_x509_crt_init(&srvcert);
    mbedtls_pk_init(&pkey);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    /*
     * 1.1. Load the trusted CA
     */
    mbedtls_printf("  . Loading the CA root certificate ...");
    fflush(stdout);

    if ((ret = mbedtls_x509_crt_parse_file(&cacert, ca_file)) < 0)
    {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", (unsigned int)-ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 1. Load the certificates and private RSA key
     */
    mbedtls_printf("\n  . Loading the server cert. and key...");
    fflush(stdout);

    key_cert_init++;
    if ((ret = mbedtls_x509_crt_parse_file(&srvcert, crt_file)) != 0)
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

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup the listening TCP socket
     */
    mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, server_name, server_port, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 3. Seed the RNG
     */
    mbedtls_printf("  . Seeding the random number generator...");
    fflush(stdout);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers,
                                     strlen(pers))) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 4. Setup stuff
     */
    mbedtls_printf("  . Setting up the SSL data....");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf( " ok\n" );
       /*
    * PCR EXTEND 
    */
    mbedtls_printf( "  . PCR extending ..." );
    fflush( stdout );
    simulate_measured_boot(programs_file);
    mbedtls_printf( " ok\n" );

    /**
     * Creating primary key and storing it
     * 
     */
    mbedtls_printf( "  . Creating Primary Key and storing it..." );
    fflush( stdout );
    create_store_pk(&public_key);
    mbedtls_printf( " ok\n" );

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif

    mbedtls_net_free(&client_fd);

    mbedtls_ssl_session_reset(&ssl);


    


    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("  . Waiting for a remote connection ...");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0)
    {
        mbedtls_printf(" failed\n  ! mbedtls_net_accept returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    mbedtls_printf(" ok\n");

    /*
     * 5. Handshake
     */
    mbedtls_printf("  . Performing the SSL/TLS handshake...");
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    /*
     * 5. Verify the client certificate
     */
    mbedtls_printf("  . Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
        char vrfy_buf[512];

        mbedtls_printf(" failed\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);

        mbedtls_printf("%s\n", vrfy_buf);
    }
    else
        mbedtls_printf(" ok\n");

    const mbedtls_x509_crt *temp = mbedtls_ssl_get_peer_cert(&ssl);
    if (mbedtls_ssl_get_peer_cert(&ssl) != NULL)
    {
        char crt_buf[512];

        mbedtls_printf("  . Peer certificate information    ...\n");
        mbedtls_x509_crt_info(crt_buf, sizeof(crt_buf), "      ",
                              temp);
        mbedtls_printf("%s\n", crt_buf);
        //mbedtls_printf("serial: %s\n",temp->serial.p);
    }
    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf("  < Read from client:");
    fflush(stdout);

    do
    {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
            continue;

        if (ret <= 0)
        {
            switch (ret)
            {
            case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                mbedtls_printf(" connection was closed gracefully\n");
                break;

            case MBEDTLS_ERR_NET_CONN_RESET:
                mbedtls_printf(" connection was reset by peer\n");
                break;

            default:
                mbedtls_printf(" mbedtls_ssl_read returned -0x%x\n", (unsigned int)-ret);
                break;
            }

            break;
        }

        len = ret;
        mbedtls_printf(" %d bytes read\n\n", len);
        //uint64_t exec;
        //ELAPSED_DURING(&exec,ms,{
        struct timespec begin, end;
        clock_gettime(CLOCK_REALTIME, &begin);
        response = send_attestresponse(temp->subject,public_key, buf, len, &attest_len);
        clock_gettime(CLOCK_REALTIME, &end);
        long seconds = end.tv_sec - begin.tv_sec;
        long nanoseconds = end.tv_nsec - begin.tv_nsec;
    //uint64_t elapsed = (uint64_t)seconds * 1000 + (uint64_t)nanoseconds / 1e6;
    //double elapsed = seconds + nanoseconds*1e-9;
        double elap = seconds * 1000 + nanoseconds / 1e6;
        //});
	
        FILE *f = fopen("ppra_attester_50_local_new.csv", "a");
        fprintf(f, "%.20f\n", elap);
        fclose(f);

        //mbedtls_printf("\n Attestationrespond created!\n");

        if (ret > 0)
            break;
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf("  > Write to client:");
    fflush(stdout);
    //printf("attest len :%d\n",attest_len);
    ret = mbedtls_ssl_write(&ssl, response, attest_len);
    //printf("attest len :%d\n",ret);
    int temp_attest_rest_len = ret;
    while ((uint32_t)temp_attest_rest_len < attest_len)
    {
        //printf("attest len :%d\n",attest_len-temp_attest_rest_len);
        ret = mbedtls_ssl_write(&ssl, &response[temp_attest_rest_len], attest_len - temp_attest_rest_len);
        temp_attest_rest_len += ret;
    }

    while ((ret) <= 0)
    {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET)
        {
            mbedtls_printf(" failed\n  ! peer closed the connection\n\n");
            goto reset;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
            goto exit;
        }
    }

    len = ret;
    mbedtls_printf(" %d bytes written\n\n%s\n", len, (char *)buf);

    mbedtls_printf("  . Closing the connection...");

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            mbedtls_printf(" failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret);
            goto reset;
        }
    }

    mbedtls_printf(" ok\n");

    ret = 0;
    goto reset;

exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0)
    {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
    }
#endif
    free(public_key);
    free(response);
    mbedtls_net_free(&client_fd);
    mbedtls_net_free(&listen_fd);
    mbedtls_x509_crt_free(&cacert);
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

#if defined(_WIN32)
    mbedtls_printf("  Press Enter to exit this program.\n");
    fflush(stdout);
    getchar();
#endif

    mbedtls_exit(ret);
}
#endif /* MBEDTLS_BIGNUM_C && MBEDTLS_CERTS_C && MBEDTLS_ENTROPY_C &&     \
          MBEDTLS_SSL_TLS_C && MBEDTLS_SSL_SRV_C && MBEDTLS_NET_C &&      \
          MBEDTLS_RSA_C && MBEDTLS_CTR_DRBG_C && MBEDTLS_X509_CRT_PARSE_C \
          && MBEDTLS_FS_IO && MBEDTLS_PEM_PARSE_C */
