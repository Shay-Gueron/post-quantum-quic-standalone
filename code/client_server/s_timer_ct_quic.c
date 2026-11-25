/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000
#define DEFAULT_WARMUP_COUNT 100
#define MAX_CONSECUTIVE_FAILURES 20

static int warmup_count_from_env(void)
{
    const char* value = getenv("WARMUP_COUNT");
    if (value == NULL || *value == '\0')
        return DEFAULT_WARMUP_COUNT;

    char* end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == value || *end != '\0' || parsed < 0 || parsed > 1000000) {
        fprintf(stderr, "Ignoring invalid WARMUP_COUNT=%s, using %d\n",
                value, DEFAULT_WARMUP_COUNT);
        return DEFAULT_WARMUP_COUNT;
    }
    return (int)parsed;
}

const char* ca_file = "../certs/root.crt";
const char* CTLOG_FILE = "../certs/ct_log_list.cnf";
const char* host = "";
const char* port = "";
CTLOG_STORE *ctlog_store;

/* Signed Certificate Timestamp */
struct sct_st {
    sct_version_t version;
    /* If version is not SCT_VERSION_V1, this contains the encoded SCT */
    unsigned char *sct;
    size_t sct_len;
    /* If version is SCT_VERSION_V1, fields below contain components of the SCT */
    unsigned char *log_id;
    size_t log_id_len;
    /*
    * Note, we cannot distinguish between an unset timestamp, and one
    * that is set to 0.  However since CT didn't exist in 1970, no real
    * SCT should ever be set as such.
    */
    uint64_t timestamp;
    unsigned char *ext;
    size_t ext_len;
    unsigned char hash_alg;
    unsigned char sig_alg;
    unsigned char *sig;
    size_t sig_len;
    /* Log entry type */
    ct_log_entry_type_t entry_type;
    /* Where this SCT was found, e.g. certificate, OCSP response, etc. */
    sct_source_t source;
    /* The result of the last attempt to validate this SCT. */
    sct_validation_status_t validation_status;
};

CTLOG_STORE* create_ct_log_store(const char* ct_log_list_path) {
    /* Initialize empty CTLOG_STORE structure which will be used later during validation of SCTs and printing the SCTs to stdout. */
    CTLOG_STORE *ctlog_store = CTLOG_STORE_new();
    if (ctlog_store == NULL) {
        exit(EXIT_FAILURE);
    }

    /* Fill CTLOG_STORE structure with information about public log servers. */
    /* For this purpose, configuration 'ct_log_list.cnf' file from OpenSSL is used. */
    int ret_val = CTLOG_STORE_load_file(ctlog_store, ct_log_list_path);
    if (ret_val != 1) {
        fprintf(stderr, "Error loading CT log list from file: %s, error %d\n", ct_log_list_path, ret_val);
        exit(EXIT_FAILURE);
    } else {
        fprintf(stderr, "CT log list loaded from file: %s\n", ct_log_list_path);
    }

    return ctlog_store;
}

int my_ct_validation_callback(const CT_POLICY_EVAL_CTX *ctx,
                            const STACK_OF(SCT) *scts,
                            void *out_alert) {
    /* Perform validation of SCTs found in the peer's certificate, TLS extensions or OCSP response. */
    /* The validation is performed according to RFC 6962 and RFC 6962-bis. */
    /* The result of the validation is returned to the caller. */
    if (out_alert == NULL) {

    }
    if (ctx == NULL) {
        fprintf(stderr, "Error my_ct_validation_callback, empty context\n");
        return 0;
    }

    /* Pretty print every SCT from the SCT list to the stdout. */
    /* Log ID, Log name, Timestamp, Signature and Signature algorithm are printed in human-readable format. */
    int sct_list_stack_size = sk_SCT_num(scts);

    /* Deinitialize. */
    SCT *single_sct;
    sct_validation_status_t validation_status;

    /* Iterate through the whole SCT list and, in each iteration, validate one SCT from the list. */
    for (int index = 0; index < sct_list_stack_size; index++) {
        /* Retrieve one SCT from the SCT list at the given index. */
        single_sct = sk_SCT_value(scts, index);

        /* Validate the single SCT. */
        int ret_val = SCT_validate(single_sct, ctx);
        if (ret_val < 0) {
            /* Internal error occured, function has failed. */
            exit(EXIT_FAILURE);
        }
        if (ret_val == 1) {
            /* Validation of this SCT passed. */
            /* Validation status should be equal to SCT_VALIDATION_STATUS_VALID. */

            validation_status = SCT_get_validation_status(single_sct);
            if (validation_status != SCT_VALIDATION_STATUS_VALID) {
                fprintf(stderr, "SCT validation status inconsistent. %d\n", validation_status);
            }
        }
        if (ret_val == 0) {
            /* Validation of this SCT failed. */
            /* Retrieve and examine the validation status and the reason of the failure. */
            validation_status = SCT_get_validation_status(single_sct);
            if (validation_status == SCT_VALIDATION_STATUS_UNVERIFIED) {
                /* Failure to provide the certificate. */
                fprintf(stderr, "SCT_VALIDATION_STATUS_UNVERIFIED\n");
            }
            else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_LOG) {
                /* Public log that issued the SCT is not present in the CTLOG_STORE structure. */
                fprintf(stderr, "SCT_VALIDATION_STATUS_UNKNOWN_LOG\n");
            }
            else if (validation_status == SCT_VALIDATION_STATUS_UNKNOWN_VERSION) {
                /* Current SCT is of an unsupported version. */
                fprintf(stderr, "SCT_VALIDATION_STATUS_UNKNOWN_VERSION\n");
            }
            else if (validation_status == SCT_VALIDATION_STATUS_INVALID) {
                /* Current SCT's signature is incorrect, its timestamp is invalid or SCT is otherwise invalid. */
                fprintf(stderr, "SCT_VALIDATION_STATUS_INVALID\n");
            } else {
                /* This should never happen. */
                fprintf(stderr, "SCT validation status is invalid. %d\n", validation_status);
            }
            fprintf(stderr, "entry type: %d\n", single_sct->entry_type);
        }

        /* It is also possible to retrieve a human-readable string of validation status */
    }
    return 1;
}

static BIO *create_socket_bio(const char *hostname, const char *port,
                              int family, BIO_ADDR **peer_addr)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    /*
     * Lookup IP address info for the server.
     */
    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_DGRAM, 0,
                       &res))
        return NULL;

    /*
     * Loop through all the possible addresses for the server and find one
     * we can connect to.
     */
    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        /*
         * Create a UDP socket. We could equally use non-OpenSSL calls such
         * as "socket" here for this and the subsequent connect and close
         * functions. But for portability reasons and also so that we get
         * errors on the OpenSSL stack in the event of a failure we use
         * OpenSSL's versions of these functions.
         */
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        /* Connect the socket to the server's address */
        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        /* Set to nonblocking mode */
        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        break;
    }

    if (sock != -1) {
        *peer_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
        if (*peer_addr == NULL) {
            BIO_closesocket(sock);
            return NULL;
        }
    }

    /* Free the address information resources we allocated earlier */
    BIO_ADDRINFO_free(res);

    /* If sock is -1 then we've been unable to connect to the server */
    if (sock == -1)
        return NULL;

    /* Create a BIO to wrap the socket */
    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        BIO_closesocket(sock);
        return NULL;
    }

    /*
     * Associate the newly created BIO with the underlying socket. By
     * passing BIO_CLOSE here the socket will be automatically closed when
     * the BIO is freed. Alternatively you can use BIO_NOCLOSE, in which
     * case you must close the socket explicitly when it is no longer
     * needed.
     */
    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

SSL* do_tls_handshake(SSL_CTX* ssl_ctx, double* measurement)
{
    BIO* conn;
    BIO_ADDR *peer_addr = NULL;
    SSL* ssl;
    int ret;

    conn = create_socket_bio(host, port, AF_INET, &peer_addr);
    if (!conn)
    {
        free(conn);
        return 0;
    }

    BIO_set_conn_hostname(conn, host);
    BIO_set_conn_mode(conn, BIO_SOCK_NODELAY);

    ctlog_store = create_ct_log_store(CTLOG_FILE);
    SSL_CTX_enable_ct(ssl_ctx, SSL_CT_VALIDATION_STRICT);
    SSL_CTX_set0_ctlog_store(ssl_ctx, ctlog_store);
    SSL_CTX_set_ct_validation_callback(ssl_ctx, my_ct_validation_callback, NULL);

    ssl = SSL_new(ssl_ctx);

    SSL_set_bio(ssl, conn, conn);
    SSL_set1_initial_peer_addr(ssl, peer_addr);

    /* ok, lets connect */
    struct timespec start, finish;
    fprintf(stderr, "Starting handshake\n");
    clock_gettime(CLOCK_MONOTONIC_RAW, &start);
    ret = SSL_connect(ssl);
    clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
    fprintf(stderr, "Completed handshake %d\n", ret);
    if (measurement != NULL)
        *measurement = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
    if (ret <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return 0;
    }

    char buf[100];
    size_t readbytes;
    ret = SSL_read_ex(ssl, buf, 100, &readbytes);
    if (ret != 1) {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        return 0;
    }
    if (readbytes != 6) {
        fprintf(stderr, "Didn't read 6 bytes\n");
        SSL_free(ssl);
        return 0;
    }

#if defined(SOL_SOCKET) && defined(SO_LINGER)
    {
        struct linger no_linger = {.l_onoff = 1, .l_linger = 0};
        int fd = SSL_get_fd(ssl);
        if (fd >= 0)
        {
            (void)setsockopt(fd, SOL_SOCKET, SO_LINGER, (char*)&no_linger,
                             sizeof(no_linger));
        }
    }
#endif
    return ssl;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    SSL_CTX* ssl_ctx = 0;
    if(argc != 5 && argc != 7)
    {
        fprintf(stderr, "Wrong number of arguments. <kex alg> <count> <host> <port> [<CA path> <CT Log Path>]\n");
        fprintf(stderr, "\t- CA path defaults to \"../certs/root.crt\"\n");
        fprintf(stderr, "\t- CT Log path defaults to \"../certs/ct_log_list.cnf\"\n");
        fprintf(stderr, "Version %lx\n", OPENSSL_VERSION_NUMBER);
        goto end;
    }
    host = argv[3];
    port = argv[4];

    const char* kex_alg = argv[1];
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;
    double measurements_sum = 0;
    double measurements_sq_sum = 0;

    if (argc == 7) {
        ca_file = argv[5];
        CTLOG_FILE = argv[6];
    }

    const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const SSL_METHOD* ssl_meth = OSSL_QUIC_client_method(); //TLS_client_method();
    SSL* ssl = NULL;

    double* handshake_times_ms = malloc(measurements_to_make * sizeof(*handshake_times_ms));

    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        fprintf(stderr, "1.\n");
        goto ossl_error;
    }

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);
    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x08ossltest", 9);

    ret = SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        fprintf(stderr, "2.\n");
        goto ossl_error;
    }

    ret = SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION);
    if (ret != 1)
    {
        fprintf(stderr, "3.\n");
        goto ossl_error;
    }

    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_COMPRESSION);

    ret = SSL_CTX_set_ciphersuites(ssl_ctx, ciphersuites);
    if (ret != 1)
    {
        fprintf(stderr, "4.\n");
        goto ossl_error;
    }
    ret = SSL_CTX_set1_groups_list(ssl_ctx, kex_alg);
    if (ret != 1)
    {
        fprintf(stderr, "5.\n");
        goto ossl_error;
    }

    ret = SSL_CTX_load_verify_locations(ssl_ctx, ca_file, 0);
    if(ret != 1)
    {
        fprintf(stderr, "6.\n");
        goto ossl_error;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    const int warmup_count = warmup_count_from_env();
    fprintf(stderr, "Warmup handshakes: %d\n", warmup_count);
    int consecutive_failures = 0;
    for(int i=0; i < warmup_count; i++){
        ssl = do_tls_handshake(ssl_ctx, NULL);
        if (!ssl)
        {
            if (++consecutive_failures > MAX_CONSECUTIVE_FAILURES)
            {
                fprintf(stderr, "Giving up after %d consecutive handshake failures\n", consecutive_failures);
                goto end;
            }
            fprintf(stderr, "Warmup Handshake failed, retrying...\n");
            i--;
            continue;
        }
        consecutive_failures = 0;
        fprintf(stderr, "Shutting down warmup\n");
        ret = SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    while(measurements < measurements_to_make)
    {
        fprintf(stderr, "Measurement %lu\n", measurements);
        double measurement = -1;
        ssl = do_tls_handshake(ssl_ctx, &measurement);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes. */
            if (++consecutive_failures > MAX_CONSECUTIVE_FAILURES)
            {
                fprintf(stderr, "Giving up after %d consecutive handshake failures\n", consecutive_failures);
                goto end;
            }
            fprintf(stderr, "Handshake failed, retrying...\n");
            continue;
        }
        consecutive_failures = 0;

        fprintf(stderr, "Shutting down\n");
            ret = SSL_shutdown(ssl);
            if (ret < 0) {
                fprintf(stderr, "Error shutting down: %d\n", ret);
            }

        SSL_free(ssl);

        handshake_times_ms[measurements] = measurement;
        measurements++;
    }

    for(size_t i = 0; i < measurements; i++)
    {
        printf("%f\n", handshake_times_ms[i]);
	    measurements_sum += handshake_times_ms[i];
	    measurements_sq_sum += handshake_times_ms[i] * handshake_times_ms[i];
    }

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
