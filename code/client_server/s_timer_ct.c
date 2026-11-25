/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000
#define MAX_CONSECUTIVE_FAILURES 20

const char* ca_file = "../certs/root.crt";
const char* CTLOG_FILE = "../certs/ct_log_list.cnf";
const char* host = "";
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

SSL* do_tls_handshake(SSL_CTX* ssl_ctx)
{
    BIO* conn;
    SSL* ssl;
    int ret;

    conn = BIO_new(BIO_s_connect());
    if (!conn)
    {
        return 0;
    }

    BIO_set_conn_hostname(conn, host);
    BIO_set_conn_mode(conn, BIO_SOCK_NODELAY);

    ssl = SSL_new(ssl_ctx);

    SSL_set_bio(ssl, conn, conn);

    /* ok, lets connect */
    ret = SSL_connect(ssl);

    if (ret <= 0)
    {
        ERR_print_errors_fp(stderr);
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
    fprintf(stderr, "In my_ct_validation_callback\n");
    /* Perform validation of SCTs found in the peer's certificate, TLS extensions or OCSP response. */
    /* The validation is performed according to RFC 6962 and RFC 6962-bis. */
    /* The result of the validation is returned to the caller. */
    if (out_alert == NULL) {

    }
    if (ctx == NULL) {
        return 0;
    }
    int sct_list_stack_size = sk_SCT_num(scts);

    /* Pretty print every SCT to stderr, so stdout stays parseable. */
    BIO *out = BIO_new_fp(stderr, BIO_NOCLOSE);
    if (out == NULL) {
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "SCT list size: %d\n", sct_list_stack_size);
    fprintf(stderr, "Printing SCT list:\n");
    SCT_LIST_print(scts, out, 1, "\n\n", ctlog_store);
    fprintf(stderr, "\nDone\n");
    BIO_free(out);
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
        const char *validation_message = SCT_validation_status_string(single_sct);
        fprintf(stderr, "%s\n", validation_message);
    }
    return 1;
}

int main(int argc, char* argv[])
{
    int ret = -1;
    SSL_CTX* ssl_ctx = 0;
    if(argc != 4 && argc != 6)
    {
        fprintf(stderr, "Wrong number of arguments. <kex alg> <count> <host:port> [<CA path> <CT Log Path>]\n");
        fprintf(stderr, "\t- CA path defaults to \"../certs/root.crt\"\n");
        fprintf(stderr, "\t- CT Log path defaults to \"../certs/ct_log_list.cnf\"\n");
        fprintf(stderr, "Version %lx\n", OPENSSL_VERSION_NUMBER);
        goto end;
    }
    fprintf(stderr, "Version %lx\n", OPENSSL_VERSION_NUMBER);

    host = argv[3];

    const char* kex_alg = argv[1];
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;
    double measurements_sum = 0;
    double measurements_sq_sum = 0;

    if(argc == 6)
    {
        ca_file = argv[4];
        CTLOG_FILE = argv[5];
    }

    const char* ciphersuites = "TLS_AES_256_GCM_SHA384";
    const SSL_METHOD* ssl_meth = TLS_client_method();
    SSL* ssl = NULL;

    struct timespec start, finish;
    double* handshake_times_ms = malloc(measurements_to_make * sizeof(*handshake_times_ms));

    ctlog_store = create_ct_log_store(CTLOG_FILE);
    ssl_ctx = SSL_CTX_new(ssl_meth);
    if (!ssl_ctx)
    {
        fprintf(stderr, "1.\n");
        goto ossl_error;
    }

    SSL_CTX_enable_ct(ssl_ctx, SSL_CT_VALIDATION_STRICT);
    SSL_CTX_set0_ctlog_store(ssl_ctx, ctlog_store);

    /* my_ct_validation_callback is kept for reference; strict validation is
     * enabled above via SSL_CTX_enable_ct and OpenSSL's built-in callback. */
    //SSL_CTX_set_ct_validation_callback(ssl_ctx, my_ct_validation_callback, NULL);

    SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_quiet_shutdown(ssl_ctx, 1);

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

    int consecutive_failures = 0;
    while(measurements < measurements_to_make)
    {
        clock_gettime(CLOCK_MONOTONIC_RAW, &start);
        ssl = do_tls_handshake(ssl_ctx);
        clock_gettime(CLOCK_MONOTONIC_RAW, &finish);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes. */
            if (++consecutive_failures > MAX_CONSECUTIVE_FAILURES)
            {
                fprintf(stderr, "Giving up after %d consecutive handshake failures\n", consecutive_failures);
                goto end;
            }
            continue;
        }
        consecutive_failures = 0;

        SSL_set_shutdown(ssl, SSL_SENT_SHUTDOWN | SSL_RECEIVED_SHUTDOWN);
        ret = BIO_closesocket(SSL_get_fd(ssl));
        if(ret == -1)
        {
            fprintf(stderr, "7.\n");
            goto ossl_error;
        }

        SSL_free(ssl);

        handshake_times_ms[measurements] = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
        measurements++;
    }

    for(size_t i = 0; i < measurements; i++)
    {
        printf("%f\n", handshake_times_ms[i]);
	    measurements_sum += handshake_times_ms[i];
	    measurements_sq_sum += handshake_times_ms[i] * handshake_times_ms[i];
    }
    fprintf(stderr, "----------------\n");
    fprintf(stderr, "Measurements: %lu\n", measurements);
    fprintf(stderr, "Average: %f\n", measurements_sum / measurements);
    fprintf(stderr, "Variance: %f\n", measurements_sq_sum / measurements - measurements_sum * measurements_sum / (measurements * measurements));

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
