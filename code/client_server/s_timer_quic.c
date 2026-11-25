/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <stdio.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <time.h>

#define NS_IN_MS 1000000.0
#define MS_IN_S 1000

const char* ca_file = "/root/post-quantum-quick-standalone/code/certs/root.crt";
const char* host = "";

static BIO *create_socket_bio(const char *hostname, const char *port,
                              int family, BIO_ADDR **peer_addr)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;// = malloc(sizeof(BIO));

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
        // if (!BIO_socket_nbio(sock, 0)) {
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
    char* port = "4433";

    // conn = BIO_new(BIO_s_connect());
    conn = create_socket_bio(host, port, AF_INET, &peer_addr);
    if (!conn)
    {
        free(conn);
        return 0;
    }

    BIO_set_conn_hostname(conn, host);
    BIO_set_conn_mode(conn, BIO_SOCK_NODELAY);

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
    *measurement = ((finish.tv_sec - start.tv_sec) * MS_IN_S) + ((finish.tv_nsec - start.tv_nsec) / NS_IN_MS);
    if (ret <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        // free(conn);
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
    if(argc != 4)
    {
        fprintf(stderr, "Wrong number of arguments. <alg> <count> <host:port>\n");
        printf("Version %lx\n", OPENSSL_VERSION_NUMBER);
        goto end;
    }
    host = argv[3];

    const char* kex_alg = argv[1];
    const size_t measurements_to_make = strtol(argv[2], 0, 10);
    size_t measurements = 0;
    double measurements_sum = 0;
    double measurements_sq_sum = 0;

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

    while(measurements < measurements_to_make)
    {
        fprintf(stderr, "Measurement %lu\n", measurements);
        double measurement = -1;
        ssl = do_tls_handshake(ssl_ctx, &measurement);
        if (!ssl)
        {
            /* Retry since at high packet loss rates,
             * the connect() syscall fails sometimes.
             * Non-retryable errors are caught by manual
             * inspection of logs, which has sufficed
             * for our purposes */
            fprintf(stderr, "Handshake failed, retrying...\n");
            continue;
        }

        fprintf(stderr, "Shutting down\n");
        // do {
            ret = SSL_shutdown(ssl);
            if (ret < 0) {
                printf("Error shutting down: %d\n", ret);
                // break;
            }
        // } while (ret != 1);

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
    printf("----------------");
    printf("Measurements: %lu\n", measurements);
    printf("Average: %f\n", measurements_sum / measurements);
    printf("Variance: %f\n", measurements_sq_sum / measurements - measurements_sum * measurements_sum / (measurements * measurements));

    ret = 0;
    goto end;

ossl_error:
    fprintf(stderr, "Unrecoverable OpenSSL error.\n");
    ERR_print_errors_fp(stderr);
end:
    SSL_CTX_free(ssl_ctx);
    return ret;
}
