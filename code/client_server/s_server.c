#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433

void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}


void load_extra_chain(SSL_CTX *ctx, const char *chain_file)
{
    BIO *bio = BIO_new_file(chain_file, "r");
    if (!bio) {
        perror("Unable to open chain file");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    while (1) {
        X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
        if (!cert)
            break; // no more certs
        if (SSL_CTX_add_extra_chain_cert(ctx, cert) != 1) {
            X509_free(cert); // free if not added
            ERR_print_errors_fp(stderr);
            exit(EXIT_FAILURE);
        }
    }

    BIO_free(bio);
}

void configure_context(SSL_CTX *ctx)
{
    /* Load certificate and private key files */
    if (SSL_CTX_use_certificate_file(ctx, "/root/post-quantum-quick-standalone/code/certs/leaf_100000.crt", SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "1.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "/root/post-quantum-quick-standalone/code/certs/leaf.priv.key", SSL_FILETYPE_PEM) <= 0 ) {
        fprintf(stderr, "2.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    /* Verify private key */
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "3.\n");
        fprintf(stderr, "Private key does not match certificate\n");
        exit(EXIT_FAILURE);
    }

    /* Load intermediate + root certificates from separate file */
    load_extra_chain(ctx, "/root/post-quantum-quick-standalone/code/certs/sub_chain.pem");

    // if (SSL_CTX_set1_groups_list(ctx, "mlkem768:mlkem512:mlkem1024:P-256:P-384:P-521") != 1) {
    if (SSL_CTX_set1_groups_list(ctx, "P-256:P-384:P-521") != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}


int main()
{
    int sock;
    struct sockaddr_in addr;

    init_openssl();
    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    /* Create socket */
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    printf("TLS server listening on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        unsigned int client_len = sizeof(client_addr);
        int client = accept(sock, (struct sockaddr*)&client_addr, &client_len);
        printf("Accepted connection from %s:%d\n",
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

        if (client < 0) {
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        printf("Creating SSL object...\n");
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        printf("Performing SSL handshake...\n");
        if (SSL_accept(ssl) <= 0) {
            printf("SSL accept failed.\n");
            ERR_print_errors_fp(stderr);
        } else {
            printf("Client connected successfully.\n");
            char buf[1024] = {0};
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            if (bytes > 0) {
                printf("Received: %s\n", buf);
                SSL_write(ssl, buf, bytes); // echo back
            }
        }

        printf("Closing connection...\n");

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
}
