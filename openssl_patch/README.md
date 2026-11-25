# OpenSSL Patch Build Helper

This directory contains:

- `openssl-3.6.0-beta1.patch` - the OpenSSL source patch extracted from the local patched tree.
- `build_openssl.sh` - a helper script that downloads upstream OpenSSL 3.6.0-beta1, applies the patch, builds, and installs it into this directory.

## How to use

From the repository root:

```bash
cd openssl_patch
./build_openssl.sh
```

The script will:

1. download `openssl-3.6.0-beta1.tar.gz` into `openssl_patch/download`
2. extract the upstream source into `openssl_patch/download/openssl-3.6.0-beta1`
3. apply `openssl-3.6.0-beta1.patch`
4. build OpenSSL
5. install the result into `openssl_patch/openssl-3.6.0-beta1-install`

## Notes

- The patch can be reviewed in `openssl_patch/openssl-3.6.0-beta1.patch`.
- If you want to use the new OpenSSL build in `client_server/Makefile`, set `OPENSSL_DIR` to the install directory produced by this script.

# Changes to Openssl

## crypto/ct/ct_sct.c
* Edited `SCT_get_signature_nid` to support `ML_DSA`

## crypto/ct/ct_sct_ctx.c
* Debug print

## crypto/ct/ct_vfy.c
* Debug print
* Edited `SCT_CTX_verify` to make it support different hashes (needed for `ML_DSA` support)
* Debug prints when verifying sig

## crypto/ml_dsa/ml_dsa_sign.c
* Debug print

## ssl/quic/quic_channel.c
* Double the size of `INIT_CRYPTO_RECV_BUF_LEN` and `INIT_CRYPTO_SEND_BUF_LEN`

## demos/quic/server/Makefile
* Change the linked libraries paths to absolute

## demos/quic/server/server.c
* Remove cast in `create_socket`?
* Debug prints
* Don't raise error if had problem with connection
* Add support to change key-exchange groups

## demos/guide/Makefile
* Change the linked libraries paths to absolute

## demos/guide/tls-server-block.c
* Ignore SIGPIPE in order
to survive abrupt shutdowns from client.
* Server certificate+key paths pass in argv
* Don't enable session caches
* Set KEX group from argv
* Don't read from socket, just write and shutdown. (With the timing client the write fails.)

## providers/implementations/signature/ml_dsa_sig.c.in
* Debug prints
* Added the function `ml_dsa_digest_verify_final` to support `ML_DSA` verification.
