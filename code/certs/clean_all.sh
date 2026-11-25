#!/usr/bin/env bash
if [ "$#" -ne 1 ]; then
    echo "Error: This script requires exactly one argument." >&2
    echo "Usage: $0 <Certs Dir>" >&2
    exit 1
fi
CERTS_DIR="$1"

rm -rf $CERTS_DIR/root/
rm -rf $CERTS_DIR/sub/
rm -rf $CERTS_DIR/ct/

rm -f $CERTS_DIR/leaf_*
rm -f $CERTS_DIR/*.key

rm -f $CERTS_DIR/sub_ca.csr
rm -f $CERTS_DIR/sub_ca.crt $CERTS_DIR/root.crt
rm -f $CERTS_DIR/sub_chain.pem
rm -f $CERTS_DIR/sub_ca.cnf $CERTS_DIR/root_ca.cnf $CERTS_DIR/minimal.cnf
rm -f $CERTS_DIR/sub_ca.pubkey.crt $CERTS_DIR/sub_ca_keyhash.bin

rm -f $CERTS_DIR/ct_log_list.cnf
