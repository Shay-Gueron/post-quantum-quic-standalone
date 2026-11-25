# Certificate generation

The experiment uses a root CA, an intermediate CA, a CT log signing key, and
leaf certificates with an embedded SCT list. All generated files land in a
target certificates directory.

## One-shot setup

`setup.py` runs the full pipeline and is what the experiment runner calls:

```bash
python3 setup.py <CA_ALG> <CT_ALG> <CERTS_DIR>
```

Examples:

```bash
python3 setup.py P-256 P-256 /tmp/certs
python3 setup.py MLDSA44 MLDSA44 /tmp/certs
```

## Individual steps

With the patched OpenSSL on `PATH` and `CERTS_DIR` pointing at the target
directory:

```bash
./clean_all.sh "$CERTS_DIR"
./setup.sh <CA_ALG> <CT_ALG> "$CERTS_DIR"
./make_leaf.py -e 100 -p "$CERTS_DIR/leaf.priv.key" -d "$CERTS_DIR"
./sct_generator.py \
    "$CERTS_DIR/ct/ct_log_signing.key" \
    "$CERTS_DIR/ct/ct_log_id.txt" \
    "$CERTS_DIR/leaf_100.crt" \
    "$CERTS_DIR/leaf.priv.key" \
    "$CERTS_DIR/sub_ca_keyhash.bin" \
    "$CERTS_DIR" \
    --hash-and-sign mldsa44
```

`make_leaf.py -e 100` creates a leaf with a 100-byte custom extension so the
certificate is large enough to exercise the fragmentation paths.
`sct_generator.py` signs two SCTs, embeds them in the certificate, and writes
`leaf_100_ct.crt` together with its chain, `leaf_100_ct.pem`.

## Algorithms

- CA keys: `MLDSA44`, `MLDSA65`, `MLDSA87`, `RSA`, `P-256`
- CT log keys: `MLDSA44`, `MLDSA65`, `MLDSA87`, `RSA`, `P-256`
- For direct `setup.sh` calls, P-256 is passed as
  `"EC -pkeyopt ec_paramgen_curve:P-256"`. `setup.py` expands the short
  `P-256` name for you.

`ct_config_generator/` is an optional helper for regenerating
`ct_log_list.cnf` from Chrome's published log list. The experiment does not
need it: `setup.sh` writes a local, synthetic log list that the client uses.
