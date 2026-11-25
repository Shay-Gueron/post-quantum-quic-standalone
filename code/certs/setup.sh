
# Usage: ./setup.sh <CA_ALGORITHM> <CT_ALGORITHM> <CERTS_DIR>
# Example: ./setup.sh mldsa87 mldsa87 /tmp/certs_dir
# Example: ./setup.sh RSA RSA /tmp/certs_dir
# Example: ./setup.sh "EC -pkeyopt ec_paramgen_curve:P-256" RSA /tmp/certs_dir
# Note: SCT signing supports ECDSA, RSA, and ML-DSA keys. Ed25519 is not supported.
if [ "$#" -ne 3 ]; then
  echo "Usage: $0 <ALGORITHM> <CT_ALGORITHM> <CERTS_DIR>"
  echo "Example: $0 mldsa87 RSA /tmp/certs_dir"
  echo "Example: $0 RSA RSA /tmp/certs_dir"
  echo "Example: $0 \"EC -pkeyopt ec_paramgen_curve:P-256\" RSA /tmp/certs_dir"
  exit 1
fi
ALGO="$1"
CT_ALGO="$2"
CERTS_DIR=$(realpath "$3")

echo "Using output dir $CERTS_DIR"

# make sure the output dir exists
mkdir -p $CERTS_DIR

# Check if algorithm exists in openssl genpkey
if ! openssl genpkey -algorithm $ALGO -out /dev/null 2>/dev/null; then
  echo "Algorithm $ALGO not supported by openssl genpkey."
  exit 2
fi

openssl genpkey -algorithm $ALGO -out $CERTS_DIR/root.priv.key
openssl genpkey -algorithm $ALGO -out $CERTS_DIR/sub_ca.priv.key
openssl genpkey -algorithm $ALGO -out $CERTS_DIR/leaf.priv.key


mkdir $CERTS_DIR/ct
# Generate CT log

openssl genpkey -algorithm $CT_ALGO -out $CERTS_DIR/ct/ct_log_signing.key
echo "Using CT algorithm: $CT_ALGO"

echo "[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_ct_log

countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
organizationalUnitName = optional

[req_distinguished_name]
CN = Experiment CT Log Signing Certificate

[v3_ct_log]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, 1.3.6.1.4.1.11129.2.4.5
# This certificate is valid for operating a Certificate Transparency log
subjectKeyIdentifier = hash" > $CERTS_DIR/ct/ct_log_config.cnf

openssl req -new -x509 -key $CERTS_DIR/ct/ct_log_signing.key -out $CERTS_DIR/ct/ct_log_signing.crt -days 3650 \
    -config $CERTS_DIR/ct/ct_log_config.cnf -extensions v3_ct_log -subj "/CN=Experiment CT Log Signing Certificate"

# Generate Log ID (SHA-256 hash of the public key)
openssl x509 -in $CERTS_DIR/ct/ct_log_signing.crt -pubkey -noout > $CERTS_DIR/ct/ct_log_pubkey.pem
openssl pkey -pubin -in $CERTS_DIR/ct/ct_log_pubkey.pem -outform DER | openssl dgst -sha256 -binary > $CERTS_DIR/ct/ct_log_id.bin
LOG_ID=$(cat $CERTS_DIR/ct/ct_log_id.bin | hexdump -v -e '/1 "%02x"')
echo "CT Log ID: $LOG_ID"
echo $LOG_ID > $CERTS_DIR/ct/ct_log_id.txt

echo "enabled_logs = https_//my_server.com/logs/

[https_//my_server.com/logs/]
description = My custom log
key = $(cat $CERTS_DIR/ct/ct_log_pubkey.pem | grep -v '\-\-\-\-\-BEGIN PUBLIC KEY\-\-\-\-\-' | grep -v '\-\-\-\-\-END PUBLIC KEY\-\-\-\-\-' | tr -d '\n')
" > $CERTS_DIR/ct_log_list.cnf

# Setup Root CA and Sub CA
mkdir $CERTS_DIR/root
echo "01" > $CERTS_DIR/root/serial
touch $CERTS_DIR/root/db.txt
mkdir $CERTS_DIR/root/newcerts

echo "[req]
distinguished_name = dn

[dn]
CN = COMMON_NAME" > $CERTS_DIR/minimal.cnf

echo "[ca]
default_ca = root_ca

[root_ca]
serial = $CERTS_DIR/root/serial
database = $CERTS_DIR/root/db.txt
new_certs_dir = $CERTS_DIR/root/newcerts/
certificate = $CERTS_DIR/root.crt
private_key = $CERTS_DIR/root.priv.key
default_md = sha256
default_days = 730
policy = root_policy 

[root_policy]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
organizationalUnitName = optional

[root_v3]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical,CA:true
keyUsage = critical, cRLSign, keyCertSign
" > $CERTS_DIR/root_ca.cnf

mkdir $CERTS_DIR/sub
echo "01" > $CERTS_DIR/sub/serial
touch $CERTS_DIR/sub/db.txt
mkdir $CERTS_DIR/sub/newcerts

echo "[ca]
default_ca = root_ca

[root_ca]
serial = $CERTS_DIR/root/serial
database = $CERTS_DIR/root/db.txt
new_certs_dir = $CERTS_DIR/root/newcerts/
certificate = $CERTS_DIR/root.crt
private_key = $CERTS_DIR/root.priv.key
default_md = sha256
default_days = 730
policy = root_policy 

[root_policy]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
organizationalUnitName = optional

[sub_ca]
serial = $CERTS_DIR/sub/serial
database = $CERTS_DIR/sub/db.txt
new_certs_dir = $CERTS_DIR/sub/newcerts/
certificate = $CERTS_DIR/sub_ca.crt
private_key = $CERTS_DIR/sub_ca.priv.key
default_md = sha256
default_days = 730
policy = sub_policy
copy_extensions = none

[sub_policy]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
organizationalUnitName = optional

[sub_v3]
subjectKeyIdentifier = hash
authorityKeyIdentifier = issuer
basicConstraints = critical,CA:true
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
extendedKeyUsage = serverAuth, clientAuth

" > $CERTS_DIR/sub_ca.cnf

# Generate root and sub CA certs
openssl req -key $CERTS_DIR/root.priv.key -x509 -days 3650 \
  -out $CERTS_DIR/root.crt -config $CERTS_DIR/root_ca.cnf -extensions root_v3 \
  -subj "/CN=Root CA"
openssl req -new -key $CERTS_DIR/sub_ca.priv.key -out $CERTS_DIR/sub_ca.csr -config $CERTS_DIR/sub_ca.cnf\
  -subj "/CN=Sub CA"
openssl ca -config $CERTS_DIR/sub_ca.cnf -extensions sub_v3 -out $CERTS_DIR/sub_ca.crt -in $CERTS_DIR/sub_ca.csr -batch
openssl x509 -in $CERTS_DIR/sub_ca.crt -pubkey -noout > $CERTS_DIR/sub_ca.pubkey.crt
openssl pkey -pubin -in $CERTS_DIR/sub_ca.pubkey.crt -outform DER | openssl dgst -sha256 -binary > $CERTS_DIR/sub_ca_keyhash.bin

cat $CERTS_DIR/sub_ca.crt $CERTS_DIR/root.crt > $CERTS_DIR/sub_chain.pem
