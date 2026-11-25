#!/usr/bin/env python3

import hashlib
import struct
import time
import binascii
import subprocess
import tempfile
import os
import sys
import argparse

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier
from pyasn1.type import univ
from pyasn1.codec.der import encoder

script_dir = os.path.abspath(os.path.dirname(__file__))

def valid_path(path):
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError(f"File not found: {path}")
    return path

def parse_args():
    parser = argparse.ArgumentParser(
        description="Create certificate with CT extention given a certificate and relevant keys."
    )

    parser.add_argument("log_key_path", type=valid_path, help="Path to the log private key file")
    parser.add_argument("log_id_path", type=valid_path, help="Path to the log ID file")
    parser.add_argument("cert_path", type=valid_path, help="Path to the certificate file")
    parser.add_argument("cert_key_path", type=valid_path, help="Path to the certificate private key file")
    parser.add_argument("ca_pub_key_hash_path", type=valid_path, help="Path to CA public key hash file")
    parser.add_argument("certs_dir", type=valid_path, help="Path to the certificates dir where outputs will be stored")
    parser.add_argument(
        "--hash-and-sign",
        type=str,
        default="sha256_ecdsa",
        help="Hash and signing algorithm (default: sha256_ecdsa)"
    )

    args = parser.parse_args()
    return args


OID_POISON = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.3")
OID_SCT_LIST = ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")

def openssl_sign(key_path: str, data: bytes) -> bytes:
    """
    Sign arbitrary data with the given private key using OpenSSL CLI.
    Equivalent to:
        openssl dgst -sha256 -sign private.pem data.txt > data.sig
    """
    with tempfile.NamedTemporaryFile(delete=False) as data_file, \
         tempfile.NamedTemporaryFile(delete=False) as sig_file:
        try:
            # Write input data
            hashed_data = hashlib.sha256(data).digest()
            data_file.write(data)
            data_file.flush()
            print(f"Data to sign (SHA-256): {binascii.hexlify(hashed_data).decode()}")
            print(f"Data: {binascii.hexlify(data).decode()}")

            # Run openssl to sign
            cmd = [
                    "openssl", "dgst",
                    "-sign", key_path,
                    "-out", sig_file.name,
                    data_file.name,
                ]
            print("Running command:", ' '.join(cmd))
            try:
                result = subprocess.run(cmd,
                    check=True,
                    capture_output=True
                )
            except subprocess.CalledProcessError as e:
                print(f"Error running openssl: {e}")
                print(f"stdout: {e.stdout.decode(errors='ignore') if e.stdout else ''}")
                print(f"stderr: {e.stderr.decode(errors='ignore') if e.stderr else ''}")
                raise

            # Read signature
            sig_file.seek(0)
            signature = sig_file.read()
            return signature
        finally:
            # Cleanup
            os.unlink(data_file.name)
            os.unlink(sig_file.name)

def load_certificate(cert_path):
    print(f"Loading certificate from {cert_path}")
    with open(cert_path, 'rb') as f:
        data = f.read()
        return x509.load_pem_x509_certificate(data)

def create_sct_data(timestamp, certificate_der, issuer_key_hash):
    """Create SCT data structure for signing"""
    print("create_sct_data")
    # Version (1 byte)
    version = b'\x00'
    # SignatureType (1 byte) - certificate_timestamp = 0
    signature_type = b'\x00'
    # Timestamp (8 bytes)
    timestamp_bytes = struct.pack('>Q', timestamp)
    # LogEntryType (2 bytes) - precert_entry = 1
    entry_type = b'\x00\x01'  # For X.509 entry, use b'\x00\x00'; for precert_entry, use b'\x00\x01'
    # # X.509 entry: just the certificate length + certificate
    tbs_length_bytes = struct.pack('>I', len(certificate_der))[1:]  # 3 bytes
    signed_entry = issuer_key_hash + tbs_length_bytes + certificate_der
    # Extensions (2 bytes length + data)
    extensions = b'\x00\x00'
    # Combine all data for signing
    sct_data = version + signature_type + timestamp_bytes + entry_type + signed_entry + extensions

    return sct_data

def sign_sct(log_key_path, sct_data):
    """Sign SCT data with CT log private key"""
    signature = openssl_sign(log_key_path, sct_data)
    return signature

def create_sct_structure(log_id, timestamp, signature, hash_and_sign_str="sha256_ecdsa"):
    print("create_sct_structure")
    """Create complete SCT structure"""
    # Version (1 byte)
    version = b'\x00'

    # Log ID (32 bytes)
    log_id_bytes = binascii.unhexlify(log_id)

    # Timestamp (8 bytes)
    timestamp_bytes = struct.pack('>Q', timestamp)

    # Extensions (2 bytes length + data)
    extensions = b""
    extensions_len = struct.pack(">H", len(extensions))

    if hash_and_sign_str == "sha256_ecdsa":
        hash_and_sign_alg = bytes([0x04, 0x03])  # SHA256 (4), ECDSA (3)
    elif hash_and_sign_str == "sha256_rsa":
        hash_and_sign_alg = bytes([0x04, 0x01])  # SHA256 (4), RSA (1)
    elif hash_and_sign_str == "mldsa44":
        hash_and_sign_alg = bytes([0x09, 0x04])
    elif hash_and_sign_str == "mldsa65":
        hash_and_sign_alg = bytes([0x09, 0x05])
    elif hash_and_sign_str == "mldsa87":
        hash_and_sign_alg = bytes([0x09, 0x06])
    else:
        raise ValueError("Unsupported hash_and_sign_str")

    # Signature length (2 bytes) + signature
    sig_length = struct.pack('>H', len(signature))

    sct = version + log_id_bytes + timestamp_bytes + extensions_len + extensions + hash_and_sign_alg + sig_length + signature

    return sct

def create_sct_list(scts):
    """Create SCT list structure for certificate extension"""
    print("create_sct_list")
    # Calculate total length of all SCTs
    total_length = 0
    sct_entries = b''

    for sct in scts:
        sct_length = struct.pack('>H', len(sct))
        sct_entries += sct_length + sct
        total_length += 2 + len(sct)

    # SCT list length (2 bytes) + SCT entries
    sct_list = struct.pack('>H', total_length) + sct_entries

    return sct_list


def generate_sct(log_key_path, log_id, cert_path, ca_key_hash_path, hash_and_sign_str):
    """Generate SCT for a certificate"""
    # Load certificate
    certificate = load_certificate(cert_path)

    # Get current timestamp (milliseconds since epoch)
    timestamp = int(time.time() * 1000)

    # Get certificate DER encoding
    print("Getting certificate DER encoding")
    cert_der_tbs = certificate.tbs_certificate_bytes

    with open(ca_key_hash_path, 'rb') as f:
        issuer_key_hash = f.read()
    # Create SCT data for signing
    sct_data = create_sct_data(timestamp, cert_der_tbs, issuer_key_hash)

    # Sign the SCT data
    signature = sign_sct(log_key_path, sct_data)

    # Create complete SCT structure
    sct = create_sct_structure(log_id, timestamp, signature, hash_and_sign_str)

    return sct, timestamp

def precert_to_final(cert_key_path, sct_list, certs_dir):
    """
    Take a precertificate (with poison extension),
    remove poison,
    add SCT list extension,
    and re-sign using CA private key.
    """
    # Load precertificate and CA key
    inner_octet = univ.OctetString(sct_list)
    nested_der = encoder.encode(inner_octet)
    der_ext = x509.UnrecognizedExtension(OID_SCT_LIST, nested_der)

    cmd = [
        os.path.join(script_dir, "make_leaf.py"),
        "-e",
        "100",
        "-c",
        f"{der_ext.oid.dotted_string} = DER:{nested_der.hex()}",
        "-p", cert_key_path,
        "-d",
        certs_dir
    ]
    print("Running command:", ' '.join(cmd))
    try:
        result = subprocess.run(cmd,
            check=True,
            capture_output=True
        )
        print(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        print(f"Error running openssl: {e}")
        print(f"stdout: {e.stdout.decode(errors='ignore') if e.stdout else ''}")
        print(f"stderr: {e.stderr.decode(errors='ignore') if e.stderr else ''}")
        raise


if __name__ == "__main__":
    args = parse_args()

    log_id = open(args.log_id_path).read().strip()
    try:
        # Generate SCT
        sct1, timestamp1 = generate_sct(args.log_key_path, log_id, args.cert_path, args.ca_pub_key_hash_path, args.hash_and_sign)
        sct2, timestamp2 = generate_sct(args.log_key_path, log_id, args.cert_path, args.ca_pub_key_hash_path, args.hash_and_sign)

        print("Generated SCT:")
        print(f"Length: {len(sct1)} and {len(sct2)} bytes")
        print(f"Timestamp: {timestamp1}, {timestamp2} "
              f"({time.ctime(timestamp1 / 1000)}, {time.ctime(timestamp2 / 1000)})")

        # Create SCT list for certificate extension
        sct_list = create_sct_list([sct1, sct2])

        precert_to_final(args.cert_key_path, sct_list, args.certs_dir)
        cert_name = os.path.basename(args.cert_path)
        cert_name_no_ext = os.path.splitext(cert_name)[0]
        ct_cert_name = os.path.join(args.certs_dir, f'{cert_name_no_ext}_ct.crt')
        ct_chain_name = os.path.join(args.certs_dir, f'{cert_name_no_ext}_ct.pem')

        # Making chain
        os.system(f"cat {ct_cert_name} {os.path.join(args.certs_dir, 'sub_chain.pem')} > {ct_chain_name}")

        print(f"\nFinal certificate with SCT extension saved to {ct_cert_name}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
