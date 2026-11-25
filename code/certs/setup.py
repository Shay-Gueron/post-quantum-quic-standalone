import os
import argparse
import subprocess

script_dir = os.path.abspath(os.path.dirname(__file__))

def main():
    parser = argparse.ArgumentParser(description="SETUP script for CA and CT log signing keys")
    parser.add_argument('ca_algo')
    parser.add_argument('ct_algo')
    parser.add_argument('certs_dir', nargs='?', default=os.path.join(script_dir, 'certs'))
    args = parser.parse_args()
    setup_certificate(args.ca_algo, args.ct_algo, args.certs_dir)


def setup_certificate(ca_algo, ct_algo, certs_dir, stdout=None, stderr=None):
    ca_algo = ca_algo.upper()
    ct_algo = ct_algo.upper()
    assert ca_algo in ["MLDSA87", "MLDSA65", "MLDSA44", "RSA", "Ed25519", "P-256", "EC -pkeyopt ec_paramgen_curve:P-256"], "Unsupported CA algorithm"
    if "P-256" in ca_algo:
        ca_algo = "EC -pkeyopt ec_paramgen_curve:P-256"

    if "P-256" in ct_algo:
        ct_algo = "EC -pkeyopt ec_paramgen_curve:P-256"
    subprocess.run(["bash", os.path.join(script_dir, "clean_all.sh"), certs_dir], stdout=stdout, stderr=stderr)
    subprocess.run(["bash", os.path.join(script_dir, "setup.sh"), ca_algo, ct_algo, certs_dir], stdout=stdout, stderr=stderr)
    leaf_private_key = os.path.join(certs_dir, "leaf.priv.key")
    subprocess.run(["python3", os.path.join(script_dir, "make_leaf.py"), "-e", f"{100}", "-p", leaf_private_key, "-d", certs_dir], stdout=stdout, stderr=stderr)
    sct_args = ["python3",
                os.path.join(script_dir, "sct_generator.py"),
                os.path.join(certs_dir, "ct/ct_log_signing.key"),
                os.path.join(certs_dir, "ct/ct_log_id.txt"),
                os.path.join(certs_dir, "leaf_100.crt"),
                leaf_private_key,
                os.path.join(certs_dir, "sub_ca_keyhash.bin"),
                certs_dir]
    if "P-256" not in ct_algo:
        sct_args += ["--hash-and-sign", f"{ct_algo.lower()}"]
    subprocess.run(sct_args, stdout=stdout, stderr=stderr)


if __name__ == "__main__":
    main()
