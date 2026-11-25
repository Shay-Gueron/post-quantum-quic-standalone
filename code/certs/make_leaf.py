#!/usr/bin/python3
import os
import argparse
import string
import subprocess
from datetime import datetime, date
import calendar

LEAF_TEMPLATE = """[ca]
default_ca = sub_ca

[sub_ca]
serial = {certs_dir}/sub/serial
database = {certs_dir}/sub/db.txt
new_certs_dir = {certs_dir}/sub/newcerts/
certificate = {certs_dir}/sub_ca.crt
private_key = {certs_dir}/sub_ca.priv.key
default_md = sha256
default_days = 730
policy = sub_policy
copy_extensions = none
unique_subject = no

[sub_policy]
countryName = optional
stateOrProvinceName = optional
organizationName = optional
commonName = optional
organizationalUnitName = optional

[req]
distinguished_name = req_dn
req_extensions = leaf_v3
prompt = no

[req_dn]
CN = Ext with size {name_suffix}

[leaf_v3]
keyUsage = critical, keyEncipherment, dataEncipherment, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
1.2.3.4.5.6.7.8 = ASN1:UTF8String:{stub_extension}
{additional_extensions}

[alt_names]
DNS.1 = domain.com
DNS.2 = *.domain.com
"""

CHARS_IN_EXTENTIONS = string.ascii_letters + string.digits

def run_cmd(cmd):
  print(f"Running command: {cmd}")
  try:
      result = subprocess.run(cmd.split(" "),
          check=True,
          capture_output=True
      )
      print(result.stdout.decode())
  except subprocess.CalledProcessError as e:
      print(f"Error running openssl: {e}")
      print(f"stdout: {e.stdout.decode(errors='ignore') if e.stdout else ''}")
      print(f"stderr: {e.stderr.decode(errors='ignore') if e.stderr else ''}")
      raise

def get_validity_dates():
    """Calculate validity period: first day of current month to last day of next month"""
    now = datetime.now()

    # First day of current month
    start_date = date(now.year, now.month, 1)

    # Last day of next month
    if now.month == 12:
        # If current month is December, next month is January of next year
        end_month = 1
        end_year = now.year + 1
    else:
        end_month = now.month + 1
        end_year = now.year

    # Get last day of next month
    last_day = calendar.monthrange(end_year, end_month)[1]
    end_date = date(end_year, end_month, last_day)

    # Format for OpenSSL
    start_str = start_date.strftime("%Y%m%d000000Z")
    end_str = end_date.strftime("%Y%m%d235959Z")

    return start_str, end_str

def main():
    parser = argparse.ArgumentParser(description="Generate a leaf certificate with specified extension size.")
    parser.add_argument("-e", dest="ext_size", type=int, required=True)
    parser.add_argument("-c", dest="custom_ext", type=str, required=False, default="",
                        help="Custom extension to include in the certificate")
    parser.add_argument("-d", dest="certs_dir", type=str, required=True, help="Path to the root certificate directory where all certs and configs are stored")
    parser.add_argument("-p", dest="priv_key", type=str, required=False, default=None,
                       help="Path to private key file (if not provided, uses private key at `CERTS_DIR`/leaf.priv.key)")

    args = parser.parse_args()

    if not os.path.isdir(args.certs_dir):
        print(f"{args.certs_dir} is not a directory. Exiting...")
        exit(1)

    certs_dir = args.certs_dir
    certs_dir += "" if certs_dir.endswith("/") else "/"

    if args.priv_key is None:
        priv_key = os.path.join(certs_dir, "leaf.priv.key")
    else:
        priv_key = args.priv_key

    if not os.path.isfile(priv_key):
        print(f"Private key file {priv_key} does not exist. Exiting...")
        exit(1)

    name = f"leaf_{args.ext_size}{'_ct' if args.custom_ext else ''}"
    leaf_conf_path = os.path.join(certs_dir, f"{name}.cnf")
    leaf_csr_path = os.path.join(certs_dir, f"{name}.csr")
    leaf_crt_path = os.path.join(certs_dir, f"{name}.crt")
    leaf_pub_path = os.path.join(certs_dir, f"{name}.pubkey.crt")

    conf = LEAF_TEMPLATE.format(certs_dir=certs_dir.rstrip("/"),
                                name_suffix=str(args.ext_size),
                                stub_extension=''.join('X' for i in range(args.ext_size)),
                                additional_extensions=args.custom_ext)
    with open(leaf_conf_path, 'w') as f:
      f.write(conf)

    print(f"Using private key: {priv_key}")
    run_cmd(f"openssl req -new -key {priv_key} -out {leaf_csr_path} -config {leaf_conf_path}")
    start_date, end_date = get_validity_dates()
    if args.custom_ext:
        # Reset sub CA db to avoid serial issues
        # remove file from sub
        run_cmd(f"rm -r {os.path.join(certs_dir, 'sub/newcerts/')}")
        run_cmd(f"mkdir -p {os.path.join(certs_dir, 'sub/newcerts/')}")
        os.system(f"truncate -s 0 {os.path.join(certs_dir, 'sub/db.txt')}")
        run_cmd(f"rm {os.path.join(certs_dir, 'sub/db.txt.attr')}")
        run_cmd(f"rm {os.path.join(certs_dir, 'sub/db.txt.old')}")
        os.system(f"echo '01' > {os.path.join(certs_dir, 'sub/serial')}")
        run_cmd(f"rm {os.path.join(certs_dir, 'sub/serial.old')}")

    run_cmd(f"openssl ca -batch -config {leaf_conf_path} -extensions leaf_v3 -in {leaf_csr_path} -out {leaf_crt_path} -startdate {start_date} -enddate {end_date}")

    os.system(f"openssl x509 -in {leaf_crt_path} -pubkey -noout > {leaf_pub_path}")
    # Make chain
    os.system(f"cat {leaf_crt_path} {os.path.join(certs_dir, 'sub_chain.pem')} > {os.path.join(certs_dir, 'leaf_' + str(args.ext_size) + '.pem')}")


if __name__ == "__main__":
    main()
