# Download all necessary python script files from Google CT github repository
wget -q https://raw.githubusercontent.com/google/certificate-transparency/refs/heads/master/python/utilities/log_list/print_log_list.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/refs/heads/master/python/utilities/log_list/cpp_generator.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/refs/heads/master/python/utilities/log_list/java_generator.py
wget -q https://raw.githubusercontent.com/google/certificate-transparency/refs/heads/master/python/utilities/log_list/openssl_generator.py

# Download other necessary files from Google CT Community Site github repository
# Download json containing list of all CT logs that are currently compliant with Google's CT policy
wget https://www.gstatic.com/ct/log_list/v3/log_list.json
# Download the signature of the Log list json, signed by Google
wget https://www.gstatic.com/ct/log_list/v3/log_list.sig
# Download the Google's public key in order to verify signature
wget https://www.gstatic.com/ct/log_list/v3/log_list_pubkey.pem
# Download the list of all known and announced CT logs
wget https://www.gstatic.com/ct/log_list/v3/all_logs_list.json
# Download the json schema, Log list and All log list should conform to this schema
wget https://www.gstatic.com/ct/log_list/v3/log_list_schema.json

# Install required python dependencies
pip install absl-py
pip install jsonschema
pip install m2crypto

# Generate the 'ct_log_list.cnf' for the OpenSSL
# This output file should be located under /etc/ssl/ct_log_list.cnf on Linux distributions
python print_log_list.py \
 --log_list_schema log_list_schema.json \
 --log_list log_list.json \
 --signer_key log_list_pubkey.pem \
 --signature log_list.sig \
 --openssl_output ct_log_list.cnf

# Clean
rm all_logs_list.json log_list.json log_list.sig log_list_pubkey.pem log_list_schema.json
rm *.py