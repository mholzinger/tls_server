#!/bin/bash

check_err(){ error_state=$(echo $?)
if [[ "$error_state" != "0" ]];then
    echo $1
    exit
fi
}

cd ca
check_err "Not running in ca dir"

CAROOT=./fips_ca

rm -rf $CAROOT
rm -rf ../crt
mkdir -p ${CAROOT}/certs \
    ${CAROOT}/crl \
    ${CAROOT}/newcerts \
    ${CAROOT}/private  # Signed certificates storage
touch ${CAROOT}/index      # Index of signed certificates
echo 01 > ${CAROOT}/serial # Next (sequential) serial number

# Configuration
cat>${CAROOT}/ca.conf<<'EOF'
[ ca ]
default_ca = ca_default

[ ca_default ]
dir = fips_ca
certs = $dir
new_certs_dir = $dir/certs
database = $dir/index
serial = $dir/serial
RANDFILE = $dir/.rand
certificate = $dir/ca.crt
private_key = $dir/ca.key
default_days = 365
default_crl_days = 30
default_md = md5
preserve = no
policy = generic_policy
[ generic_policy ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional
[ policy_anything ]
countryName		= optional
stateOrProvinceName	= optional
localityName		= optional
organizationName	= optional
organizationalUnitName	= optional
commonName		= supplied
emailAddress		= optional
EOF

expire_days=10000

# Generate rand file and store in private dir
openssl rand -out ${CAROOT}/.rand 2048

# Gen certificate authority private key and self-signed cert
openssl req -new \
    -x509 -nodes \
    -rand ${CAROOT}/.rand \
    -newkey rsa:2048 \
    -sha256 \
    -subj "/C=US/ST=WA/L=Seattle/O=github\ user/OU=FIPS\ test\ CA/CN=fips.localhost/emailAddress=gituser@email-address.com" \
    -days $expire_days -keyout ${CAROOT}/private/ca_key.pem \
    -out ${CAROOT}/certs/ca_cert.pem \
    -days $expire_days -keyout ${CAROOT}/private/ca_key.pem \
    -out ${CAROOT}/certs/ca_cert.pem \
    -verbose

# server
echo "Create server key (server_key.pem) and csr (server_csr.pem)"

openssl req \
    -rand ${CAROOT}/private/.rand \
    -new \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -keyout ${CAROOT}/private/server_key.pem \
    -out ${CAROOT}/certs/server_csr.pem \
    -subj "/C=US/ST=WA/L=Seattle/O=github\ user/OU=FIPS\ test\ CA/CN=tlserver.localhost/emailAddress=gituser@email-address.com"

echo "CA signs cert (server_cert.pem)"
openssl ca \
    -batch \
    -days $expire_days \
    -policy policy_anything \
    -keyfile ${CAROOT}/private/ca_key.pem \
    -cert ${CAROOT}/certs/ca_cert.pem \
    -outdir ${CAROOT}/newcerts \
    -config ${CAROOT}/ca.conf \
    -out ${CAROOT}/certs/server_cert.pem \
    -infiles ${CAROOT}/certs/server_csr.pem

# client
echo "Create client key (client_key.pem) and csr (client_csr.pem)"

openssl req \
    -rand ${CAROOT}/private/.rand \
    -new \
    -newkey rsa:2048 \
    -sha256 \
    -nodes \
    -keyout ${CAROOT}/private/client_key.pem \
    -subj "/C=US/ST=WA/L=Seattle/O=github\ user/OU=FIPS\ test\ CA/CN=tlclient.localhost/emailAddress=gituser@email-address.com" \
    -out ${CAROOT}/certs/client_csr.pem

echo "CA signs cert (client_cert.pem)"
openssl ca \
    -batch \
    -days $expire_days \
    -policy policy_anything \
    -keyfile ${CAROOT}/private/ca_key.pem \
    -cert ${CAROOT}/certs/ca_cert.pem \
    -outdir ${CAROOT}/newcerts \
    -config ${CAROOT}/ca.conf \
    -out ${CAROOT}/certs/client_cert.pem \
    -infiles ${CAROOT}/certs/client_csr.pem

rm ${CAROOT}/certs/*csr.pem

mkdir ../crt
cp ${CAROOT}/certs/server_cert.pem ../crt
cp ${CAROOT}/private/server_key.pem ../crt
cp ${CAROOT}/certs/ca_cert.pem ../crt

