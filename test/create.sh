# https://jamielinux.com/docs/openssl-certificate-authority/introduction.html

set -ex

rm -rf tmp

mkdir tmp
mkdir tmp/certs tmp/crl tmp/newcerts tmp/private
touch tmp/index.txt
echo 1000 > tmp/serial

# Create a new CA
openssl genrsa -out tmp/schannel-ca.key 4096
openssl req -config openssl.cnf \
  -new -x509 -days 3650 \
  -key tmp/schannel-ca.key \
  -out tmp/schannel-ca.crt \
  -extensions v3_ca \
  -subj "/C=US/ST=California/L=/O=schannel-rs/CN=schannel-rs root CA"
openssl x509 -noout -text -in tmp/schannel-ca.crt

# Create a new key and certificate signing request for localhost
openssl req -config openssl.cnf \
  -nodes -newkey rsa:2048 \
  -keyout tmp/localhost.key \
  -out tmp/localhost.csr \
  -subj "/C=US/ST=California/L=/O=schannel-rs/CN=localhost"

# Sign this CSR with the CA we created from before
openssl ca -config openssl.cnf \
  -extensions server_cert \
  -days 6000 -notext -md sha256 \
  -in tmp/localhost.csr \
  -out tmp/localhost.crt \
  -batch

# Copy out everything we'll need
cp tmp/schannel-ca.crt .
cp tmp/localhost.key .
cp tmp/localhost.crt .

# Blow away our temporary state, including the CA key
rm -rf tmp

# Export to der format
openssl x509 -outform der -in localhost.crt -out localhost.der
openssl x509 -outform der -in schannel-ca.crt -out schannel-ca.der

# Export to pkcs12 format
openssl pkcs12 -export -nodes \
    -out localhost.p12 \
    -inkey localhost.key \
    -in localhost.crt \
    -password pass:foobar
