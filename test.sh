#!/usr/bin/ksh

rm -rf /tmp/test-ca

echo creating new CA
./tlsauth.py /tmp/test-ca createca crl joe j@c 23 || exit 1

echo running blindgen
./tlsauth.py /tmp/test-ca blindgen $USER $USER@localhost >/tmp/test-blind || exit 1

echo running genkey
( ./tlsauth.py genkey | tee /tmp/test-key ) || exit 1

echo running gencsr
( ./tlsauth.py /tmp/test-ca gencsr $USER $USER@localhost </tmp/test-key | tee /tmp/test-csr ) || exit 1

echo running submit
./tlsauth.py /tmp/test-ca submit </tmp/test-csr || exit 1

echo running sign
( ./tlsauth.py /tmp/test-ca sign </tmp/test-csr | tee /tmp/test-cert ) || exit 1

echo running sign with mail
./tlsauth.py /tmp/test-ca mail sign </tmp/test-csr || exit 1

echo running pkcs12
( ./tlsauth.py /tmp/test-ca p12 /tmp/test-key </tmp/test-cert >/tmp/test-p12 ) || exit 1

echo running newcsr
( ./tlsauth.py /tmp/test-ca newcsr $USER $USER@localhost | ./tlsauth.py /tmp/test-ca sign ) || exit 1

echo submitting a few csrs
( ./tlsauth.py /tmp/test-ca newcsr $USER $USER@localhost | ./tlsauth.py /tmp/test-ca submit ) || exit 1
( ./tlsauth.py /tmp/test-ca newcsr $USER $USER@localhost | ./tlsauth.py /tmp/test-ca submit ) || exit 1
( ./tlsauth.py /tmp/test-ca newcsr $USER $USER@localhost | ./tlsauth.py /tmp/test-ca submit ) || exit 1
( ./tlsauth.py /tmp/test-ca newcsr $USER $USER@localhost | ./tlsauth.py /tmp/test-ca submit ) || exit 1

echo running batchsign with mail
( ./tlsauth.py /tmp/test-ca mail batchsign ) || exit 1

rm -rf /tmp/test-ca

