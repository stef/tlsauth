#!/usr/bin/env python

import shutil, os
from tlsauth import CertAuthority, mailsigned, genkeycsr, pkcs12

# DEMO code
# initialize your own CA by running
# createca.sh CA
if os.path.exists('test-ca'): shutil.rmtree('test-ca')
ca=CertAuthority.createca('test-ca', 'http://www.example.com/crl.pem', 'example CA', 'ca@example.com', valid=5)

# do not try this at home.
# warning: irresponsible blind trust in 3rd parties
# warning: will be ignored anyway.
ca.gencert('joe', 'joe@example.com', 'ACME Inc.')
print "dropped correct pkcs12 cert"

# even worse (and intentionally ugly)
#mail(ca.gencert('s', 's@ctrlc.hu', 'ctrlc'),
#     "Howdy.\n\n" \
#     "Your login certificate from %s is attached.\n\n" \
#     "You should import this into your browser, keep a safe\n" \
#     "copy and delete this mail and other copies containing it.\n\n" \
#     "Have fun and respect",
#     {'emailAddress': 's@ctrlc.hu', 'CN': 's', 'O': 'ctrlc'},
#     ca.dn,
#     ext='p12')

# this is the correct - but less automagic - procedure
sec, pub, csr = genkeycsr('joe', 'joe@example.com', 'ACME Inc.')

# send csr to CA,
ca.submit(csr)

# who the after diligent inspection either does
cert=ca.signcsr(csr)
print cert
# or bulk processes multiple incoming CSRs
certs=ca.signincoming()
#print certs
mailsigned(certs)

# or uses the supplied signcert.sh script. The CA sends the resulting cert

# ...back to the user who after calling
pkcs12(sec,cert,ca._pub)
print "dropped good pkcs12 cert"

# imports both the result and ca._pub.
# and stores sec, cert away in a # safe offline location.

if os.path.exists('test-ca'): shutil.rmtree('test-ca')
