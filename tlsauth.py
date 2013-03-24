#!/usr/bin/env python

import M2Crypto as m2
import OpenSSL as ssl
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
import os, smtplib, datetime, hashlib, jinja2
BASEPATH = os.path.dirname(os.path.abspath(__file__))

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1

def gencert(name, mail, org, ca):
    """ automagically creates a PKCS12 cert in a totally untrusted but
        convenient way if you want to do this the correct way, then
        read certs-done-r8.org
    """
    sec,pub=genkey()
    csr=gencsr(sec, name, mail, org)
    cert=ca.signcsr(csr)
    return pkc12(sec,cert,ca)

def genkeycsr(name, mail, org):
    """ creates a 4K RSA key and a related CSR based on the parameters
    """
    sec,pub=genkey()
    csr=gencsr(sec, name, mail, org)
    return (sec,pub,csr)

def genkey (klen=4096, pext=0x10001 ):
    """ generates a 4K RSA key in PEM format
    """
    keypair = m2.RSA.gen_key( klen, pext)

    pkey = m2.EVP.PKey ( md='sha512')
    pkey.assign_rsa ( keypair )
    return (keypair.as_pem(cipher=None),
            m2.RSA.new_pub_key(keypair.pub()).as_pem(cipher=None))

def gencsr(key, name, email, org):
    """ generates a CSR using the supplied parameters
    """
    key=loadkey(key)

    # create csr
    csr = m2.X509.Request()
    dn = m2.X509.X509_Name()
    dn.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry=org, len=-1, loc=-1, set=0 )
    dn.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=name, len=-1, loc=-1, set=0 )
    dn.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry=email, len=-1, loc=-1, set=0 )
    csr.set_subject_name(dn)
    csr.set_pubkey(pkey=key )
    csr.sign(pkey=key, md='sha512' )
    return csr.as_pem()

def pkc12(key, cert, ca, pwd="asdf"):
    """ creates a PKCS12 certificate for browsers based on the supplied parameters
    """
    p12 = ssl.crypto.PKCS12()
    p12.set_privatekey(ssl.crypto.load_privatekey(ssl.SSL.FILETYPE_PEM, key))
    p12.set_certificate(ssl.crypto.load_certificate(ssl.SSL.FILETYPE_PEM, cert))
    p12.set_ca_certificates((ssl.crypto.load_certificate(ssl.SSL.FILETYPE_PEM, ca._pub),))
    return p12.export(pwd)

def mailsigned(signed):
    """ mails the signed certs to their listed emailAddress from
        the emailAddress of the CA
    """
    txt="Howdy.\n\n" \
         "Your login certificate from %s is attached\n" \
         "You should apply cert2pkcs12.sh from tlsauth to it,\n" \
         "and then import the result into your browser.\n\n" \
         "Have fun and respect"
    for crt in signed:
        bio = m2.BIO.MemoryBuffer(crt)
        cert = m2.X509.load_cert_bio(bio)
        dn = todn(cert.get_subject())
        idn = todn(cert.get_issuer())
        mail(cert.as_pem(), txt, dn, idn)
    return signed

def mail(data, txt, to, ca, ext='pem'):
    """ mails the cert in attach with a text message
    """
    outer = MIMEMultipart()
    outer['Subject'] = 'Your login certificate for %s' % ca['O']
    outer['To'] = to['emailAddress']
    outer['From'] = ca['emailAddress']

    msg = MIMEBase('text', 'plain')
    msg.set_payload(txt % ca['O'])
    outer.attach(msg)

    att = MIMEBase('application', 'x-x509-user-cert')
    att.set_payload(data)
    att.add_header('Content-Disposition', 'attachment', filename='%s-cert.%s' % (to['CN'], ext))
    outer.attach(att)

    composed = outer.as_string()
    s = smtplib.SMTP('localhost')
    s.sendmail(ca['emailAddress'], to['emailAddress'], composed)

def todn(obj):
    """ converts the DN to a dictionary
    """
    dn = str(obj)
    return dict([(ass.split('=')[0], '='.join(ass.split('=')[1:])) for ass in dn.split('/') if ass])

def loadkey(txt):
    """ loads an RSA key from a PEM string
    """
    bio = m2.BIO.MemoryBuffer(txt)
    keypair = m2.RSA.load_key_bio(bio)
    key = m2.EVP.PKey(md='sha512')
    key.assign_rsa(keypair)
    return key

def load(path):
    """ loads a file from disk to memory
    """
    fd=open(path,'r')
    res=fd.read()
    fd.close()
    return res

class CertAuthority(object):
    """represents a CA
    """
    def __init__(self, pub, sec, serial, dummy, crl, incoming):
        """Initializes the CA

        Arguments:
        - `pub`: path to cert of CA
        - `sec`: path to private key of CA
        - `serial`: path to file containing serial number
        - `dummy`: path for source of authorityKeyIdentifier
        - `crl`: url to the CRL
        - `incoming`: path to files containing CSRs to be signed
        """
        self._pub = load(pub)
        self._sec = load(sec)
        self._serial = int(load(serial))
        self._serialfname = serial
        self._dummy = load(dummy)
        self._crl = crl
        self._incoming = incoming
        # calculate dn
        bio = m2.BIO.MemoryBuffer(self._pub)
        tmp = m2.X509.load_cert_bio(bio)
        self.dn = todn(tmp.get_issuer())

    def serial(self):
        """ increments persistently and returns the serial counter
        """
        self._serial+=1
        # TODO implement locking!!!
        with open(self._serialfname,'w') as fd:
            fd.write("%02d" % self._serial)
        return self._serial

    def signcsr(self, csr, valid=1):
        """ returns a PEM that contains a signed CSR with a validity
            specified in years
        """
        casec=loadkey(self._sec)
        if type(csr) in [str, unicode]:
            bio = m2.BIO.MemoryBuffer(csr)
            csr = m2.X509.load_request_bio(bio)
        cert = m2.X509.X509()
        cert.set_version(2)
        # time notBefore
        ASN1 = m2.ASN1.ASN1_UTCTIME()
        ASN1.set_datetime(datetime.datetime.now())
        cert.set_not_before( ASN1 )
        # time notAfter
        ASN1 = m2.ASN1.ASN1_UTCTIME()
        ASN1.set_datetime(datetime.datetime.now()+datetime.timedelta(days=int(365*valid)))
        cert.set_not_after(ASN1)
        # public key
        cert.set_pubkey(pkey=csr.get_pubkey())
        # subject
        cert.set_subject_name( csr.get_subject ())
        # issuer
        dn = m2.X509.X509_Name ( m2.m2.x509_name_new () )
        # careful ordering these around, must be the same order as the issuing CA DN!!!
        dn.add_entry_by_txt(field='C', type=MBSTRING_ASC, entry=self.dn['C'], len=-1, loc=-1, set=0)
        dn.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry=self.dn['O'], len=-1, loc=-1, set=0)
        dn.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=self.dn['CN'], len=-1, loc=-1, set=0)
        dn.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry=self.dn['emailAddress'], len=-1, loc=-1, set=0)
        cert.set_issuer_name( dn )

        # Set the X509 extenstions
        #cert.add_ext(m2.X509.new_extension('nsCertType', 'client'))
        #cert.add_ext(m2.X509.new_extension('extendedKeyUsage', 'clientAuth',
        #                                critical=1))
        #cert.add_ext(m2.X509.new_extension('keyUsage', 'digitalSignature',
        #                                critical=1))
        cert.add_ext(m2.X509.new_extension('basicConstraints', 'CA:FALSE'))

        # Create the subject key identifier
        modulus = cert.get_pubkey().get_modulus()
        sha_hash = hashlib.sha1(modulus).digest()
        sub_key_id = ":".join(["%02X"%ord(byte) for byte in sha_hash])
        cert.add_ext(m2.X509.new_extension('subjectKeyIdentifier', sub_key_id))

        # Authority Identifier
        bio = m2.BIO.MemoryBuffer(self._dummy)
        dummy = m2.X509.load_cert_bio(bio)
        cert.add_ext(dummy.get_ext('authorityKeyIdentifier'))

        cert.add_ext(m2.X509.new_extension('nsCaRevocationUrl', self._crl))

        # load serial number
        cert.set_serial_number(self.serial())

        # signing
        cert.sign( pkey=casec, md='sha512' )
        #print cert.as_text()
        return cert.as_pem()

    def submit(self,csr):
        """ stores an incoming CSR for later certification
        """
        bio = m2.BIO.MemoryBuffer(csr)
        csr = m2.X509.load_request_bio(bio)
        modulus = csr.get_pubkey().get_modulus()
        hashsum = hashlib.sha1(modulus).hexdigest()
        with open(self._incoming+'/'+hashsum,'a') as fd:
            fd.write(csr.as_pem())

    def incoming(self):
        """ returns a list of req objects to be certified
        """
        res=[]
        for fname in sorted(os.listdir(self._incoming)):
            if fname.endswith('.invalid'):
                continue
            bio = m2.BIO.MemoryBuffer(load(self._incoming+'/'+fname))
            try:
                csr = m2.X509.load_request_bio(bio)
            except:
                print self._incoming+'/'+fname, "is fishy, skipping"
                continue
            res.append((csr,self._incoming+'/'+fname))
        return res

    def signincoming(self, scrutinizer=None):
        """ signs all incoming CSRs before doing so it consults the
            optional scrutinizer for approval.
        """
        signed=[]
        for csr,path in ca.incoming():
            if not scrutinizer or scrutinizer(csr):
                cert=ca.signcsr(csr)
                print "signed", csr.get_subject()
                if cert:
                    os.unlink(path)
                    signed.append(cert)
            else:
                os.rename(path, path+'.invalid')
        return signed

"""
# DEMO code
# initialize your own CA by running
# ./createca.sh CA
ca=CertAuthority('CA/public/root.pem',
                 'CA/private/root.pem',
                 'CA/conf/serial',
                 'CA/dummy.pem',
                 'http://www.example.com/ctrlCA.crl',
                 'CA/incoming',
                 )

# do not try this at home.
# warning: irresponsible blind trust in 3rd parties
# warning: will be ignored anyway.
# gencert('joe', 'joe@example.com', 'ACME Inc.', ca)
# even worse (and intentionally ugly)
mail(gencert('s', 's@ctrlc.hu', 'ctrlc', ca),
     "Howdy.\n\n" \
     "Your login certificate from %s is attached.\n\n" \
     "You should import this into your browser, keep a safe\n" \
     "copy and delete this mail and other copies containing it.\n\n" \
     "Have fun and respect",
     {'emailAddress': 's@ctrlc.hu', 'CN': 's', 'O': 'ctrlc'},
     ca.dn,
     ext='p12')

# this is the correct - but less automagic - procedure
#sec, pub, csr = genkeycsr('joe', 'joe@example.com', 'ACME Inc.')
sec, pub, csr = genkeycsr('stef', 's@ctrlc.hu', 'ctrlc')

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
pkc12(sec,cert,ca)

# imports both the result and ca._pub.
# and stores sec, cert away in a # safe offline location.
"""
