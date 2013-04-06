#!/usr/bin/env python

import M2Crypto as m2
import OpenSSL as ssl
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from pyspkac import SPKAC
import os, smtplib, datetime, hashlib, sys, getpass

MBSTRING_FLAG = 0x1000
MBSTRING_ASC  = MBSTRING_FLAG | 1

# for more objectIds see: https://tools.ietf.org/html/rfc3279#section-2.2.1
# https://tools.ietf.org/html/rfc4055#section-2.1

def genkeycsr(name, mail, org=None, klen=4096, pext=0x10001):
    """ creates a 4K RSA key and a related CSR based on the parameters
    """
    sec,pub=genkey(klen, pext)
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

def gencsr(key, name=None, email=None, org=None):
    """ generates a CSR using the supplied parameters
    """
    key=loadkey(key)

    # create csr
    csr = m2.X509.Request()
    dn = m2.X509.X509_Name()
    if org: dn.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry=org, len=-1, loc=-1, set=0 )
    if name: dn.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=name, len=-1, loc=-1, set=0 )
    if email: dn.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry=email, len=-1, loc=-1, set=0 )
    csr.set_subject_name(dn)
    csr.set_pubkey(pkey=key )
    csr.sign(pkey=key, md='sha512' )
    return csr.as_pem()

def pkcs12(key, cert, root_cert):
    """ creates a PKCS12 certificate for browsers based on the supplied parameters
    """
    p12 = ssl.crypto.PKCS12()
    p12.set_privatekey(ssl.crypto.load_privatekey(ssl.SSL.FILETYPE_PEM, key))
    p12.set_certificate(ssl.crypto.load_certificate(ssl.SSL.FILETYPE_PEM, cert))
    p12.set_ca_certificates((ssl.crypto.load_certificate(ssl.SSL.FILETYPE_PEM, root_cert),))
    return p12.export(getpass.getpass("Password for importing this key: "))

def spkac2pem(pk):
    csr = m2.X509.Request()
    csr.set_subject_name(pk.subject)
    csr.set_pubkey(pk.pkey )
    return csr.as_pem()

def spkac2cert(pk, email, name=None):
    pk=SPKAC(pk)
    csr = m2.X509.Request()
    csr.set_subject_name(pk.subject)
    csr.set_pubkey(pk.pkey )
    dn=csr.get_subject()
    print dn, len(dn), type(dn)
    if len(dn)==0:
        dn = m2.X509.X509_Name()
        if name: dn.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=name, len=-1, loc=-1, set=0 )
        dn.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry=email, len=-1, loc=-1, set=0 )
        csr.set_subject_name(dn)
    return csr.as_pem()

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
    outer['Subject'] = 'Your login certificate for %s' % ca.get('O', ca['CN'])
    outer['To'] = to['emailAddress']
    outer['From'] = ca['emailAddress']

    msg = MIMEBase('text', 'plain')
    msg.set_payload(txt % ca.get('O',ca['CN']))
    outer.attach(msg)

    att = MIMEBase('application', 'x-x509-user-cert')
    att.set_payload(data)
    att.add_header('Content-Disposition', 'attachment', filename='%s-cert.%s' % (to.get('CN',to['emailAddress']), ext))
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
    #def __init__(self, pub, sec, serial, crl, incoming):
    def __init__(self, path):
        """Initializes the CA
        """
        self.path=path
        with open(path+'/ca.cfg','r') as fd:
            cfg=dict([[x.strip() for x in line.split('=')] for line in fd.readlines()])

        self._pub = load(path+'/'+cfg['pub'] if cfg['pub'][0]!='/' else cfg['pub'])
        self._sec = load(path+'/'+cfg['sec'] if cfg['sec'][0]!='/' else cfg['sec'])
        self._serial = int(load(path+'/'+cfg['serial'] if cfg['serial'][0]!='/' else cfg['serial']))
        self._serialfname = path+'/'+cfg['serial' if cfg['serial'][0]!='/' else cfg['serial']]
        self._crl = cfg['crl']
        self._incoming = path+'/'+cfg['incoming' if cfg['incoming'][0]!='/' else cfg['incoming']]
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

    def gencert(self, name, mail, org=None, klen=4096, pext=0x10001):
        """ automagically creates a PKCS12 cert in a totally untrusted but
            convenient way if you want to do this the correct way, then
            use genkeycsr and a manual procedure.
        """
        sec,pub=genkey(klen, pext)
        csr=gencsr(sec, name, mail, org)
        cert=self.signcsr(csr)
        return pkcs12(sec,cert,self._pub)

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
        if self.dn.get('C'): dn.add_entry_by_txt(field='C', type=MBSTRING_ASC, entry=self.dn['C'], len=-1, loc=-1, set=0)
        if self.dn.get('O'): dn.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry=self.dn['O'], len=-1, loc=-1, set=0)
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
        bio = m2.BIO.MemoryBuffer(self._pub)
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
        for csr,path in self.incoming():
            if not scrutinizer or scrutinizer(csr):
                cert=self.signcsr(csr)
                print "signed", csr.get_subject()
                if cert:
                    os.unlink(path)
                    signed.append(cert)
            else:
                os.rename(path, path+'.invalid')
        return signed

    @classmethod
    def createca(self, path, crl, name, mail, org=None, valid=5):
        """ creates and initializes a new CA on the filesystem
        """
        if not os.path.exists(path):
            os.mkdir(path)
        for d in ['conf','certs','public','private','incoming']:
            os.mkdir(path+'/'+d)
        os.chmod(path+"/private", 0700)
        # initialize serial
        with open(path+'/conf/serial','w') as fd:
            fd.write("01")

        sec, pub = genkey()
        with open(path+'/private/root.pem','w') as fd:
            fd.write(sec)

        sec = loadkey(sec)

        # create csr
        cert = m2.X509.X509()
        cert.set_version(2)
        cert.set_pubkey(pkey=sec )

        dn = m2.X509.X509_Name()
        if org: dn.add_entry_by_txt(field='O', type=MBSTRING_ASC, entry=org, len=-1, loc=-1, set=0 )
        dn.add_entry_by_txt(field='CN', type=MBSTRING_ASC, entry=name, len=-1, loc=-1, set=0 )
        dn.add_entry_by_txt(field='emailAddress', type=MBSTRING_ASC, entry=mail, len=-1, loc=-1, set=0 )
        cert.set_subject_name(dn)
        cert.set_issuer_name(dn)

        # serial 8 byte random
        serial = int(ssl.rand.bytes(8).encode('hex'),16)
        cert.set_serial_number(serial)

        # time notBefore - from original PGP key
        ASN1 = m2.ASN1.ASN1_UTCTIME()
        now=datetime.datetime.now()
        ASN1.set_datetime(now)
        cert.set_not_before( ASN1 )
        # time notAfter - from original PGP key
        ASN1 = m2.ASN1.ASN1_UTCTIME()
        ASN1.set_datetime(now+datetime.timedelta(days=int(365*valid)))
        cert.set_not_after(ASN1)

        # Set the X509 extenstions
        cert.add_ext(m2.X509.new_extension('basicConstraints', 'CA:TRUE'))

        # Create the subject key identifier
        modulus_str = cert.get_pubkey().get_modulus()
        sha_hash = hashlib.sha1(modulus_str).digest()
        sub_key_id = ":".join(["%02X"%ord(byte) for byte in sha_hash])
        cert.add_ext(new_extension('subjectKeyIdentifier', sub_key_id))

        # Authority Identifier
        authid='keyid,issuer:always'
        cert.add_ext(new_extension('authorityKeyIdentifier', authid, issuer=cert))

        cert.add_ext(m2.X509.new_extension('nsCaRevocationUrl', crl))

        cert.sign( pkey=sec, md='sha512' )

        with open(path+'/public/root.pem','w') as fd:
            fd.write(cert.as_pem())

        # dump initial config
        with open(path+'/ca.cfg','w') as fd:
            fd.write("crl=%s\nsec=%s\npub=%s\nserial=%s\nincoming=%s" % (
                crl,
                os.path.abspath(path+"/private/root.pem"),
                os.path.abspath(path+"/public/root.pem"),
                os.path.abspath(path+"/conf/serial"),
                os.path.abspath(path+"/incoming")))

        return CertAuthority(path)

# workaround for keyauthority coredump from
# https://bugzilla.osafoundation.org/show_bug.cgi?id=7530
import ctypes
class Ctx(ctypes.Structure):
    _fields_ = [ ('flags', ctypes.c_int),
                 ('issuer_cert', ctypes.c_void_p),
                 ('subject_cert', ctypes.c_void_p),
                 ('subject_req', ctypes.c_void_p),
                 ('crl', ctypes.c_void_p),
                 ('db_meth', ctypes.c_void_p),
                 ('db', ctypes.c_void_p),
                ]

def fix_ctx(m2_ctx, issuer = None):
    ctx = Ctx.from_address(int(m2_ctx))

    ctx.flags = 0
    ctx.subject_cert = None
    ctx.subject_req = None
    ctx.crl = None
    if issuer is None:
        ctx.issuer_cert = None
    else:
        ctx.issuer_cert = int(issuer.x509)

def new_extension(name, value, critical=0, issuer=None, _pyfree = 1):
    """
    Create new X509_Extension instance.
    """
    if name == 'subjectKeyIdentifier' and \
        value.strip('0123456789abcdefABCDEF:') is not '':
        raise ValueError('value must be precomputed hash')


    lhash = m2.m2.x509v3_lhash()
    ctx = m2.m2.x509v3_set_conf_lhash(lhash)
    #ctx not zeroed
    fix_ctx(ctx, issuer)

    x509_ext_ptr = m2.m2.x509v3_ext_conf(lhash, ctx, name, value)
    #ctx,lhash freed

    if x509_ext_ptr is None:
        raise Exception
    x509_ext = m2.X509.X509_Extension(x509_ext_ptr, _pyfree)
    x509_ext.set_critical(critical)
    return x509_ext

def run():
    if 'help' in sys.argv[1:]:
        print """tlsauth parameters
User operations
    genkey                                     generates a new RSA keypair
    gencsr name email [organization]           generates a CSR, expects a secret key on stdin
    newcsr name email [organization]           generates a new RSA keypair and a CSR
    p12 privatekey                             combines a signed CSR and a private key into a PKCS12 cert
CA operations (path must point to dir containing ca.cfg)
    path createca crl name mail [org] [valid]  creates a new CA
    path blindgen name email [organization]    blindly generates a PKCS12 certificate,
    path submit                                reads a CSR from stdin and stores it in the CA incoming queue
    path sign                                  reads a CSR from stdin and signs it with the CA root key
    path batchsign                             signs all certs in the incoming queue
options (combine with the above)
    mail                                       mail results to cert subjects"""
        return

    if 'genkey' in sys.argv[1:]:
        sec,pub=genkey()
        print "Secret key"
        print sec
        print "Public key"
        print pub
        print "store these away, especially the secret key"
        return

    path=sys.argv[1]
    if 'createca' in sys.argv[2:]:
        start=sys.argv.index('createca')+1
        fields=sys.argv[start:start+6]
        crl=fields[0]
        name=fields[1]
        mail=fields[2]
        org=None
        valid=5
        if len(fields)==4:
            try: valid=int(fields[3].strip())
            except: org=fields[3]
        elif len(fields)==5:
            org=fields[3]
            valid=int(fields[4])
        return CertAuthority.createca(path,crl, name,mail, org, valid)

    ca=CertAuthority(path)

    if 'blindgen' in sys.argv[1:]:
        start=sys.argv[1:].index('blindgen')+1
        fields=sys.argv[start:start+3]
        org=fields[2] if len(fields)>2 else None

        cert=ca.gencert(fields[0], fields[1], org)
        if 'mail' in sys.argv[1:]:
            mail(cert,
                 "Howdy.\n\n" \
                 "Your login certificate from %s is attached.\n\n" \
                 "You should import this into your browser, keep a safe\n" \
                 "copy and delete this mail and other copies containing it.\n\n" \
                 "Have fun and respect",
                 {'emailAddress': fields[1], 'CN': fields[0], 'O': org},
                 ca.dn,
                 ext='p12')
        else:
            print cert
        return

    if 'gencsr' in sys.argv[1:]:
        # expects a secret key on stdin
        start=sys.argv[1:].index('gencsr')+1
        fields=sys.argv[start:start+3]
        org=fields[2] if len(fields)>2 else None

        csr=gencsr(sys.stdin.read(), fields[0], fields[1], org)
        if 'mail' in sys.argv[1:]:
            mail(csr,
                 "Howdy.\n\nI would like you to sign my attached CSR.\n\nthx %s" % fields[0],
                 ca.dn,
                 {'emailAddress': fields[1], 'CN': fields[0], 'O': org},
                 )
        else:
            print csr
        return

    if 'newcsr' in sys.argv:
        start=sys.argv.index('newcsr')+1
        fields=sys.argv[start:start+3]
        org=fields[2] if len(fields)>2 else None
        sec, pub, csr = genkeycsr(fields[0],fields[1],org)
        print "Secret key"
        print sec
        if 'mail' in sys.argv[1:]:
            mail(pub,
                 "Howdy.\n\nAttached is your key.\n\ncheers",
                 {'emailAddress': fields[1], 'CN': fields[0], 'O': org},
                 ca.dn,
                 )
            mail(csr,
                 "Howdy.\n\nI would like you to sign my attached CSR.\n\nthx %s" % fields[0],
                 ca.dn,
                 {'emailAddress': fields[1], 'CN': fields[0], 'O': org},
                 )
        else:
            print "Public key"
            print pub
            print "CSR"
            print csr
        print "store these away, especially the secret key"
        return

    if 'submit' in sys.argv[1:]:
        # expects a csr
        ca.submit(sys.stdin.read())
        return

    # who the after diligent inspection either does
    if 'sign' in sys.argv[1:]:
        # expects a csr
        cert=ca.signcsr(sys.stdin.read())
        if 'mail' in sys.argv[1:]:
            mailsigned([cert])
        else:
            print cert
        return

    # or bulk processes multiple incoming CSRs
    if 'batchsign' in sys.argv[1:]:
        certs=ca.signincoming()
        if 'mail' in sys.argv[1:]:
            mailsigned(certs)
        else:
            print certs
        return

    if 'p12' in sys.argv[1:]:
        # expects a path after 'p12' pointing to the secret key
        # reads the cert from stdin
        sec=load(sys.argv[1:][sys.argv[1:].index('p12')+1])
        cert=sys.stdin.read()
        print pkcs12(sec,cert, ca._pub)
        return

if __name__ == "__main__":
    run()
