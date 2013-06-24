import os
from setuptools import setup

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name = "tlsauth",
    version = "0.3.1-5",
    author = "Stefan Marsiske",
    author_email = "s@ctrlc.hu",
    license = "BSD",
    keywords = "crypto authentication TLS certificate x509 CA",
    py_modules=['tlsauth'],
    install_requires = ['M2Crypto', 'pyOpenSSL', 'pyasn1', 'pyspkac'],
    scripts=['bin/cert2pkcs12.sh', 'bin/createca.sh', 'bin/gencert.sh', 'bin/servercert.sh','bin/signcert.sh'],
    url = "https://pypi.python.org/pypi/tlsauth",
    description = "Implements TLS Authentication - simple client certificate CA inclusive",
    long_description=read('README.org'),
    classifiers = ["Development Status :: 4 - Beta",
                   "License :: OSI Approved :: BSD License",
                   "Topic :: Security :: Cryptography",
                   "Environment :: Web Environment",
                 ],
)
