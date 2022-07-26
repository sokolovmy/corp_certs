#!/usr/local/bin/python

import json

from config import __version__, __author__
from net import get_certs
from db import CacheDB

import sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from datetime import datetime, timezone


def usage():
    print(f'''
Check SSL certificates expiration. version {__version__}
© {__author__}

Usage: {sys.argv[0]} command [arguments]

    listcerts <domain_name> <dns_server>
    cert <id>

''')

def cmd_listcerts(domain_name, dns_server):
    cur_date = datetime.now(tz=timezone.utc)
    certs = get_certs(domain_name, dns_server)
    cacheDB = CacheDB()
    cacheDB.flushCertsTable()
    for_out = []
    for cert in certs:
        hosts = ', '.join(certs[cert])
        c = x509.load_pem_x509_certificate(cert.encode())
        sn = str(c.serial_number)
        id = cacheDB.addCert(cert, hosts)
        exp_date = c.not_valid_after.replace(tzinfo=timezone.utc)
        cert_obj = {
            '{#ID}': id,
            '{#SERIAL}': sn,
            '{#EXPDAYS}': (exp_date - cur_date).days,
            '{#COMMON_NAME}': c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
            '{#SUBJECT}': str(c.subject),
            '{#ISSUER}': str(c.issuer),
            '{#EXPDATE}': exp_date.strftime('%Y-%m-%d %H:%M:%S %Z'),
            '{#SUBJECTALTNAME}': str(c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)),
            '{#HOSTS}': hosts
        }
        for_out.append(cert_obj)
    
    cacheDB.commit()
    print(json.dumps(for_out, indent=2))

def cmd_cert(id):
    cacheDB = CacheDB()
    cert_row = cacheDB.getCertById(id)
    c = x509.load_pem_x509_certificate(cert_row[0].encode())
    cur_date = datetime.now(tz=timezone.utc)
    exp_date = c.not_valid_after.replace(tzinfo=timezone.utc)
    c_obj = {
        'ExpDate': exp_date.strftime('%Y-%m-%d %H:%M:%S %Z'),
        'ExpDays': (exp_date - cur_date).days,
        'ComName': c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        'Serial': str(c.serial_number),
        'Subject': str(c.subject),
        'Issuer': str(c.issuer),
        'SubjectAltName': str(c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)),
        'Hosts': cert_row[1]
    }
    print(json.dumps(c_obj, indent=2))
    pass

def opts():
    if len(sys.argv) == 4 and sys.argv[1] == 'listcerts':
        cmd_listcerts(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == 'cert':
        cmd_cert(sys.argv[2])
    else:
        usage()

if __name__ == "__main__":
    # cmd_listcerts('haulmont.com', '10.5.0.3')
    # cmd_cert('a12fd4f886b4ac0934daa87dd9db834d')
    opts()
    