
from config import excluded_names

import dns.zone
import dns.resolver
import ipaddress
import socket
import ssl
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID

from threading import Thread, Lock

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)



def netcat(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    # sock.setblocking()
    res = sock.connect_ex((host, port))
    sock.close()
    return res == 0

def resolve(hostname):
    try:
        answ = dns.resolver.resolve(hostname)
        return ( ii.address for ii in answ )
    except:
        return ()
    
def remove_bad_hosts(hosts_dict):
    '''
    remove hosts that not answer on tcp/443
    '''
    def check_item(shared_dict, lock, item):
        if netcat(item, 443):
            return
        with lock:
            del shared_dict[item]

    threads = []
    lock = Lock()    
    for ip in list(hosts_dict):
        thread = Thread(target=check_item, args=(hosts_dict, lock, ip))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

        
def check_excluded_names(name):
    if name[0] == '*':
        return False
    if name in excluded_names:
        return False
    return True

def dns_zone_xfer(domain, dns_server):
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(dns_server, domain))
    except Exception as e:
        print("[*] NS refused zone transfer!")

    hosts_dict = {}
    for name, ttl, rdata in zone.iterate_rdatas("A"):
        name = name.to_text()
        if not check_excluded_names(name):
            continue
        ip = rdata.to_text()
        if not ipaddress.ip_address(ip).is_private:
                continue
        if hosts_dict.get(ip):
            hosts_dict[ip].append(name)
        else:
            hosts_dict[ip] = [name]

    for name, ttl, rdata in zone.iterate_rdatas("CNAME"):
        name = name.to_text()
        if not check_excluded_names(name):
            continue
        cname = rdata.to_text()
        cname = cname + '.' + domain if cname[-1] != '.' else cname[:-1]
        
        for address in resolve(cname):
            if not ipaddress.ip_address(address).is_private:
                continue

            if hosts_dict.get(address):
                hosts_dict[address].append(name)
            else:
                hosts_dict[address] = [name]
    return hosts_dict

def check_valid_hostname(cert: x509.Certificate, hostname_f):
    def check_name(hostname_f, cert_name):
        if cert_name[0] == '*': # wildcard cert
            return True if cert_name[1:] in hostname_f else False
        else:
            return True if cert_name == hostname_f else False

    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    if check_name(hostname_f, cn):
        return True
    
    for subj_alt_name in cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value:
        if check_name(hostname_f, subj_alt_name.value):
            return True
    
    return False


def get_certs(domain_name, dns_server):
    def check_add_cert(hostname, shared_certs, lock):
        try:
            hostname_f = hostname + '.' + domain_name
            cert = ssl.get_server_certificate((hostname_f, 443))
            c = x509.load_pem_x509_certificate(cert.encode())
            cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
            if domain_name not in cn: # not checked domain
                return
            if c.subject == c.issuer: # selfsigned cert
                return
            
            if not check_valid_hostname(c, hostname_f): # check valid hostname
                return
            
            if shared_certs.get(cert):
                with lock:
                    shared_certs[cert].append(hostname_f)
            else:
                with lock:
                    shared_certs[cert] = [hostname_f]
        # cert_dict = ssl._ssl._test_decode_cert()
        except Exception as e:
            pass



    hosts_dict = dns_zone_xfer(domain_name, dns_server)
    remove_bad_hosts(hosts_dict)
    
    hostnames = []
    for ip in hosts_dict:
        hostnames += hosts_dict[ip]
    hostnames = list(set(hostnames))

    certs = {}
    threads = []
    lock = Lock()
    for hostname in hostnames:
        thread = Thread(target=check_add_cert, args=(hostname, certs, lock))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    return certs 
