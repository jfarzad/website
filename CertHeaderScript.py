import socket
import pyodbc
from datetime import datetime
import ssl
import OpenSSL
import grequests
import re

#Timestamp everytime we insert data
timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')


List = open("C:\\Users\\Farzad\\Desktop\\hosts.txt").read().splitlines()


rs = (grequests.get(url) for url in List)
requests = grequests.map(rs)


def get_certificate(host, port=443):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    der_cert = sock.getpeercert(True)
    sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)
    
#for loop for each URL in our List
for response in requests:
    #Our method to get a certificate from a domain
    
    #Regular expression method
    urlfix = re.compile(r"https?://(www\.)?")
    urlre = urlfix.sub('', response.url).strip().strip('/')
    
    #Convert each URL from the list to IP, however it has to be formatted to website.tld format and therefore we use our regular expression method.
    ip = socket.gethostbyname(urlre)


    #The publickey gets dumped from the certificate and we use a get_pubkey() method to get it.

    certificate = get_certificate(urlre)
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
    Pubkeyobj = x509.get_pubkey() 
    pubKeyString = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, Pubkeyobj)
    pubkey = b'\n'.join(pubKeyString.splitlines()[1:-1])
    
    #extensions are extra data from the certificate fingerprints, certificate basic constrains and more.
    extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
    extension_data = {e.get_short_name(): str(e) for e in extensions}
    
    #These are not readable object's when recieved so they have to be converted to a new str(string) object to be inserted or else it throws an error.
    subj = str(x509.get_subject().CN)
    subjCN = str(x509.get_subject().CN)
    subjAlt = extension_data[b'subjectAltName']
    serial = str(x509.get_serial_number())
    issuerCN = str(x509.get_issuer().CN)
    sign = str(x509.get_signature_algorithm())  
    
    #Gets the bit length - has to be converted to str object to be readable.
    keylength = str(Pubkeyobj.bits())
    
    #Formats the date from the certificate into year/month/day - Hour/minute/second
    certvalidfrom = datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    certvalidtill = datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
        
    
    #SQL Connection to our local Microsoft SQL server and I've added the driver that is compatible.
    #https://datatofish.com/how-to-connect-python-to-sql-server-using-pyodbc/
    con = pyodbc.connect('Driver={SQL Server Native Client 11.0};'
                      'Server=DESKTOP-THV2IDL;'
                      'Database=host;'
                      'Trusted_Connection=yes;')

    cursor = con.cursor()

    
    cursor.execute('INSERT INTO host.dbo.domains (ip, Host, HSTS, HPKP, XContentTypeOptions, XFrameOptions, ContentSecurityPolicy, XXssProtection, Server, Timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
    (ip, response.url, response.headers.get('Strict-Transport-Security'), response.headers.get('Public-Key-Pins'), response.headers.get('X-Content-Type-Options'), response.headers.get('X-Frame-Options'), response.headers.get('Content-Security-Policy'), response.headers.get('X-XSS-Protection'), response.headers.get('Server'), timestamp))
    
    
    cursor.execute('INSERT INTO host.dbo.certificate (host, ssubject, CommonName, AlternativeNames, PublicKey, SerialNumber, [KeyLength(BITS)], Validfrom, Validtill, [Issuer(CN)], CSA, Timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
    (response.url, subj, subjCN, subjAlt, pubkey, serial, keylength, certvalidfrom, certvalidtill, issuerCN, sign, timestamp))
    con.commit()


