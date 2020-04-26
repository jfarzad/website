import socket
import ssl
import grequests
import re

weakCounter = 0
knownCounter = 0
modernCounter = 0


WeakCipher = 'NULL-MD5'

KnownCipher = 'DHE-RSA-AES256-GCM-SHA384'

ModernCipher = 'ECDHE-RSA-AES256-SHA384'

#Read from txt file and convert it into a List.
List = open("C:\\Users\\Farzad\\Desktop\\hosts.txt").read().splitlines()

#async method to do more than 1 URL at a time
rs = (grequests.get(url) for url in List)
requests = grequests.map(rs)


for response in requests:
    urlfix = re.compile(r"https?://(www\.)?")
    urlre = urlfix.sub('', response.url).strip().strip('/')

    context = ssl.create_default_context()
    context.set_ciphers(WeakCipher)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print("ERROR:", response.url, "DOES NOT SUPPORT YOUR WEAK CIPHER")
    else:
        weakCounter +=1
        print(response.url,"CONNECTION ESTABLISHED WITH YOUR WEAK CIPHER")

    
    context = ssl.create_default_context()
    context.set_ciphers(KnownCipher)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print("ERROR:", response.url, "DOES NOT SUPPORT YOUR MODERN CIPHER")
    else:
        knownCounter +=1
        print(response.url,"CONNECTION ESTABLISHED WITH YOUR KNOWN CIPHER" )

    
    context = ssl.create_default_context()
    context.set_ciphers(ModernCipher)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print("ERROR:", response.url, "DOES NOT SUPPORT YOUR MODERN CIPHER" '\n')
    else:
        modernCounter +=1 
        print(response.url,"CONNECTION ESTABLISHED WITH YOUR MODERN CIPHER" '\n')


print("Number of websites that supports your weakcipher is =", weakCounter)
print("Number of websites that supports your knowncipher is =", knownCounter)
print("Number of websites that supports your moderncipher is =", modernCounter)