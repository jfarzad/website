import socket
import ssl
import grequests
import re

tlscounter1 = 0
tlscounter2 = 0
tlscounter3 = 0

#Read from txt file and convert it into a List.
List = open("C:\\Users\\Farzad\\Desktop\\hosts.txt").read().splitlines()

#async method to do more than 1 URL at a time
rs = (grequests.get(url) for url in List)
requests = grequests.map(rs)


for response in requests:
    urlfix = re.compile(r"https?://(www\.)?")
    urlre = urlfix.sub('', response.url).strip().strip('/')
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print(response.url,"ERROR: WEBSITE DOES NOT SUPPORT PROTOCOL 1.0")
    else:
        tlscounter1 +=1
        print(response.url,"CONNECTION ESTABLISHED WITH TLS PROTOCOL 1.0")

#Hvis forbindelsen ikke er tilladt via TLS protocollen, printer vi en error.
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print(response.url,"ERROR: WEBSITE DOES NOT SUPPORT PROTOCOL 1.1")
    else:
        tlscounter2 +=1
        print(response.url,"CONNECTION ESTABLISHED WITH TLS PROTOCOL 1.1")
#Hvis forbindelsen ikke er tilladt via TLS protocollen, printer vi en error.
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ssl_sock = context.wrap_socket(s, server_hostname=urlre)
    try:
        ssl_sock.connect((urlre, 443))
    except Exception as e:
        print(response.url,"ERROR: WEBSITE DOES NOT SUPPORT PROTOCOL 1.2" '\n')
    else:
        tlscounter3 +=1
        print(response.url,"CONNECTION ESTABLISHED WITH TLS PROTOCOL 1.2" '\n')
        
print("Number of websites that supports your TLS Protocol 1.0 Connection =", tlscounter1)
print("Number of websites that supports your TLS Protocol 1.1 Connection =", tlscounter2)
print("Number of websites that supports your TLS Protocol 1.2 Connection =", tlscounter3)