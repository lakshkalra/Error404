import ssl
import socket
import hashlib


#checking connection protocol
def protocol(url):
    
    if url[0:5] == "https":
        #score += 1
        return 1
    else:
        return 0
#checking possition of "//"
def slash(url):
    
    if url[6:8] == "//":
        #score += 1
        return 1 
    else:
        return 0
#checking usage of "@"
def at(url):
    
    if url.find != "@":
        #score  += 1
        return 1

    else:
        return 0

#checking usage of cyrillic letters
def spell(url,url1):

    if url == url1:
        return 1
    else:
        return 0

#fetching expiry date and serial number
def valid(url):
    try:
        from urllib.request import Request, urlopen, ssl, socket
        from urllib.error import URLError, HTTPError
        import json
        # some site without http/https in the path
        host = (url.split("https://"))[1].split("/")[0]
        port = '443'
        #print("host =" + host)

        hostname = host
        context = ssl.create_default_context()

        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                #print(ssock.version())
                data = json.dumps(ssock.getpeercert())
                # print(ssock.getpeercert())

        s_no = (data.split('"serialNumber": "'))[1].split('",')[0]
        #return  s_no


        expiry = (data.split('"notAfter": "'))[1].split('",')[0]
        return expiry,s_no
    except:
        return 0



#fetching hashed sinatures
def cert_hash(url):
    try:
        host = (url.split("https://"))[1].split("/")[0]

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        wrappedSocket = ssl.wrap_socket(sock)

        try:
            wrappedSocket.connect((host, 443))
        except:
            response = False
        else:
            der_cert_bin = wrappedSocket.getpeercert(True)
            pem_cert = ssl.DER_cert_to_PEM_cert(wrappedSocket.getpeercert(True))
            #print(pem_cert)
            #print(der_cert_bin)eturn expiry

        #hashes
        hash_sha1 = hashlib.sha1(der_cert_bin).hexdigest()
        hash_sha256 = hashlib.sha256(der_cert_bin).hexdigest()
        res1 = ':'.join(hash_sha1[i:i + 2] for i in range(0, len(hash_sha1), 2))
        res256 = ':'.join(hash_sha256[i:i + 2] for i in range(0, len(hash_sha256), 2))
        return res1,res256
    except:
        return 0

if __name__ == "__main__":
    url = "https://paytm.com"
    url1 = "https://paytm.com"
    



    #print(str(valid(url)[0]))

    count = 0

    #1
    protocol(url)
    print(protocol(url))
    count += 1

    #2
    spell(url,url1)
    print(spell(url,url1))
    count += 1
    
    #3
    at(url)
    print(at(url))
    count += 1

    #4
    #checking expiry date of url
    try:

        if str(valid(url)[0]) == str(valid(url1)[0]):
            print(1)
            count += 1
        else:
            print(0)
            None
    except:
        print(0)
        None
    
    #5
    #checking serial number of url
    try:
        if valid(url)[1] == valid(url1)[1]:
            print(1)
            count += 1
        else:
            print(0)
            None
    except:
        print(0)    
        None
    
    #6
    #checking sha1 of url
    try:
        if cert_hash(url)[0] == cert_hash(url1)[0]:
            print(1)
            count += 1
        else:
            print(0)
            None
    except:
        print(0)
        None
    
    
    #7
    #checking sha256 of url
    try:
        if cert_hash(url)[1] == cert_hash(url1)[1]:
            print(1)
            count += 1
            None
        else:
            print(0)
            None
    except:
        print(0)    
        None

    print(count)
