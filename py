import ssl
import socket
import hashlib


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

def certi(url):
    hostname = (url.split("https://"))[1].split("/")[0]
    ctx = ssl.create_default_context()
    s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
    s.connect((hostname, 443))
    cert = s.getpeercert()

    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject['commonName']
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer['commonName']
    issue_date = cert['notBefore']
    ca_issuer = cert['caIssuers']
    return issued_to, issued_by, issue_date
    #[0]= issued to which domain
    #[1] = issued by which certificate provider
    #[2] = issued on which date
    

import re 

url = "рaytm.com"
def has_cyrillic(text):
    return bool(re.search('[а-яА-Я]', text))


if __name__ == "__main__":
    
    url = "https://рaytm.com"  #original url
    url1 = "https://paytm.com"  #url fetched by chrome ext
    
    count = 0

    #1
    #checking if cyrillic letters are used or not
    if has_cyrillic(url) == True:
        print(1)
        count += 1
        check0 = 1
    else:
        print(0)
        check0 = 0

    #print(str(valid(url)[0]))

    
    #1 
    #checking connection protocol
    if url[0:5] == "https":
        #score += 1
        print(1)
        count += 1
        check1 = 1
    else:
        print(0)
        check1 = 0


    #2
    #checking spelling of the url
    if url == url1:
        print(1)
        count += 1
        check2 = 1
    else:
        print(0)
        check2 = 0
    #3
    #checking usage of @ symbol
    if url.find != "@":
        print(1)
        count += 1
        check3 = 1
        
    else:
        print(0)
        check3 = 0


    #4
    #checking issued date
    try:
        if str(certi(url)[2]) == str(certi(url1)[2]):
            print(1)
            count +=1
            check4 = 1
        else:
            print(0)
            check4 = 0
            None
    except:
        print(0)
        check4 = 0
        None


    #5
    #checking expiry date of url
    try:

        if str(valid(url)[0]) == str(valid(url1)[0]):
            print(1)
            count += 1
            check5 = 1
        else:
            print(0)
            check5 = 0
            None
    except:
        print(0)
        check5 = 0
        None
    
    #6
    #checking serial number of url
    try:
        if valid(url)[1] == valid(url1)[1]:
            print(1)
            count += 1
            check6 = 1
        else:
            print(0)
            check6 = 0
            None
    except:
        print(0)    
        check6 = 0
        None
    
    #7
    #checking sha1 of url
    try:
        if cert_hash(url)[0] == cert_hash(url1)[0]:
            print(1)
            count += 1
            check7 = 1
        else:
            print(0)
            check7 = 0
            None
    except:
        print(0)
        check7 = 0
        None
    
    
    #8
    #checking sha256 of url
    try:
        if cert_hash(url)[1] == cert_hash(url1)[1]:
            print(1)
            count += 1
            check8 = 1
            None
        else:
            print(0)
            check8 = 0
            None
    except:
        print(0)    
        check8 = 0
        None


    #9
    #checking which certificate provider provided the ssl certificate
    try:
        if str(certi(url)[1]) == str(certi(url1)[1]):
            print(1)
            count += 1
            check9 = 1
        else:
            print(0)
            check9 = 0
            None
    except:
        print(0)
        check9 = 0
        None
    

    #10
    #checking which domain was exactly issued this particular certificate
    try:
        if str(certi(url)[0]) == str(certi(url1)[0]):
            print(1)
            count += 1
            check10 = 1
        else:
            print(0)
            check10 = 0
            None
    except:
        print(0)
        check10 = 0
        None


    print(count)

    if count == 11:
        print("everything is ok")
    else:
        print("something phishy is going on!!")

    check_dict = {'check_0': check0, 'check_1': check1, 'check_2': check2, 'check_3': check3, 'check_4': check4, 'check_5': check5, 'check_6': check6, 'check_7': check7, 'check_8': check8, 'check_9': check9, 'check_10': check10,}

    info_dict = {'issued_date': certi(url1)[2], 'expiry_date': valid(url1)[0], 'serial_number': valid(url1)[1], 'sha1': cert_hash(url1)[0], 'sha256': cert_hash(url1)[1], 'issuer': certi(url1)[1], 'issued_to': certi(url1)[0]}
    
    print(info_dict)

    print(check_dict)


    
