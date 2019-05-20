# from watchdog.observers import Observer
# from watchdog.events import *
import numpy as np
import dns, os, shutil, json, re, subprocess, time
import pymysql.cursors
import threading, sys, os, requests, bs4, crypt
import geoip2.database
from dns import resolver
from dns.exception import DNSException

reader = geoip2.database.Reader("GeoLite2-City.mmdb")
salt = crypt.mksalt(crypt.METHOD_SHA512)

# get basic info of a given IP: ASN, ISP, CC, REGION.
def getas(ip):
    try:
        cmd = "whois -h whois.cymru.com " + ip
        buff = os.popen(cmd, 'r', 2)
        for l in buff:
            if l.find("AS Name") < 0 and l.find("whois.cymru.com") < 0:
                seg = l.split("|")
                return seg[0].strip(),seg[2].split(",")[0].strip()
        return "", ""
    except:
        return "", ""

# batch of getas().
def getaslist(iplist):
    asnlist, isplist = [], []
    for item in iplist:
        a, b = getas(item)
        asnlist.append(a)
        isplist.append(b)
    return list(set(asnlist)), list(set(isplist))

def geoip_query(ip):
    try:
        response = reader.city(ip)
        country = response.country.iso_code
        region = response.subdivisions.most_specific.name
        return country, region
    except Exception as e:
        print(ip, e)
        return "", ""
    return "", ""

# check if a resolver IP is still alive.
def ifresolverok(ip):
    tmp = resolver.Resolver()
    tmp.nameservers = [ip]
    tmp.lifetime = 5.0
    resultlist = []
    try:
        ans = tmp.query("thunisl.com")
        resultlist = [a.address for a in ans.rrset.items]
        if(len(resultlist) == 1 and resultlist[0] == "202.112.51.37"):
            return True, resultlist[0]
        else:
            return False, str(resultlist)
    except Exception as e:
        print("")
    return False, ""

# check the ground results of one domain.
def checkdomainresolved(domain):
    # TODO: add v6 resolvers.
    ground_resolver = ["8.8.8.8", "8.8.4.4", "140.82.36.158", "47.88.213.154"]
    resultlist = []
    for item in ground_resolver:
        tmp = resolver.Resolver()
        tmp.nameservers = [item]
        tmp.lifetime = 5.0
    #    resultlist=[]
        try:
            ans = tmp.query(domain)
            temp = [a.address for a in ans.rrset.items]
            resultlist.append(temp)
        except Exception as e:
            print(domain, e)
            resultlist.append([])
    resultset = set(resultlist[0]) | set(resultlist[1]) | set(resultlist[2]) | set(resultlist[3])
    resultlist = list(resultset)
    if(len(resultlist) == 0):
        return False, resultlist
    else:
        return True, resultlist

# resolve a domain on a resolver.
def domainresolver(ip, domain):
    tmp = resolver.Resolver()
    tmp.nameservers = [ip]
    tmp.lifetime = 5.0
    resultlist = []
    failtype = ""
    try:
        ans = tmp.query(domain)
        resultlist = [a.address for a in ans.rrset.items]
    except resolver.NXDOMAIN:
        failtype = "NXDOMAIN"
    except resolver.Timeout:
        failtype = "Timeout"
    except resolver.NoNameservers:
        failtype = "NoNameservers"
    except DNSException as e:
        failtype = "others"
        print(ip, domain, e)
    return resultlist, failtype

# get (hashed) HTTP webpage of a batch of IPs.
def gethttpcontent(iplist):
    resultlist = []
    for item in iplist:
        try:
            url = "http://" + item
            response = requests.get(url, headers={'Connection': 'close'})
            a = response.text
            hashvalue = crypt.crypt(a, salt)
            resultlist.append(hashvalue)
        except Exception as e:
            print("wrong during gethttpcontent", e)
    return list(set(resultlist))

# get the certificates on port 443 of a list of IPs.
def getcert(iplist):
    resultlist = []
    subjectlist = []
    for ipstr in iplist:
        cmd1 = "openssl s_client -connect %s:443 -showcerts" % (ipstr)
        p = subprocess.Popen(cmd1, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        text_stdout = p.stdout.read().decode()
        alist = text_stdout.split("\n")
        comment, hashvalue = "", ""
        for i in range(0, len(alist))[::-1]:
            if(alist[i].strip().startswith("Verify return code:")):
                templist = re.split(r":|\(",alist[i])
                comment = templist[2]
        blist = re.split(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----", text_stdout)
        with open("test.pem", "w") as fid:
            try:
                fid.write("-----BEGIN CERTIFICATE-----" + blist[1] + "-----END CERTIFICATE-----")
            except Exception as e:
                print(ipstr, e)
        cmd2 = "openssl x509 -text -in test.pem"
        try:
            p2 = os.popen(cmd2)
            text = p2.read()
            hashvalue = crypt.crypt(text,salt)
            resultlist.append(hashvalue)
            textlist = text.split("\n")
        except Exception as e:
            print(ipstr, e)
        issuer = ""
        subject = ""
        notafter = ""
        for i in range(len(textlist)):
            if(textlist[i].strip().startswith("Subject:")):
                subject = textlist[i].split(":", 1)[1].strip()
                subject = subject.replace("'", "$")
                subjectlist.append(subject)
                break
    return list(set(resultlist), set(subjectlist))

# get the certificates on port 443 of a list of IPs (with SNI).
def getcert_SNI(iplist, domain):
    resultlist,subjectlist=[],[]
    for ipstr in iplist:
        cmd1 = "openssl s_client -connect %s:443 -showcerts -servername %s"% (ipstr,domain)
        p=subprocess.Popen(cmd1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        text_stdout=p.stdout.read().decode()
        alist=text_stdout.split("\n")
        comment,hashvalue="",""
        for i in range(0,len(alist))[::-1]:
            if(alist[i].strip().startswith("Verify return code:")):
                templist=re.split(r":|\(",alist[i])
                comment=templist[2]
        blist=re.split(r"-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----",text_stdout)
        with open("test.pem","w") as fid:
            try:
                fid.write("-----BEGIN CERTIFICATE-----"+blist[1]+"-----END CERTIFICATE-----")
            except Exception as e:
                print(ipstr,e)
        cmd2="openssl x509 -text -in test.pem"
        try:
            p2=os.popen(cmd2)
            text=p2.read()
            hashvalue=crypt.crypt(text,salt)
        except Exception as e:
            print(ip,e)
        resultlist.append(hashvalue)
        textlist=text.split("\n")
        issuer=""
        subject=""
        notafter=""
        for i in range(len(textlist)):
            if(textlist[i].strip().startswith("Subject:")):
                subject=textlist[i].split(":",1)[1].strip()
                subject=subject.replace("'","$")
                subjectlist.append(subject)
                break
    return list(set(resultlist)),list(set(subjectlist))

# is the certificate valid?
def checkcert(iplist):
    result=False
    for ipstr in iplist:
        cmd1 = "openssl s_client -connect %s:443 -showcerts"% (ipstr)
        p=subprocess.Popen(cmd1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        text_stdout=p.stdout.read().decode()
        alist=text_stdout.split("\n")
        comment,hashvalue="",""
        for i in range(0,len(alist))[::-1]:
            if(alist[i].strip().startswith("Verify return code:")):
                templist=re.split(r":|\(",alist[i])
                comment=templist[2]
                if comment=="ok)":
                    result=True
                    return True
    return result

# is the certificate valid? (with SNI)?
def checkcert_SNI(iplist,domain):
    result=False
    for ipstr in iplist:
        cmd1 = "openssl s_client -connect %s:443 -showcerts -servername %s"% (ipstr,domain)
        p=subprocess.Popen(cmd1,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        text_stdout=p.stdout.read().decode()
        alist=text_stdout.split("\n")
        comment,hashvalue="",""
        for i in range(0,len(alist))[::-1]:
            if(alist[i].strip().startswith("Verify return code:")):
                templist=re.split(r":|\(",alist[i])
                comment=templist[2]
                if comment=="ok)":
                    result=True
    return result

# get the SDN of a list of IPs.
def getcdn(iplist):
    resultlist=[]
    for ipstr in iplist:
        tmp=resolver.Resolver()
        qname=dns.reversename.from_address(ipstr)
        hostname=""
        pattern="ns[0-9]+|nameserver[0-9]*"
        try:
            ans=resolver.query(qname,'PTR')
            hostname = ans.rrset[0].target.to_text(True)
            resultlist.append(hostname)
        except DNSException as e:
            print(e)
        except Exception as e:
            print(e)
    return resultlist


# main function of each thread.
def threadFunc(num1, num2):
    # connect to the mysql database.
    config = {'host': '202.112.51.179', 'port': 3306, 'user': 'root', 'password': 'thunisl', 'db': 'opendns_bak', 'charset': 'utf8'}
    connection = pymysql.connect(**config)
    connection.autocommit(1)
    cur = connection.cursor()

    # for each domain in the thread
    for i in range(num1, num2):
        domaincsv = domainlist[i].decode()
        domain = domaincsv.split(',')[0]
        category = domaincsv.split(',')[1]
        # get the ground resolution results of this domain.
        ifdomainresolved, ground_ip = checkdomainresolved(domain)
        if ifdomainresolved:
            # ground resolution successful.
            for j in range(0,len(dnslist)):
                ip = dnslist[j].decode()
                if(dnsdict[ip] != ""):
                    # and the test resolver works. start the remaining tests.
                    ground_asn, ground_isp = getaslist(ground_ip)       # get ground results
                    response_ip, fail_type = domainresolver(ip, domain)  # get test results
                    response_asn, response_isp = getaslist(response_ip) # get the stats of test results
                    if set(ground_ip) >= set(response_ip):
                        sameip = True       # same IP.
                    if set(ground_asn) >= set(response_asn) or set(ground_isp) >= set(response_isp):
                        sameas = True       # same ASN.
                    checkset = set(response_ip) - set(ground_ip)
                    if len(checkset) == 0:      # completely the same IP
                        # TODO: this is sql.
                        sql_insert = 'INSERT INTO paper_redo5(ip,asn,isp,country,region,domain,sameip,sameas,samehttp,samecert,samecert_withSNI,correctcert,correctcert_withSNI,sameCDN,ground_ip,response_ip,category)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                        try:
                            cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], dnsdict[ip][3], domain,
                                                     str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                     str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                     str(ground_ip), str(response_ip), category)) # and others
                        except Exception:
                            try:
                                # remove REGION and try again.
                                cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], "", domain,
                                                         str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                         str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                         str(ground_ip), str(response_ip), category))
                            except Exception as e:
                                print(ip, domain, e)
                        continue

                    # otherwise, response does not agree with ground.
                    print("ip is", ip, "domain is", domain, "groundip is", str(ground_ip), "responseip is", str(response_ip))
                    # compare the (hashes of) HTTP webpages of ground and test results.
                    ground_httpcontent = gethttpcontent(ground_ip)
                    response_httpcontent = gethttpcontent(response_ip)
                    if set(ground_httpcontent) >= set(response_httpcontent):
                        samehttp = True
                    # compare the certs of ground and test results.
                    ground_cert, ground_subject = getcert(ground_ip)
                    response_cert, response_subject = getcert(response_ip)
                    if set(ground_cert) >= set(response_cert):
                        samecert = True
                    # compare the certs of ground and test results (with SNI).
                    ground_cert_SNI, ground_subject_SNI = getcert_SNI(ground_ip, domain)
                    response_cert_SNI, response_subject_SNI = getcert_SNI(response_ip, domain)
                    if set(ground_cert_SNI) >= set(response_cert_SNI):
                        samecert_withSNI = True
                    # check if the cert is valid.
                    correctcert = checkcert(response_ip)
                    correctcert_withSNI = checkcert_SNI(response_ip, domain)
                    # check if the SDNs of ground and test results belong to the same CDN.
                    ground_CDN = getcdn(ground_ip)
                    response_CDN = getcdn(response_ip)
                    if set(ground_CDN) >= set(response_CDN) or set(ground_asn) >= set(response_CDN) \
                            or set(ground_subject) >= set(response_CDN) or set(ground_subject_SNI) >= set(response_CDN):
                        sameCDN = True

                    sql_insert = 'INSERT INTO paper_redo5(ip,asn,isp,country,region,domain,sameip,sameas,samehttp,samecert,samecert_withSNI,correctcert,correctcert_withSNI,sameCDN,ground_ip,response_ip,category)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                    try:
                        cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], dnsdict[ip][3], domain,
                                                 str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                 str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                 str(ground_ip), str(response_ip), category)) # and others
                    except Exception:
                        try:
                            cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], "", domain,
                                                     str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                     str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                     str(ground_ip), str(response_ip), category))
                        except Exception as e:
                            print(ip, domain, e)
    connection.commit()
    connection.close()

def main(num):
    # TODO: add custom domain. parameters.
    # init, read resolver list and domain list from file.
    global dnslist, domainlist, dnsdict
    dnsdict = {}
    dnslist = np.genfromtxt("dns.txt", delimiter="\n", dtype="S16")
    domainlist = np.genfromtxt("domaincn", delimiter="\n", dtype="S")
    for i in range(0, len(dnslist)):
        ip = dnslist[i].decode()
        asn, isp = getas(ip)
        country, region = geoip_query(ip)
        # check if this resolver is still alive, by resolving "thunisl.com"
        flag, result_thunisl = ifresolverok(ip)
        if flag:
            # it works! record the resolver.
            dnsdict[ip] = [asn, isp, country, region]
        else:
            dnsdict[ip] = ""
        time.sleep(0.2)
    # print(str(dnsdict))
    threads = []
    # start probing each resolver alive with the test domains.
    for i in range(0, num):
        threads.append(threading.Thread(target=threadFunc, args=(int(i * len(domainlist) / num), int((i + 1) * len(domainlist) / num),)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    # parameter: num of threads
    main(2)
