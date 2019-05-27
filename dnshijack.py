# from watchdog.observers import Observer
# from watchdog.events import *
import numpy as np
import dns, os, shutil, json, re, subprocess, time
import pymysql.cursors
import threading, sys, os, requests, bs4, crypt
import geoip2.database
from dns import resolver
from dns.exception import DNSException

import argparse
from tqdm import tqdm

parser = argparse.ArgumentParser(description="DNS Hijacking detection program.")

reader = geoip2.database.Reader("GeoLite2-City.mmdb")
salt = crypt.mksalt(crypt.METHOD_SHA512)
SQL = False

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
        print("[geo]", ip, e)
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
        print("[resolver check]", e)
    return False, ""

# check the ground results of one domain.
def checkdomainresolved(domain):
    if use_v6:
        ground_resolver = ["2606:4700:4700::1111", "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9"]
    else:
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
            print("[ground resolution]", domain, e)
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
    except Exception as e:
        failtype = "DNS query failure"
        print("[test resolution]", ip, domain, e)
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
            print("[HTTP]", e)
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
                print("[cert]", ipstr, e)
        cmd2 = "openssl x509 -text -in test.pem"
        try:
            p2 = os.popen(cmd2)
            text = p2.read()
            hashvalue = crypt.crypt(text,salt)
            resultlist.append(hashvalue)
            textlist = text.split("\n")
        except Exception as e:
            print("[cert2]", ipstr, e)
        issuer = ""
        subject = ""
        notafter = ""
        for i in range(len(textlist)):
            if(textlist[i].strip().startswith("Subject:")):
                subject = textlist[i].split(":", 1)[1].strip()
                subject = subject.replace("'", "$")
                subjectlist.append(subject)
                break
    return list(set(resultlist)), list(set(subjectlist))

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
                print("[cert_sni]", ipstr,e)
        cmd2="openssl x509 -text -in test.pem"
        try:
            p2=os.popen(cmd2)
            text=p2.read()
            hashvalue=crypt.crypt(text,salt)
        except Exception as e:
            print("[cert_sni2]", ipstr,e)
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
            print("[cdn]", e)
        except Exception as e:
            print("[cdn]", e)
    return resultlist


# main function of each thread.
def threadFunc(num1, num2, num):
    if SQL:
        # connect to the mysql database.
        config = {'host': '202.112.51.179', 'port': 3306, 'user': 'root', 'password': 'thunisl', 'db': 'opendns_bak', 'charset': 'utf8'}
        connection = pymysql.connect(**config)
        connection.autocommit(1)
        cur = connection.cursor()
    else:
        # create output file.
        ts = time.time()
        filename = str(int(ts)) + "_" + str(num) + ".txt"
        outputf = open(filename, "a+")
        if DEBUGGING:
            print("===> Output file created:", filename)

    # for each domain in the thread
    # for i in range(num1, num2):
    # for all domains in the list
    for i in range(0, len(domainlist)):
        domaincsv = domainlist[i].decode()
        domain = domaincsv.split(',')[0]
        if DEBUGGING:
            print("Testing domain:", domain)
        # category = domaincsv.split(',')[1]

        # get the ground resolution results of this domain.
        ifdomainresolved, ground_ip = checkdomainresolved(domain)
        if DEBUGGING:
            print("===> Ground resolution result:", ground_ip)
        if ifdomainresolved:
            # ground resolution successful.
            # for j in range(0, len(dnslist)):
            for j in range(num1, num2):
                ip = dnslist[j].decode()
                if ip in dnsdict:
                    sameip = False
                    sameas = False
                    samehttp = False
                    samecert = False
                    samecert_withSNI = False
                    correctcert = False
                    correctcert_withSNI = False
                    sameCDN = False
                    Comment = ""
                    # and the test resolver works. start the remaining tests
                    if DEBUGGING:
                        print("Testing resolver:", ip)
                    ground_asn, ground_isp = getaslist(ground_ip)       # get ground stats
                    response_ip, fail_type = domainresolver(ip, domain)  # get test results
                    # preprocess the response. is it empty or encounter errors?
                    if len(response_ip) == 0:
                        # empty response.
                        Comment = "Empty response"
                        try:
                            if write_empty:
                                outputf.write(ip + "\t" + dnsdict[ip][0] + "\t" + dnsdict[ip][1] + "\t" + dnsdict[ip][2]
                                          + "\t" + domain + "\t" + str(ground_ip) + "\t" + str(ground_asn) +
                                          "\t" + str(response_ip) + "\t[]" +
                                          "\tFalse\t" + Comment + "\n")
                        except Exception as e:
                            print("[write1]", ip, domain, e)
                        continue
                    elif fail_type != "":
                        # other failures.
                        Comment = fail_type
                        try:
                            outputf.write(ip + "\t" + dnsdict[ip][0] + "\t" + dnsdict[ip][1] + "\t" + dnsdict[ip][2]
                                      + "\t" + domain + "\t" + str(ground_ip) + "\t" + str(ground_asn) +
                                      "\t" + str(response_ip) + "\t[]" +
                                      "\tFalse\t" + Comment + "\n")
                        except Exception as e:
                            print("[write2]", ip, domain, e)
                        continue

                    response_asn, response_isp = getaslist(response_ip)  # get the stats of test results
                    if DEBUGGING:
                        print("Testing result:", response_ip)
                    if set(ground_ip) >= set(response_ip):
                        sameip = True       # same IP.
                        Comment = "Same IP"
                    if (set(ground_asn) >= set(response_asn) and len(set(response_asn)) > 0) \
                            or (set(ground_isp) >= set(response_isp) and len(set(response_isp)) > 0):
                        sameas = True       # same ASN.
                        Comment = "Same ASN"
                    # checkset = set(response_ip) - set(ground_ip)
                    # if len(checkset) == 0:      # completely the same IP
                    if sameip or sameas:
                        if SQL:
                            # insert into SQL database.
                            sql_insert = 'INSERT INTO paper_redo5(ip,asn,isp,country,region,domain,sameip,sameas,samehttp,samecert,samecert_withSNI,correctcert,correctcert_withSNI,sameCDN,ground_ip,response_ip,category)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                            try:
                                cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], dnsdict[ip][3], domain,
                                                         str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                         str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                         str(ground_ip), str(response_ip))) # and others
                            except Exception:
                                try:
                                    # remove REGION and try again.
                                    cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], "", domain,
                                                             str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                             str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                             str(ground_ip), str(response_ip)))
                                except Exception as e:
                                    print(ip, domain, e)
                            continue
                        else:
                            # write into output file.
                            try:
                                if DEBUGGING:
                                    print("===> Same IP/ASN.")
                                if write_normal:
                                    outputf.write(ip + "\t" + dnsdict[ip][0] + "\t" + dnsdict[ip][1] + "\t" + dnsdict[ip][2]
                                                   + "\t" + domain + "\t" + str(ground_ip) + "\t" + str(ground_asn) +
                                                   "\t" + str(response_ip) + "\t" + str(response_asn) +
                                                   "\tTrue\t" + Comment + "\n")
                            except Exception as e:
                                print("[write3]", ip, domain, e)
                            continue

                    # otherwise, response does not agree with ground.
                    # compare the (hashes of) HTTP webpages of ground and test results.
                    ground_httpcontent = gethttpcontent(ground_ip)
                    response_httpcontent = gethttpcontent(response_ip)
                    if DEBUGGING:
                        print("Got HTTP.")
                    if set(ground_httpcontent) >= set(response_httpcontent) and len(response_httpcontent) > 0:
                        samehttp = True
                        Comment = "Same HTTP"
                        if DEBUGGING:
                            print("===> Same HTTP.")

                    if not samehttp:
                        # compare the certs of ground and test results.
                        ground_cert, ground_subject = getcert(ground_ip)
                        response_cert, response_subject = getcert(response_ip)
                        if DEBUGGING:
                            print("Got cert.")
                        if set(ground_cert) >= set(response_cert) and len(response_cert) > 0:
                            samecert = True
                            Comment = "Same Cert"
                            if DEBUGGING:
                                print("===> Same cert.")
                        if not samecert:
                            # compare the certs of ground and test results (with SNI).
                            ground_cert_SNI, ground_subject_SNI = getcert_SNI(ground_ip, domain)
                            response_cert_SNI, response_subject_SNI = getcert_SNI(response_ip, domain)
                            if DEBUGGING:
                                print("Got cert with SNI.")
                            if set(ground_cert_SNI) >= set(response_cert_SNI) and len(response_cert_SNI) > 0:
                                samecert_withSNI = True
                                Comment = "Same Cert (with SNI)"
                                if DEBUGGING:
                                    print("===> Same cert with SNI.")
                            if not samecert_withSNI:
                                # check if the cert is valid.
                                # correctcert = checkcert(response_ip)
                                correctcert_withSNI = checkcert_SNI(response_ip, domain)
                                if DEBUGGING:
                                    print("Cert validated.")
                                if not correctcert_withSNI:
                                    # check if the SDNs of ground and test results belong to the same CDN.
                                    ground_CDN = getcdn(ground_ip)
                                    response_CDN = getcdn(response_ip)
                                    if DEBUGGING:
                                        print("Got CDN.")
                                    if len(response_CDN) > 0:
                                        if set(ground_CDN) >= set(response_CDN) or set(ground_asn) >= set(response_CDN) \
                                                or set(ground_subject) >= set(response_CDN) or set(ground_subject_SNI) >= set(response_CDN):
                                            sameCDN = True
                                            Comment = "Same CDN"
                                            if DEBUGGING:
                                                print("===> Same CDN.")

                    if SQL:
                        # insert the result into database.
                        sql_insert = 'INSERT INTO paper_redo5(ip,asn,isp,country,region,domain,sameip,sameas,samehttp,samecert,samecert_withSNI,correctcert,correctcert_withSNI,sameCDN,ground_ip,response_ip,category)VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)'
                        try:
                            cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], dnsdict[ip][3], domain,
                                                     str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                     str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                     str(ground_ip), str(response_ip))) # and others
                        except Exception:
                            try:
                                cur.execute(sql_insert, (ip, dnsdict[ip][0], dnsdict[ip][1], dnsdict[ip][2], "", domain,
                                                         str(sameip), str(sameas), str(samehttp), str(samecert), str(samecert_withSNI),
                                                         str(correctcert), str(correctcert_withSNI), str(sameCDN),
                                                         str(ground_ip), str(response_ip)))
                            except Exception as e:
                                print(ip, domain, e)
                    else:
                        # output into output file.
                        normal = sameip | sameas | samehttp | samecert | samecert_withSNI | correctcert | correctcert_withSNI | sameCDN
                        if normal and not write_normal:
                            continue
                        outputf.write(ip + "\t" + dnsdict[ip][0] + "\t" + dnsdict[ip][1] + "\t" + dnsdict[ip][2]
                                      + "\t" + domain + "\t" + str(ground_ip) + "\t" + str(ground_asn) + "\t" +
                                      str(response_ip) + "\t" + str(response_asn) + "\t" + str(normal) + "\t" + Comment + "\n")
    if SQL:
        connection.commit()
        connection.close()
    else:
        outputf.close()


# check if resovler is still alive (one thread).
def check_resolver_alive(num1, num2):
    for i in range(num1, num2):
        ip = dnslist[i].decode()
        # check if this resolver is still alive, by resolving "thunisl.com"
        flag, result_thunisl = ifresolverok(ip)
        if flag:
            # it works! record the resolver.
            asn, isp = getas(ip)
            country, region = geoip_query(ip)
            dnsdict[ip] = [asn, isp, country, region]


DEBUGGING = True
write_normal = True
write_empty = False
use_v6 = False
MAX_THREADS = 100

def main():
    global dnslist, domainlist, dnsdict, write_normal, use_v6
    dnsdict = {}

    # parse the parameters: resolver list & domain list / domain.
    parser.add_argument("resolver_list", action="store", default=None, help="resolver list file")
    parser.add_argument("-l", action="store", default=None, help="domain list file", dest="domain_list")
    parser.add_argument("-d", action="store", default=None, help="single test domain", dest="domain")
    parser.add_argument("-c", action="store", type=int, default=10, help="count of sampled resolvers", dest="resolver_count")
    parser.add_argument("-6", action="store_true", default=False, dest="v6")
    results = parser.parse_args()
    resolver_list_file = results.resolver_list
    domain_list_file = results.domain_list
    single_domain = results.domain
    resolver_count = results.resolver_count
    use_v6 = results.v6

    try:
        # read resolver list from file.
        # resolver_list_file = sys.argv[1]
        dnslist = np.genfromtxt(resolver_list_file, delimiter="\n", dtype="S16")
    except:
        print("Resolver file ERROR.")
        exit(1)
    if DEBUGGING:
        print("===> Loaded resolver file. ", len(dnslist), "resolvers in total.")

    try:
        # domain_list_file = sys.argv[2]
        domainlist = np.genfromtxt(domain_list_file, delimiter="\n", dtype="S")
    except:
        # this file does not exist. try take domain name.
        try:
            domainlist = np.array([single_domain], dtype="S")
            # sample from resolver list.
            np.random.shuffle(dnslist)
            dnslist = dnslist[:resolver_count]
        except Exception as e:
            print("Domain file ERROR.")
            exit(2)
    if DEBUGGING:
        print("===> Loaded domain file. ", len(domainlist), "domains in total.")


    # determine number of threads.
    num = int(len(domainlist) * len(dnslist) / 20) + 1
    if num > MAX_THREADS:
        num = MAX_THREADS

    print("Begin resolver check.")
    # for i in range(0, len(dnslist))
    threads_resolver_check = []
    if int(len(dnslist) / 50) > MAX_THREADS:
        num_tmp = MAX_THREADS
    else:
        num_tmp = int(len(dnslist) / 50) + 1
    for i in range(0, num_tmp):
        threads_resolver_check.append(threading.Thread(target=check_resolver_alive, args=(int(i * len(dnslist) / num_tmp),
                                                                                          int((i + 1) * len(dnslist) / num_tmp), )))
    for t in threads_resolver_check:
        t.start()
    for t in threads_resolver_check:
        t.join()

    if DEBUGGING:
        print("===> Resolver check done. ", len(dnsdict), "resolvers alive.")
    # if there's no resolver alive, terminate.
    if len(dnsdict) == 0:
        if DEBUGGING:
            print("No resolver alive. Terminate.")
        exit(0)

    threads = []
    # start probing each resolver alive with the test domains.
    for i in range(0, num):
        threads.append(threading.Thread(target=threadFunc, args=(int(i * len(dnslist) / num), int((i + 1) * len(dnslist) / num), i,)))
    for t in threads:
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()
