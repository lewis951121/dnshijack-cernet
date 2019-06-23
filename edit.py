# convert txt files into json files. collect and merge the history temp files.
import sys, os, json

ts = sys.argv[1]
v6 = sys.argv[2]

os.system("mkdir temp_data")
os.system("mkdir result_data")
if v6 == "True":
    os.system("cat " + ts + "* | grep False > result_data/abnormal.v6." + ts + ".txt")
    inputf = open("result_data/abnormal.v6." + ts + ".txt")
    outputf = open("v6_abnormal_resover_list.json", "w")
    key = "abnormal_v6_resolver_list"
else:
    os.system("grep False " + ts + "* > result_data/abnormal.v4." + ts + ".txt")
    inputf = open("result_data/abnormal.v4." + ts + ".txt")
    outputf = open("v4_abnormal_resover_list.json", "w")
    key = "abnormal_v4_resolver_list"
os.system("mv " + ts + "* temp_data")

# print into json.
outjson = {}
resolver_list = []
for line in inputf:
    line = line.strip()
    resolver = {}
    try:
        part = line.split("\t")
        ip = part[0]
        resolver["ip"] = ip
        asn = part[1]
        resolver["asn"] = asn
        asname = part[2]
        resolver["as"] = asname
        country = part[3]
        resolver["country"] = country
        domain = part[4]
        resolver["domain"] = domain
        result_ip = part[7]
        resolver["result_ip"] = result_ip
        result_asn = part[8]
        resolver["result_asn"] = result_asn
        flag = part[9]
        if flag == "False":
            resolver_list.append(resolver)
    except Exception as e:
        print(e, line)
        continue

outjson[key] = resolver_list
json.dump(outjson, outputf, indent=4)

os.system("cp *abnormal*json /usr/share/nginx/html/openinfo/data")
