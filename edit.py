# convert txt files into json files. collect and merge the history temp files.
import sys, os, json, time, datetime

ts = sys.argv[1]
v6 = sys.argv[2]

test = False
if test:
    os.system("mkdir test")
    web_dir = "test"
else:
    web_dir = "/usr/share/nginx/html/openinfo/data"
    print("this is real! careful!")
time.sleep(2)

os.system("mkdir temp_data")
os.system("mkdir result_data")

if v6 == "True":
    os.system("cat " + ts + "* | grep False > result_data/abnormal.v6." + ts + ".txt")
    inputf = open("result_data/abnormal.v6." + ts + ".txt")
    outputf = open("v6_abnormal_resover_list.json", "w")
    key = "abnormal_v6_resolver_list"
    os.system("mkdir " + web_dir + "/abnormal_dns_v6/")
    # copy the history result files to the web dir, and create a json mapping file.
    os.system("cp " + "result_data/abnormal.v6." + ts + ".txt " + web_dir + "/abnormal_dns_v6/")
else:
    os.system("cat " + ts + "* | grep False > result_data/abnormal.v4." + ts + ".txt")
    inputf = open("result_data/abnormal.v4." + ts + ".txt")
    outputf = open("v4_abnormal_resover_list.json", "w")
    key = "abnormal_v4_resolver_list"
    os.system("mkdir " + web_dir + "/abnormal_dns_v4/")
    # copy the history result files to the web dir, and create a json mapping file.
    os.system("cp " + "result_data/abnormal.v4." + ts + ".txt " + web_dir + "/abnormal_dns_v4/")
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
outputf.close()

time.sleep(1)
# os.system("chown nginx *abnormal*json")
os.system("cp *abnormal*json " + web_dir)

# create a json mapping file for the history files.
__all__ = os.listdir("result_data/")
__all__ = sorted(__all__, reverse=True)
# take top 10
__all__ = __all__[:11]
mapping = {}
for filename in __all__:
    if filename.startswith("abnormal"):
        ts = int(filename.split(".")[2])
        datearrary = datetime.datetime.utcfromtimestamp(ts)
        day = datearrary.strftime("%Y-%m-%d")
        mapping[filename] = day
json.dump(mapping, open("result_data/file_mapping.json", "w"))
# copy this json to web dir.
if v6 == "True":
    os.system("cp result_data/file_mapping.json " + web_dir + "/abnormal_dns_v6/")
else:
    os.system("cp result_data/file_mapping.json " + web_dir + "/abnormal_dns_v4/")