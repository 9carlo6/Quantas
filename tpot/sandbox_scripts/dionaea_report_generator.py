import json
import csv
import requests
import pandas as pd
import os

header = ['t-pot_ip_ext','honeypot','id','target','tag_d1','tag_d2','tag_d3','family_d','score_d','tag_s1','tag_s2','tag_s3','family_s','score_s','platform']

def normalize_json(single_sandbox_json):
    row=list()

    if "error" in single_sandbox_json:
        return None, 1

    row.append("212.35.201.182")
    row.append("Dionaea")
    row.append(single_sandbox_json["sample"]["id"])
    row.append(single_sandbox_json["sample"]["target"])

    tags_d=list()
    tags_s=list()

    platform = "-"
    score_d = "-1"
    score_s = "-"

    for t in single_sandbox_json["tasks"].keys():
        if "behavioral" in t and single_sandbox_json["tasks"][t]["score"] > int(score_d):
            if "tags" in single_sandbox_json["tasks"][t].keys():
                for x in single_sandbox_json["tasks"][t]["tags"]:
                    tags_d.append(x)

            if "score" in single_sandbox_json["tasks"][t].keys():
                score_d = single_sandbox_json["tasks"][t]["score"]

            if "platform" in single_sandbox_json["tasks"][t].keys():
                platform= single_sandbox_json["tasks"][t]["platform"]
            elif "os" in single_sandbox_json["tasks"][t].keys():
                platform= single_sandbox_json["tasks"][t]["os"]

        elif "static" in t:
            if "tags" in single_sandbox_json["tasks"][t].keys():
                for x in single_sandbox_json["tasks"][t]["tags"]:
                    tags_s.append(x)

            if "score" in single_sandbox_json["tasks"][t].keys():
                score_s = single_sandbox_json["tasks"][t]["score"]

    tag_d1="-"
    tag_d2="-"
    tag_d3="-"
    tag_s1="-"
    tag_s2="-"
    tag_s3="-"
    family_d = "-"
    family_s = "-"

    for i in range(0,len(tags_d)):
        if "family" in tags_d[i]:
            family_d = tags_d[i].split(':')[1]
            break

        else:
            if i == 0:
                if ":" in tags_d[i]:
                    tags_d1 = tags_d[i].split(':')[1]
                tag_d1 = tags_d[i]
            elif i == 1:
                if ":" in tags_d[i]:
                    tags_d2 = tags_d[i].split(':')[1]
                else:
                    tag_d2 = tags_d[i]
            elif i == 2:
                if ":" in tags_d[i]:
                    tags_d3 = tags_d[i].split(':')[1]
                else:
                    tag_d3 = tags_d[i]
            else:
                break

    for i in range(0,len(tags_s)):
        if "family" in tags_s[i]:
            family_s = tags_s[i].split(':')[1]
            break

        else:
            if i == 0:
                if ":" in tags_s[i]:
                    tag_s1 = tags_s[i].split(':')[1]
                else:
                    tag_s1 = tags_s[i]
            elif i == 1:
                if ":" in tags_s[i]:
                    tag_s2 = tags_s[i].split(':')[1]
                else:
                    tag_s2 = tags_s[i]
            elif i == 2:
                if ":" in tags_s[i]:
                    tag_s3 = tags_s[i].split(':')[1]
                else:
                    tag_s3 = tags_s[i]
            else:
                break

    row.append(tag_d1)
    row.append(tag_d2)
    row.append(tag_d3)
    row.append(family_d)
    row.append(score_d)
    row.append(tag_s1)
    row.append(tag_s2)
    row.append(tag_s3)
    row.append(family_s)
    row.append(score_s)
    row.append(platform)

    return row, 0

#---------------------------------------------

# File che contiene gli id delle analisi effettuate sulla sandbox
sandbox_file = open('/data/dionaea/dionaea_analysis.txt', 'r')
sandbox_lines = sandbox_file.readlines()
sandbox_newlist = list()
for line in sandbox_lines:
    sandbox_newlist.append(line.strip())
sandbox_file.close()

# Creazione file di analisi globale (sandbox)
with open('/home/tsec/Quantas/tpot/reports/dionaea_report.csv','w',newline='') as out_file:
    writer = csv.writer(out_file)
    writer.writerow(header)

report_dict = dict()

# Collezione di tutti i report della sandbox
for element in sandbox_newlist:
    headers = {
        'Authorization': 'Bearer 0978fce771feb88066139a174ce8f2d5f08a53d6'
    }
    response = requests.get('https://private.tria.ge/api/v0/samples/'+element+'/overview.json', headers=headers)
    sandbox_json = json.loads(response.text)

    if  "error" not in sandbox_json.keys():
        shasum = sandbox_json["sample"]["sha256"]
        print (sandbox_json["sample"]["sha256"])
        report_dict[shasum] = sandbox_json
    else:
        print(element + " ha dato errore come risposta ")

print("Inizio popolazione file di analisi globale")

# Popolazione file di analisi globale (sandbox)
for rep in report_dict.keys():
    row, error_code = normalize_json(report_dict[rep])

    if error_code == 0:
        with open('/home/tsec/Quantas/tpot/reports/dionaea_report.csv','a',newline='') as out_file:
            writer = csv.writer(out_file)
            writer.writerow(row)

print('File csv update')

__author__ = "Carlo Pannullo"
