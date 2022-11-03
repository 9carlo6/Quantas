import json
import csv
import requests
import pandas as pd
import os
from time import sleep
from progress.bar import Bar

header = ['t-pot_ip_ext','honeypot','id','target','timestamp','src_ip','tag_d1','tag_d2','tag_d3','family_d','score_d','tag_s1','tag_s2','tag_s3','family_s','score_s','platform']

def normalize_json(single_sandbox_json, log):
    row=list()

    if "error" in single_sandbox_json.keys():
        return None, 1

    row.append("212.35.201.182")
    row.append("Cowrie")
    row.append(single_sandbox_json["sample"]["id"])
    row.append(single_sandbox_json["sample"]["target"])
    row.append(log["timestamp"])
    row.append(str(log["src_ip"]))

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

def main():
    # Aggregazione di tutti i file di log generati dall'honeypot cowrie
    # in un unico file di log chiamato global_logs.json
    os.system('zcat /data/cowrie/log/cowrie.json.*.gz | grep outfile > /data/cowrie/log/global_logs/global_logs.json')
    os.system('cat /data/cowrie/log/cowrie.json.?????????? | grep outfile >> /data/cowrie/log/global_logs/global_logs.json')

    # Apertura del file precedentemente, che contiene tutti i log di cowrie
    tpot_json = []
    with open('/data/cowrie/log/global_logs/global_logs.json', 'r') as f:
        for l in f:
            log = json.loads(l)
            tpot_json.append(log)

    # DEBUG
    # Stampa del numero dei log di cowrie
    print("I log di cowrie sono: " + str(len(tpot_json)))

    # Viene aperto il file che contiene gli id delle analisi effettuate
    # sulla sandbox per generare una lista (sandbox_newlist)
    sandbox_file = open('/data/cowrie/cowrie_analysis.txt', 'r')
    sandbox_lines = sandbox_file.readlines()
    sandbox_newlist = list()
    for line in sandbox_lines:
        sandbox_newlist.append(line.strip())
    sandbox_file.close()

    # Creazione del file di analisi globale (analisi sandbox + log)
    with open('/home/tsec/Quantas/tpot/reports/cowrie_report.csv','w',newline='') as out_file:
        writer = csv.writer(out_file)
        writer.writerow(header)

    report_dict = dict()
    not_analyzed_files = 0

    # Collezione di tutti i report della sandbox
    for element in sandbox_newlist:
        headers = {
            'Authorization': 'Bearer 0978fce771feb88066139a174ce8f2d5f08a53d6'
        }
        response = requests.get('https://private.tria.ge/api/v0/samples/'+element+'/overview.json', headers=headers)
        sandbox_json = json.loads(response.text)

        if  "error" not in sandbox_json.keys():
            shasum = sandbox_json["sample"]["sha256"]
            report_dict[shasum] = sandbox_json
        else:
            # DEBUG
            print("Non e' stato possibile analizzare correttamente il seguente file: " + element)
            not_analyzed_files=not_analyzed_files+1

    # DEBUG
    # Stampa del numero di elementi che non sono stati analizzati dalla sandbox
    print(not_analyzed_files + " file non sono stati analizzati correttamente dalla sandbox")

    ok_report = set()
    not_ok_report = set()

    print("Inizio popolazione file di analisi globale")

    # Popolazione file di analisi globale (sandbox + log)
    with Bar('Processing...') as bar:
        for log in tpot_json:
            if log["shasum"] in report_dict.keys():

                ok_report.add(log["shasum"])

                single_sandbox_json = report_dict[log["shasum"]]
                row, error_code = normalize_json(single_sandbox_json, log)

                if error_code == 0:
                    with open('/home/tsec/Quantas/tpot/reports/cowrie_report.csv','a',newline='') as out_file:
                        writer = csv.writer(out_file)
                        writer.writerow(row)
            else:
                not_ok_report.add(log["shasum"])
            sleep(0.02)
            bar.next()

    # DEBUG
    # Creazione di un file contenente tutti i file che non sono presenti
    # nel log globale
    with open('/home/tsec/Quantas/tpot/reports/cowrie_not_logged_shasum.txt','w') as f:
        not_logged_shasum_report = report_dict.keys() - ok_report
        not_logged_shasum_report = not_logged_shasum_report - not_ok_report

        for x in not_logged_shasum_report:
            f.write(str(x) + "\n")

    # DEBUG
    # Creazione di un file contenente tutti i file che sono stati
    # analizzati in maniera corretta
    with open('/home/tsec/Quantas/tpot/reports/cowrie_ok.txt','w') as f:
        for x in ok_report:
            f.write(str(x) + "\n")

    # DEBUG
    # Creazione di un file contenente tutti i file che non sono stati
    # analizzati in maniera corretta
    with open('/home/tsec/Quantas/tpot/reports/cowrie_not_ok.txt','w') as f:
        for x in not_ok_report:
            f.write(str(x) + "\n")

    # DEBUG
    # Fine della generazione del file di analisi globale
    print('Report di Cowrie Aggiornato')


if __name__ == "__main__":
    main()

__author__ = "Carlo Pannullo"
