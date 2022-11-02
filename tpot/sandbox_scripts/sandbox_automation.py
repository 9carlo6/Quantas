# Questo script permette di automatizzare il processo di analisi dei binari
# prodotti diverse honeypot.
# In particolare, estrae i file presenti nella cartella dell'honeypot
# spostandoli tutti all'interno di un'unica cartella.
# Successivamente questi binari vengono inviati alla sandbox e viene prodotto
# un file contenente gli id delle analisi eseguite.

import requests
import sys
import json
import os

# Dionaea Paths
dionaea_path = "/data/dionaea/"
dionaea_binaries_folder = "/data/dionaea/extract_binaries/"
dionaea_tar_command_1 = "find /data/dionaea/ -maxdepth 1 -name 'binaries.tgz.*' -exec tar -xf '{}' -C /data/dionaea/ \;"
dionaea_tar_command_2 = 'tar -zxvf /data/dionaea/binaries.tgz'
dionaea_cp_command_1 = 'cp -n /data/dionaea/data/dionaea/binaries/* /data/dionaea/extract_binaries/'
dionaea_cp_command_2 = 'cp -n /data/dionaea/binaries/* /data/dionaea/extract_binaries/'
dionaea_analysis_file = "/data/dionaea/dionaea_analysis.txt"
dionaea_binaries_already_analyzed = "/data/dionaea/dionaea_already_analyzed.txt"

# Cowrie Paths
cowrie_path = "/data/cowrie/"
cowrie_binaries_folder = "/data/cowrie/extract_downloads/"
cowrie_tar_command_1 = "find /data/cowrie/ -maxdepth 1 -name 'downloads.tgz*' -exec tar -xf '{}' -C /data/cowrie/ \;"
cowrie_tar_command_2 = 'tar -zxvf /data/cowrie/downloads.tgz'
cowrie_cp_command_1 = 'cp -n /data/cowrie/data/cowrie/downloads/* /data/cowrie/extract_downloads/'
cowrie_cp_command_2 = 'cp -n /data/cowrie/downloads/* /data/cowrie/extract_downloads/'
cowrie_analysis_file = "/data/cowrie/cowrie_analysis.txt"
cowrie_downloads_already_analyzed = "/data/cowrie/cowrie_already_analyzed.txt"

# Scelta dell'honeypot sulla quale far partire l'analisi
def honeypot_selection(honeypot_name):
    if honeypot_name == "dionaea":
        # Estrazione
        unzip_honeypot_files(dionaea_path, dionaea_tar_command_1, dionaea_tar_command_2, dionaea_cp_command_1, dionaea_cp_command_2)
        # Analisi
        analyze_files("Dionaea", dionaea_analysis_file, dionaea_binaries_already_analyzed, dionaea_binaries_folder)
    elif honeypot_name == "cowrie":
        # Estrazione
        unzip_honeypot_files(cowrie_path, cowrie_tar_command_1, cowrie_tar_command_2, cowrie_cp_command_1, cowrie_cp_command_2)
        # Analisi
        analyze_files("Cowrie", cowrie_analysis_file, cowrie_downloads_already_analyzed, cowrie_binaries_folder)
    elif honeypot_name == "all":
        # Estrazione
        unzip_honeypot_files(dionaea_path, dionaea_tar_command_1, dionaea_tar_command_2, dionaea_cp_command_1, dionaea_cp_command_2)
        unzip_honeypot_files(cowrie_path, cowrie_tar_command_1, cowrie_tar_command_2, cowrie_cp_command_1, cowrie_cp_command_2)
        # Analisi
        analyze_files("Dionaea", dionaea_analysis_file, dionaea_binaries_already_analyzed, dionaea_binaries_folder)
        analyze_files("Cowrie", cowrie_analysis_file, cowrie_downloads_already_analyzed, cowrie_binaries_folder)
    else:
        print("Prova -h per maggiori informazioni")

# Estrazione dei file presenti nella cartella dell'honeypot
def unzip_honeypot_files(honeypot_path, tar_command_1, tar_command_2, cp_command_1, cp_command_2):
    # Estrae i sample presenti nella cartella dell'honeypot
    #os.system("cd " + honeypot_path)
    os.system(tar_command_1)
    os.system(tar_command_2)
    # Sposta i sample estratti all'interno di un unica cartella
    os.system(cp_command_1)
    os.system(cp_command_2)

# Recupero della lista dei file gia analizzati
def get_files_already_analyzed(files_already_analyzed):
    file = open(files_already_analyzed, "r")
    data = file.read()
    list = data.split("\n")
    file.close()
    return list

# Invio dei file alla sandbox per eseguire analisi statica e dinamica
def analyze_files(honeypot_name, analysis_file, files_already_analyzed, honeypot_files_folder):
    # Apertura del file dove verranno salvati gli id delle analisi eseguite
    text_file = open(analysis_file, 'a')
    # Apertura del file dove verranno salvati i nomi dei binari già analizzati
    text_file_binaries = open(files_already_analyzed, 'a')

    # Recupero della lista dei sample già analizzati
    files_already_analyzed_list = get_files_already_analyzed(files_already_analyzed)

    # Debug
    count = 1

    for filename in os.listdir(honeypot_files_folder):
        if filename not in files_already_analyzed_list:
            # Debug
            print(honeypot_name + ' - ' + str(count) + ' file in analisi: ' + filename)
            count = count + 1

            # Creazione header per la richiesta alla sandbox
            headers = {
                'Authorization': 'Bearer 0978fce771feb88066139a174ce8f2d5f08a53d6'
            }

            # Creazione del campo files per la richiesta alla sandbox
            files = {
                'file': open(honeypot_files_folder + '/' + filename, 'rb'),
                '_json': (None, '{"kind":"file","interactive":false}'),
            }

            # url per la richiesta alla sandbox
            url = 'https://private.tria.ge/api/v0/samples'

            try:
                # POST
                response = requests.post(url, headers=headers, files=files)
                # Salvataggio dell'analisi eseguita in formato json
                json_data = json.loads(response.text)

                # Scrittura dell'id dell'analsi eseguita
                text_file.write(json_data.get('id') + '\n')
                # Scrittura del nome del binario di cui è stata effettuata l'analisi
                text_file_binaries.write(filename + '\n')
            except:
                print("Qualcosa è andato storto con l'analisi del file: " + filename)

    # Chiusura dei file precedentemente aperti
    text_file.close()
    text_file_binaries.close()

def main():
    honeypot_name = str(sys.argv[1])
    honeypot_selection(honeypot_name)

if __name__ == "__main__":
    main()

__author__ = "Carlo Pannullo"
