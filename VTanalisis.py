import argparse
import time
from pathlib import Path
import requests
import re
import pandas as pd
import json
import base64
import os
import hashlib






API_KEY = "12e739206c9c3bb613bbe6abd04f7f79f055b9413cdcc88ef5ee40680552ffe0"



# Inicia el parseador, mi parse 
parser = argparse.ArgumentParser(description="Automatizador de URL e IP de VirusTotal V3")
parser.add_argument("-s", "--single-entry", help="ip o url a analizar")
parser.add_argument("-i", "--ip-list", help="analisis de fichero de ip")
parser.add_argument("-u", "--url-list", help="analisis de fichero de url")
parser.add_argument("-V", "--version", help="enseñame la version", action="store_true")

#Parseador finaliza


# Empieza el dataframe
dataframe = []

report_time = ' '



def urlReport(arg):

    target_url = arg

    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")


    url = "https://www.virustotal.com/api/v3/urls/" + url_id


    headers = {
        "Accept": "application/json",
        "x-apikey": API_KEY
    }

    response = requests.request("GET", url, headers=headers)

    decodedResponse = json.loads(response.text)

    timeStamp = time.time()

    global report_time

    report_time = time.strftime('%c', time.localtime(timeStamp))
    
    global dataframe

    epoch_time = (decodedResponse["data"]["attributes"]["last_analysis_date"])
    
    time_formatted = time.strftime('%c', time.localtime(epoch_time))

    UrlId_unEncrypted = ("http://" + target_url + "/")

    def encrypt_string(hash_string):
        sha_signature = \
            hashlib.sha256(hash_string.encode()).hexdigest()
        return sha_signature

    hash_string = UrlId_unEncrypted
    
    sha_signature = encrypt_string(hash_string)
 
    vt_urlReportLink = ("https://www.virustotal.com/gui/url/" + sha_signature)

    filteredResponse = (decodedResponse["data"]["attributes"])

    keys_to_remove = [
        "last_http_response_content_sha256", 
        "last_http_response_code",
        "last_analysis_results",
        "last_final_url", 
        "last_http_response_content_length", 
        "url", 
        "last_analysis_date", 
        "tags", 
        "last_submission_date", 
        "threat_names",
        "last_http_response_headers",
        "categories",
        "last_modification_date",
        "title",
        "outgoing_links",
        "first_submission_date",
        "total_votes",
        "type",
        "id",
        "links",
        "trackers",
        "last_http_response_cookies",
        "html_meta"
        ]

    for key in keys_to_remove:
      filteredResponse.pop(key, None)

    dataframe = pd.DataFrame.from_dict(filteredResponse, orient="index")
    
    dataframe.columns = [target_url]

    community_score = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])

    total_vt_reviewers = (decodedResponse["data"]["attributes"]["last_analysis_stats"]["harmless"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["malicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["suspicious"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["undetected"])+(decodedResponse["data"]["attributes"]["last_analysis_stats"]["timeout"])

    community_score_info = str(community_score)+ ("/") + str(total_vt_reviewers) + ("  : TRIAJE : malicioso")

    dataframe.loc['virustotal report',:] = vt_urlReportLink

    dataframe.loc['community score',:] = community_score_info

    dataframe.loc['last_analysis_date',:] = time_formatted

    dataframe.sort_index(inplace = True)

    global html

    html = dataframe.to_html(render_links=True, escape=False)






def urlReportLst(arg):
    print("Option 2:")
    with open(arg) as fcontent:
        fstring = fcontent.readlines()
    pattern = re.compile(r'(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*)?')

    lst=[]

    for line in fstring:
        lst.append(pattern.search(line)[0])

    print("Valid URLs ")
    print(lst, "\n")

    global dataframe
    






def urlReportIPLst(arg):
    print("Option 3:")
    with open(arg) as fh:
        string = fh.readlines()

    pattern = re.compile(r'(^0\.)|(^10\.)|(^100\.6[4-9]\.)|(^100\.[7-9]\d\.)|(^100\.1[0-1]\d\.)|(^100\.12[0-7]\.)|(^127\.)|(^169\.254\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.0\.0\.)|(^192\.0\.2\.)|(^192\.88\.99\.)|(^192\.168\.)|(^198\.1[8-9]\.)|(^198\.51\.100\.)|(^203.0\.113\.)|(^22[4-9]\.)|(^23[0-9]\.)|(^24[0-9]\.)|(^25[0-5]\.)')

    Private_IPs =[]
    Public_IPs=[]

    for line in string:
        line = line.rstrip()
        result = pattern.search(line)
  
        if result:
            Private_IPs.append(line)
    
        else:
            Public_IPs.append(line)
    
    
    

    print("Ips Privadas")
    print(Private_IPs)
    print("Ips Publicas")
    print(Public_IPs)

    
    
    pattern2 =re.compile(r'(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])')
    
    valid2 =[]
    invalid2=[]

    for i in Public_IPs:
        i = i.rstrip()
        result = pattern2.search(i)
        
        if result:
            valid2.append(i)
        else:
            invalid2.append(i)

    print("IPs publicas validas")
    print(valid2, "\n")


    global dataframe
    global html
    
    html_table_array = []

    for i in valid2:
        urlReport(i)
        print(dataframe, "\n")
        html_table_array.append(html)

    html = html_table_array










args = parser.parse_args()


if args.single_entry:
    urlReport(args.single_entry)
    print(dataframe)
    
elif args.ip_list:
    urlReportIPLst(args.ip_list)
    
elif args.url_list:
    urlReportLst(args.url_list)
    
elif args.version:
    print("VT API v3 IP address and URL analysis 2.0")
else:
    print("uso: vt-ip-url-analysis.py [-h] [-s ENTRADA_UNICA] [-i LISTA_IP] [-u LISTA_URL] [-V]")

