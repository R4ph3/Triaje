import requests
import json,time
import argparse

KEY="debea831911d6acfc5b757b6741499b91890f0e6c10c5e931ecee50008ffed99609bacb9532a744b"
file = "target-ips.txt"
def send_req(ip, file):
    url = 'https://api.abuseipdb.com/api/v2/check'
    querystring = {
            'ipAddress': ip
    }
    headers = {
            'Accept': 'application/json',
            'Key': KEY
    }
    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    time.sleep(5)
    if(response.headers['X-RateLimit-Remaining'] == 0 or response.status_code == 429):
        print("Rate Limiting reached. Got 429 error!")
        exit()
    response = json.loads(response.text)
    try:
        if(response['errors'] is not None):
            return "AbuseIPDB ha devuelto un error para " + ip + " "+ response['errors'][0]['detail']
    except:
        if(file == "target-ips.txt"):
            return "La IP "+ip+" se ha reportado "+ str(response['data']['totalReports']) + " veces. Su ISP: "+ str(response['data']['isp']) + ". Confidence Score: "+ str(response['data']['abuseConfidenceScore']) + ". WhiteListing status: "+str(response['data']['isWhitelisted']) + ". Ultimo reporte: " + str(response['data']['lastReportedAt'])


print("---------ABUSEDIP-------")
ips = (open(file).read()).split("\n")
if (file == "target-ips.txt"):
    for i in ips:
        resp = send_req(i, file)
        print(resp)


