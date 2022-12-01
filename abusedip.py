import requests
import argparse
import json,time
KEY="debea831911d6acfc5b757b6741499b91890f0e6c10c5e931ecee50008ffed99609bacb9532a744b"
def send_req(ip,format):
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
            return "AbuseIPDB returned an error for " + ip + " "+ response['errors'][0]['detail']
    except:
        if(format == "readable"):
            return "The IP "+ip+" is reported "+ str(response['data']['totalReports']) + " times. It's ISP: "+ str(response['data']['isp']) + ". Confidence Score: "+ str(response['data']['abuseConfidenceScore']) + ". WhiteListing status: "+str(response['data']['isWhitelisted']) + ". Last Reported: " + str(response['data']['lastReportedAt'])
        if(format == "csv"):
            return "" +ip+","+ str(response['data']['totalReports']) + ","+ str(response['data']['isp']) + ","+ str(response['data']['abuseConfidenceScore']) + ","+str(response['data']['isWhitelisted']) + "," + str(response['data']['lastReportedAt'])
        if(format == "json"):
            return response
parser = argparse.ArgumentParser()
parser.add_argument('--format', help="This is REQUIRED! Use `readable` for readable format or Use `csv` for CSV format or Use `json` for JSON format.")
parser.add_argument('--file', help="This is OPTIONAL if you use ip parameter, otherwise required. Specify the file with IPs. Please format the file to include one IP per line.")
parser.add_argument('--ip', help="This is OPTIONAL if you use file parameter, otherwise required. This is IP you want to query the AbuseDB with.")
args = parser.parse_args()
if(args.format != "readable" and args.format != "csv" and args.format != "json") and (args.ip is not None or args.file is not None):
    parser.print_help()
else:
    if(args.file is not None):
        ips = (open(args.file).read()).split("\n")
        if args.format == "csv":
            print("ip,total_reports,isp,abuse_confidence,is_whitelisted,last_reported_at")
        for i in ips:
            resp = send_req(i,args.format)
            if "error" not in resp:
                print(resp)
    elif(args.ip is not None):
        if args.format == "csv":
            print("ip,total_reports,isp,abuse_confidence,is_whitelisted,last_reported_at")
        resp = send_req(args.ip, args.format)
        if "error" not in resp:
            print(resp)
