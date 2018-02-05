import requests
import json
import datetime
import time

# format: www.example.ab"
domainName = "www.passeportformation.eu"

########################## GeoIP ##########################
# need url
###########################################################
def geoIP():
    geoIPServer = "http://freegeoip.net/json/"+domainName
    geoResponse = requests.get(geoIPServer,verify=True)
    if geoResponse.status_code == 200:
        jsonData = json.loads(geoResponse.content)      # load json response to a dict
        # test whether domainName is in France
        if jsonData["country_name"] == "France":
            print("GeoIP result: "+domainName+" is based in France")
            virusTotalRetrieve() #next step
        else:
            print("GeoIP result: "+domainName+" is not based in France")
    else:
        geoResponse.raise_for_status()

###################### VirusTotal #########################
#need url and apikey
###########################################################
apikey = 'faced81f396711bc4706b31392a40c0d7f3ffbc01d13e521b9e48ed9c7879da6'

"""virusTotal account:
zepufeho@ugimail.net
pass: zepufeho@ugimail.netzepufeho@ugimail.net

response types:
response_code = 0 : url is not present in the dataset of VirusTotal
response_code = -2 : url is still queued for analysis 
response_code = 1 : url report could be retrieved 
"""

def virusTotalRetrieve():
    # first, retrieve report and examine if it is new enought
    paramsReport = {'apikey': apikey,'resource': domainName}
    reportResponse = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=paramsReport)
    if reportResponse.status_code == 200:
        reportJson = reportResponse.json()
        if reportJson["response_code"] !=0:
            #extract Last analysis date:
            dateAnalysis = datetime.datetime.strptime((reportJson["scan_date"]).split(" ")[0],'%Y-%m-%d').date()
            #today date:
            dateToday = datetime.datetime.now().date()
            threshold = str(1)       #threshold in months
            if str(dateToday - dateAnalysis) >= threshold:   #test if report is >= threshold
                print ("Last VirusTotal's report is older than "+str(threshold)+" month(s) ("+str(dateAnalysis))+"), will scan for a new one..."
                virusTotalScan()
            else:
                print ("Last VirusTotal's report is less than "+str(threshold)+" month(s) old ("+str(dateAnalysis)+")")
                if reportJson["positives"]==0 :      # if there is no negative vote
                    print ("\tAnalyse result: site is clean, suspected "+ str(reportJson["positives"]) + " time(s).")
                else:
                    print("\tAnalyse result: site is suspected " + str(reportJson["positives"]) + " time(s).")
        else:
            print (domainName + " is not present in the dataset of VirusTotal")
    elif reportResponse.status_code == 204:
        print("API requests exceeded ")

def virusTotalScan():
    #if report is old, scan for a new one (may take several minutes/hours before report is ready)
    #after this, a retrieve report operation must be executed to retrieve it
    params = {'apikey': apikey, 'url': domainName}
    virusTotalResponse = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)
    if virusTotalResponse.status_code == 200:
        DataJson = virusTotalResponse.json()
        if DataJson["response_code"] == 1:
            print("VirusTotal's report is ready, will be retrieved in 5 seconds...")
            time.sleep(5)      #wait 5 sec
            virusTotalRetrieve()
        elif DataJson["response_code"] == -2:
            print("VirusTotal's report is not yet ready...waiting 5 minutes")
            time.sleep(300)     #wait 5 min
            virusTotalRetrieve()
        elif DataJson["response_code"] == 0:
            print(domainName + " is not present in the dataset of VirusTotal")
    elif virusTotalResponse.status_code == 204:
        print("API requests exceeded ")


#Launch
def main():
    geoIP()

if __name__ == '__main__':
    main()