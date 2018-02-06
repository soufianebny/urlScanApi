# urlScanApi
Using geoIP (http://freegeoip.net) and Virustotal (http://virustotal.com) APIs to check and scan URLs

# To execute this script you need:
- The URL (format: www.example.xx) you want to test.
- The VirusTotal Token (called: APIKEY). Register there to obtain one.

## GeoIP:
Checks if the URL originates from France, if it is the case, continues with virustotal scan, otherwise stops.

## VirusTotal:
First checks if the URL has already been analysed or not:
- If yes (depends on a modifiable threshold), retrieves the report and shows the result.
- If not (analysis is too old), launchs a new scan request, retrieves the report and shows the result.