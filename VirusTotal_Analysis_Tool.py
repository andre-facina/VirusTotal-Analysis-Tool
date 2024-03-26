#!/usr/bin/env python3
#VirusTotal analysis tool, the idea is use this tool to check if the files, domains or url are malicious whithout the need to go to the VirtusTotal Website. This script uses the VirusTotal API KEY, you need to create an account in the VirtusTotal website. Using this script you will be able to automate the malicious files verification.

# chmod +x ./VirusTotal_Analysis_Tool.py 
# ./VirusTotal_Analysis_Tool.py --help to see the options

# Author: André Facina

import argparse
import requests
import time

# Replace API_KEY
API_KEY = 'CHANGEIT'
VIRUSTOTAL_FILE_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
VIRUSTOTAL_URL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
VIRUSTOTAL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'


def scan_file(file_path):
    with open(file_path, 'rb') as file:
        files = {'file': file}
        params = {'apikey': API_KEY}
        response = requests.post(VIRUSTOTAL_FILE_SCAN_URL, files=files, params=params)
        if response.status_code == 200:
            return response.json()
        else:
            return {'error': f'Failed to scan file: {response.text}'}

# For URL and Domains I didn't tested yet, maybe it is not working
def scan_url(url):
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(VIRUSTOTAL_URL_SCAN_URL, data=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': f'Failed to scan URL: {response.text}'}

# Function for report, returns the json
def get_file_report(resource):
    params = {'apikey': API_KEY, 'resource': resource}
    response = requests.get(VIRUSTOTAL_REPORT_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        return {'error': f'Failed to get file report: {response.text}'}

# Function to print the report
def print_analysis_results(report):
    if 'error' in report:
        print(report['error'])
    else:
        print("\nAnalysis Report:")
        print("---------------------------------------------------------------------")
        if report.get('positives', 0) > 0:
            print(f"Positives: {report['positives']}")
            print(f"Total: {report['total']}")
            print(f"Scan Date: {report['scan_date']}")
            print("\nScan Results:")
            for antivirus, result in report['scans'].items():
                if result['detected']:
                    print(f"{antivirus}: Detected - {result['result']}, Version - {result['version']}")
        else:
            print("No positives found. File is clean according to all antivirus engines.")
        print("---------------------------------------------------------------------")


def main():
    parser = argparse.ArgumentParser(description='VirusTotal analysis tool')
    parser.add_argument('-f', '--file', help='File path to analyze')
    parser.add_argument('-u', '--url', help='URL to analyze NOT TESTED')
    args = parser.parse_args()

    if args.file:
        file_path = args.file
        result = scan_file(file_path)
        if 'error' in result:
            print(result['error'])
        else:
            scan_id = result['scan_id']
            print(f"Scan ID for file '{file_path}': {scan_id}")

    elif args.url:
        url = args.url
        result = scan_url(url)
        if 'error' in result:
            print(result['error'])
        else:
            scan_id = result['scan_id']
            print(f"Scan ID for URL '{url}': {scan_id}")

    # This will check if the result is ready each 10 seconds, if so will print the result
    while True:
        if 'scan_id' in locals():
            print("Fetching analysis report...")
            report = get_file_report(scan_id)
            if 'verbose_msg' in report and report['verbose_msg'] == 'Scan finished, information embedded':
                print_analysis_results(report)
                break
        time.sleep(10)


if __name__ == '__main__':
    main()

