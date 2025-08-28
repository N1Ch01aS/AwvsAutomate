#!/usr/bin/env python3
# Unoficial Acunetix CLI version for automation

import requests
import json
import argparse
import validators
import textwrap
import sys
import time
import os
from datetime import datetime

requests.packages.urllib3.disable_warnings()

with open('config.json') as config_file:
    config = json.load(config_file)

tarurl = config['url'] + ":" + str(config['port'])
headers = {
    "X-Auth": config['api_key'],
    "Content-Type": "application/json"
}


def create_scan(target_url, scan_type):
    scan_profile = {
        "full": "11111111-1111-1111-1111-111111111111",
        "high": "11111111-1111-1111-1111-111111111112",
        "weak": "11111111-1111-1111-1111-111111111115",
        "crawl": "11111111-1111-1111-1111-111111111117",
        "xss": "11111111-1111-1111-1111-111111111116",
        "sql": "11111111-1111-1111-1111-111111111113",
    }
    profile_id = scan_profile.get(scan_type, scan_profile['full'])

    def add_task(url=''):
        data = {"address": url, "description": url, "criticality": "10"}
        try:
            response = requests.post(tarurl + "/api/v1/targets", data=json.dumps(data), headers=headers, timeout=30,
                                     verify=False)
            result = json.loads(response.content)
            return result['target_id']
        except Exception as e:
            print(str(e))
            return

    url = tarurl + "/api/v1/scans"

    print("[*] Running scan on : " + str(target_url))

    data = {
        "target_id": add_task(target_url),
        "profile_id": profile_id,
        "schedule": {"disable": False, "start_date": None, "time_sensitive": False},
    }

    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)
    if response.status_code == 201:
        scan_id = response.json().get('scan_id')
        print(f"[+] Scan started successfully. Scan ID: {scan_id}")
        return scan_id
    else:
        print(f"[-] Failed to start scan. Status code: {response.status_code}")
        return None


def scan_targets_from_file(file_path, scan_type):
    try:
        with open(file_path) as f:
            targets = f.readlines()
        targets = [x.strip() for x in targets]
        scan_ids = []
        for target in targets:
            if validators.url(target):
                scan_id = create_scan(target, scan_type)
                if scan_id:
                    scan_ids.append(scan_id)
            else:
                print("[!] Invalid URL: " + target)
        return scan_ids
    except Exception as e:
        print("[!] Error reading file: " + str(e))
        return []


def stop_scan(scan_id):
    url = tarurl + "/api/v1/scans/" + str(scan_id) + "/abort"
    response = requests.post(url, headers=headers, verify=False)
    if response.status_code == 200:
        print(f"[-] Scan stopped successfully. Scan ID: {scan_id}")
    else:
        print(f"[-] Failed to stop scan. Status code: {response.status_code}")


def stop_specific_scan(target):
    url = tarurl + "/api/v1/scans?q=status:processing;"
    response = requests.get(url, headers=headers, verify=False)
    scans = response.json()["scans"]
    for scan in scans:
        if target == scan["target"]["description"]:
            stop_scan(scan["scan_id"])


def stop_all_scans():
    url = tarurl + "/api/v1/scans?q=status:processing;"
    response = requests.get(url, headers=headers, verify=False)
    scans = response.json()["scans"]
    for scan in scans:
        stop_scan(scan["scan_id"])


def list_scans():
    """List all scans with their status"""
    url = tarurl + "/api/v1/scans"
    response = requests.get(url, headers=headers, verify=False)
    if response.status_code == 200:
        scans = response.json().get('scans', [])
        print("\n[+] Available Scans:")
        print("-" * 80)
        print(f"{'Scan ID':<20} {'Target':<30} {'Status':<15} {'Started':<20}")
        print("-" * 80)
        for scan in scans:
            print(
                f"{scan.get('scan_id', 'N/A'):<20} {scan.get('target', {}).get('description', 'N/A')[:28]:<30} {scan.get('status', 'N/A'):<15} {scan.get('start_date', 'N/A')[:19]:<20}")
        print("-" * 80)
        return scans
    else:
        print(f"[-] Failed to list scans. Status code: {response.status_code}")
        return []


def list_reports():
    """List all reports with their status and download links"""
    url = tarurl + "/api/v1/reports"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code == 200:
        reports_data = response.json()
        reports = reports_data.get('reports', [])

        print("\n[+] Available Reports:")
        print("-" * 120)
        print(f"{'Report ID':<40} {'Scan ID':<40} {'Report Type':<20} {'Status':<12} {'Download Links'}")
        print("-" * 120)

        for report in reports:
            report_id = report.get('report_id', 'N/A')
            template_name = report.get('template_name', 'N/A')
            status = report.get('status', 'N/A')

            # Get scan IDs from source
            scan_ids = report.get('source', {}).get('id_list', [])
            scan_id_str = ', '.join(scan_ids) if scan_ids else 'N/A'

            # Get download links
            download_links = report.get('download', [])
            download_str = ', '.join(download_links) if download_links else 'No download links'

            print(f"{report_id:<40} {scan_id_str:<40} {template_name:<20} {status:<12} {download_str}")

        print("-" * 120)
        return reports
    else:
        print(f"[-] Failed to list reports. Status code: {response.status_code}")
        return []


def generate_report(scan_id, report_type='developer'):
    """Generate a report for a specific scan"""

    report_types = {
        'developer': '11111111-1111-1111-1111-111111111111',
        'comprehensive': '11111111-1111-1111-1111-111111111126'
    }

    type_id = report_types.get(report_type, report_types['developer'])

    data = {
        "template_id": type_id,
        "source": {
            "list_type": "scans",
            "id_list": [scan_id]
        }
    }

    url = tarurl + "/api/v1/reports"
    response = requests.post(url, headers=headers, data=json.dumps(data), verify=False)

    if response.status_code == 201:
        report_id = response.json().get('report_id')
        print(f"[+] {report_type.capitalize()} report generation started. Report ID: {report_id}")
        return report_id
    else:
        print(f"[-] Failed to generate report. Status code: {response.status_code}")
        print(f"[-] Response content: {response.text}")
        return None


def download_report_by_id(report_id, output_dir=None):
    """Download a specific report by report ID"""
    # Check report status first
    status_url = tarurl + f"/api/v1/reports/{report_id}"
    response = requests.get(status_url, headers=headers, verify=False)

    if response.status_code != 200:
        print(f"[-] Failed to get report status. Status code: {response.status_code}")
        return False

    report_data = response.json()
    report_status = report_data.get('status')

    if report_status != 'completed':
        print(f"[-] Report is not ready yet. Current status: {report_status}")
        return False

    # Get download links
    download_links = report_data.get('download', [])
    if not download_links:
        print(f"[-] No download links available for report {report_id}")
        return False

    # Set output directory
    if not output_dir:
        output_dir = os.getcwd()
    elif not os.path.exists(output_dir):
        os.makedirs(output_dir)

    downloaded_files = []

    # Download all available formats
    for download_link in download_links:
        # Extract filename from download link
        filename = download_link.split('/')[-1]
        output_path = os.path.join(output_dir, filename)

        # Download the report
        download_url = tarurl + download_link
        response = requests.get(download_url, headers=headers, verify=False, stream=True)

        if response.status_code == 200:
            with open(output_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            downloaded_files.append(output_path)
            print(f"[+] Downloaded: {output_path}")
        else:
            print(f"[-] Failed to download {filename}. Status code: {response.status_code}")

    return len(downloaded_files) > 0


def download_reports_by_scan_id(scan_id, output_dir=None):
    """Download all reports for a specific scan ID"""
    # Get all reports
    url = tarurl + "/api/v1/reports"
    response = requests.get(url, headers=headers, verify=False)

    if response.status_code != 200:
        print(f"[-] Failed to get reports list. Status code: {response.status_code}")
        return False

    reports = response.json().get('reports', [])
    found_reports = False

    # Set output directory
    if not output_dir:
        output_dir = os.getcwd()
    elif not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Find reports for the specified scan ID
    for report in reports:
        scan_ids = report.get('source', {}).get('id_list', [])
        if scan_id in scan_ids:
            found_reports = True
            report_id = report.get('report_id')
            report_status = report.get('status')

            if report_status == 'completed':
                print(f"[*] Downloading reports for scan {scan_id} (Report ID: {report_id})")
                download_report_by_id(report_id, output_dir)
            else:
                print(f"[-] Report {report_id} for scan {scan_id} is not ready. Status: {report_status}")

    if not found_reports:
        print(f"[-] No reports found for scan ID: {scan_id}")
        return False

    return True


def wait_for_scan_completion(scan_id, check_interval=30):
    """Wait for a scan to complete and return the status"""
    print(f"[*] Waiting for scan {scan_id} to complete...")

    while True:
        url = tarurl + f"/api/v1/scans/{scan_id}"
        response = requests.get(url, headers=headers, verify=False)

        if response.status_code == 200:
            scan_data = response.json()
            status = scan_data.get('status')
            progress = scan_data.get('current_session', {}).get('scan_session', {}).get('progress', 0)

            print(f"[*] Scan status: {status}, Progress: {progress}%")

            if status in ['completed', 'failed', 'aborted', 'canceled']:
                print(f"[*] Scan {status}.")
                return status

            time.sleep(check_interval)
        else:
            print(f"[-] Failed to get scan status. Status code: {response.status_code}")
            return None


if __name__ == "__main__":
    banner = r"""
                                       __  _                 ___
          ____ ________  ______  ___  / /_(_)  __      _____/ (_)
         / __ `/ ___/ / / / __ \/ _ \/ __/ / |/_/_____/ ___/ / /
        / /_/ / /__/ /_/ / / / /  __/ /_/ />  </_____/ /__/ / /
        \__,_/\___/\__,_/_/ /_/\___/\__/_/_/|_|      \___/_/_/

                           -: by N1Ch01aS :-
    """
    print(banner)

    if len(sys.argv) < 2:
        print("usage: AwvsAutomate.py [-h]")

    parser = argparse.ArgumentParser(description="Launch or stop a scan using Acunetix API")
    subparsers = parser.add_subparsers(dest="action", help="Action to perform")

    # Start sub-command
    start_parser = subparsers.add_parser("scan", help="Launch a scan use scan -h")
    start_parser.add_argument("-p", "--pipe", action='store_true', help='Read from pipe')
    start_parser.add_argument("-d", "--domain", help="Domain to scan")
    start_parser.add_argument("-f", "--file", help="File containing list of URLs to scan")
    start_parser.add_argument("-t", "--type", choices=["full", "high", "weak", "crawl", "xss", "sql"], default="full",
                              help=textwrap.dedent('''\
                        High Risk Vulnerabilities Scan,
                        Weak Password Scan,
                        Crawl Only,
                        XSS Scan,
                        SQL Injection Scan,
                        Full Scan (by default)'''))

    # Stop sub-command
    stop_parser = subparsers.add_parser("stop", help="Stop a scan")
    stop_parser.add_argument("-d", "--domain", help="Domain of the scan to stop")
    stop_parser.add_argument("-a", "--all", action='store_true', help="Stop all Running Scans")

    # List sub-command
    list_parser = subparsers.add_parser("list", help="List all scans")

    # Report sub-command - Modified with new options
    report_parser = subparsers.add_parser("report", help="Generate and download reports")
    report_parser.add_argument("-S", "--scan-id", help="Scan ID to generate report for")
    report_parser.add_argument("-G", "--generate", choices=["developer", "comprehensive"], default="developer",
                               help="Type of report to generate: developer or comprehensive")
    report_parser.add_argument("-D", "--download", nargs='?', const='',
                               help="Download reports for scan ID (default: current directory)")
    report_parser.add_argument("-l", "--list", action='store_true', help="List all available reports")

    args = parser.parse_args()

    if args.action == "scan":
        if args.domain:
            if validators.url(args.domain):
                create_scan(args.domain, args.type)
            else:
                print("[!] Invalid URL: " + args.domain)

        elif args.file:
            scan_targets_from_file(args.file, args.type)

        elif args.pipe:
            input_data = sys.stdin.read().split('\n')
            for url in input_data:
                if validators.url(url):
                    create_scan(url, args.type)

        else:
            print("[!] Must provide either domain or file containing list of targets \nFor Help: AwvsAutomate.py scan -h")

    elif args.action == "stop":
        if args.domain:
            stop_specific_scan(args.domain)
        elif args.all == True:
            stop_all_scans()
        else:
            print("[!] Must provide either domain or stop all flag \nFor Help: AwvsAutomate.py stop -h")

    elif args.action == "list":
        list_scans()

    elif args.action == "report":
        if args.list:
            # List all reports
            list_reports()

        elif args.download is not None:
            # Download reports for scan ID
            if not args.scan_id:
                print("[!] Must provide scan ID with -S option when using -D")
            else:
                output_dir = args.download if args.download != '' else None
                download_reports_by_scan_id(args.scan_id, output_dir)

        elif args.scan_id:
            # Generate report
            report_id = generate_report(args.scan_id, args.generate)
            if report_id:
                print("[*] Report generated successfully. Use -D option to download it.")
            else:
                print("[-] Failed to generate report.")

        else:
            print("[!] Must provide either -l, -S with -G, or -S with -D \nFor Help: AwvsAutomate.py report -h")
