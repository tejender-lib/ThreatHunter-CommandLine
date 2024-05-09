import os
import requests

def is_valid_domain(domain):
    return domain.strip() != ""

def scan_file(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}

    try:
        with open(file_path, 'rb') as file:
            files = {'file': file}
            response = requests.post(url, files=files, params=params)
            response.raise_for_status()  
            return response.json()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

def get_scan_report(resource, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': resource}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  
        return response.json()
    except Exception as e:
        print(f"An error occurred: {e}")

def scan_domain(domain, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/scan'
    params = {'apikey': api_key, 'url': domain}

    try:
        response = requests.post(url, params=params)
        response.raise_for_status()  
        return response.json()
    except Exception as e:
        print(f"An error occurred: {e}")

def get_domain_report(resource, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params = {'apikey': api_key, 'resource': resource}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  
        return response.json()
    except Exception as e:
        print(f"An error occurred: {e}")

def print_threathunter_banner():
    print("\033[1;37;40m" + ".S    S.    .S       S.    .S_sSSs    sdSS_SSSSSSbs    sSSs   .S_sSSs     " + "\033[0m")
    print("\033[1;37;40m" + ".SS    SS.  .SS       SS.  .SS~YS%%b   YSSS~S%SSSSSP   d%%SP  .SS~YS%%b   " + "\033[0m")
    print("\033[1;37;40m" + "S%S    S%S  S%S       S%S  S%S   `S%b       S%S       d%S'    S%S   `S%b  " + "\033[0m")
    print("\033[1;37;40m" + "S%S    S%S  S%S       S%S  S%S    S%S       S%S       S%S     S%S    S%S  " + "\033[0m")
    print("\033[1;37;40m" + "S%S SSSS%S  S&S       S&S  S%S    S&S       S&S       S&S     S%S    d*S  " + "\033[0m")
    print("\033[1;37;40m" + "S&S  SSS&S  S&S       S&S  S&S    S&S       S&S       S&S_Ss  S&S   .S*S  " + "\033[0m")
    print("\033[1;37;40m" + "S&S    S&S  S&S       S&S  S&S    S&S       S&S       S&S~SP  S&S_sdSSS   " + "\033[0m")
    print("\033[1;37;40m" + "S&S    S&S  S&S       S&S  S&S    S&S       S&S       S&S     S&S~YSY%b   " + "\033[0m")
    print("\033[1;37;40m" + "S*S    S*S  S*b       d*S  S*S    S*S       S*S       S*b     S*S   `S%b  " + "\033[0m")
    print("\033[1;37;40m" + "S*S    S*S  S*S.     .S*S  S*S    S*S       S*S       S*S.    S*S    S%S  " + "\033[0m")
    print("\033[1;37;40m" + "S*S    S*S   SSSbs_sdSSS   S*S    S*S       S*S        SSSbs  S*S    S&S  " + "\033[0m")
    print("\033[1;37;40m" + "SSS    S*S    YSSP~YSSY    S*S    SSS       S*S         YSSP  S*S    SSS  " + "\033[0m")
    print("\033[1;37;40m" + "       SP                  SP               SP                SP          " + "\033[0m")
    print("\033[1;37;40m" + "       Y                   Y                Y                 Y           " + "\033[0m")
    print("\033[1;37;40m" + "                             ThreatHunter                                 " + "\033[0m\n")
                                                                          

print_threathunter_banner()


def scan_input(api_key):
    choice = input("\n[-] Tool Created by tejenderthakur (tejender-lib)\n\n[::] Select An Scan\n\n[::][01] To scan a file: \n[::][02] To scan single domain: \n[::][03] To scan multiple domains:\n\n[-]Select an option:")
 
    if choice == '01':
        file_path = input("\nEnter the path to the file or folder to scan: ")
        if not os.path.exists(file_path):
            print("File or folder not found.")
            return
        if os.path.isfile(file_path):
            print(f"Scanning file: {file_path}")
            scan_result = scan_file(file_path, api_key)
            if scan_result and 'resource' in scan_result:
                resource = scan_result['resource']
                print(f"File submitted for scanning. Resource: {resource}")

                report = get_scan_report(resource, api_key)
                if report:
                    if 'positives' in report:
                        positives = report['positives']
                        total = report['total']
                        print(f"Scan results: {positives}/{total} scanners detected the file as malicious.")
                    else:
                        print("Scan report not available yet. Try again later.")
                else:
                    print("Failed to retrieve scan report.")
            else:
                print("Failed to submit file for scanning.")
        elif os.path.isdir(file_path):
            print(f"Scanning folder: {file_path}")
            for root, _, files in os.walk(file_path):
                for file_name in files:
                    file_to_scan = os.path.join(root, file_name)
                    print(f"Scanning file: {file_to_scan}")
                    scan_result = scan_file(file_to_scan, api_key)
                    if scan_result and 'resource' in scan_result:
                        resource = scan_result['resource']
                        print(f"File submitted for scanning. Resource: {resource}")

                        report = get_scan_report(resource, api_key)
                        if report:
                            if 'positives' in report:
                                positives = report['positives']
                                total = report['total']
                                print(f"Scan results: {positives}/{total} scanners detected the file as malicious.")
                            else:
                                print("Scan report not available yet. Try again later.")
                        else:
                            print("Failed to retrieve scan report.")
                    else:
                        print("Failed to submit file for scanning.")
        else:
            print("Invalid file or folder.")
    elif choice == '02':
        domain = input("\nEnter the domain to scan: ")
        if not is_valid_domain(domain):
            print("Invalid domain.")
            return
        print(f"Scanning domain: {domain}")
        scan_result = scan_domain(domain, api_key)
        if scan_result and 'resource' in scan_result:
            resource = scan_result['resource']
            print(f"Domain submitted for scanning. Resource: {resource}")

            report = get_domain_report(resource, api_key)
            if report:
                if 'positives' in report:
                    positives = report['positives']
                    total = report['total']
                    if positives > 0:
                        print(f"Scan results: {positives}/{total} scanners detected the domain as malicious.")
                    else:
                        print("No malicious indicators found. The domain is clean.")
                else:
                    print("No malicious indicators found. The domain is clean.")
            else:
                print("Failed to retrieve scan report.")
        else:
            print("Failed to submit domain for scanning.")
    elif choice == '03':
        urls_input = input("\nEnter the URLs (separated by comma): ")
        urls = [url.strip() for url in urls_input.split(',')]
        for url in urls:
            if not is_valid_domain(url):
                print(f"Invalid URL: {url}")
                continue
            print(f"Scanning URL: {url}")
            scan_result = scan_domain(url, api_key)
            if scan_result and 'resource' in scan_result:
                resource = scan_result['resource']
                print(f"URL submitted for scanning. Resource: {resource}")

                report = get_domain_report(resource, api_key)
                if report:
                    if 'positives' in report:
                        positives = report['positives']
                        total = report['total']
                        if positives > 0:
                            print(f"Scan results: {positives}/{total} scanners detected the URL as malicious.")
                        else:
                            print("No malicious indicators found. The URL is clean.")
                    else:
                        print("No malicious indicators found. The URL is clean.")
                else:
                    print("Failed to retrieve scan report.")
            else:
                print(f"Failed to submit URL for scanning: {url}")
    else:
        print("Invalid choice.")

def main():
    api_key = input("Enter your VirusTotal API key: ")

    if not api_key:
        print("API key is required.")
        return

    scan_input(api_key)

if __name__ == "__main__":
    main()
