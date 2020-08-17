"""
    Title:      Sooty
    Desc:       The SOC Analysts all-in-one CLI tool to automate and speed up workflow.
    Author:     Connor Jackson
    Version:    1.3.2
    GitHub URL: https://github.com/TheresAFewConors/Sooty
    This Fork:  https://github.com/RafaelRuales/Sooty
"""

import base64
import hashlib
import re
import json
import time
import socket
import strictyaml
from urllib.parse import unquote
import requests
from ipwhois import IPWhois
import tkinter
from tkinter.filedialog import askopenfilename
from email.parser import BytesParser
from email.policy import default
# from Modules import iplists
# from Modules import phishtank


try:
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")

# linksFoundList = []
# linksRatingList = []
# linksSanitized = []
# linksDict = {}


def mainMenu():
    print("\n What would you like to do? ")
    print(" OPTION 1: Sanitise URL and/or emails for ServiceNow tickets ")
    print(" OPTION 2: Decoders (URLs, SafeLinks, Base64, UNshorten urls) ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing and Sandbox Functions")
    print(" OPTION 6: Phishing Analysis")
    print(" OPTION 7: URL scan")
    print(" OPTION 0: Exit Tool")
    switchMenu(input())


def switchMenu(choice):
    if choice == '1':
        sanitise()
    if choice == '2':
        decoderMenu()
    if choice == '3':
        repChecker()
    if choice == '4':
        dnsMenu()
    if choice == '5':
        hashMenu()
    if choice == '6':
        phishingMenu()
    if choice == '7':
        url_scans()
    if choice == '0':
        exit()
    else:
        mainMenu()


def decoderSwitch(choice):
    if choice == '1':
        url_decoder()
    if choice == '2':
        safelinksDecoder()
    if choice == '3':
        unshortenUrl()
    if choice == '4':
        b64Decoder()
    if choice == '5':
        get_clean_link()
    if choice == '0':
        mainMenu()


def dnsSwitch(choice):
    if choice == '1':
        reverseDnsLookup()
    if choice == '2':
        dnsLookup()
    if choice == '3':
        whoIs()
    if choice == '0':
        mainMenu()


def hashSwitch(choice):
    if choice == '1':
        get_file_hash()
    if choice == '2':
        hash_text()
    if choice == '3':
        vt_check_hash()
    if choice == '4':
        second_write_sandbox()
    if choice == '0':
        mainMenu()


def phishingSwitch(choice):
    if choice == '1':
        get_email_headers()
    if choice == '2':
        analyzeEmailInput()
    # if choice == '4':
    #     phishtankModule()
    else:
        mainMenu()


def sanitise(*args):
    if args:
        print("\nExtracting Headers...\n")
        for k, v in args[0].items():
            v = re.sub(r"\.", "[.]", v)
            print(k, ":", v)
        return
    print('\n' + '-' * 27, ' S A N I T I S E   T O O L ', '-' * 27, sep='\n')
    element = input("Enter URL/Email to sanitize: ").strip()
    sanitised_elem = re.sub(r"\.", "[.]", element)
    print("\n\033[32m Sanitized element:  {} \033[00m".format(sanitised_elem))
    mainMenu()


def decoderMenu():
    print('\n' + '-' * 34, '           D E C O D E R S        ', '-' * 34, sep='\n')
    print(" What would you like to do? ")
    print(" OPTION 1: URL Decoder")
    print(" OPTION 2: Office SafeLinks Decoder")
    print(" OPTION 3: URL unShortener")
    print(" OPTION 4: Base64 Decoder")
    print(" OPTION 5: Get clean link for scanning")
    print(" OPTION 0: Exit to Main Menu")
    decoderSwitch(input())


def url_decoder(*args):
    if args:
        decoded_url = unquote(args[0])
        return decoded_url
    print('\n' + '-' * 23, ' U R L   D E C O D E R ', '-' * 23, sep='\n')
    url = input(' Enter URL: ').strip()
    decoded_url = unquote(url)
    print("\n\033[32m Decoded URL:  {} \033[00m".format(decoded_url))
    decoderMenu()


def safelinksDecoder(*args):
    if args:
        url_from_safelinks(args[0])
        return
    print('\n' + '-' * 36, ' S A F E L I N K S   D E C O D E R  ', '-' * 36, sep='\n')
    url = input(' Enter URL: ').strip()
    link = unquote(url)
    url_from_safelinks(link)


def url_from_safelinks(link):
    mod_link = re.search('(?<=url=)(.*)(?=&data|&amp;data)', link)
    if mod_link is None:
        print("Unable to parse the url")
        return None
    temp_link = re.search('(https?://)(.*?)(/)(.*)', mod_link.group(0))
    bad_chars = re.compile('[^a-zA-Z0-9./]')
    char = bad_chars.search(temp_link.group(2))
    if char is None:
        print('\n\033[32m Decoded URL:  {} \033[00m'.format(mod_link.group(0)))
    else:
        clean_link = list(temp_link.groups())
        swap = bad_chars.sub('', clean_link[1])
        clean_link[1] = swap
        print('\n\033[32m Decoded URL:  {} \033[00m'.format(''.join(clean_link)))


def unshortenUrl():
    print('\n' + '-' * 34, '   U R L   U N S H O R T E N E R  ', '-' * 34, sep='\n')
    link = input(' Enter URL: ').strip()
    req = requests.get(str('https://unshorten.me/s/' + link))
    print("\n\033[32m Full URL:  {} \033[00m".format(req.text))
    decoderMenu()


def b64Decoder():
    print('\n' + '-' * 31, '   B A S E 6 4 D E C O D E R   ', '-' * 31, sep='\n')
    url = input(' Enter Base64 Encoded String: ').strip()
    try:
        b64 = str(base64.b64decode(url))
        a = re.split("'", b64)[1]
        print(" B64 String:     " + url)
        print(" Decoded String: " + a)
    except:
        print(' No Base64 Encoded String Found')
    decoderMenu()


def get_clean_link():
    print('\n' + '-' * 24, '   C L E A N   L I N K   ', '-' * 24, sep='\n')
    url = input(' Enter URL: ').strip()
    decoded_url = url_decoder(url)
    safelinksDecoder(decoded_url)
    mainMenu()


def repChecker():
    print('\n' + '-' * 35, ' R E P U T A T I O N     C H E C K ', '-' * 35, sep='\n')
    user_input = input("Enter IP, URL or Email Address: ").strip()
    s = re.findall(r'\S+@\S+', user_input)
    if s:
        print(' Email Detected...')
        analyzeEmail(''.join(s))
    else:
        ipadd = socket.gethostbyname(user_input)
        try:
            TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
            req = requests.get(TOR_URL)
            print("\n TOR Exit Node Report: ")
            if req.status_code == 200:
                tl = req.text.split('\n')
                c = 0
                for i in tl:
                    if ipadd == i:
                        print("  " + i + " is a TOR Exit Node")
                        c = c+1
                if c == 0:
                    print("  " + ipadd + " is NOT a TOR Exit Node")
            else:
                print("   TOR LIST UNREACHABLE")
        except Exception as e:
            print("There is an error with checking for Tor exit nodes:\n" + str(e))

        print("\n Checking BadIP's... ")
        try:
            BAD_IPS_URL = 'https://www.badips.com/get/info/' + ipadd
            response = requests.get(BAD_IPS_URL)
            if response.status_code == 200:
                result = response.json()

                sc = result['Score']['ssh']
                print("  " + str(result['suc']))
                print("  Score: " + str(sc))
            else:
                print('  Error reaching BadIPs')
        except:
            print('  IP not found')

        print("\n ABUSEIPDB Report:")
        try:
            AB_URL = 'https://api.abuseipdb.com/api/v2/check'
            days = '180'

            querystring = {
                'ipAddress': ipadd,
                'maxAgeInDays': days
            }

            headers = {
                'Accept': 'application/json',
                'Key': configvars.data['AB_API_KEY']
            }
            response = requests.request(method='GET', url=AB_URL, headers=headers, params=querystring)
            if response.status_code == 200:
                req = response.json()

                print("   IP:          " + str(req['data']['ipAddress']))
                print("   Reports:     " + str(req['data']['totalReports']))
                print("   Abuse Score: " + str(req['data']['abuseConfidenceScore']) + "%")
                print("   Last Report: " + str(req['data']['lastReportedAt']))
            else:
                print("   Error Reaching ABUSE IPDB")
        except:
            print('   IP Not Found')
        
        # print("\n\nChecking against IP blacklists: ")
        # iplists.main(user_input)

    mainMenu()


def dnsMenu():
    print('\n' + '-' * 36, '         D N S    T O O L S        ', '-' * 36, sep='\n')
    print(" What would you like to do? ")
    print(" OPTION 1: Reverse DNS Lookup")
    print(" OPTION 2: DNS Lookup")
    print(" OPTION 3: WHOIS Lookup")
    print(" OPTION 0: Exit to Main Menu")
    dnsSwitch(input())


def reverseDnsLookup():
    print('-' * 27, '         PTR RECORD        ', '-' * 27, sep='\n')
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()


def dnsLookup():
    print('-' * 27, '         NSLOOKUP        ', '-' * 27, sep='\n')
    d = str(input(" Enter Domain Name to check: ").strip())
    d = re.sub("http://", "", d)
    d = re.sub("https://", "", d)
    try:
        s = socket.gethostbyname(d)
        print('\n ' + s)
    except:
        print("Website not found")
    dnsMenu()


def whoIs():
    print('-' * 26, '         W H O I S        ', '-' * 26, sep='\n')
    item = input(' Enter IP / Domain: ').strip()
    try:
        if socket.inet_pton(socket.AF_INET, item) or socket.inet_pton(socket.AF_INET6, item):
            ip = IPWhois(item)
            ip = ip.lookup_whois()

    except OSError as err:
        domain = re.sub('https://', '', item)
        domain = re.sub('http://', '', item)
        ip = socket.gethostbyname(domain)
        ip = IPWhois(ip)
        ip = ip.lookup_whois()

    whoIsPrint(ip)
    dnsMenu()


def whoIsPrint(element):
    try:
        print("\n WHO IS REPORT:")
        print("  CIDR:      " + element['nets'][0]['cidr'])
        print("  Name:      " + element['nets'][0]['name'])
        print("  Range:     " + element['nets'][0]['range'])
        print("  Descr:     " + element['nets'][0]['description'])
        print("  Country:   " + element['nets'][0]['country'])
        print("  State:     " + element['nets'][0]['state'])
        print("  City:      " + element['nets'][0]['city'])
        print("  Address:   " + element['nets'][0]['address'])
        print("  Post Code: " + element['nets'][0]['postal_code'])
        print("  Created:   " + element['nets'][0]['created'])
        print("  Updated:   " + element['nets'][0]['updated'])
    except:
        print('  IP or Domain not Found')
    return


def hashMenu():
    print("\n --------------------------------- ")
    print(" H A S H I N G   F U N C T I O N S ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Get a file's hash")
    print(" OPTION 2: Input and hash text")
    print(" OPTION 3: Search hash in VirusTotal")
    print(" OPTION 4: Sandbox file in Second Write")
    print(" OPTION 0: Exit to Main Menu")
    hashSwitch(input())


def get_file_hash():
    root = tkinter.Tk()
    root.withdraw()
    try:
        # https://www.quickprogrammingtips.com/python/how-to-calculate-md5-hash-of-a-file-in-python.html
        # https://www.quickprogrammingtips.com/python/how-to-calculate-sha256-hash-of-a-file-in-python.html
        filename = askopenfilename(title="Select file")
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(filename, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
            print('\nMD5: ', md5_hash.hexdigest())
            print('SHA256: ', sha256_hash.hexdigest())
    except:
        print('Error ocurred')

    hashMenu()


def hash_text():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())
    print("SHA256: " + hashlib.sha256(userinput.encode('utf-8')).hexdigest())
    hashMenu()


def vt_check_hash():
    try:
        root = tkinter.Tk()
        root.withdraw()
        file = askopenfilename(title="Select file")
        if not file:
            print("No file selected")
        else:
            sha256_hash = hashlib.sha256()
            with open(file, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
    except:
        print(' Error Opening File')
    try:
        response = requests.get('https://www.virustotal.com/api/v3/' + 'files/' + sha256_hash.hexdigest(),
                                headers={'x-apikey': configvars.data['VT_API_KEY']})
        response.raise_for_status()
        if response.status_code == 200:
            search = response.json()
            print('\n', "-" * 16, "VIRUS TOTAL SCAN", "-" * 16, sep="\n")
            print_results(search['data']['attributes']['last_analysis_stats'])
    except Exception as err:
        print(f'Hash not found: {err}')
    hashMenu()


def second_write_sandbox():
    sandbox_os = input('Enter OS - options are: win7 | osx12 | ubuntu18  ').strip()
    try:
        root = tkinter.Tk()
        root.withdraw()
        file = askopenfilename(title="Select file")
        if not file:
            print("No file selected")
        else:
            with open(file, 'rb') as sandbox_file:
                try:
                    submit = requests.post('https://api.secondwrite.com/' + 'submit',
                                           files={'file': sandbox_file},
                                           data={'api_key': configvars.data['SECOND_WRITE_KEY'], 'os': sandbox_os})
                    submit.raise_for_status()
                    if submit.status_code == 200:
                        print('Second Write is detonating the file, please wait 3 minutes')
                        time.sleep(180)
                        try:
                            report = requests.get('https://api.secondwrite.com/' + 'slim_report',
                                                  params={'sample': submit.text,
                                                          'api_key': configvars.data['SECOND_WRITE_KEY'],
                                                          'format': 'json',
                                                          'os': sandbox_os})
                            report.raise_for_status()
                            api_call_count = 0
                            while report.status_code != 200:
                                print("Waiting on SecondWrite report, please wait 90 seconds")
                                time.sleep(90)
                                report = requests.get('https://api.secondwrite.com/' + 'slim_report',
                                                      params={'sample': submit.text,
                                                              'api_key': configvars.data['SECOND_WRITE_KEY'],
                                                              'format': 'json',
                                                              'os': sandbox_os})
                                api_call_count += 1
                                if api_call_count == 5:
                                    print('SecondWrite API is taking too long, check the website for results')
                                    hashMenu()
                            json_report = report.json()
                            pretty_report = json.dumps(json_report, indent=1)
                            print(pretty_report)
                        except Exception as err:
                            print(f'Error returned by SecondWrite api: {err}')
                except Exception as err:
                    print(f'Submission failed: {err}')
    except:
        print(' Error Opening File')
    hashMenu()


def phishingMenu():
    print("\n --------------------------------- ")
    print("          P H I S H I N G          ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Get Email Headers ")
    print(" OPTION 2: Analyze an Email Address for Known Activity")
    # print(" OPTION 4: Analyze an URL with Phishtank")
    print(" OPTION 0: Exit to Main Menu")
    phishingSwitch(input())


def get_email_headers():
    print('-' * 30, '         EMAIL HEADERS        ', '-' * 30, sep='\n')
    try:
        root = tkinter.Tk()
        root.withdraw()
        eml_email = askopenfilename(filetypes=[("Eml files", "*.eml"), ("All Files", "*.*")], title="Select file")
        if not eml_email:
            print("No file selected")
        else:
            with open(eml_email, 'rb') as phish:
                msg = BytesParser(policy=default).parse(phish)
    except:
        print(' Error Opening File')

    try:
        header_dict = {
            'From': str(msg['from']),
            'To': str(msg['to']),
            'Message-ID': str(msg['message-id']),
            'Return-Path': str(msg['return-path']),
            'X-Env-Sender': str(msg.get('X-Env-Sender', 'Key is not present in header')),
            'X-Originating-Ip': str(msg.get('X-Originating-Ip', 'Key is not present in header'))
        }
        sanitise(header_dict)

    except:
        print('   Header Error')

    phishingMenu()


def analyzeEmailInput():
    print('-' * 27, '   EMAIL ADDRESS ANALYSIS    ', '-' * 27, sep='\n')
    try:
        email = str(input(' Enter Email Address to Analyze: ').strip())
        analyzeEmail(email)
        phishingMenu()
    except:
        print("   Error Scanning Email Address")


def analyzeEmail(email):
    try:
        url = 'https://emailrep.io/'
        summary = '?summary=true'
        url = url + email + summary
        response = requests.get(url)
        req = response.json()
        emailDomain = re.split('@', email)[1]

        print('\n Email Analysis Report from Emailrep.io ')
        if response.status_code == 400:
            print(' Invalid Email / Bad Request')
        if response.status_code == 401:
            print(' Unauthorized / Invalid API Key (for Authenticated Requests)')
        if response.status_code == 429:
            print(' Too many requests, ')
        if response.status_code == 200:
            print('   Email:       %s' % req['email'])
            print('   Reputation:  %s' % req['reputation'])
            print('   Suspicious:  %s' % req['suspicious'])
            print('   Spotted:     %s' % req['references'] + ' Times')
            print('   Blacklisted: %s' % req['details']['blacklisted'])
            print('   Last Seen:   %s' % req['details']['last_seen'])
            print('   Known Spam:  %s' % req['details']['spam'])

            print('\n Domain Report ')
            print('   Domain:        @%s' % emailDomain)
            print('   Domain Exists: %s' % req['details']['domain_exists'])
            print('   Domain Rep:    %s' % req['details']['domain_reputation'])
            print('   Domain Age:    %s' % req['details']['days_since_domain_creation'] + ' Days')
            print('   New Domain:    %s' % req['details']['new_domain'])
            print('   Deliverable:   %s' % req['details']['deliverable'])
            print('   Free Provider: %s' % req['details']['free_provider'])
            print('   Disposable:    %s' % req['details']['disposable'])
            print('   Spoofable:     %s' % req['details']['spoofable'])

            print('\n Malicious Activity Report ')
            print('   Malicious Activity: %s' % req['details']['malicious_activity'])
            print('   Recent Activity:    %s' % req['details']['malicious_activity_recent'])
            print('   Credentials Leaked: %s' % req['details']['credentials_leaked'])
            print('   Found in breach:    %s' % req['details']['data_breach'])

            # if (req['details']['data_breach']):
            #     try:
            #         url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % email
            #         userAgent = 'Sooty'
            #         headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}
            #
            #         try:
            #             reqHIBP = requests.get(url, headers=headers)
            #             response = reqHIBP.json()
            #             lr = len(response)
            #             if lr != 0:
            #                 print('\nThe account has been found in the following breaches: ')
            #                 for each in range(lr):
            #                     breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
            #                     breachReq = requests.get(breach, headers=headers)
            #                     breachResponse = breachReq.json()
            #                     breachList = []
            #                     print('   Title:        %s' % breachResponse['Title'])
            #                     print('   Breach Date:  %s' % breachResponse['BreachDate'])
            #
            #                     for each in breachResponse['DataClasses']:
            #                         breachList.append(each)
            #                     print('   Data leaked: %s' % breachList, '\n')
            #         except:
            #             print(' Error')
            #     except:
            #         print(' No API Key Found')
            # print('\n Profiles Found ')
            # if (len(req['details']['profiles']) != 0):
            #     profileList = (req['details']['profiles'])
            #     for each in profileList:
            #         print('   - %s' % each)
            # else:
            #     print('   No Profiles Found For This User')
            #
            # print('\n Summary of Report: ')
            # repSum = req['summary']
            # repSum = re.split(r"\.\s*", repSum)
            # for each in repSum:
            #     print('   %s' % each)

    except:
        print(' Error Analyzing Submitted Email')


# def phishtankModule():
#     if "phishtank" in configvars.data:
#         url = input(' Enter the URL to be checked: ').strip()
#         download, appname, api = (
#             configvars.data["phishtank"]["download"],
#             configvars.data["phishtank"]["appname"],
#             configvars.data["phishtank"]["api"],
#         )
#         phishtank.main(download, appname, api, url)
#     else:
#         print("Missing configuration for phishtank in the config.yaml file.")


def url_scans():
    url_to_scan = str(input('\nEnter url: ').strip())
    api_data_structure = [
        [
            'https://www.virustotal.com/api/v3/',
            {'x-apikey': configvars.data['VT_API_KEY']},
            {'url': url_to_scan}
        ],

        [
            'https://urlscan.io/api/v1/',
            {'API-Key': configvars.data['URLSCAN_IO_KEY'], 'Content-Type': 'application/json'},
            {'url': url_to_scan, 'visibility': 'private'}
        ],

        [
            'https://api.secondwrite.com/',
            {'api_key': configvars.data['SECOND_WRITE_KEY'], 'url': url_to_scan, 'type': 'url'}
        ]
    ]

    url_search_vt = search_url_vt(*api_data_structure[0])
    urlscanio_submit = submit_urlscanio(*api_data_structure[1])
    url_search_sw = search_url_sw(*api_data_structure[2])

    if url_search_vt == 'found' and url_search_sw == 'found' and urlscanio_submit is None:
        mainMenu()

    if url_search_sw != 'found':
        print("\nSubmitting to SecondWrite for analysis, wait for reports to generate")
        url_submit_sw = submit_url_sw(*api_data_structure[2])
    else:
        url_submit_sw = 'found'

    if url_search_vt != 'found':
        print("\nSubmitting to VirusTotal for analysis, wait for reports to generate")
        url_submit_vt = submit_url_vt(*api_data_structure[0])
    else:
        url_submit_vt = 'found'

    if urlscanio_submit:
        print("\nSubmitting to URLScanIO for analysis, wait for reports to generate")

    time.sleep(60)

    if url_submit_vt != 'found':
        result_url_vt(api_data_structure[0][0], api_data_structure[0][1], url_submit_vt)

    if urlscanio_submit:
        result_urlscanio(api_data_structure[1][0], urlscanio_submit)

    if url_submit_sw != 'found':
        result_url_sw(api_data_structure[2][0], api_data_structure[2][1]['api_key'], url_submit_sw)

    mainMenu()


def search_url_vt(api_endpoint: str, header: dict, payload: dict):
    url_id = base64.urlsafe_b64encode(payload['url'].encode()).decode().strip("=")
    try:
        response = requests.get(api_endpoint + 'urls/' + url_id, headers=header)
        response.raise_for_status()
        if response.status_code != 200:
            return
        search = response.json()
        print("-" * 16, "VIRUS TOTAL SCAN", "-" * 16, sep="\n")
        print_results(search['data']['attributes']['last_analysis_stats'])
        return 'found'
    except Exception as err:
        print(f'Error occurred: {err}')


def submit_url_vt(api_endpoint: str, header: dict, payload: dict):
    try:
        response = requests.post(api_endpoint + 'urls', headers=header, data=payload)
        response.raise_for_status()
        if response.status_code != 200:
            return
        submit = response.json()
        return submit['data']['id']
    except Exception as err:
        print(f'Error occurred: {err}')


def result_url_vt(api_endpoint: str, header: dict, uuid_vt: str):
    try:
        response = requests.get(api_endpoint + 'analyses/' + uuid_vt, headers=header)
        response.raise_for_status()
        if uuid_vt is None:
            return
        result = response.json()
        # Check for occasional empty result - start
        while sum(result['data']['attributes']['stats'].values()) == 0:
            time.sleep(3)
            response = requests.get(api_endpoint + 'analyses/' + uuid_vt, headers=header)
            result = response.json()
        # Check for occasional empty result - end
        print('\n', "-" * 16, "VIRUS TOTAL SCAN", "-" * 16, sep="\n")
        print_results(result['data']['attributes']['stats'])
    except Exception as err:
        print(f'Error occurred: {err}')


def submit_urlscanio(api_endpoint: str, header: dict, payload: dict):
    try:
        response = requests.post(api_endpoint + "scan/", headers=header, data=json.dumps(payload))
        response.raise_for_status()
        if response.status_code != 200:
            return
        result = response.json()
        try:
            return result['uuid']
        except KeyError:
            print('Unable to submit to URLScanio')
    except Exception as err:
        print(f'Error occurred: {err}')


def result_urlscanio(api_endpoint, uuid):
    try:
        response = requests.get(api_endpoint + 'result/' + uuid)
        response.raise_for_status()
        while response.status_code != 200:
            time.sleep(5)
            response = requests.get(api_endpoint + 'result/' + uuid)
        result = response.json()
        print('\n', "-" * 14, "URLSCANIO SCAN", "-" * 14, sep="\n")
        try:
            print_results(result['verdicts']['overall'])
        except KeyError:
            print('Unable to get report from URLscanIO')
    except Exception as err:
        print(f'Error occurred: {err}')


def search_url_sw(api_endpoint: str, payload: dict):
    url = payload['url']
    hash_url = hashlib.sha256(url.encode('utf-8'))
    hex_url = hash_url.hexdigest()
    try:
        response = requests.get(api_endpoint + 'slim_report',
                                params={'sample': hex_url,
                                        'api_key': payload['api_key'],
                                        'format': 'json'})
        response.raise_for_status()
        if response.status_code != 200:
            return
        result = response.json()
        sw_url_print(result)
        return 'found'
    except Exception:
        print('\nURL not in SecondWrite database')


def submit_url_sw(api_endpoint: str, payload: dict):
    try:
        response = requests.post(api_endpoint + 'submit', data=payload)
        response.raise_for_status()
        if response.status_code != 200:
            return
        return response.text
    except Exception:
        print('Error returned by SecondWrite api')


def result_url_sw(api_endpoint, api_key, uuid):
    try:
        response = requests.get(api_endpoint + 'slim_report',
                                params={'sample': uuid,
                                        'api_key': api_key,
                                        'format': 'json'})
        response.raise_for_status()
        api_call_count = 0
        while response.status_code != 200:
            print("Waiting on SecondWrite report, please wait 90 seconds")
            time.sleep(90)
            response = requests.get(api_endpoint + 'slim_report',
                                    params={'sample': uuid,
                                            'api_key': api_key,
                                            'format': 'json'})
            api_call_count += 1
            if api_call_count == 5:
                print('SecondWrite API is taking too long, check the website for results')
                return
        result = response.json()
        sw_url_print(result)
    except Exception:
        print('Error returned by SecondWrite api')


def sw_url_print(stats):
    print('\n', "-" * 16, "SECONDWRITE SCAN", "-" * 16, sep="\n")
    print_results(stats['result'])
    if stats['malware_classification']:
        print('Malware Classification: ')
        print_results(stats['malware_classification'][0])


def print_results(output):
    for key, value in output.items():
        if key.lower() == 'malicious' and value > 0 or \
                key.lower() == 'malicious' and value == 'True' or \
                key.lower() == 'malware_confidence' and value == 100 or \
                key.lower() == 'result' and value == 'Malicious' or \
                key.lower() == 'confidence' or key.lower() == 'description':
            key = "\033[1;31m{}\033[00m".format(key)
            value = "\033[1;31m{}\033[00m".format(value)
        print(key + ":", value)


if __name__ == '__main__':
    mainMenu()
