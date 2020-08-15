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
import html.parser
import os
import re
import json
import time
import socket
import strictyaml
from urllib.parse import unquote
import requests
from ipwhois import IPWhois
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from email.parser import BytesParser, Parser
from email.policy import default
from Modules import iplists
from Modules import phishtank


try:
    f = open("config.yaml", "r")
    configvars = strictyaml.load(f.read())
    f.close()
except FileNotFoundError:
    print("Config.yaml not found. Check the example config file and rename to 'config.yaml'.")

linksFoundList = []
linksRatingList = []
linksSanitized = []
linksDict = {}

def mainMenu():
    print("\n What would you like to do? ")
    print(" OPTION 1: Sanitise URL and/or emails for ServiceNow tickets ")
    print(" OPTION 2: Decoders (URLs, SafeLinks, Base64, UNshorten urls) ")
    print(" OPTION 3: Reputation Checker")
    print(" OPTION 4: DNS Tools")
    print(" OPTION 5: Hashing Function")
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
        urlscans()
    if choice == '0':
        exit()
    else:
        mainMenu()


def decoderSwitch(choice):
    if choice == '1':
        urlDecoder()
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
        hashFile()
    if choice == '2':
        hashText()
    if choice == '3':
        hashRating()
    if choice == '4':
        hashAndFileUpload()
    if choice == '0':
        mainMenu()


def phishingSwitch(choice):
    if choice == '1':
        analyzePhish()
    if choice == '2':
        analyzeEmailInput()
    if choice == '3':
        emailTemplateGen()
    if choice == '4':
        phishtankModule()
    if choice == '9':
        haveIBeenPwned()
    else:
        mainMenu()


def sanitise():
    print('\n' + '-' * 27, ' S A N I T I S E   T O O L ', '-' * 27, sep='\n')
    element = str(input("Enter URL/Email to sanitize: ").strip())
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


def urlDecoder(*args):
    if args:
        decodedUrl = unquote(args[0])
        return decodedUrl

    print('\n' + '-' * 23, ' U R L   D E C O D E R ', '-' * 23, sep='\n')
    url = input(' Enter URL: ').strip()
    decodedUrl = unquote(url)
    print("\n\033[32m Decoded URL:  {} \033[00m".format(decodedUrl))
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
    decoded_url = urlDecoder(url)
    safelinksDecoder(decoded_url)
    mainMenu()


def repChecker():
    print('\n' + '-' * 35, ' R E P U T A T I O N     C H E C K ', '-' * 35, sep='\n')
    selection = input("Enter IP, URL or Email Address: ").strip()
    # ip = str(rawInput[0])
    s = re.findall(r'\S+@\S+', selection)
    if s:
        print(' Email Detected...')
        analyzeEmail(''.join(s))
    else:
        whoIsPrint(ip)
        wIP = socket.gethostbyname(ip)
        try:
            TOR_URL = "https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=1.1.1.1"
            req = requests.get(TOR_URL)
            print("\n TOR Exit Node Report: ")
            if req.status_code == 200:
                tl = req.text.split('\n')
                c = 0
                for i in tl:
                    if wIP == i:
                        print("  " + i + " is a TOR Exit Node")
                        c = c+1
                if c == 0:
                    print("  " + wIP + " is NOT a TOR Exit Node")
            else:
                print("   TOR LIST UNREACHABLE")
        except Exception as e:
            print("There is an error with checking for Tor exit nodes:\n" + str(e))


        print("\n Checking BadIP's... ")
        try:
            BAD_IPS_URL = 'https://www.badips.com/get/info/' + wIP
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
                'ipAddress': wIP,
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
        
        print("\n\nChecking against IP blacklists: ")
        iplists.main(rawInput)

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
    d = str(input(" Enter IP to check: ").strip())
    try:
        s = socket.gethostbyaddr(d)
        print('\n ' + s[0])
    except:
        print(" Hostname not found")
    dnsMenu()


def dnsLookup():
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
    item = input(' Enter IP / Domain: ').strip()
    try:
        if socket.inet_pton(socket.AF_INET, item) or socket.inet_pton(socket.AF_INET6,item):
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
    print(" OPTION 1: Hash a file")
    print(" OPTION 2: Input and hash text")
    print(" OPTION 3: Check a hash for known malicious activity")
    print(" OPTION 4: Hash a file, check a hash for known malicious activity")
    print(" OPTION 0: Exit to Main Menu")
    hashSwitch(input())

def hashFile():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    print(" MD5 Hash: " + hasher.hexdigest())
    root.destroy()
    hashMenu()

def hashText():
    userinput = input(" Enter the text to be hashed: ")
    print(" MD5 Hash: " + hashlib.md5(userinput.encode("utf-8")).hexdigest())
    hashMenu()

def hashRating():
    apierror = False
    # VT Hash Checker
    fileHash = str(input(" Enter Hash of file: ").strip())
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    
    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Reponse")
    hashMenu()

def hashAndFileUpload():
    root = tkinter.Tk()
    root.filename = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
    hasher = hashlib.md5()
    with open(root.filename, 'rb') as afile:
        buf = afile.read()
        hasher.update(buf)
    fileHash = hasher.hexdigest()
    print(" MD5 Hash: " + fileHash)
    root.destroy()
    apierror = False
    # VT Hash Checker
    url = 'https://www.virustotal.com/vtapi/v2/file/report'

    params = {'apikey': configvars.data['VT_API_KEY'], 'resource': fileHash}
    response = requests.get(url, params=params)

    try:  # EAFP
        result = response.json()
    except:
        apierror = True
        print("Error: Invalid API Key")
    if not apierror:
        if result['response_code'] == 0:
            print("\n Hash was not found in Malware Database")
        elif result['response_code'] == 1:
            print(" VirusTotal Report: " + str(result['positives']) + "/" + str(result['total']) + " detections found")
            print("   Report Link: " + "https://www.virustotal.com/gui/file/" + fileHash + "/detection")
        else:
            print("No Response")
    hashMenu()

def phishingMenu():
    print("\n --------------------------------- ")
    print("          P H I S H I N G          ")
    print(" --------------------------------- ")
    print(" What would you like to do? ")
    print(" OPTION 1: Analyze an Email ")
    print(" OPTION 2: Analyze an Email Address for Known Activity")
    print(" OPTION 3: Generate an Email Template based on Analysis")
    print(" OPTION 4: Analyze an URL with Phishtank")
    print(" OPTION 9: HaveIBeenPwned")
    print(" OPTION 0: Exit to Main Menu")
    phishingSwitch(input())

def analyzePhish():
    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()

        # Fixes issue with file name / dir name exceptions
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')   # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(' Error Opening File')

    print("\n Extracting Headers...")
    try:
        print("   FROM:      ", str(msg.SenderName), ", ", str(msg.SenderEmailAddress))
        print("   TO:        ", str(msg.To))
        print("   SUBJECT:   ", str(msg.Subject))
        print("   NameBehalf:", str(msg.SentOnBehalfOfName))
        print("   CC:        ", str(msg.CC))
        print("   BCC:       ", str(msg.BCC))
        print("   Sent On:   ", str(msg.SentOn))
        print("   Created:   ", str(msg.CreationTime))
        s = str(msg.Body)
    except:
        print('   Header Error')
        f.close()

    print("\n Extracting Links... ")
    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        print('   %s' % each)

    print("\n Extracting Emails Addresses... ")
    try:
        match = r'([\w0-9._-]+@[\w0-9._-]+\.[\w0-9_-]+)'
        emailList = list()
        a = re.findall(match, s, re.M | re.I)

        for b in a:
            if b not in emailList:
                emailList.append(b)
                print(" ", b)
            if len(emailList) == 0:
                print('   No Emails Found')

        if len(a) == 0:
            print('   No Emails Found...')
    except:
        print('   Emails Error')
        f.close()

    print("\n Extracting IP's...")
    try:
        ipList = []
        foundIP = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s)
        ipList.append(foundIP)

        if not ipList:
            for each in ipList:
                print(each)
        else:
            print('   No IP Addresses Found...')
    except:
        print('   IP error')

    try:
        analyzeEmail(msg.SenderEmailAddress)
    except:
        print('')

    phishingMenu()

def haveIBeenPwned():
    print("\n --------------------------------- ")
    print(" H A V E   I   B E E N   P W N E D  ")
    print(" --------------------------------- ")

    try:
        acc = str(input(' Enter email: ').strip())
        haveIBeenPwnedPrintOut(acc)
    except:
        print('')
    phishingMenu()

def haveIBeenPwnedPrintOut(acc):
    try:
        url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % acc
        userAgent = 'Sooty'
        headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}
        try:
            req = requests.get(url, headers=headers)
            response = req.json()
            lr = len(response)
            if lr != 0:
                print('\n The account has been found in the following breaches: ')
                for each in range(lr):
                    breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                    breachReq = requests.get(breach, headers=headers)
                    breachResponse = breachReq.json()

                    breachList = []
                    print('\n   Title:        %s' % breachResponse['Title'])
                    print('   Domain:       %s' % breachResponse['Domain'])
                    print('   Breach Date:  %s' % breachResponse['BreachDate'])
                    print('   Pwn Count:    %s' % breachResponse['PwnCount'])
                    for each in breachResponse['DataClasses']:
                        breachList.append(each)
                    print('   Data leaked: %s' % breachList)
        except:
            print(' No Entries found in Database')
    except:
        print('')

def analyzeEmailInput():
    print("\n --------------------------------- ")
    print("    E M A I L   A N A L Y S I S    ")
    print(" --------------------------------- ")
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

        print('\n Email Analysis Report ')
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

            if (req['details']['data_breach']):
                try:
                    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/%s' % email
                    userAgent = 'Sooty'
                    headers = {'Content-Type': 'application/json', 'hibp-api-key': configvars.data['HIBP_API_KEY'], 'user-agent': userAgent}

                    try:
                        reqHIBP = requests.get(url, headers=headers)
                        response = reqHIBP.json()
                        lr = len(response)
                        if lr != 0:
                            print('\nThe account has been found in the following breaches: ')
                            for each in range(lr):
                                breach = 'https://haveibeenpwned.com/api/v3/breach/%s' % response[each]['Name']
                                breachReq = requests.get(breach, headers=headers)
                                breachResponse = breachReq.json()
                                breachList = []
                                print('   Title:        %s' % breachResponse['Title'])
                                print('   Breach Date:  %s' % breachResponse['BreachDate'])

                                for each in breachResponse['DataClasses']:
                                    breachList.append(each)
                                print('   Data leaked: %s' % breachList, '\n')
                    except:
                        print(' Error')
                except:
                    print(' No API Key Found')
            print('\n Profiles Found ')
            if (len(req['details']['profiles']) != 0):
                profileList = (req['details']['profiles'])
                for each in profileList:
                    print('   - %s' % each)
            else:
                print('   No Profiles Found For This User')

            print('\n Summary of Report: ')
            repSum = req['summary']
            repSum = re.split(r"\.\s*", repSum)
            for each in repSum:
                print('   %s' % each)

    except:
        print(' Error Analyzing Submitted Email')

def virusTotalAnalyze(result, sanitizedLink):
    linksDict['%s' % sanitizedLink] = str(result['positives'])
    #print(str(result['positives']))

def emailTemplateGen():
    print('\n--------------------')
    print('  Phishing Response')
    print('--------------------')

    try:
        file = tkinter.filedialog.askopenfilename(initialdir="/", title="Select file")
        with open(file, encoding='Latin-1') as f:
            msg = f.read()
        file = file.replace('//', '/')  # dir
        file2 = file.replace(' ', '')  # file name (remove spaces / %20)
        os.rename(file, file2)
        outlook = win32com.client.Dispatch("Outlook.Application").GetNamespace("MAPI")
        msg = outlook.OpenSharedItem(file)
    except:
        print(' Error importing email for template generator')

    url = 'https://emailrep.io/'
    email = msg.SenderEmailAddress
    url = url + email
    responseRep = requests.get(url)
    req = responseRep.json()
    f = msg.To.split(' ', 1)[0]

    try:
        match = r"((www\.|http://|https://)(www\.)*.*?(?=(www\.|http://|https://|$)))"
        a = re.findall(match, msg.Body, re.M | re.I)
        for b in a:
            match = re.search(r'https://urldefense.proofpoint.com/(v[0-9])/', b[0])
            if match:
                if match.group(1) == 'v1':
                    decodev1(b[0])
                elif match.group(1) == 'v2':
                    decodev2(b[0])
            else:
                if b[0] not in linksFoundList:
                    linksFoundList.append(b[0])
        if len(a) == 0:
            print(' No Links Found...')
    except:
        print('   Links Error')
        f.close()

    for each in linksFoundList:
        x = re.sub(r"\.", "[.]", each)
        x = re.sub("http://", "hxxp://", x)
        x = re.sub("https://", "hxxps://", x)
        sanitizedLink = x

    if 'API Key' not in configvars.data['VT_API_KEY']:
        try:  # EAFP
            url = 'https://www.virustotal.com/vtapi/v2/url/report'
            for each in linksFoundList:
                link = each
                params = {'apikey': configvars.data['VT_API_KEY'], 'resource': link}
                response = requests.get(url, params=params)
                result = response.json()
                if response.status_code == 200:
                    virusTotalAnalyze(result, sanitizedLink)

        except:
            print("\n Threshold reached for VirusTotal: "
                  "\n   60 seconds remaining...")
            time.sleep(15)
            print('   45 seconds remaining...')
            time.sleep(15)
            print('   30 seconds remaining...')
            time.sleep(15)
            print('   15 seconds remaining...')
            time.sleep(15)
            virusTotalAnalyze(result, sanitizedLink)
    else:
        print('No API Key set, results will not show malicious links')

    rc = 'potentially benign'
    threshold = '1'

    if req['details']['spam'] or req['suspicious'] or req['details']['blacklisted'] or req['details']['malicious_activity']:
        rc = 'potentially suspicious'

    for key, value in linksDict.items():
        if int(value) >= int(threshold):
            rc = 'potentially malicious'

    if responseRep.status_code == 200:
        print('\nHi %s,' % f,)
        print('\nThanks for your recent submission.')
        print('\nI have completed my analysis of the submitted mail and have classed it is as %s.' % rc)
        print('\nThe sender has a reputation score of %s,' % req['reputation'], 'for the following reasons: ')

        if req['details']['spam']:
            print(' - The sender has been reported for sending spam in the past.')
        if req['suspicious']:
            print(' - It has been marked as suspicious on reputation checking websites.')
        if req['details']['free_provider']:
            print(' - The sender is using a free provider.')
        if req['details']['days_since_domain_creation'] < 365:
            print(' - The domain is less than a year old.')
        if req['details']['blacklisted']:
            print(' - It has been blacklisted on several sites.')
        if req['details']['data_breach']:
            print(' - Has been seen in data breaches')
        if req['details']['credentials_leaked']:
            print(' - The credentials have been leaked for this address')
        if req['details']['malicious_activity']:
            print(' - This sender has been flagged for malicious activity.')

        malLink = 0     # Controller for mal link text
        for each in linksDict.values():
            if int(threshold) <= int(each):
                malLink = 1

        if malLink == 1:
            print('\nThe following potentially malicious links were found embedded in the body of the mail:')
            for key, value in linksDict.items():
                if int(value) >= int(threshold):
                    print(' - %s' % key)

        print('\nAs such, I would recommend the following: ')

        if 'suspicious' in rc:
            print(' - Delete and Ignore the mail for the time being.')

        if 'malicious' in rc:
            print(' - If you clicked any links or entered information into any displayed webpages let us know asap.')

        if 'spam' in rc:
            print(' - If you were not expecting the mail, please delete and ignore.')
            print(' - We would advise you to use your email vendors spam function to block further mails.')

        if 'task' in rc:
            print(' - If you completed any tasks asked of you, please let us know asap.')
            print(' - If you were not expecting the mail, please delete and ignore.')

        if 'benign' in rc:
            print(' - If you were not expecting this mail, please delete and ignore.')
            print('\nIf you receive further mails from this sender, you can use your mail vendors spam function to block further mails.')

        if 'suspicious' or 'malicious' or 'task' in rc:
            print('\nI will be reaching out to have this sender blocked to prevent the sending of further mails as part of our remediation effort.')
            print('For now, I would recommend to simply delete and ignore this mail.')
            print('\nWe appreciate your diligence in reporting this mail.')

        print('\nRegards,')

def phishtankModule():
    if "phishtank" in configvars.data:
        url = input(' Enter the URL to be checked: ').strip()
        download, appname, api = (
            configvars.data["phishtank"]["download"],
            configvars.data["phishtank"]["appname"],
            configvars.data["phishtank"]["api"],
        )
        phishtank.main(download, appname, api, url)
    else:
        print("Missing configuration for phishtank in the config.yaml file.")


def urlscans():
    url_to_scan = str(input('\nEnter url: ').strip())
    api_data_structure = [
        [
            'https://www.virustotal.com/api/v3/',
            {'x-apikey': configvars.data['VT_API_KEY']},
            {'url': url_to_scan}
        ],

        [
            # 'https://urlscan.io/api/v1/',
            # {'API-Key': configvars.data['URLSCAN_IO_KEY'], 'Content-Type': 'application/json'},
            # {'url': url_to_scan, 'visibility': 'private'}
        ],

        [
            'https://api.secondwrite.com/',
            {'api_key': configvars.data['SECOND_WRITE_KEY'], 'url': url_to_scan, 'type': 'url'}
        ]
    ]

    url_search_vt = search_url_vt(*api_data_structure[0])
    url_search_sw = search_url_sw(*api_data_structure[2])

    if url_search_vt is 'found' and url_search_sw is 'found':
        mainMenu()

    if url_search_sw is not 'found':
        print("\nSubmitting to SecondWrite for analysis, wait for reports to generate")
        url_submit_sw = submit_url_sw(*api_data_structure[2])
    else:
        url_submit_sw = 'found'

    if url_search_vt is not 'found':
        print("\nSubmitting to VirusTotal for analysis, wait for reports to generate")
        url_submit_vt = submit_url_vt(*api_data_structure[0])
    else:
        url_submit_vt = 'found'

    time.sleep(60)

    if url_submit_sw is not 'found':
        result_url_sw(api_data_structure[2][0], api_data_structure[2][1]['api_key'], url_submit_sw)

    if url_submit_vt is not 'found':
        result_url_vt(api_data_structure[0][0], api_data_structure[0][1], url_submit_vt)



    mainMenu()


def search_url_vt(api_endpoint: str, header: dict, payload: dict):
    url_id = base64.urlsafe_b64encode(payload['url'].encode()).decode().strip("=")
    try:
        response = requests.get(api_endpoint + 'urls/' + url_id, headers=header)
        response.raise_for_status()
    except Exception as err:
        print(f'Error occurred: {err}')
    if response.status_code != 200:
        return
    search = response.json()
    print("-" * 16, "VIRUS TOTAL SCAN", "-" * 16, sep="\n")
    print_results(search['data']['attributes']['last_analysis_stats'])
    return 'found'


def submit_url_vt(api_endpoint: str, header: dict, payload: dict):
    try:
        response = requests.post(api_endpoint + 'urls', headers=header, data=payload)
        response.raise_for_status()
    except Exception as err:
        print(f'Error occurred: {err}')
    if response.status_code != 200:
        return
    submit = response.json()
    return submit['data']['id']


def result_url_vt(api_endpoint: str, header: dict, uuid_vt: str):
    try:
        response = requests.get(api_endpoint + 'analyses/' + uuid_vt, headers=header)
        response.raise_for_status()
    except Exception as err:
        print(f'Error occurred: {err}')
    if uuid_vt is None:
        return
    result = response.json()
    # Check for occasional empty result - start
    while sum(result['data']['attributes']['stats'].values()) == 0:
        time.sleep(3)
        response = requests.get(api_endpoint + 'analyses/' + uuid_vt, headers=header)
        result = response.json()
    # Check for occasional empty result - end
    print("-" * 16, "VIRUS TOTAL SCAN", "-" * 16, sep="\n")
    print_results(result['data']['attributes']['stats'])


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
    except Exception:
        print('\nURL not in SecondWrite database')
    if response.status_code != 200:
        return
    result = response.json()
    sw_url_print(result)
    return 'found'


def submit_url_sw(api_endpoint: str, payload: dict):
    try:
        response = requests.post(api_endpoint + 'submit', data=payload)
        response.raise_for_status()
    except Exception:
        print('Error returned by SecondWrite api')
    if response.status_code != 200:
        return
    return response.text


def result_url_sw(api_endpoint, api_key, uuid):
    try:
        response = requests.get(api_endpoint + 'slim_report',
                                params={'sample': uuid,
                                        'api_key': api_key,
                                        'format': 'json'})
        response.raise_for_status()
    except Exception:
        print('Error returned by SecondWrite api')
    api_call_count = 0
    while response.status_code != 200:
        print("Waiting for report, please wait 90 seconds")
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


def sw_url_print(stats):
    print("-" * 16, "SECONDWRITE SCAN", "-" * 16, sep="\n")
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
