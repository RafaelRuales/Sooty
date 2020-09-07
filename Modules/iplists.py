"""
Author: Axel Robbe
Version: 0.1

This script checks given ip or domain names against online blacklists.
Minimal required Python version 3.3


"""

import ipaddress
import json
import requests


class userInput:
    def __init__(self, ipaddrs):
        self.lookup = ipaddrs
        self.version = 0

    def urlOrIP(self):
        # Test if it is an ip address, otherwise it must be a string, thus try as an URL.
        try:
            ip = ipaddress.ip_address(self.lookup)
            self.version = ip.version

        # If value error, then it cannot be an IP
        except ValueError:
            print("URLs are not (yet) supported")
            exit()

        except Exception as exc:
            print(exc)


class lookupLists:
    def __init__(self, name, desc, category, listURL, period):
        self.name = name
        self.desc = desc
        self.category = category
        self.listURL = listURL
        self.period = period

    def blacklistCheck(self, ipObj):
        # Create an unique list of IPs that match the list being searched
        self.hitlist = set()

        req = requests.get(self.listURL)
        if req.status_code == 200:
            lines = req.text.splitlines()

            # check if line matches with ip
            for line in lines:
                if ipObj.lookup == line:
                    self.hitlist.add(ipObj.lookup)

    def reporter(self, ipObjs):
        # Lists without an entry in the hitlist are no further processed
        if len(self.hitlist) != 0:
            return self.hitlist
        else:
            return self.name


def main(userInputip):
    # Create objects for each user entry and check whether IPv4, IPv6 or URL
    # ipObjs = [userInput(ip) for ip in userInputList]
    # for ipObj in ipObjs:
    #     ipObj.urlOrIP()
    ip_obj = userInput(userInputip)
    ip_obj.urlOrIP()

    # get the blacklist URLs and details

    with open("config/iplists.json") as settings:
        blacklists = json.load(settings)

    # Instantiate the blacklists
    blacklistObjs = [
        lookupLists(blacklist["name"],blacklist["desc"],
            blacklist["category"],
            blacklist["listURL"],
            blacklist["period"]
        )
        for blacklist in blacklists
    ]

    # For each list, perform a check on the ip-object
    for listObj in blacklistObjs:
        print("Checking " + listObj.name + "...")
        listObj.blacklistCheck(ip_obj)

    # For each list, run the reporter on the ip-object (list of IPs)
    print("\nResults:")
    for listObj in blacklistObjs:
        report = listObj.reporter(ip_obj)
        if len(listObj.hitlist) == 0:
            print(listObj.name + " - no result")
        else:
            print(listObj.category,
                ":",
                listObj.name,
                "-",
                str(len(listObj.hitlist)),
                "hit(s) - max age",
                listObj.period,
                ":",
                listObj.desc,
            )
            for ip in report:
                print("     " + ip)


if __name__ == "__main__":
    # Create a unique list of userInput to prevent redundant lookups
    userInputList = set(
        input("Please provide one or multiple IP addresses to check: ").split()
    )
    main(userInputList)
