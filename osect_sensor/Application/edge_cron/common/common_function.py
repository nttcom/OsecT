# from dpkt.compat import compat_ord
# import dpkt
# import ipaddress
from unicodedata import category

# import re
# import struct


def deleteCc(s):
    r = ""
    for c in s:
        if category(c) == "Cc":
            continue
        r += c

    return r


# def parseDHCP(udpData):
# def parseNBNS(udpData):
# def parseMWBP(udpData):
# def parseSSDP(udpData):
# def parseDHCPv6(udpData):
# def pcap2log(pcapFile, logDir):
