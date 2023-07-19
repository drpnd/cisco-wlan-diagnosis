#!/usr/bin/env python3

import sys
import time
import json
import requests
import subprocess
import os
import fcntl
import mydb
import config

## SNMPv2-MIB
OID_TRAP = '.1.3.6.1.6.3.1.1.4.1.0'
OID_SYSUPTIME = '.1.3.6.1.2.1.1.3.0'

## CISCO-LWAPP-DOT11-CLIENT-MIB
OID_ASSOC = '.1.3.6.1.4.1.9.9.599.0.9' # ciscoLwappDot11ClientAssocTrap
OID_ASSOC_STATS = '.1.3.6.1.4.1.9.9.599.0.7' # ciscoLwappDot11ClientAssocDataStatsTrap
OID_DEASSOC_STATS = '.1.3.6.1.4.1.9.9.599.0.6' # ciscoLwappDot11ClientDisassocDataStatsTrap
OID_DEAUTH = '.1.3.6.1.4.1.9.9.599.0.10' # ciscoLwappDot11ClientDeAuthenticatedTrap
OID_APJOIN = '.1.3.6.1.4.1.9.9.513.0.4' # ciscoLwappApAssociated

## CISCO-LWAPP-AP-MIB
OID_APNAME = '.1.3.6.1.4.1.9.9.513.1.1.1.1.5' # cLApEntry

## AIRESPACE-WIRELESS-MIB
OID_APREMOVE = '.1.3.6.1.4.1.14179.2.6.3.8' # bsnAPDisassociated
OID_DFS_DETECTED = '.1.3.6.1.4.1.14179.2.6.3.81' # bsnRadarChannelDetected
OID_DFS_CLEARED = '.1.3.6.1.4.1.14179.2.6.3.82' # bsnRadarChannelCleared


"""
Post a message to Slack
"""
def post_slack(msg):
    payload_dic = {
        "text": msg,
    }
    r = requests.post(config.SLACK_WEBHOOK, data=json.dumps(payload_dic))

    return r

"""
AP joined
"""
def apjoin(data):
    try:
        uptime = data[OID_SYSUPTIME]
        macoid = False
        for k in data:
            if k.startswith(OID_APNAME + '.'):
                macoid = k[len(OID_APNAME) + 1:]
                break
        if not macoid:
            ## AP name not found
            return False
        ## Find the AP MAC address
        b = macoid.split(".")
        if len(b) == 7:
            ## Remove the length
            del b[0]
        if len(b) != 6:
            return False
        mac = "%02x%02x.%02x%02x.%02x%02x" % (int(b[0]), int(b[1]), int(b[2]), int(b[3]), int(b[4]), int(b[5]))
        apname = data[OID_APNAME + '.' + macoid]
    except:
        return False

    detail = "  AP: {}\n".format(apname)
    detail = detail + "  MAC address: {}\n".format(mac)
    post_slack("*New AP joined* at Uptime @ {}\n{}".format(uptime, detail))

    return True

"""
AP removed
"""
def apremove(data):
    pass

"""
Main routine
"""
def main():
    ts = int(time.time())
    try:
        ## Parse the input
        host = sys.stdin.readline().rstrip()
        connection = sys.stdin.readline().rstrip()

        rawtext = ''
        data = {}
        for l in sys.stdin:
            ## Raw text to the database
            rawtext += l
            ## Parse to a Key-Value dictionary
            l = l.strip()
            k, v = l.split(" ", 1)
            if v.startswith("Wrong Type"):
                wmsg, nv = v.split(": ", 1)
                v = nv
            data[k] = v
    except:
        pass

    ## Insert an entry into the database
    db = mydb.connect()
    c = db.cursor()
    sql = '''insert into snmp_trap_log (ts, host, connection, rawtext) values (%s, %s, %s, %s)'''
    c.execute(sql, (ts, host, connection, rawtext))
    db.commit()

    ## Check if the trap OID exists
    if OID_TRAP not in data:
        return False

    if data[OID_TRAP] == OID_APJOIN:
        apjoin(data)
    elif data[OID_TRAP] == OID_APREMOVE:
        apremove(data)

    return True

"""
Call the main routine
"""
if __name__ == "__main__":
    main()
