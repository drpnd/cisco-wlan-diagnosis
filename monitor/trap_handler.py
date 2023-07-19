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

## CISCO-LWAPP-DOT11-CLIENT-MIB
OID_TRAP = '.1.3.6.1.6.3.1.1.4.1.0'
OID_ASSOC = '.1.3.6.1.4.1.9.9.599.0.9' # ciscoLwappDot11ClientAssocTrap
OID_ASSOC_STATS = '.1.3.6.1.4.1.9.9.599.0.7' # ciscoLwappDot11ClientAssocDataStatsTrap
OID_DEASSOC_STATS = '.1.3.6.1.4.1.9.9.599.0.6' # ciscoLwappDot11ClientDisassocDataStatsTrap
OID_DEAUTH = '.1.3.6.1.4.1.9.9.599.0.10' # ciscoLwappDot11ClientDeAuthenticatedTrap
OID_APJOIN = '.1.3.6.1.4.1.9.9.513.0.4' # ciscoLwappApAssociated

## AIRESPACE-WIRELESS-MIB
OID_APREMOVE = '.1.3.6.1.4.1.14179.2.6.3.8' # bsnAPDisassociated
OID_DFS_DETECTED = '.1.3.6.1.4.1.14179.2.6.3.81' # bsnRadarChannelDetected
OID_DFS_CLEARED = '.1.3.6.1.4.1.14179.2.6.3.82' # bsnRadarChannelCleared

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

    return True

"""
Call the main routine
"""
if __name__ == "__main__":
    main()
