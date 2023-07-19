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

"""
Main routine
"""
def main():
    fp = open(config.TRAP_LOG_FILE, "a+")
    fcntl.flock(fp.fileno(), fcntl.LOCK_EX)

    ts = int(time.time())
    try:
        ## Parse the input
        host = sys.stdin.readline().rstrip()
        connection = sys.stdin.readline().rstrip()

        fp.write("{}\n{}\n{}\n".format(time.time(), host, connection))

        rawtext = ''
        data = {}
        for l in sys.stdin:
            rawtext += l
            fp.write(l)
            l = l.strip()
            k, v = l.split(" ", 1)
            if v.startswith("Wrong Type"):
                wmsg, nv = v.split(": ", 1)
                v = nv
            data[k] = v
        fp.write("---------------------------------------\n")
    except:
        pass
    fcntl.flock(fp.fileno(), fcntl.LOCK_UN)
    fp.close()

    ## Insert into the database
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
