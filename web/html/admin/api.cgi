#!/usr/bin/env python3

# -*- coding: utf-8 -*-
"""
Copyright (c) 2023-2024 Hirochika Asai <asai@jar.jp>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import cgi
import os
import time
import re
import api.client


"""
Defaunlt function
"""
def default(args):
    bad_request(args)
def bad_request(args):
    print('Status: 400 Bad Request')
    print('')
    print('400 Bad Request')
    #print(args)
    return

"""
Main routine
"""
def main():
    args = cgi.FieldStorage()
    ## Function
    try:
        f = args['f'].value
    except:
        f = 'default'
    if f == 'default':
        default(args)
    elif f == 'ap_history':
        db = api.mydb.connect()
        c = db.cursor()
        ts = int(time.time())
        mac_addr = api.client.resolve_macaddr(db, c)
        if not mac_addr:
            return False
        api.client.ap_history(mac_addr, ts - 7200, ts)
    elif f == 'ap_history_detail':
        ts = int(time.time())
        api.client.ap_history_detail(ts - 7200, ts)
    elif f == 'stats':
        db = api.mydb.connect()
        c = db.cursor()
        ts = int(time.time())
        mac_addr = api.client.resolve_macaddr(db, c)
        if not mac_addr:
            return False
        api.client.statistics(mac_addr, ts - 7200, ts)
    elif f == 'admin_stats':
        db = api.mydb.connect()
        c = db.cursor()
        ts = int(time.time())
        try:
            mac_addr = args['mac'].value
        except:
            return False
        ## Sanitize the MAC address
        mac_addr = mac_addr.lower()
        result = re.match('^([0-9a-f]{4})\.([0-9a-f]{4})\.([0-9a-f]{4})$', mac_addr)
        if result:
            mac_addr = result.group(1)[0:2] + ':' + result.group(1)[2:4] + ':' + result.group(2)[0:2] + ':' + result.group(2)[2:4] + ':' + result.group(3)[0:2] + ':' + result.group(3)[2:4]
        result = re.match('^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$', mac_addr)
        if not result:
            return False
        api.client.statistics(mac_addr, ts - 7200, ts)
    elif f == 'syslog':
        db = api.mydb.connect()
        c = db.cursor()
        ts = int(time.time())
        mac_addr = api.client.resolve_macaddr(db, c)
        if not mac_addr:
            return False
        api.client.syslog(mac_addr, ts - 7200, ts)
    elif f == 'admin_syslog':
        db = api.mydb.connect()
        c = db.cursor()
        ts = int(time.time())
        try:
            mac_addr = args['mac'].value
        except:
            return False
        api.client.syslog(mac_addr, ts - 7200, ts)
    elif f == 'token':
        api.client.token(args)
    else:
        bad_request(args)

if __name__ == "__main__":
    main()

