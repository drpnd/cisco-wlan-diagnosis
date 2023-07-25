#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Copyright (c) 2023 Hirochika Asai <asai@jar.jp>

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

import cisco_gnmi
import json
import os
import errno
import argparse
import time
import mydb
import config

## Arguments
parser = argparse.ArgumentParser()
parser.add_argument('--host', type=str, default='localhost')
parser.add_argument('--port', type=int, default=9339)
parser.add_argument('--cacert', type=str, default='rootCA.pem')
parser.add_argument('--private-key', type=str, default='client.key')
parser.add_argument('--cert-chain', type=str, default='client.crt')

## Parse the arguments
args = parser.parse_args()

## Target controller
target = '%s:%d' % (args.host, args.port)

## Interval (in seconds)
interval = 60 * 2

## Initialize the GNMI client
client = cisco_gnmi.ClientBuilder(target).set_os('IOS XE').set_secure_from_file(
    root_certificates=args.cacert,
    private_key=args.private_key,
    certificate_chain=args.cert_chain,
).construct()

"""
Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data
"""
def client_common_oper_data(db, c, ts, hwts, jm):
    sql = '''insert into client_oper_data (ts, hwts, client_mac, ap_name, ms_ap_slot_id, ms_radio_type, wlan_id, client_type, co_state, username) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
    try:
        if isinstance(jm['username'], str):
            username = jm['username']
        else:
            username = ''
    except:
        username = ''
    try:
        vals = (ts, hwts, jm['client-mac'], jm['ap-name'], jm['ms-ap-slot-id'], jm['ms-radio-type'], jm['wlan-id'], jm['client-type'], jm['co-state'], username)
        c.execute(sql, vals)
    except:
        print('client_oper_data', sql, jm)
    return

"""
Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data
"""
def client_dot11_oper_data(db, c, ts, hwts, jm):
    sql = '''insert into client_dot11_oper_data (ts, hwts, ms_mac_address, ms_bssid, ap_mac_address, current_channel, ms_wlan_id, vap_ssid, policy_profile, ms_ap_slot_id, radio_type, ms_assoc_time, is_11g_client, ewlc_ms_phy_type, encryption_type, dot11_6ghz_cap) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
    v1 = False
    try:
        if jm['is-11g-client'] == 'true':
            v1 = True
    except:
        pass
    v2 = False
    try:
        if jm['dot11-6ghz-cap'] == 'true':
            v2 = True
    except:
        pass
    try:
        vals = (ts, hwts, jm['ms-mac-address'], jm['ms-bssid'], jm['ap-mac-address'], jm['current-channel'], jm['ms-wlan-id'], jm['vap-ssid'], jm['policy-profile'], jm['ms-ap-slot-id'], jm['radio-type'], jm['ms-assoc-time'], v1, jm['ewlc-ms-phy-type'], jm['encryption-type'], v2)
        c.execute(sql, vals)
    except:
        print('client_dot11_oper_data', sql, jm)
    return

"""
Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats
"""
def client_traffic_stats(db, c, ts, hwts, jm):
    try:
        sql = '''insert into client_traffic_stats (ts, hwts, ms_mac_address, bytes_rx, bytes_tx, pkts_rx, pkts_tx, data_retries, mic_mismatch, mic_missing, most_recent_rssi, most_recent_snr, tx_retries, speed, spatial_stream) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
        vals = (ts, hwts, jm['ms-mac-address'], jm['bytes-rx'], jm['bytes-tx'], jm['pkts-rx'], jm['pkts-tx'], jm['data-retries'], jm['mic-mismatch'], jm['mic-missing'], jm['most-recent-rssi'], jm['most-recent-snr'], jm['tx-retries'], jm['speed'], jm['spatial-stream'])
        c.execute(sql, vals)
    except:
        print('client_traffic_stats', sql, jm)
    return

"""
Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac
"""
def client_sisf_db_mac(db, c, ts, hwts, jm):
    try:
        ipv4 = jm['ipv4-binding']['ip-key']['ip-addr']
    except:
        ipv4 = ''
    ipv6list = []
    try:
        for e in jm['ipv6-binding']:
            if e['ip-key']['ip-addr']:
                ipv6list.append(e['ip-key']['ip-addr'])
    except:
        pass
    ipv6 = "\n".join(ipv6list)
    sql = '''insert into client_sisf_db_mac (ts, hwts, mac_addr, ipv4_binding, ipv6_binding) values (%s, %s, %s, %s, %s)'''
    vals = (ts, hwts, jm['mac-addr'], ipv4, ipv6)
    c.execute(sql, vals)

    ## IPv4
    sql = '''insert into ipbinding (ts, ip_addr, mac_addr) values(%s, %s, %s)'''
    if ipv4 and ipv4 != '':
        vals = (ts, ipv4, jm['mac-addr'])
        c.execute(sql, vals)
    for ipv6 in ipv6list:
        vals = (ts, ipv6, jm['mac-addr'])
        c.execute(sql, vals)
    return

"""
Main routine
"""
def main():
    ## Database preparation
    db = mydb.connect()
    c = db.cursor()

    xpaths = ['Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac']

    ## Use get instead of subscribe as subscribe has some issues
    while True:
        ts = int(time.time())
        response = client.get_xpaths(xpaths, data_type='STATE', encoding='JSON_IETF')
        for msg in response.notification:
            ## Timestamp
            hwts = msg.timestamp
            for um in msg.update:
                ## common-oper-data
                if um.path.elem[0].name == 'Cisco-IOS-XE-wireless-client-oper:client-oper-data':
                    if um.path.elem[1].name == 'common-oper-data':
                        client_common_oper_data(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
                    elif um.path.elem[1].name == 'dot11-oper-data':
                        client_dot11_oper_data(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
                    elif um.path.elem[1].name == 'traffic-stats':
                        client_traffic_stats(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
                    elif um.path.elem[1].name == 'sisf-db-mac':
                        client_sisf_db_mac(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
                #print(um)
        ## data point
        sql = '''insert into datapoints (ts) values(%s)'''
        c.execute(sql, (ts, ))
        db.commit()
        time.sleep(interval)

if __name__ == "__main__":
    main()
