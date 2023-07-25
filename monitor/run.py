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
msgsize = 500 * 1024 * 1024
client = cisco_gnmi.ClientBuilder(target).set_os('IOS XE').set_channel_option('grpc.max_message_length', msgsize).set_secure_from_file(
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
Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/radio-oper-data
"""
def ap_radio_oper_data(db, c, ts, hwts, jm):
    vht = False
    if jm['phy-ht-cfg']['cfg-data']['vht-enable'] == 'true':
        vht = True
    sql = '''insert into ap_radio_oper_data (ts, wtp_mac, radio_slot_id, slot_id, radio_type, admin_state, oper_state, radio_mode, radio_sub_mode, radio_subtype, radio_subband, ht_enable, phy_ht_cfg_config_type, curr_freq, chan_width, ext_chan, vht_enable, rrm_channel_change_reason) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
    vals = (ts, jm['wtp-mac'], jm['radio-slot-id'], jm['slot-id'], jm['radio-type'], jm['admin-state'], jm['oper-state'], jm['radio-mode'], jm['radio-sub-mode'], jm['radio-subtype'], jm['radio-subband'], jm['phy-ht-cfg']['cfg-data']['ht-enable'], jm['phy-ht-cfg']['cfg-data']['phy-ht-cfg-config-type'], jm['phy-ht-cfg']['cfg-data']['curr-freq'], jm['phy-ht-cfg']['cfg-data']['chan-width'], jm['phy-ht-cfg']['cfg-data']['ext-chan'], vht, jm['phy-ht-cfg']['cfg-data']['rrm-channel-change-reason'])
    c.execute(sql, vals)
    if 'vap-oper-config' in jm:
        try:
            for d in jm['vap-oper-config']:
                sql = '''insert into ap_radio_oper_data_vap_oper_config (ts, wtp_mac, radio_slot_id, ap_vap_id, wlan_id, bssid_mac, wlan_profile_name, ssid) values(%s, %s, %s, %s, %s, %s, %s, %s)'''
                vals = (ts, jm['wtp-mac'], jm['radio-slot-id'], d['ap-vap-id'], d['wlan-id'], d['bssid-mac'], d['wlan-profile-name'], d['ssid'])
                c.execute(sql, vals)
        except:
            print('ap_radio_oper_data/vap', sql, jm)
    if 'radio-band-info' in jm:
        try:
            for d in jm['radio-band-info']:
                sql = '''insert into ap_radio_oper_data_radio_band_info (ts, wtp_mac, radio_slot_id, band_id, phy_tx_power_config_type, current_tx_power_level, num_supp_power_levels, curr_tx_power_in_dbm, diversity_selection, antenna_mode, num_of_antennas) values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'''
                vals = (ts, jm['wtp-mac'], jm['radio-slot-id'], d['band-id'], d['phy-tx-pwr-cfg']['cfg-data']['phy-tx-power-config-type'], d['phy-tx-pwr-cfg']['cfg-data']['current-tx-power-level'], d['phy-tx-pwr-lvl-cfg']['cfg-data']['num-supp-power-levels'], d['phy-tx-pwr-lvl-cfg']['cfg-data']['curr-tx-power-in-dbm'], d['antenna-cfg']['cfg-data']['diversity-selection'], d['antenna-cfg']['cfg-data']['antenna-mode'], d['antenna-cfg']['cfg-data']['num-of-antennas'])
                c.execute(sql, vals)
        except:
            print('ap_radio_oper_data/radio-band-info', sql, jm)
    return

"""
Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/rrm_measurement
"""
def rrm_measurement(db, c, ts, hwts, jm):
    try:
        sql = '''insert into rrm_measurement (ts, wtp_mac, radio_slot_id, rx_util_percentage, tx_util_percentage, cca_util_percentage, rx_noise_channel_utilization) values(%s, %s, %s, %s, %s, %s, %s)'''
        vals = (ts, jm['wtp-mac'], jm['radio-slot-id'], jm['load']['rx-util-percentage'], jm['load']['tx-util-percentage'], jm['load']['cca-util-percentage'], jm['load']['rx-noise-channel-utilization'])
        c.execute(sql, vals)
    except:
        print('rrm_measurement', sql, jm)
    return

"""
Main routine
"""
def main():
    ## Database preparation
    db = mydb.connect()
    c = db.cursor()

    xpaths = ['Cisco-IOS-XE-wireless-client-oper:client-oper-data/common-oper-data', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/dot11-oper-data', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/traffic-stats', 'Cisco-IOS-XE-wireless-client-oper:client-oper-data/sisf-db-mac', 'Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data/radio-oper-data', 'Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data/rrm-measurement']

    ## Use get instead of subscribe as subscribe has some issues
    while True:
        ts = int(time.time())
        for xpath in xpaths:
            response = client.get_xpaths([xpath], data_type='STATE', encoding='JSON_IETF')
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
                    elif um.path.elem[0].name == 'Cisco-IOS-XE-wireless-access-point-oper:access-point-oper-data':
                        if um.path.elem[1].name == 'radio-oper-data':
                            ap_radio_oper_data(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
                    elif um.path.elem[0].name == 'Cisco-IOS-XE-wireless-rrm-oper:rrm-oper-data':
                        if um.path.elem[1].name == 'rrm-measurement':
                            rrm_measurement(db, c, ts, hwts, json.loads(um.val.json_ietf_val))
        ## data point
        sql = '''insert into datapoints (ts) values(%s)'''
        c.execute(sql, (ts, ))
        db.commit()
        time.sleep(interval)

if __name__ == "__main__":
    main()
