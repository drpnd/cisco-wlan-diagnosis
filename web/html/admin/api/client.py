
import os
import time
import json
import api.config
import api.mydb

"""
Resolve the IP address of the requested client
"""
def resolve_ipaddr():
    if "REMOTE_ADDR" in os.environ:
        return os.environ["REMOTE_ADDR"]
    else:
        return None

"""
Resolve the MAC address of the client
"""
def resolve_macaddr(db, c):
    ipaddr = resolve_ipaddr()
    sql = 'select ts from datapoints order by id desc limit 1'
    c.execute(sql)
    res = c.fetchone()
    if res:
        d = dict(zip(c.column_names, res))
        ts = d['ts']
    else:
        return False
    sql = 'select * from ipbinding where ts=%s and ip_addr=%s'
    c.execute(sql, (ts, ipaddr))
    res = c.fetchone()
    if res:
        d = dict(zip(c.column_names, res))
        mac_addr = d['mac_addr']
    else:
        return False
    return mac_addr

"""
Client AP history
"""
def ap_history(mac_addr, ts_min, ts_max):
    ## Database preparation
    db = api.mydb.connect()
    c = db.cursor()
    sql = 'select * from client_oper_data t1 inner join client_dot11_oper_data t2 on t1.client_mac=t2.ms_mac_address and t1.ts=t2.ts where t1.client_mac=%s and t1.ts>=%s and t1.ts<=%s order by t1.ts'
    c.execute(sql, (mac_addr, ts_min, ts_max))
    res = c.fetchall()
    cols = c.column_names
    aphist = {}
    for r in res:
        r  = dict(zip(cols, r))
        d = {'ts': r['ts'], 'data': True, 'ap_name': r['ap_name'], 'radio_type': r['ms_radio_type'], 'bssid': r['ms_bssid'], 'ap_mac_address': r['ap_mac_address'], 'channel': r['current_channel'], 'ssid': r['vap_ssid'], 'phy_type': r['ewlc_ms_phy_type']}
        aphist[r['ts']] = d
    sql = 'select * from datapoints where ts>=%s and ts<=%s order by ts'
    c.execute(sql, (ts_min, ts_max))
    res = c.fetchall()
    cols = c.column_names
    hist = []
    for r in res:
        r  = dict(zip(cols, r))
        if r['ts'] in aphist:
            d = aphist[r['ts']]
        else:
            d = {'ts': r['ts'], 'data': False}
        hist.append(d)
    print("Content-type: application/json\r\n")
    print(json.dumps(hist))
    return

"""
Client statistics
"""
def statistics(mac_addr, ts_min, ts_max):
    ## Database preparation
    db = api.mydb.connect()
    c = db.cursor()
    sql = 'select t0.ts,t0.ms_mac_address,t4.bytes_rx,t4.bytes_tx,t4.pkts_rx,t4.pkts_tx,t4.data_retries,t4.mic_mismatch,t4.mic_missing,t4.most_recent_rssi,t4.most_recent_snr,t4.tx_retries,t4.speed,t4.spatial_stream,t0.vap_ssid,t0.current_channel,t0.ms_bssid,t1.bssid_mac,t2.curr_freq,t2.chan_width,t3.rx_util_percentage,t3.tx_util_percentage,t3.cca_util_percentage,t3.rx_noise_channel_utilization,t5.name,t5.ap_location from client_dot11_oper_data t0 inner join client_traffic_stats t4 on t0.ts=t4.ts and t0.ms_mac_address=t4.ms_mac_address inner join ap_radio_oper_data_vap_oper_config t1 on t0.ts=t1.ts and t0.ms_bssid=t1.bssid_mac and t0.ms_ap_slot_id=t1.radio_slot_id inner join ap_radio_oper_data t2 on t1.ts=t2.ts and t1.wtp_mac=t2.wtp_mac and t1.radio_slot_id=t2.radio_slot_id left join rrm_measurement t3 on t2.ts=t3.ts and t2.wtp_mac=t3.wtp_mac and t2.radio_slot_id=t3.radio_slot_id inner join ap_capwap_data t5 on t2.ts=t5.ts and t2.wtp_mac=t5.wtp_mac'
    sql += ' where t0.ms_mac_address=%s and t0.ts>=%s and t0.ts<=%s order by t0.ts'
    #sql = 'select * from client_traffic_stats where ms_mac_address=%s and ts>=%s and ts<=%s order by ts'
    c.execute(sql, (mac_addr, ts_min, ts_max))
    res = c.fetchall()
    cols = c.column_names
    aphist = {}
    for r in res:
        r  = dict(zip(cols, r))
        d = {'ts': r['ts'], 'data': True, 'bytes_rx': r['bytes_rx'], 'bytes_tx': r['bytes_tx'], 'pkts_rx': r['pkts_rx'], 'pkts_tx': r['pkts_tx'], 'data_retries': r['data_retries'], 'mic_mismatch': r['mic_mismatch'], 'mic_missing': r['mic_missing'], 'most_recent_rssi': r['most_recent_rssi'], 'most_recent_snr': r['most_recent_snr'], 'tx_retries': r['tx_retries'], 'speed': r['speed'], 'spatial_stream': r['spatial_stream'], 'vap_ssid': r['vap_ssid'], 'bssid': r['ms_bssid'], 'curr_freq': r['curr_freq'], 'chan_width': r['chan_width'], 'rx_util_percentage': r['rx_util_percentage'], 'tx_util_percentage': r['tx_util_percentage'], 'cca_util_percentage': r['cca_util_percentage'], 'rx_noise_channel_utilization': r['rx_noise_channel_utilization'], 'name': r['name'], 'ap_location': r['ap_location']}
        aphist[r['ts']] = d
    sql = 'select * from datapoints where ts>=%s and ts<=%s order by ts'
    c.execute(sql, (ts_min, ts_max))
    res = c.fetchall()
    cols = c.column_names
    hist = []
    for r in res:
        r  = dict(zip(cols, r))
        if r['ts'] in aphist:
            d = aphist[r['ts']]
        else:
            d = {'ts': r['ts'], 'data': False}
        hist.append(d)
    print("Content-type: application/json\r\n")
    print(json.dumps(hist))
    return

"""
Get related syslog
"""
def syslog(mac_addr, ts_min, ts_max):
    ## Database preparation
    db = api.mydb.connect()
    c = db.cursor()
    sql = 'select * from logs where msg like %s limit 10'
    c.execute(sql, ('%'+mac_addr+'%',))
    pass

def token(args):
    ## Database preparation
    db = api.mydb.connect()
    c = db.cursor()
    print("Content-type: text/plain\r\n")
    #print(resolve_ipaddr())
    #print(resolve_macaddr(db, c))
    ## Resolve the AP connection history
    mac_addr = resolve_macaddr(db, c)
    if not mac_addr:
        return False
    #print(ap_history(db, c, int(time.time() - 3600), int(time.time())))
    return

