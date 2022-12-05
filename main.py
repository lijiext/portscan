import nmap
import json
import os
import time
from subprocess import PIPE, Popen
from datetime import datetime
import concurrent.futures
import requests

def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True,
        stderr=PIPE
    )
    exitcode = process.wait()
    return exitcode

def masscan(target_file, rate, exclude):
    # masscan not installed
    if cmdline('which masscan') != 0:
        print('masscan not found')
        exit(1)
    start_time = time.time()
    # excute the scan and save result to json file
    flag = cmdline(f'sudo masscan -iL {target_file} -p1-65535 --rate {rate} --exclude={exclude}  -oJ scan_result.json')
    end_time = time.time()
    scan_used_time = end_time - start_time
    # print(f'masscan used time: {scan_used_time}')
    # print time cost human readable
    print(f'masscan used time: {time.strftime("%H:%M:%S", time.gmtime(scan_used_time))}')
    if flag == 0:
        # if exist scan_result.json
        if os.path.exists('scan_result.json'):
            with open('scan_result.json', 'r') as f:
                data = json.load(f)
                return data
            os.remove('scan_result.json')
        else:
            return []
    else:
        return []

def parse_masscan_json(data):
    if data:
        start_time = time.time()
        open_ports = []
        for i in data:
            if i['ports'][0]['status'] == 'open':
                timestamp = int(i['timestamp'])
                dt_object = datetime.fromtimestamp(timestamp)
                open_ports.append({'ip': i['ip'], 'port': str(i['ports'][0]['port']), 'time': str(dt_object)})
        end_time = time.time()
        parse_used_time = end_time - start_time
        # print(f'masscan result parse used time: {parse_used_time}')
        print(f'masscan result parse used time: {time.strftime("%H:%M:%S", time.gmtime(parse_used_time))}')
        return open_ports
    else:
        return []

def parse_masscan_json_by_ip(masscan_filtered):
     if masscan_filtered:
        ip_ports = []
        # get open port of a unique ip in masscan_filtered
        for i in masscan_filtered:
            ip = i['ip']
            # get unique ip's open ports
            ports = [j['port'] for j in masscan_filtered if j['ip'] == ip]
            # get unique ip's open ports and scan it
            ip_ports.append({"ip": ip, "ports": ports})
        # remove duplicate ip
        ip_ports = list({v['ip']:v for v in ip_ports}.values())
        return ip_ports

def filter_by_whitelist(scan_result, whitelist_file='whitelist.json'):
    if scan_result:
        start_time = time.time()
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
            # print(whitelist)
        else:
            whitelist = []
        for i in scan_result:
            # compare ip and port with whitelist
            for j in whitelist:
                if i['ip'] == j['ip'] and i['port'] == j['port']:
                    scan_result.remove(i)
        end_time = time.time()
        filter_used_time = end_time - start_time
        # print(f'filter used time: {filter_used_time}')
        print(f'whitelist filter used time: {time.strftime("%H:%M:%S", time.gmtime(filter_used_time))}')
        return scan_result
    else:
        return []


def nmap_scan(ip, port):
    nmap_filterd_ports = []
    try:
        start_time = time.time()
        nm = nmap.PortScanner()
        nm.scan(ip, port)
        state = nm[ip][nm[ip].all_protocols()[0]][int(port)]['state']
        service_name = nm[ip][nm[ip].all_protocols()[0]][int(port)]['name']
        nmap_filterd_ports.append({"ip": ip, "port": port, "state": state, "name": service_name})
        end_time = time.time()
        nmap_used_time = end_time - start_time
        print(f'nmap scan used time: {time.strftime("%H:%M:%S", time.gmtime(nmap_used_time))} for {ip}:{port}')
        return nmap_filterd_ports
    except Exception as e:
        print(e)

def concurrent_namp_scan(masscan_filtered):
    if masscan_filtered:
        scan_result = concurrent.futures.ThreadPoolExecutor(max_workers=1000).map(nmap_scan, [i['ip'] for i in masscan_filtered], [i['port'] for i in masscan_filtered])
        return list(scan_result)
    else:
        return []

def calc_scan_accuracy(scan_result, whitelist_file='whitelist.json'):
    # calc masscan scan accuracy
    if scan_result:
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
        else:
            whitelist = []
        # print(whitelist)
        scan_result_len = len(scan_result)
        whitelist_len = len(whitelist)
        accuracy = 1 - scan_result_len / whitelist_len
        print(f'masscan scan accuracy: {accuracy}')
        return accuracy
    pass

def trigger_webhook(type, data):
    if type == 'feishu':
        # feishu webhook
        webhook = 'https://open.feishu.cn/open-apis/bot/v2/hook/xxxxx'
        # feishu webhook header
        headers = {'Content-Type': 'application/json'}
        # feishu webhook data
        data = {
            "msg_type": "text",
            "content": {
                "text": data
            }
        }
        # trigger feishu webhook
        res = requests.post(webhook, headers=headers, data=json.dumps(data))
        if res.status_code == 200:
            print('feishu webhook trigger success')
        else:
            print('feishu webhook trigger failed')
    elif type == 'tt':
        # tt webhook
        webhook = 'http://xxxx.com:8080/robot/send?access_token=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
        # tt webhook header
        headers = {'Content-Type': 'application/json'}
        # tt webhook data
        data = {
            "msgtype": "text",
            "text": {
                "content": data
            }
        }
        # trigger tt webhook
        res = requests.post(webhook, headers=headers, data=json.dumps(data))

    pass

if __name__ == '__main__':
    print('start scan, please wait...')
    # masscan scan
    masscan_result = masscan(target_file='target.txt', rate=5000, exclude='10.0.0.0/8')
    # parse masscan result
    masscan_filtered = parse_masscan_json(masscan_result)
    # filter by whitelist
    masscan_filtered = filter_by_whitelist(masscan_filtered, whitelist_file='whitelist.json')
    # nmap scan
    scan_result = concurrent_namp_scan(masscan_filtered)
    print(scan_result)
    # # save scan result to json file
    # with open('scan_result.json', 'w') as f:
    #     json.dump(scan_result, f)