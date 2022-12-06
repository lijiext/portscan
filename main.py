import nmap
import json
import os
import time
from subprocess import PIPE, Popen
from datetime import datetime
import concurrent.futures
import requests
import logging

logger = logging.getLogger(__name__)
logger.setLevel(level=logging.INFO)
file_handler = logging.FileHandler('main.log')
formatter = logging.Formatter('%(asctime)s :: %(levelname)s :: %(funcName)s :: %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

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
    # 检测是否安装了 masscan
    if cmdline('which masscan') != 0:
        logger.error('没有安装 masscan')
        exit(1)
    if os.path.exists('paused.conf'):
        # 检测是否有 paused.conf 文件, 如果有, 则删除
        os.remove('paused.conf')
    start_time = time.time()
    # 暂存 masscan 结果到 scan_result.json
    logger.info(f'开始 masscan 扫描: sudo masscan -iL {target_file} -p1-65535 --rate {rate} --exclude={exclude}  -oJ scan_result.json')
    flag = cmdline(f'sudo masscan -iL {target_file} -p1-65535 --rate {rate} --exclude={exclude}  -oJ scan_result.json')
    end_time = time.time()
    scan_used_time = end_time - start_time
    logger.info(f'masscan 耗时: {time.strftime("%H:%M:%S", time.gmtime(scan_used_time))}')
    if flag == 0:
        # if exist scan_result.json
        if os.path.exists('scan_result.json'):
            with open('scan_result.json', 'r') as f:
                data = json.load(f)
                os.remove('scan_result.json')
                return data
        else:
            return []
    else:
        logger.error('masscan 扫描失败, exit code: %s' % flag)
        return []

def parse_masscan_json(data):
    if data:
        open_ports = []
        for i in data:
            if i['ports'][0]['status'] == 'open':
                timestamp = int(i['timestamp'])
                dt_object = datetime.fromtimestamp(timestamp)
                open_ports.append({'ip': i['ip'], 'port': str(i['ports'][0]['port']), 'time': str(dt_object)})
        return open_ports
    else:
        return []

def parse_masscan_json_by_ip(masscan_filtered):
     if masscan_filtered:
        ip_ports = []
        # 将 masscan 扫描结果按 ip 分组
        for i in masscan_filtered:
            ip = i['ip']
            # 某个 ip 的所有端口
            ports = [j['port'] for j in masscan_filtered if j['ip'] == ip]
            ip_ports.append({"ip": ip, "ports": ports})
        # 操作完后可能会有重复的 ip, 去重
        ip_ports = list({v['ip']:v for v in ip_ports}.values())
        return ip_ports

def filter_by_whitelist(scan_result, whitelist_file='whitelist.json'):
    if scan_result:
        logger.info(f'开始过滤白名单, 共有 {len(scan_result)} 条结果')
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist = json.load(f)
            logger.info(f'开始过滤白名单, 白名单中共有 {len(whitelist)} 条规则')
        else:
            logger.error('没有白名单文件')
            whitelist = []
        for i in scan_result:
            for j in whitelist:
                if i['ip'] == j['ip'] and i['port'] == j['port']:
                    logger.debug(f'过滤白名单: {i["ip"]}:{i["port"]}')
                    scan_result.remove(i)
        logger.info(f'过滤白名单后, 剩余 {len(scan_result)} 条结果')
        return scan_result
    else:
        logger.error('没有扫描结果, 无法过滤白名单')
        return []


def nmap_scan(ip, port):
    nmap_filterd_ports = []
    try:
        logger.info(f'开始 nmap 扫描: {ip}:{port}')
        start_time = time.time()
        nm = nmap.PortScanner()
        nm.scan(ip, port)
        state = nm[ip][nm[ip].all_protocols()[0]][int(port)]['state']
        service_name = nm[ip][nm[ip].all_protocols()[0]][int(port)]['name']
        nmap_filterd_ports.append({"ip": ip, "port": port, "state": state, "name": service_name})
        end_time = time.time()
        nmap_used_time = end_time - start_time
        logger.info(f'扫描结果: {ip}:{port} {state} {service_name} 用时: {time.strftime("%H:%M:%S", time.gmtime(nmap_used_time))}')
        return nmap_filterd_ports
    except Exception as e:
        logger.error(f'nmap 扫描失败: {ip}:{port}')

def concurrent_namp_scan(masscan_filtered):
    if masscan_filtered:
        scan_result = concurrent.futures.ThreadPoolExecutor(max_workers=1000).map(nmap_scan, [i['ip'] for i in masscan_filtered], [i['port'] for i in masscan_filtered])
        scan_result = list(scan_result)
        # repackage 
        scan_result = [i[0] for i in scan_result if i]
        return scan_result
    else:
        return []

def trigger_webhook(type, data):
    if type == 'feishu':
        logger.info('触发飞书 webhook')
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



def calc_masscan_accuaracy(masscan_result, whitelist_file='whitelist.json'):
    if len(masscan_result) == 0:
        logger.error('没有扫描结果, 无法计算准确率')
        return 0
    if os.path.exists(whitelist_file):
        with open(whitelist_file, 'r') as f:
            whitelist = json.load(f)
        # 计算准确率
        for i in masscan_result:
            for j in whitelist:
                if i['ip'] == j['ip'] and i['port'] == j['port']:
                    whitelist.remove(j)
        accuracy = 1 - len(whitelist) / len(masscan_result)
        return round(number=accuracy, ndigits=2)
    else:
        logger.error('白名单文件不存在, 无法计算准确率')
        return 1

def save_scan_result(scan_result=[]):
    if scan_result:
        # 保存结果到文件
        with open('result.json', 'w') as f:
            json.dump(scan_result, f, indent=2)
        logger.info('保存扫描结果成功')
    else:
        logger.error('没有扫描结果, 无法保存')

def diff_alert(new_scan_result):
    if new_scan_result:
        if os.path.exists('result.json'):
            with open('result.json', 'r') as f:
                old_scan_result = json.load(f)
            logger.info(f'旧的扫描结果: {old_scan_result}')
            logger.info(f'新的扫描结果: {new_scan_result}')
            # 计算差异
            # 增加的端口
            add_ip_port = [i for i in new_scan_result if i not in old_scan_result]
            # TODO 见鬼了, 为什么这里会有重复的端口
            del_ip_port = [i for i in old_scan_result if i not in new_scan_result]
            if add_ip_port or del_ip_port:
                logger.info('发现差异, 触发告警')
                logger.info(f'增加的端口: {add_ip_port}')
                logger.info(f'减少的端口: {del_ip_port}')
            else:
                logger.info('没有差异, 不触发告警')
    else:
        logger.error('没有扫描结果, 无法进行差异告警')

if __name__ == '__main__':
    logger.info('开始端口扫描')
    # 1. masscan 扫描
    masscan_result = masscan(target_file='target.txt', rate=5000, exclude='10.0.0.0/8')
    # 2. 过滤 masscan 结果为需要的格式
    masscan_filtered = parse_masscan_json(masscan_result)
    # 3. 在这一步计算准确率
    accuarcy = calc_masscan_accuaracy(masscan_filtered)
    logger.info(f'准确率: {accuarcy * 100}%')
    # 4. 过滤白名单
    masscan_filtered = filter_by_whitelist(masscan_filtered, whitelist_file='whitelist.json')
    # 5. nmap 再次扫描
    # 表示不在白名单中的端口信息
    nmap_scan_result = concurrent_namp_scan(masscan_filtered)
    # 6. 和上次的结果比较并进行告警
    # TODO
    diff_alert(nmap_scan_result)

    # 7. 保存本次扫描结果到文件
    save_scan_result(nmap_scan_result)

