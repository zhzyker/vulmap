#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from thirdparty import requests
from module import globals
from module.color import color
from module.time import now
from module.md5 import random_md5
import json
import time


def dns_request():
    timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
    dnslog = globals.get_value("DNSLOG")  # 获取全局变量DNSLOG
    #print(dnslog)

    def ceye_io():
        ceye_host = globals.get_value("ceye_domain")
        ceye_token = globals.get_value("ceye_token")
        if r"xxxxxx" not in ceye_host:
            dns_host = random_md5() + "." + ceye_host
            return dns_host
    def dnslog_cn():
        headers_dnslog = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
            'Host': 'www.dnslog.cn',
            'Cookie': 'UM_distinctid=1703200149e449-053d4e8089c385-741a3944-1fa400-1703200149f80a; PHPSESSID=jfhfaj7op8u8i5sif6d4ai30j4; CNZZDATA1278305074=1095383570-1581386830-null%7C1581390548',
            'Accept': '*/*',
            'Referer': 'http://www.dnslog.cn/',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'
        }
        dnslog_api = "http://www.dnslog.cn/getdomain.php?t=0.08025501698741366"
        d_p = globals.get_value("DNS_DNSLOG_HOST")
        try:
            if d_p is None:
                dns = requests.get(dnslog_api, headers=headers_dnslog, timeout=timeout, verify=False)
                dns_host = random_md5() + "." + dns.text
                globals.set_value("DNS_DNSLOG_HOST", dns.text)
                return dns_host
            else:
                dns_host = random_md5() + "." + globals.get_value("DNS_DNSLOG_HOST")
                return dns_host
        except Exception:
            return "error"
    def hyuga_co():
        headers_hyuga = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
            'Connection': 'close',
            'Accept': '*/*',
            'Accept-Language': 'zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6'
        }
        hyuga_api = "http://api.hyuga.co/v1/users"
        hyuga_host = globals.get_value("hyuga_domain")
        hyuga_token = globals.get_value("hyuga_token")
        try:
            if r"xxxxxx" in hyuga_host:  # 如果没有指定域名和token，就自动获取, 第一次获取token
                if r"xxxxxx" in hyuga_token:
                    dns = requests.post(hyuga_api, headers=headers_hyuga, timeout=timeout, verify=False)
                    hyuga_host = json.loads(dns.text)["data"]["identity"]
                    dns_host = random_md5() + "." + str(hyuga_host)
                    hyuga_token = json.loads(dns.text)["data"]["token"]
                    globals.set_value("hyuga_token", hyuga_token)
                    globals.set_value("hyuga_domain", hyuga_host)
                    return dns_host
                else:
                    return "bug"
            else:
                dns_host = random_md5() + "." + hyuga_host
                return dns_host
        except Exception as e:
            pass
    if dnslog == "auto":
        if hyuga_co():  # 判断dns平台是否可用时调用一次，仅存活测试
            dns_req = hyuga_co()
            globals.set_value("AUTO_DNSLOG", "hyuga")
            return dns_req
        elif dnslog_cn():  # 判断dns平台是否可用时调用一次，仅存活测试
            dns_req = dnslog_cn()
            globals.set_value("AUTO_DNSLOG", "dnslog")
            return dns_req
        elif ceye_io():
            dns_req = ceye_io()
            globals.set_value("AUTO_DNSLOG", "ceye")
            return dns_req
        else:
            print(now.timed(de=0) + color.red_warn() + color.red(" The dnslog platform cannot be used, please check the current network"))
            return "no dnslog"
    elif r"hyuga" in dnslog:
        dns_req = hyuga_co()
        #globals.set_value("DNSLOG", "hyuga")
        return str(dns_req)
    elif r"dnslog" in dnslog:
        dns_req = dnslog_cn()

        #globals.set_value("DNSLOG", "dnslog")
        return dns_req
    elif r"ceye" in dnslog:
        ceye_host = globals.get_value("ceye_domain")
        if r"xxxxxx" in ceye_host:
            print(now.timed(de=0) + color.red_warn() + color.red(" Ceye.io domain and token are incorrectly configured"))
            exit(0)
        dns_req = ceye_io()
        #globals.set_value("DNSLOG", "ceye")
        return dns_req
    else:
        return "no dnslog"
        #print(now.timed(de=0) + color.red_warn() + color.red(" Only supports (hyuga, dnslog, ceye)"))
        #exit(0)

def dns_result(md):
    time.sleep(1)
    timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
    dnslog = globals.get_value("DNSLOG")  # 获取全局变量DNSLOG，用于判断dnslog平台类型
    def ceye_io(md):
        ceye_token = globals.get_value("ceye_token")
        api_url = "http://api.ceye.io/v1/records?type=dns&token=" + ceye_token
        headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        res = requests.get(api_url, headers=headers, timeout=timeout, verify=False)
        if md in res.text:
            return md

    def dnslog_cn(md):
        headers_dnslog = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3970.5 Safari/537.36',
            'Host': 'www.dnslog.cn',
            'Cookie': 'UM_distinctid=1703200149e449-053d4e8089c385-741a3944-1fa400-1703200149f80a; PHPSESSID=jfhfaj7op8u8i5sif6d4ai30j4; CNZZDATA1278305074=1095383570-1581386830-null%7C1581390548',
            'Accept': '*/*',
            'Referer': 'http://www.dnslog.cn/',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Connection': 'close'
        }
        dnslog_url = "http://www.dnslog.cn/getrecords.php?t=0.913020034617231"
        dns = requests.get(dnslog_url, headers=headers_dnslog, timeout=timeout, verify=False)
        if md in dns.text:
            return md

    def hyuga_co(md):
        headers_hyuga = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36',
            'Connection': 'close',
            'Accept': '*/*',
            'Accept-Language': 'zh,zh-TW;q=0.9,en-US;q=0.8,en;q=0.7,zh-CN;q=0.6'
        }
        hyuga_token = globals.get_value("hyuga_token")
        hyuga_url = "http://api.hyuga.co/v1/records?type=dns&token=" + hyuga_token
        dns = requests.get(hyuga_url, headers=headers_hyuga, timeout=timeout, verify=False)
        if md in dns.text:
            return md

    if dnslog == "auto":
        au_dns = globals.get_value("AUTO_DNSLOG")
        if au_dns == "hyuga":
            dns_req = hyuga_co(md)
            return dns_req
        elif au_dns == "dnslog":
            dns_req = dnslog_cn(md)
            return dns_req
        elif au_dns == "ceye":
            dns_req = ceye_io(md)
            return dns_req
    else:
        if r"hyuga" in dnslog:
            dns_req = hyuga_co(md)
            return dns_req
        elif r"dnslog" in dnslog:
            dns_req = dnslog_cn(md)
            return dns_req
        elif r"ceye" in dnslog:
            dns_req = ceye_io(md)
            return dns_req
        else:
            pass
            # print("error ???")
