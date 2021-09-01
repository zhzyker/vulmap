#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: zhzyker
# github: https://github.com/zhzyker/vulmap
from module.color import color
import random

banner_1 = color.yellow("""                   __
                  [  |                              
  _   __  __   _   | |  _ .--..--.   ,--.  _ .--.   
 [ \ [  ][  | | |  | | [ `.-. .-. | `'_\ :[ '/'`\ \ 
  \ \/ /  | \_/ |, | |  | | | | | | // | |,| \__/ | 
   \__/   '.__.'_/[___][___||__||__]\'-;__/| ;.___/  
                                          [__|""")

banner_2 = color.yellow(r'''
                                +---------------+
 How to find vulnerabilities?   |    vulmap     |
                                +---------------+ 
    (╯▔＾▔)╯                        \ (•◡ •) / 
     \   |                            |   /
￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣￣''')


def banner():
    o_o = random.choice(range(10))
    if o_o == 0:
        return banner_1
    elif o_o == 1:
        return banner_1
    elif o_o == 2:
        return banner_1
    elif o_o == 3:
        return banner_1
    elif o_o == 3:
        return banner_1
    elif o_o == 4:
        return banner_1
    elif o_o == 5:
        return banner_1
    elif o_o == 6:
        return banner_1
    elif o_o == 7:
        return banner_1
    elif o_o == 8:
        return banner_1
    elif o_o == 9:
        return banner_2


def vul_list():
    vuln_list = color.cyan_fine("""
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Apache ActiveMQ   | CVE-2015-5254    |  Y  |  N  | < 5.13.0, deserialization remote code execution             |
 | Apache ActiveMQ   | CVE-2016-3088    |  Y  |  Y  | < 5.14.0, http put&move upload webshell                     |
 | Apache Druid      | CVE-2021-25646   |  Y  |  Y  | < 0.20.1, apache druid console remote code execution        |
 | Apache Flink      | CVE-2020-17518   |  Y  |  N  | < 1.11.3 or < 1.12.0, upload path traversal                 |
 | Apache Flink      | CVE-2020-17519   |  Y  |  Y  | 1.5.1 - 1.11.2, 'jobmanager/logs' path traversal            |
 | Apache OFBiz      | CVE-2021-26295   |  Y  |  N  | < 17.12.06, rmi deserializes arbitrary code execution       |
 | Apache OFBiz      | CVE-2021-29200   |  Y  |  N  | < 17.12.07, rmi deserializes arbitrary code execution       |
 | Apache OFBiz      | CVE-2021-30128   |  Y  |  Y  | < 17.12.07, deserialize remote command execution            | 
 | Apache Shiro      | CVE-2016-4437    |  Y  |  Y  | <= 1.2.4, shiro-550, rememberme deserialization rce         |
 | Apache Solr       | CVE-2017-12629   |  Y  |  Y  | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
 | Apache Solr       | CVE-2019-0193    |  Y  |  N  | < 8.2.0, dataimporthandler module remote code execution     |
 | Apache Solr       | CVE-2019-17558   |  Y  |  Y  | 5.0.0 - 8.3.1, velocity response writer rce                 |
 | Apache Solr       | time-2021-0318   |  Y  |  Y  | all, apache solr arbitrary file reading                     |
 | Apache Solr       | CVE-2021-27905   |  Y  |  N  | 7.0.0-7.7.3, 8.0.0-8.8.1, replication handler ssrf          |
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
 | Apache Struts2    | S2-059           |  Y  |  Y  | 2.0.0 - 2.5.20, cve-2019-0230 ognl interpreter rce          |
 | Apache Struts2    | S2-061           |  Y  |  Y  | 2.0.0-2.5.25, cve-2020-17530 ognl interpreter rce           |
 | Apache Struts2    | S2-devMode       |  Y  |  Y  | 2.1.0 - 2.5.1, devmode remote code execution                |
 | Apache Tomcat     | Examples File    |  Y  |  N  | all version, /examples/servlets/servlet                     |
 | Apache Tomcat     | CVE-2017-12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Apache Unomi      | CVE-2020-13942   |  Y  |  Y  | < 1.5.2, apache unomi remote code execution                 |
 | CoreMail          | time-2021-0414   |  Y  |  N  | Coremail configuration information disclosure vulnerability |
 | Drupal            | CVE-2018-7600    |  Y  |  Y  | 6.x, 7.x, 8.x, drupalgeddon2 remote code execution          |
 | Drupal            | CVE-2018-7602    |  Y  |  Y  | < 7.59, < 8.5.3 (except 8.4.8) drupalgeddon2 rce            |
 | Drupal            | CVE-2019-6340    |  Y  |  Y  | < 8.6.10, drupal core restful remote code execution         |
 | Ecology           | time-2021-0515   |  Y  |  Y  | <= 9.0, e-cology oa workflowservicexml rce                  |
 | Elasticsearch     | CVE-2014-3120    |  Y  |  Y  | < 1.2, elasticsearch remote code execution                  |
 | Elasticsearch     | CVE-2015-1427    |  Y  |  Y  | < 1.3.7, < 1.4.3, elasticsearch remote code execution       |
 | Exchange          | CVE-2021-26855   |  Y  |  N  | 2010 2013 2016 2019, microsoft exchange server ssrf         |
 | Exchange          | CVE-2021-27065   |  Y  |  Y  | 2010 2013 2016 2019, exchange arbitrary file write          |
 | Eyou Email        | CNVD-2021-26422  |  Y  |  Y  | eyou email system has remote command execution              |
 | F5 BIG-IP         | CVE-2020-5902    |  Y  |  Y  | < 11.6.x, f5 big-ip remote code execution                   |
 | F5 BIG-IP         | CVE-2021-22986   |  Y  |  Y  | < 16.0.1, f5 big-ip remote code execution                   |
 | Fastjson          | VER-1224-1       |  Y  |  Y  | <= 1.2.24 fastjson parse object remote code execution       |
 | Fastjson          | VER-1224-2       |  Y  |  Y  | <= 1.2.24 fastjson parse object remote code execution       |
 | Fastjson          | VER-1224-3       |  Y  |  Y  | <= 1.2.24 fastjson parse object remote code execution       |
 | Fastjson          | VER-1247         |  Y  |  Y  | <= 1.2.47 fastjson autotype remote code execution           |
 | Fsatjson          | VER-1262         |  Y  |  Y  | <= 1.2.62 fastjson autotype remote code execution           |
 | Jenkins           | CVE-2017-1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
 | Jenkins           | CVE-2018-1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Laravel           | CVE-2018-15133   |  N  |  Y  | 5.5.x <= 5.5.40, 5.6.x <= 5.6.29, laravel get app_key rce   |
 | Laravel           | CVE-2021-3129    |  Y  |  N  | ignition <= 2.5.1, laravel debug mode remote code execution |
 | Nexus OSS/Pro     | CVE-2019-7238    |  Y  |  Y  | 3.6.2 - 3.14.0, remote code execution vulnerability         |
 | Nexus OSS/Pro     | CVE-2020-10199   |  Y  |  Y  | 3.x <= 3.21.1, remote code execution vulnerability          |
 | Node.JS           | CVE-2021-21315   |  Y  |  N  | systeminformation < 5.3.1, node.js command injection        |
 | Oracle Weblogic   | CVE-2014-4210    |  Y  |  N  | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2016-0638    |  Y  |  N  | 10.3.6.0, 12.2.1-3, t3 deserialization rce                  |
 | Oracle Weblogic   | CVE-2017-3506    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    |  Y  |  Y  | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2018-3191    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3, t3 deserialization rce        |
 | Oracle Weblogic   | CVE-2019-2725    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2890    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3, t3 deserialization rce        |
 | Oracle Weblogic   | CVE-2019-2729    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3 wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2551    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, wlscore deserialization rce |
 | Oracle Weblogic   | CVE-2020-2555    |  Y  |  Y  | 3.7.1.17, 12.1.3.0.0, 12.2.1.3-4.0, t3 deserialization rce  |
 | Oracle Weblogic   | CVE-2020-2883    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, iiop t3 deserialization rce |
 | Oracle Weblogic   | CVE-2020-14882   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2020-2109    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, unauthorized jndi |
 | QiAnXin           | time-2021-0410   |  Y  |  Y  | qianxin ns-ngfw netkang next generation firewall front rce  |
 | RedHat JBoss      | CVE-2010-0738    |  Y  |  Y  | 4.2.0 - 4.3.0, jmx-console deserialization any files upload |
 | RedHat JBoss      | CVE-2010-1428    |  Y  |  Y  | 4.2.0 - 4.3.0, web-console deserialization any files upload |
 | RedHat JBoss      | CVE-2015-7501    |  Y  |  Y  | 5.x, 6.x, jmxinvokerservlet deserialization any file upload |
 | RuiJie            | time_2021_0424   |  Y  |  N  | get account password, background rce                        |
 | Saltstack         | CVE-2021-25282   |  Y  |  Y  | < 3002.5, saltStack arbitrary file writing vulnerability    |
 | Spring Data       | CVE-2018-1273    |  Y  |  Y  | 1.13 - 1.13.10, 2.0 - 2.0.5, spring data commons rce        |
 | Spring Cloud      | CVE-2019-3799    |  Y  |  Y  | 2.1.0-2.1.1, 2.0.0-2.0.3, 1.4.0-1.4.5, directory traversal  |
 | Spring Cloud      | CVE-2020-5410    |  Y  |  Y  | < 2.2.3, < 2.1.9, directory traversal vulnerability         |
 | ThinkPHP          | CVE-2019-9082    |  Y  |  Y  | < 3.2.4, thinkphp rememberme deserialization rce            |
 | ThinkPHP          | CVE-2018-20062   |  Y  |  Y  | <= 5.0.23, 5.1.31, thinkphp rememberme deserialization rce  |
 | Vmware vCenter    | time-2020-1013   |  Y  |  N  | <= 6.5u1, vmware vcenter arbitrary file reading (not cve)   |
 | Vmware vCenter    | CVE-2021-21972   |  Y  |  Y  | 7.0 < 7.0U1c, 6.7 < 6.7U3l, 6.5 < 6.5U3n, any file upload   |
 | VMware vRealize   | CVE-2021-21975   |  Y  |  N  | <= 8.3.0, vmware vrealize operations manager api ssrf       |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
    """ + color.yellow("\n Vulmap release does not provide the exploit function after September 1, 2021 \n"))
    return vuln_list
