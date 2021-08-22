## 🌟 Vulmap - Web vulnerability scanning and verification tools
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/python-3.8+-blueviolet"></a>
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/Version-vulmap 0.8-yellow"></a>
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/LICENSE-GPL-ff69b4"></a>
![GitHub Repo stars](https://img.shields.io/github/stars/zhzyker/vulmap?color=gree)
![GitHub forks](https://img.shields.io/github/forks/zhzyker/vulmap)  

[中文版本(Chinese Version)](https://github.com/zhzyker/vulmap)  
> Vulmap is a web vulnerability scanning and verification tool that can scan webapps for vulnerabilities and has vulnerability exploitation functions. Currently supported webapps include activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins , nexus, weblogic, jboss, spring, thinkphp
> 
> Vulmap combines vulnerability scanning and verification (vulnerability exploitation), and to a large extent, it is convenient for testers to take the next step in time after discovering vulnerabilities. The tool pursues efficiency and convenience
Efficient: Batch scanning, Fofa, Shodan batch scanning are slowly introduced in the gradual development, and multi-threading is supported by default to enable coroutines to scan a large number of assets at the fastest speed
Convenience: You can take advantage of vulnerabilities found, scan a large number of assets and output results in multiple formats
> 
> Vulmap version 0.8 starts to support the direct vulnerability scanning of the dismap recognition result file `-f output.txt`

## 🛒 Installation
The operating system must have python3, python3.8 or higher is recommended
* git or go to release to get the original code
```
git clone https://github.com/zhzyker/vulmap.git
```
* Installation dependency
```
pip3 install -r requirements.txt
```
* Linux & MacOS & Windows
```
python vulmap.py -u http://example.com
```

Configure Fofa Api && Shodan Api && Ceye
* Fofa info: https://fofa.so/user/users/info
```bash
# Replace xxxxxxxxxx with fofa email
globals.set_value("fofa_email", "xxxxxxxxxx")  
# Replace xxxxxxxxxx with fofa key
globals.set_value("fofa_key", "xxxxxxxxxx")
```
* Shodan key: https://account.shodan.io
```bash
# Replace xxxxxxxxxx with your shodan key
globals.set_value("shodan_key", "xxxxxxxxxx")
```

* Ceye info: http://ceye.io
```bash
# Replace xxxxxxxxxx with your own domain name
globals.set_value("ceye_domain","xxxxxxxxxx")  
# Replace xxxxxxxxxx with your own ceye token
globals.set_value("ceye_token", "xxxxxxxxxx") 
```

## 📑 Licenses
Add the following disclaimer to the original agreement [LICENSE](https://github.com/zhzyker/vulmap/blob/main/LICENSE). In case of conflict with the original agreement, the disclaimer shall prevail.

Unauthorized commercial use of this tool is prohibited, and unauthorized commercial use after secondary development is prohibited

This tool is only for legally authorized corporate security construction activities. When using this tool for testing, you should ensure that the behavior complies with local laws and regulations and has obtained sufficient authorization.

If you have any illegal behavior in the process of using this tool, you need to bear the corresponding consequences yourself, and we will not bear any legal and joint liabilities.

Before using this tool, please read carefully and fully understand the content of each clause. Restrictions, exemptions, or other clauses involving your major rights and interests may be bolded, underlined, etc. to remind you to pay attention. Unless you have fully read, fully understood and accepted all the terms of this agreement, please do not use this tool. Your use behavior or your acceptance of this agreement in any other express or implied manner shall be deemed to have been read and agreed to be bound by this agreement.


## 🙋 Discussion
* Vulmap bug feedback or new feature suggestions[Point Me](https://github.com/zhzyker/vulmap/issues)
* Telegram: t.me/zhzyker

## 🔧 Options
``` 
optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     target URL (e.g. -u "http://example.com")
  -f FILE, --file FILE  select a target list file (e.g. -f "list.txt")
  --fofa keyword        call fofa api to scan (e.g. --fofa "app=Apache-Shiro")
  --shodan keyword      call shodan api to scan (e.g. --shodan "Shiro")
  -m MODE, --mode MODE  supports poc and exp, if not specified the default poc
  -a APP [APP ...]      specify webapps (e.g. -a "tomcat") allow multiple
  -v VUL, --vul VUL     exploit, specify vuln number (e.g. -v CVE-2019-2729)
  -t NUM, --thread NUM  number of scanning function threads, default 10 threads
  --dnslog server       dnslog server (hyuga,dnslog,ceye) default automatic
  --output-text file    result export txt file (e.g. "result.txt")
  --output-json file    result export json file (e.g. "result.json")
  --proxy-socks SOCKS   socks proxy (e.g. --proxy-socks 127.0.0.1:1080)
  --proxy-http HTTP     http proxy (e.g. --proxy-http 127.0.0.1:8080)
  --fofa-size SIZE      Fofa query target number, default 100 (1-10000)
  --user-agent UA       you can customize the user-agent headers
  --delay DELAY         delay check time, default 0s
  --timeout TIMEOUT     scan timeout time, default 10s
  --list                display the list of supported vulnerabilities
  --debug               exp echo request and responses, poc echo vuln lists
  --check               survival check (on and off), default on
```

## 🐾 Examples
Test all vulnerabilities poc mode
```
python3 vulmap.py -u http://example.com
```

Check http://example.com for struts2 vuln
```
python3 vulmap.py -u http://example.com -a struts2
```
```
python3 vulmap.py -u http://example.com -m poc -a struts2
```
Exploit the CVE-2019-2729 vuln of WebLogic on http://example.com:7001
```
python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729
```
```
python3 vulmap.py -u http://example.com:7001 -m exp -v CVE-2019-2729
```
Export scan results to result.json
```
python3 vulmap.py -u http://example.com:7001 --output-json result.json
```
# Call fofa api batch scan
```
python3 vulmap.py --fofa app=Apache-Shiro
```

## 🍵 Vulnerabilitys List
Vulmap supported vulnerabilities are as follows
```
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
```

## 🐟 Docker

```shell
docker build -t vulmap/vulmap .
docker run --rm -ti vulmap/vulmap  python vulmap.py -u https://www.example.com
```
