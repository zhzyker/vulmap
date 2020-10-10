## Vulmap - Vulnerability scanning and verification tools
[中文版本(Chinese Version)](https://github.com/zhzyker/vulmap/blob/main/readme.zh-cn.md)  
[русский(Russian Version)](https://github.com/zhzyker/vulmap/blob/main/readme.ru-ru.md)  
Vulmap is a vulnerability scanning tool that can scan for vulnerabilities in Web containers, Web servers, Web middleware, and CMS and other Web programs, and has vulnerability exploitation functions.
Relevant testers can use vulmap to detect whether the target has a specific vulnerability, and can use the vulnerability exploitation function to verify whether the vulnerability actually exists.

Vulmap currently has vulnerability scanning (poc) and exploiting (exp) modes. Use "-m" to select which mode to use, and the default poc mode is the default. In poc mode, it also supports "-f" batch target scanning, "-o" File output results and other main functions, Other functions [Options](https://github.com/zhzyker/vulmap/#options) Or python3 vulmap.py -h, the Poc function will no longer be provided in the exploit exploit mode, but the exploit will be carried out directly, and the exploit result will be fed back to further verify whether the vulnerability exists and whether it can be exploited.

## Installation
The operating system must have python3, python3.7 or higher is recommended
* Installation dependency
```
pip3 install -r requirements.txt
```
* Linux & MacOS & Windows
```
python3 vulmap.py -u http://example.com
```

## Options
``` 
optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL (e.g. -u "http://example.com")
  -f FILE, --file FILE  Select a target list file, and the url must be distinguished by lines (e.g. -f "/home/user/list.txt")
  -m MODE, --mode MODE  The mode supports "poc" and "exp", you can omit this option, and enter poc mode by default
  -a APP, --app APP     Specify a web app or cms (e.g. -a "weblogic"). default scan all
  -c CMD, --cmd CMD     Custom RCE vuln command, Other than "netstat -an" and "id" can affect program judgment. defautl is "netstat -an"
  -v VULN, --vuln VULN  Exploit, Specify the vuln number (e.g. -v "CVE-2020-2729")
  --list                Displays a list of vulnerabilities that support scanning
  --debug               Debug mode echo request and responses
  --delay DELAY         Delay check time, default 0s
  --timeout TIMEOUT     Scan timeout time, default 10s
  --output FILE         Text mode export (e.g. -o "result.txt")
```

## Examples
Test all vulnerabilities poc mode
```
python3 vulmap.py -u http://example.com
```
For RCE vuln, use the "id" command to test the vuln, because some linux does not have the "netstat -an" command
```
python3 vulmap.py -u http://example.com -c "id"
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
Batch scan URLs in list.txt
```
python3 vulmap.py -f list.txt
```
Export scan results to result.txt
```
python3 vulmap.py -u http://example.com:7001 -o result.txt
```

## Vulnerabilitys List
Vulmap supported vulnerabilities are as follows
```
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
```
