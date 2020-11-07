## Vulmap - Web vulnerability scanning and verification tools
[英文版本(English Version)](https://github.com/zhzyker/vulmap/blob/main/readme.us-en.md)  
Vulmap是一款漏洞扫描工具, 可对Web容器、Web服务器、Web中间件以及CMS等Web程序进行漏洞扫描, 并且具备漏洞利用功能。
相关测试人员可以使用vulmap检测目标是否存在特定漏洞, 并且可以使用漏洞利用功能验证漏洞是否真实存在。

Vulmap目前有漏洞扫描(poc)和漏洞利用(exp)模式, 使用"-m"选现指定使用哪个模式, 缺省则默认poc模式, 在poc模式中还支持"-f"批量目标扫描、"-o"文件输出结果等主要功能, 更多功能参见[Options](https://github.com/zhzyker/vulmap/#options)或者python3 vulmap.py -h, 漏洞利用exp模式中将不再提供poc功能, 而是直接进行漏洞利用, 并反馈回利用结果, 用于进一步验证漏洞是否存在, 是否可被利用。

程序完全使用python3编写, 只要确保操作系统中有python3环境, 在Linux、MacOS、Windows中都可运行, 推荐使用python3.7或者更高的版本, vulmap目前只有CLI(命令行)界面, 所以需要在命令行中运行, 详细使用说明请参[Options](https://github.com/zhzyker/vulmap/#options)

**应尽量使用 "-a" 指定目标类型以减少误报，例如 "-a solr"**  

## Installation
操作系统中必须有python3, 推荐python3.7或者更高版本
* 安装所需的依赖环境
```
pip3 install -r requirements.txt
```
* Linux & MacOS & Windows
```
python3 vulmap.py -u http://example.com
```

## Options
``` 
可选参数:
  -h, --help            显示此帮助消息并退出
  -u URL, --url URL     目标 URL (示例: -u "http://example.com")
  -f FILE, --file FILE  选择一个目标列表文件,每个 url 必须用行来区分 (示例: -f "/home/user/list.txt")
  -m MODE, --mode MODE  模式支持 "poc" 和 "exp",可以省略此选项,默认进入 "poc" 模式
  -a APP, --app APP     指定 Web 容器、Web 服务器、Web 中间件或 CMD（例如: "weblogic"）不指定则默认扫描全部
  -c CMD, --cmd CMD     自定义远程命令执行执行的命令,默认是echo
  -v VULN, --vuln VULN  利用漏洞,需要指定漏洞编号 (示例: -v "CVE-2020-2729")
  --list                显示支持的漏洞列表
  --debug               Debug 模式,将显示 request 和 responses
  --delay DELAY         延时时间,每隔多久发送一次,默认0s
  --timeout TIMEOUT     超时时间,默认10s
  --output FILE         文本模式输出结果 (示例: -o "result.txt")
```
## Examples
测试所有漏洞 poc
```
python3 vulmap.py -u http://example.com
```
针对 RCE 漏洞,使用 id 命令检测是否存在漏洞,因为个别 linux 系统中没有 "netstat -an" 命令
```
python3 vulmap.py -u http://example.com -c "id"
```

检查 http://example.com 是否存在 struts2 漏洞
```
python3 vulmap.py -u http://example.com -a struts2
```
```
python3 vulmap.py -u http://example.com -m poc -a struts2
```
对 http://example.com:7001 进行 WebLogic 的 CVE-2019-2729 漏洞利用
```
python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729
```
```
python3 vulmap.py -u http://example.com:7001 -m exp -v CVE-2019-2729
```
批量扫描 list.txt 中的 url
```
python3 vulmap.py -f list.txt
```
扫描结果导出到 result.txt
```
python3 vulmap.py -u http://example.com:7001 -o result.txt
```

## Vulnerabilitys List
vulmap支持的漏洞如下
```
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Apache Shiro      | CVE-2016-4437    |  Y  |  Y  | <= 1.2.4, shiro-550, rememberme deserialization rce         |
 | Apache Solr       | CVE-2017-12629   |  Y  |  Y  | < 7.1.0, runexecutablelistener rce & xxe, only rce is here  |
 | Apache Solr       | CVE-2019-0193    |  Y  |  N  | < 8.2.0, dataimporthandler module remote code execution     |
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
 | Drupal            | CVE-2019-6340    |  Y  |  Y  | < 8.6.10, drupal core restful remote code execution         |
 | Jenkins           | CVE-2017-1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
 | Jenkins           | CVE-2018-1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Nexus OSS/Pro     | CVE-2019-7238    |  Y  |  Y  | 3.6.2 - 3.14.0, remote code execution vulnerability         |
 | Nexus OSS/Pro     | CVE-2020-10199   |  Y  |  Y  | 3.x  <= 3.21.1, remote code execution vulnerability         |
 | Oracle Weblogic   | CVE-2014-4210    |  Y  |  N  | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    |  Y  |  Y  | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3 wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2551    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, wlscore deserialization rce |
 | Oracle Weblogic   | CVE-2020-2555    |  Y  |  Y  | 3.7.1.17, 12.1.3.0.0, 12.2.1.3-4.0, t3 deserialization rce  |
 | Oracle Weblogic   | CVE-2020-14882   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0.0, console rce     |
 | RedHat JBoss      | CVE-2010-0738    |  Y  |  Y  | 4.2.0 - 4.3.0, jmx-console deserialization any files upload |
 | RedHat JBoss      | CVE-2010-1428    |  Y  |  Y  | 4.2.0 - 4.3.0, web-console deserialization any files upload |
 | RedHat JBoss      | CVE-2015-7501    |  Y  |  Y  | 5.x, 6.x, jmxinvokerservlet deserialization any file upload |
 | ThinkPHP          | CVE-2019-9082    |  Y  |  Y  | < 3.2.4, thinkphp rememberme deserialization rce            |
 | ThinkPHP          | CVE-2018-20062   |  Y  |  Y  | <= 5.0.23, 5.1.31, thinkphp rememberme deserialization rce  |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
```
