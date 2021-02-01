## 🌟 Vulmap - Web vulnerability scanning and verification tools
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/python-3.8+-blueviolet"></a>
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/Version-vulmap 0.5-yellow"></a>
<a href="https://github.com/zhzyker/vulmap"><img alt="Release" src="https://img.shields.io/badge/LICENSE-GPL-ff69b4"></a>
![GitHub Repo stars](https://img.shields.io/github/stars/zhzyker/vulmap?color=gree)
![GitHub forks](https://img.shields.io/github/forks/zhzyker/vulmap)

 
[英文版本(English Version)](https://github.com/zhzyker/vulmap/blob/main/readme.us-en.md)  
> Vulmap是一款Web漏洞扫描和验证工具, 可对Web容器、Web服务器、Web中间件以及CMS等Web程序进行漏洞扫描, 并且具备漏洞利用功能

> Vulmap目前有漏洞扫描(poc)和漏洞利用(exp)模式, 使用"-m"选现指定使用哪个模式, 缺省则默认poc模式, 在poc模式中还支持"-f"批量目标扫描、"-o"文件输出结果等主要功能, 更多功能参见[options](https://github.com/zhzyker/vulmap/#options)或者python vulmap.py -h, 目前支持扫描 all, activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal, elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp


## 🛒 Installation
* 操作系统中必须有python3, 推荐python3.8或者更高版本
```bash
# git 或前往 release 获取原码
git clone https://github.com/zhzyker/vulmap.git
# 安装所需的依赖环境
pip3 install -r requirements.txt
# Linux & MacOS & Windows
python3 vulmap.py -u http://example.com
```
* 配置 Fofa Api && Shodan Api && Ceye
若想使用fofa api调用资产需要修改 vulmap.py 中的配置信息：
Fofa info: https://fofa.so/user/users/info  
Shodan key: https://account.shodan.io  
Ceye info: http://ceye.io/  

```
# 把xxxxxxxxxx替换成fofa的邮箱
globals.set_value("fofa_email", "xxxxxxxxxx")  
# 把xxxxxxxxxx替换成fofa的key
globals.set_value("fofa_key", "xxxxxxxxxx")  
```
```
# 把xxxxxxxxxx替换成自己shodan的key
globals.set_value("shodan_key", "xxxxxxxxxx")  
```
```
# 把xxxxxxxxxx替换为自己的域名
globals.set_value("ceye_domain","xxxxxxxxxx")  
# 把xxxxxxxxxx替换自己ceye的token
globals.set_value("ceye_token", "xxxxxxxxxx")  
```

## 📺 video demo
> YouTube:  https://www.youtube.com/watch?v=g4czwS1Snc4  
> Bilibili: https://www.bilibili.com/video/BV1Fy4y1v7rd  
> Gif: ![https://github.com/zhzyker/vulmap/blob/main/images/vulmap-0.5-demo-gif.gif](https://github.com/zhzyker/vulmap/blob/main/images/vulmap-0.5-demo-gif.gif)

## 🙋 Discussion
* Vulmap Bug 反馈或新功能建议[点我](https://github.com/zhzyker/vulmap/issues)
* Twitter: https://twitter.com/zhzyker
* WeChat: 微信群满200了，只能拉进群，点击下方按钮即可
<details>
<summary> [点我扫描加微信群] </summary>  
<p>
    <img alt="QR-code" src="https://github.com/zhzyker/zhzyker/blob/main/my-wechat.jpg" width="20%" height="20%" style="max-width:100%;">
</p>
 </details>

## 🔧 Options
``` 
可选参数:
  -h, --help            显示此帮助消息并退出
  -u URL, --url URL     目标 URL (e.g. -u "http://example.com")
  -f FILE, --file FILE  选择一个目标列表文件,每个url必须用行来区分 (e.g. -f "/home/user/list.txt")
  --fofa keyword        使用fofa api批量扫描 (e.g. --fofa "app=Apache-Shiro")
  --shodan keyword      shodan api批量扫描 (e.g. --shodan "Shiro")
  -m MODE, --mode MODE  模式支持"poc"和"exp",可以省略此选项,默认进入"poc"模式
  -a APP [APP ...]      指定web容器、web服务器、web中间件或cms（e.g. "weblogic"）不指定则默认扫描全部
  -c CMD, --cmd CMD     自定义远程命令执行执行的命令,默认是echo随机md5
  -v VULN, --vuln VULN  利用漏洞,需要指定漏洞编号 (e.g. -v "CVE-2019-2729")
  --output-text file    扫描结果输出到txt文件 (e.g. "result.txt")
  --output-json file    扫描结果输出到json文件 (e.g. "result.json")
  --fofa-size SIZE      fofa api调用资产数量，默认100，可用(1-10000)
  --list                显示支持的漏洞列表
  --debug               exp模式显示request和responses,poc模式显示扫描漏洞列表
  --delay DELAY         延时时间,每隔多久发送一次,默认0s
  --timeout TIMEOUT     超时时间,默认5s
  -t NUM, --thread NUM  扫描线程数量,默认10线程
  --user-agent UA       允许自定义User-Agent
  --proxy-socks SOCKS   使用socks代理 (e.g. --proxy-socks 127.0.0.1:1080)
  --proxy-http HTTP     使用http代理 (e.g. --proxy-http 127.0.0.1:8080)
```

## 🐾 Examples
```
# 测试所有漏洞 poc
python3 vulmap.py -u http://example.com

# 针对 RCE 漏洞,自定义命令检测是否存在漏洞,例如针对没有回现的漏洞使用dnslog
python3 vulmap.py -u http://example.com -c "ping xxx.xxx"

# 检查 http://example.com 是否存在 struts2 漏洞
python3 vulmap.py -u http://example.com -a struts2
python3 vulmap.py -u http://example.com -m poc -a struts2

# 对 http://example.com:7001 进行 WebLogic 的 CVE-2019-2729 漏洞利用
python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729
python3 vulmap.py -u http://example.com:7001 -m exp -v CVE-2019-2729

# 批量扫描 list.txt 中的 url
python3 vulmap.py -f list.txt

# 扫描结果导出到 result.json
python3 vulmap.py -u http://example.com:7001 --output-json result.json

# 调用fofa api批量扫描
python3 vulmap.py --fofa app=Apache-Shiro
```

## 🍵 Vulnerabilitys List
<details>
<summary>支持的漏洞列表 [点击展开] </summary>  
 
```
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Target type       | Vuln Name        | Poc | Exp | Impact Version && Vulnerability description                 |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
 | Apache ActiveMQ   | CVE-2015-5254    |  Y  |  N  | < 5.13.0, deserialization remote code execution             |
 | Apache ActiveMQ   | CVE-2016-3088    |  Y  |  Y  | < 5.14.0, http put&move upload webshell                     |
 | Apache Flink      | CVE-2020-17518   |  Y  |  N  | < 1.11.3 or < 1.12.0, upload path traversal                 |
 | Apache Flink      | CVE-2020-17519   |  Y  |  Y  | 1.5.1 - 1.11.2, 'jobmanager/logs' path traversal            |
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
 | Apache Struts2    | S2-059           |  Y  |  Y  | 2.0.0 - 2.5.20, cve-2019-0230 ognl interpreter rce          |
 | Apache Struts2    | S2-061           |  Y  |  Y  | 2.0.0-2.5.25, cve-2020-17530 ognl interpreter rce           |
 | Apache Struts2    | S2-devMode       |  Y  |  Y  | 2.1.0 - 2.5.1, devmode remote code execution                |
 | Apache Tomcat     | Examples File    |  Y  |  N  | all version, /examples/servlets/servlet                     |
 | Apache Tomcat     | CVE-2017-12615   |  Y  |  Y  | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    |  Y  |  Y  | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Apache Unomi      | CVE-2020-13942   |  Y  |  Y  | < 1.5.2, apache unomi remote code execution                 |
 | Drupal            | CVE-2018-7600    |  Y  |  Y  | 6.x, 7.x, 8.x, drupalgeddon2 remote code execution          |
 | Drupal            | CVE-2018-7602    |  Y  |  Y  | < 7.59, < 8.5.3 (except 8.4.8) drupalgeddon2 rce            |
 | Drupal            | CVE-2019-6340    |  Y  |  Y  | < 8.6.10, drupal core restful remote code execution         |
 | Elasticsearch     | CVE-2014-3120    |  Y  |  Y  | < 1.2, elasticsearch remote code execution                  |
 | Elasticsearch     | CVE-2015-1427    |  Y  |  Y  | < 1.3.7, < 1.4.3, elasticsearch remote code execution       |
 | Fastjson          | 1.2.24           |  Y  |  Y  | <= 1.2.24 fastjson parse object remote code execution       |
 | Fastjson          | 1.2.47           |  Y  |  Y  | <= 1.2.47 fastjson autotype remote code execution           |
 | Fsatjson          | 1.2.62           |  Y  |  Y  | <= 1.2.24 fastjson autotype remote code execution           |
 | Jenkins           | CVE-2017-1000353 |  Y  |  N  | <= 2.56, LTS <= 2.46.1, jenkins-ci remote code execution    |
 | Jenkins           | CVE-2018-1000861 |  Y  |  Y  | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Nexus OSS/Pro     | CVE-2019-7238    |  Y  |  Y  | 3.6.2 - 3.14.0, remote code execution vulnerability         |
 | Nexus OSS/Pro     | CVE-2020-10199   |  Y  |  Y  | 3.x <= 3.21.1, remote code execution vulnerability          |
 | Oracle Weblogic   | CVE-2014-4210    |  Y  |  N  | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    |  Y  |  Y  | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3 wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2551    |  Y  |  N  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, wlscore deserialization rce |
 | Oracle Weblogic   | CVE-2020-2555    |  Y  |  Y  | 3.7.1.17, 12.1.3.0.0, 12.2.1.3-4.0, t3 deserialization rce  |
 | Oracle Weblogic   | CVE-2020-2883    |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, iiop t3 deserialization rce |
 | Oracle Weblogic   | CVE-2020-14882   |  Y  |  Y  | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0.0, console rce     |
 | RedHat JBoss      | CVE-2010-0738    |  Y  |  Y  | 4.2.0 - 4.3.0, jmx-console deserialization any files upload |
 | RedHat JBoss      | CVE-2010-1428    |  Y  |  Y  | 4.2.0 - 4.3.0, web-console deserialization any files upload |
 | RedHat JBoss      | CVE-2015-7501    |  Y  |  Y  | 5.x, 6.x, jmxinvokerservlet deserialization any file upload |
 | Spring Data       | CVE-2018-1273    |  Y  |  Y  | 1.13 - 1.13.10, 2.0 - 2.0.5, spring data commons rce        |
 | Spring Cloud      | CVE-2019-3799    |  Y  |  Y  | 2.1.0-2.1.1, 2.0.0-2.0.3, 1.4.0-1.4.5, directory traversal  |
 | ThinkPHP          | CVE-2019-9082    |  Y  |  Y  | < 3.2.4, thinkphp rememberme deserialization rce            |
 | ThinkPHP          | CVE-2018-20062   |  Y  |  Y  | <= 5.0.23, 5.1.31, thinkphp rememberme deserialization rce  |
 +-------------------+------------------+-----+-----+-------------------------------------------------------------+
```
</details>

## 🐟 Docker

```shell
docker build -t vulmap/vulmap .
docker run --rm -ti vulmap/vulmap  python vulmap.py -u https://www.example.com
```
