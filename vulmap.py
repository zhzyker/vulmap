#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# author: zhzyker
# github: https://github.com/zhzyker/vulmap
# If you have any problems, please give feedback to https://github.com/zhzyker/vulmap/issues
from gevent import monkey
monkey.patch_all()
import argparse
from module.banner import banner
from module.allcheck import version_check
from module import globals
from core.core import core

parser = argparse.ArgumentParser(usage="python3 vulmap [options]", add_help=False)
target = parser.add_argument_group("target", "you must to specify target")
target.add_argument("-u", "--url", dest="url", type=str, help=" target URL (e.g. -u \"http://example.com\")")
target.add_argument("-f", "--file", dest="file", help="select a target list file (e.g. -f \"list.txt\")")
target.add_argument("--fofa", dest="fofa", metavar='keyword', type=str, help=" call fofa api to scan (e.g. --fofa \"app=Apache-Shiro\")")
target.add_argument("--shodan", dest="shodan", metavar='keyword', type=str, help=" call shodan api to scan (e.g. --shodan \"Shiro\")")
mo = parser.add_argument_group("mode", "options vulnerability scanning or exploit mode")
mo.add_argument("-m", "--mode", dest="mode", type=str, help="supports poc and exp, if not specified the default poc")
mo.add_argument("-a", dest="app", type=str, nargs='+', help="specify webapps (e.g. -a \"tomcat\") allow multiple")
mo.add_argument("-v", "--vul", type=str, default=None, help="exploit, specify vuln number (e.g. -v CVE-2019-2729)")
ge = parser.add_argument_group("general", "general options")
ge.add_argument("-h", "--help", action="help", help="show this help message and exit")
ge.add_argument("-t", "--thread", dest="thread_num", type=int, default=10, metavar='NUM',
                help="number of scanning function threads, default 10 threads")
ge.add_argument("--output-text", type=str, dest="O_TEXT", metavar='file', help="result export txt file (e.g. \"result.txt\")")
ge.add_argument("--output-json", type=str, dest="O_JSON", metavar='file', help="result export json file (e.g. \"result.json\")")
ge.add_argument("--proxy-socks", dest="socks", type=str, help="socks proxy (e.g. --proxy-socks 127.0.0.1:1080)")
ge.add_argument("--proxy-http", dest="http", type=str, help="http proxy (e.g. --proxy-http 127.0.0.1:8080)")
ge.add_argument("--fofa-size", dest="size", type=int, default=100, help="Fofa query target number, default 100 (1-10000)")
ge.add_argument("--user-agent", dest="ua", type=str,
                default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 "
                        "Safari/537.36", help="you can customize the user-agent headers")
ge.add_argument("--delay", dest="delay", type=int, default=0, help="delay check time, default 0s")
ge.add_argument("--timeout", dest="TIMEOUT", type=int, default=10, help="scan timeout time, default 10s")
ge.add_argument("--list", dest="list", action='store_false', help="display the list of supported vulnerabilities")
ge.add_argument("--debug", action='store_false', help="exp echo request and responses, poc echo vuln lists")
support = parser.add_argument_group("support")
support.add_argument(action='store_false', dest="types of vulnerability scanning:\n  "
                     "all, activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal\n  "
                     "elasticsearch, fastjson, jenkins, nexus, weblogic, jboss, spring, thinkphp")
example = parser.add_argument_group("examples")
example.add_argument(action='store_false',
                     dest="python3 vulmap.py -u http://example.com\n  "
                          "python3 vulmap.py -u http://example.com -a struts2\n  "
                          "python3 vulmap.py -u http://example.com:7001 -v CVE-2019-2729\n  "
                          "python3 vulmap.py -f list.txt -a weblogic -t 20\n  "
                          "python3 vulmap.py -f list.txt --output-json results.json\n  "
                          "python3 vulmap.py --fofa app=Apache-Shiro")


def config():
    header = {
        'Accept': 'application/x-shockwave-flash, image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, '
                  'application/vnd.ms-excel, application/vnd.ms-powerpoint, application/msword, */*',
        'User-agent': args.ua,
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    globals.init()  # 初始化全局变量模块
    globals.set_value("UA", args.ua)  # 设置全局变量UA
    globals.set_value("VUL", args.vul)  # 设置全局变量VULN用于判断是否漏洞利用模式
    globals.set_value("DEBUG", args.debug)  # 设置全局变量DEBUG
    globals.set_value("DELAY", args.delay)  # 设置全局变量延时时间DELAY
    globals.set_value("VULMAP", str(0.6))  # 设置全局变量程序版本号
    globals.set_value("O_TEXT", args.O_TEXT)  # 设置全局变量OUTPUT判断是否输出TEXT
    globals.set_value("O_JSON", args.O_JSON)  # 设置全局变量OUTPUT判断是否输出JSON
    globals.set_value("HEADERS", header)  # 设置全局变量HEADERS
    globals.set_value("TIMEOUT", args.TIMEOUT)  # 设置全局变量超时时间TOMEOUT
    globals.set_value("THREADNUM", args.thread_num)  # 设置全局变量THREADNUM传递线程数量

    # 替换自己的 ceye.io 用户名和 token
    globals.set_value("ceye_domain","6eb4yw.ceye.io")
    globals.set_value("ceye_token", "2490ae17e5a04f03def427a596438995")
    globals.set_value("ceye_api", "http://api.ceye.io/v1/records?type=dns&token=")

    # fofa 邮箱和 key，需要手动修改为自己的
    globals.set_value("fofa_email", "xxxxxxxxxx")
    globals.set_value("fofa_key", "xxxxxxxxxx")

    # shodan key
    globals.set_value("shodan_key", "xxxxxxxxxx")


if __name__ == '__main__':
    print(banner())  # 显示随机banner
    args = parser.parse_args()  # 初始化各选项参数
    config()  # 加载全局变量
    version_check()  # 检查vulmap版本
    core.control_options(args)  # 运行核心选项控制方法用于处理不同选项并开始扫描
