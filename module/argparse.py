#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse


def arg():
    parser = argparse.ArgumentParser(usage="python3 vulmap [options]", add_help=False)
    target = parser.add_argument_group("target", "you must to specify target")
    target.add_argument("-u", "--url", dest="url", type=str, help=" target URL (e.g. -u \"http://example.com\")")
    target.add_argument("-f", "--file", dest="file", help="select a target list file (e.g. -f \"list.txt\")")
    target.add_argument("--fofa", dest="fofa", metavar='keyword', type=str, help=" call fofa api to scan (e.g. --fofa \"app=Apache-Shiro\")")
    target.add_argument("--shodan", dest="shodan", metavar='keyword', type=str, help=" call shodan api to scan (e.g. --shodan \"Shiro\")")
    mo = parser.add_argument_group("mode", "options vulnerability scanning or exploit mode")
    mo.add_argument("-a", dest="app", type=str, nargs='+', help="specify webapps (e.g. -a \"tomcat\") allow multiple")
    ge = parser.add_argument_group("general", "general options")
    ge.add_argument("-h", "--help", action="help", help="show this help message and exit")
    ge.add_argument("-t", "--thread", dest="thread_num", type=int, default=10, metavar='NUM',
                    help="number of scanning function threads, default 10 threads")
    ge.add_argument("--dnslog", type=str, default="auto", metavar='server', help="dnslog server (hyuga,dnslog,ceye) default automatic")
    ge.add_argument("--output-text", type=str, dest="O_TEXT", metavar='file', help="result export txt file (e.g. \"result.txt\")")
    ge.add_argument("--output-json", type=str, dest="O_JSON", metavar='file', help="result export json file (e.g. \"result.json\")")
    ge.add_argument("--proxy-socks", dest="socks", type=str, help="socks proxy (e.g. --proxy-socks 127.0.0.1:1080)")
    ge.add_argument("--proxy-http", dest="http", type=str, help="http proxy (e.g. --proxy-http 127.0.0.1:8080)")
    ge.add_argument("--fofa-size", dest="size", type=int, default=100, help="fofa query target number, default 100 (1-10000)")
    ge.add_argument("--user-agent", dest="ua", type=str,
                    default="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 "
                            "Safari/537.36", help="you can customize the user-agent headers")
    ge.add_argument("--delay", dest="delay", type=int, default=0, help="delay check time, default 0s")
    ge.add_argument("--timeout", dest="TIMEOUT", type=int, default=10, help="scan timeout time, default 10s")
    ge.add_argument("--list", dest="list", action='store_false', help="display the list of supported vulnerabilities")
    ge.add_argument("--debug", action='store_false', help="exp echo request and responses, poc echo vuln lists")
    ge.add_argument("--check", metavar='', default='on', help="survival check (on and off), default on")
    support = parser.add_argument_group("support")
    support.add_argument(action='store_false', dest="types of vulnerability scanning:\n  "
                         "all, activemq, flink, shiro, solr, struts2, tomcat, unomi, drupal\n  "
                         "elasticsearch, fastjson, jenkins, laravel, nexus, weblogic, jboss\n  "
                         "spring, thinkphp, druid, exchange, nodejs, saltstack, vmware\n  "
                         "bigip, ofbiz, coremail, ecology, eyou, qianxin, ruijie")
    example = parser.add_argument_group("examples")
    example.add_argument(action='store_false',
                         dest="python3 vulmap.py -u http://example.com\n  "
                              "python3 vulmap.py -u http://example.com -a struts2\n  "
                              "python3 vulmap.py -f list.txt -a weblogic -t 20\n  "
                              "python3 vulmap.py -f list.txt --output-json results.json\n  "
                              "python3 vulmap.py --fofa \"app=Apache-Shiro\"")
    return parser.parse_args()
