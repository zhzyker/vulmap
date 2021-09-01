#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
from gevent import joinall

from module import globals
from module.time import now
from module.color import color
from module.output import output
from module.dismap import dismap
from module.dismap import dismap_getwebapps
from module.banner import vul_list
from module.proxy import proxy_set
from module.allcheck import url_check
from module.allcheck import survival_check
from module.api.fofa import fofa
from module.api.dns import dns_result, dns_request
from module.api.shodan import shodan_api
from core.scan import scan
from identify.identify import Identify
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED


class Core(object):
    @staticmethod
    def control_options(args):  # 选项控制，用于处理所有选项
        mode = "poc"
        delay = globals.get_value("DELAY")  # 获取全局变量延时时间DELAY
        now_warn = now.timed(de=delay) + color.red_warn()
        if args.socks:
            proxy_set(args.socks, "socks")  # proxy support socks5 http https
        elif args.http:
            proxy_set(args.http, "http")  # proxy support socks5 http https
        if args.list is False:  # 判断是否显示漏洞列表
            print(now.timed(de=0) + color.yel_info() + color.yellow(" List of supported vulnerabilities"))
            print(vul_list())
            exit(0)
        if args.thread_num != 10:  # 判断是否为默认线程
            print(now.timed(de=0) + color.yel_info() + color.yellow(" Custom thread number: " + str(args.thread_num)))
        if args.debug is False:  # 判断是否开启--debug功能
            print(now.timed(de=delay) + color.yel_info() + color.yellow(" Using debug mode to echo debug information"))
            globals.set_value("DEBUG", "debug")  # 设置全局变量DEBUG
        #ceye_api()  # 测试ceye连接性
        if dns_request(): # 初始化dnslog, 并判断是否可用
            pass
        else:
            print(now_warn + color.red(" Dnslog platform (hyuga.co dnslog.cn ceye.io) is not available"))
        if args.O_TEXT:  # 判断是否text输出
            if os.path.isfile(args.O_TEXT):  # 判断text输出文件是否冲突
                print(now.timed(de=delay) + color.red_warn() + color.red(" The json file: [" + args.O_TEXT + "] already exists"))
                exit(0)
        if args.O_JSON:  # 判断是否json输出
            if os.path.isfile(args.O_JSON):  # 判断json输出文件是否冲突
                print(now.timed(de=delay) + color.red_warn() + color.red(" The json file: [" + args.O_JSON + "] already exists"))
                exit(0)
        if mode == "poc":  # 判断是否进入poc模式
            if args.url is not None and args.file is None:  # 判断是否为仅-u扫描单个URL
                args.url = url_check(args.url)  # 处理url格式
                if survival_check(args.url) == "f":  # 检查目标存活状态
                    print(now.timed(de=0) + color.red_warn() + color.red(" Survival check failed: " + args.url))
                    exit(0)  # 单个url时存活失败就退出
                print(now.timed(de=0) + color.yel_info() + color.cyan(" Start scanning target: " + args.url))
                if args.app is None:  # 判断是否扫描扫描全部webapps
                    globals.set_value("RUNALLPOC", True)  # 扫描单个URL并且所有webapps时RUNALLPOC=True
                    core.control_webapps("url", args.url, args.app, "poc")
                else:  # 否则扫描单个webapps
                    core.control_webapps("url", args.url, args.app, "poc")
            elif args.file is not None and args.url is None:  # 判断是否为仅-f批量扫描文件
                if os.path.isfile(args.file):  # 判断批量目标文件是否存在
                    print(now.timed(de=0) + color.yel_info() + color.cyan(" Start batch scanning target: " + args.file))
                else:  # 没有文件错误并退出
                    print(now.timed(de=0) + color.red_warn() + color.red(" Not found target file: " + args.file))
                    exit(0)
                if args.app is None:  # 判断是否扫描扫描全部webapps
                    globals.set_value("RUNALLPOC", "FILE")  # 批量扫描URL并且所有webapps时RUNALLPOC="FILE"
                    core.control_webapps("file", args.file, args.app, "poc")
                else:  # 否则批量扫描单个webapps
                    core.control_webapps("file", args.file, args.app, "poc")
            elif args.url is None and args.file is None and args.fofa is not None:  # 调用fofa api
                print(now.timed(de=0) + color.yel_info() + color.yellow(" Use fofa api to search [" + args.fofa + "] and start scanning"))
                if r"xxxxxx" in globals.get_value("fofa_key"):  # 使用fofa api之前判断fofa信息是否正确
                    print(now.timed(de=0) + color.red_warn() + color.red(" Check fofa email is xxxxxx Please replace key and email"))
                    print(now.timed(de=0) + color.red_warn() + color.red(" Go to https://fofa.so/user/users/info find key and email"))
                    print(now.timed(de=0) + color.red_warn() + color.red(" How to use key and email reference https://github.com/zhzyker/vulmap"))
                    exit(0)
                else:
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Fofa email: " + globals.get_value("fofa_email")))
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Fofa key: " + globals.get_value("fofa_key")))
                fofa_list = fofa(args.fofa, args.size)  # 调用fofa api拿到目标数组默认100个
                if args.app is None:  # 判断是否扫描扫描全部webapps
                    core.control_webapps("fofa", fofa_list, args.app, "poc")
                else:
                    core.control_webapps("fofa", fofa_list, args.app, "poc")

            elif args.url is None and args.file is None and args.shodan is not None:  # 调用fofa api 或者 shodan api
                print(now.timed(de=0) + color.yel_info() + color.yellow(" Use shodan api to search [" + args.shodan + "] and start scanning"))
                if r"xxxxxx" in globals.get_value("shodan_key"):  # 使用shodan api之前判断shodan信息是否正确
                    print(now.timed(de=0) + color.red_warn() + color.red(" Check shodan key is xxxxxx Please replace key"))
                    print(now.timed(de=0) + color.red_warn() + color.red(" Go to https://account.shodan.io/ find key"))
                    print(now.timed(de=0) + color.red_warn() + color.red(" How to use key reference https://github.com/zhzyker/vulmap"))
                    exit(0)
                else:
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Shodan key: " + globals.get_value("shodan_key")))
                shodan_list = shodan_api(args.shodan)  # 调用shodan api拿到目标数组默认100个
                if args.app is None:  # 判断是否扫描扫描全部webapps
                    core.control_webapps("shodan", shodan_list, args.app, "poc")
                else:
                    core.control_webapps("shodan", shodan_list, args.app, "poc")

            if args.O_TEXT:
                print(now.timed(de=delay) + color.yel_info() + color.cyan(" Scan result text saved to: " + args.O_TEXT))
            if args.O_JSON:
                print(now.timed(de=delay) + color.yel_info() + color.cyan(" Scan result json saved to: " + args.O_JSON))
        else:
            print(now_warn + color.red(" Options error ... ..."))

    @staticmethod
    def control_webapps(target_type, target, webapps, mode):
        t_num = globals.get_value("THREADNUM")  # 线程数量
        thread_poc = []  # 多线程字典，用于添加线程任务
        gevent_pool = []  # 协程字段，用于添加协程任务
        thread_pool = ThreadPoolExecutor(t_num)  # 多线程池数量t_num由选项控制，默认10线程
        webapps_identify = []  # 定义目标类型字典，用于目标类型识别并记录，为跑所有poc时进行类型识别
        if mode == "poc":  # poc漏洞扫描模式
            if target_type == "url":  # ========================================================= 第一种扫描仅扫描单个URL
                output("text", "[*] " + target)  # 丢给output模块判断是否输出文件
                if webapps is None:  # 判断是否进行指纹识别
                    Identify.start(target, webapps_identify)  # 第一种情况需要进行指纹识别
                elif r"all" in webapps:  # 判断是否扫描所有类型poc
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify to scan all vulnerabilities"))
                    webapps_identify.append("all")  # 指定扫描所有时，需要将指纹全部指定为all
                else:
                    webapps_identify = webapps  # 指定但不是all，也可以指定多个类型，比如-a solr struts2
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify scan vulnerabilities for: "), end='')
                    count = 0  # 用于判断类型的数量，一个还是多个
                    for w_i in webapps_identify:
                        print(color.cyan(w_i), end=' ')
                        count += 1
                        if count % len(webapps_identify) == 0:
                            print(end='\n')
                core.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, target)  # 调用scan开始扫描
                joinall(gevent_pool)  # 运行协程池
                wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                print(now.timed(de=0) + color.yel_info() + color.yellow(" Scan completed and ended                             "))
            elif target_type == "file":  # ========================= 第二种扫描情况，批量扫描文件不指定webapps时需要做指纹识别
                count_line = -1  # 用于判断行数
                count_null = 0
                for line in open(target).readlines():  # 判断文件里有多少空行
                    line = line.strip()  # 读取目标时过滤杂质
                    if line == "":
                        count_null += 1
                for count_line, line in enumerate(open(target, 'rU')):  # 判断文件的行数
                    pass
                count_line += 1  # 行数加1
                target_num = count_line - count_null
                now_num = 0  # 当前数量
                target_list = []  # 批量扫描需要读取的字典
                with open(target, 'r') as _:  # 打开目标文件
                    for line in _:  # 用for循环读取文件
                        line = line.strip()  # 过滤杂质
                        get_line = dismap(line)
                        if get_line == "######":
                            target_num = target_num - 1
                            continue
                        if globals.get_value("DISMAP") == "true":
                            dismap_webapps = dismap_getwebapps(line)
                        if get_line:  # 判断是否结束
                            if globals.get_value("DISMAP") == "true":
                                if dismap_webapps is None:
                                    continue
                                else:
                                    print(now.timed(de=0) + color.yel_info() +
                                        " The result of dismap identifiy is " + color.yellow(dismap_webapps))
                            target_list.append(get_line)  # 读取到的目标加入字典准备扫描
                            now_num += 1  # 读取到之后当前数量+1
                            furl = get_line
                            furl = url_check(furl)  # url格式检测
                            output("text", "[*] " + furl)  # 丢给output模块判断是否输出文件
                            if survival_check(furl) == "f":  # 如果存活检测失败就跳过
                                print(now.timed(de=0) + color.red_warn() + color.red(
                                    " Current:[" + str(now_num) + "] Total:[" + str(
                                        target_num) + "] Survival check failed: " + furl))
                                continue
                            else:  # 存活不失败就正常显示
                                print(now.timed(de=0) + color.yel_info() + color.yellow(
                                    " Current:[" + str(now_num) + "] Total:[" + str(
                                        target_num) + "] Scanning target: " + furl))

                            if globals.get_value("DISMAP") == "true" and webapps is None:
                                webapps_identify.append(dismap_getwebapps(line))
                            elif webapps is None:  # 判断是否要进行指纹识别
                                webapps_identify.clear()  # 可能跟单个url冲突需要清理字典
                                Identify.start(furl, webapps_identify)  # 识别指纹
                                # print(webapps_identify)
                            elif r"all" in webapps:  # 不识别指纹运行所有
                                print(now.timed(de=0) + color.yel_info() + color.yellow(
                                    " Specify to scan all vulnerabilities"))
                                webapps_identify.append("all")
                            else:
                                webapps_identify = webapps
                                print(now.timed(de=0) + color.yel_info() + color.yellow(
                                    " Specify scan vulnerabilities for: "),
                                      end='')
                                count = 0
                                for w_i in webapps_identify:
                                    print(color.cyan(w_i), end=' ')
                                    count += 1
                                    if count % len(webapps_identify) == 0:
                                        print(end='\n')
                            core.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, furl)  # 开扫
                            joinall(gevent_pool)  # 运行协程池
                            wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                            if globals.get_value("DISMAP") == "true" and webapps is None:
                                webapps_identify.clear()
                    print(now.timed(de=0) + color.yel_info() + color.yellow(" Scan completed and ended                             "))
            elif target_type == "fofa" or target_type == "shodan":  # ======================================================= 第三种调用fofa api
                total = len(target)  # fofa api的总数，不出意外100个
                if webapps is not None:
                    if r"all" in webapps:  # 不识别直接扫描所有类型
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify to scan all vulnerabilities"))
                        webapps_identify.append("all")
                    else:
                        webapps_identify = webapps  # 扫描指定的类型
                        print(now.timed(de=0) + color.yel_info() + color.yellow(" Specify scan vulnerabilities for: "), end='')
                        count = 0
                        for w_i in webapps_identify:
                            print(color.cyan(w_i), end=' ')
                            count += 1
                            if count % len(webapps_identify) == 0:
                                print(end='\n')
                now_num = 0  # 当前第几个
                for f_target in target:
                    fofa_target = url_check(f_target)
                    output("text", "[*] " + fofa_target)  # 丢给output模块判断是否输出文件
                    now_num += 1
                    if survival_check(fofa_target) == "f":
                        print(now.timed(de=0) + color.red_warn() + color.red(
                            " Current:[" + str(now_num) + "] Total:[" + str(
                                total) + "] Survival check failed: " + fofa_target))
                        continue
                    else:
                        print(now.timed(de=0) + color.yel_info() + color.yellow(
                            " Current:[" + str(now_num) + "] Total:[" + str(
                                total) + "] Scanning target: " + fofa_target))
                    if webapps is None:  # 需要指纹识别
                        webapps_identify.clear()
                        Identify.start(fofa_target, webapps_identify)  # 是否需要进行指纹识别
                    core.scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, fofa_target)
                    joinall(gevent_pool)  # 运行协程池
                    wait(thread_poc, return_when=ALL_COMPLETED)  # 等待所有多线程任务运行完
                print(now.timed(de=0) + color.yel_info() + color.yellow(" Scan completed and ended                             "))

    @staticmethod
    def scan_webapps(webapps_identify, thread_poc, thread_pool, gevent_pool, target):
        # 自动处理大小写的webapps类型: https://github.com/zhzyker/vulmap/commit/5e1ee00b0598b5dd5b9898a01fabcc4b84dc4e8c
        webapps_identify = [x.lower() for x in webapps_identify]
        if globals.get_value("DISMAP") == "true":
            webapps_identify = ','.join(webapps_identify)
        if r"weblogic" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.oracle_weblogic(target, gevent_pool)))
        if r"shiro" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_shiro(target, gevent_pool)))
        if r"activemq" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_activemq(target, gevent_pool)))
        if r"flink" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_flink(target, gevent_pool)))
        if r"fastjson" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.fastjson(target, gevent_pool)))
        if r"spring" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.spring(target, gevent_pool)))
        if r"solr" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_solr(target, gevent_pool)))
        if r"tomcat" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_tomcat(target, gevent_pool)))
        if r"elasticsearch" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.elasticsearch(target, gevent_pool)))
        if r"jenkins" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.jenkins(target, gevent_pool)))
        if r"nexus" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.nexus(target, gevent_pool)))
        if r"jboss" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.redhat_jboss(target, gevent_pool)))
        if r"unomi" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_unomi(target, gevent_pool)))
        if r"thinkphp" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.thinkphp(target, gevent_pool)))
        if r"drupal" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.drupal(target, gevent_pool)))
        if r"struts2" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_strtus2(target, gevent_pool)))
        if r"druid" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_druid(target, gevent_pool)))
        if r"laravel" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.laravel(target, gevent_pool)))
        if r"vmware" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.vmware(target, gevent_pool)))
        if r"saltstack" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.saltstack(target, gevent_pool)))
        if r"nodejs" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.nodejs(target, gevent_pool)))
        if r"exchange" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.exchange(target, gevent_pool)))
        if r"bigip" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.big_ip(target, gevent_pool)))
        if r"ofbiz" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.apache_ofbiz(target, gevent_pool)))
        if r"qianxin" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.qiaixin(target, gevent_pool)))
        if r"ruijie" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.ruijie(target, gevent_pool)))
        if r"eyou" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.eyou(target, gevent_pool)))
        if r"coremail" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.coremail(target, gevent_pool)))
        if r"ecology" in webapps_identify or r"all" in webapps_identify:
            thread_poc.append(thread_pool.submit(scan.ecology(target, gevent_pool)))

core = Core()
