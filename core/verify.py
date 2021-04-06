#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
from module import globals
from module.time import now
from module.color import color
from module.output import output


class Verification:
    @staticmethod
    def scan_print(vul_info):
        try:
            delay = globals.get_value("DELAY")  # 获取全局变量DELAY
            debug = globals.get_value("DEBUG")  # 获取全局变量DEBUG
            result = vul_info["prt_resu"]
            prt_name = vul_info["prt_name"]
            vul_name = vul_info["vul_name"]
            vul_type = vul_info["vul_type"]
            vul_numb = vul_info["vul_numb"]
            info = vul_info["prt_info"]
            if result == "PoCSuCCeSS":  # 存在漏洞时候输出以下内容
                print(now.timed(de=delay) + color.green("[+] The target is " + prt_name + " " + info))
                # 丢给output模块判断是否输出文件
                output("json", vul_info)
                output("text", "--> [名称:" + vul_name + "] [编号:" + vul_numb + "] [类型:" + vul_type + "] " + info)
            elif result == "PoC_MaYbE":
                print(now.timed(de=delay) + color.green("[?] The target maybe " + prt_name + " " + info))
                # 丢给output模块判断是否输出文件
                output("json", vul_info)
                output("text", "--> [名称:" + vul_name + "] [编号:" + vul_numb + "] [类型:" + vul_type + "] " + info)
            else:  # 否则就是没有洞
                if debug == "debug":
                    print(now.timed(de=delay) + color.magenta("[-] The target no " + color.magenta(prt_name)))
                else:
                    print("\r{0}{1}{2}".format(now.timed(de=delay),
                                               color.magenta("[-] The target no "),
                                               color.magenta(prt_name)), end="                           \r", flush=True)
        except IndexError as error:
            print(now.timed(de=0) + color.red("[ERROR] " + error.__traceback__.tb_frame.f_globals['__file__']
                                              + " " + str(error.__traceback__.tb_lineno)))

    @staticmethod
    def exploit_print(request, raw_data):
        delay = globals.get_value("DELAY")  # 获取全局变量DELAY
        debug = globals.get_value("DEBUG")  # 获取全局变量DEBUG
        if debug == "debug":
            print(raw_data)
        elif r"PoC_WaTinG" in request:
            print(now.timed(de=delay) + color.red_warn() + color.magenta(" Command Executed Failed... ..."))
        else:
            print(request)

    @staticmethod
    def timeout_print(prt_name):
        delay = globals.get_value("DELAY")  # 获取全局变量DELAY
        debug = globals.get_value("DEBUG")  # 获取全局变量DEBUG
        if debug == "debug":
            print(now.timed(de=delay) + color.red_warn() +
                  color.cyan(" " + prt_name + " check failed because timeout !!!"))
        else:
            print("\r{0}{1}{2}".format(now.timed(de=delay),
                                       color.red_warn(),
                                       color.cyan(" " + prt_name + " connection timeout !!!")),
                  end="                            \r",
                  flush=True)
    @staticmethod
    def connection_print(prt_name):
        delay = globals.get_value("DELAY")  # 获取全局变量DELAY
        debug = globals.get_value("DEBUG")  # 获取全局变量DEBUG
        if debug == "debug":
            print(now.timed(de=delay) + color.red_warn() +
                  color.cyan(" " + prt_name + " check failed because unable to connect !!!"))
        else:
            print("\r{0}{1}{2}".format(now.timed(de=delay),
                                       color.red_warn(),
                                       color.cyan(" " + prt_name + " connection failed !!!")),
                  end="                            \r",
                  flush=True)

    @staticmethod
    def error_print(prt_name):
        delay = globals.get_value("DELAY")  # 获取全局变量DELAY
        debug = globals.get_value("DEBUG")  # 获取全局变量DEBUG
        if debug == "debug":
            print(now.timed(de=delay) + color.magenta("[-] The target no " + color.magenta(prt_name)))
        else:
            print("\r{0}{1}{2}".format(now.timed(de=delay),
                                       color.magenta("[-] The target no "),
                                       color.magenta(prt_name)),
                  end="                            \r",
                  flush=True)


verify = Verification()


def misinformation(req, md):  # 用来处理echo被错误返回时的误报，代码小巧作用甚大
    bad = "echo.{0,10}" + md    # 使用正则来应对复杂的编码情况
    if(re.search(bad, req) != None):
        return "misinformation"
    else:
        return req
