#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import sys
import json
from thirdparty.pysocks import socks
import socket
from thirdparty import requests
from module import globals
from module.time import now
from module.color import color


def proxy_set(pr, pr_mode):
    headers = globals.get_value("HEADERS")  # 获取全局变量HEADERS
    try:
        proxy_ip = str(re.search(r"(.*):", pr).group(1))
        proxy_port = int(re.search(r":(.*)", pr).group(1))
    except AttributeError:
        print(now.timed(de=0) + color.red_warn() + color.red(" Proxy format error (e.g. --proxy-socks 127.0.0.1:1080)"))
        sys.exit(0)
    if r"socks" in pr_mode:
        socks.set_default_proxy(socks.SOCKS5, proxy_ip, proxy_port)
    elif r"http" in pr_mode:
        socks.set_default_proxy(socks.HTTP, addr=proxy_ip, port=proxy_port)
    socket.socket = socks.socksocket
    try:
        proxy_ip_info = requests.get("http://api.hostip.info/get_json.php", headers=headers, timeout=5)
        proxy_ip_info_json = json.loads(proxy_ip_info.text)
        proxy_ip_info_dict = "[region: " + proxy_ip_info_json["country_name"] + "] " + "[city: " + proxy_ip_info_json[
            "city"] + "] " + "[proxy ip: " + proxy_ip_info_json["ip"] + "]"
    except requests.exceptions.ConnectionError:
        proxy_ip_info_dict = "[region: ???] [city: ???] [proxy ip: ???]"
    except requests.exceptions.Timeout:
        proxy_ip_info_dict = "[region: ???] [city: ???] [proxy ip: ???]"
    print(now.timed(de=0) + color.yel_info() + color.yellow(" Use custom proxy: " + pr))
    print(now.timed(de=0) + color.yel_info() + color.yellow(" Proxy info: " + proxy_ip_info_dict))
